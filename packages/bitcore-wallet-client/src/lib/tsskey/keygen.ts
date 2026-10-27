import { EventEmitter } from 'events';
import { ECDSA, utils as TssUtils } from '@bitpay-labs/bitcore-tss';
import { BitcoreLib } from '@bitpay-labs/crypto-wallet-core';
import { API as Client } from '../api';
import { Constants } from '../common';
import { Credentials } from '../credentials';
import { Errors } from '../errors';
import { Key, PasswordMaybe } from '../key';
import { Request, RequestResponse, getRequestErrorStatus, isTransientRequestError } from '../request';
import { normalizePubKey } from '../tssdelivery';
import { TssKey } from './key';
import type { Network } from '../common';
import type { DeliveryBindings, ITssKeyGenConstructorParams, RestoreTrustedInputs, SessionParams, SessionWrapper, TssKeyGenSubscribeOptions } from './types';

const $ = BitcoreLib.util.preconditions;
const { TSS_KEYGEN_VERSION } = Constants;
const SESSION_WRAPPER_PREFIX = 'tsskeygen.1.';
const SESSION_WRAPPER_VERSION = 1;

/**
 * Read `n`, `m` and `partyId` from the DKG's own export (`round:n:m:partyId:...`), which is encrypted to the request key.
 * Only the leading fields are parsed so the rest of the plaintext (which includes the seed) never becomes a string.
 */
function readKeygenSessionParams(keygenSession: string, requestPrivKey: BitcoreLib.PrivateKey) {
  const plaintext = TssUtils.decrypt(Buffer.from(keygenSession, 'base64'), requestPrivKey.publicKey, requestPrivKey);
  try {
    let end = -1;
    // advance end to the correct position: the fourth ':'
    for (let i = 0; i < 4; i++) {
      end = plaintext.indexOf(':', end + 1);
      if (end < 0) {
        throw new Error('Invalid session');
      }
    }
    // end is advanced to the correct position so subarray().toString() doesn't create an immutable string containing the seed
    const [, n, m, partyId] = plaintext.subarray(0, end).toString().split(':').map(Number);
    return { n, m, partyId };
  } finally {
    plaintext.fill(0);
  }
}

/**
 * Shared machinery for one local participant in one TSS ceremony.
 * Construct TssKeyGenCreator or TssKeyGenRecipient to select a role. Each instance can start only once,
 * even if starting fails, because BWS may already have accepted it. Restoration supports recovery and rollback.
 */
export abstract class TssKeyGen<TTrustedInputs = RestoreTrustedInputs> extends EventEmitter {
  #request: Request;
  #requestPrivateKey: BitcoreLib.PrivateKey;
  #seed: Buffer;
  #key: Key;
  #xPrivKey: string;
  #keygen: ECDSA.KeyGen;
  #credentials: Credentials;
  #initializationState: 'unused' | 'initializing' | 'in-use' = 'unused';
  #subscriptionId: ReturnType<typeof setInterval>;
  #subscriptionRunning: boolean;
  #stopErrors = new WeakSet<object>();
  id: string;
  chain: string;
  network: Network;
  m: number;
  n: number;
  partyId: number;
  backupKeyShare: boolean;

  constructor(
    /** Constructor parameters */
    params: ITssKeyGenConstructorParams,
    /** EventEmitter options object */
    eventOpts?
  ) {
    super(eventOpts);
    $.checkArgument(params.chain, 'Missing required param: chain');
    $.checkArgument(params.network, 'Missing required param: network');
    $.checkArgument(params.baseUrl, 'Missing required param: baseUrl');
    $.checkArgument(params.key, 'Missing required param: key');
    $.checkArgument(params.key instanceof Key, 'key must be an instance of Key');

    this.chain = params.chain.toLowerCase();
    this.network = params.network;
    this.#request = new Request(params.baseUrl, {
      r: params.request, // For testing only
    });

    this.#key = params.key;
    // n is always 1 when creating credentials because the wallet is not multisig (threshold sig !== multisig).
    // In other words, it will look like a single sig wallet on-chain.
    this.#credentials = this.#key.createCredentials(params.password, { chain: this.chain, network: this.network, n: 1, account: 0 });
    this.request.setCredentials(this.#credentials);
    this.#requestPrivateKey = BitcoreLib.PrivateKey.fromString(this.#credentials.requestPrivKey);

    const baseXPrivKey = this.#key.get(params.password).xPrivKey;
    const derivationPath = this.#credentials.getRootPath();
    this.#xPrivKey = new BitcoreLib.HDPrivateKey(baseXPrivKey).deriveChild(derivationPath).toString();
    const _seed = BitcoreLib.HDPrivateKey.fromString(this.#xPrivKey);
    this.#seed = BitcoreLib.crypto.Hash.sha256(_seed.toBuffer());

    // Backup to server is disabled
    // this.backupKeyShare = !!params.backupKeyShare;
  }

  // Getters keep shared private material out of enumerable instance fields.
  protected get request(): Request {
    return this.#request;
  }

  protected get requestPrivateKey(): BitcoreLib.PrivateKey {
    return this.#requestPrivateKey;
  }

  protected get seed(): Buffer {
    return this.#seed;
  }

  protected abstract getDeliveryBindings(): DeliveryBindings;
  protected abstract setDeliveryBindings(bindings: DeliveryBindings): void;
  protected abstract applyTrustedInputs(
    trusted: TTrustedInputs | undefined,
    restored: SessionParams,
    retained: DeliveryBindings
  ): DeliveryBindings;
  protected abstract verifyOtherPartyBindings(expectKey: (partyId: number, trusted: string) => void): void;

  protected assertUnused(): void {
    $.checkState(this.#initializationState === 'unused', 'TssKeyGen initialization already started. Use a new instance for each participant and ceremony.');
  }

  /** Shared startup, including the guard against repeating an ambiguous enrollment. */
  protected async initializeKeygen(
    params: Omit<SessionParams, 'm' | 'n'> & { m: number | string; n: number | string; chain: string; network: Network },
    enrollment: { n?: number | string; password?: string },
    bindings: DeliveryBindings
  ): Promise<this> {
    this.assertUnused();
    const { id, m, n, partyId, chain, network } = params;
    const keygen = new ECDSA.KeyGen({ m, n, partyId, seed: this.seed, authKey: this.#credentials.requestPrivKey });
    this.#initializationState = 'initializing';
    this.id = id;
    this.m = parseInt(String(m));
    this.n = parseInt(String(n));
    this.partyId = partyId;
    this.chain = chain;
    this.network = network;
    this.#keygen = keygen;
    this.setDeliveryBindings(bindings);

    try {
      const message = await keygen.initJoin();
      await this.request.post(`/v1/tss/keygen/${this.id}`, { message, ...enrollment, version: TSS_KEYGEN_VERSION });
      return this;
    } finally {
      this.#initializationState = 'in-use';
    }
  }

  /** This participant's request public key, used in the trusted invitation exchange. */
  getAuthPublicKey(): string {
    return this.#credentials.requestPubKey;
  }

  /**
   * Check the locally retained delivery keys against the session's party/request-key mapping from BWS.
   * The retained keys are the source of trust: BWS data is only compared against them, never adopted.
   * Throws if a retained key is missing or the session disagrees with it.
   * @param sessionKeys The request public key each party enrolled in the session with, indexed by partyId
   *   (the `publicKey` of each party's round-0 message at BWS)
   */
  verifyDeliveryBindings(sessionKeys: Array<string>): void {
    $.checkArgument(Array.isArray(sessionKeys), 'sessionKeys must be an array');
    const sessionKey = (partyId: number) => {
      const key = sessionKeys[partyId];
      if (!key) {
        throw new Error(`Session has no public key for party ${partyId}`);
      }
      try {
        return normalizePubKey(key);
      } catch {
        throw new Error(`Session has an invalid public key for party ${partyId}`);
      }
    };
    const expectKey = (partyId: number, trusted: string) => {
      if (sessionKey(partyId) !== trusted) {
        throw new Error(`Session public key for party ${partyId} does not match the trusted key`);
      }
    };

    this.verifyOtherPartyBindings(expectKey);
    // Every party must be registered under its own request key
    expectKey(this.partyId, normalizePubKey(this.#credentials.requestPubKey));
  }

  /** Export the DKG state and the subclass's retained trust, encrypted to this party's request key. */
  exportSession(): string {
    if (this.#keygen.isKeyChainReady()) {
      throw new Error('Cannot export a completed session. Run getKeyChain() instead.');
    }
    const bindings = this.getDeliveryBindings();
    const wrapper: SessionWrapper = {
      version: SESSION_WRAPPER_VERSION,
      id: this.id,
      partyId: this.partyId,
      chain: this.chain,
      network: this.network,
      m: this.m,
      n: this.n,
      requestPubKey: normalizePubKey(this.#credentials.requestPubKey),
      session: [this.id, this.partyId, this.m, this.n, this.#keygen.export()].join(':'),
      creatorPubKey: bindings.creatorPubKey,
      recipientKeys: [...bindings.recipientKeys].map(([partyId, pubKey]) => ({ partyId, pubKey }))
    };
    const plaintext = Buffer.from(JSON.stringify(wrapper));
    try {
      const encrypted = TssUtils.encrypt(plaintext, this.requestPrivateKey.publicKey, this.requestPrivateKey);
      return SESSION_WRAPPER_PREFIX + encrypted.toString('base64');
    } finally {
      plaintext.fill(0);
    }
  }

  /**
   * Restore a session from a previously exported session
   *
   * A session exported before delivery keys were retained (a legacy export) carries none.
   * Supply them from the original invitation exchange with `trusted`; otherwise delivery reports missing trust.
   * They are never reconstructed from BWS.
   * @returns {Promise<this>} Restored TSS instance
   */
  async restoreSession(params: {
    /**
     * Session string to restore
     */
    session: string;
    /**
     * Original trusted invitation inputs. Required to establish delivery trust for a legacy export.
     * For an export that retained its keys, they must agree with what was retained.
     */
    trusted?: TTrustedInputs;
  }): Promise<this> {
    $.checkState(this.#initializationState !== 'initializing', 'TssKeyGen initialization is in progress. Wait for it to finish before restoring a session.');
    const { session, trusted } = params;
    // Everything is validated before any state is replaced, so a failed restore changes nothing.
    const { restored, keygenSession, retained } = this.#readSession(session);
    const bindings = this.applyTrustedInputs(trusted, restored, retained);

    const previousState = this.#initializationState;
    this.#initializationState = 'initializing';
    try {
      const keygen = await ECDSA.KeyGen.restore({ session: keygenSession, authKey: this.#credentials.requestPrivKey });
      this.id = restored.id;
      this.m = restored.m;
      this.n = restored.n;
      this.partyId = restored.partyId;
      this.#keygen = keygen;
      this.setDeliveryBindings(bindings);
    } catch (err) {
      this.#initializationState = previousState;
      throw err;
    }
    this.#initializationState = 'in-use';
    return this;
  }

  /**
   * Parse either session format. Does not retain anything.
   * `retained` is what the session string itself vouches for: the keys from a wrapper, and always nothing for a legacy export.
   */
  #readSession(session: string): {
    restored: SessionParams;
    keygenSession: string;
    retained: DeliveryBindings;
  } {
    const isWrapped = session.startsWith(SESSION_WRAPPER_PREFIX);
    const retained: DeliveryBindings = { recipientKeys: new Map() };
    // legacy, reassigned if isWrapped
    let unwrappedSession = session;

    if (isWrapped) {
      const wrapper = this.#readSessionWrapper(session.slice(SESSION_WRAPPER_PREFIX.length));
      unwrappedSession = wrapper.session;
      retained.creatorPubKey = wrapper.creatorPubKey;
      for (const { partyId, pubKey } of wrapper.recipientKeys) {
        retained.recipientKeys.set(partyId, pubKey);
      }
    }

    const parts = unwrappedSession.split(':');
    const id = parts.slice(0, -4).join(':'); // id may contain colons, so we join all parts except the last 4
    const [partyId, m, n, keygenSession] = parts.slice(-4);
    const restored = { id, partyId: parseInt(partyId), m: parseInt(m), n: parseInt(n) };

    // Check both formats against the authenticated DKG state; legacy outer parameters are plaintext.
    let dkg: ReturnType<typeof readKeygenSessionParams>;
    try {
      dkg = readKeygenSessionParams(keygenSession, this.requestPrivateKey);
    } catch {
      throw new Error('Session could not be decrypted or verified');
    }
    if (dkg.n !== restored.n || dkg.m !== restored.m || dkg.partyId !== restored.partyId) {
      throw new Error('Session ceremony parameters do not match its DKG state');
    }
    return { restored, keygenSession, retained };
  }

  /**
   * Decrypt and validate a session wrapper against this instance's request identity and chain/network.
   * Does not retain anything.
   */
  #readSessionWrapper(encoded: string): SessionWrapper {
    let wrapper: SessionWrapper;
    try {
      const plaintext = TssUtils.decrypt(Buffer.from(encoded, 'base64'), this.requestPrivateKey.publicKey, this.requestPrivateKey);
      try {
        wrapper = JSON.parse(plaintext.toString());
      } finally {
        plaintext.fill(0);
      }
    } catch {
      throw new Error('Session could not be decrypted or verified');
    }

    const fail = (reason: string): never => { throw new Error('Invalid session: ' + reason); };
    const isInt = (v: unknown): v is number => Number.isSafeInteger(v);
    if (!wrapper || typeof wrapper !== 'object') fail('malformed');
    if (wrapper.version !== SESSION_WRAPPER_VERSION) fail('unsupported version');
    if (typeof wrapper.id !== 'string' || !wrapper.id) fail('missing session id');
    if (!isInt(wrapper.m) || !isInt(wrapper.n) || !isInt(wrapper.partyId)) fail('malformed ceremony parameters');
    if (wrapper.m < 1 || wrapper.m > wrapper.n || wrapper.partyId < 0 || wrapper.partyId >= wrapper.n) fail('ceremony parameters out of range');
    if (typeof wrapper.session !== 'string') fail('missing DKG state');
    if (wrapper.requestPubKey !== normalizePubKey(this.#credentials.requestPubKey)) fail('exported by a different request key');
    if (wrapper.chain !== this.chain || wrapper.network !== this.network) fail('chain or network does not match');
    if (!Array.isArray(wrapper.recipientKeys)) fail('malformed delivery keys');

    // The wrapper's own fields must describe the DKG export it wraps
    const parts = wrapper.session.split(':');
    const sessionId = parts.slice(0, -4).join(':');
    const [partyId, m, n] = parts.slice(-4).map(Number);
    if (sessionId !== wrapper.id || partyId !== wrapper.partyId || m !== wrapper.m || n !== wrapper.n) {
      fail('ceremony parameters do not match the wrapped session');
    }

    // The subclasses validate the retained keys and their role before restoration changes any state.
    const seen = new Set<number>();
    for (const entry of wrapper.recipientKeys) {
      if (!entry || typeof entry !== 'object' || !isInt(entry.partyId) || seen.has(entry.partyId)) {
        fail('malformed delivery keys');
      }
      seen.add(entry.partyId);
    }
    return wrapper;
  }

  /**
   * Subscribe to the TSS key generation process + wallet creation
   * Various events will be emitted during the process:
   * - `roundready` => number: A new round is ready to be processed. Emits the round number.
   * - `roundprocessed` => number: A round has been processed. Emits the round number.
   * - `roundsubmitted` => number: A round has been submitted to the server. Emits the round number.
   * - `tsskey` => TssKey: The TSS key is ready. Emits the key class object.
   * - `tsskeystored`: => void: The TSS pub key and keyshare backup has been stored on the server.
   * - `wallet` => any: The wallet has been created. Emits the wallet object.
   * - `complete` => void: The key generation process (+ wallet creation, if applicable) is complete. This is the final event emitted along the happy path.
   * - `error` => Error: An error occurred during the process. Emits the error. Note that this will not stop the subscription,
   *   unless the wallet phase cannot be retried: creating the wallet or delivering its secret (party 0), or receiving it and
   *   joining (other parties). E.g. missing/conflicting trusted keys, a delivery that fails decryption or verification,
   *   or an ambiguous wallet creation/join failure. The subscription then stops, emitting `unsubscribe` after the error.
   * @returns {NodeJS.Timeout} Subscription ID
   */
  abstract subscribe(params?: TssKeyGenSubscribeOptions): NodeJS.Timeout;

  /** One polling/round-processing loop, with wallet completion supplied by the participant's role. */
  protected subscribeKeygen(
    params: TssKeyGenSubscribeOptions,
    finishWallet: () => Promise<any>
  ): NodeJS.Timeout {
    $.checkState(
      this.#initializationState === 'in-use' && this.#keygen,
      'Initialize or restore the TSS key generation session before subscribing'
    );
    const { timeout, iterHandler, copayerName } = params;
    const complete = () => {
      this.emit('complete');
      if (iterHandler) iterHandler();
      this.unsubscribe();
      // Anything after unsubscribe() will not be executed
    };

    // Whether the server is known to hold the shared public key: either a round poll showed it, or this party stored it.
    // Until then each tick polls a round, since that is where the server reports the key. After, it need not.
    let keyStored = false;

    this.#subscriptionId = setInterval(async () => {
      if (this.#subscriptionRunning) return;
      this.#subscriptionRunning = true;
      const thisRound = this.#keygen.getRound();
      // Once the DKG is complete there are no more rounds. Polling one is only needed to learn whether the shared public
      //  key is stored; after that the wallet phase below repeats on its own, without depending on round requests
      //  (which must also never export a completed session or advance the DKG again).
      let body: { messages?: Array<any>; publicKey?: string } = {};
      try {
        if (!this.#keygen.isKeyChainReady() || !keyStored) {
          const prevRound = thisRound - 1; // Get previous round's messages
          ({ body } = await this.request.get(`/v1/tss/keygen/${this.id}/${prevRound}`) as RequestResponse);
          // false to true the first time publicKey is found - shouldn't be toggled off again
          keyStored ||= !!body.publicKey;
        }

        // Once complete there is no round left to process, whatever the poll returned
        const hasEveryoneSubmitted = !this.#keygen.isKeyChainReady() && body.messages?.length === this.n - 1; // subtract yourself
        if (hasEveryoneSubmitted) {
          this.emit('roundready', thisRound);
          // Snapshot the session in case there's an API failure
          //  since this.#keygen can't re-process the messages
          const sessionBak = this.exportSession();
          try {
            const msg = await this.#keygen.nextRound(body.messages);
            this.emit('roundprocessed', thisRound);
            // If the keychain is ready, there's nothing to send to the server and msg will have empty arrays.
            if (!this.#keygen.isKeyChainReady()) {
              // For 2 P2P messages (i.e. party of 3), it already exceeds 100 KB (190 KB)
              // Assuming ~80KB per message, the max server size of 2MB would be ~25 P2P messages
              await this.request.post(`/v1/tss/keygen/${this.id}`, { message: msg, version: TSS_KEYGEN_VERSION });
              this.emit('roundsubmitted', thisRound);
            }
          } catch (err) {
            // Restore the session to the previous state
            await this.restoreSession({ session: sessionBak });
            throw err;
          }
        }

        const key = this.getTssKey();
        if (key) {
          this.emit('tsskey', key);

          // Only the common public keychain is published; private-share backup is disabled.
          if (!keyStored) {
            await this.request.post(`/v1/tss/keygen/${this.id}/store`, { publicKey: key.keychain.commonKeyChain });
            this.emit('tsskeystored');
            keyStored = true;
          }

          if (!copayerName) {
            complete();
            // Anything after complete()/unsubscribe() will not be executed
          } else {
            const wallet = await finishWallet();

            if (wallet) {
              this.emit('wallet', wallet);
              complete();
              // Anything after complete()/unsubscribe() will not be executed
            }
          }
        }
        // iteration handler
        // Some custom function to fire every iteration
        if (iterHandler) iterHandler();
      } catch (err) {
        try {
          this.emit('error', err);
        } finally {
          // A failure that repeating cannot fix would only repeat itself (or, for wallet creation, repeat the enrollment).
          // Once the DKG is complete, a rejected or expired session is such a failure. Before that, it is left to the consumer.
          if (this.#stopErrors.has(err) || (this.#keygen.isKeyChainReady() && (err instanceof Errors.NOT_AUTHORIZED || err instanceof Errors.TSS_SESSION_EXPIRED))) {
            this.unsubscribe({ clearEvents: false });
          }
        }
      } finally {
        this.#subscriptionRunning = false;
      }
    }, timeout || 1000);

    return this.#subscriptionId;
  }

  /**
   * Unsubscribe from the TSS key generation process
   * Calling this method will emit the 'unsubscribe' event.
   */
  unsubscribe(params: {
    /**
     * Whether to remove all event listeners
     * @default true
     */
    clearEvents: boolean;
  } = { clearEvents: true }): void {
    const { clearEvents } = params;
    clearInterval(this.#subscriptionId);
    if (clearEvents) {
      this.removeAllListeners();
    }
    this.#subscriptionId = null;
    this.#subscriptionRunning = false;
    this.emit('unsubscribe');
  }

  /**
   * Get the key object if the key generation process is complete
   * @returns {TssKey|null} The keychain object if the key generation process is complete, otherwise null
   */
  getTssKey(password?: PasswordMaybe): TssKey | null {
    if (this.#keygen.isKeyChainReady()) {
      const keychain = this.#keygen.getKeyChain();
      const key = new TssKey({
        ...this.#key.toObj(),
        keychain: { ...keychain },
        metadata: {
          id: this.id,
          m: this.m,
          n: this.n,
          partyId: this.partyId
        }
      });
      if (password) {
        key.encrypt(password);
      }
      return key;
    }
    return null;
  }

  protected requireTssKey(): TssKey {
    const key = this.getTssKey();
    if (!key) {
      throw new Error('TSS Key generation is not complete. This should be called after the `complete` event is emitted.');
    }
    return key;
  }

  /** Wallet clients share this participant's credentials and HTTP transport. */
  protected createWalletClient(key: TssKey): Client {
    this.#credentials.clientDerivedPublicKey = key.getXPubKey(this.network);
    const client = new Client({ baseUrl: this.request.baseUrl, request: this.request.r });
    client.fromObj(this.#credentials.toObj());
    return client;
  }

  protected recordWallet(client: Client, wallet: any, copayerName: string, walletName?: string): void {
    const credentials = client.toObj();
    this.#credentials.addWalletInfo(credentials.walletId, walletName ?? credentials.walletName, 1, 1, copayerName, {
      useNativeSegwit: ['P2WPKH', 'P2WSH', 'P2TR'].includes(wallet.addressType),
      segwitVersion: wallet.addressType === 'P2TR' ? 1 : 0,
      tssKeyId: this.id,
    });
  }

  protected isNormalizedDeliveryKey(key: unknown): boolean {
    try {
      return typeof key === 'string' && key === normalizePubKey(key);
    } catch {
      return false;
    }
  }

  /** Only delivery publication and retrieval are safe to repeat after a server failure. */
  protected isRetryableDeliveryRequestError(err: unknown): boolean {
    return getRequestErrorStatus(err) === 500 || isTransientRequestError(err);
  }

  /**
   * Record that the subscription must stop on this error, and return it.
   * Used directly where even a transient-looking failure must stop: a lost response to the wallet creation request
   * does not say whether the wallet was created, so repeating it could create another.
   * Anything that is not an object cannot be recorded (a WeakSet rejects it), and must not replace the error being thrown.
   */
  protected stopOn<T>(err: T): T {
    if (err && typeof err === 'object') {
      this.#stopErrors.add(err);
    }
    return err;
  }

  /** Clean up sensitive DKG state after use. */
  cleanup(): void {
    this.#keygen?.cleanup();
  }
}
