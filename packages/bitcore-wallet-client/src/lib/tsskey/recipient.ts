import { ECIES } from '@bitpay-labs/bitcore-tss';
import { BitcoreLib } from '@bitpay-labs/crypto-wallet-core';
import { Utils } from '../common';
import { Errors } from '../errors';
import { JOIN_DELIVERY_VERSION, decryptJoinDelivery, normalizePubKey } from '../tssdelivery';
import { TssKeyGen } from './keygen';
import type { Network } from '../common';
import type { RequestResponse } from '../request';
import type { DeliveryBindings, JoinCodeParams, RecipientRestoreTrustedInputs, SessionParams, TssKeyGenSubscribeOptions } from './types';

const $ = BitcoreLib.util.preconditions;

/**
 * Parse and validate the ceremony fields of a decrypted join code. A correctly encrypted code is not necessarily a well-formed one,
 * and its fields become ceremony state and (via the creator key) trusted delivery state.
 * Fields may be undefined if the code had too few of them.
 * Numeric fields m, n, and partyId are validated together.
 */
function parseJoinCodeFields(fields: RawJoinCodeFields): JoinCodeFields {
  const { id, partyId, chain, network, m, n } = fields;
  const fail = (reason: string): never => { throw new Error('Invalid join code: ' + reason); };
  const toInt = (name: string, value?: string) => {
    const int = /^\d+$/.test(value ?? '') ? Number(value) : NaN;
    return Number.isSafeInteger(int) ? int : fail(`${name} must be a non-negative integer`);
  };

  if (!id) return fail('missing session id');
  if (!chain) return fail('missing chain');
  if (!Utils.isValidNetwork(network)) return fail('unknown network');
  const mInt = toInt('m', m);
  const nInt = toInt('n', n);
  const partyInt = toInt('partyId', partyId);
  if (mInt < 1 || mInt > nInt) fail('m must be in [1. n]');
  if (partyInt < 1 || partyInt >= nInt) fail('partyId must be in [1, n)');
  return { id, partyId: partyInt, chain, network, m: mInt, n: nInt };
}

/**
 * Validated join code contents, with numeric fields parsed as safe integers.
 * When used, m, n, and partyId should be confirmed integers - see parseJoinCodeFields return
 */
interface ParsedJoinCode {
  id: string;
  partyId: number;
  chain: string;
  network: Network;
  m: number;
  n: number;
  /** Anything after the ceremony fields (the optional invitation `extra`, used as the server password fallback) */
  extra: string;
  /** Normalized creator public key the code was issued by */
  creatorPubKey: string;
}

type JoinCodeFields = Omit<ParsedJoinCode, 'extra' | 'creatorPubKey'>;
/** Fields from splitting the plaintext; truncated invitations may omit fields. */
type RawJoinCodeFields = Partial<Record<keyof JoinCodeFields, string>>;

/** Joins an invitation and verifies the creator's encrypted delivery before enrolling in the wallet. */
export class TssKeyGenRecipient extends TssKeyGen<RecipientRestoreTrustedInputs> {
  #creatorPubKey: string;

  /** Inspect an invitation locally without retaining trust or enrolling with BWS. */
  checkJoinCode(params: JoinCodeParams): JoinCodeFields {
    const { id, partyId, chain, network, m, n } = this.#readJoinCode(params);
    return { id, partyId, chain, network, m, n };
  }

  /** Join the ceremony once, retaining the invitation's creator key for later delivery verification. */
  async joinKey(params: JoinCodeParams & {
    /** BWS admission password. Defaults to the invitation's extra field. */
    password?: string;
  }): Promise<this> {
    this.assertUnused();
    const { extra, creatorPubKey, ...session } = this.#readJoinCode(params);
    return this.initializeKeygen(session, { password: params.password || extra }, {
      creatorPubKey,
      recipientKeys: new Map()
    });
  }

  /**
   * Decrypt a join code and identify the creator key it was issued by.
   * Does not retain anything; callers decide whether the result becomes trusted state.
   */
  #readJoinCode(params: JoinCodeParams): ParsedJoinCode {
    let { code } = params;
    const { opts, creatorPubKey } = params;
    $.checkArgument(code, 'Missing required param: code');
    $.checkArgument(typeof code === 'string' || Buffer.isBuffer(code), '`code` must be a string or buffer');
    code = Buffer.isBuffer(code) ? code : Buffer.from(code, opts?.encoding || 'hex');

    const expectedCreatorKey = creatorPubKey == null ? undefined : normalizePubKey(creatorPubKey, 'creatorPubKey');

    const authKey = this.requestPrivateKey;
    let senderKey: string;
    let decrypted: Buffer | undefined;
    try {
      if (opts?.noKey) {
        // A noKey code carries no sender key, so the caller must supply the creator's key from a trusted exchange.
        if (!expectedCreatorKey) {
          throw new Error('creatorPubKey is required for a join code created with noKey');
        }
        senderKey = expectedCreatorKey;
        decrypted = ECIES.decrypt({ payload: code, privateKey: authKey, publicKey: senderKey });
      } else {
        senderKey = normalizePubKey(ECIES.readSenderPublicKey(code));
        decrypted = ECIES.decrypt({ payload: code, privateKey: authKey });
      }

      if (expectedCreatorKey && senderKey !== expectedCreatorKey) {
        throw new Error('Join code was not issued by the expected creator key');
      }

      // Parsing needs strings, which cannot be wiped. The decrypted buffer is zeroed below.
      const [id, partyId, chain, network, m, n, ...more] = (decrypted as Buffer).toString().split(':');
      // parseJoinCodeFields ensures partyId, m, and n are integers.
      const fields = parseJoinCodeFields({ id, partyId, chain, network, m, n });
      return { ...fields, extra: more.join(':'), creatorPubKey: senderKey };
    } finally {
      decrypted?.fill(0);
    }
  }

  protected getDeliveryBindings(): DeliveryBindings {
    return { creatorPubKey: this.#creatorPubKey, recipientKeys: new Map() };
  }

  protected setDeliveryBindings(bindings: DeliveryBindings): void {
    this.#creatorPubKey = bindings.creatorPubKey;
  }

  protected applyTrustedInputs(
    trusted: RecipientRestoreTrustedInputs | undefined,
    restored: SessionParams,
    retained: DeliveryBindings
  ): DeliveryBindings {
    $.checkArgument(restored.partyId > 0, 'A recipient instance can only restore a recipient session (partyId > 0)');
    if (retained.recipientKeys.size) {
      throw new Error('Invalid session: a recipient has no recipient keys');
    }
    if (retained.creatorPubKey != null && !this.isNormalizedDeliveryKey(retained.creatorPubKey)) {
      throw new Error('Invalid session: malformed delivery keys');
    }
    const bindings: DeliveryBindings = { creatorPubKey: retained.creatorPubKey, recipientKeys: new Map() };
    if (!trusted) return bindings;
    $.checkArgument(!trusted.recipientKeys, 'Recipient keys can only be supplied when restoring the creator\'s session');
    const { joinCode } = trusted;
    if (joinCode) {
      const code = this.#readJoinCode(joinCode);
      if (code.id !== restored.id || code.partyId !== restored.partyId ||
        code.m !== restored.m || code.n !== restored.n ||
        code.chain.toLowerCase() !== this.chain || code.network !== this.network) {
        throw new Error('Join code does not match the session being restored');
      }
      if (bindings.creatorPubKey && bindings.creatorPubKey !== code.creatorPubKey) {
        throw new Error('Join code creator key does not match the retained key');
      }
      bindings.creatorPubKey = code.creatorPubKey;
    }
    return bindings;
  }

  protected verifyOtherPartyBindings(expectKey: (partyId: number, trusted: string) => void): void {
    if (!this.#creatorPubKey) {
      throw new Error('Missing trusted creator public key. Join using the creator\'s join code.');
    }
    expectKey(0, this.#creatorPubKey);
  }

  subscribe(params: TssKeyGenSubscribeOptions = {}): NodeJS.Timeout {
    return this.subscribeKeygen(params, async () => {
      try {
        return await this.joinWallet({ copayerName: params.copayerName });
      } catch (err) {
        if (!(err instanceof Errors.TSS_JOIN_DELIVERY_PENDING)) {
          throw err;
        }
        // The creator has not published yet. Let the shared subscription try again on its next tick.
      }
    });
  }

  /**
   * Join the wallet the session creator created, using the join secret the creator delivered (encrypted) through BWS.
   * The secret is decrypted and checked here against the invitation and the local DKG result before anything is joined.
   *
   * Throws `TSS_JOIN_DELIVERY_PENDING` if the creator has not published it yet; calling this again later is safe.
   * Joining itself is not repeated by the subscription: a failure of the join request does not say whether it was applied.
   */
  async joinWallet(params: {
    copayerName: string;
    opts?: {
      coin?: string;
      dryRun?: boolean;
    };
  }) {
    const { copayerName, opts = {} } = params;
    const key = this.requireTssKey();
    $.checkState(this.partyId > 0, 'The session creator creates the wallet, it does not join it');

    const secret = await this.#getJoinSecret(key.keychain.commonKeyChain);

    try {
      const client = this.createWalletClient(key);

      const wallet = await client.joinWallet(
        secret,
        copayerName,
        Object.assign({}, opts, {
          chain: this.chain
        })
      );

      this.recordWallet(client, wallet, copayerName);

      return wallet;
    } catch (err) {
      // The join may or may not have been applied at BWS, so it must not be repeated as another attempt
      throw this.stopOn(err);
    }
  }

  /**
   * Fetch this party's delivery from BWS, then decrypt it and check it against what is known locally.
   * The creator's key is the one retained from the trusted invitation; nothing BWS returns can replace it.
   * A pending delivery and a transient transport failure are left as they are, since asking again can succeed.
   * Everything else would only repeat itself, so it stops the subscription. There is no fallback to plaintext delivery.
   */
  async #getJoinSecret(commonKeyChain: string): Promise<string> {
    const creatorPubKey = this.#creatorPubKey;
    if (!creatorPubKey) {
      throw this.stopOn(new Error('Missing trusted creator public key. Join with the join code (or restore the session with it) to verify the delivery.'));
    }

    let delivery: RequestResponse['body'];
    try {
      ({ body: delivery } = await this.request.get(`/v1/tss/keygen/${this.id}/join-delivery`) as RequestResponse);
    } catch (err) {
      throw (err instanceof Errors.TSS_JOIN_DELIVERY_PENDING || this.isRetryableDeliveryRequestError(err)) ? err : this.stopOn(err);
    }

    try {
      if (delivery?.version !== JOIN_DELIVERY_VERSION) {
        throw new Error('Unsupported join delivery version');
      }
      return decryptJoinDelivery({
        delivery,
        recipientPrivKey: this.requestPrivateKey,
        creatorPubKey,
        expected: {
          sessionId: this.id,
          partyId: this.partyId,
          requestPubKey: this.getAuthPublicKey(),
          chain: this.chain,
          network: this.network,
          m: this.m,
          n: this.n,
          commonKeyChain
        }
      });
    } catch (err) {
      throw this.stopOn(err);
    }
  }
}
