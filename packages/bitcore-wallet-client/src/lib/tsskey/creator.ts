import { ECIES } from '@bitpay-labs/bitcore-tss';
import { BitcoreLib } from '@bitpay-labs/crypto-wallet-core';
import { JOIN_DELIVERY_VERSION, encryptJoinDelivery, normalizePubKey } from '../tssdelivery';
import { TssKeyGen } from './keygen';
import type { CreateWalletOpts } from '../api';
import type { RequestResponse } from '../request';
import type { CreatorRestoreTrustedInputs, DeliveryBindings, JoinCodeOptions, SessionParams, TssKeyGenCreatorSubscribeOptions } from './types';

const $ = BitcoreLib.util.preconditions;

/** Creates invitations, retains recipient trust, and creates and delivers the shared wallet. */
export class TssKeyGenCreator extends TssKeyGen<CreatorRestoreTrustedInputs> {
  #recipientKeys = new Map<number, string>();
  #createdWallet?: { wallet: any; secret: string };

  /** Start a ceremony as party 0. Starting consumes this instance even if enrollment fails. */
  async newKey(params: {
    m: number | string;
    n: number | string;
    /** Optional BWS session admission password, shared with recipients through their invitations. */
    password?: string;
  }): Promise<this> {
    this.assertUnused();
    const { m, n, password } = params;
    return this.initializeKeygen({
      id: BitcoreLib.crypto.Hash.sha256sha256(this.seed).toString('hex'),
      partyId: 0,
      m,
      n,
      chain: this.chain,
      network: this.network
    }, { n, password }, { recipientKeys: new Map() });
  }

  /**
   * Create a join code for a party to join the TSS key.
   * The join code is encrypted with the party's public key and is thus party-specific.
   * Note that the join code is verified on the client side only. Someone could theoretically
   *  intercept or brute force the session ID and submit an initial message to join the session
   *  uninvited. To prevent this (unlikely) possibility, set a password in the newKey() method
   *  and share it with the other parties.
   * @returns {Promise<string>} Encrypted join code
   */
  async createJoinCode(params: {
    /**
     * Party ID to create the join code for
     */
    partyId: number;
    /**
     * Public key of the party to encrypt the join code to
     */
    partyPubKey: string;
    /**
     * Extra data to include in the join code
     */
    extra?: string;
    /** Encoding and ECIES options for the invitation. */
    opts?: JoinCodeOptions;
  }): Promise<string> {
    const { partyId, partyPubKey, opts } = params;
    $.checkArgument(Number.isInteger(partyId) && partyId > 0 && partyId < this.n, 'partyId must be an integer between 1 and n - 1');
    const normalizedPubKey = normalizePubKey(partyPubKey, 'partyPubKey');
    const extra = params.extra || '';
    await this.request.post('/v1/tss/keygen/' + this.id + '/register', { partyId, partyPubKey: normalizedPubKey });
    const data = [this.id, partyId, this.chain, this.network, this.m, this.n, extra].join(':');
    const code = ECIES.encrypt({
      message: data,
      publicKey: normalizedPubKey,
      privateKey: this.requestPrivateKey,
      opts
    });
    // Only retain the assignment once the invitation was successfully produced.
    // Reissuing for the same party replaces its key (e.g. the creator corrected a mistyped key before delivery).
    this.#recipientKeys.set(partyId, normalizedPubKey);
    return code.toString(opts?.encoding || 'hex');
  }

  protected getDeliveryBindings(): DeliveryBindings {
    return { recipientKeys: new Map(this.#recipientKeys) };
  }

  protected setDeliveryBindings(bindings: DeliveryBindings): void {
    this.#recipientKeys = new Map(bindings.recipientKeys);
    this.#createdWallet = undefined;
  }

  protected applyTrustedInputs(
    trusted: CreatorRestoreTrustedInputs | undefined,
    restored: SessionParams,
    retained: DeliveryBindings
  ): DeliveryBindings {
    $.checkArgument(restored.partyId === 0, 'A creator instance can only restore a creator session (partyId 0)');
    if (retained.creatorPubKey != null) {
      throw new Error('Invalid session: the creator should not have a creator key');
    }
    for (const [recipient, key] of retained.recipientKeys) {
      if (recipient < 1 || recipient >= restored.n || !this.isNormalizedDeliveryKey(key)) {
        throw new Error('Invalid session: malformed delivery keys');
      }
    }
    const bindings: DeliveryBindings = { recipientKeys: new Map(retained.recipientKeys) };
    if (!trusted) return bindings;
    $.checkArgument(!trusted.joinCode, 'A join code can only be supplied when restoring a recipient\'s session');
    const suppliedRecipients = trusted.recipientKeys;
    if (suppliedRecipients) {
      $.checkArgument(Array.isArray(suppliedRecipients), 'recipientKeys must be an array');
      for (const { partyId, partyPubKey } of suppliedRecipients) {
        $.checkArgument(Number.isInteger(partyId) && partyId > 0 && partyId < restored.n, 'partyId must be an integer between 1 and n - 1');
        const key = normalizePubKey(partyPubKey, 'partyPubKey');
        const existing = bindings.recipientKeys.get(partyId);
        if (existing && existing !== key) {
          throw new Error(`Supplied public key for party ${partyId} does not match the retained key`);
        }
        bindings.recipientKeys.set(partyId, key);
      }
    }
    return bindings;
  }

  protected verifyOtherPartyBindings(expectKey: (partyId: number, trusted: string) => void): void {
    for (let partyId = 1; partyId < this.n; partyId++) {
      const trusted = this.#recipientKeys.get(partyId);
      if (!trusted) {
        throw new Error(`Missing trusted public key for party ${partyId}. Create a join code for this party first.`);
      }
      expectKey(partyId, trusted);
    }
  }

  subscribe(params: TssKeyGenCreatorSubscribeOptions = {}): NodeJS.Timeout {
    const { walletName, copayerName, createWalletOpts } = params;
    $.checkArgument(
      (walletName == null && copayerName == null) || (walletName && copayerName),
      'Both the walletName and copayerName must be provided if you wish to create the wallet in subscribe().'
    );
    return this.subscribeKeygen(params, () => this.createWallet({ walletName, copayerName, opts: createWalletOpts }));
  }

  /**
   * Create the wallet and publish its join secret, encrypted to each other party, to BWS.
   * Only the session creator (party 0) can do this, after the DKG is complete.
   *
   * If publishing fails, calling this again publishes the same wallet's secret again; it does not create another wallet.
   * That only holds within this instance: the created wallet is not persisted.
   */
  async createWallet(params: {
    walletName: string;
    copayerName: string;
    opts?: CreateWalletOpts & { addressType?: string };
  }) {
    const { walletName, copayerName, opts = {} } = params;
    const key = this.requireTssKey();
    $.checkState(this.partyId === 0, 'Only the session creator can create the wallet');

    // Checked before creating anything, since a wallet whose secret cannot be delivered would be left behind,
    // and again on every retry: createJoinCode() can replace a retained key in between.
    // Delivery is encrypted only to the keys that passed this check.
    let recipientKeys: Map<number, string>;
    try {
      recipientKeys = await this.#checkSessionKeys();
    } catch (err) {
      throw this.isRetryableDeliveryRequestError(err) ? err : this.stopOn(err);
    }

    if (!this.#createdWallet) {
      const client = this.createWalletClient(key);

      try {
        const created = await client.createWallet(
          walletName,
          copayerName,
          key.metadata.m,
          key.metadata.n,
          Object.assign({}, opts, {
            tssKeyId: this.id,
            chain: this.chain,
            network: this.network,
          })
        );

        if (!created?.wallet) {
          throw new Error('Wallet creation returned no wallet');
        }

        this.recordWallet(client, created.wallet, copayerName, walletName);
        this.#createdWallet = created;
      } catch (err) {
        // The wallet may or may not exist at BWS by now, and may not be recorded here, so a failure anywhere
        // from the request to recording the result must not be retried as another creation
        throw this.stopOn(err);
      }
    }

    const { wallet, secret } = this.#createdWallet;
    await this.#publishJoinDelivery(secret, key.keychain.commonKeyChain, recipientKeys);
    return wallet;
  }

  /**
   * Check the retained recipient keys against the request key each party enrolled in the session with at BWS.
   * The keys BWS reports are only compared against the retained ones, never used.
   * @returns The retained recipient keys as they were when checked
   */
  async #checkSessionKeys(): Promise<Map<number, string>> {
    // Round 0 holds each party's enrollment message, which carries its request key. BWS leaves out the caller's own.
    const { body } = await this.request.get(`/v1/tss/keygen/${this.id}/0`) as RequestResponse;
    const sessionKeys: Array<string> = [];
    for (const message of body.messages || []) {
      sessionKeys[message.partyId] = message.publicKey;
    }
    sessionKeys[this.partyId] = this.getAuthPublicKey();
    this.verifyDeliveryBindings(sessionKeys);
    // Taken in the same tick as the check, so later changes to the retained keys cannot slip in
    return new Map(this.#recipientKeys);
  }

  /**
   * Encrypt the join secret to each recipient's retained key and replace the published set at BWS.
   * The ciphertext is rebuilt (with fresh randomness) on every call. There is no fallback to plaintext delivery.
   */
  async #publishJoinDelivery(secret: string, commonKeyChain: string, recipientKeys: Map<number, string>) {
    const records: Array<{ partyId: number; encryptedMessage: string; signature: string }> = [];
    try {
      for (let partyId = 1; partyId < this.n; partyId++) {
        const requestPubKey = recipientKeys.get(partyId);
        if (!requestPubKey) {
          throw new Error(`Missing trusted public key for party ${partyId}. Create a join code for this party first.`);
        }
        const { encryptedMessage, signature } = encryptJoinDelivery({
          context: {
            sessionId: this.id,
            partyId,
            requestPubKey,
            chain: this.chain,
            network: this.network,
            m: this.m,
            n: this.n,
            commonKeyChain
          },
          secret,
          creatorPrivKey: this.requestPrivateKey
        });
        records.push({ partyId, encryptedMessage, signature });
      }
    } catch (err) {
      throw this.stopOn(err);
    }

    try {
      await this.request.post(`/v1/tss/keygen/${this.id}/join-delivery`, { version: JOIN_DELIVERY_VERSION, records });
    } catch (err) {
      throw this.isRetryableDeliveryRequestError(err) ? err : this.stopOn(err);
    }
  }

  cleanup(): void {
    this.#createdWallet = undefined;
    super.cleanup();
  }
}
