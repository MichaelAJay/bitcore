import type { CreateWalletOpts } from '../api';
import type { Network } from '../common';
import type { Key } from '../key';
import type { Request } from '../request';

export interface ITssKeyGenConstructorParams {
  /**
   * Chain this key is for (e.g. 'btc', 'bch', 'eth')
   */
  chain: string;
  /**
   * Network this key is for (e.g. 'livenet', 'testnet', 'regtest')
   */
  network: Network;
  /**
   * URL of the BWS server
   */
  baseUrl: string;
  /**
   * Key used for seeding generation, signing, and encrypting payloads
   */
  key: Key;
  /**
   * Password for `key` (if encrypted)
   */
  password?: string;
  /**
   * Pre-defined Request object for making HTTP requests.
   * For testing only
   */
  request?: Request;
  /**
   * Backup your encrypted key share to the server.
   * This allows for portability and recoverability with your xPrivKey.
   * Default: false
   * DISABLED
   */
  // backupKeyShare?: boolean;
};

/** Options shared by invitation creation and reading. */
export interface JoinCodeOptions {
  /** Encoding for the join code (default: 'hex'). */
  encoding?: BufferEncoding;
  /** Omit the creator's public key from the invitation; reading then requires creatorPubKey. */
  noKey?: boolean;
}

export interface JoinCodeParams {
  /** The original recipient-specific invitation received from the creator. */
  code: string | Buffer;
  opts?: JoinCodeOptions;
  /**
   * The creator's getAuthPublicKey(), obtained from a trusted exchange.
   * Required for noKey invitations; otherwise, when supplied, pins the expected creator.
   */
  creatorPubKey?: string;
}

/** Trusted inputs always come from the original invitation exchange, never BWS. */
export interface CreatorRestoreTrustedInputs {
  /** The public key each recipient gave the creator, as passed to createJoinCode(). */
  recipientKeys: Array<{ partyId: number; partyPubKey: string }>;
  joinCode?: never;
}

export interface RecipientRestoreTrustedInputs {
  /** The original join code, with the same options used by joinKey(). */
  joinCode: JoinCodeParams;
  recipientKeys?: never;
}

export type RestoreTrustedInputs = CreatorRestoreTrustedInputs | RecipientRestoreTrustedInputs;

export interface TssKeyGenSubscribeOptions {
  /** Poll interval in milliseconds (default: 1000). */
  timeout?: number;
  /** Called on every successful iteration. */
  iterHandler?: () => void;
  /** Supply to create/join a wallet automatically; omit to generate only the TSS key. */
  copayerName?: string;
}

export interface TssKeyGenCreatorSubscribeOptions extends TssKeyGenSubscribeOptions {
  /** Supply together with copayerName to create a wallet after DKG. */
  walletName?: string;
  createWalletOpts?: CreateWalletOpts;
}

/** Authenticated ceremony parameters common to both session formats. */
export interface SessionParams {
  id: string;
  partyId: number;
  m: number;
  n: number;
}

/** Serialization boundary: each subclass owns and retains only its role's keys. */
export interface DeliveryBindings {
  creatorPubKey?: string;
  recipientKeys: Map<number, string>;
}

/** Encrypted session wrapper. Its wire format is unchanged by the role split. */
export interface SessionWrapper extends SessionParams {
  version: number;
  chain: string;
  network: string;
  requestPubKey: string;
  /** The legacy export: id:partyId:m:n:<DKG export>. */
  session: string;
  creatorPubKey?: string;
  recipientKeys: Array<{ partyId: number; pubKey: string }>;
}
