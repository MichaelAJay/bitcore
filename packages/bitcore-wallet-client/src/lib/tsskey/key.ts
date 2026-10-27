import { BitcoreLib } from '@bitpay-labs/crypto-wallet-core';
import { Encryption } from '../common';
import { Credentials } from '../credentials';
import { ExportedKey, Key, KeyAlgorithm, PasswordMaybe } from '../key';

export interface ITssKey extends Key {
  keychain: {
    privateKeyShare?: Buffer;
    privateKeyShareEncrypted?: string;
    reducedPrivateKeyShare?: Buffer;
    reducedPrivateKeyShareEncrypted?: string;
    commonKeyChain: string;
  };
  metadata: {
    id: string;
    m: number;
    n: number;
    partyId: number;
  };
};

export interface TssExportedKey extends ExportedKey {
  keychain: ITssKey['keychain'];
};

export class TssKey extends Key implements ITssKey {
  keychain: ITssKey['keychain'];
  metadata: ITssKey['metadata'];
  credentials: Credentials;
  tssXPubKey: string;

  constructor(obj: ITssKey) {
    super({ seedType: 'object', seedData: obj });
    this.keychain = obj.keychain;
    this.metadata = obj.metadata;
  }

  toObj(): ITssKey {
    return {
      ...super.toObj(),
      // Create de-referenced copies
      keychain: {
        privateKeyShare: this.keychain.privateKeyShare ? Buffer.from(this.keychain.privateKeyShare) : undefined,
        privateKeyShareEncrypted: this.keychain.privateKeyShareEncrypted,
        reducedPrivateKeyShare: this.keychain.reducedPrivateKeyShare ? Buffer.from(this.keychain.reducedPrivateKeyShare) : undefined,
        reducedPrivateKeyShareEncrypted: this.keychain.reducedPrivateKeyShareEncrypted,
        commonKeyChain: this.keychain.commonKeyChain
      } as ITssKey['keychain'],
      metadata: {
        id: this.metadata.id,
        m: this.metadata.m,
        n: this.metadata.n,
        partyId: this.metadata.partyId
      } as ITssKey['metadata']
    };
  }

  createCredentials(
    password: PasswordMaybe,
    opts: {
      chain?: string;
      coin?: string;
      network: string;
      account: number;
      addressType?: string;
      walletPrivKey?: string;
      algo?: 'EDDSA' | 'ECDSA';
    }
  ): Credentials {
    this.tssXPubKey = this.getXPubKey(opts.network);
    // n is always 1 for TSS keys since they act like single-sig wallets
    const c = super.createCredentials(password, { ...opts, n: 1, tssXPubKey: this.tssXPubKey });
    this.credentials = c;
    this.credentials.m = 1;
    return c;
  }

  getXPubKey(network?: string): string {
    const publicKey = this.keychain.commonKeyChain.substring(0, 66);
    const chainCode = this.keychain.commonKeyChain.substring(66);
    const xPubKey = new BitcoreLib.HDPublicKey({
      network: BitcoreLib.Networks.get(network) || 'testnet',
      depth: 0,
      parentFingerPrint: 0,
      childIndex: 0,
      publicKey,
      chainCode
    });
    return xPubKey.toString();
  }

  isKeyChainEncrypted(): boolean {
    return !!this.keychain.privateKeyShareEncrypted;
  }

  get(password: PasswordMaybe, algo?: KeyAlgorithm): TssExportedKey {
    const keyObj = {
      ...super.get(password, algo),
      keychain: !this.isKeyChainEncrypted() ? { ...this.keychain } : {
        privateKeyShare: Encryption.decryptWithPassword(this.keychain.privateKeyShareEncrypted, password),
        reducedPrivateKeyShare: Encryption.decryptWithPassword(this.keychain.reducedPrivateKeyShareEncrypted, password),
        commonKeyChain: this.keychain.commonKeyChain,
      }
    };
    return keyObj;
  }

  encrypt(password: string, opts?: { iter?: number; ks?: number }) {
    if (!this.isPrivKeyEncrypted()) {
      super.encrypt(password, opts);
    } else if (!this.checkPassword(password)) {
      throw new Error('Private key is already encrypted but with a different password');
    }
    if (this.isKeyChainEncrypted()) {
      throw new Error('Keychain is already encrypted');
    }
    this.keychain.privateKeyShareEncrypted = JSON.stringify(Encryption.encryptWithPassword(this.keychain.privateKeyShare, password, opts));
    this.keychain.reducedPrivateKeyShareEncrypted = JSON.stringify(Encryption.encryptWithPassword(this.keychain.reducedPrivateKeyShare, password, opts));
    // remove the private data
    this.keychain.privateKeyShare.fill(0);
    this.keychain.privateKeyShare = null;
    this.keychain.reducedPrivateKeyShare.fill(0);
    this.keychain.reducedPrivateKeyShare = null;
  }

  decrypt(password: string) {
    try {
      super.decrypt(password);
    } catch (e) {
      if (e.message !== 'Private key is not encrypted') {
        throw e;
      }
    }
    if (this.isKeyChainEncrypted()) {
      this.keychain.privateKeyShare = Encryption.decryptWithPassword(this.keychain.privateKeyShareEncrypted, password);
      this.keychain.reducedPrivateKeyShare = Encryption.decryptWithPassword(this.keychain.reducedPrivateKeyShareEncrypted, password);
      // remove the encrypted data
      this.keychain.privateKeyShareEncrypted = null;
      this.keychain.reducedPrivateKeyShareEncrypted = null;
    }
  }
};
