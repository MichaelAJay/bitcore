import { expect } from 'chai';
import express from 'express';
import sinon from 'sinon';
import request from 'supertest';
import { set } from 'lodash';
import { BitcoreLib } from '@bitpay-labs/crypto-wallet-core';
import { ECIES } from '@bitpay-labs/bitcore-tss';
import { Utils } from '../src/lib/common/utils';
import { TssKeyGenModel } from '../src/lib/model/tsskeygen';
import { TssRouter } from '../src/lib/routes/tss';
import { WalletService } from '../src/lib/server';
import { Storage } from '../src/lib/storage';

describe('TSS wallet join compatibility', function() {
  const sandbox = sinon.createSandbox();
  const keys = [0, 1, 2].map(() => new BitcoreLib.PrivateKey());
  const participants = ['creator', 'joiner1', 'joiner2'];
  const path = '/v1/tss/keygen/session/secret';
  const legacySecret = 'legacy-wallet-join-secret';
  const delivery = {
    chain: 'eth',
    network: 'livenet',
    secrets: Object.fromEntries([1, 2].map(partyId => [partyId, ECIES.encrypt({
      message: 'encrypted-wallet-join-secret', publicKey: keys[partyId].publicKey, privateKey: keys[0], opts: { noKey: true }
    }).toString('hex')]))
  };
  let doc: any;
  let app: express.Express;
  let update: sinon.SinonStub;

  // Exercise the actual routes, request authentication, model hydration and storage
  // updates, with only the MongoDB collection replaced.
  beforeEach(function() {
    doc = {
      id: 'session', schemeVersion: 1.3, n: 3, participants,
      authPublicKeys: keys.map(k => k.publicKey.toString()),
      rounds: [keys.map((k, partyId) => ({
        fromPartyId: partyId,
        messages: { partyId, round: 0, publicKey: k.publicKey.toString(), broadcastMessages: [], p2pMessages: [] }
      }))],
      createdOn: Date.now(), timeLimit: 60_000, __v: 0
    };
    update = sandbox.stub().callsFake(async (filter, change) => {
      expect(filter).to.deep.equal({ id: doc.id });
      for (const [field, value] of Object.entries(change.$set)) {
        set(doc, field, value);
      }
      return { result: { ok: 1 } };
    });
    const collection = { findOne: async () => doc, updateOne: update };
    const storage = new Storage({ db: { collection: () => collection } as any });
    sandbox.stub(WalletService, 'getStorage').returns(storage);
    const router = new TssRouter({
      opts: { ignoreRateLimiter: true },
      returnError: (err, res) => res.status(400).json({ code: err.code, message: err.message })
    });
    app = express();
    app.use(express.json());
    app.use('/bws/api', router.router);
  });

  afterEach(function() {
    sandbox.restore();
  });

  function signed(method: 'get' | 'post', body = {}, partyId = 0, url = path) {
    const hash = Utils.hashMessage(`${method}|${url}|${JSON.stringify(body)}`, false);
    const signature = BitcoreLib.crypto.ECDSA.sign(hash, keys[partyId], { endian: 'little' }).toString();
    const req = request(app)[method]('/bws/api' + url)
      .set('x-identity', participants[partyId])
      .set('x-signature', signature);
    return method === 'post' ? req.send(body) : req;
  }

  function encryptedDelivery(partyId: number, chain = delivery.chain, network = delivery.network) {
    return signed('get', {}, partyId, `${path}?chain=${chain}&network=${network}`);
  }

  for (const version of [1, 1.1, 1.2]) {
    describe(`legacy scheme ${version}`, function() {
      beforeEach(function() {
        doc.schemeVersion = version;
        if (version < 1.2) delete doc.authPublicKeys;
      });

      it('accepts the old POST body and repeatedly returns the old GET shape to every participant', async function() {
        expect((await signed('post', { secret: legacySecret })).status).to.equal(200);
        expect(update.firstCall.args[1]).to.deep.equal({ $set: { bwsJoinSecret: legacySecret } });
        expect(doc).not.to.have.property('bwsJoinSecrets');
        for (let i = 0; i < 2; i++) {
          for (const partyId of [0, 1, 2]) {
            const res = await signed('get', {}, partyId);
            expect(res.status).to.equal(200);
            expect(res.body).to.deep.equal({ secret: legacySecret });
          }
        }
      });

      it('reads plaintext documents written before the server upgrade', async function() {
        doc.bwsJoinSecret = legacySecret;
        expect(TssKeyGenModel.fromObj(doc).bwsJoinSecret).to.equal(legacySecret);
        expect((await signed('get', {}, 1)).body).to.deep.equal({ secret: legacySecret });
        expect(update.called).to.equal(false);
      });

      it('rejects publication by a joiner', async function() {
        expect((await signed('post', { secret: legacySecret }, 1)).status).to.equal(400);
        expect(update.called).to.equal(false);
      });

      it('rejects missing or malformed secrets and the obsolete records-only body', async function() {
        for (const body of [{}, { secret: '' }, { secret: 1 }, { records: [] }]) {
          expect((await signed('post', body)).status).to.equal(400);
        }
        expect(update.called).to.equal(false);
      });
    });
  }

  it('serves the authenticated recipient its decryptable ciphertext for the requested wallet', async function() {
    expect((await signed('post', delivery)).status).to.equal(200);
    expect(TssKeyGenModel.fromObj(doc).bwsJoinSecrets).to.deep.equal({ 'eth:livenet': delivery.secrets });
    expect(doc).not.to.have.property('bwsJoinSecret');
    for (const partyId of [1, 2]) {
      const res = await encryptedDelivery(partyId);
      expect(res.status).to.equal(200);
      expect(res.body).to.deep.equal({ secret: delivery.secrets[partyId] });
      const decrypted = ECIES.decrypt({ payload: Buffer.from(res.body.secret, 'hex'), privateKey: keys[partyId], publicKey: keys[0].publicKey });
      expect(decrypted.toString()).to.equal('encrypted-wallet-join-secret');
    }
    expect((await encryptedDelivery(0)).status).to.equal(400);
  });

  it('retains the legacy secret contract even for scheme 1.3', async function() {
    expect((await signed('post', { secret: legacySecret })).status).to.equal(200);
    expect((await signed('get', {}, 1)).body).to.deep.equal({ secret: legacySecret });
  });

  it('never falls back to a plaintext secret when the requested chain delivery is absent', async function() {
    doc.bwsJoinSecret = legacySecret;
    const res = await encryptedDelivery(1);
    expect(res.status).to.equal(400);
    expect(res.body.code).to.equal('TSS_BWS_JOIN_SECRET_NOT_FOUND');
    expect(update.called).to.equal(false);
  });

  it('keeps legacy and encrypted sibling-wallet deliveries separate on a legacy session', async function() {
    doc.schemeVersion = 1.2;
    expect((await signed('post', delivery)).status).to.equal(200);
    expect((await signed('post', { secret: legacySecret })).status).to.equal(200);
    expect((await signed('get', {}, 1)).body).to.deep.equal({ secret: legacySecret });
    expect((await encryptedDelivery(1)).body).to.deep.equal({ secret: delivery.secrets[1] });
  });

  it('rejects encrypted publication by a joiner without changing the session', async function() {
    const before = JSON.stringify(doc);
    expect((await signed('post', delivery, 1)).status).to.equal(400);
    expect(JSON.stringify(doc)).to.equal(before);
    expect(update.called).to.equal(false);
  });

  it('keeps encrypted deliveries isolated by chain and network', async function() {
    expect((await signed('post', delivery)).status).to.equal(200);
    for (const [chain, network] of [['arb', 'livenet'], ['eth', 'testnet']]) {
      const res = await encryptedDelivery(1, chain, network);
      expect(res.status).to.equal(400);
      expect(res.body.code).to.equal('TSS_BWS_JOIN_SECRET_NOT_FOUND');
    }
  });

  it('allows authenticated publication and retrieval after key generation expires', async function() {
    doc.createdOn = Date.now() - 120_000;
    expect(TssKeyGenModel.fromObj(doc).isExpired()).to.equal(true);
    expect((await signed('post', delivery)).status).to.equal(200);
    expect((await encryptedDelivery(1)).body).to.deep.equal({ secret: delivery.secrets[1] });
    const res = await signed('get', {}, 1, '/v1/tss/keygen/session/0');
    expect(res.status).to.equal(400);
    expect(res.body.code).to.equal('TSS_SESSION_EXPIRED');
  });

  it('rejects callers whose request signature belongs to another participant', async function() {
    const req = signed('get', {}, 1).set('x-identity', participants[2]);
    expect((await req).status).to.equal(401);
  });

});
