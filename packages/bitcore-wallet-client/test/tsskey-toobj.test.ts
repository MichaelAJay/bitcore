'use strict';

import * as chai from 'chai';
import { TssKey } from '../src/lib/tsskey';
import { Key } from '../src/lib/key';

const should = chai.should();

/**
 * C1 — TssKey.toObj() buffer serialization round-trip (active bug)
 *
 * JSON.stringify calls Buffer.toJSON() BEFORE the custom replacer,
 * so the replacer never sees a Buffer — it sees {type:"Buffer",data:[...]}.
 * The reviver never produces a Buffer because the serialized form is not `_0x<hex>`.
 */
describe('TssKey.toObj() buffer serialization', function () {
  const expectedPrivateKeyShareHex =
    'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233';
  const expectedReducedPrivateKeyShareHex =
    '11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd';

  function createTssKey(): TssKey {
    const key = new Key({ seedType: 'new' });
    return new TssKey({
      ...key.toObj(),
      keychain: {
        privateKeyShare: Buffer.from(expectedPrivateKeyShareHex, 'hex'),
        privateKeyShareEncrypted: null,
        reducedPrivateKeyShare: Buffer.from(expectedReducedPrivateKeyShareHex, 'hex'),
        reducedPrivateKeyShareEncrypted: null,
        commonKeyChain: '03' + 'aabbccdd00112233'.repeat(6),
      },
      metadata: { id: 'test-tss-id', m: 2, n: 3, partyId: 0 },
    });
  }

  function assertKeychainBuffers(tssKey: TssKey) {
    Buffer.isBuffer(tssKey.keychain.privateKeyShare).should.be.true;
    Buffer.isBuffer(tssKey.keychain.reducedPrivateKeyShare).should.be.true;
  }

  it('should return Buffer instances in the keychain after toObj()', function () {
    const tssKey = createTssKey();

    // — precondition: input keychain has proper Buffers —
    assertKeychainBuffers(tssKey);
    (tssKey.keychain.privateKeyShare as Buffer).toString('hex').should.equal(expectedPrivateKeyShareHex);
    (tssKey.keychain.reducedPrivateKeyShare as Buffer).toString('hex').should.equal(expectedReducedPrivateKeyShareHex);

    console.log('Preconditions confirmed for "should return Buffer instances in the keychain after toObj()"');

    const exported = tssKey.toObj();

    Buffer.isBuffer(exported.keychain.privateKeyShare).should.be.true;
    Buffer.isBuffer(exported.keychain.reducedPrivateKeyShare).should.be.true;
  });

  it('should preserve buffer contents after toObj()', function () {
    const tssKey = createTssKey();

    // — precondition —
    assertKeychainBuffers(tssKey);

    console.log('Preconditions confirmed for "should preserve buffer contents after toObj()"');

    const exported = tssKey.toObj();

    // — precondition for the assertion: toObj must have returned Buffers —
    const ps = exported.keychain.privateKeyShare as Buffer;
    const rps = exported.keychain.reducedPrivateKeyShare as Buffer;
    Buffer.isBuffer(ps).should.be.true;
    Buffer.isBuffer(rps).should.be.true;

    ps.toString('hex').should.equal(expectedPrivateKeyShareHex);
    rps.toString('hex').should.equal(expectedReducedPrivateKeyShareHex);
  });

  it('should survive a full JSON.stringify → JSON.parse round-trip', function () {
    const tssKey = createTssKey();

    // — precondition: input keychain has proper Buffers —
    assertKeychainBuffers(tssKey);

    console.log('Preconditions confirmed for "should survive a full JSON.stringify → JSON.parse round-trip"');

    const exported = tssKey.toObj();
    const serialized = JSON.stringify(exported);
    const loaded = JSON.parse(serialized);

    Buffer.isBuffer(loaded.keychain.privateKeyShare).should.be.true;
    Buffer.isBuffer(loaded.keychain.reducedPrivateKeyShare).should.be.true;

    const ps = loaded.keychain.privateKeyShare as Buffer;
    const rps = loaded.keychain.reducedPrivateKeyShare as Buffer;
    ps.toString('hex').should.equal(expectedPrivateKeyShareHex);
    rps.toString('hex').should.equal(expectedReducedPrivateKeyShareHex);
  });

  it('should allow constructing a new TssKey from toObj() output with valid Buffers', function () {
    const tssKey = createTssKey();

    // — precondition: input keychain has proper Buffers —
    assertKeychainBuffers(tssKey);

    console.log('Preconditions confirmed for "should allow constructing a new TssKey from toObj() output with valid Buffers"');

    const exported = tssKey.toObj();
    const reconstructed = new TssKey(exported);

    assertKeychainBuffers(reconstructed);
    (reconstructed.keychain.privateKeyShare as Buffer).toString('hex').should.equal(expectedPrivateKeyShareHex);
    (reconstructed.keychain.reducedPrivateKeyShare as Buffer).toString('hex').should.equal(expectedReducedPrivateKeyShareHex);
  });
});
