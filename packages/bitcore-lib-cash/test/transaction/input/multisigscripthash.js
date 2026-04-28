'use strict';
/* jshint unused: false */

const should = require('chai').should();
const expect = require('chai').expect;

const bitcore = require('../../..');

const Transaction = bitcore.Transaction;
const PrivateKey = bitcore.PrivateKey;
const Address = bitcore.Address;
const Script = bitcore.Script;
const Signature = bitcore.crypto.Signature;
const MultiSigScriptHashInput = bitcore.Transaction.Input.MultiSigScriptHash;

describe('MultiSigScriptHashInput', function() {

  const privateKey1 = new PrivateKey('KwF9LjRraetZuEjR8VqEq539z137LW5anYDUnVK11vM3mNMHTWb4');
  const privateKey2 = new PrivateKey('L4PqnaPTCkYhAqH3YQmefjxQP6zRcF4EJbdGqR8v6adtG9XSsadY');
  const privateKey3 = new PrivateKey('L4CTX79zFeksZTyyoFuPQAySfmP7fL3R41gWKTuepuN7hxuNuJwV');
  const public1 = privateKey1.publicKey;
  const public2 = privateKey2.publicKey;
  const public3 = privateKey3.publicKey;
  const address = new Address('H8piCq1XQrr3DbkPF5YFi5VdMV2mCQEnKW');

  const output = {
    address: 'H8piCq1XQrr3DbkPF5YFi5VdMV2mCQEnKW',
    txId: '66e64ef8a3b384164b78453fa8c8194de9a473ba14f89485a0e433699daec140',
    outputIndex: 0,
    script: new Script(address),
    satoshis: 1000000
  };
  it('can count missing signatures', function() {
    const transaction = new Transaction()
      .from(output, [public1, public2, public3], 2)
      .to(address, 1000000);
    const input = transaction.inputs[0];

    input.countSignatures().should.equal(0);

    transaction.sign(privateKey1);
    input.countSignatures().should.equal(1);
    input.countMissingSignatures().should.equal(1);
    input.isFullySigned().should.equal(false);

    transaction.sign(privateKey2);
    input.countSignatures().should.equal(2);
    input.countMissingSignatures().should.equal(0);
    input.isFullySigned().should.equal(true);
  });
  it('returns a list of public keys with missing signatures', function() {
    const transaction = new Transaction()
      .from(output, [public1, public2, public3], 2)
      .to(address, 1000000);
    const input = transaction.inputs[0];

    const toSortedPublicKeyStrings = function(publicKeys) {
      return publicKeys.map(function(publicKey) {
        return publicKey.toString();
      }).sort();
    };
    const allPublicKeys = toSortedPublicKeyStrings([public1, public2, public3]);
    toSortedPublicKeyStrings(input.publicKeysWithoutSignature()).should.deep.equal(allPublicKeys);

    transaction.sign(privateKey1);
    const remainingPublicKeys = toSortedPublicKeyStrings([public2, public3]);
    toSortedPublicKeyStrings(input.publicKeysWithoutSignature()).should.deep.equal(remainingPublicKeys);
  });
  it('can clear all signatures', function() {
    const transaction = new Transaction()
      .from(output, [public1, public2, public3], 2)
      .to(address, 1000000)
      .sign(privateKey1)
      .sign(privateKey2);

    const input = transaction.inputs[0];
    input.isFullySigned().should.equal(true);
    input.clearSignatures();
    input.isFullySigned().should.equal(false);
  });
  it('can estimate how heavy is the output going to be', function() {
    const transaction = new Transaction()
      .from(output, [public1, public2, public3], 2)
      .to(address, 1000000);
    const input = transaction.inputs[0];
    input._estimateSize().should.equal(297);
  });
  it('uses SIGHASH_ALL|FORKID by default', function() {
    const transaction = new Transaction()
      .from(output, [public1, public2, public3], 2)
      .to(address, 1000000);
    const input = transaction.inputs[0];
    const sigs = input.getSignatures(transaction, privateKey1, 0);
    // eslint-disable-next-line no-bitwise
    sigs[0].sigtype.should.equal(Signature.SIGHASH_ALL|Signature.SIGHASH_FORKID);
  });
  it('roundtrips to/from object', function() {
    const transaction = new Transaction()
      .from(output, [public1, public2, public3], 2)
      .to(address, 1000000)
      .sign(privateKey1);
    const input = transaction.inputs[0];
    const roundtrip = new MultiSigScriptHashInput(input.toObject());
    roundtrip.toObject().should.deep.equal(input.toObject());
  });
  it('roundtrips to/from object when not signed', function() {
    const transaction = new Transaction()
      .from(output, [public1, public2, public3], 2)
      .to(address, 1000000);
    const input = transaction.inputs[0];
    const roundtrip = new MultiSigScriptHashInput(input.toObject());
    roundtrip.toObject().should.deep.equal(input.toObject());
  });
  it('can build a redeem script from non-sorted public keys with a noSorting option', function() {
    const nonSortedPublicKeys = [public1, public2, public3];
    const threshold = 2;
    const opts = { noSorting: true };
    const nonSortedRedeemScript = Script.buildMultisigOut(nonSortedPublicKeys, threshold, opts);
    const nonSortedAddress = Address.payingTo(nonSortedRedeemScript);

    nonSortedAddress.toLegacyAddress().should.equal('HLEAcJ3iYF5sRGR4oSowZx5fuqigfD5Ah7');

    const nonSortedOutput = Object.assign({}, output, {
      address: nonSortedAddress.toLegacyAddress(),
      script: new Script(nonSortedAddress)
    });
    const transaction = new Transaction()
      .from(nonSortedOutput, nonSortedPublicKeys, threshold, opts)
      .to(address, 1000000);
    const input = transaction.inputs[0];

    input.redeemScript.equals(nonSortedRedeemScript).should.equal(true);
  });
});
