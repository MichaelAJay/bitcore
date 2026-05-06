'use strict';

/* jshint unused: false */
const assert = require('assert');
const should = require('chai').should();
const expect = require('chai').expect;
const bitcore = require('..');

const errors = bitcore.errors;
const hdErrors = bitcore.errors.HDPublicKey;
const BufferUtil = bitcore.util.buffer;
const HDPrivateKey = bitcore.HDPrivateKey;
const HDPublicKey = bitcore.HDPublicKey;
const Base58Check = bitcore.encoding.Base58Check;
const Networks = bitcore.Networks;

const xprivkey = 'xprv9s21ZrQH143K31tyHAnPm2G7KxguGH32b928eMrkWUPhCXDzVE1sFp51hsVwWBmn6QzHLbcq8NNpD1WH9NNHGR99CyV9rW3Xr6cj2GV4tPV';
const xpubkey = 'xpub661MyMwAqRbcFVySPCKQ8ACqszXPfjksxMwjSkGN4ovg5KZ92mL7ocPVZArbpNm6x1gqZkqdthgdLg1EefyRHU1mQrp1k5NYFmd5hkkJgAw';
const xpubkeyTestnet = 'tpubD6NzVbkrYhZ4XYPZvipwgH4KsgXUDy6YdUCkqjSHxZjWBJkMLxAeAWpsAPExUFSjPiTf6xAGK21hhwCPtTSdHrkkHLQuW8c2mP7tQHJ8zrG';
const json = '{"network":"livenet","depth":0,"fingerPrint":-1457505106,"parentFingerPrint":0,"childIndex":0,"chainCode":"602e52a0b9a7730844e81a7faf6fb0e46514388b3dc7eddefc038165b4d430ad","publicKey":"0391822fb6dc1307a952e723d3deef6aeb38da447dae0eeb5aa272ef76e7f0b572","checksum":1280922356,"xpubkey":"xpub661MyMwAqRbcFVySPCKQ8ACqszXPfjksxMwjSkGN4ovg5KZ92mL7ocPVZArbpNm6x1gqZkqdthgdLg1EefyRHU1mQrp1k5NYFmd5hkkJgAw"}';
const derived_0_1_200000 = 'xpub6DR2ndWe682c9rmUdb4kdvTvbjkMmra9m7HqCwS4254Bgn1UeGQPTVYt9jQh7mA5RyU1f82icedfmxwQLLJZaxGXPfbeAjrM2Y9CbyinXnd';

describe('HDPublicKey interface', function() {

  const expectFail = function(func, errorType) {
    (function() {
      func();
    }).should.throw(errorType);
  };

  const expectDerivationFail = function(argument, error) {
    (function() {
      const pubkey = new HDPublicKey(xpubkey);
      pubkey.deriveChild(argument);
    }).should.throw(error);
  };

  const expectFailBuilding = function(argument, error) {
    (function() {
      return new HDPublicKey(argument);
    }).should.throw(error);
  };

  describe('creation formats', function() {

    it('returns same argument if already an instance of HDPublicKey', function() {
      const publicKey = new HDPublicKey(xpubkey);
      publicKey.should.equal(new HDPublicKey(publicKey));
    });

    it('returns the correct xpubkey for a xprivkey', function() {
      const publicKey = new HDPublicKey(xprivkey);
      publicKey.xpubkey.should.equal(xpubkey);
    });

    it('allows to call the argument with no "new" keyword', function() {
      HDPublicKey(xpubkey).xpubkey.should.equal(new HDPublicKey(xpubkey).xpubkey);
    });

    it('fails when user doesn\'t supply an argument', function() {
      expectFailBuilding(null, hdErrors.MustSupplyArgument);
    });

    it('should not be able to change read-only properties', function() {
      const publicKey = new HDPublicKey(xprivkey);
      expect(function() {
        publicKey.fingerPrint = 'notafingerprint';
      }).to.throw(TypeError);
    });

    it('doesn\'t recognize an invalid argument', function() {
      expectFailBuilding(1, hdErrors.UnrecognizedArgument);
      expectFailBuilding(true, hdErrors.UnrecognizedArgument);
    });


    describe('xpubkey string serialization errors', function() {
      it('fails on invalid length', function() {
        expectFailBuilding(
          Base58Check.encode(Buffer.from([1, 2, 3])),
          hdErrors.InvalidLength
        );
      });
      it('fails on invalid base58 encoding', function() {
        expectFailBuilding(
          xpubkey + '1',
          errors.InvalidB58Checksum
        );
      });
      it('user can ask if a string is valid', function() {
        (HDPublicKey.isValidSerialized(xpubkey)).should.equal(true);
      });
    });

    it('can be generated from a json', function() {
      expect(new HDPublicKey(JSON.parse(json)).xpubkey).to.equal(xpubkey);
    });

    it('can generate a json that has a particular structure', function() {
      assert.deepEqual(
        new HDPublicKey(JSON.parse(json)).toJSON(),
        new HDPublicKey(xpubkey).toJSON()
      );
    });

    it('builds from a buffer object', function() {
      (new HDPublicKey(new HDPublicKey(xpubkey)._buffers)).xpubkey.should.equal(xpubkey);
    });

    it('checks the checksum', function() {
      const buffers = new HDPublicKey(xpubkey)._buffers;
      buffers.checksum = BufferUtil.integerAsBuffer(1);
      expectFail(function() {
        return new HDPublicKey(buffers);
      }, errors.InvalidB58Checksum);
    });
  });

  describe('error checking on serialization', function() {
    const compareType = function(a, b) {
      expect(a instanceof b).to.equal(true);
    };
    it('throws invalid argument when argument is not a string or buffer', function() {
      compareType(HDPublicKey.getSerializedError(1), hdErrors.UnrecognizedArgument);
    });
    it('if a network is provided, validates that data corresponds to it', function() {
      compareType(HDPublicKey.getSerializedError(xpubkey, 'testnet'), errors.InvalidNetwork);
    });
    it('recognizes invalid network arguments', function() {
      compareType(HDPublicKey.getSerializedError(xpubkey, 'invalid'), errors.InvalidNetworkArgument);
    });
    it('recognizes a valid network', function() {
      expect(HDPublicKey.getSerializedError(xpubkey, 'livenet')).to.equal(null);
    });
  });

  it('toString() returns the same value as .xpubkey', function() {
    const pubKey = new HDPublicKey(xpubkey);
    pubKey.toString().should.equal(pubKey.xpubkey);
  });

  it('publicKey property matches network', function() {
    const livenet = new HDPublicKey(xpubkey);
    const testnet = new HDPublicKey(xpubkeyTestnet);

    livenet.publicKey.network.should.equal(Networks.livenet);
    testnet.publicKey.network.should.equal(Networks.testnet);
  });

  it('inspect() displays correctly', function() {
    const pubKey = new HDPublicKey(xpubkey);
    pubKey.inspect().should.equal('<HDPublicKey: ' + pubKey.xpubkey + '>');
  });

  describe('conversion to/from buffer', function() {

    it('should roundtrip to an equivalent object', function() {
      const pubKey = new HDPublicKey(xpubkey);
      const toBuffer = pubKey.toBuffer();
      const fromBuffer = HDPublicKey.fromBuffer(toBuffer);
      const roundTrip = new HDPublicKey(fromBuffer.toBuffer());
      roundTrip.xpubkey.should.equal(xpubkey);
    });
  });

  describe('conversion to different formats', function() {
    const plainObject = {
      network: 'livenet',
      depth: 0,
      fingerPrint: 2837462190, // unsigned (-1457505106 >>> 0)
      parentFingerPrint: 0,
      childIndex: 0,
      chainCode: '602e52a0b9a7730844e81a7faf6fb0e46514388b3dc7eddefc038165b4d430ad',
      publicKey: '0391822fb6dc1307a952e723d3deef6aeb38da447dae0eeb5aa272ef76e7f0b572',
      checksum: 1280922356,
      xpubkey: 'xpub661MyMwAqRbcFVySPCKQ8ACqszXPfjksxMwjSkGN4ovg5KZ92mL7ocPVZArbpNm6x1gqZkqdthgdLg1EefyRHU1mQrp1k5NYFmd5hkkJgAw'
    };
    it('roundtrips to JSON and to Object', function() {
      const pubkey = new HDPublicKey(xpubkey);
      expect(HDPublicKey.fromObject(pubkey.toJSON()).xpubkey).to.equal(xpubkey);
    });
    it('recovers state from Object', function() {
      new HDPublicKey(plainObject).xpubkey.should.equal(xpubkey);
    });
  });

  describe('derivation', function() {
    it('derivation is the same whether deriving with number or string', function() {
      const pubkey = new HDPublicKey(xpubkey);
      const derived1 = pubkey.deriveChild(0).deriveChild(1).deriveChild(200000);
      const derived2 = pubkey.deriveChild('m/0/1/200000');
      derived1.xpubkey.should.equal(derived_0_1_200000);
      derived2.xpubkey.should.equal(derived_0_1_200000);
    });

    it('allows special parameters m, M', function() {
      const expectDerivationSuccess = function(argument) {
        new HDPublicKey(xpubkey).deriveChild(argument).xpubkey.should.equal(xpubkey);
      };
      expectDerivationSuccess('m');
      expectDerivationSuccess('M');
    });

    it('doesn\'t allow object arguments for derivation', function() {
      expectFail(function() {
        return new HDPublicKey(xpubkey).deriveChild({});
      }, hdErrors.InvalidDerivationArgument);
    });

    it('needs first argument for derivation', function() {
      expectFail(function() {
        return new HDPublicKey(xpubkey).deriveChild('s');
      }, hdErrors.InvalidPath);
    });

    it('doesn\'t allow other parameters like m\' or M\' or "s"', function() {
      /* jshint quotmark: double */
      expectDerivationFail("m'", hdErrors.InvalidIndexCantDeriveHardened);
      expectDerivationFail("M'", hdErrors.InvalidIndexCantDeriveHardened);
      expectDerivationFail('1', hdErrors.InvalidPath);
      expectDerivationFail('S', hdErrors.InvalidPath);
    });

    it('can\'t derive hardened keys', function() {
      expectFail(function() {
        return new HDPublicKey(xpubkey).deriveChild(HDPublicKey.Hardened);
      }, hdErrors.InvalidIndexCantDeriveHardened);
    });

    it('can\'t derive hardened keys via second argument', function() {
      expectFail(function() {
        return new HDPublicKey(xpubkey).deriveChild(5, true);
      }, hdErrors.InvalidIndexCantDeriveHardened);
    });

    it('validates correct paths', function() {
      let valid;

      valid = HDPublicKey.isValidPath('m/123/12');
      valid.should.equal(true);

      valid = HDPublicKey.isValidPath('m');
      valid.should.equal(true);

      valid = HDPublicKey.isValidPath(123);
      valid.should.equal(true);
    });

    it('rejects illegal paths', function() {
      let valid;

      valid = HDPublicKey.isValidPath('m/-1/12');
      valid.should.equal(false);

      valid = HDPublicKey.isValidPath("m/0'/12");
      valid.should.equal(false);

      valid = HDPublicKey.isValidPath('m/8000000000/12');
      valid.should.equal(false);

      valid = HDPublicKey.isValidPath('bad path');
      valid.should.equal(false);

      valid = HDPublicKey.isValidPath(-1);
      valid.should.equal(false);

      valid = HDPublicKey.isValidPath(8000000000);
      valid.should.equal(false);

      valid = HDPublicKey.isValidPath(HDPublicKey.Hardened);
      valid.should.equal(false);
    });
  });
});
