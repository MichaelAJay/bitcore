'use strict';

const should = require('chai').should();
const bitcore = require('../..');

const Interpreter = bitcore.Script.Interpreter;
const Transaction = bitcore.Transaction;
const PrivateKey = bitcore.PrivateKey;
const Script = bitcore.Script;
const BN = bitcore.crypto.BN;
const BufferWriter = bitcore.encoding.BufferWriter;
const Opcode = bitcore.Opcode;
const _ = require('lodash');

const script_tests = require('../data/bitcoind/script_tests');
const tx_valid = require('../data/bitcoind/tx_valid');
const tx_invalid = require('../data/bitcoind/tx_invalid');

// the script string format used in bitcoind data tests
Script.fromBitcoindString = function(str) {
  const bw = new BufferWriter();
  const tokens = str.split(' ');
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token === '') {
      continue;
    }

    let opstr;
    let opcodenum;
    let tbuf;
    if (token[0] === '0' && token[1] === 'x') {
      const hex = token.slice(2);
      bw.write(Buffer.from(hex, 'hex'));
    } else if (token[0] === '\'') {
      const tstr = token.slice(1, token.length - 1);
      const cbuf = Buffer.from(tstr);
      tbuf = Script().add(cbuf).toBuffer();
      bw.write(tbuf);
    } else if (typeof Opcode['OP_' + token] !== 'undefined') {
      opstr = 'OP_' + token;
      opcodenum = Opcode[opstr];
      bw.writeUInt8(opcodenum);
    } else if (typeof Opcode[token] === 'number') {
      opstr = token;
      opcodenum = Opcode[opstr];
      bw.writeUInt8(opcodenum);
    } else if (!isNaN(parseInt(token))) {
      const script = Script().add(new BN(token).toScriptNumBuffer());
      tbuf = script.toBuffer();
      bw.write(tbuf);
    } else {
      console.log(str);
      throw new Error('Could not determine type of script value');
    }
  }
  const buf = bw.concat();
  return this.fromBuffer(buf);
};



describe('Interpreter', function() {

  it('should make a new interp', function() {
    const interp = new Interpreter();
    (interp instanceof Interpreter).should.equal(true);
    interp.stack.length.should.equal(0);
    interp.altstack.length.should.equal(0);
    interp.pc.should.equal(0);
    interp.pbegincodehash.should.equal(0);
    interp.nOpCount.should.equal(0);
    interp.vfExec.length.should.equal(0);
    interp.errstr.should.equal('');
    interp.flags.should.equal(0);
  });

  describe('@castToBool', function() {

    it('should cast these bufs to bool correctly', function() {
      Interpreter.castToBool(new BN(0).toSM({
        endian: 'little'
      })).should.equal(false);
      Interpreter.castToBool(Buffer.from('0080', 'hex')).should.equal(false); // negative 0
      Interpreter.castToBool(new BN(1).toSM({
        endian: 'little'
      })).should.equal(true);
      Interpreter.castToBool(new BN(-1).toSM({
        endian: 'little'
      })).should.equal(true);

      const buf = Buffer.from('00', 'hex');
      const bool = BN.fromSM(buf, {
        endian: 'little'
      }).cmp(BN.Zero) !== 0;
      Interpreter.castToBool(buf).should.equal(bool);
    });

  });

  describe('#verify', function() {

    it('should verify these trivial scripts', function() {
      let verified;
      const si = Interpreter();
      verified = si.verify(Script('OP_1'), Script('OP_1'));
      verified.should.equal(true);
      verified = Interpreter().verify(Script('OP_1'), Script('OP_0'));
      verified.should.equal(false);
      verified = Interpreter().verify(Script('OP_0'), Script('OP_1'));
      verified.should.equal(true);
      verified = Interpreter().verify(Script('OP_CODESEPARATOR'), Script('OP_1'));
      verified.should.equal(true);
      verified = Interpreter().verify(Script(''), Script('OP_DEPTH OP_0 OP_EQUAL'));
      verified.should.equal(true);
      verified = Interpreter().verify(Script('OP_1 OP_2'), Script('OP_2 OP_EQUALVERIFY OP_1 OP_EQUAL'));
      verified.should.equal(true);
      verified = Interpreter().verify(Script('9 0x000000000000000010'), Script(''));
      verified.should.equal(true);
      verified = Interpreter().verify(Script('OP_1'), Script('OP_15 OP_ADD OP_16 OP_EQUAL'));
      verified.should.equal(true);
      verified = Interpreter().verify(Script('OP_0'), Script('OP_IF OP_VER OP_ELSE OP_1 OP_ENDIF'));
      verified.should.equal(true);
    });

    it('should verify these simple transaction', function() {
      // first we create a transaction
      const privateKey = new PrivateKey('QRnivs36yg7VgWZZ3kqZzofXEaLh27X46zzAupJUpcqqybvHSjra');
      const publicKey = privateKey.publicKey;
      const fromAddress = publicKey.toAddress();
      const toAddress = 'DS1csbTjWURfExDwVKg12p9c8Vha6CGsG3';
      const scriptPubkey = Script.buildPublicKeyHashOut(fromAddress);
      const utxo = {
        address: fromAddress,
        txId: 'a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458',
        outputIndex: 0,
        script: scriptPubkey,
        satoshis: 100000
      };
      const tx = new Transaction()
        .from(utxo)
        .to(toAddress, 100000)
        .sign(privateKey);

      // we then extract the signature from the first input
      const inputIndex = 0;
      const signature = tx.getSignatures(privateKey)[inputIndex].signature;

      const scriptSig = Script.buildPublicKeyHashIn(publicKey, signature);
      const flags = Interpreter.SCRIPT_VERIFY_P2SH | Interpreter.SCRIPT_VERIFY_STRICTENC;
      const verified = Interpreter().verify(scriptSig, scriptPubkey, tx, inputIndex, flags);
      verified.should.equal(true);
    });
  });


  const getFlags = function getFlags(flagstr) {
    let flags = 0;
    if (flagstr.indexOf('NONE') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_NONE;
    }
    if (flagstr.indexOf('P2SH') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_P2SH;
    }
    if (flagstr.indexOf('STRICTENC') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_STRICTENC;
    }
    if (flagstr.indexOf('DERSIG') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_DERSIG;
    }
    if (flagstr.indexOf('LOW_S') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_LOW_S;
    }
    if (flagstr.indexOf('NULLDUMMY') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_NULLDUMMY;
    }
    if (flagstr.indexOf('SIGPUSHONLY') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_SIGPUSHONLY;
    }
    if (flagstr.indexOf('MINIMALDATA') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_MINIMALDATA;
    }
    if (flagstr.indexOf('DISCOURAGE_UPGRADABLE_NOPS') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
    }
    if (flagstr.indexOf('CHECKLOCKTIMEVERIFY') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }
    if (flagstr.indexOf('CHECKSEQUENCEVERIFY') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    }
    if (flagstr.indexOf('NULLFAIL') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_NULLFAIL;
    }

    if (flagstr.indexOf('WITNESS') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_WITNESS;
    }

    if (flagstr.indexOf('DISCOURAGE_UPGRADABLE_WITNESS') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
    }

    if (flagstr.indexOf('CLEANSTACK') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_CLEANSTACK;
    }

    if (flagstr.indexOf('WITNESS_PUBKEYTYPE') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_WITNESS_PUBKEYTYPE;
    }
    if (flagstr.indexOf('MINIMALIF') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_MINIMALIF;
    }

    return flags;
  };


  const testToFromString = function(script) {
    const s = script.toString();
    Script.fromString(s).toString().should.equal(s);
  };

  const testFixture = function(vector, expected, witness, amount) {
    amount = amount || 0;
    const scriptSig = Script.fromBitcoindString(vector[0]);
    const scriptPubkey = Script.fromBitcoindString(vector[1]);
    const flags = getFlags(vector[2]);

    const hashbuf = Buffer.alloc(32);
    hashbuf.fill(0);
    const credtx = new Transaction();
    credtx.setVersion(1);
    credtx.uncheckedAddInput(new Transaction.Input({
      prevTxId: '0000000000000000000000000000000000000000000000000000000000000000',
      outputIndex: 0xffffffff,
      sequenceNumber: 0xffffffff,
      script: Script('OP_0 OP_0')
    }));
    credtx.addOutput(new Transaction.Output({
      script: scriptPubkey,
      satoshis: amount
    }));
    const idbuf = credtx.id;

    const spendtx = new Transaction();
    spendtx.setVersion(1);
    spendtx.uncheckedAddInput(new Transaction.Input({
      prevTxId: idbuf.toString('hex'),
      outputIndex: 0,
      sequenceNumber: 0xffffffff,
      script: scriptSig
    }));
    spendtx.addOutput(new Transaction.Output({
      script: new Script(),
      satoshis: amount
    }));


    const interp = new Interpreter();
    const verified = interp.verify(scriptSig, scriptPubkey, spendtx, 0, flags, witness, amount);
    verified.should.equal(expected);
  };

  describe('bitcoind script evaluation fixtures', function() {
    const testAllFixtures = function(set) {

      
      let c = 0;
      for (const vector of set) {
        if (vector.length === 1) {
          continue;
        }
        c++;

        let witness, amount;
        if (_.isArray(vector[0])) {
          const extra = vector.shift();
          amount = extra.pop() * 1e8;
          witness = extra.map(function(x) { 
            return Buffer.from(x, 'hex');
          });
        } else {
          continue;
        }

        const fullScriptString = vector[0] + ' ' + vector[1];
        const expected = vector[3] == 'OK';
        const descstr = vector[4];

        const comment = descstr ? (' (' + descstr + ')') : '';
        it('should ' + vector[3] + ' script_tests ' +
          'vector #' + c + ': ' + fullScriptString + comment,
        function() {
          testFixture(vector, expected, witness, amount);
        });
      }
    };
    testAllFixtures(script_tests);

  });
  describe('bitcoind transaction evaluation fixtures', function() {
    const test_txs = function(set, expected) {
      let c = 0;
      let label = '';
      let runIdx = 1;  // Useful for debugging
      for (const [vIndex, vector] of set.entries()) {
        if (vector.length === 1) {
          continue;
        }
        c++;
        const cc = c; // copy to local
        if (set[vIndex - 1].length === 1) {
          label = set[vIndex - 1][0];
        }
        it('should pass tx_' + (expected ? '' : 'in') + 'valid vector ' + cc + ' -- ' + label, function() {
          runIdx++;
          const inputs = vector[0];
          const txhex = vector[1];
          const flags = getFlags(vector[2]);
        

          const map = {};
          const mapprevOutValues = {};
          for (const input of inputs) {
            const txid = input[0];
            let txoutnum = input[1];
            const scriptPubKeyStr = input[2];
            if (txoutnum === -1) {
              txoutnum = 0xffffffff; // bitcoind casts -1 to an unsigned int
            }
            map[txid + ':' + txoutnum] = Script.fromBitcoindString(scriptPubKeyStr);
            if (input.length >= 4) {
              mapprevOutValues[txid + ':' + txoutnum] = input[3];
            }
          }

          const tx = new Transaction(txhex);
          let allInputsVerified = true;
          for (const [j, txin] of tx.inputs.entries()) {
            if (txin.isNull()) {
              continue;
            }
            const scriptSig = txin.script;
            const txidhex = txin.prevTxId.toString('hex');
            const txoutnum = txin.outputIndex;
            const scriptPubkey = map[txidhex + ':' + txoutnum];
            const amount = mapprevOutValues[txidhex + ':' + txoutnum] || tx.outputAmount;
            should.exist(scriptPubkey);
            (scriptSig !== undefined).should.equal(true);
            const interp = new Interpreter();

            const txinWitnesses = txin.getWitnesses() || [];
            const verified = interp.verify(scriptSig, scriptPubkey, tx, j, flags, txinWitnesses, amount);
            if (!verified) {
              allInputsVerified = false;
            }
          }
          let txVerified = tx.verify();
          txVerified = (txVerified === true) ? true : false;
          allInputsVerified = allInputsVerified && txVerified;
          allInputsVerified.should.equal(expected);

        });
      }
    };
    test_txs(tx_valid, true);
    test_txs(tx_invalid, false);

  });

});
