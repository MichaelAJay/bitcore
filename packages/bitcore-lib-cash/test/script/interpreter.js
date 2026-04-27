/* eslint-disable no-bitwise */
'use strict';

const should = require('chai').should();
const bitcore = require('../..');

const Interpreter = bitcore.Script.Interpreter;
const Transaction = bitcore.Transaction;
const Output = bitcore.Transaction.Output;
const PrivateKey = bitcore.PrivateKey;
const Script = bitcore.Script;
const BN = bitcore.crypto.BN;
const BufferReader = bitcore.encoding.BufferReader;
const BufferWriter = bitcore.encoding.BufferWriter;
const Opcode = bitcore.Opcode;
const _ = require('lodash');

const script_tests = require('../data/bitcoind/script_tests');
const tx_valid = require('../data/bitcoind/tx_valid');
const tx_invalid = require('../data/bitcoind/tx_invalid');
const vmb_tests = require('../data/libauth/vmb_tests');

// the script string format used in bitcoind data tests
Script.fromBitcoindString = function(str) {
  const bw = new BufferWriter();
  const tokens = str.split(' ');
  for (let i = 0; i < tokens.length; i++) {
    let token = tokens[i];
    if (token === '') {
      continue;
    }
    if (token === '-1') {
      token = '1NEGATE';
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
      const privateKey = new PrivateKey('cSBnVM4xvxarwGQuAfQFwqDg9k5tErHUHzgWsEfD4zdwUasvqRVY');
      const publicKey = privateKey.publicKey;
      const fromAddress = publicKey.toAddress();
      const toAddress = 'mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc';
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
        .sign(privateKey, 1);

      // we then extract the signature from the first input
      const inputIndex = 0;
      const signature = tx.getSignatures(privateKey, 1)[inputIndex].signature;

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

    if (flagstr.indexOf('CLEANSTACK') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_CLEANSTACK;
    }

    if (flagstr.indexOf('DISALLOW_SEGWIT_RECOVERY') !== -1) {
      flags = flags | Interpreter.SCRIPT_DISALLOW_SEGWIT_RECOVERY;
    }

    if (flagstr.indexOf('FORKID') !== -1) {
      flags = flags | Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID;
    }

    if (flagstr.indexOf('REPLAY_PROTECTION') !== -1) {
      flags = flags | Interpreter.SCRIPT_ENABLE_REPLAY_PROTECTION;
    }

    if (flagstr.indexOf('CHECKDATASIG') !== -1) {
      flags = flags | Interpreter.SCRIPT_ENABLE_CHECKDATASIG;
    }

    if (flagstr.indexOf('SCHNORR_MULTISIG') !== -1) {
      flags = flags | Interpreter.SCRIPT_ENABLE_SCHNORR_MULTISIG;
    }

    if (flagstr.indexOf('MINIMALIF') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_MINIMALIF;
    }

    if (flagstr.indexOf('64_BIT_INTEGERS') !== -1) {
      flags = flags | Interpreter.SCRIPT_64_BIT_INTEGERS;
    }

    if (flagstr.indexOf('INPUT_SIGCHECKS') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_INPUT_SIGCHECKS;
    }

    if (flagstr.indexOf('NATIVE_INTROSPECTION') !== -1) {
      flags = flags | Interpreter.SCRIPT_NATIVE_INTROSPECTION;
    }

    if (flagstr.indexOf('ENABLE_TOKENS') !== -1) {
      flags = flags | Interpreter.SCRIPT_ENABLE_TOKENS;
    }

    if (flagstr.indexOf('ENABLE_P2SH_32') !== -1) {
      flags = flags | Interpreter.SCRIPT_ENABLE_P2SH_32;
    }

    return flags;
  };


  const testToFromString = function(script) {
    const s = script.toString();
    Script.fromString(s).toString().should.equal(s);
  };

  const testFixture = function(vector, expected, extraData) {
  
    const scriptSig = Script.fromBitcoindString(vector[0]);
    const scriptPubkey = Script.fromBitcoindString(vector[1]);
    const flags = getFlags(vector[2]);
    let inputAmount = 0;
    if (extraData) {
      inputAmount = extraData[0] * 1e8;
    }

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
      satoshis: inputAmount,
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
      satoshis: inputAmount,
    }));

    const interp = new Interpreter();
    const verified = interp.verify(scriptSig, scriptPubkey, spendtx, 0, flags, new BN(inputAmount));
    verified.should.equal(expected);
  };
  describe('bitcoind script evaluation fixtures', function() {
    let c = 0;
    const l = script_tests.length;
    for (const vector of script_tests) {
      if (vector.length === 1) {
        continue;
      }
      c++;

      let extraData;
      if (Array.isArray(vector[0])) {
        extraData = vector.shift();
      }

      const fullScriptString = vector[0] + ' ' + vector[1];
      const expected = vector[3] == 'OK';
      const descstr = vector[4];
      const comment = descstr ? (' (' + descstr + ')') : '';
      const result = vector[3] == 'OK' ? 'PASS' : 'FAIL';
      const txt = `should ${result} script_tests vector #${c}/${l}: ${fullScriptString + comment}`;

      it(txt, function() {
        testFixture(vector, expected, extraData);
      });
    }
  });
  describe('libauth vmb evaluation fixtures', () => {
    const flags = getFlags('P2SH CLEANSTACK MINIMALDATA VERIFY_CHECKLOCKTIMEVERIFY NATIVE_INTROSPECTION 64_BIT_INTEGERS ENABLE_TOKENS ENABLE_P2SH_32');
    const getOutputsFromHex = outputsHex => {
      const reader = new BufferReader(Buffer.from(outputsHex, 'hex'));
      const numOutputs = reader.readVarintNum();
      const outputs = new Array(numOutputs).fill(1).map(() => Output.fromBufferReader(reader));
      return outputs;
    };
    for (const test of vmb_tests) {
      const testId = test[0];
      const txHex = test[4];
      const sourceOutputsHex = test[5];
      const labels = test[6];
      const inputIndex = test[7] || 0;
      it(`should pass vmb_tests vector ${testId}`, () => {
        const shouldFail = labels.includes('chip_cashtokens_invalid') || !labels.some(label => label.includes('cashtokens')) && labels.includes('2022_invalid');
        const expectedValidity = !shouldFail;
        let tx;
        try {
          tx = new Transaction(txHex);
        } catch (e) {
          false.should.equal(expectedValidity);
          return;
        }
        try {
          const outputs = getOutputsFromHex(sourceOutputsHex);
          for (let i = 0; i < tx.inputs.length; i++) {
            const input = tx.inputs[i];
            input.output = outputs[i];
          }
          tx.validateTokens();
        } catch (e) {
          false.should.equal(expectedValidity);
          return;
        }
        const scriptSig = tx.inputs[inputIndex].script;
        const scriptPubkey = tx.inputs[inputIndex].output.script;
        const interpreter = Interpreter();
        try {
          const valid = interpreter.verify(scriptSig, scriptPubkey, tx, inputIndex, flags);
          valid.should.equal(expectedValidity);
        } catch (err) {
          false.should.equal(expectedValidity);
        }
      });
    }
  });
  describe('bitcoind transaction evaluation fixtures', function() {
    const test_txs = function(set, expected) {
      for (let c = 0; c < set.length; c++) {
        const vector = set[c];
        if (vector.length === 1) {
          return;
        }

        const cc = c; // copy to local
        it('should pass tx_' + (expected ? '' : 'in') + 'valid vector ' + cc, function() {
          const inputs = vector[0];
          const txhex = vector[1];
  
          const flags = getFlags(vector[2]);
          const map = {};
          for (const input of inputs) {
            const txid = input[0];
            let txoutnum = input[1];
            const scriptPubKeyStr = input[2];
            if (txoutnum === -1) {
              txoutnum = 0xffffffff; // bitcoind casts -1 to an unsigned int
            }
            map[txid + ':' + txoutnum] = Script.fromBitcoindString(scriptPubKeyStr);
          }
  
          const tx = new Transaction(txhex);
          tx.setVersion(1);
          let allInputsVerified = true;
          tx.inputs.forEach(function(txin, j) {
            if (txin.isNull()) {
              return;
            }
            const scriptSig = txin.script;
            const txidhex = txin.prevTxId.toString('hex');
            const txoutnum = txin.outputIndex;
            const scriptPubkey = map[txidhex + ':' + txoutnum];
            should.exist(scriptPubkey);
            (scriptSig !== undefined).should.equal(true);
            const interp = new Interpreter();
            const verified = interp.verify(scriptSig, scriptPubkey, tx, j, flags);
            if (!verified) {
              allInputsVerified = false;
            }
          });
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
