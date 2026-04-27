'use strict';

const _ = require('lodash');
const BufferUtil = require('../util/buffer');
const JSUtil = require('../util/js');
const $ = require('../util/preconditions');
const BN = require('./bn');

function hasHighBitSet(value) {
  // eslint-disable-next-line no-bitwise
  return (value & 0x80) !== 0;
}

const Signature = function Signature(r, s, isSchnorr) {
  if (!(this instanceof Signature)) {
    return new Signature(r, s, isSchnorr);
  }
  if (r instanceof BN) {
    this.set({
      r: r,
      s: s,
      isSchnorr: isSchnorr,
    });
  } else if (r) {
    const obj = r;
    this.set(obj);
  }
};

/* jshint maxcomplexity: 7 */
Signature.prototype.set = function(obj) {
  this.r = obj.r || this.r || undefined;
  this.s = obj.s || this.s || undefined;

  this.i = typeof obj.i !== 'undefined' ? obj.i : this.i; // public key recovery parameter in range [0, 3]
  this.compressed = typeof obj.compressed !== 'undefined' ?
    obj.compressed : this.compressed; // whether the recovered pubkey is compressed
  this.isSchnorr = obj.isSchnorr || this.isSchnorr;
  this.nhashtype = obj.nhashtype || this.nhashtype || undefined;
  return this;
};

Signature.fromCompact = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf), 'Argument is expected to be a Buffer');

  const sig = new Signature();

  let compressed = true;
  let i = buf.slice(0, 1)[0] - 27 - 4;
  if (i < 0) {
    compressed = false;
    i = i + 4;
  }

  const b2 = buf.slice(1, 33);
  const b3 = buf.slice(33, 65);

  $.checkArgument(i === 0 || i === 1 || i === 2 || i === 3, new Error('i must be 0, 1, 2, or 3'));
  $.checkArgument(b2.length === 32, new Error('r must be 32 bytes'));
  $.checkArgument(b3.length === 32, new Error('s must be 32 bytes'));

  sig.compressed = compressed;
  sig.i = i;
  sig.r = BN.fromBuffer(b2);
  sig.s = BN.fromBuffer(b3);

  return sig;
};

Signature.fromDER = Signature.fromBuffer = function(buf, strict) {
  // Schnorr signatures are 64 bytes: r [len] 32 || s [len] 32
  //  There can be a 65th byte that is the nhashtype. It needs to be trimmed before calling this.
  if (buf.length === 64) {
    const obj = Signature.parseSchnorrEncodedSig(buf);
    const sig = new Signature();
    sig.r = obj.r;
    sig.s = obj.s;
    sig.isSchnorr = true;
    return sig;
  }
  
  const obj = Signature.parseDER(buf, strict);
  const sig = new Signature();

  sig.r = obj.r;
  sig.s = obj.s;

  return sig;
};

// The format used in a tx
Signature.fromTxFormat = function(buf) {
  const nhashtype = buf.readUInt8(buf.length - 1);
  const derbuf = buf.slice(0, buf.length - 1);
  const sig = new Signature.fromDER(derbuf, false);
  sig.nhashtype = nhashtype;
  return sig;
};


// The format used in a tx
Signature.fromDataFormat = function(buf) {
  const derbuf = buf.slice(0, buf.length);
  const sig = new Signature.fromDER(derbuf, false);
  return sig;
};


// This assumes the str is a raw signature DER and does not have nhashtype
// Use Signature.fromTxString when decoding a tx
Signature.fromString = function(str) {
  const buf = Buffer.from(str, 'hex');
  
  return Signature.fromDER(buf);
};

// Use this when decoding a tx signature string
Signature.fromTxString = function(str, encoding = 'hex') {
  return Signature.fromTxFormat(Buffer.from(str, encoding));
};


Signature.parseSchnorrEncodedSig = function(buf) {
  const r = buf.slice(0, 32);
  const s = buf.slice(32, 64);
  let hashtype;
  if (buf.length === 65) {
    hashtype = buf.slice(64, 65);
    this.nhashtype = hashtype;
  }

  const obj = {
    r: BN.fromBuffer(r),
    s: BN.fromBuffer(s),
    nhashtype: hashtype
  };

  return obj;
};

/**
 * In order to mimic the non-strict DER encoding of OpenSSL, set strict = false.
 */
Signature.parseDER = function(buf, strict) {
  $.checkArgument(BufferUtil.isBuffer(buf), new Error('DER formatted signature should be a buffer'));
  if (_.isUndefined(strict)) {
    strict = true;
  }

  const header = buf[0];
  $.checkArgument(header === 0x30, new Error('Header byte should be 0x30'));

  let length = buf[1];
  const buflength = buf.slice(2).length;
  $.checkArgument(!strict || length === buflength, new Error('Length byte should length of what follows'));

  length = length < buflength ? length : buflength;

  const rheader = buf[2 + 0];
  $.checkArgument(rheader === 0x02, new Error('Integer byte for r should be 0x02'));

  const rlength = buf[2 + 1];
  const rbuf = buf.slice(2 + 2, 2 + 2 + rlength);
  const r = BN.fromBuffer(rbuf);
  const rneg = buf[2 + 1 + 1] === 0x00 ? true : false;
  $.checkArgument(rlength === rbuf.length, new Error('Length of r incorrect'));

  const sheader = buf[2 + 2 + rlength + 0];
  $.checkArgument(sheader === 0x02, new Error('Integer byte for s should be 0x02'));

  const slength = buf[2 + 2 + rlength + 1];
  const sbuf = buf.slice(2 + 2 + rlength + 2, 2 + 2 + rlength + 2 + slength);
  const s = BN.fromBuffer(sbuf);
  const sneg = buf[2 + 2 + rlength + 2 + 2] === 0x00 ? true : false;
  $.checkArgument(slength === sbuf.length, new Error('Length of s incorrect'));

  const sumlength = 2 + 2 + rlength + 2 + slength;
  $.checkArgument(length === sumlength - 2, new Error('Length of signature incorrect'));

  const obj = {
    header: header,
    length: length,
    rheader: rheader,
    rlength: rlength,
    rneg: rneg,
    rbuf: rbuf,
    r: r,
    sheader: sheader,
    slength: slength,
    sneg: sneg,
    sbuf: sbuf,
    s: s
  };

  return obj;
};


Signature.prototype.toCompact = function(i, compressed) {
  i = typeof i === 'number' ? i : this.i;
  compressed = typeof compressed === 'boolean' ? compressed : this.compressed;

  if (!(i === 0 || i === 1 || i === 2 || i === 3)) {
    throw new Error('i must be equal to 0, 1, 2, or 3');
  }

  let val = i + 27 + 4;
  if (compressed === false) {
    val = val - 4;
  }
  const b1 = Buffer.from([val]);
  const b2 = this.r.toBuffer({
    size: 32
  });
  const b3 = this.s.toBuffer({
    size: 32
  });
  return Buffer.concat([b1, b2, b3]);
};

Signature.prototype.toBuffer = Signature.prototype.toDER = function() {

  // Schnorr signatures use a 64 byte r,s format, where as ECDSA takes the form decribed
  // below, above the isDER function signature.

  if (this.isSchnorr) {
    return Buffer.concat([this.r.toBuffer({ size: 32 }), this.s.toBuffer({ size: 32 })]);
  }

  const rnbuf = this.r.toBuffer();
  const snbuf = this.s.toBuffer();
  
  const rneg = hasHighBitSet(rnbuf[0]);
  const sneg = hasHighBitSet(snbuf[0]);

  const rbuf = rneg ? Buffer.concat([Buffer.from([0x00]), rnbuf]) : rnbuf;
  const sbuf = sneg ? Buffer.concat([Buffer.from([0x00]), snbuf]) : snbuf;

  const rlength = rbuf.length;
  const slength = sbuf.length;
  const length = 2 + rlength + 2 + slength;
  const rheader = 0x02;
  const sheader = 0x02;
  const header = 0x30;

  const der = Buffer.concat([Buffer.from([header, length, rheader, rlength]), rbuf, Buffer.from([sheader, slength]), sbuf]);
  return der;
};

Signature.prototype.toString = function() {
  const buf = this.toDER();
  return buf.toString('hex');
};


Signature.isTxDER = function(buf) {
  return Signature.isDER(buf.slice(0, buf.length-1));
};

/**
 * This function is translated from bitcoind's IsDERSignature and is used in
 * the script interpreter.  This "DER" format actually includes an extra byte,
 * the nhashtype, at the end. It is really the tx format, not DER format.
 *
 * A canonical signature exists of: [30] [total len] [02] [len R] [R] [02] [len S] [S]
 * Where R and S are not negative (their first byte has its highest bit not set), and not
 * excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
 * in which case a single 0 byte is necessary and even required).
 *
 * See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
 */
Signature.isDER = function(buf) {
  // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
  // * total-length: 1-byte length descriptor of everything that follows,
  // excluding the sighash byte.
  // * R-length: 1-byte length descriptor of the R value that follows.
  // * R: arbitrary-length big-endian encoded R value. It must use the
  // shortest possible encoding for a positive integers (which means no null
  // bytes at the start, except a single one when the next byte has its
  // highest bit set).
  // * S-length: 1-byte length descriptor of the S value that follows.
  // * S: arbitrary-length big-endian encoded S value. The same rules apply.

  // Minimum and maximum size constraints.
  if (buf.length < 8 || buf.length > 72) {
    return false;
  }

  //
  // Check that the signature is a compound structure of proper size.
  //

  // A signature is of type 0x30 (compound).
  if (buf[0] != 0x30) {
    return false;
  }

  // Make sure the length covers the entire signature.
  // Remove:
  // * 1 byte for the coupound type.
  // * 1 byte for the length of the signature.
  if (buf[1] != buf.length - 2) {
    return false;
  }

  //
  // Check that R is an positive integer of sensible size.
  //

  // Check whether the R element is an integer.
  if (buf[2] != 0x02) {
    return false;
  }

  // Extract the length of the R element.
  const lenR = buf[3];

  // Zero-length integers are not allowed for R.
  if (lenR == 0) {
    return false;
  }

  // Negative numbers are not allowed for R.
  if (hasHighBitSet(buf[4])) {
    return false;
  }

  // Make sure the length of the R element is consistent with the signature
  // size.
  // Remove:
  // * 1 byte for the coumpound type.
  // * 1 byte for the length of the signature.
  // * 2 bytes for the integer type of R and S.
  // * 2 bytes for the size of R and S.
  // * 1 byte for S itself.
  if (lenR > (buf.length - 7)) {
    return false;
  }

  // Null bytes at the start of R are not allowed, unless R would otherwise be
  // interpreted as a negative number.
  //
  // /!\ This check can only be performed after we checked that lenR is
  //     consistent with the size of the signature or we risk to access out of
  //     bound elements.
  if (lenR > 1 && (buf[4] == 0x00) && !hasHighBitSet(buf[5])) {
    return false;
  }

  //
  // Check that S is an positive integer of sensible size.
  //

  // S's definition starts after R's definition:
  // * 1 byte for the coumpound type.
  // * 1 byte for the length of the signature.
  // * 1 byte for the size of R.
  // * lenR bytes for R itself.
  // * 1 byte to get to S.
  const startS = lenR + 4;

  // Check whether the S element is an integer.
  if (buf[startS] != 0x02) {
    return false;
  }

  // Extract the length of the S element.
  const lenS = buf[startS + 1];

  // Zero-length integers are not allowed for S.
  if (lenS == 0) {
    return false;
  }

  // Negative numbers are not allowed for S.
  if (hasHighBitSet(buf[startS + 2])) {
    return false;
  }

  // Verify that the length of S is consistent with the size of the signature
  // including metadatas:
  // * 1 byte for the integer type of S.
  // * 1 byte for the size of S.
  if (startS + lenS + 2 != buf.length) {
    return false;
  }

  // Null bytes at the start of S are not allowed, unless S would otherwise be
  // interpreted as a negative number.
  //
  // /!\ This check can only be performed after we checked that lenR and lenS
  //     are consistent with the size of the signature or we risk to access
  //     out of bound elements.
  if (lenS > 1 && (buf[startS + 2] == 0x00) && !hasHighBitSet(buf[startS + 3])) {
    return false;
  }

  return true;
};

/**
 * Compares to bitcoind's IsLowDERSignature
 * See also ECDSA signature algorithm which enforces this.
 * See also BIP 62, "low S values in signatures"
 */
Signature.prototype.hasLowS = function() {
  if (this.s.lt(new BN(1)) ||
    this.s.gt(new BN('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0', 'hex'))) {
    return false;
  }
  return true;
};

/**
 * @returns true if the nhashtype is exactly equal to one of the standard options or combinations thereof.
 * Translated from bitcoind's IsDefinedHashtypeSignature
 */
Signature.prototype.hasDefinedHashtype = function() {
  if (!JSUtil.isNaturalNumber(this.nhashtype)) {
    return false;
  }
  // accept with or without Signature.SIGHASH_ANYONECANPAY by ignoring the bit
  // base mask was 1F
  // eslint-disable-next-line no-bitwise
  const mask = ~(Signature.SIGHASH_FORKID | Signature.SIGHASH_ANYONECANPAY) >>>0;
  // eslint-disable-next-line no-bitwise
  const temp = this.nhashtype & mask;
  if (temp < Signature.SIGHASH_ALL || temp > Signature.SIGHASH_SINGLE) {
    return false;
  }
  return true;
};

Signature.prototype.toTxFormat = function(signingMethod) {
  const derbuf = this.toDER(signingMethod);
  const buf = Buffer.alloc(1);
  buf.writeUInt8(this.nhashtype, 0);
  return Buffer.concat([derbuf, buf]);
};

Signature.SIGHASH_ALL = 0x01;
Signature.SIGHASH_NONE = 0x02;
Signature.SIGHASH_SINGLE = 0x03;
Signature.SIGHASH_FORKID = 0x40;
Signature.SIGHASH_ANYONECANPAY = 0x80;

module.exports = Signature;
