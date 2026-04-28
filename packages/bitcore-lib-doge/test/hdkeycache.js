'use strict';

const _ = require('lodash');
const expect = require('chai').expect;
const bitcore = require('..');

const HDPrivateKey = bitcore.HDPrivateKey;

const xprivkey = 'xprv9s21ZrQH143K2n4rV4AtAJFptEmd1tNMKCcSyQBCSuN5eq1dCUhcv6KQJS49joRxu8NNdFxy8yuwTtzCPNYUZvVGC7EPRm2st2cvE7oyTbB';

describe('HDKey cache', function() {
  this.timeout(10000);

  /* jshint unused: false */
  const cache = bitcore._HDKeyCache;
  const master = new HDPrivateKey(xprivkey);

  beforeEach(function() {
    cache._cache = {};
    cache._count = 0;
    cache._eraseIndex = 0;
    cache._usedIndex = {};
    cache._usedList = {};
    cache._CACHE_SIZE = 3; // Reduce for quick testing
  });

  it('saves a derived key', function() {
    const child = master.deriveChild(0);
    expect(cache._cache[master.xprivkey + '/0/false'].xprivkey).to.equal(child.xprivkey);
  });
  it('starts erasing unused keys', function() {
    const child1 = master.deriveChild(0);
    const child2 = child1.deriveChild(0);
    const child3 = child2.deriveChild(0);
    expect(cache._cache[master.xprivkey + '/0/false'].xprivkey).to.equal(child1.xprivkey);
    const child4 = child3.deriveChild(0);
    expect(cache._cache[master.xprivkey + '/0/false']).to.equal(undefined);
  });
  it('avoids erasing keys that get cache hits ("hot keys")', function() {
    const child1 = master.deriveChild(0);
    const child2 = master.deriveChild(0).deriveChild(0);
    expect(cache._cache[master.xprivkey + '/0/false'].xprivkey).to.equal(child1.xprivkey);
    const child1_copy = master.deriveChild(0);
    expect(cache._cache[master.xprivkey + '/0/false'].xprivkey).to.equal(child1.xprivkey);
  });
  it('keeps the size of the cache small', function() {
    const child1 = master.deriveChild(0);
    const child2 = child1.deriveChild(0);
    const child3 = child2.deriveChild(0);
    const child4 = child3.deriveChild(0);
    expect(_.size(cache._cache)).to.equal(3);
  });
});
