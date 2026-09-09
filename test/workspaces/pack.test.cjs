'use strict';

const fs = require('fs');
const assert = require('node:assert/strict');
const test = require('node:test');
const path = require('path');
const { checkManifest, checkContents } = require('../../scripts/workspaces/pack.cjs');
const { makeTempDir } = require('./helpers.cjs');

function candidate(overrides = {}) {
  return {
    directory: 'packages/pkg',
    name: '@bitpay-labs/pkg',
    version: '1.0.0',
    publishConfig: null,
    prepare: [],
    ...overrides,
  };
}

function manifest(overrides = {}) {
  return {
    name: '@bitpay-labs/pkg',
    version: '1.0.0',
    ...overrides,
  };
}

test('checkManifest rejects a private package', () => {
  assert.throws(() => checkManifest(manifest({ private: true }), candidate()), /private package/);
});

test('checkManifest rejects a name or version mismatch against the recorded baseline', () => {
  assert.throws(() => checkManifest(manifest({ name: '@bitpay-labs/other' }), candidate()));
  assert.throws(() => checkManifest(manifest({ version: '2.0.0' }), candidate()));
});

test('checkManifest rejects a publishConfig that differs from the recorded baseline', () => {
  assert.throws(() =>
    checkManifest(manifest({ publishConfig: { access: 'restricted' } }), candidate({ publishConfig: null }))
  );
});

test('checkManifest rejects a workspace/file/link protocol on an internal dependency range', () => {
  for (const range of ['workspace:*', 'file:../bitcore-lib', 'link:../bitcore-lib']) {
    assert.throws(
      () => checkManifest(manifest({ dependencies: { '@bitpay-labs/bitcore-lib': range } }), candidate()),
      /nonportable range/
    );
  }
});

test('checkManifest rejects an absolute checkout path leaking into a dependency range', () => {
  assert.throws(
    () =>
      checkManifest(
        manifest({ dependencies: { '@bitpay-labs/bitcore-lib': '/Users/dev/bitcore/packages/bitcore-lib' } }),
        candidate()
      ),
    /nonportable range/
  );
});

test('checkManifest requires an internal @bitpay-labs/* range to be valid semver', () => {
  assert.throws(
    () => checkManifest(manifest({ dependencies: { '@bitpay-labs/bitcore-lib': 'not-a-semver-range' } }), candidate()),
    /must use semver/
  );
});

test('checkManifest passes a manifest matching its recorded candidate, internal ranges included', () => {
  assert.doesNotThrow(() =>
    checkManifest(manifest({ dependencies: { '@bitpay-labs/bitcore-lib': '^11.10.4' } }), candidate())
  );
});

test('checkContents fails when the declared `main` is missing from the packed file set', () => {
  const dir = makeTempDir('pack-contents-main-missing');
  assert.throws(
    () => checkContents(manifest({ main: 'index.js' }), new Set(['package.json']), dir),
    /tarball missing index\.js/
  );
});

test('checkContents passes once main, types, and every declared bin are present', () => {
  const dir = makeTempDir('pack-contents-ok');
  const files = new Set(['package.json', 'ts_build/src/index.js', 'ts_build/src/index.d.ts', 'bin/cli']);
  assert.doesNotThrow(() =>
    checkContents(
      manifest({ main: 'ts_build/src/index.js', types: 'ts_build/src/index.d.ts', bin: { pkg: './bin/cli' } }),
      files,
      dir
    )
  );
});

test('checkContents strips a leading "./" from declared paths before comparing against packed files', () => {
  const dir = makeTempDir('pack-contents-dotslash');
  const files = new Set(['package.json', 'ts_build/src/index.js']);
  assert.doesNotThrow(() => checkContents(manifest({ main: './ts_build/src/index.js' }), files, dir));
});

test('checkContents requires bitcore-build\'s shared browser configs alongside its main', () => {
  const dir = makeTempDir('pack-contents-bitcore-build');
  const pkg = manifest({ name: '@bitpay-labs/bitcore-build', main: 'index.js' });
  assert.throws(
    () => checkContents(pkg, new Set(['package.json', 'index.js']), dir),
    /tarball missing karma\.conf\.js/
  );
  assert.doesNotThrow(() =>
    checkContents(pkg, new Set(['package.json', 'index.js', 'karma.conf.js', 'wdio.conf.js']), dir)
  );
});

test('checkContents requires every file under wallet-service\'s real on-disk templates tree to also be packed', () => {
  const dir = makeTempDir('pack-contents-wallet-service-templates');
  fs.mkdirSync(path.join(dir, 'templates/en'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'templates/en/master-template.html'), 'hi');

  const pkg = manifest({ name: '@bitpay-labs/bitcore-wallet-service', main: 'ts_build/src/index.js' });
  assert.throws(
    () => checkContents(pkg, new Set(['package.json', 'ts_build/src/index.js']), dir),
    /tarball missing ts_build\/templates\/en\/master-template\.html/
  );
  assert.doesNotThrow(() =>
    checkContents(
      pkg,
      new Set(['package.json', 'ts_build/src/index.js', 'ts_build/templates/en/master-template.html']),
      dir
    )
  );
});
