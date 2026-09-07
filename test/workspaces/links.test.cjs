'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { findLexicalResolution, run } = require('../../scripts/workspaces/lib/links.cjs');
const { makeTempDir, writePackage, symlink } = require('./helpers.cjs');

const WORKSPACES = ['packages/lib', 'packages/consumer-a', 'packages/consumer-b'];

function baseFixture() {
  const rootDir = makeTempDir('links');
  writePackage(rootDir, 'packages/lib', { name: '@bitpay-labs/lib', version: '1.0.0' });
  writePackage(rootDir, 'packages/consumer-a', {
    name: '@bitpay-labs/consumer-a',
    version: '1.0.0',
    dependencies: { '@bitpay-labs/lib': '^1.0.0' },
  });
  writePackage(rootDir, 'packages/consumer-b', {
    name: '@bitpay-labs/consumer-b',
    version: '1.0.0',
    dependencies: { '@bitpay-labs/lib': '^1.0.0' },
  });
  return rootDir;
}

test('findLexicalResolution walks up to the first node_modules entry found', () => {
  const rootDir = makeTempDir('links-find');
  symlink(path.join(rootDir, 'target'), path.join(rootDir, 'node_modules/@bitpay-labs/lib'));
  fs.mkdirSync(path.join(rootDir, 'target'), { recursive: true });
  const found = findLexicalResolution(path.join(rootDir, 'packages/consumer'), '@bitpay-labs/lib');
  assert.equal(found, path.join(rootDir, 'node_modules/@bitpay-labs/lib'));
});

test('findLexicalResolution returns null when nothing resolves', () => {
  const rootDir = makeTempDir('links-none');
  const found = findLexicalResolution(path.join(rootDir, 'packages/consumer'), '@bitpay-labs/nonexistent');
  assert.equal(found, null);
});

test('run() passes when every consumer reaches one workspace through one shared root alias', () => {
  const rootDir = baseFixture();
  symlink(path.join(rootDir, 'packages/lib'), path.join(rootDir, 'node_modules/@bitpay-labs/lib'));
  const result = run({ rootDir, workspaces: WORKSPACES });
  assert.equal(result.ok, true);
  assert.deepEqual(result.failures, []);
});

test('run() fails when the same workspace is reachable through two distinct lexical aliases', () => {
  const rootDir = baseFixture();
  // Root-hoisted alias serves consumer-b...
  symlink(path.join(rootDir, 'packages/lib'), path.join(rootDir, 'node_modules/@bitpay-labs/lib'));
  // ...but consumer-a has its own nested alias to the same real target. Both
  // canonicalize identically; the lexical paths differ, which is exactly the
  // aliasing invariant this mode exists to catch.
  symlink(path.join(rootDir, 'packages/lib'), path.join(rootDir, 'packages/consumer-a/node_modules/@bitpay-labs/lib'));
  const result = run({ rootDir, workspaces: WORKSPACES });
  assert.equal(result.ok, false);
  assert.equal(result.failures.length, 1);
  assert.match(result.failures[0], /multiple distinct lexical symlink aliases/);
});

test('run() fails when a consumer resolves to the wrong physical package (registry substitute)', () => {
  const rootDir = baseFixture();
  const impostor = path.join(rootDir, 'impostor');
  fs.mkdirSync(impostor, { recursive: true });
  fs.writeFileSync(path.join(impostor, 'package.json'), JSON.stringify({ name: '@bitpay-labs/lib', version: '9.9.9' }));
  symlink(impostor, path.join(rootDir, 'node_modules/@bitpay-labs/lib'));
  const result = run({ rootDir, workspaces: WORKSPACES });
  assert.equal(result.ok, false);
  assert.ok(result.failures.some((f) => /unexpected package instance/.test(f)));
});

function baseFixtureWithEntryPoint() {
  const rootDir = makeTempDir('links-entry');
  writePackage(rootDir, 'packages/lib', { name: '@bitpay-labs/lib', version: '1.0.0', main: 'index.js' });
  writePackage(rootDir, 'packages/consumer-a', {
    name: '@bitpay-labs/consumer-a',
    version: '1.0.0',
    dependencies: { '@bitpay-labs/lib': '^1.0.0' },
  });
  return rootDir;
}

test('run() also resolves the target\'s declared entry point via consumer-originating Node resolution', () => {
  const rootDir = baseFixtureWithEntryPoint();
  fs.writeFileSync(path.join(rootDir, 'packages/lib/index.js'), 'module.exports = {};\n');
  symlink(path.join(rootDir, 'packages/lib'), path.join(rootDir, 'node_modules/@bitpay-labs/lib'));
  const result = run({ rootDir, workspaces: ['packages/lib', 'packages/consumer-a'] });
  assert.equal(result.ok, true);
  assert.deepEqual(result.failures, []);
});

test('run() fails when a target declares an entry point that does not actually resolve', () => {
  const rootDir = baseFixtureWithEntryPoint();
  // index.js is declared as `main` but was never built/committed.
  symlink(path.join(rootDir, 'packages/lib'), path.join(rootDir, 'node_modules/@bitpay-labs/lib'));
  const result = run({ rootDir, workspaces: ['packages/lib', 'packages/consumer-a'] });
  assert.equal(result.ok, false);
  assert.ok(result.failures.some((f) => /cannot resolve/.test(f)));
});

test('run() records both the lexical and canonical path for every internal edge, not only failing ones', () => {
  const rootDir = baseFixture();
  symlink(path.join(rootDir, 'packages/lib'), path.join(rootDir, 'node_modules/@bitpay-labs/lib'));
  const result = run({ rootDir, workspaces: WORKSPACES });
  assert.equal(result.ok, true);
  // Two consumers each declare the same dependency on lib.
  assert.equal(result.report.length, 2);
  for (const entry of result.report) {
    assert.equal(entry.workspace, '@bitpay-labs/lib');
    assert.equal(entry.ok, true);
    assert.equal(entry.lexicalPath, path.join(rootDir, 'node_modules/@bitpay-labs/lib'));
    assert.equal(entry.realPath, fs.realpathSync(path.join(rootDir, 'packages/lib')));
  }
});

test('run() fails when an internal dependency does not resolve at all', () => {
  const rootDir = baseFixture();
  // No node_modules/@bitpay-labs/lib anywhere -- dependency declared but unresolved.
  const result = run({ rootDir, workspaces: WORKSPACES });
  assert.equal(result.ok, false);
  assert.ok(result.failures.some((f) => /does not resolve from its consumer/.test(f)));
});
