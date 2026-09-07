'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { EXPECTED_WORKSPACES, COMPILE_ORDER } = require('../../scripts/workspaces/lib/constants.cjs');
const {
  checkWorkspaceMembership,
  checkInternalRanges,
  checkForbiddenProtocols,
  checkCompileMembership,
  checkWorkspaceManifestsPresent,
  checkWorkspaceIdentities,
  run,
} = require('../../scripts/workspaces/lib/manifests.cjs');
const { loadWorkspaceManifests } = require('../../scripts/workspaces/lib/util.cjs');
const { makeTempDir, writePackage, writeJson } = require('./helpers.cjs');

test('checkWorkspaceMembership fails when workspaces is absent', () => {
  const failures = checkWorkspaceMembership({});
  assert.equal(failures.length, 1);
  assert.match(failures[0], /no `workspaces` array/);
});

test('checkWorkspaceMembership passes for the exact expected list', () => {
  const failures = checkWorkspaceMembership({ workspaces: EXPECTED_WORKSPACES });
  assert.deepEqual(failures, []);
});

test('checkWorkspaceMembership fails when Insight is accidentally included', () => {
  const failures = checkWorkspaceMembership({ workspaces: [...EXPECTED_WORKSPACES, 'packages/insight'] });
  assert.equal(failures.length, 1);
  assert.match(failures[0], /membership\/order does not match/);
});

test('checkWorkspaceMembership fails on a reordered list', () => {
  const reordered = [...EXPECTED_WORKSPACES].reverse();
  const failures = checkWorkspaceMembership({ workspaces: reordered });
  assert.equal(failures.length, 1);
});

test('checkInternalRanges fails when a consumer range excludes the local workspace version', () => {
  const rootDir = makeTempDir('manifests-range');
  writePackage(rootDir, 'packages/dep', { name: '@bitpay-labs/dep', version: '2.0.0' });
  writePackage(rootDir, 'packages/consumer', {
    name: '@bitpay-labs/consumer',
    version: '1.0.0',
    dependencies: { '@bitpay-labs/dep': '^1.0.0' },
  });
  const manifests = loadWorkspaceManifests(rootDir, ['packages/dep', 'packages/consumer']);
  const failures = checkInternalRanges(manifests);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /incompatible with the local workspace version/);
  assert.match(failures[0], /packages\/consumer/);
});

test('checkInternalRanges passes when the declared range is satisfied', () => {
  const rootDir = makeTempDir('manifests-range-ok');
  writePackage(rootDir, 'packages/dep', { name: '@bitpay-labs/dep', version: '1.2.3' });
  writePackage(rootDir, 'packages/consumer', {
    name: '@bitpay-labs/consumer',
    version: '1.0.0',
    dependencies: { '@bitpay-labs/dep': '^1.0.0' },
  });
  const manifests = loadWorkspaceManifests(rootDir, ['packages/dep', 'packages/consumer']);
  assert.deepEqual(checkInternalRanges(manifests), []);
});

test('checkForbiddenProtocols rejects workspace:/file:/* local specifiers', () => {
  const rootDir = makeTempDir('manifests-protocol');
  writePackage(rootDir, 'packages/dep', { name: '@bitpay-labs/dep', version: '1.0.0' });
  writePackage(rootDir, 'packages/consumer', {
    name: '@bitpay-labs/consumer',
    version: '1.0.0',
    dependencies: { '@bitpay-labs/dep': 'workspace:*' },
  });
  const manifests = loadWorkspaceManifests(rootDir, ['packages/dep', 'packages/consumer']);
  const failures = checkForbiddenProtocols(manifests);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /forbidden local specifier protocol/);
});

test('checkForbiddenProtocols accepts an ordinary semver range', () => {
  const rootDir = makeTempDir('manifests-protocol-ok');
  writePackage(rootDir, 'packages/dep', { name: '@bitpay-labs/dep', version: '1.0.0' });
  writePackage(rootDir, 'packages/consumer', {
    name: '@bitpay-labs/consumer',
    version: '1.0.0',
    dependencies: { '@bitpay-labs/dep': '^1.0.0' },
  });
  const manifests = loadWorkspaceManifests(rootDir, ['packages/dep', 'packages/consumer']);
  assert.deepEqual(checkForbiddenProtocols(manifests), []);
});

test('checkCompileMembership fails when a required compile-bearing package loses its script', () => {
  const rootDir = makeTempDir('manifests-compile-missing');
  const paths = [];
  for (const [i, name] of COMPILE_ORDER.entries()) {
    const workspacePath = `packages/p${i}`;
    paths.push(workspacePath);
    const isLastPackage = i === COMPILE_ORDER.length - 1;
    writePackage(rootDir, workspacePath, {
      name,
      version: '1.0.0',
      // Omit `compile` on the last configured package to simulate it
      // disappearing.
      scripts: isLastPackage ? {} : { compile: 'tsc' },
    });
  }
  const manifests = loadWorkspaceManifests(rootDir, paths);
  const failures = checkCompileMembership(manifests);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /no longer declares a `compile` script/);
});

test('checkCompileMembership fails when an unaccounted-for workspace gains a compile script', () => {
  const rootDir = makeTempDir('manifests-compile-extra');
  const paths = [];
  for (const [i, name] of COMPILE_ORDER.entries()) {
    const workspacePath = `packages/p${i}`;
    paths.push(workspacePath);
    writePackage(rootDir, workspacePath, { name, version: '1.0.0', scripts: { compile: 'tsc' } });
  }
  writePackage(rootDir, 'packages/extra', {
    name: '@bitpay-labs/extra',
    version: '1.0.0',
    scripts: { compile: 'tsc' },
  });
  paths.push('packages/extra');
  const manifests = loadWorkspaceManifests(rootDir, paths);
  const failures = checkCompileMembership(manifests);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /not part of the configured compile order/);
});

test('checkWorkspaceManifestsPresent fails when a declared workspace has no package.json on disk', () => {
  const rootDir = makeTempDir('manifests-missing-file');
  writePackage(rootDir, 'packages/a', { name: '@x/a', version: '1.0.0' });
  // packages/b is declared but its manifest was never written.
  const { failures, present } = checkWorkspaceManifestsPresent(rootDir, ['packages/a', 'packages/b']);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /no package\.json on disk/);
  assert.match(failures[0], /packages\/b/);
  assert.deepEqual(present, ['packages/a']);
});

test('checkWorkspaceManifestsPresent passes when every declared workspace has a manifest', () => {
  const rootDir = makeTempDir('manifests-present-ok');
  writePackage(rootDir, 'packages/a', { name: '@x/a', version: '1.0.0' });
  const { failures, present } = checkWorkspaceManifestsPresent(rootDir, ['packages/a']);
  assert.deepEqual(failures, []);
  assert.deepEqual(present, ['packages/a']);
});

test('run() fails on a missing workspace manifest instead of silently filtering it out', () => {
  const rootDir = makeTempDir('manifests-run-missing');
  writeJson(path.join(rootDir, 'package.json'), {
    name: 'x',
    workspaces: ['packages/a', 'packages/b'],
  });
  writePackage(rootDir, 'packages/a', { name: '@x/a', version: '1.0.0' });
  // packages/b is listed in `workspaces` but its package.json does not exist.
  const result = run({ rootDir, structureOnly: true });
  assert.equal(result.ok, false);
  assert.ok(result.failures.some((f) => /no package\.json on disk/.test(f) && /packages\/b/.test(f)));
});

test('checkWorkspaceIdentities fails when a manifest name disagrees with its directory-implied identity', () => {
  const rootDir = makeTempDir('manifests-identity');
  writePackage(rootDir, 'packages/bitcore-lib', { name: '@bitpay-labs/wrong-name', version: '1.0.0' });
  const manifests = loadWorkspaceManifests(rootDir, ['packages/bitcore-lib']);
  const failures = checkWorkspaceIdentities(manifests);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /does not match the package identity/);
});

test('checkWorkspaceIdentities passes when the manifest name matches the @bitpay-labs/<directory> convention', () => {
  const rootDir = makeTempDir('manifests-identity-ok');
  writePackage(rootDir, 'packages/bitcore-lib', { name: '@bitpay-labs/bitcore-lib', version: '1.0.0' });
  const manifests = loadWorkspaceManifests(rootDir, ['packages/bitcore-lib']);
  assert.deepEqual(checkWorkspaceIdentities(manifests), []);
});

test('checkCompileMembership passes when membership matches exactly', () => {
  const rootDir = makeTempDir('manifests-compile-ok');
  const paths = [];
  for (const [i, name] of COMPILE_ORDER.entries()) {
    const workspacePath = `packages/p${i}`;
    paths.push(workspacePath);
    writePackage(rootDir, workspacePath, { name, version: '1.0.0', scripts: { compile: 'tsc' } });
  }
  const manifests = loadWorkspaceManifests(rootDir, paths);
  assert.deepEqual(checkCompileMembership(manifests), []);
});
