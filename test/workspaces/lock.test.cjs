'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {
  checkLockfileVersion,
  checkRootDependencyDeclarationsMatchManifest,
  checkWorkspaceRecordsAndLinks,
  checkWorkspaceDependencyDeclarationsMatchManifest,
  checkNoBackendChildLocks,
  checkExcludedLocksPreserved,
  run,
} = require('../../scripts/workspaces/lib/lock.cjs');
const { makeTempDir, writePackage, writeJson } = require('./helpers.cjs');

const WORKSPACES = ['packages/a', 'packages/b'];

function baseFixture() {
  const rootDir = makeTempDir('lock');
  writePackage(rootDir, 'packages/a', { name: '@x/a', version: '1.0.0' });
  writePackage(rootDir, 'packages/b', { name: '@x/b', version: '1.0.0' });
  const lock = {
    lockfileVersion: 3,
    packages: {
      '': { name: 'root', version: '1.0.0' },
      'packages/a': { name: '@x/a', version: '1.0.0' },
      'packages/b': { name: '@x/b', version: '1.0.0' },
      'node_modules/@x/a': { resolved: 'packages/a', link: true },
      'node_modules/@x/b': { resolved: 'packages/b', link: true },
    },
  };
  return { rootDir, lock };
}

test('checkLockfileVersion fails on a non-v3 lock', () => {
  const failures = checkLockfileVersion({ lockfileVersion: 2 });
  assert.equal(failures.length, 1);
});

test('checkWorkspaceRecordsAndLinks passes for a correctly linked workspace', () => {
  const { rootDir, lock } = baseFixture();
  assert.deepEqual(checkWorkspaceRecordsAndLinks(rootDir, lock, WORKSPACES), []);
});

test('checkWorkspaceRecordsAndLinks fails when a workspace record is missing', () => {
  const { rootDir, lock } = baseFixture();
  delete lock.packages['packages/b'];
  const failures = checkWorkspaceRecordsAndLinks(rootDir, lock, WORKSPACES);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /no package record/);
});

test('checkWorkspaceRecordsAndLinks fails when the recorded version disagrees with the manifest', () => {
  const { rootDir, lock } = baseFixture();
  lock.packages['packages/a'].version = '9.9.9';
  const failures = checkWorkspaceRecordsAndLinks(rootDir, lock, WORKSPACES);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /version disagrees/);
});

test('checkWorkspaceRecordsAndLinks fails when the node_modules link entry is missing', () => {
  const { rootDir, lock } = baseFixture();
  delete lock.packages['node_modules/@x/a'];
  const failures = checkWorkspaceRecordsAndLinks(rootDir, lock, WORKSPACES);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /no node_modules link entry/);
});

test('checkWorkspaceRecordsAndLinks fails when the link entry resolves to the wrong path (registry substitution)', () => {
  const { rootDir, lock } = baseFixture();
  lock.packages['node_modules/@x/a'] = { resolved: '', integrity: 'sha512-fake', version: '1.0.0' };
  const failures = checkWorkspaceRecordsAndLinks(rootDir, lock, WORKSPACES);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /not a workspace link/);
});

test('checkWorkspaceDependencyDeclarationsMatchManifest passes when the lock mirrors the manifest exactly', () => {
  const { rootDir, lock } = baseFixture();
  lock.packages['packages/a'].dependencies = { leftpad: '^1.0.0' };
  writePackage(rootDir, 'packages/a', { name: '@x/a', version: '1.0.0', dependencies: { leftpad: '^1.0.0' } });
  assert.deepEqual(checkWorkspaceDependencyDeclarationsMatchManifest(rootDir, lock, WORKSPACES), []);
});

test('checkWorkspaceDependencyDeclarationsMatchManifest fails when the manifest gained a dependency the lock never recorded', () => {
  const { rootDir, lock } = baseFixture();
  // The lock still reflects the pre-edit manifest -- a classic stale lock,
  // even though the workspace's own name/version identity still matches.
  writePackage(rootDir, 'packages/a', { name: '@x/a', version: '1.0.0', dependencies: { leftpad: '^2.0.0' } });
  const failures = checkWorkspaceDependencyDeclarationsMatchManifest(rootDir, lock, WORKSPACES);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /is stale/);
  assert.match(failures[0], /packages\/a/);
});

test('checkWorkspaceDependencyDeclarationsMatchManifest fails when a dependency range was edited without regenerating the lock', () => {
  const { rootDir, lock } = baseFixture();
  lock.packages['packages/a'].dependencies = { leftpad: '^1.0.0' };
  writePackage(rootDir, 'packages/a', { name: '@x/a', version: '1.0.0', dependencies: { leftpad: '^2.0.0' } });
  const failures = checkWorkspaceDependencyDeclarationsMatchManifest(rootDir, lock, WORKSPACES);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /leftpad/);
});

test('checkRootDependencyDeclarationsMatchManifest passes when the root lock record mirrors root package.json exactly', () => {
  const rootDir = makeTempDir('lock-root-deps-ok');
  writeJson(path.join(rootDir, 'package.json'), { name: 'bitcore-monorepo', version: '1.0.0', dependencies: { semver: '^7.6.3' } });
  const lock = { packages: { '': { name: 'bitcore-monorepo', version: '1.0.0', dependencies: { semver: '^7.6.3' } } } };
  assert.deepEqual(checkRootDependencyDeclarationsMatchManifest(rootDir, lock), []);
});

test('checkRootDependencyDeclarationsMatchManifest fails when the root lock record disagrees with root package.json', () => {
  const rootDir = makeTempDir('lock-root-deps-stale');
  writeJson(path.join(rootDir, 'package.json'), { name: 'bitcore-monorepo', version: '1.0.0', dependencies: { semver: '^7.6.3' } });
  // The lock still reflects a stale root dependency range -- the same
  // scenario this task's own semver dependency actually hit.
  const lock = { packages: { '': { name: 'bitcore-monorepo', version: '1.0.0', dependencies: { semver: '^5.5.0' } } } };
  const failures = checkRootDependencyDeclarationsMatchManifest(rootDir, lock);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /disagrees with the root manifest/);
  assert.match(failures[0], /semver/);
});

test('checkRootDependencyDeclarationsMatchManifest fails when the lock has no root record at all', () => {
  const rootDir = makeTempDir('lock-root-record-missing');
  writeJson(path.join(rootDir, 'package.json'), { name: 'bitcore-monorepo', version: '1.0.0', dependencies: { semver: '^7.6.3' } });
  // Deleting the root record must not silently bypass root dependency
  // agreement -- it must fail, not fall through as "nothing to compare".
  const lock = { packages: {} };
  const failures = checkRootDependencyDeclarationsMatchManifest(rootDir, lock);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /no record for the root package/);
});

test('run() fails end-to-end when the root lock has no record for the root package', () => {
  const { rootDir, lock } = baseFixture();
  delete lock.packages[''];
  writeJson(path.join(rootDir, 'package-lock.json'), lock);
  const result = run({ rootDir, workspaces: WORKSPACES, excludedLocks: [] });
  assert.equal(result.ok, false);
  assert.ok(result.failures.some((f) => /no record for the root package/.test(f)));
});

test('run() fails end-to-end when the root lock record is stale relative to root package.json', () => {
  const { rootDir, lock } = baseFixture();
  writeJson(path.join(rootDir, 'package.json'), { name: 'root', version: '1.0.0', dependencies: { leftpad: '^2.0.0' } });
  lock.packages[''] = { name: 'root', version: '1.0.0', dependencies: { leftpad: '^1.0.0' } };
  writeJson(path.join(rootDir, 'package-lock.json'), lock);
  const result = run({ rootDir, workspaces: WORKSPACES, excludedLocks: [] });
  assert.equal(result.ok, false);
  assert.ok(result.failures.some((f) => /disagrees with the root manifest/.test(f)));
});

test('checkNoBackendChildLocks fails when a backend workspace kept its own lockfile', () => {
  const { rootDir } = baseFixture();
  writeJson(path.join(rootDir, 'packages/a/package-lock.json'), { lockfileVersion: 3 });
  const failures = checkNoBackendChildLocks(rootDir, WORKSPACES);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /still has its own child lockfile/);
});

test('checkNoBackendChildLocks passes when no backend child locks remain', () => {
  const { rootDir } = baseFixture();
  assert.deepEqual(checkNoBackendChildLocks(rootDir, WORKSPACES), []);
});

test('checkExcludedLocksPreserved fails when an excluded project lock was deleted', () => {
  const { rootDir } = baseFixture();
  const failures = checkExcludedLocksPreserved(rootDir, ['packages/insight-fixture/package-lock.json']);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /excluded project lockfile/);
});

test('checkExcludedLocksPreserved passes when the excluded lock still exists', () => {
  const { rootDir } = baseFixture();
  writeJson(path.join(rootDir, 'excluded/package-lock.json'), { lockfileVersion: 1 });
  assert.deepEqual(checkExcludedLocksPreserved(rootDir, ['excluded/package-lock.json']), []);
});

test('run() reports FAIL with no lockfile present', () => {
  const rootDir = makeTempDir('lock-missing');
  const result = run({ rootDir, workspaces: WORKSPACES, excludedLocks: [] });
  assert.equal(result.ok, false);
  assert.match(result.failures[0], /does not exist/);
});

test('run() passes end-to-end for a correctly assembled candidate lock', () => {
  const { rootDir, lock } = baseFixture();
  writeJson(path.join(rootDir, 'package-lock.json'), lock);
  const result = run({ rootDir, workspaces: WORKSPACES, excludedLocks: [] });
  assert.equal(result.ok, true);
  assert.deepEqual(result.failures, []);
});

test('run() fails end-to-end when the lock still describes the pre-migration (no-workspace) shape', () => {
  const rootDir = makeTempDir('lock-baseline');
  fs.mkdirSync(rootDir, { recursive: true });
  writeJson(path.join(rootDir, 'package-lock.json'), { lockfileVersion: 3, packages: { '': {} } });
  const result = run({ rootDir, workspaces: WORKSPACES, excludedLocks: [] });
  assert.equal(result.ok, false);
  assert.ok(result.failures.length >= WORKSPACES.length);
});
