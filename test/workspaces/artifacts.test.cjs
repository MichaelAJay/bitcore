'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { runBuildStage, runTestFixturesStage } = require('../../scripts/workspaces/lib/artifacts.cjs');
const { makeTempDir, writePackage, writeJson, symlink } = require('./helpers.cjs');

function touch(filePath, content = '') {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
}

test('runBuildStage fails when a required TypeScript build artifact is missing', () => {
  const rootDir = makeTempDir('artifacts-ts-missing');
  writePackage(rootDir, 'packages/bitcore-logging', { name: '@bitpay-labs/bitcore-logging', version: '1.0.0' });
  touch(path.join(rootDir, 'packages/bitcore-logging/ts_build/src/index.js'));
  // index.d.ts intentionally omitted.
  const result = runBuildStage({ rootDir, workspaces: ['packages/bitcore-logging'] });
  assert.equal(result.ok, false);
  assert.ok(result.failures.some((f) => /index\.d\.ts/.test(f)));
});

test('runBuildStage passes once both required TypeScript build outputs exist', () => {
  const rootDir = makeTempDir('artifacts-ts-ok');
  writePackage(rootDir, 'packages/bitcore-logging', { name: '@bitpay-labs/bitcore-logging', version: '1.0.0' });
  touch(path.join(rootDir, 'packages/bitcore-logging/ts_build/src/index.js'));
  touch(path.join(rootDir, 'packages/bitcore-logging/ts_build/src/index.d.ts'));
  const result = runBuildStage({ rootDir, workspaces: ['packages/bitcore-logging'] });
  assert.equal(result.ok, true);
});

test('runBuildStage checks a generic JavaScript workspace entry point resolves locally', () => {
  const rootDir = makeTempDir('artifacts-generic');
  writePackage(rootDir, 'packages/plain-lib', { name: '@x/plain-lib', version: '1.0.0', main: 'index.js' });
  let result = runBuildStage({ rootDir, workspaces: ['packages/plain-lib'] });
  assert.equal(result.ok, false);
  assert.ok(result.failures.some((f) => /main.*does not resolve/.test(f)));

  touch(path.join(rootDir, 'packages/plain-lib/index.js'));
  result = runBuildStage({ rootDir, workspaces: ['packages/plain-lib'] });
  assert.equal(result.ok, true);
});

test('runBuildStage checks the CLI build entry, tracked launcher, and root .bin link', () => {
  const rootDir = makeTempDir('artifacts-cli');
  writePackage(rootDir, 'packages/bitcore-cli', { name: '@bitpay-labs/bitcore-cli', version: '1.0.0' });
  touch(path.join(rootDir, 'packages/bitcore-cli/build/src/cli.js'));
  const launcher = path.join(rootDir, 'packages/bitcore-cli/bin/bitcore-cli');
  touch(launcher, '#!/usr/bin/env node\nprocess.exit(0);\n');

  let result = runBuildStage({ rootDir, workspaces: ['packages/bitcore-cli'] });
  assert.equal(result.ok, false);
  assert.ok(result.failures.some((f) => /Root \.bin CLI executable was not linked/.test(f)));

  // Real npm links a workspace bin as a symlink to the package's declared
  // launcher file -- model that instead of an unrelated standalone file.
  const rootBin = path.join(rootDir, 'node_modules/.bin/bitcore-cli');
  symlink(launcher, rootBin);
  result = runBuildStage({ rootDir, workspaces: ['packages/bitcore-cli'] });
  assert.ok(result.failures.some((f) => /not executable/.test(f)));

  fs.chmodSync(launcher, 0o755);
  result = runBuildStage({ rootDir, workspaces: ['packages/bitcore-cli'] });
  assert.equal(result.ok, true);
});

test('runBuildStage fails when the root .bin executable does not target the tracked launcher', () => {
  const rootDir = makeTempDir('artifacts-cli-wrong-target');
  writePackage(rootDir, 'packages/bitcore-cli', { name: '@bitpay-labs/bitcore-cli', version: '1.0.0' });
  touch(path.join(rootDir, 'packages/bitcore-cli/build/src/cli.js'));
  touch(path.join(rootDir, 'packages/bitcore-cli/bin/bitcore-cli'), '#!/usr/bin/env node\n');
  // An unrelated executable sits at the root .bin location instead of a link
  // to the tracked launcher.
  const impostor = path.join(rootDir, 'impostor-bin');
  fs.writeFileSync(impostor, '#!/usr/bin/env node\n');
  fs.chmodSync(impostor, 0o755);
  const rootBin = path.join(rootDir, 'node_modules/.bin/bitcore-cli');
  fs.mkdirSync(path.dirname(rootBin), { recursive: true });
  fs.symlinkSync(impostor, rootBin);

  const result = runBuildStage({ rootDir, workspaces: ['packages/bitcore-cli'] });
  assert.equal(result.ok, false);
  assert.ok(result.failures.some((f) => /does not target the tracked launcher/.test(f)));
});

test('runBuildStage fails when the tracked CLI launcher exists on disk but is not tracked by git', () => {
  const rootDir = makeTempDir('artifacts-cli-untracked');
  execFileSync('git', ['init', '-q'], { cwd: rootDir });
  writePackage(rootDir, 'packages/bitcore-cli', { name: '@bitpay-labs/bitcore-cli', version: '1.0.0' });
  execFileSync('git', ['add', 'packages/bitcore-cli/package.json'], { cwd: rootDir });
  execFileSync(
    'git',
    ['-c', 'user.email=t@t.com', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'init'],
    { cwd: rootDir }
  );
  touch(path.join(rootDir, 'packages/bitcore-cli/build/src/cli.js'));
  const launcher = path.join(rootDir, 'packages/bitcore-cli/bin/bitcore-cli');
  touch(launcher, '#!/usr/bin/env node\nprocess.exit(0);\n');
  fs.chmodSync(launcher, 0o755);
  // Launcher exists on disk (e.g. regenerated by a build step) but was never
  // `git add`-ed.
  symlink(launcher, path.join(rootDir, 'node_modules/.bin/bitcore-cli'));

  const result = runBuildStage({ rootDir, workspaces: ['packages/bitcore-cli'] });
  assert.equal(result.ok, false);
  assert.ok(result.failures.some((f) => /not tracked by git/.test(f)));
});

test('runBuildStage fails when the root .bin CLI executable does not exit zero on --help', () => {
  const rootDir = makeTempDir('artifacts-cli-help-fails');
  writePackage(rootDir, 'packages/bitcore-cli', { name: '@bitpay-labs/bitcore-cli', version: '1.0.0' });
  touch(path.join(rootDir, 'packages/bitcore-cli/build/src/cli.js'));
  const launcher = path.join(rootDir, 'packages/bitcore-cli/bin/bitcore-cli');
  touch(launcher, '#!/usr/bin/env node\nprocess.exit(1);\n');
  fs.chmodSync(launcher, 0o755);
  symlink(launcher, path.join(rootDir, 'node_modules/.bin/bitcore-cli'));

  const result = runBuildStage({ rootDir, workspaces: ['packages/bitcore-cli'] });
  assert.equal(result.ok, false);
  assert.ok(result.failures.some((f) => /did not exit zero when run with `--help`/.test(f)));
});

test('runBuildStage checks node production/client-test-required outputs', () => {
  const rootDir = makeTempDir('artifacts-node');
  writePackage(rootDir, 'packages/bitcore-node', { name: '@bitpay-labs/bitcore-node', version: '1.0.0' });
  touch(path.join(rootDir, 'packages/bitcore-node/build/src/server.js'));
  touch(path.join(rootDir, 'packages/bitcore-node/build/src/services/api.js'));
  touch(path.join(rootDir, 'packages/bitcore-node/build/src/services/storage.js'));
  // build/src/modules/index.js intentionally omitted.
  const result = runBuildStage({ rootDir, workspaces: ['packages/bitcore-node'] });
  assert.equal(result.ok, false);
  assert.ok(result.failures.some((f) => /modules\/index\.js/.test(f)));
});

test('runBuildStage checks wallet-service worker entries and copied templates', () => {
  const rootDir = makeTempDir('artifacts-bws');
  const dir = path.join(rootDir, 'packages/bitcore-wallet-service');
  writePackage(rootDir, 'packages/bitcore-wallet-service', {
    name: '@bitpay-labs/bitcore-wallet-service',
    version: '1.0.0',
  });
  touch(path.join(dir, 'ts_build/src/index.js'));
  touch(path.join(dir, 'ts_build/src/index.d.ts'));
  touch(path.join(dir, 'ts_build/src/bws.js'));
  touch(path.join(dir, 'ts_build/src/messagebroker/messagebroker.js'));
  touch(path.join(dir, 'ts_build/src/bcmonitor/bcmonitor.js'));
  touch(path.join(dir, 'ts_build/src/emailservice/emailservice.js'));
  touch(path.join(dir, 'ts_build/src/pushnotificationsservice/pushnotificationsservice.js'));
  touch(path.join(dir, 'ts_build/src/fiatrateservice/fiatrateservice.js'));
  touch(path.join(dir, 'templates/en/master-template.html'));

  let result = runBuildStage({ rootDir, workspaces: ['packages/bitcore-wallet-service'] });
  assert.equal(result.ok, false);
  assert.ok(result.failures.some((f) => /template output directory was not produced/.test(f)));

  touch(path.join(dir, 'ts_build/templates/en/master-template.html'));
  result = runBuildStage({ rootDir, workspaces: ['packages/bitcore-wallet-service'] });
  assert.equal(result.ok, true);
});

test('runBuildStage fails when a manifest declares a `types` path that does not exist, even though the compiled index does', () => {
  const rootDir = makeTempDir('artifacts-types-typo');
  // Reproduces the real wallet-client defect: manifest declares the wrong
  // extension (`.d.js`) while the compiler actually emits `.d.ts`.
  writePackage(rootDir, 'packages/bitcore-wallet-client', {
    name: '@bitpay-labs/bitcore-wallet-client',
    version: '1.0.0',
    types: 'ts_build/src/index.d.js',
  });
  touch(path.join(rootDir, 'packages/bitcore-wallet-client/ts_build/src/index.js'));
  touch(path.join(rootDir, 'packages/bitcore-wallet-client/ts_build/src/index.d.ts'));
  const result = runBuildStage({ rootDir, workspaces: ['packages/bitcore-wallet-client'] });
  assert.equal(result.ok, false);
  assert.ok(result.failures.some((f) => /Declared package `types` does not resolve/.test(f)));
});

test('runBuildStage detects a template file nested in a locale subdirectory that was not copied', () => {
  const rootDir = makeTempDir('artifacts-templates-nested');
  const dir = path.join(rootDir, 'packages/bitcore-wallet-service');
  writePackage(rootDir, 'packages/bitcore-wallet-service', {
    name: '@bitpay-labs/bitcore-wallet-service',
    version: '1.0.0',
  });
  touch(path.join(dir, 'ts_build/src/index.js'));
  touch(path.join(dir, 'ts_build/src/index.d.ts'));
  touch(path.join(dir, 'ts_build/src/bws.js'));
  touch(path.join(dir, 'ts_build/src/messagebroker/messagebroker.js'));
  touch(path.join(dir, 'ts_build/src/bcmonitor/bcmonitor.js'));
  touch(path.join(dir, 'ts_build/src/emailservice/emailservice.js'));
  touch(path.join(dir, 'ts_build/src/pushnotificationsservice/pushnotificationsservice.js'));
  touch(path.join(dir, 'ts_build/src/fiatrateservice/fiatrateservice.js'));
  touch(path.join(dir, 'templates/en/master-template.html'), 'english');
  touch(path.join(dir, 'templates/es/master-template.html'), 'spanish');
  // The locale directory itself was created in the build output, but this
  // specific nested file inside it was not -- a shallow, directory-name-only
  // comparison would miss this.
  touch(path.join(dir, 'ts_build/templates/en/master-template.html'), 'english');
  fs.mkdirSync(path.join(dir, 'ts_build/templates/es'), { recursive: true });

  const result = runBuildStage({ rootDir, workspaces: ['packages/bitcore-wallet-service'] });
  assert.equal(result.ok, false);
  assert.ok(result.failures.some((f) => /missing files present \(possibly nested\)/.test(f)));
});

test('runTestFixturesStage rejects an unsupported workspace/stage combination', () => {
  const rootDir = makeTempDir('artifacts-fixture-unsupported');
  const result = runTestFixturesStage({ rootDir, workspace: '@bitpay-labs/bitcore-node' });
  assert.equal(result.ok, false);
  assert.match(result.failures[0], /requires a supported --workspace/);
});

test('runTestFixturesStage detects wallet-client test data copied with divergent content', () => {
  const rootDir = makeTempDir('artifacts-fixture-wc');
  const dir = path.join(rootDir, 'packages/bitcore-wallet-client');
  writePackage(rootDir, 'packages/bitcore-wallet-client', {
    name: '@bitpay-labs/bitcore-wallet-client',
    version: '1.0.0',
  });
  writeJson(path.join(dir, 'test/data/fixture.json'), { a: 1 });
  writeJson(path.join(dir, 'ts_build/test/data/fixture.json'), { a: 2 });

  let result = runTestFixturesStage({
    rootDir,
    workspace: '@bitpay-labs/bitcore-wallet-client',
    workspaces: ['packages/bitcore-wallet-client'],
  });
  assert.equal(result.ok, false);
  assert.ok(result.failures.some((f) => /content diverges/.test(f)));

  writeJson(path.join(dir, 'ts_build/test/data/fixture.json'), { a: 1 });
  result = runTestFixturesStage({
    rootDir,
    workspace: '@bitpay-labs/bitcore-wallet-client',
    workspaces: ['packages/bitcore-wallet-client'],
  });
  assert.equal(result.ok, true);
});

test('runTestFixturesStage detects CLI test wallets not yet copied', () => {
  const rootDir = makeTempDir('artifacts-fixture-cli');
  const dir = path.join(rootDir, 'packages/bitcore-cli');
  writePackage(rootDir, 'packages/bitcore-cli', { name: '@bitpay-labs/bitcore-cli', version: '1.0.0' });
  touch(path.join(dir, 'test/wallets/wallet1.dat'), 'wallet-data');

  const result = runTestFixturesStage({
    rootDir,
    workspace: '@bitpay-labs/bitcore-cli',
    workspaces: ['packages/bitcore-cli'],
  });
  assert.equal(result.ok, false);
  assert.ok(result.failures.some((f) => /not been copied|was not copied/.test(f)));
});
