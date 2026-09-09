#!/usr/bin/env node
'use strict';

// This command deliberately never invokes pub, publish, version, or tag.
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const semver = require('semver');
const { audit } = require('./audit-packed.cjs');
const baseline = require('./release-baseline.json');

const root = path.resolve(__dirname, '../..');

function run(args, options = {}) {
  const result = spawnSync('npm', args, { cwd: root, stdio: 'inherit', ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const error = new Error(`npm ${args.join(' ')} failed (${result.signal || result.status})`);
    error.exitCode = result.status || 1;
    throw error;
  }
  return result.stdout;
}

function checkManifest(manifest, expected) {
  assert.equal(manifest.private, undefined, `${expected.name}: private package`);
  assert.equal(manifest.name, expected.name);
  assert.equal(manifest.version, expected.version);
  assert.deepEqual(manifest.publishConfig ?? null, expected.publishConfig);
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const [name, range] of Object.entries(manifest[field] || {})) {
      assert(!/(?:file:|workspace:|link:|\/Users\/|\/bitcore\/)/.test(range), `${manifest.name}: ${name} has nonportable range ${range}`);
      if (name.startsWith('@bitpay-labs/')) assert(semver.validRange(range), `${manifest.name}: ${name} must use semver`);
    }
  }
}

function checkContents(manifest, files, directory) {
  const required = [manifest.main, manifest.types,
    ...Object.values(typeof manifest.bin === 'string' ? { bin: manifest.bin } : manifest.bin || {})].filter(Boolean);
  if (manifest.name === '@bitpay-labs/bitcore-build') required.push('karma.conf.js', 'wdio.conf.js');
  if (manifest.name === '@bitpay-labs/bitcore-wallet-service') {
    function walk(dir) {
      for (const entry of fs.readdirSync(path.join(directory, dir), { withFileTypes: true })) {
        const relative = `${dir}/${entry.name}`;
        if (entry.isDirectory()) walk(relative);
        else required.push(`ts_build/${relative}`);
      }
    }
    walk('templates');
  }
  for (const entry of required) assert(files.has(entry.replace(/^\.\//, '')), `${manifest.name}: tarball missing ${entry}`);
}

function main() {
  const args = process.argv.slice(2);
  assert(args.length === 0 || args.length === 1 && args[0].startsWith('--destination='), 'Usage: npm run artifacts:check -- [--destination=/absolute/path]');
  const destination = args.length ? path.resolve(args[0].slice('--destination='.length)) : fs.mkdtempSync(path.join(os.tmpdir(), 'bitcore-artifacts-'));
  fs.mkdirSync(destination, { recursive: true });
  const releaseOrder = fs.readFileSync(path.join(root, 'packages/pub'), 'utf8').match(/MODULES='([^']+)'/)[1].trim().split(/\s+/);
  assert.deepEqual(releaseOrder, baseline.releaseOrder, 'Release selection/order changed');
  const publicPaths = require('../../package.json').workspaces.filter(p => !require(path.join(root, p, 'package.json')).private).sort();
  assert.deepEqual(publicPaths, baseline.packages.map(p => p.directory).sort());
  for (const candidate of baseline.packages) checkManifest(require(path.join(root, candidate.directory, 'package.json')), candidate);
  run(['run', 'compile']);
  const artifacts = [];
  for (const candidate of baseline.packages) {
    for (const script of candidate.prepare) run(['run', script, `--workspace=${candidate.name}`]);
    const output = run(['pack', `--workspace=${candidate.name}`, `--pack-destination=${destination}`, '--json'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
    const [packed] = JSON.parse(output);
    const tarball = path.join(destination, packed.filename);
    const extracted = spawnSync('tar', ['-xOf', tarball, 'package/package.json'], { encoding: 'utf8' });
    assert.equal(extracted.status, 0, `Cannot read ${tarball}`);
    const manifest = JSON.parse(extracted.stdout);
    checkManifest(manifest, candidate);
    checkContents(manifest, new Set(packed.files.map(f => f.path)), path.join(root, candidate.directory));
    // Declared-dependency audit runs against the package's own source tree,
    // never against what the combined validation consumer happens to have
    // hoisted (see scripts/workspaces/audit-packed.cjs) -- a consumer
    // containing every tarball together could otherwise mask a genuinely
    // missing runtime dependency declaration.
    const { failures: auditFailures, exceptions: auditExceptions } = audit(path.join(root, candidate.directory));
    assert(auditFailures.length === 0, auditFailures.join('\n'));
    for (const exception of auditExceptions) console.log(`[artifacts:check] documented exception: ${exception}`);
    artifacts.push({ name: candidate.name, version: candidate.version, tarball });
    console.log(`[artifacts:check] ${candidate.name}: ${tarball}`);
  }
  fs.writeFileSync(path.join(destination, 'artifacts.json'), JSON.stringify(artifacts, null, 2) + '\n');
  console.log(`[artifacts:check] PASS: ${artifacts.length} packages; ${destination}/artifacts.json`);
}

module.exports = { checkManifest, checkContents };
if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = error.exitCode || 1; }
}
