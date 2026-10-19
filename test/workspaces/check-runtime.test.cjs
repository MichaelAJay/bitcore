'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { evaluateRuntime, enforceRuntime } = require('../../scripts/workspaces/check-runtime.cjs');

test('accepts the exact supported Node 22 / npm 10.9.2 pair', () => {
  const result = evaluateRuntime({ nodeVersion: 'v22.16.0', npmVersion: '10.9.2' });
  assert.equal(result.ok, true);
  assert.deepEqual(result.problems, []);
});

test('rejects Node 20', () => {
  const result = evaluateRuntime({ nodeVersion: 'v20.11.0', npmVersion: '10.9.2' });
  assert.equal(result.ok, false);
  assert.match(result.problems.join('\n'), /Expected Node 22\.x, observed v20\.11\.0/);
});

test('rejects Node 24', () => {
  const result = evaluateRuntime({ nodeVersion: 'v24.0.0', npmVersion: '10.9.2' });
  assert.equal(result.ok, false);
  assert.match(result.problems.join('\n'), /Expected Node 22\.x, observed v24\.0\.0/);
});

test('rejects a mismatched npm version on Node 22', () => {
  const result = evaluateRuntime({ nodeVersion: 'v22.16.0', npmVersion: '10.8.0' });
  assert.equal(result.ok, false);
  assert.match(result.problems.join('\n'), /Expected npm 10\.9\.2 exactly, observed 10\.8\.0/);
});

test('rejects a missing/unidentified npm version', () => {
  const result = evaluateRuntime({ nodeVersion: 'v22.16.0', npmVersion: null });
  assert.equal(result.ok, false);
  assert.match(result.problems.join('\n'), /Unable to determine an installed npm version/);
});

test('rejects an unparseable Node version string', () => {
  const result = evaluateRuntime({ nodeVersion: 'not-a-version', npmVersion: '10.9.2' });
  assert.equal(result.ok, false);
  assert.match(result.problems.join('\n'), /Unable to parse Node version/);
});

test('enforceRuntime resolves npm from the user agent, reports problems, and does not set an exit code', () => {
  const errors = [];
  const result = enforceRuntime({
    env: { npm_config_user_agent: 'npm/0.0.0 node/v22.16.0 darwin arm64' },
    nodeVersion: 'v22.16.0',
    spawn: () => assert.fail('must not shell out when a user agent is present'),
    logError: (line) => errors.push(line),
  });
  assert.equal(result.ok, false);
  assert.match(errors.join('\n'), /Unsupported toolchain/);
  assert.match(errors.join('\n'), /observed 0\.0\.0/);
});

test('enforceRuntime falls back to `npm --version` and is silent when supported', () => {
  const errors = [];
  const result = enforceRuntime({
    env: {},
    nodeVersion: 'v22.16.0',
    spawn: () => ({ status: 0, stdout: '10.9.2\n' }),
    logError: (line) => errors.push(line),
  });
  assert.equal(result.ok, true);
  assert.deepEqual(errors, []);
});
