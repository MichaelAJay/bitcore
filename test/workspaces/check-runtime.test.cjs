'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { evaluateRuntime } = require('../../scripts/workspaces/check-runtime.cjs');

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
