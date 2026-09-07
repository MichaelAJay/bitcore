#!/usr/bin/env node
'use strict';

// Sequential compile runner (acceptance-spec §2). Invokes each compile-
// bearing workspace's own `compile` script, in the configured order, through
// `npm run compile --workspace=<name>` -- never `tsc` directly -- so each
// package keeps selecting its own compiler and lifecycle (CLI's postbuild
// launcher generation, wallet-service's template copying, ...). Stops
// before the next package after the first nonzero exit or signal; this is
// how bitcore-migration-plan.md's Task 1.3 keeps the seven-package build
// order explicit instead of relying on a workspace tool's own topological
// sort (see target-design item 8).
//
// This module is intentionally usable against any npm-workspaces root, not
// only this repository: `runSequentialCompile`/`runWorkspaceCompile` take an
// explicit `order` and `root`, so Phase 1 fixtures can exercise the real
// ordering/failure/signal-handling behavior against a disposable synthetic
// workspace tree without depending on this repository's own cutover to npm
// workspaces (not yet done -- see Task 2.1). Only `main()` below binds the
// real COMPILE_ORDER and this repository's root.

const { spawn } = require('child_process');
const path = require('path');
const { EXPECTED_WORKSPACES, COMPILE_ORDER } = require('./lib/constants.cjs');
const { checkCompileMembership } = require('./lib/manifests.cjs');
const { loadWorkspaceManifests } = require('./lib/util.cjs');

// Confirms exactly COMPILE_ORDER's packages declare a `compile` script,
// scanning EXPECTED_WORKSPACES's package.json files directly on disk. This
// works whether or not root workspace cutover (Task 2.1) has happened yet --
// it does not rely on `npm`'s own workspace discovery. Reuses
// checkCompileMembership (already exercised by test/workspaces/manifests.test.cjs)
// instead of re-implementing the same rule: "discovery must reject a new
// compile-bearing workspace until the explicit order is updated."
function checkDiscovery(rootDir) {
  const workspaceManifests = loadWorkspaceManifests(rootDir, EXPECTED_WORKSPACES);
  return checkCompileMembership(workspaceManifests);
}

// Runs one workspace's compile script to completion. Forwards SIGINT/SIGTERM
// received by this process to the child and waits for its real `exit` event
// before resolving, so an interrupted runner never leaves an orphaned
// compile running in the background and never reports done before the
// child has actually terminated.
function runWorkspaceCompile(name, { root, npmCommand = 'npm', spawnImpl = spawn } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawnImpl(npmCommand, ['run', 'compile', `--workspace=${name}`], {
      cwd: root,
      stdio: 'inherit',
      env: process.env,
    });

    // Tracks whether *this runner process* was asked to stop, independent of
    // how the child eventually exits. A child that handles the forwarded
    // signal gracefully mid cleanup and exits 0 (which is legitimate,
    // well-behaved child behavior, not a bug in the child) must still count
    // as an interruption here -- otherwise the sequence would read that as
    // an ordinary success and silently continue into dependents the caller
    // asked to stop before. `interruptedBy` is set the instant the signal is
    // received, before the child has had any chance to exit, so its value
    // reflects why the runner is stopping, not what the child's exit looked
    // like.
    let interruptedBy = null;
    const forward = (signal) => {
      interruptedBy = interruptedBy || signal;
      if (!child.killed) child.kill(signal);
    };
    process.on('SIGINT', forward);
    process.on('SIGTERM', forward);
    const stopForwarding = () => {
      process.removeListener('SIGINT', forward);
      process.removeListener('SIGTERM', forward);
    };

    child.on('error', (err) => {
      stopForwarding();
      reject(err);
    });
    child.on('exit', (code, signal) => {
      stopForwarding();
      resolve({ name, code, signal, interruptedBy });
    });
  });
}

// Runs every workspace in `order` in sequence, stopping before the next one
// after any nonzero exit code or termination-by-signal. `started` lists
// every workspace actually begun, in the order it was begun, so callers
// (including fixtures) can assert exactly which packages ran without
// relying on timing or log-scraping.
async function runSequentialCompile(order, opts) {
  const started = [];
  for (const name of order) {
    started.push(name);
    console.log(`[compile] ${name}`);
    const result = await runWorkspaceCompile(name, opts);
    // Checked first and independent of code/signal: the runner itself was
    // asked to stop, so this package's own exit outcome (even a clean 0)
    // must not be read as permission to continue into dependents.
    if (result.interruptedBy) {
      return {
        ok: false,
        started,
        failedName: name,
        code: result.code,
        signal: result.signal,
        interruptedBy: result.interruptedBy,
      };
    }
    if (result.signal) {
      return { ok: false, started, failedName: name, code: null, signal: result.signal, interruptedBy: null };
    }
    if (result.code !== 0) {
      return { ok: false, started, failedName: name, code: result.code, signal: null, interruptedBy: null };
    }
  }
  return { ok: true, started, failedName: null, code: 0, signal: null, interruptedBy: null };
}

async function main() {
  const rootDir = path.resolve(__dirname, '..', '..');

  const discoveryFailures = checkDiscovery(rootDir);
  if (discoveryFailures.length > 0) {
    console.error('[compile] Compile-bearing workspace set does not match the configured order:');
    for (const failure of discoveryFailures) console.error(failure);
    process.exitCode = 1;
    return;
  }

  const summary = await runSequentialCompile(COMPILE_ORDER, { root: rootDir });
  if (summary.ok) {
    console.log('[compile] All seven packages compiled successfully, in order.');
    return;
  }

  if (summary.interruptedBy) {
    console.error(`[compile] Received ${summary.interruptedBy}; stopped after ${summary.failedName}, before dependents.`);
    process.exitCode = 1;
    return;
  }
  if (summary.signal) {
    console.error(`[compile] ${summary.failedName} was terminated by ${summary.signal}; stopping before dependents.`);
    process.exitCode = 1;
    return;
  }
  console.error(`[compile] ${summary.failedName} exited with code ${summary.code}; stopping before dependents.`);
  process.exitCode = summary.code || 1;
}

module.exports = {
  checkDiscovery,
  runWorkspaceCompile,
  runSequentialCompile,
};

if (require.main === module) {
  main();
}
