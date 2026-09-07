'use strict';

const fs = require('fs');
const path = require('path');
const { EXPECTED_WORKSPACES, EXCLUDED_PROJECT_LOCKS } = require('./constants.cjs');
const { readJsonIfExists, formatFailure } = require('./util.cjs');

const REQUIRED_LOCKFILE_VERSION = 3;

// npm mirrors each workspace's own dependency tables into its lock record
// (see the root "" record for a live example). Comparing those mirrored
// tables against the live manifest is what actually catches a stale lock: a
// workspace whose package.json gained/lost/re-ranged a dependency without
// the lock being regenerated still has a matching name/version identity, so
// identity alone is not sufficient evidence the lock reflects reality.
const DEPENDENCY_FIELDS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];

function diffDependencyTable(field, expectedTable, observedTable) {
  const expected = expectedTable || {};
  const observed = observedTable || {};
  const names = new Set([...Object.keys(expected), ...Object.keys(observed)]);
  const diffs = [];
  for (const name of names) {
    if (expected[name] !== observed[name]) {
      diffs.push({ field, name, expected: expected[name], observed: observed[name] });
    }
  }
  return diffs;
}

// Same staleness check as above, but for the root manifest/lock record
// itself (`lock.packages['']`) rather than a backend workspace -- a root
// dependency edited without regenerating the lock is exactly as stale as a
// workspace one, and root identity/version checks elsewhere never look at
// root's own dependency tables.
function checkRootDependencyDeclarationsMatchManifest(rootDir, lock) {
  const failures = [];
  const record = (lock.packages || {})[''];
  if (!record) {
    // Nothing else in this mode checks for the root record's existence --
    // without this, deleting it would silently bypass root dependency
    // agreement entirely rather than surfacing as a failure.
    failures.push(
      formatFailure({
        mode: 'lock',
        detail: 'Root lock has no record for the root package itself; root dependency agreement cannot be verified.',
        workspace: '(root)',
        expected: 'packages[""] present',
        observed: 'missing',
      })
    );
    return failures;
  }

  const manifest = readJsonIfExists(path.join(rootDir, 'package.json'));
  if (!manifest) return failures;

  for (const field of DEPENDENCY_FIELDS) {
    for (const diff of diffDependencyTable(field, manifest[field], record[field])) {
      failures.push(
        formatFailure({
          mode: 'lock',
          detail: `Root lock's recorded ${diff.field} disagrees with the root manifest -- the lock is stale.`,
          workspace: '(root)',
          expected: `${diff.name}: ${diff.expected === undefined ? '(absent)' : diff.expected}`,
          observed: `${diff.name}: ${diff.observed === undefined ? '(absent)' : diff.observed}`,
        })
      );
    }
  }
  return failures;
}

function checkWorkspaceDependencyDeclarationsMatchManifest(rootDir, lock, workspaces = EXPECTED_WORKSPACES) {
  const failures = [];
  const packages = lock.packages || {};
  for (const workspacePath of workspaces) {
    const record = packages[workspacePath];
    if (!record) continue; // already reported by checkWorkspaceRecordsAndLinks

    const manifest = readJsonIfExists(path.join(rootDir, workspacePath, 'package.json'));
    if (!manifest) continue;

    for (const field of DEPENDENCY_FIELDS) {
      for (const diff of diffDependencyTable(field, manifest[field], record[field])) {
        failures.push(
          formatFailure({
            mode: 'lock',
            detail: `Root lock's recorded ${diff.field} for a workspace disagrees with its manifest -- the lock is stale.`,
            workspace: workspacePath,
            expected: `${diff.name}: ${diff.expected === undefined ? '(absent)' : diff.expected}`,
            observed: `${diff.name}: ${diff.observed === undefined ? '(absent)' : diff.observed}`,
          })
        );
      }
    }
  }
  return failures;
}

function checkLockfileVersion(lock) {
  if (lock.lockfileVersion !== REQUIRED_LOCKFILE_VERSION) {
    return [
      formatFailure({
        mode: 'lock',
        detail: 'Root package-lock.json is not the required lockfile version.',
        expected: REQUIRED_LOCKFILE_VERSION,
        observed: lock.lockfileVersion,
      }),
    ];
  }
  return [];
}

// Confirms each expected workspace has both its own package record (the
// source of truth for name/version) and a `node_modules/<name>` link entry
// pointing back at it -- the shape npm produces for a real workspace member,
// as opposed to a hoisted registry copy.
function checkWorkspaceRecordsAndLinks(rootDir, lock, workspaces = EXPECTED_WORKSPACES) {
  const failures = [];
  const packages = lock.packages || {};
  for (const workspacePath of workspaces) {
    const record = packages[workspacePath];
    if (!record) {
      failures.push(
        formatFailure({
          mode: 'lock',
          detail: 'Root lock has no package record for an expected workspace.',
          workspace: workspacePath,
          expected: `packages["${workspacePath}"] present`,
          observed: 'missing',
        })
      );
      continue;
    }

    const manifestPath = path.join(rootDir, workspacePath, 'package.json');
    const manifest = readJsonIfExists(manifestPath);
    if (manifest) {
      if (record.name !== manifest.name) {
        failures.push(
          formatFailure({
            mode: 'lock',
            detail: 'Lock workspace record name disagrees with the workspace manifest.',
            workspace: workspacePath,
            expected: manifest.name,
            observed: record.name,
          })
        );
      }
      if (record.version !== manifest.version) {
        failures.push(
          formatFailure({
            mode: 'lock',
            detail: 'Lock workspace record version disagrees with the workspace manifest.',
            workspace: workspacePath,
            expected: manifest.version,
            observed: record.version,
          })
        );
      }
    }

    const name = record.name || (manifest && manifest.name);
    if (!name) continue;
    const linkKey = `node_modules/${name}`;
    const link = packages[linkKey];
    if (!link) {
      failures.push(
        formatFailure({
          mode: 'lock',
          detail: 'Root lock has no node_modules link entry for an expected workspace.',
          workspace: workspacePath,
          expected: `packages["${linkKey}"] present with link: true`,
          observed: 'missing',
        })
      );
      continue;
    }
    if (link.link !== true || link.resolved !== workspacePath) {
      failures.push(
        formatFailure({
          mode: 'lock',
          detail: 'Root lock node_modules entry for a workspace is not a workspace link to the expected path.',
          workspace: workspacePath,
          expected: { link: true, resolved: workspacePath },
          observed: { link: link.link, resolved: link.resolved },
        })
      );
    }
  }
  return failures;
}

function checkNoBackendChildLocks(rootDir, workspaces = EXPECTED_WORKSPACES) {
  const failures = [];
  for (const workspacePath of workspaces) {
    const childLock = path.join(rootDir, workspacePath, 'package-lock.json');
    if (fs.existsSync(childLock)) {
      failures.push(
        formatFailure({
          mode: 'lock',
          detail: 'A backend workspace still has its own child lockfile; only the root lock should own installation.',
          workspace: workspacePath,
          expected: 'no package-lock.json',
          observed: path.relative(rootDir, childLock),
        })
      );
    }
  }
  return failures;
}

function checkExcludedLocksPreserved(rootDir, excludedLocks = EXCLUDED_PROJECT_LOCKS) {
  const failures = [];
  for (const relPath of excludedLocks) {
    if (!fs.existsSync(path.join(rootDir, relPath))) {
      failures.push(
        formatFailure({
          mode: 'lock',
          detail: 'An excluded project lockfile that must remain independent is missing.',
          expected: relPath,
          observed: 'missing',
        })
      );
    }
  }
  return failures;
}

function run({ rootDir, workspaces = EXPECTED_WORKSPACES, excludedLocks = EXCLUDED_PROJECT_LOCKS }) {
  const lockPath = path.join(rootDir, 'package-lock.json');
  const lock = readJsonIfExists(lockPath);
  if (!lock) {
    return {
      ok: false,
      failures: [
        formatFailure({
          mode: 'lock',
          detail: 'Root package-lock.json does not exist.',
          expected: lockPath,
          observed: 'missing',
        }),
      ],
    };
  }

  const failures = [
    ...checkLockfileVersion(lock),
    ...checkRootDependencyDeclarationsMatchManifest(rootDir, lock),
    ...checkWorkspaceRecordsAndLinks(rootDir, lock, workspaces),
    ...checkWorkspaceDependencyDeclarationsMatchManifest(rootDir, lock, workspaces),
    ...checkNoBackendChildLocks(rootDir, workspaces),
    ...checkExcludedLocksPreserved(rootDir, excludedLocks),
  ];

  return { ok: failures.length === 0, failures };
}

module.exports = {
  checkLockfileVersion,
  checkRootDependencyDeclarationsMatchManifest,
  checkWorkspaceRecordsAndLinks,
  checkWorkspaceDependencyDeclarationsMatchManifest,
  checkNoBackendChildLocks,
  checkExcludedLocksPreserved,
  run,
};
