'use strict';

const fs = require('fs');
const path = require('path');

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function readJsonIfExists(file) {
  if (!fs.existsSync(file)) return null;
  return readJson(file);
}

// Loads every backend workspace manifest under `workspacePaths`, keyed by the
// workspace path (e.g. "packages/bitcore-lib"), each carrying its parsed
// package.json and absolute directory.
function loadWorkspaceManifests(rootDir, workspacePaths) {
  const manifests = new Map();
  for (const workspacePath of workspacePaths) {
    const dir = path.join(rootDir, workspacePath);
    const manifest = readJson(path.join(dir, 'package.json'));
    manifests.set(workspacePath, { dir, manifest, workspacePath });
  }
  return manifests;
}

function isInternalDependencyName(name) {
  return name.startsWith('@bitpay-labs/');
}

// Returns [{ name, range, field }] for every @bitpay-labs/* dependency
// declared in dependencies/devDependencies/peerDependencies/optionalDependencies,
// excluding a self-reference.
function internalDependencyEdges(manifest) {
  const fields = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];
  const edges = [];
  for (const field of fields) {
    const table = manifest[field];
    if (!table) continue;
    for (const [name, range] of Object.entries(table)) {
      if (isInternalDependencyName(name) && name !== manifest.name) {
        edges.push({ name, range, field });
      }
    }
  }
  return edges;
}

function formatFailure({ mode, consumer, workspace, expected, observed, detail }) {
  const lines = [`[${mode}] ${detail}`];
  if (workspace) lines.push(`    workspace: ${workspace}`);
  if (consumer) lines.push(`    consumer: ${consumer}`);
  if (expected !== undefined) lines.push(`    expected: ${JSON.stringify(expected)}`);
  if (observed !== undefined) lines.push(`    observed: ${JSON.stringify(observed)}`);
  return lines.join('\n');
}

module.exports = {
  readJson,
  readJsonIfExists,
  loadWorkspaceManifests,
  isInternalDependencyName,
  internalDependencyEdges,
  formatFailure,
};
