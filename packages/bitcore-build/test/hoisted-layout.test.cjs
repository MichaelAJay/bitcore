'use strict';

// Focused helper test for bitcore-migration-plan.md Task 1.1. Reproduces the
// RED that motivates the task: index.js locates Browserify/Karma/WebdriverIO
// and its own shared config by concatenating fixed-depth, cwd-relative
// strings (see the "buildPath"/"buildBinPath" construction and the two
// fs.existsSync fallbacks in index.js). That assumes bitcore-build's own
// dependencies are nested inside a per-consumer copy of bitcore-build
// (packages/<consumer>/node_modules/@bitpay-labs/bitcore-build/node_modules),
// which is how Lerna's per-package bootstrap installs it today. npm
// workspaces instead link bitcore-build once at the repository root and
// hoist its dependencies there too, so neither hardcoded depth exists under
// the consumer, even though the tools and the workspace itself are real and
// installed.
//
// The fixture below is self-contained: the helper under test is a
// byte-for-byte copy of today's real index.js/karma.conf.js placed inside a
// disposable temp workspace (not a symlink out to the real repository), and
// the shared tools it looks for (browserify/karma/wdio) are real npm-style
// packages built inside that same fixture -- a package.json with a "bin"
// field plus the target script, and an npm-style node_modules/.bin symlink
// generated from that manifest, exactly as a real install would produce.
// Only gulp/gulp-shell/gulp-rename/gulp-terser -- the plumbing that runs the
// helper, not the subject of this task -- are reused via symlink from the
// real repository's already-installed copies, so this fixture does not need
// to reimplement a build tool's own dependency tree to exercise it.
//
// Fixtures here are independent of the real repository's current install
// state (see test/workspaces/helpers.cjs's own rationale for the same
// pattern), so this test exercises today's real helper *logic* against a
// synthetic hoisted layout, not the migrated repository itself.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const BITCORE_BUILD_DIR = path.join(REPO_ROOT, 'packages', 'bitcore-build');
const REAL_HELPER_SOURCE = path.join(BITCORE_BUILD_DIR, 'index.js');
const REAL_KARMA_CONF_SOURCE = path.join(BITCORE_BUILD_DIR, 'karma.conf.js');
// The plumbing gulp-shell needs to actually run the helper; not the tool
// resolution behavior under test.
const ENGINE_DEPENDENCIES = ['gulp', 'gulp-rename', 'gulp-shell', 'gulp-terser'];

function makeTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `bitcore-build-${prefix}-`));
}

// Builds a real npm-style tool package (manifest + bin target) at the
// fixture root and links its bin the way npm itself would: a relative
// symlink from node_modules/.bin generated from the package's own "bin"
// field, not a hand-placed script standing in for one.
function writeToolPackage(fixtureRoot, name, binRelativePath) {
  const pkgDir = path.join(fixtureRoot, 'node_modules', name);
  const binPath = path.join(pkgDir, binRelativePath);
  fs.mkdirSync(path.dirname(binPath), { recursive: true });
  fs.writeFileSync(
    path.join(pkgDir, 'package.json'),
    JSON.stringify({ name, version: '0.0.0-fixture', bin: { [name]: binRelativePath } }, null, 2)
  );
  fs.writeFileSync(binPath, '#!/usr/bin/env node\nprocess.exit(0);\n');
  fs.chmodSync(binPath, 0o755);
  const binDir = path.join(fixtureRoot, 'node_modules', '.bin');
  fs.mkdirSync(binDir, { recursive: true });
  fs.symlinkSync(path.relative(binDir, binPath), path.join(binDir, name));
}

// Simulates the npm-workspaces root-hoisted layout: the helper and its tool
// dependencies are installed once, at the fixture root -- exactly where npm
// places a workspace and its hoisted dependencies -- and the consuming
// package directory has no node_modules of its own at all, matching an
// ordinary workspace member with nothing requiring a nested install.
function buildHoistedFixture() {
  const fixtureRoot = makeTempDir('hoisted');

  for (const dependency of ENGINE_DEPENDENCIES) {
    fs.mkdirSync(path.join(fixtureRoot, 'node_modules'), { recursive: true });
    fs.symlinkSync(
      path.join(BITCORE_BUILD_DIR, 'node_modules', dependency),
      path.join(fixtureRoot, 'node_modules', dependency),
      'dir'
    );
  }

  writeToolPackage(fixtureRoot, 'browserify', 'bin/cmd.js');
  writeToolPackage(fixtureRoot, 'karma', 'bin/karma');
  writeToolPackage(fixtureRoot, 'wdio', 'bin/wdio.js');

  const helperDir = path.join(fixtureRoot, 'node_modules', '@bitpay-labs', 'bitcore-build');
  fs.mkdirSync(helperDir, { recursive: true });
  fs.writeFileSync(
    path.join(helperDir, 'package.json'),
    JSON.stringify({ name: '@bitpay-labs/bitcore-build', version: '0.0.0-fixture', main: 'index.js' }, null, 2)
  );
  fs.copyFileSync(REAL_HELPER_SOURCE, path.join(helperDir, 'index.js'));
  fs.copyFileSync(REAL_KARMA_CONF_SOURCE, path.join(helperDir, 'karma.conf.js'));

  const consumerDir = path.join(fixtureRoot, 'packages', 'consumer');
  fs.mkdirSync(path.join(consumerDir, 'lib'), { recursive: true });
  fs.mkdirSync(path.join(consumerDir, 'test'), { recursive: true });
  fs.writeFileSync(path.join(consumerDir, 'lib', 'index.js'), 'module.exports = {};\n');
  fs.writeFileSync(path.join(consumerDir, 'test', 'index.js'), '');

  return { fixtureRoot, consumerDir, helperDir, helperIndexPath: path.join(helperDir, 'index.js') };
}

test('old helper cannot find browserify or its config when tools are hoisted to the workspace root', async () => {
  const { consumerDir, helperDir, helperIndexPath } = buildHoistedFixture();

  // The tool genuinely is resolvable via standard npm package/bin metadata
  // from the helper's own location -- proving this is a physical-path
  // assumption bug in the helper, not a missing dependency.
  const browserifyManifestPath = require.resolve('browserify/package.json', { paths: [helperDir] });
  const browserifyManifest = JSON.parse(fs.readFileSync(browserifyManifestPath, 'utf8'));
  const resolvedBrowserifyBin = path.join(path.dirname(browserifyManifestPath), browserifyManifest.bin.browserify);
  assert.equal(
    fs.existsSync(resolvedBrowserifyBin),
    true,
    'browserify must be genuinely reachable from the helper\'s own location via its manifest bin metadata'
  );

  const originalCwd = process.cwd();
  process.chdir(consumerDir);

  try {
    // Neither of the helper's own hardcoded, consumer-cwd-relative candidate
    // paths exists under this layout.
    const nestedPath = './node_modules/@bitpay-labs/bitcore-build/node_modules/.bin/browserify';
    const fallbackPath = './node_modules/.bin/browserify';
    assert.equal(fs.existsSync(nestedPath), false, 'nested per-consumer .bin path should not exist under a hoisted layout');
    assert.equal(fs.existsSync(fallbackPath), false, 'consumer-local .bin fallback should not exist under a hoisted layout');
    assert.equal(
      fs.existsSync('./node_modules/@bitpay-labs/bitcore-build/karma.conf.js'),
      false,
      'default karma.conf.js lookup should not exist under a hoisted layout'
    );
    assert.equal(
      fs.existsSync(require.resolve('@bitpay-labs/bitcore-build', { paths: [consumerDir] })),
      true,
      'the helper package itself is genuinely discoverable via normal require() resolution'
    );

    // Capture the exact command the helper constructs, without altering its
    // logic. gulp-shell resolves to the same real, cached module both here
    // and from inside the (copied) helper -- Node resolves the symlinked
    // dependency to its real path for cache identity -- so patching it here
    // intercepts the helper's own call.
    const shell = require('gulp-shell');
    const originalTask = shell.task;
    const capturedCommands = [];
    shell.task = (commands, options) => {
      capturedCommands.push(commands);
      return originalTask(commands, options);
    };

    let tasks;
    try {
      delete require.cache[helperIndexPath];
      const startGulp = require(helperIndexPath);
      tasks = startGulp('lib', {});
    } finally {
      shell.task = originalTask;
    }

    // startGulp registers several shell tasks (test:karma, test:webdriverio,
    // browser:uncompressed, browser:maketests, test:node); pick out the one
    // this test actually exercises rather than assuming call order.
    const browserifyCommands = capturedCommands
      .flat()
      .filter((command) => command.includes(' -o bitcore-lib.js'));
    assert.equal(browserifyCommands.length, 1, 'expected exactly one captured browserify bundling command');
    const [browserifyCommand] = browserifyCommands;
    assert.ok(
      browserifyCommand.includes(fallbackPath),
      `expected the constructed command to embed the specific nonexistent fallback path (${fallbackPath}); got: ${browserifyCommand}`
    );

    const exitError = await new Promise((resolve) => {
      tasks['browser:uncompressed']((err) => resolve(err || null));
    });
    assert.ok(
      exitError,
      `expected browser:uncompressed to fail invoking the missing path embedded in: ${browserifyCommand}`
    );
  } finally {
    process.chdir(originalCwd);
  }
});
