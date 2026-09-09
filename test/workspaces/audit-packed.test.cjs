'use strict';

const fs = require('fs');
const assert = require('node:assert/strict');
const test = require('node:test');
const path = require('path');
const { audit, DOCUMENTED_BASELINE_EXCEPTIONS } = require('../../scripts/workspaces/audit-packed.cjs');
const { makeTempDir, writeJson } = require('./helpers.cjs');

function writeFile(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
}

test('audit fails a `require`d runtime dependency that the manifest never declares', () => {
  const dir = makeTempDir('audit-undeclared-require');
  writeJson(path.join(dir, 'package.json'), { name: '@x/pkg', version: '1.0.0' });
  writeFile(path.join(dir, 'lib', 'index.js'), "module.exports = require('left-pad');\n");

  const result = audit(dir);
  assert.equal(result.failures.length, 1);
  assert.match(result.failures[0], /imports undeclared runtime dependency left-pad/);
});

test('audit passes once the dependency is declared', () => {
  const dir = makeTempDir('audit-declared');
  writeJson(path.join(dir, 'package.json'), { name: '@x/pkg', version: '1.0.0', dependencies: { 'left-pad': '^1.0.0' } });
  writeFile(path.join(dir, 'lib', 'index.js'), "module.exports = require('left-pad');\n");

  const result = audit(dir);
  assert.deepEqual(result.failures, []);
});

test('audit ignores relative requires, Node builtins, and a self-reference to the package\'s own name', () => {
  const dir = makeTempDir('audit-ignored');
  writeJson(path.join(dir, 'package.json'), { name: '@x/pkg', version: '1.0.0' });
  writeFile(
    path.join(dir, 'lib', 'index.js'),
    [
      "const fs = require('node:fs');",
      "const other = require('./other');",
      "const self = require('@x/pkg/lib/other');",
      '',
    ].join('\n')
  );

  const result = audit(dir);
  assert.deepEqual(result.failures, []);
  // Builtins are never recorded as imports at all. The self-reference *is*
  // still recorded (it is a real, non-relative specifier) -- it is only
  // exempted from *failing*, since a package importing its own name is
  // never a missing dependency.
  assert.deepEqual(
    result.imports.map((i) => i.name),
    ['@x/pkg']
  );
});

test('audit scans a package\'s own root-level entry file, not only known implementation subdirectories', () => {
  // Regression test: several real packages (bitcore-lib, bitcore-p2p*,
  // bitcore-mnemonic, crypto-rpc, bitcore-build) declare `main` directly at
  // the package root. An earlier version of this walker only recursed into
  // a fixed subdirectory allowlist and never looked at the root's own
  // files, silently skipping exactly those packages' entry points.
  const dir = makeTempDir('audit-root-entry');
  writeJson(path.join(dir, 'package.json'), { name: '@x/pkg', version: '1.0.0', main: 'index.js' });
  writeFile(path.join(dir, 'index.js'), "module.exports = require('undeclared-dep');\n");

  const result = audit(dir);
  assert.equal(result.failures.length, 1);
  assert.match(result.failures[0], /undeclared-dep/);
});

test('audit does not recurse into an unrelated top-level directory that sits next to the root entry file', () => {
  // Regression test for the fix above: scanning the root level must stay
  // shallow (files only), the same way bitcore-lib's real, unrelated
  // `karma-wdio-mig-TMP/` leftover directory must never be walked into.
  const dir = makeTempDir('audit-root-shallow');
  writeJson(path.join(dir, 'package.json'), { name: '@x/pkg', version: '1.0.0', main: 'index.js' });
  writeFile(path.join(dir, 'index.js'), "module.exports = require('./lib');\n");
  writeFile(path.join(dir, 'unrelated-tmp', 'stray.js'), "module.exports = require('undeclared-dep');\n");

  const result = audit(dir);
  assert.deepEqual(result.failures, []);
});

test('audit excludes build/lint config files and generated browser bundles by filename convention', () => {
  const dir = makeTempDir('audit-config-excluded');
  writeJson(path.join(dir, 'package.json'), { name: '@bitpay-labs/pkg', version: '1.0.0' });
  writeFile(path.join(dir, 'gulpfile.js'), "require('undeclared-dep');\n");
  writeFile(path.join(dir, 'karma.conf.js'), "require('undeclared-dep');\n");
  writeFile(path.join(dir, 'bitcore-pkg.js'), "require('undeclared-dep');\n"); // browserify bundle output
  writeFile(path.join(dir, 'bitcore-pkg.min.js'), "require('undeclared-dep');\n");
  writeFile(path.join(dir, 'tests.js'), "require('undeclared-dep');\n"); // browserify test bundle output

  const result = audit(dir);
  assert.deepEqual(result.failures, []);
  assert.deepEqual(result.imports, []);
});

test('audit does not walk into node_modules, test directories, or other excluded subtrees', () => {
  const dir = makeTempDir('audit-excluded-subtrees');
  writeJson(path.join(dir, 'package.json'), { name: '@x/pkg', version: '1.0.0' });
  for (const excluded of ['node_modules', 'test', 'tests', 'coverage', 'docs', 'benchmark']) {
    writeFile(path.join(dir, 'lib', excluded, 'index.js'), "require('undeclared-dep');\n");
  }

  const result = audit(dir);
  assert.deepEqual(result.failures, []);
});

test('audit resolves a scoped package name to its first two path segments', () => {
  const dir = makeTempDir('audit-scoped');
  writeJson(path.join(dir, 'package.json'), { name: '@x/pkg', version: '1.0.0' });
  writeFile(path.join(dir, 'lib', 'index.js'), "require('@bitpay-labs/bitcore-lib/lib/transaction');\n");

  const result = audit(dir);
  assert.equal(result.failures.length, 1);
  assert.match(result.failures[0], /@bitpay-labs\/bitcore-lib/);
  assert.equal(result.imports[0].name, '@bitpay-labs/bitcore-lib');
});

test('audit detects a TypeScript `import type(...)` reference to an undeclared package, in a .d.ts file', () => {
  const dir = makeTempDir('audit-import-type');
  writeJson(path.join(dir, 'package.json'), { name: '@x/pkg', version: '1.0.0' });
  writeFile(path.join(dir, 'ts_build', 'index.d.ts'), "export declare function f(): import('undeclared-types-dep').Thing;\n");

  const result = audit(dir);
  assert.equal(result.failures.length, 1);
  assert.match(result.failures[0], /undeclared-types-dep/);
});

test('a documented baseline exception is reported separately from failures, keyed to the exact package/file/import triple', () => {
  const [key] = [...DOCUMENTED_BASELINE_EXCEPTIONS];
  assert.ok(key, 'expected at least one documented baseline exception to exist');
  const [packageName, relativeFile, importName] = key.split('::');

  const dir = makeTempDir('audit-documented-exception');
  writeJson(path.join(dir, 'package.json'), { name: packageName, version: '1.0.0' });
  writeFile(path.join(dir, relativeFile), `import { X } from '${importName}';\n`);

  const result = audit(dir);
  assert.deepEqual(result.failures, []);
  assert.equal(result.exceptions.length, 1);
  assert.match(result.exceptions[0], new RegExp(importName));
});

test('an import matching a documented exception\'s specifier but a different file is still a real failure', () => {
  const [key] = [...DOCUMENTED_BASELINE_EXCEPTIONS];
  const [packageName, , importName] = key.split('::');

  const dir = makeTempDir('audit-not-exception');
  writeJson(path.join(dir, 'package.json'), { name: packageName, version: '1.0.0' });
  writeFile(path.join(dir, 'ts_build/src/lib/chain/some-other-file.d.ts'), `import { X } from '${importName}';\n`);

  const result = audit(dir);
  assert.equal(result.failures.length, 1);
  assert.deepEqual(result.exceptions, []);
});
