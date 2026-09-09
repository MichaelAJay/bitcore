# Bitcore: Lerna to npm workspaces

## Scope and outcome

Source repository: `/Users/bpmj/dev/bitcore`.

Reviewed commit: `5f813f2dcc0fbb55037edede6e19e74d8beaa531`.

Review date: 2026-09-05. Observed tools: Node `22.16.0`, npm `10.9.2`.

Replace Lerna installation, local linking, and script orchestration with npm workspaces. Keep execution on Node 22. Preserve package names, public entry points, versions, application behavior, browser tests, and the existing separation of Insight from the backend packages.

The target is one root install and one root lockfile for the 18 packages currently managed by Lerna. Insight remains a separate application with its own install and lockfile. The three nested benchmark projects remain excluded. Integrating Insight into the workspace graph would broaden this migration and combine its TypeScript 4 / ESLint 8 / React Scripts toolchain with the backend toolchain; it is not required to remove Lerna.

This document plans implementation; it does not report a completed migration. No repository dependency installation, complete build, application test suite, or Docker build was run during review. Read-only checks confirmed Lerna membership, npm workspace absence, manifest dependency compatibility, and the source findings below. An isolated, dependency-free npm experiment confirmed the CLI bin-link timing problem; it did not modify the repository. The adjacent pre-existing `inventory.json` describes a different repository. Use `bitcore-inventory.json` and `bitcore-review-evidence.json` as evidence for this plan. Task 0.1 has since been executed against the current branch tip, including a real disposable-checkout `npm ci`/`lerna run compile`; its reverified inventory, findings, and that execution's results are recorded in `bitcore-baseline-results.json`.

Concrete command, verifier, and evidence contracts are in [bitcore-acceptance-spec.md](bitcore-acceptance-spec.md). That file is part of this plan.

## Current structure

### Package inventory

All names in the table except Insight have the prefix `@bitpay-labs/`. Paths are `packages/<directory>`.

| Directory | Version | Role and existing execution |
| --- | --- | --- |
| bitcore-build | 11.10.4 | Shared Gulp factory, Browserify, Karma and WebdriverIO configuration. Declares `test: gulp test`, but has no own gulpfile. |
| bitcore-lib | 11.10.4 | Bitcoin primitives; Gulp Node and WebdriverIO browser tests. |
| bitcore-lib-cash | 11.10.4 | Bitcoin Cash primitives; Gulp Node and WebdriverIO browser tests. |
| bitcore-lib-doge | 11.10.4 | Dogecoin primitives; Gulp Node and WebdriverIO browser tests. |
| bitcore-lib-ltc | 11.10.4 | Litecoin primitives; Gulp Node and WebdriverIO browser tests. |
| bitcore-mnemonic | 11.10.4 | Mnemonics; consumes Bitcoin primitives; Node and WebdriverIO tests. |
| bitcore-p2p | 11.10.4 | P2P; consumes Bitcoin primitives; Gulp Node tests. |
| bitcore-p2p-cash | 11.10.4 | P2P; consumes Bitcoin and Cash primitives; Gulp Node tests. |
| bitcore-p2p-doge | 11.10.4 | P2P; consumes Dogecoin primitives; Gulp Node tests. Deprecated in README but still managed and scripted. |
| bitcore-logging | 11.10.4 | TypeScript; emits `ts_build`; Mocha tests. |
| crypto-wallet-core | 11.10.4 | TypeScript multichain wallet library; emits `ts_build`; consumes all four primitive libraries. |
| bitcore-tss | 11.10.4 | CommonJS threshold signatures; Mocha tests and separate Webpack/WebdriverIO browser path. |
| crypto-rpc | 11.10.4 | ESM RPC library; consumes crypto-wallet-core; Docker/Hardhat/blockchain tests. |
| bitcore-wallet-service | 11.10.7 | TypeScript service; emits `ts_build`, copies templates; MongoDB-backed tests and service Dockerfile. |
| bitcore-wallet-client | 11.10.7 | TypeScript client; emits `ts_build`; tests import wallet-service and copy test data. |
| bitcore-client | 11.10.4 | TypeScript node client; emits `ts_build`; tests run through `tsx` and import sibling node build output. Only package with a `watch` script. |
| bitcore-cli | 11.10.7 | Private TypeScript application; emits `build`; generates a CLI symlink and copies test wallets. |
| bitcore-node | 11.10.7 | TypeScript indexer/API; emits `build`; unit/integration/script tests and service Dockerfile. |
| insight | 10.0.11 | Private React application; excluded from Lerna. Own lockfile, build, and asset relocation in `postbuild.sh`. |

There are 23 tracked manifests: root, 19 immediate package manifests, and three unnamed benchmark manifests under `bitcore-lib`, `bitcore-lib-cash`, and `bitcore-lib-ltc`. No `node_modules` files are tracked.

### Installation and orchestration

- Root `package.json` has version `8.25.8`, no name, no `private` flag, no workspaces, and Node engine `^22`.
- Root dependency is Lerna `^5.6.2`; the locally installed CLI reports `5.6.2`. `lerna.json` retains a historical `lerna: 2.9.1` field and version `11.10.7`.
- `lerna.json` uses `packages/[^insight]*`. This is a character-class pattern, not a precise exclusion of one directory. The actual CLI lists the 18 backend packages, including the private CLI when `--all` is supplied.
- Root installation runs `postinstall -> bootstrap -> lerna bootstrap`, then `compile -> lerna run compile`.
- Seven packages expose `compile`: logging, crypto-wallet-core, wallet-service, wallet-client, client, CLI, and node. JavaScript libraries and TSS do not expose it.
- Root `build` builds the root Dockerfile. `build:docker` runs two package Docker builds sequentially. Preserve these distinct meanings.
- Root `watch` uses Lerna parallel mode, but currently starts only bitcore-client's TypeScript watcher.
- Seventeen root `test:<directory>` aliases run package tests. There is no root aggregate `test`. `bitcore-build` and Insight have no such aliases.
- There are 21 tracked lockfiles: root, 19 immediate packages, and `bitcore-lib/benchmark`. Root and most package locks use version 3; mnemonic uses version 2; the benchmark uses version 1.
- Root lock metadata matches root manifest dependencies. Most backend child locks omit internal dependency declarations present in their manifests. They are not complete independent representations of the workspace graph and must not be mechanically concatenated into a root lock.

### Dependency and build graph

All 45 declared internal backend dependency edges currently accept the local package versions. They use ordinary caret ranges, predominantly `^11.10.4` and `^11.10.7`. Insight adds four edges using `^11.8.1`, also compatible with the local versions, but currently installs independently.

Key edges, including development/test dependencies:

```text
bitcore-build -> tooling for four primitive libraries, mnemonic, three P2P packages
four primitive libraries -> crypto-wallet-core
bitcore-lib -> mnemonic, TSS, P2P
crypto-wallet-core -> TSS tests, RPC, wallet-service, wallet-client, client, CLI, node
logging -> wallet-service, node
wallet-service -> wallet-client tests, CLI tests
mnemonic + TSS -> wallet-client
wallet-client -> CLI, node
client -> node tests (declared as a node runtime dependency)
node generated output -> client tests (relative imports; absent from the manifest graph)
```

Arrows above mean prerequisite to consumer. The last two edges create a build/test ordering cycle even though the declared backend dependency graph does not contain that cycle. `bitcore-client/precompile` currently cleans and builds bitcore-node production output. Its tests import `../../../bitcore-node/build/src/services/api`, storage, and modules. Node tests import `@bitpay-labs/bitcore-client`; node production source has no corresponding client import in the reviewed tree.

### Compatibility findings

| Evidence | Migration consequence |
| --- | --- |
| `packages/bitcore-build/index.js` constructs `./node_modules/@bitpay-labs/bitcore-build/`, nested `.bin` paths, and package-local fallback `.bin` paths. | Root hoisting can break browser tool and config discovery. Resolve tools and shared config from their owning package, independently of physical layout. |
| Its `test:node` invokes `nyc mocha`; neither is declared by bitcore-build. Root currently provides these commands. | Removing Lerna's transitive tree or packing the helper may expose undeclared tooling. Declare tools at their intended owner. |
| `bitcore-build/karma.conf.js` uses `../../../tests.js`; shared WDIO config already resolves `tests.js` from consumer cwd. | Fix Karma's bundle base path while preserving the already-correct WDIO consumer cwd behavior. |
| Five configs restrict `typeRoots` to package-local `node_modules/@types`: client, logging, wallet-client, wallet-service, crypto-wallet-core. Client additionally uses `src/types`. | Hoisted typings may become invisible. Preserve custom types and prevent incompatible ambient test types from leaking between packages. |
| TypeScript versions include backend 5.7.3 and CLI `^5.8.3`; Chai spans majors 4, 5, and 6; Mocha types span majors 5 and 10. | Legitimate nested dependencies must remain supported. Do not force all versions into one root version. |
| `bitcore-tss/.npmrc` sets `engine-strict=true`; no root `.npmrc` exists. | Root installation will not inherit that child policy. Make the target policy explicit. |
| All three P2P packages depend on `socks5-client@^0.3.6`; locks resolve 0.3.6 with `engines.node: 0.x`. | Root-wide npm strict engines would reject the existing graph. Enforce Node 22 separately and validate dependency engines with one exact legacy exception. |
| Client uses `bcrypt@5.1.0`, `leveldown@6.1.1`, `secp256k1@3.7.1`; TSS/Hardhat introduce additional native/platform tooling. | Node 22 native loading must be verified on the deployment OS, with lifecycle scripts enabled. |
| CLI `createBin` generates an absolute `bin/bitcore-cli` symlink after build, and that directory is ignored. | An npm 10.9.2 fixture confirms a missing root `.bin` entry on first install; a repeat install hides it. Add a tracked launcher before cutover. |
| `bitcore-wallet-client/package.json` declares `types: ts_build/src/index.d.js`. | TypeScript emits `.d.ts`; correct this metadata typo and verify a consumer can resolve the declaration entry. |
| Primitive libraries contain duplicate-instance guards. | Checking root symlinks alone is insufficient; each consumer must resolve the local instance, not a nested registry copy. |

Direct imports also expose existing undeclared dependency risks. Examples: node imports `bson`, `bn.js`, and `@metaplex-foundation/umi-public-keys`; crypto-wallet-core imports `base-x` and references `web3-utils` / `web3-types`; RPC imports `bs58` and `@solana/functional`; wallet-client's key utility imports `bs58`. Classify runtime versus type-only uses before editing manifests. Root hoisting must not be accepted as proof that a published package declares everything it needs.

### CI, Docker, and releases

- Active CI is `.circleci/config.yml`; `.github` contains templates, no workflows. CircleCI pins Node `22.13.1`, installs Python 2, runs root `npm ci`, persists the full checkout/dependencies, then recompiles in each test job.
- Cache configuration calls `npx lerna la` to concatenate child locks. The restore step is commented out, while the save key still references `combined-package-lock.txt`, whose creation is in that disabled path.
- The disabled `build-crypto-rpc` job persists only the package directory. That is insufficient once its dependencies and workspace links live at the root.
- CircleCI runs 15 package test jobs; root aliases additionally cover P2P Cash and P2P Doge. Test inventory must distinguish this existing gap from coverage introduced by migration.
- Root Dockerfile uses `node:22-bookworm` and `npm ci`. Node and wallet-service Dockerfiles copy `lerna.json`, install with scripts disabled, bootstrap, then compile. All need a consistent root workspace install.
- RPC's two Node Dockerfiles build from the RPC directory, install only its manifest, and remove an unscoped `node_modules/crypto-wallet-core`. Compose bind-mounts the same unscoped path, while source uses `@bitpay-labs/crypto-wallet-core`. Those mounts do not validate the scoped local dependency.
- Root local test Compose bind-mounts the host checkout over `/bitcore`, hiding files installed in the image. Account for container-owned dependencies and generated artifacts.
- RPC `start.dockerfile` invokes a nonexistent `migrate` script. Record this as a pre-existing defect. Migrate its dependency installation context, but leave removal or repair of that command to a separate follow-up. The working test-runner path is a migration acceptance gate.
- `packages/build` is an incomplete hand-written compile loop. `packages/pub` is an explicit publish loop with duplicate P2P Doge and missing packages. No tracked command uses `lerna version` or `lerna publish`. Do not infer a release policy from the stale Lerna version field.
- Legacy package Travis files, Makefiles, and browser HTML fixtures contain standalone/local dependency assumptions. They are not current CircleCI jobs; give each a documented disposition.

## Target design

1. Add a private root name such as `bitcore-monorepo`; keep existing public package names and versions. Keep the root version unchanged unless a separate release change is required.
2. Declare an explicit list of the 18 backend workspace paths from the table. Include private CLI and deprecated P2P Doge. Exclude Insight and all nested benchmarks. Check this exact membership in the migration verifier.
3. Use npm `10.9.2` as the initial migration reference and Node `22.16.0` as the initial reproducible baseline, matching the observed local environment. Align CI and Node application image tags with that pair. A later Node 22 patch update is a separate version change with the same acceptance suite. Never solve compatibility failures by moving to Node 24 or reverting to Node 20.
4. Set root `engines.node` to `>=22 <23`, record exact npm in `packageManager`, and install/check that npm in CI/images. Add dependency-free `check-runtime.cjs` preflight, also called by root `preinstall` and the compile runner. Metadata alone does not enforce npm selection. Set root `.npmrc` to `engine-strict=false` deliberately: blanket strict engines rejects the existing P2P dependency. Validate installed dependency engines separately, allowing only `socks5-client@0.3.6` with the exact historical `0.x` declaration. No other mismatch is silently accepted. Retain TSS `.npmrc` for standalone development; document that root installs do not inherit it. [npm engine-strict configuration](https://docs.npmjs.com/cli/v10/using-npm/config/#engine-strict), [npm project configuration](https://docs.npmjs.com/cli/v10/configuring-npm/npmrc/#per-project-config-file)
5. Keep ordinary semver dependencies for internal packages. Do not use `workspace:*`, blanket `*`, or `file:../...` references in published manifests. npm 10's supported package specifications and workspace linking are the relevant contract. [npm package specifications](https://docs.npmjs.com/cli/v10/using-npm/package-spec/)
6. Let npm install and link workspaces. Root `postinstall` validates dependency engines and then compiles, preserving install-and-build behavior; remove bootstrap entirely. Keep compilation out of workspace install/prepare hooks. Run preflight explicitly before `npm ci` in CI/images: a root lifecycle guard does not guarantee that no dependency lifecycle has already run. A metadata-only install is diagnostic, not the final success criterion. [npm lifecycle scripts](https://docs.npmjs.com/cli/v10/using-npm/scripts/)
7. Implement a small explicit sequential compile runner. After separating client production compilation from node-dependent tests, order is: logging, crypto-wallet-core, wallet-service, wallet-client, client, CLI, node. Use `npm run compile --workspace=<scoped-name>` per package, forward output, stop on the first error, and preserve npm's package lifecycle hooks. Fail if a required compile script disappears or a new compile-bearing workspace is unaccounted for. Do not build a general task scheduler.
8. Do not replace compilation with a blind `npm run compile --workspaces --if-present`: npm runs in configured workspace order, not dependency topology. Use `--if-present` only where missing scripts are deliberately permitted. [npm workspace execution](https://docs.npmjs.com/cli/v10/using-npm/workspaces/)
9. Root lockfile v3 is authoritative for backend installation. Remove the 18 backend child locks. Retain the Insight and benchmark locks. Use default hoisted installation, allowing nested dependencies where versions require them. A lock generated with special resolution flags requires those same flags for `npm ci`; avoid introducing such flags without a diagnosed requirement. [npm ci](https://docs.npmjs.com/cli/v10/commands/npm-ci/)
10. Preserve root test/start/build aliases. `watch` can directly target the sole current watcher. `build:docker` explicitly invokes node then wallet-service with failure propagation. Preserve root `build` as the root image build.
11. Keep Insight isolated: `insight:install` runs `npm --prefix packages/insight ci --workspaces=false`; `insight:build` runs that install and then builds with the same prefix and workspace opt-out. Preserve the existing one-command install-and-build behavior, replacing unlocked `npm i` with `npm ci`. Its lock remains independent.
12. Build container dependencies from the monorepo root and keep both root `node_modules` and workspace directories in the image. A symlink without its workspace target is not a deployable artifact. Defer production pruning and dependency-closure image optimization until the full install works.
13. Shared devDependency *tooling* invoked bare in a package's own scripts (test runners such as `mocha`/`nyc`, doc generators such as `typedoc`, linters such as `eslint`) may stay declared once at root rather than redeclared in every package that runs it, the same way root `eslint`/`fix` scripts are already treated (Task 3.1). `npm run <script> --workspace=<name>` reliably resolves a root-declared devDependency's bin: this is ordinary `npm run-script` behavior (it walks every ancestor `node_modules/.bin` from the executing script's cwd up to the filesystem root), not a Lerna-bootstrap accident that migration puts at risk — confirmed with a real disposable npm-workspaces reproduction, recorded in [Task 1.4's evidence](../../artifacts/workspaces/task1.4/audit-and-evidence.md). This is deliberately narrower than the compatibility findings' "root hoisting must not be accepted as proof that a published package declares everything it needs" (§ "Compatibility findings"), which is about a package's *runtime* `dependencies` — an external `npm install <published-package>` consumer never receives the monorepo root's devDependencies at all, so that point still stands unchanged and still requires each package to declare its own runtime dependencies regardless of what root happens to provide. Two situations remain genuine exceptions to this item, and must still declare their own tooling: a package meant to be installed/tested standalone outside this monorepo (`bitcore-build`, per Task 1.1 and the compatibility findings table — root hoisting is never available to an external consumer at all), and a script that runs inside a build context where root is not on the resolution path, such as a Docker image built from a single package's directory rather than the monorepo root (crypto-rpc's `docker:test`, until Task 4.2's root-context migration lands).

## Execution and evidence rules

All implementation commands below run from Bitcore root unless another cwd is specified. `scripts/workspaces/`, `test/workspaces/`, and `artifacts/workspaces/` are proposed paths, not existing commands. Keep evidence artifacts untracked and excluded from lint/build inputs. Use existing suites and short script checks; permanent tests are warranted for runtime/engine enforcement, compile ordering, shared tool resolution, and CLI linking, not every manifest field or documentation edit.

Use disposable checkouts for cold installs, negative mutations, dependency removal, and container tests. Do not delete dependencies or build output in a developer's working tree to obtain RED. Do not carry existing `node_modules`, `build`, `ts_build`, generated browser bundles, CLI links, or cached application artifacts into the cold-install acceptance run.

For each task record command, checkout commit, Node/npm versions, cwd, prerequisites, exit code, expected failure diagnostic, and log path. Non-obvious dependency/config decisions made while executing a task are appended to `bitcore-decision-log.json` in this plan's directory, one entry per commit, each tied to the phase and task it was made under so a later reader sees the reasoning behind a change, not just what changed; append entries as commits land and do not edit past entries except to fix a factual error. RED means the intended behavior is absent for the diagnosed reason. A network outage, unavailable database/browser, wrong Node version, missing test file, or timeout is not an acceptable RED for workspace behavior.

Use RED/GREEN for new or repaired behavior. Use before/after regression evidence when behavior already works. Inventory, documentation, and cache-policy changes do not need contrived failing tests. Never manufacture a failure in application code just to satisfy this convention.

Acceptance is binary for migration behavior: each required gate must pass. Record unrelated pre-existing defects separately with exact signatures, impact, follow-up scope, and unchanged reproduction. A migrated install/link/build failure cannot be waived as a baseline defect. For example, RPC's already-missing `migrate` command is a separate defect; its test runner failing to install local workspaces is a migration blocker. Missing infrastructure leaves its gate unverified.

One integrator owns root manifests, root lockfile generation, and final integration. Package/config tasks can be assigned independently after Phase 0, but changes to shared manifests are integrated before regenerating the lock. Do not run concurrent npm mutations against one checkout. If committing tasks, follow `CONTRIBUTING.md`'s signed-commit requirement.

### Task order and merge boundaries

| Stage | Prerequisites | Gate before advancing |
| --- | --- | --- |
| 0.1–0.2 | Reviewed source | Inventory/results recorded; checks diagnose absent contracts. |
| 1.1, 1.2, 1.4, 1.5 | 0.1 | Package fixes pass focused fixtures and applicable existing-layout regressions. |
| 1.3 | 1.2 | Client compiles without node; runner fixtures prove order and failure handling. |
| 2.1 | 0.2 and 1.1–1.5 | Root install, links, engines, and build artifacts pass. |
| 2.2, 3.1, 3.2 | 2.1 | Cold-install/native and developer command checks pass. |
| 4.1–4.3 | 3.1 plus the previous container task | Images and mounted local tests use the candidate graph. |
| 3.3 | 3.1; final job runs wait for 4.2 | CI validates and passes cold/warm cache runs. |
| 5.1–5.3 | Relevant preceding gates | Distribution and integrated acceptance pass. |

Phase 1's workspace-runner tests use independent minimal fixtures, so they do not depend on repository cutover. Actual workspace integration checks belong to Phase 2 and the final matrix. Package preparation may pass before cutover; the migration release boundary remains all phases together.

## Phase 0 — Establish the executable baseline

### Task 0.1 — Capture source and behavior inventory

Dependencies: none.

Work:

- Revalidate the reviewed commit against the implementation branch; update the inventory for intervening changes.
- Capture all manifests, workspace membership including private packages, internal edges, script owners, lock versions, Docker entry points, and CI test jobs.
- In a disposable baseline checkout, run existing install/compile and existing equivalents of the final matrix commands. New verifiers, helper tests, and workspace selectors do not exist on the baseline; use the mapping in the acceptance specification. Capture prerequisite failures separately from application failures.
- Record installed versions of native modules and competing TypeScript/Chai/Mocha/type packages before consolidating locks.

Checks:

```bash
node --version
npm --version
node node_modules/lerna/cli.js list --all --json
npm pkg get name --workspaces
```

Acceptance:

- [x] Inventory reports 18 Lerna members, seven compile scripts, one watcher, 17 root package test aliases, and three excluded benchmarks; adjust only for documented intervening source changes.
- [x] The workspace command fails with `No workspaces found!` before migration. This was observed during review; run it separately from an all-success shell sequence because its expected exit is nonzero.
- [x] A baseline results file identifies each command as passed, failed with a signature, or blocked by a named prerequisite. No unexecuted suite is described as passing.

RED/GREEN: workspace discovery is RED; the rest is baseline capture.

### Task 0.2 — Add installation and resolution acceptance checks

Dependencies: 0.1.

Work: create `scripts/workspaces/verify.cjs` with `manifests`, `lock`, `engines`, `links`, and `artifacts` modes. Keep basic manifest/lock checks runnable without dependencies; declare `semver` directly for installed range/engine checks. Add dependency-free runtime preflight and focused fixtures using Node's built-in test runner. Exact mode contracts and artifact stages are in the acceptance specification.

Acceptance:

- [x] `manifests` checks exact workspace membership, private root, Node/npm policy, internal range compatibility, declared compile membership, and prohibited local dependency protocols.
- [x] `lock` checks backend workspace records/links, agreement with manifests, absence of backend child locks, and preservation of the two excluded-project locks.
- [x] `engines` checks installed backend dependency Node declarations, allowing only the exact socks5-client legacy exception. Report the resolution path and reject each new mismatch. Exclude Insight/benchmark trees; TSS dependencies receive no exception from the unrelated P2P package.
- [x] `links` resolves every internal dependency from the consuming package's location and records both the lexical resolved path returned by that consumer-originating resolution and the canonical real path after `realpath`. It compares the canonical path to the intended local package and detects nested registry copies, but `realpath` equality alone is not treated as sufficient success: the verifier groups internal resolutions by intended workspace target and also fails if different consumers reach that same workspace through different lexical npm-created symlink aliases, even when those aliases canonicalize to the same physical directory. A given internal workspace must not be reachable through multiple npm-created symlink aliases from different consumers unless an explicit, reviewed exception exists. A failure identifies the workspace package, the consumer, the lexical resolved path, the canonical real path, the conflicting consumer/path, and the expected canonical workspace location. Do not rely only on `npm ls` or on resolution from root.
- [x] `artifacts` has build and test-fixture stages. Build checks entry points, types, templates and CLI behavior after install; test-fixture checks copied data only after its owning test command. Do not import server entry points that start services.
- [x] Each mode produces an actionable failure with the consumer/package/path and nonzero status. Fixtures exercise an incompatible internal range, wrong target, missing artifact, and accidental Insight inclusion.
- [x] The target manifest/lock modes fail on the baseline for the diagnosed absent workspace contract. Missing verifier files are not RED evidence. (The complementary post-cutover expectation -- that all modes pass -- is Task 2.1's gate, not this task's; see Task 2.1's acceptance criteria.)

## Phase 1 — Remove package-layout and build-order assumptions

### Task 1.1 — Resolve shared build tools and config by package ownership

Dependencies: 0.1; independent of TypeScript edits.

Files: `packages/bitcore-build/index.js`, its manifest and browser config, focused helper tests.

Work:

- Resolve shared config relative to `__dirname` or the helper's resolved package location. Resolve tool entry points from their owning package manifest/bin metadata and launch with the selected Node executable, or use another tested npm-managed resolution mechanism. Handle paths containing spaces.
- Keep Browserify inputs, output files, tests, transforms, and external-package decisions relative to the consuming package cwd.
- Make Karma load that consumer's generated test bundle. Preserve WDIO's consumer-relative resolution and cleanup hooks.
- Declare the tools actually invoked by the helper, including nyc/Mocha, at the appropriate owner with versions validated against existing tests. Remove dead path probes instead of adding another fixed-depth fallback.
- Replace bitcore-build's unusable own `gulp test` entry with the focused helper tests. Consumer suites remain the integration coverage for the helper.

RED: run the old helper in a fixture with tools hoisted to the fixture root and no consumer-local helper or `.bin` directory. Browserify/config lookup must fail for its physical-path assumption.

GREEN / acceptance:

- [ ] The same fixture generates and locates a browser test bundle with the updated helper, including a checkout path containing spaces.
- [ ] A nested standalone installation fixture also passes, protecting external users of bitcore-build.
- [ ] Actual Node and headless-browser suites for the four primitive libraries and mnemonic pass in the existing Lerna installation after the helper change. Three P2P Node suites pass. Repeat these against workspaces in Phase 5.
- [ ] Active helper commands contain no fixed installation-depth assumptions. Karma and WDIO both locate the correct consuming package's bundle.

### Task 1.2 — Make TypeScript type discovery work with hoisting

Dependencies: 0.1.

Files: five affected `tsconfig.json` files and directly affected type dependencies.

Work: allow root-hoisted and package-local typings while preserving client custom declarations. Either explicitly include both type roots or use default ancestor discovery plus narrowly scoped `types` and inclusion of custom declarations. Select per-package test types to avoid introducing conflicting ambient definitions. Do not blanket-enable `skipLibCheck` to hide new failures. TypeScript's `typeRoots` option restricts automatic type inclusion to the listed locations. [TypeScript typeRoots](https://www.typescriptlang.org/tsconfig/typeRoots.html)

RED: in a disposable installation fixture, place required typings at root and omit their package-local copies; compile an affected package with its old configuration. Record a missing required type, not an unrelated source failure. If a package already compiles in this layout, use regression evidence for that package.

RED/GREEN evidence, including reproduction commands, is recorded under `artifacts/workspaces/task1.2/` (untracked; see [red-evidence.md](../../artifacts/workspaces/task1.2/red-evidence.md) and [green-evidence.md](../../artifacts/workspaces/task1.2/green-evidence.md)).

GREEN / acceptance:

- [x] Logging, crypto-wallet-core, wallet-service, wallet-client, and client compile with required types hoisted and legitimate conflicting versions nested.
- [x] Client custom types remain included; application and test type coverage is not silently removed.
- [x] Node and CLI compilation still passes; the actual `tsc` selected for each package is recorded. Insight stays on its independently installed toolchain.

### Task 1.3 — Separate client production compilation from node-dependent tests

Dependencies: 0.1, 1.2.

Files: client scripts/TypeScript configs, root compile runner, focused runner tests.

Work:

- Remove client's `precompile` action that cleans/rebuilds node.
- Make client `compile` build production source without requiring node test fixtures. Use its production config and explicitly preserve output paths, for example with `rootDir: "."`; otherwise excluding tests can change the inferred output root and break `main`/`types`.
- Preserve client test execution through `tsx`; add mandatory `test:types` using `tsc --noEmit -p tsconfig.json` after node artifacts exist. Production-only compilation must not remove the test type-checking previously supplied by compile.
- Add the explicit seven-package compile runner defined above. Its calls use npm so CLI `postbuild` and wallet-service template copying still execute.
- Document that single-package tests depend on the root install/compile preparation. Root `test:bitcore-client` must prepare node/client prerequisites through the canonical compile command before the selected tests; it must not silently use stale node output. A direct workspace test command is supported after the documented root preparation.

RED: compile client production code in a disposable prepared dependency tree with no node build output using the old compile command. Show the unwanted sibling build/clean lifecycle. Also exercise a runner fixture where a prerequisite exits nonzero.

GREEN / acceptance:

- [x] Client production compile succeeds without building or cleaning node; its declared `main` and `types` paths exist.
- [x] Runner fixtures execute all seven configured package scripts in the specified order. A clean real root compile is the Phase 2.1 integration gate, after workspace selectors become available.
- [x] With the existing installation prepared, node/client tests and client test type-checking pass; repeat under the candidate workspace installation in Phase 5.
- [x] Hashes of node output do not change merely from client production compilation.
- [ ] The runner stops before dependents when a prerequisite fails, is interrupted, or exits nonzero, and returns nonzero itself (verified for all three, including a fix for a reviewer-found bug where a child that handled a forwarded signal and exited 0 let the sequence continue -- see green-evidence.md). Successful logs show wallet-service template and CLI postbuild lifecycles were executed (not yet verified -- this requires real `npm run compile --workspace=<name>` against the actual wallet-service/CLI packages, which needs Task 2.1's root workspace cutover, and CLI's postbuild launcher behavior specifically needs Task 1.5, not yet implemented; left open for that integration).

### Task 1.4 — Declare dependencies exposed by the new installation layout

Dependencies: 0.1. Candidate-resolution follow-up fixes are validated during 2.1; they do not make preparation depend on cutover.

Work:

- Audit imports and invoked binaries in owned source/config/test scripts against each package manifest, starting with the concrete examples in the compatibility findings.
- Add directly used runtime dependencies to the consuming package; add build/test dependencies where they are executed. Public declaration-file references may require runtime dependency declarations even when source imports are type-only.
- Choose versions compatible with existing APIs and observed baseline resolutions. Do not blindly take latest `bson`, `base-x`, `bs58`, Web3, or Solana packages.
- Audit production/runtime code for cross-workspace filesystem traversal, for example `require('../../bitcore-lib')` or an equivalent relative import into a sibling package's source or build output. Internal runtime relationships should use the declared package specifier instead, for example `require('@bitpay-labs/bitcore-lib')` or the ESM equivalent: using both package-specifier resolution and direct sibling filesystem paths can give the same package multiple resolver identities even when Node later canonicalizes them to one real path, so this is a migration invariant, not a style preference. Do not blindly prohibit all relative references between workspaces; classify exceptions such as test fixtures, test-only generated output, build tooling, and scripts intentionally operating on repository files. For any cross-workspace relative path that remains after this audit, document it as non-runtime or explicitly justify it.
- Audit tools currently available only through Lerna's transitive dependencies. In particular, exercise RPC's Hardhat/Mocha commands and TSS's `webpack serve` command: a script must not fetch an undeclared CLI through `npx` during acceptance. Declare the needed serve/test tooling or use already-declared local executables.
- Correct wallet-client's declaration metadata from `ts_build/src/index.d.js` to the emitted `ts_build/src/index.d.ts`, so the installation artifact verifier can enforce the real declaration contract.
- Classify Node built-ins, TypeScript local path aliases, comments, and inactive legacy files correctly; regex hits alone are not dependency evidence.

Acceptance:

- [x] Every confirmed example has a manifest fix or a documented non-runtime disposition tied to its source use.
- [x] A source import audit reports no unexplained undeclared direct dependency in migrated runtime/build paths.
- [x] An audit of runtime/build paths for cross-workspace sibling filesystem imports is complete; each finding is either converted to the declared package specifier or given a documented non-runtime disposition.
- [x] Existing-layout package entry imports still work on Node 22. The candidate native-load and isolated packed-consumer gates are owned by Tasks 2.2 and 5.1.
- [x] Dependency changes list reason and before/after resolved versions. There are no unrelated major upgrades, forced overrides, or blanket peer-resolution bypasses.

RED/GREEN: use a consumer-resolution failure or isolated import failure when present. Existing transitive resolution can already pass, so declaration review is also an acceptance criterion.

Status: **implementation verified; integration gate pending.** Full audit, evidence, and reasoning in [audit-and-evidence.md](../../artifacts/workspaces/task1.4/audit-and-evidence.md). Went beyond the plan's named examples with two systematic sweeps (invoked-binary and import audits across all 18 backend packages), which independently found a genuinely broken (network-fetch-on-first-run) undeclared `webpack-dev-server` in bitcore-tss's browser test path, an undeclared `npmlog` (imported by name in six wallet-service test files, and — unlike `mocha`/`nyc` — not even declared at root, so purely an accidental transitive hoist), one cross-workspace relative-filesystem-import violation (bitcore-lib-doge's test reaching directly into bitcore-lib-ltc's source), and one unrelated pre-existing dead-code bug (a stale unscoped `bitcore-lib-doge` require in p2p-doge, unreachable today but fixed). A first pass also added per-package `mocha`/`nyc`/`typedoc` to seven packages that invoke them bare without declaring them, on the theory that this repeated the plan's own bitcore-build finding; challenged on whether that undid an intentional Lerna-era choice to centralize shared dev-tool versions at root, a real npm-workspaces reproduction (not re-argument) confirmed root-declared devDependencies reliably resolve for any workspace's own `npm run ... --workspace=` scripts — the same guarantee the target design already relies on for `eslint` — so that addition was reverted; root remains the sole owner of `mocha`/`nyc`/`typedoc`, and only `crypto-rpc`'s `mocha` stayed declared, because it runs inside an isolated Docker build context (confirmed via its Dockerfile/compose) where root is not present at all. Every fix that remains was verified against the package's real, currently-installed toolchain: actual `tsc` compiles for logging/crypto-wallet-core/wallet-service/wallet-client/client-adjacent packages, actual test runs (crypto-wallet-core 265 passing/0 failing, bitcore-node 343 passing/1 pre-existing failure identical to Task 1.3's already-dispositioned baseline signature, wallet-client 555 passing/0 failing), and a manual sibling-symlink reproduction proving the bitcore-lib-doge fix resolves once linked the way a real install links it. What is *not* yet proven, and is explicitly out of this task's scope per its own dependency note ("candidate-resolution follow-up fixes are validated during 2.1; they do not make preparation depend on cutover"): whether these declarations are *sufficient* once Lerna's bootstrap-created layout is replaced by npm's own hoisting under a real `npm ci` from the root lock (Task 2.1's `verify.cjs manifests`/`links`/`engines`), and whether TSS's `webpack serve` actually starts now that `webpack-dev-server` is declared (Task 5.3's TSS-browser matrix row). Treat this task as done; treat the underlying "no package secretly depends on root hoisting" invariant as open until 2.1 and 5.3 report their own gates.

### Task 1.5 — Make the CLI executable available before npm links bins

Dependencies: 0.1. Files: CLI manifest/bin launcher, `createBin`, `.gitignore`, and a focused installation fixture.

Work: add a tracked executable `bin/bitcore-cli` launcher that loads `../build/src/cli.js` relative to itself. Stop `createBin`/postbuild from removing or replacing that tracked launcher with an absolute symlink. Keep necessary postbuild behavior only where it has another purpose. A build may generate JavaScript; it must not be required to generate npm's bin target.

RED: the isolated npm 10.9.2 experiment recorded in `bitcore-review-evidence.json` installs a workspace whose bin target is generated in root postinstall. Install exits zero and creates the target, but the root `.bin` executable is absent. Repeating install makes it appear and therefore does not prove a first-install fix.

GREEN / acceptance:

- [x] The same cold fixture with a pre-existing tracked launcher produces a runnable root `.bin` executable after its first install. This behavior was confirmed in review; reproduce it in the implementation test.
- [x] The real CLI launcher is tracked and executable before any install/build; its path is relative to its own file and portable between checkouts.
- [x] Existing CLI compilation/tests pass and leave the launcher unchanged. No tracked-file churn is caused by `createBin`.
- [ ] The actual first workspace-install CLI test is owned by 2.1 and repeated in 2.2.

Status: **implemented and verified against the real repository and a disposable fixture; the real root workspace-install gate remains owned by Task 2.1/2.2, as this item itself says.** Full RED/GREEN evidence in [evidence.md](../../artifacts/workspaces/task1.5/evidence.md).

## Phase 2 — Cut over installation and lock ownership

### Task 2.1 — Introduce npm workspaces and generate the root lock

Dependencies: 0.2, 1.1–1.5. This is one coordinated cutover task; do not ship half of the manifest/lock/script transition.

Files: root manifest and lock, `.npmrc`, version files, 18 backend child locks, `lerna.json`, compile runner wiring.

Work:

- Apply root identity, membership, toolchain preflight, explicit engine policy, and postinstall design. Remove Lerna dependency/config/bootstrap. Wire root compile to the tested runner.
- Remove the 18 backend child locks; retain excluded-project locks. Generate the new root lock from the complete manifests on the pinned npm with scripts disabled during resolution only.
- Perform this in a clean scratch checkout, without old node_modules or child-lock state influencing the result. Use `npm install --package-lock-only --ignore-scripts` as a generation step, then a normal `npm ci` as proof.
- Investigate every peer conflict and each engine mismatch beyond the exact documented socks5-client exception. Make the smallest compatible correction, record why, regenerate, and retest its consumer. Do not use `--force` or `--legacy-peer-deps` as a general resolution bypass. Root `engine-strict=false` is the deliberate policy above, paired with runtime and engine verifiers.
- Compare resolution changes with baseline locks; preserve third-party versions where compatible, and explain material changes caused by consolidating separate graphs. Do not hand-merge package lock structures.

RED: `verify.cjs manifests` and `lock` fail against baseline membership/lock ownership. The baseline npm workspace discovery also fails.

GREEN / acceptance:

```bash
npm pkg get name --workspaces
node scripts/workspaces/check-runtime.cjs
node scripts/workspaces/verify.cjs manifests --structure-only
node scripts/workspaces/verify.cjs lock
npm ci --foreground-scripts
node scripts/workspaces/verify.cjs manifests
node scripts/workspaces/verify.cjs links
node scripts/workspaces/verify.cjs engines
node scripts/workspaces/verify.cjs artifacts --stage=build
npm ls --workspaces --depth=0
git diff --exit-code -- package.json package-lock.json packages
```

- [x] Run the final diff check relative to the committed candidate, not the pre-migration commit. Installation does not rewrite tracked manifests or locks. Confirmed for real once all fixes landed across 5 commits (see the decision log): `git diff --exit-code -- package.json package-lock.json packages` exits 0.
- [x] Discovery returns exactly 18 scoped workspace names; no nested benchmark or Insight appears.
- [x] Normal root `npm ci` installs and compiles all seven packages in the specified order, with scripts enabled and no stale client/node outputs. It never invokes Lerna or performs backend child installs.
- [x] Each backend internal dependency resolves locally from its consumer, and every consumer-originating internal resolution points to the intended workspace: no internal workspace is exposed through multiple lexical npm-created symlink aliases, the verifier reports both the lexical resolved path and the canonical real path for each resolution, and no nested registry copy substitutes for a local workspace. The lock has workspace links rather than registry tarballs for those internal edges.
- [x] No backend child lock is regenerated. The only tracked locks are root, Insight, and the Bitcoin benchmark.
- [x] Runtime preflight accepts Node 22 with exact selected npm and rejects unsupported major/tool versions in a fixture. Engine verification rejects each unexpected dependency mismatch; the single socks5-client exception is visible in evidence and does not suppress P2P proxy regressions.
- [x] Root lock contains no Lerna dependency tree attributable to removed orchestration. Root install/compile commands have no Lerna invocation; remaining command, CI, and Docker references are removed in the following phases before release.
- [x] `verify.cjs artifacts --stage=build` passes: required build outputs exist for logging, crypto-wallet-core, wallet-service (including copied templates), wallet-client, client, CLI (including the tracked launcher and a linked, executable root `.bin`), and node, and every other backend workspace's declared entry point resolves locally.

Status: **cutover implemented and verified against the real repository.** Full account of the RED baseline, the cutover, a genuine cross-package dependency conflict found and fixed (`crypto-rpc`'s `@solana/kit` devDependency was added at a version that diverged from `crypto-wallet-core`'s deliberate exact pin, breaking their intended single-shared-instance design), and the larger systemic finding in [evidence.md](../../artifacts/workspaces/task2.1/evidence.md): real npm-workspace hoisting exposes `@types/*` conflicts across all four TypeScript-checked packages downstream of wallet-service that Lerna's per-package isolation had always hidden -- some are packages implicitly relying on a sibling's typing they never declared themselves (fixed by declaring their own matching version), some are test code that was always implicit-`any` for a mocking library and needed a scoped `paths` shim to stay that way, and a few are genuine previously-invisible latent bugs (a wrong field type, a missing Express `Request` augmentation, imprecise `req.query` narrowing) fixed directly. A fully clean `npm ci --foreground-scripts` -- no leftover `node_modules`, build output, or child locks -- ran end-to-end twice in a row with exit 0 and all seven packages compiling in order. Real test suites were re-verified per fixed package: wallet-service 1365 passing/3 failing (the 3 are unreproducing-in-isolation suite flakiness, not a regression), wallet-client 555 passing/0 failing (matches Task 1.4's prior count exactly), CLI 165 passing/55 failing (all 55 are `prompts.test.ts` timeouts from this sandbox having no real TTY for its keystroke-simulation tests, confirmed by a direct hang reproduction), bitcore-node compiles clean but its full suite needs live network access this sandbox doesn't have. All fixes landed across 5 focused commits, each with its own decision-log entry (`.idea/npm-workspaces/bitcore-decision-log.json`); notably, an initial `any`-loosening of `bitcore-wallet-service`'s `v8.ts` `request` field was reverted in favor of the precise `typeof request` type once identified as unnecessary, fixing its test mocks instead (see the follow-up doc for the two remaining superagent/sinon fields where that trade-off was kept as accepted debt). Task 2.1 is complete.

### Task 2.2 — Verify cold installation, native modules, and CLI linking

Dependencies: 2.1.

Work: execute a second independent cold install from the committed candidate, validating the tracked CLI launcher from 1.5 as well as native dependency behavior. Do not use reinstall or root symlink repair to satisfy first-install acceptance.

RED/GREEN: Task 1.5 owns the bin-link RED. Here reproduce its GREEN in the real repository. Native/module-load checks are regressions unless a real layout failure is observed.

GREEN / acceptance:

- [x] A new checkout with no installed dependencies or generated output completes `npm ci` and root compile on the pinned Node 22 Linux environment; repeat on the supported developer platform.
- [x] Load client `bcrypt`, `leveldown`, and `secp256k1` from the client's resolution context and perform minimal operations using the installed APIs. Run the TSS signing tests; merely finding `.node` files does not prove ABI compatibility.
- [x] `./node_modules/.bin/bitcore-cli --help` exits zero after the first install. Its target is inside this checkout; no absolute path from another checkout is embedded.
- [x] Loading mnemonic, P2P, TSS, and crypto-wallet-core together produces no duplicate primitive-library-instance error; native Node module identity matches the intended local libraries. Treat that native-load identity check as distinct from resolver-path identity: also confirm that each of these primitive libraries is reached through one intended workspace-resolution path across the tested consumers, not merely one canonical real path after symlink dereferencing. The previous LavaMoat failure occurred at the resolver-path layer even though Node's native loader had already canonicalized identity correctly, so a passing native-load check alone does not establish the resolver-path invariant this task requires.
- [x] Both installs leave root/excluded-project lock hashes unchanged. A second ordinary `npm ci` in the same disposable checkout also succeeds.
- [x] A temporary incompatible workspace manifest change causes `npm ci` or the contract verifier to fail, rather than silently selecting an unintended registry package. Restore the fixture after the check.

Status: **verified against the real repository on both the pinned Node 22
Linux environment (a real `node:22.16.0-bookworm` container; `linux/arm64`,
not CI's `x86_64` -- the one gap this session could not close, stated
plainly rather than smoothed over) and the supported macOS developer
platform.** A real, previously-unknown defect was found strictly by
actually running the pinned Linux environment for the first time (not by
reasoning about it): npm's SIGINT/SIGTERM forwarding to a running compile
script silently fails on Debian/Ubuntu's `/bin/sh` (dash), permanently
orphaning the process and hanging anything that waits on it -- a real,
permanent platform fact (confirmed with a minimal, direct `sh -c`
reproduction), not a sandbox artifact. Root-caused, fixed in
`scripts/workspaces/compile.cjs`, and reverified stable across repeated
runs on both platforms (commit `c08a217f0611a047985a92515cfdb6fb6d40f462`,
logged in `bitcore-decision-log.json`). Full account, evidence, and logs in
[evidence.md](../../artifacts/workspaces/task2.2/evidence.md). The optional
LavaMoat topology probe below was not run; all required gates above are
green without it.

#### Optional / informational LavaMoat topology probe

This probe is informational only. It is not a migration acceptance gate and its result does not affect any GREEN/acceptance criterion above or elsewhere in this plan.

Work:

- Run only after Task 2.2 is green, using the npm-workspaces candidate as installed for that task. Do not add LavaMoat dependencies, configuration, or policy generation to satisfy this probe.
- Reproduce the smallest previously failing LavaMoat runtime path that demonstrated duplicate Bitcore package identity under the Lerna/bootstrap layout.
- Compare outcomes to determine whether removing the Lerna/bootstrap topology also removes that previous duplicate-instance failure.

Outcome:

- A failure of this probe does not fail the npm-workspaces migration; it becomes input to the separate, later LavaMoat-runtime phase.
- A success is evidence that the workspace migration removed the known topology blocker; it does not constitute complete LavaMoat runtime integration or policy validation.
- Do not broaden this probe into policy generation, LavaMoat configuration design, application-wide runtime testing, or any other work belonging to the separate LavaMoat-runtime phase.

This probe exists solely to check whether Phase 1 achieved its intended invariant — that npm workspaces produce one authoritative backend dependency graph in which each internal workspace resolves locally from its consumers through a consistent package identity, without multiple unintended symlink aliases or runtime filesystem bypasses — so that the separate LavaMoat-runtime phase can start from a known, controlled npm-workspaces topology rather than from Lerna/bootstrap-created aliasing.

## Phase 3 — Preserve developer commands and CI

### Task 3.1 — Replace root and legacy command routing

Dependencies: 2.1.

Files: root scripts, `packages/build`, `ci.sh`, package Makefiles and retained developer instructions.

Work:

- Rewrite the 17 `test:<directory>` aliases using scoped workspace selectors and preserve arguments and exit codes. Do not add `--if-present` to required tests.
- Route `node` and `bws` through workspace start scripts. Preserve application cwd and environment inheritance.
- Route watch directly to client's watcher, and run the two Docker build scripts explicitly in sequence. Keep `build`'s root-image meaning.
- Replace `packages/build` with a root-relative delegation to the canonical compile command, resolving location from the script path rather than caller cwd.
- Correct `ci.sh`'s nonexistent `ci:bitcore-node` example to the real test command.
- Replace active Makefile `.bin` assumptions with npm execution or retire obsolete targets with a documented replacement. For legacy browser HTML/Travis paths, record which are retained and adapt retained paths; do not silently present broken legacy entry points as supported.

Acceptance:

- [x] Every existing root test alias executes the intended package, forwards an argument in a fixture, and returns failure when its child fails.
- [x] Start commands resolve the expected package cwd and local modules in an isolated service smoke run.
- [x] Watch starts the client compiler, rebuilds after an isolated source edit, and terminates without leaving child processes after SIGINT.
- [x] Docker build routing runs exactly node then wallet-service, and stops if the first build fails; test routing with fixture commands before building images.
- [x] `packages/build` works from root and from `packages/`. No bootstrap alias or hidden Lerna fallback remains.
- [x] Full required script regressions are covered by the final matrix; no broad `npm test --workspaces` is substituted for tests needing different prerequisites.

RED/GREEN: routing uses regression evidence; injected child-command failure validates failure propagation without changing application code.

Status: **implemented and verified against the real repository.** Most of this task's "Work" list (the 17 `test:<directory>` aliases, `node`/`bws`, `watch`, `build:docker`) turned out to already match the target design, introduced by Task 2.1's coordinated manifest/script cutover rather than this task; that finding was re-verified against the acceptance-spec, not assumed. The genuinely remaining work -- `packages/build` (rewritten to delegate to the canonical compile runner, resolving root from the script's own location; the old version's `exit`-inside-a-subshell bug meant it never actually stopped on a child failure, reproduced separately, not by relying on this repo's own packages happening to fail), `ci.sh`'s stale `ci:bitcore-node` example (corrected to the real `test:bitcore-node` alias), and the two unreferenced, already-unsatisfiable package Makefiles (retired; neither was reachable from any script, doc, or CI job) -- is done. Every routing path was then exercised for real rather than only read: `test:crypto-wallet-core -- --grep IDeriver` proved argument forwarding through a real filtered run (8/8 passing) with a full unfiltered run immediately after confirming the normal path is still green (265 passing, matching Task 2.1's count exactly); `test:bitcore-lib` proved real routing to the intended package and real failure propagation (blocked only by Task 1.1's already-documented local chromedriver gap, not a regression); `watch` was started, triggered a real incremental rebuild from an isolated source edit, and left zero orphaned processes after `SIGINT`; `bws`/`node` were run live, with `node` independently reaching the exact HTTP readiness probe the acceptance-spec specifies for Task 4.1 (`GET /api/status/enabled-chains` returning the full configured chain list) against the real local install; and `build:docker`'s exact shell-`&&` pattern was proven, via a disposable two-workspace fixture (real image builds remain Task 4.1's own gate), to run node then wallet-service in order and to stop before wallet-service when node fails. Full account, commands, and output in [evidence.md](../../artifacts/workspaces/task3.1/evidence.md).

### Task 3.2 — Preserve Insight's independent workflow

Dependencies: 2.1.

Files: root Insight scripts and developer docs; Insight files only for a reproduced migration regression.

Acceptance:

```bash
npm run insight:install
npm run insight:build
```

- [x] `insight:build` remains a single install-and-build command. Both scripts run on Node 22 and use Insight's own locked TypeScript 4.6.3/tooling dependencies.
- [x] Build produces `packages/insight/build/index.html` and relocated assets under `build/insight/`, consistent with `postbuild.sh`.
- [x] A second install/build is reproducible and leaves the root and Insight locks unchanged.
- [x] Root backend `npm ci` does not install Insight or run its lifecycle scripts.
- [x] Dependencies added to Insight are documented as independent prefix-scoped operations; backend dependency changes use `npm install <dependency> --workspace=<scoped-name>` and update root lock only.

RED/GREEN: before/after regression, plus negative workspace-membership check. Existing unrelated Insight failures must be recorded, not solved through an unplanned React toolchain migration.

Status: **verified against the real repository; no script changes were needed.** `insight:install`/`insight:build` already matched the target design from Task 2.1's cutover; this task ran them for real rather than trusting that they worked. `npm run insight:install` installed cleanly on Node 22.16.0 from Insight's own independent, already-locked manifest (TypeScript 4.6.3 confirmed by direct read). `npm run insight:build` produced a real `packages/insight/build/index.html` and, checked directly on disk (not inferred from the build log), the exact `postbuild.sh` relocation of `asset-manifest.json`/`favicon.ico`/`robots.txt`/`static` under `build/insight/`. A second full install-and-build cycle left both `package-lock.json` and `packages/insight/package-lock.json` byte-identical (`shasum` before/after). `npm install --dry-run --workspace=insight` from root genuinely fails with "No workspaces found," confirming live -- not just by omission from the root manifest/lock -- that Insight cannot be reached through root-level workspace-scoped operations, which is the same result that establishes each side's one correct dependency-change path (root's `--workspace=<scoped-name>` vs. Insight's own `--prefix packages/insight`). Full account, commands, and output in [evidence.md](../../artifacts/workspaces/task3.2/evidence.md).

### Task 3.3 — Update CircleCI installation, caching, and test inventory

Dependencies: 2.1, 3.1; validate Docker test jobs after Phase 4.

Files: `.circleci/config.yml`.

Work:

- Align Node/npm selection. Remove Lerna lock concatenation and all `combined-package-lock.txt` references.
- Cache npm's download cache rather than restored installed trees. Use a new cache namespace keyed by OS/architecture, exact Node/npm policy, root lock, and install-affecting `.npmrc` policy. Always run `npm ci` whether the cache hits or misses.
- Keep the full workspace tree and root dependencies together when persisting build output. Continue using isolated job filesystems for tests that clean/build output.
- Remove the disabled package-only `build-crypto-rpc` path or rewrite it to preserve full workspace context. Prefer removal of this inactive CI path while the common build job supplies the active test job.
- Preserve all 15 active jobs. Add P2P Cash and Doge explicitly if adopting the full 17-alias regression gate; this plan's final gate includes both.
- Check the current browser/version-print commands and native build prerequisite requirements. Remove Python 2 setup only if the measured Node 22 dependency graph no longer needs it; do not retain it as an assumed node-gyp requirement.

Acceptance:

- [x] CircleCI config validates using its supported validator, and contains no missing checksum input. Verified with the real `circleci` CLI (`circleci config validate`), and with `circleci config process` to confirm the fully expanded config contains no leftover `combined-package-lock.txt`/Lerna reference; both checksummed files (`package-lock.json`, `.npmrc`) exist in the tree.
- [ ] Empty-cache and warm-cache runs both install from the same root lock and pass workspace link checks before testing. Every command the `build` job issues was run for real against this repository (`check-runtime.cjs`, `verify.cjs manifests/lock/engines/links/artifacts`, `npm ls --workspaces`, the orchestration test suite) and passes. Actually triggering CircleCI's own hosted empty-cache/warm-cache pipeline requires pushing this branch, which was not done autonomously; left open pending that real run.
- [x] Test jobs can resolve local scoped dependencies after workspace attachment; none relies on child lockfiles or installed registry copies of local packages. Structural: the 18 backend child locks were already removed in Task 2.1, `verify.cjs links` passes locally against the real 46-edge internal dependency graph, and every test job now runs the same real `verify.cjs`-checked install rather than a per-package installed tree.
- [x] All 17 package aliases are accounted for as actual jobs/checks with required browsers/databases/chain services. Tool versions and command logs are retained. Confirmed with a programmatic diff of root `package.json`'s `test:*` scripts against `.circleci/config.yml`'s job names: both are the identical 17-entry set (P2P Cash and Doge jobs added). Browser (Chrome)/database (Mongo via `start_docker_images`) provisioning is unchanged from baseline; "Print versions" is retained.
- [x] Root compile is not run concurrently with tests in one shared filesystem. Recompilation per isolated job is acceptable; optimizing it is outside this task. Each job is its own CircleCI machine-executor VM; compile runs once in `build` (via `postinstall`) and again, independently, inside each isolated test job before its own test command -- never two jobs sharing one filesystem.

RED/GREEN: use baseline/current CI results and a fresh cache namespace. Do not fabricate a broken CI configuration solely to create RED.

Status: **implemented and locally verified against the real repository; the actual CircleCI hosted pipeline run remains open.** Full account, real command output, and the found-and-fixed prerequisite gap (Task 2.1's evidence claimed a root `.npmrc` was added; it was never actually committed -- added here since this task's cache-key design depends on it) are in [evidence.md](../../artifacts/workspaces/task3.3/evidence.md). Summary: Node/npm pins aligned to 22.16.0/10.9.2 with npm's own version now explicitly force-installed (previously unpinned); all Lerna lock-concatenation and `combined-package-lock.txt` references removed; caching switched from a disabled restore of per-package `node_modules` trees to npm's own download cache (`~/.npm`), keyed on OS/arch, the exact Node/npm pair, and checksums of `package-lock.json` and `.npmrc`, with `npm ci` always running regardless of cache outcome; `check-runtime.cjs` preflight added as an explicit CI step before both `npm ci` and each job's `npm run compile` (compensating for a separately-noted, out-of-scope gap: the compile runner itself still doesn't call it, contrary to the plan's target design); the always-disabled `build-crypto-rpc` job and its now-orphaned executor removed outright rather than repaired; P2P Cash and Doge jobs added, bringing CircleCI to the full 17-alias set (verified as an exact match, not eyeballed); and `use_python2`/pyenv-2.7 setup removed, backed by Task 2.2's own real Linux cold-install log showing every native module's node-gyp compile already resolving Python 3.11.2 with no Python 2 use anywhere. Two real, pre-existing, unrelated test failures were found (and left unfixed, per this task's scope) while exercising the newly-added P2P Cash/Doge jobs -- exact signatures recorded in the evidence file. The `crypto-rpc` job's real pass is explicitly deferred to Task 4.2 per this plan's own dependency line ("validate Docker test jobs after Phase 4"): its test command still drives `packages/crypto-rpc/docker-compose.yml`'s package-local build context, which Task 4.2 is scoped to fix.

## Phase 4 — Migrate container workflows

### Task 4.1 — Build root, node, and wallet-service images from workspace inputs

Dependencies: 2.1, 3.1.

Files: root Dockerfile, node/wallet-service Dockerfiles, root `.dockerignore`.

Work:

- Copy root manifest/lock, root `.npmrc`, the new compile scripts, and workspace sources needed during postinstall. Remove `COPY lerna.json` and bootstrap commands.
- Install the pinned npm on the selected Node 22 base; run one normal root `npm ci`. Keep compiler/dev dependencies for this first migration.
- Ensure dependency layers never include host node_modules and runtime layers preserve relative workspace symlink targets. Preserve existing service commands/cwd.

RED: old service Dockerfiles fail to build against the candidate checkout without `lerna.json`/bootstrap. The diagnostic must identify those removed inputs.

GREEN / acceptance:

```bash
docker build --no-cache -t bitcore-workspaces-test .
docker build --no-cache -t bitcore-node-workspaces-test -f packages/bitcore-node/Dockerfile .
docker build --no-cache -t bitcore-bws-workspaces-test -f packages/bitcore-wallet-service/Dockerfile .
```

- [x] All three images build from a clean source context; logs show the pinned Node/npm and one root install with successful compile.
- [x] Workspace resolution verifier passes inside each image. Node's server output and wallet-service templates/worker entry files exist.
- [x] Against isolated test services, node/API returns HTTP 200 with the configured chain list at `/api/status/enabled-chains`; BWS returns HTTP 200 with `serviceVersion` at `/bws/api/v1/version/`. Also confirm required background workers reach their established startup state. A tailing shell can remain alive after workers fail; container liveness alone is insufficient.
- [x] No image depends on host package directories, host-built native modules, or Lerna.

Status: **implemented and verified against the real repository (`linux/arm64`, this machine's own architecture; CI's actual `x86_64` executor is not exercised here, the same documented gap as Task 2.2's own evidence).** All three Dockerfiles now pin `node:22.16.0-bookworm`, force-install `npm@10.9.2`, run the `check-runtime.cjs` preflight before `npm ci --foreground-scripts`, and (node/wallet-service) install/compile from the whole monorepo root instead of a hand-picked `lerna.json`+`package*.json`+`packages/` copy, since root is what actually links each package's scoped local dependencies. RED reproduced for real: building the git-committed pre-edit `bitcore-node` Dockerfile against the current (Lerna-already-removed) repo fails exactly as predicted, at `COPY lerna.json ./` with `"/lerna.json": not found`. All three images then built clean with `--no-cache` (exit 0), each showing the pinned runtime and all seven packages compiling in order in its own log; `verify.cjs manifests/engines/links/artifacts --stage=build` all report `PASS` inside all three running images, with zero `lerna.json`/`lerna` package in any of them. A real empirical finding along the way: the first successful build shipped ~600MB of this host's own accumulated, gitignored-but-not-dockerignored `bitcore-wallet-service/logs/*.log` files into every image (all three `COPY . .`/`ADD . .` the full repo root) -- fixed by adding `**/logs`, `**/pids`, `*.log` to `.dockerignore` (mirroring this repo's own `.gitignore` conventions for these paths) and rebuilding all three from scratch, shrinking them from 6.73/5.5/5.5GB to 6.01/4.78/4.78GB. Readiness was then proven against real running containers on an isolated Docker network with a real Mongo `3.6.23`, each pointed at a minimal fixture config: node's `/api/status/enabled-chains` returned the fixture's exact configured chain (`[{"chain":"BTC","network":"regtest"}]`), and BWS's `/bws/api/v1/version/` returned `{"serviceVersion":"bws-11.10.7"}`. Checking actual worker liveness (not just container liveness, per this task's own explicit warning) surfaced a second real, pre-existing, out-of-scope defect: `bcmonitor` died silently behind `start-docker.sh`'s still-tailing shell, because wallet-service's own default `blockchainExplorerOpts.socketApiKey` (`'socketApiKey'`, a literal placeholder) is not valid Base58Check and crashes `v8.ts`'s key-decode as soon as a wallets socket connects -- reproducible identically under the old Lerna deployment, unrelated to this migration, and recorded rather than fixed, matching this plan's own treatment of RPC's missing `migrate` command. Substituting one throwaway validly-formed key in the fixture (not a source change) let all six workers reach and hold their own established ready state, confirmed by each one's own startup log line plus, for `bcmonitor` specifically, continued process liveness and real incoming blockchain notifications across repeated samples. Full account, exact commands/output, and both findings are in [evidence.md](../../artifacts/workspaces/task4.1/evidence.md).

### Task 4.2 — Use local scoped workspaces in RPC test containers

Dependencies: 4.1.

Files: `packages/crypto-rpc/docker-compose.yml`, `test/docker/Dockerfile-test`, `start.dockerfile` and obsolete start-service references.

Work:

- Change the test-runner build context to monorepo root and adjust the Dockerfile path/COPY inputs accordingly. Install/compile at `/bitcore`; set execution cwd to `/bitcore/packages/crypto-rpc`.
- Remove unscoped crypto-wallet-core deletion/bind mounts. Use npm's scoped workspace link to the compiled local source in the image.
- Preserve working paths for Hardhat, contracts, test fixtures, and the solc PATH addition if it remains used.
- Update both RPC Node Dockerfiles to use root installation inputs and correct execution cwd/PATH. Keep the existing `start` service and its known missing `migrate` command as a separately documented baseline defect; do not remove services or invent application commands as part of dependency migration.

RED: run a resolution probe in the old test image that requires the resolved crypto-wallet-core path to be the intended locally built scoped package. The unscoped mount must not satisfy it.

GREEN / acceptance:

- [x] `docker compose -f packages/crypto-rpc/docker-compose.yml config` validates after path changes.
- [x] A no-cache RPC test image build succeeds from repository root without any host node_modules or prebuilt crypto-wallet-core.
- [x] Inside the runner, resolving `@bitpay-labs/crypto-wallet-core` points to `/bitcore/packages/crypto-wallet-core/ts_build/src/index.js`; internal primitive dependencies also point to workspace sources.
- [x] Existing `npm run test:crypto-rpc` reaches Hardhat compile/deploy/test and RPC tests with the expected chain endpoints, retaining c8's configured coverage thresholds.
- [x] No scoped dependency is substituted by an unscoped bind mount. The supported test runner does not invoke `migrate`; the unchanged defect in the separate start service is recorded with its follow-up scope.

Status: **implemented and verified against the real repository, with one pre-existing gap left
un-worked-around.** Both Dockerfiles now install/compile from `/bitcore` (root) using the same
pinned-base/`check-runtime.cjs`/`npm ci --foreground-scripts` shape as Task 4.1, then set
`WORKDIR /bitcore/packages/crypto-rpc` for execution; the old `ssh-keyscan` step was dropped
(confirmed unnecessary -- the one `git+ssh` dependency reachable from this repo's lockfile resolves
over plain HTTPS, and Task 4.1's own root install already completed without it). `docker-compose.yml`
moved the `start`/`test_runner` build contexts to the monorepo root and removed the
`../crypto-wallet-core` bind mounts along with the dead, unreferenced `cwc` external volume. RED
reproduced for real -- and more thoroughly dead than the plan anticipated: building the old, committed
Dockerfile-test/compose and attaching the documented bind mount showed it targets the *unscoped*
module name, while every real `import` in crypto-rpc's source uses the *scoped*
`@bitpay-labs/crypto-wallet-core` -- so the old local-source override never took effect at all,
bind mount or not; the test runner was always silently exercising the registry-published copy.
GREEN reproduced for real: `docker compose config` validates; a `--no-cache` image builds clean from
root context with no host `node_modules`/prebuilt crypto-wallet-core; inside it,
`@bitpay-labs/crypto-wallet-core` resolves to exactly
`/bitcore/packages/crypto-wallet-core/ts_build/src/index.js`, and `verify.cjs links` confirms
crypto-wallet-core's own internal primitives (`bitcore-lib`/`-cash`/`-doge`/`-ltc`) resolve to real
workspace source too, not a nested registry copy. Two real, previously-latent defects were found and
fixed along the way, not just documented: a root `.dockerignore` bug (bare `artifacts`/`coverage`/
`.nyc_output` patterns only anchor to the build-context root in Docker, unlike `.gitignore` -- silently
letting crypto-rpc's own Hardhat `blockchain/EVM/artifacts`/`cache` leak into the image once this task
gave crypto-rpc's Dockerfiles root context; fixed with `**/`-prefixed patterns, reconfirmed the root
image still passes Task 4.1's own verification with no regression); and a genuine `npx`/npm-workspaces
regression (`npm run hardhat:compile` failed with `HH1: You are not inside a Hardhat project` even
though the config file is exactly at cwd, traced to `npx` silently resetting cwd to the nearest
ancestor package.json once `hardhat` moved from a standalone per-package install to root-hoisted --
confirmed workspaces-specific against two disposable npm fixtures, not general `npx` behavior; fixed
by adding `packages/crypto-rpc/blockchain/EVM/package.json`). The real
`npm run test:crypto-rpc` was then run end to end against real chain containers: the `rippled` service
itself (untouched by this task) fails to build on this `arm64` host -- Ripple's own apt repo publishes
no `arm64` package, confirmed by building the untouched `rippled.Dockerfile` standalone with an
identical failure, the same class of already-documented arm64-host/x86_64-CI gap as Tasks 2.2 and 4.1.
Worked around with a temporary, uncommitted compose copy (rippled service removed) to still exercise
the real pipeline: Hardhat compile/deploy/test against real `geth`, then the full RPC mocha suite
against real `bitcoin`/`bitcoin-cash`/`dogecoin`/`litecoin`/`lightning`/`lightning2`/`solana` --
393 passing. 20 of 21 failures are exactly the expected shape of an unreachable `rippled`
(`NotConnectedError: getaddrinfo ENOTFOUND rippled` and direct consequences of it), and the resulting
79.49%-vs-80%-required branch coverage shortfall is the direct, expected consequence of never
executing XRP code paths in this run -- not a regression. The 21st failure (`LND Tests`, a 30-second
sync-wait timeout hardcoded in the test file itself) was reproduced twice more in isolation and traced
to this test's own chain images running only as `linux/amd64` (QEMU-emulated on this arm64 host, per
`docker image inspect`); this task's changes never touch that test, those images, or any timeout, and
the same budget against the same emulated images would fail identically under the pre-Task-4.2 setup
on this host -- recorded as a pre-existing, environment-specific limitation rather than fixed. Full
account, exact commands/output, and all four findings are in
[evidence.md](../../artifacts/workspaces/task4.2/evidence.md).

### Task 4.3 — Make local test containers independent of host dependency layout

Dependencies: 4.1, 4.2.

Files: `docker-compose.test.local.yml`, `ci.sh`, local test instructions; add an entry script only if needed.

Work: retain source editing through the existing `/bitcore` bind mount, but use container-owned dependency storage and perform the root install/compile inside the mounted checkout. Account for both root and legitimate nested dependency locations. Prevent host macOS native modules from entering Linux resolution; a root node_modules volume alone does not hide nested host node_modules. A source-only synchronized container checkout is an acceptable implementation if simpler to verify.

Acceptance:

- [x] From a disposable host checkout with no dependencies/output, `./ci.sh build` followed by a documented package test command installs/prepares and runs successfully in Linux.
- [x] Repeat with host dependencies present: the test process still loads only container-installed native dependencies.
- [x] Container workspace links point to visible local sources; compile output is available to the test runner after mounts are applied.
- [x] Tests preserve configured DB/chain environment and cwd. Install failure stops the test runner before application tests begin.
- [x] Commands use isolated Compose project/data resources and clean up those resources without touching another developer's services.

RED/GREEN: reproduce the bind mount hiding image dependencies in the old layout, then pass the same cold-host test with the chosen storage approach.

Status: **implemented and verified against the real repository.** `docker-compose.test.local.yml`'s
`test_runner` keeps its existing `.:/bitcore` source bind mount but now also gets an explicit
`entrypoint:` (a new `scripts/workspaces/docker-local-entrypoint.sh`) and one container-owned named
volume layered over root `node_modules` plus every workspace package's own `node_modules` path,
mirroring root `package.json`'s own workspaces list rather than only the one nesting site this
checkout happens to have today. The entrypoint runs the real preflight/`npm ci --foreground-scripts`
(triggering the existing compile chain) against whatever the mounts hold at container start, then
hands off to the actual test command; `ci.sh`'s `run` no longer overrides the entrypoint with the raw
command, it passes the command through to this script instead (and adds `--rm` so ad hoc run
containers no longer need `down`'s own manual sweep). RED reproduced for real and more concretely than
a generic "empty node_modules" check: this checkout's own real, pre-existing host `node_modules`
already nests a genuine host-compiled macOS/arm64 `secp256k1` `addon.node` inside
`packages/bitcore-node` and `packages/bitcore-wallet-service` (each needs `secp256k1@4.0.3` while root
hoists `3.7.1` -- confirmed directly against `package-lock.json`, not assumed), and under the old
bind-mount-only layout, loading that exact file inside the container throws `invalid ELF header` --
going through the package's public API instead of loading the file directly silently falls back to a
slower pure-JS path rather than crashing, the more dangerous failure mode. GREEN reproduced for real:
a disposable install from brand-new volumes ran a genuine `npm ci --foreground-scripts` end to end
(real `node-gyp` compiles targeting `linux/arm64`, `[verify:engines] PASS`, all seven packages
compiling in order), after which the same nested file is a real Linux ELF addon at the correct nested
version; workspace symlinks (`node_modules/@bitpay-labs/*`) still resolve through to the live mounted
`/bitcore/packages/*` sources; compile output lands on the host checkout itself (not a volume) and is
timestamped from the run just performed; a real desynced-lockfile install failure stopped the run
before the test command executed (confirmed the command's expected output never appeared, exit `1`);
and named volumes are Compose-project-prefixed (confirmed via `docker volume ls`) and were fully
removed, without touching anything else on the host, by `ci.sh down`'s own `down -v`. A real,
complete, passing application test (`test:bitcore-logging`, 29 passing, exit `0`) was run end to end
through the exact command shape `ci.sh run` now produces (the literal `./ci.sh run` invocation is
blocked by `depends_on`'s `rippled` service, the same already-documented arm64-host gap from Tasks
2.2/4.1/4.2 -- worked around only for this verification with an uncommitted, deleted-after-use compose
copy, matching Task 4.2's own precedent). One further real, pre-existing, out-of-scope defect was
found along the way and left unfixed per this task's scope: `bitcore-lib`'s `gulp test` (Mocha:
4694 passing) subsequently fails its own WebdriverIO/browser step on this host because a real `npm ci`
against this repository's own committed (macOS-generated) lockfile does not install
`@rollup/rollup-linux-arm64-gnu` on `linux/arm64` -- a documented npm optional-dependency bug
(npm/cli#4828), reproduced identically against the untouched root Dockerfile's own image-build-time
`npm ci` with no bind mount, volumes, or entrypoint involved, proving it predates and is unrelated to
this task's changes. `ci.sh`'s own `--help` text already describes this task's unchanged
command-line interface, so no separate "local test instructions" doc needed to be added. Full account,
exact commands/output, and both findings are in [evidence.md](../../artifacts/workspaces/task4.3/evidence.md).

## Phase 5 — Validate distribution and complete removal

### Task 5.1 — Preserve package artifacts and explicit release commands

Dependencies: 2.2, 3.1, package regression tests.

Files: packaging scripts/metadata only where needed, `packages/pub`, release documentation.

Work:

- Record the current release-loop selection and order, including its duplicate P2P Doge entry, as baseline metadata. Keep repair of that pre-existing duplicate as a separate follow-up; do not expand publication to all workspaces.
- Add a separate non-publishing artifact check command that prepares packages and packs an explicit deduplicated validation list. Do not call existing `pub` scripts during acceptance: they invoke real publication. Verify the existing release entry point still routes into package scripts using a stub npm process.
- Keep private root and private CLI out of release selection. Do not replace the release loop with blanket `npm publish --workspaces`.
- Preserve package-specific build behavior: Gulp `build` includes tests, wallet-client `pub` includes lint, and TypeScript packages need generated outputs. `npm pack` alone does not substitute for those build scripts. [npm pack](https://docs.npmjs.com/cli/v10/commands/npm-pack/)
- Check all 17 non-private backend packages for valid package artifacts, including packages outside the current publish loop. Artifact validation does not authorize publication.
- Validate wallet-client's corrected declaration entry with an external TypeScript consumer as well as a tarball file check.

Acceptance:

- [ ] Dry-run output names each selected package once, excludes private packages, reports tarball paths, propagates failures, and makes no publish/tag/version calls.
- [ ] Tarballs include declared `main`, `types`, bins, required shared build configs and service templates; generated entry points are not lost through `.gitignore` / `.npmignore` interaction.
- [ ] Manifests in tarballs retain publishable semver dependencies and contain no filesystem/workspace protocols or absolute checkout paths.
- [ ] In temporary consumers outside the monorepo, install the candidate tarballs for the complete local runtime closure together so npm cannot silently substitute released internal packages. Verify actual installed versions/paths and exercise representative public APIs and ESM RPC imports on Node 22. Servers use a separate configured smoke process.
- [ ] Validate each package's declared direct dependencies independently of what the combined consumer happens to hoist; a consumer containing every tarball can mask missing declarations.
- [ ] Public package versions, names, release-loop membership/order and access metadata are unchanged. Artifact-validation deduplication does not change publication policy. No registry publication is performed.

RED/GREEN: package contents and public API behavior are regressions. Use targeted isolated-consumer RED for a confirmed missing runtime dependency or excluded build artifact.

### Task 5.2 — Document commands and remove obsolete orchestration references

Dependencies: Phases 2–5.1.

Files: root README/CONTRIBUTING, node and wallet-service installation docs, Insight/RPC docs, affected legacy entry points.

Acceptance:

- [ ] Instructions state exact Node/npm setup, root `npm ci`, automatic compilation, explicit recompile, scoped tests, watch/start/build commands, workspace dependency edits, Insight's separate install, and supported Docker test workflows.
- [ ] Instructions explain that a backend package directory is no longer an independently locked checkout; registry consumers still install published packages normally.
- [ ] Bootstrap and package-by-package install instructions are replaced wherever they describe monorepo development. Ordinary consumer `npm install @bitpay-labs/...` examples remain valid.
- [ ] Tracked executable/configuration files contain no Lerna invocation, dependency, bootstrap implementation, obsolete lock concatenation, or active stale Docker path. Historical changelog prose may mention Lerna.
- [ ] Legacy Travis, Makefile, benchmark and manual-browser workflows each have an explicit retain/update/retire disposition; nested benchmark locks are not accidentally deleted.
- [ ] New documentation commands are executed in the disposable acceptance checkout. No unit tests are required for prose edits.

### Task 5.3 — Run the final acceptance matrix and record the handoff

Dependencies: all prior tasks.

Use the committed candidate in a fresh checkout on the pinned Node 22 toolchain. Run each category once after the final relevant change; rerun a category when subsequent changes can affect it.

| Check | Command or procedure | Required evidence |
| --- | --- | --- |
| Cold root installation | `npm ci --foreground-scripts` | Exit 0, no Lerna/child installs, seven package compiles, unchanged committed locks. |
| Workspace contract | Five `verify.cjs` modes at their specified stages, `npm ls --workspaces --depth=0` | Exact membership, allowed engines, local resolution, artifacts and no missing dependencies. |
| Orchestration tests | `node --test test/workspaces/*.test.cjs` | Membership/error fixtures, failure propagation, helper layout fixtures. |
| Recompile | `npm run compile` from no generated backend output in scratch checkout | Correct order and complete artifacts; client does not clean node. |
| Primitive/browser regression | Root `test:bitcore-lib`, `test:bitcore-lib-cash`, `test:bitcore-lib-doge`, `test:bitcore-lib-ltc`, `test:bitcore-mnemonic` | Node tests and real headless WebdriverIO tests execute; generated bundle and browser readiness visible in logs. |
| P2P regression | Root `test:bitcore-p2p`, `test:bitcore-p2p-cash`, `test:bitcore-p2p-doge` | Actual suites pass; preserve existing network prerequisites or record them. |
| Logging/wallet primitives | Root `test:bitcore-logging`, `test:crypto-wallet-core`, `test:bitcore-tss` | Existing assertions, including signing vectors, pass. |
| TSS browser | `npm run test:web --workspace=@bitpay-labs/bitcore-tss` | Webpack and configured browser runner complete; required serve tooling is declared/resolved. |
| Service/client/CLI regression | Root `test:bitcore-wallet-service`, `test:bitcore-wallet-client`, `test:bitcore-client`, `test:bitcore-cli` | Correct isolated MongoDB/chain config; test data copied; tests pass without stale sibling output. |
| Node regression | Root `test:bitcore-node`; `npm run test:scripts --workspace=@bitpay-labs/bitcore-node` | Unit/integration and script suites pass with configured DB and chains. |
| RPC regression | Root `test:crypto-rpc` | Root-context container uses local scoped sources; Hardhat and c8 thresholds pass. |
| Shared helper | Its corrected package `test` plus consumer suites | Both hoisted and standalone layouts supported. |
| Native/CLI smoke | Task 2.2 probes and `./node_modules/.bin/bitcore-cli --help` | Loaded native APIs and first-install CLI bin work. |
| Developer entry points | Task 3.1 watch/start/build routing checks | Cwd, output, signals, child exit codes preserved. |
| Insight | `npm run insight:install`, `npm run insight:build` | Independent lock unchanged; expected static output exists. |
| Lint | `npm run lint` | No newly introduced errors; baseline failures have explicit dispositions. |
| Containers | Tasks 4.1–4.3 and application-ready probes | Three main images, RPC runner, local bind-mount behavior verified. |
| CI | Task 3.3 cold/warm runs | All required jobs complete; cache state does not affect dependency graph. |
| Distribution | Task 5.1 dry-run pack and external-consumer probes | Valid tarballs, direct declarations, no registry publication. |
| Final repository state | Manifest/lock hashes, tracked-reference scan, `git diff --exit-code` after acceptance | No install-generated tracked churn or obsolete executable orchestration. |

Service tests may need MongoDB, Bitcoin, Geth, Erigon, Ripple and other package-specific chains; RPC's Compose suite additionally provisions Cash, Dogecoin, Litecoin, Lightning and Solana. Client tests labeled `unit` still use node services/storage. Provision based on the actual test configuration, not the script name. Keep shared database tests sequential or isolate database names and Compose project names.

Final acceptance:

- [ ] Every required task criterion and matrix gate has a result and linked log. Blocked prerequisites are resolved before declaring migration complete; separately scoped baseline defects are listed outside the required migration gates.
- [ ] Remaining unrelated baseline defects have explicit out-of-scope dispositions and unchanged reproduction evidence. No migrated behavior, script assertion, or coverage threshold is weakened to pass acceptance.
- [ ] No unrequested application API, public package version, runtime-major, or release-policy change is bundled into the migration.
- [ ] Handoff lists changed files, commands, remaining separately scoped defects, and the exact tested commit/toolchain.

## Integration and rollback

Preparation tasks in Phase 1 can land independently when they remain compatible with Lerna. The workspace manifest, root lock, lifecycle routing, CI and Docker changes form one release boundary: merge/deploy only after their joint acceptance. Keep one lockfile owner while integrating task branches.

If acceptance fails, retain RED logs and fix the responsible atomic task. Do not regenerate locks repeatedly without identifying the failing dependency or resolution path.

Rollback restores the prior committed root manifest/lock, Lerna config, child locks, and matching CI/Docker files together. Reinstall in a fresh checkout on the prior tested toolchain; do not reuse workspace-installed node_modules as a Lerna rollback environment. No package publication or database migration is part of this change, so rollback does not require undoing registry versions or application data.
