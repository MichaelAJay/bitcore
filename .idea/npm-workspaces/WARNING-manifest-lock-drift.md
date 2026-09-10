# ⚠️ WARNING: never hand-edit a `package.json` dependency list directly

## What happened

During Task 5.1 ("Preserve package artifacts and explicit release commands"), three
runtime dependencies were moved from `devDependencies` to `dependencies` as real
defect fixes:

- `packages/bitcore-node/package.json` — `axios`
- `packages/bitcore-wallet-client/package.json` — `kbpgp`, `request-promise`

These edits were made directly to the `package.json` files (a text edit to the
`dependencies`/`devDependencies` objects) instead of through npm's own workspace
dependency command. **`package-lock.json` was never regenerated afterward.** The
root lock kept recording all three packages under `devDependencies`, silently
disagreeing with the manifests that Task 5.1 itself had just changed.

This went undetected through Tasks 5.1 and 5.2 and was only caught when Task 5.3
(final acceptance) actually ran `node scripts/workspaces/verify.cjs lock` against
the committed candidate — the one check in this migration specifically designed to
catch exactly this class of drift. It was fixed in a follow-up pass (see
`bitcore-decision-log.json` for the commit once landed) by regenerating the lock
with `npm install --package-lock-only --ignore-scripts` from a **clean scratch
checkout with no pre-existing `node_modules`** (per this plan's own Task 2.1
procedure), verified byte-identical against an independent from-scratch
regeneration, and reconfirmed with a real `npm ci` plus the full verifier suite.

## Why this is dangerous and easy to miss

- **`npm ci` does not catch it.** npm ci's own manifest/lock consistency check does
  not enforce the `dependencies`/`devDependencies` split when the resolved package
  *set* is unchanged — it happily installs and compiles as if nothing were wrong.
  A developer or a reviewer running the normal, documented install command sees no
  failure at all.
- **It is not automatically re-checked on every commit.** `verify.cjs lock` *is*
  wired into CI (`.circleci/config.yml`'s `build` job runs it before `npm ci`), so
  pushing a branch with this drift would fail CI loudly — but nothing runs it
  locally after an ordinary manifest edit, and this drift sat undetected across two
  full tasks (5.1, 5.2) before anyone actually exercised the full acceptance
  matrix (5.3) against the real committed candidate.
- **The failure mode is silent, not loud.** There is no error message pointing at
  the actual edit that caused it; it only surfaces as an abstract lock/manifest
  disagreement, potentially long after the responsible commit has landed.

## The correct practice, going forward

**Never hand-edit a `dependencies`/`devDependencies` entry in any `packages/*/package.json` directly.** Always use npm's own workspace-scoped install command, exactly as README.md already documents for adding or updating a dependency:

```bash
# Add or update a dependency (lands in "dependencies")
npm install <dependency>[@version] --workspace=@bitpay-labs/<package-directory-name>

# Add or update a dev-only dependency (lands in "devDependencies")
npm install <dependency>[@version] --workspace=@bitpay-labs/<package-directory-name> --save-dev
```

This single command updates the package's `package.json` **and** the root
`package-lock.json` together, atomically, in one npm-managed operation — including
"promoting" an existing dependency from `devDependencies` to `dependencies`:
running the plain (non-`--save-dev`) form on a package that's currently only in
`devDependencies` moves it to `dependencies` and updates the lock accordingly, at
the same pinned version if one is given.

If a manifest is ever hand-edited anyway (for example, as part of a larger
multi-file sweep where re-running `npm install --workspace=...` per change isn't
practical), **regenerate the lock immediately afterward**, following this plan's
own Task 2.1 procedure exactly:

```bash
# From a clean scratch checkout with NO pre-existing node_modules anywhere —
# old node_modules state can (in principle) influence npm's resolution.
npm install --package-lock-only --ignore-scripts
node scripts/workspaces/verify.cjs lock   # must print PASS
npm ci --foreground-scripts               # real proof, not just the lock check
```

**Do not trust "`npm ci` succeeded" as proof the lock is not stale.** Only
`node scripts/workspaces/verify.cjs lock` checks this specific invariant. Run it
explicitly after touching any `package.json` in this repository, not only when CI
happens to run it for you.
