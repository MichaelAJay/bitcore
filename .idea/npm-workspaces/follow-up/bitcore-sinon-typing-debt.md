# Follow-up: real Sinon (and Superagent) typing for wallet-service, wallet-client, and bitcore-cli

Status: not started. Not blocking anything. Discovered during the npm-workspaces
migration (Task 2.1); tracked here as an intentionally separate, optional
cleanup rather than folded into that migration.

## Where this comes from

See [`bitcore-migration-plan.md`](../bitcore-migration-plan.md) Task 2.1 and its
full evidence at
[`../../../artifacts/workspaces/task2.1/evidence.md`](../../../artifacts/workspaces/task2.1/evidence.md).
Short version: under Lerna's per-package-isolated installs, `bitcore-wallet-service`,
`bitcore-wallet-client`, and `bitcore-cli` never had a reachable `@types/sinon`
package at all (only `bitcore-node` ever declared one), so `sinon` type-checked
as an implicit `any` in all three (`tsconfig.json` sets `"noImplicitAny": false`).
Their test suites grew real reliance on that: ad hoc mock objects, and Sinon
methods that aren't part of the current public API (`wrappedMethod`, custom
per-test stub properties like `addAddresses`/`getUtxos` attached to plain
objects, etc.).

Real npm-workspace hoisting is permanent, not a transitional state, and it
makes `bitcore-node`'s pinned `@types/sinon@4.3.3` (`bitcore-cli` also uses a
much newer `sinon@^21.0.0` that doesn't bundle its own types either, so it
falls back to the same old pin) ambiently reachable from every sibling
workspace. Without intervention, all three packages' test compiles broke
permanently, every time, not just once during the cutover.

## The stopgap in place today

Each of the three packages has a `types/sinon-shim.d.ts` file:

- `packages/bitcore-wallet-service/types/sinon-shim.d.ts`
- `packages/bitcore-wallet-client/types/sinon-shim.d.ts`
- `packages/bitcore-cli/types/sinon-shim.d.ts`

wired via that package's own `tsconfig.json` `compilerOptions.paths`:

```json
"paths": {
  "sinon": ["./types/sinon-shim.d.ts"]
}
```

Each shim is just `declare const sinon: any; export = sinon;` — it redirects
that one package's own `import sinon from 'sinon'` resolution away from
whatever `@types/sinon` happens to be ambiently reachable, back to an
untyped `any`, restoring exactly the pre-migration behavior these three
packages' tests were actually written against. It changes nothing at
runtime (the real `sinon` package is still what actually runs); it only
un-does type-checking that never happened before.

A closely related instance, **not** using this shim mechanism but caused by
the exact same root problem, lives in `bitcore-wallet-client`:
`src/lib/paypro.ts`'s `static r` and `src/lib/payproV2.ts`'s `static request`
fields (both normally inferred from `import superagent from 'superagent'`)
are explicitly annotated `: any`, because `bitcore-wallet-client`'s test
mocks for these (lightweight fakes like `{ get: ..., end: ... }`) never
implemented the real `SuperAgentRequest` shape either — the same
"was-always-implicit-any, now made visible by hoisting" story, just via an
accidental transitive `@types/superagent` (a real dependency of
`@bitgo/sdk-lib-mpc`, used by `bitcore-tss`) instead of a sibling's deliberate
pin.

## What "done" looks like

Retire each shim (and the two `superagent` `any` fields) by actually
modernizing that package's test doubles to satisfy Sinon's (and, for the
`superagent` case, `SuperAgentRequest`'s) real typed API:

- Replace ad hoc mock objects and legacy-API calls (`wrappedMethod`,
  custom stub-attached properties that aren't real Sinon methods) with
  proper `sinon.stub()`/`sinon.createStubInstance()` usage that the real
  types actually accept.
- Once a package's test suite genuinely compiles against real Sinon types,
  declare that package's own matching `@types/sinon` (or confirm the
  package's own `sinon` version ships bundled types and none is needed) as a
  devDependency, remove its `paths` shim entry, delete its
  `types/sinon-shim.d.ts`, and re-verify with a real `tsc` and a real test
  run.
- For `bitcore-wallet-client`'s two `superagent` fields: give the test mocks
  a real interface (even a narrow hand-written one covering only the methods
  actually used -- `get`/`post`/`set`/`query`/`send`/`agent`/`end` -- would
  likely be enough) instead of relying on `any`.

This is real, potentially nontrivial test-code work per package (three
separate test suites, one of them -- `bitcore-wallet-service` -- fairly
large), not a quick follow-up. It's independent per package, so it can be
picked up and completed for one package at a time without touching the
others.

## Why this wasn't done as part of Task 2.1

Task 2.1's job was the workspace/lock/install cutover itself. Modernizing
years of accumulated test-mock patterns across three packages' test suites
to satisfy strict Sinon typing is a real, separate body of work with its own
judgment calls per call site (what the correct real type actually is at each
mock), and doing it as a side effect of a packaging migration risked scope
creep well beyond what that task needed to prove. The shim is the deliberate,
minimal choice that preserves prior behavior exactly while unblocking the
migration; this document exists so the debt it intentionally left behind
doesn't get lost.
