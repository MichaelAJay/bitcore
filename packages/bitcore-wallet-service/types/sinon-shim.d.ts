// Under Lerna's per-package installs this test suite never had a reachable
// `@types/sinon` at all, so `sinon` type-checked as implicit `any`
// (tsconfig.json sets "noImplicitAny": false) and its tests attach ad hoc
// stub methods (e.g. `addAddresses`, `getUtxos`) that were never part of the
// real Sinon API. Under real npm-workspace hoisting, bitcore-node's own
// pinned `@types/sinon` becomes ambiently reachable from every workspace,
// including this one, and typing `sinon` for real breaks that ad hoc usage.
// This shim (wired via tsconfig.json's `paths`) restores the untyped
// behavior this package's tests were actually written against, without
// touching bitcore-node's own real typing.
declare const sinon: any;
export = sinon;
