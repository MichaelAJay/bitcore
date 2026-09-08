// Under Lerna's per-package installs this test suite never had a reachable
// `@types/sinon` at all, so `sinon` type-checked as implicit `any`
// (tsconfig.json sets "noImplicitAny": false). Under real npm-workspace
// hoisting, bitcore-node's own pinned `@types/sinon` becomes ambiently
// reachable from every workspace, including this one, and its real API
// surface (e.g. a top-level `sinon.restore()` overload requiring an
// argument) doesn't match how this suite calls it. This shim (wired via
// tsconfig.json's `paths`) restores the untyped behavior this package's
// tests were actually written against, without touching bitcore-node's own
// real typing.
declare const sinon: any;
export = sinon;
