// Under Lerna's per-package installs this test suite never had a reachable
// `@types/sinon` at all, so `sinon` type-checked as implicit `any`
// (tsconfig.json sets "noImplicitAny": false). Under real npm-workspace
// hoisting, bitcore-node's own pinned `@types/sinon@4.3.3` becomes ambiently
// reachable from every workspace, including this one -- and this package's
// own `sinon@^21.0.0` doesn't ship its own bundled types, so it would
// otherwise fall back to that badly outdated declaration (e.g. rejecting
// `sinon.stub(API.prototype, 'constructor')`, and missing the legacy
// `wrappedMethod` property these tests rely on). This shim (wired via
// tsconfig.json's `paths`) restores the untyped behavior this package's
// tests were actually written against, without touching bitcore-node's own
// real typing.
declare const sinon: any;
export = sinon;
