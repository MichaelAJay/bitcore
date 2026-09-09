You are performing **Task 5.3 — Run the final acceptance matrix and record the handoff** for the Bitcore Lerna → npm workspaces migration.

This is an **acceptance execution and evidence-gathering task**, not an implementation task.

## Authoritative sources

Read these before beginning:

1. `.idea/npm-workspaces/bitcore-migration-plan.md`
2. `.idea/npm-workspaces/bitcore-acceptance-spec.md`
3. Relevant prior task evidence under `artifacts/workspaces/`
4. `.idea/npm-workspaces/bitcore-decision-log.json`
5. Any baseline/inventory/result artifacts referenced by the migration plan

Treat the migration plan and acceptance specification as normative.

Prior task evidence is supporting evidence, not proof that the final candidate still passes.

The actual committed repository state and actual command execution against it are authoritative.

## Objective

Execute Task 5.3 against the **current committed candidate in a fresh/disposable checkout**, using the exact pinned Node/npm toolchain required by the migration plan.

Produce a complete acceptance dossier showing whether every required Task 5.3 matrix gate passes.

Do **not** repair failures during this task.

If you discover a migration failure:

1. preserve the exact evidence;
2. classify it;
3. mark the affected gate FAIL;
4. continue only where doing so cannot invalidate or obscure the failure.

Do not modify application/source/configuration code to make acceptance pass.

## First: establish the tested candidate

Before executing the matrix, record:

* exact Git commit;
* branch;
* `git status`;
* Node version;
* npm version;
* OS and architecture;
* checkout path;
* confirmation that the checkout did not inherit `node_modules`, generated build output, package-local generated artifacts, or other state prohibited by the migration plan.

If the candidate has uncommitted migration changes, STOP and report that Task 5.3 cannot validly certify an uncommitted candidate.

## Build the acceptance matrix before running it

Translate Task 5.3 into a checklist containing every matrix category:

* Cold root installation
* Workspace contract
* Orchestration tests
* Recompile
* Primitive/browser regression
* P2P regression
* Logging/wallet primitives
* TSS browser
* Service/client/CLI regression
* Node regression
* RPC regression
* Shared helper
* Native/CLI smoke
* Developer entry points
* Insight
* Lint
* Containers
* CI
* Distribution
* Final repository state

Also include the four Final Acceptance requirements beneath the matrix.

For every gate record:

* normative requirement;
* exact command/procedure;
* prerequisites;
* expected evidence;
* result: `PASS`, `FAIL`, `BLOCKED`, or `NOT RUN`;
* exit code where applicable;
* log/evidence path;
* tested commit;
* Node/npm versions;
* relevant observations;
* any prior evidence consulted;
* whether later repository changes could invalidate this result.

`PASS` requires affirmative evidence.

Absence of a known failure is not PASS.

## Execute the matrix

Follow the exact Task 5.3 commands/procedures and the detailed contracts in `bitcore-acceptance-spec.md`.

Do not replace a required test with a weaker proxy.

Examples:

* If browser execution is required, compilation alone is insufficient.
* If local workspace resolution is required, `npm ls` alone is insufficient when `verify.cjs links` is specified.
* If application readiness is required, container liveness alone is insufficient.
* If first-install CLI behavior is required, a second install is insufficient.
* If external-consumer package validation is required, successful monorepo imports are insufficient.
* If CI hosted cold/warm runs are required, local reproduction does not silently convert that requirement to PASS.

Run categories sequentially where shared infrastructure or database state requires it.

Use isolated Compose project/database names where the specification requires isolation.

## Prior evidence

You may use earlier task evidence to:

* identify commands;
* understand known baseline defects;
* establish expected failure signatures;
* avoid needlessly rediscovering prior reasoning.

However, Task 5.3 is final acceptance.

Do not mark a gate PASS solely because Task 2.x, 3.x, 4.x, or 5.1 previously reported it passing.

A prior result is valid final evidence only if the acceptance specification explicitly permits reuse and it still applies to the exact final tested commit/toolchain/environment.

When uncertain, rerun the relevant command.

## Baseline defects versus migration failures

Maintain a separate baseline-defect table.

A failure may be classified as an unrelated baseline defect only when evidence establishes:

* it predates the migration or reproduces unchanged in the appropriate baseline;
* the migration did not create or worsen it;
* no migration requirement depends on the failing behavior;
* the acceptance specification permits it to remain separately scoped.

Do not use "pre-existing" as a generic waiver.

A migrated install, workspace link, compile, orchestration, Docker, distribution, CI, or other required migration behavior that fails is a migration blocker.

## Blocked gates

`BLOCKED` is not PASS.

For every blocked gate record:

* exact missing prerequisite;
* why it is unavailable;
* whether Task 5.3 requires that prerequisite before completion;
* what concrete action/environment is needed to execute it.

Task 5.3 cannot be declared complete while a required migration gate remains blocked.

## Evidence output

Create/update:

`artifacts/workspaces/task5.3/`

At minimum produce:

* `acceptance-matrix.md`
* `command-results.json`
* `baseline-defects.md`
* `unresolved-gates.md`
* `handoff.md`
* `logs/`

Preserve raw logs where practical rather than only prose summaries.

`command-results.json` should make individual commands machine-auditable and include at least:

* gate;
* command;
* cwd;
* prerequisite/environment;
* start/end or ordering information where material;
* exit status;
* commit;
* Node/npm versions;
* log path;
* classification.

Do not overwrite useful prior evidence unrelated to Task 5.3.

## Repository-state integrity

At the end:

* verify expected manifest/lock hashes/state;
* perform the required tracked-reference scan;
* perform the required `git diff --exit-code` acceptance check;
* explicitly identify any files generated or modified by acceptance;
* ensure acceptance itself did not introduce tracked churn.

## Final report

Do not give a vague summary such as "everything mostly works."

Conclude with exactly one overall state:

### `ACCEPTANCE PASS`

Only if every required migration gate passes and every Final Acceptance requirement is satisfied.

### `ACCEPTANCE FAIL`

If one or more required gates fail.

### `ACCEPTANCE INCOMPLETE`

If one or more required gates remain blocked/not run.

Then provide:

1. tested commit/toolchain/environment;
2. count of PASS / FAIL / BLOCKED / NOT RUN gates;
3. failing migration gates;
4. blocked gates;
5. separately scoped baseline defects;
6. evidence directory;
7. any acceptance category that must be rerun if the repository changes.

Do not modify the migration implementation during this task.
