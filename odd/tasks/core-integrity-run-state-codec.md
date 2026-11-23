# Pure core-integrity state codec

## Objective and authority

Implement and unit-test the pure schema-1 state value and canonical JSON codec from [the design](../../openspec/changes/core-integrity-checker/design.md). The user authorized this bounded component after choosing the normal WordPress.org plugin-owned state model. This is ODD, not an SDD phase or approval of the full production plan. R1 remains open.

The component validates a snapshot; it does not authorize a transition or establish storage correctness. No database, SQL adapter, coordinator, WordPress bootstrap, UI, clock, random-token generation or filesystem boundary belongs here. No installation, network, branch, staging, commit or publication is authorized. Preserve existing dirty work and all OpenSpec artifacts.

## Exact surfaces and API

Writer surfaces (both new at mapping):
- `src/CoreIntegrity/CoreIntegrityRunState.php`
- `tests/Unit/CoreIntegrityRunStateTest.php`

The parent alone owns this progress document and its full Engram mirror under `odd/core-integrity-run-state-codec/tasks`. No other source/test/configuration edits or helper files are initially authorized.

Candidate pure API, following existing immutable CoreIntegrity values:
- `initial(string $epoch): self`
- `fromParts(string $epoch, string $revision, bool $initialEligible, ?string $owner, ?array $run): self`
- `encode(int $maxEncodedBytes, int $maxFindings): string`
- `decode(string $bytes, int $maxEncodedBytes, int $maxFindings): self`

Use `final`, private construction, readonly scalar/array properties and `InvalidArgumentException` for invalid values. Require explicit byte and finding limits; do not ship the unapproved 1 MiB/100 defaults. Fixture limits are test inputs, not product configuration. Bounds must be validated consistently by encode/decode. `fromParts` validates intrinsic schema limits; encoding additionally enforces supplied serialization/retention limits.

Reconstruct validated nested values defensively. PHP array copy-on-write alone is not proof against embedded references: test nested caller-owned references and reject objects where arrays are expected. Stored arrays must not retain mutable aliases. Never expose decoded mutable objects as readonly-but-internally-mutable state.

## Contract and boundaries

- Exact schema-1 ordered control and nested fields, nullability, object/list distinction, phase and safe-reason enums, valid UTF-8 and intrinsic bounds follow the design.
- Epoch/owner/fingerprint are supplied lowercase 64-hex values. Revision and timestamps use bounded canonical decimal strings, without integer/float conversion or arithmetic helpers not needed by this component.
- Enforce snapshot invariants for initial eligibility, owner/run combinations, progress/count/retry/findings and initial, preparing, paused, exhausted, stopped-identity, unavailable and post-purge shapes.
- Decoding uses object mode, depth 16 and strict types; reconstruct ordered objects, re-encode and compare exact bytes. Reject noncanonical whitespace/escaping/order, duplicate-field bytes, trailing input, invalid UTF-8, wrong types and excessive limits. Do not claim native decoding retains duplicate keys.
- Manifest membership/order requires the bound manifest and is not proven by structural decoding. No file existence checks or WordPress calls.
- Sticky eligibility across two states, revision reservation/increment, Continue preservation, confirmed replacement and dispatch/commit authority belong to later transition/coordinator work. A valid snapshot grants no execution authority.
- Last-file unverifiable findings can coexist with exhausted traversal and incomplete coverage. The codec validates that shape; it does not execute the batching algorithm.

## Test discipline and authorized checks

TDD is **ON**, from `openspec/config.yaml` (`strict_tdd: true`). Configured runner is PHPUnit 10.5 via `composer test`; PHP support starts at 8.1.

Focused RED/GREEN/REFACTOR command:

`composer test -- --do-not-cache-result --filter CoreIntegrityRunStateTest tests/Unit/CoreIntegrityRunStateTest.php`

Permitted focused syntax checks:
- `php -l src/CoreIntegrity/CoreIntegrityRunState.php`
- `php -l tests/Unit/CoreIntegrityRunStateTest.php`

The final verification task may run the configured `composer syntax` after source inspection confirms the existing syntax script is lint-only. Do not run `composer check` (includes audit), installs, the full suite, or any integration fixture in this unit. Further commands need parent authorization. No existing experimental enabled-run permission is renewed.

Write behavioral tests before implementation and observe RED on the exact command. Missing proposed API is an implementation gap; a wrong runner/environment/bootstrap failure is not behavioral RED. Report commands and actual counts/outcomes, then GREEN and justified refactoring. Stop on an environmental incident rather than inventing workarounds.

Runtime harness: N/A because this component has no database, WordPress, filesystem or process integration boundary and no production consumer; focused PHPUnit exercises its pure behavior. This does not replace later backend/coordinator evidence.

## Work units, routes and forecast

One coherent uncommitted component, delivered in two sequential behavior slices:
- Construction, snapshot validation and canonical encoding with tests.
- Strict decoding and malformed-input/round-trip coverage with tests.

Initial forecast: approximately 620–900 added source/test lines. Corrected S2 measures 788 lines (289 source + 499 tests); with the decoder suite, the revised complete-component forecast is approximately 1,000–1,150 added lines, with no planned deletions of preexisting work. This exceeds the advisory 400-line per-task heuristic because the schema has multiple safety-relevant states and adversarial cases. Do not omit checks, minify or add artificial files to reduce line counts. Logical slices preserve review focus; neither implies a PR or measured size exception. Delivery strategy is `ask-on-risk`, chain deferred; the user's no-Git-mutation/no-commit restriction overrides automatic delivery. Decide delivery separately if later authorized.

Routes: S1 delegated read-only mapping (4+ configuration/source inputs); S2/S3 one sequential delegated writer per slice (two nontrivial files, preparation included); S4 delegated independent verification when native assessment requires it, plus parent structural/state readback. No overlapping writers or SDD agents.

## Tasks

- [x] S1 — Map conventions, exact surfaces, configured TDD, scope and checks.
- [x] S2 — Test-first construction/shape validation/canonical encoding; timestamp regression corrected; independent 268-test / 337-assertion run and both syntax checks passed.
- [x] S3 — Test-first strict decoder and noncanonical/malformed-input coverage; writer GREEN 553 tests / 651 assertions and both syntax checks passed.
- [x] S4 — Independent 553-test / 651-assertion verification, targeted lints, repository syntax lint and 20 protected hashes passed; native review approved and acknowledged. R1 remains open.

## Evidence and progress

Mapper `mu7fcv10-m-bxw7` completed read-only. It found no target-path collision and no concrete specification behavior contradicting this bounded pure component. The user's authorization does not approve the full feature or waive future proposal/preproposal/spec reconciliation.

Parent read actual OpenSpec configuration and observed the known dirty `master` status. Before source writes, SHA-256 baselines for 20 protected paths were captured in Engram observation `5120` (`core-integrity/pure-codec-preservation-baseline`), including design, configuration, Composer/PHPUnit files, bootstrap, existing runner/tests and both experiment records. This is selected-path preservation evidence, not a whole-repository snapshot.

At creation of this task record, no codec source, tests or execution evidence existed. S2 writer `mu7fpc40-n-5saa` subsequently created only the two allowed files: 289 source lines and 475 test lines (764 total). Its observed RED was the missing required class: 260 tests, 233 assertions, 27 errors and 233 failures before implementation. GREEN passed 260 tests / 325 assertions; additional boundary cases passed with a final 265 tests / 334 assertions, no errors/failures/skips, on PHP 8.4.4 / PHPUnit 10.5.64. Both exact syntax commands passed. No implementation refactor was needed. These are writer observations, not an independent rerun.

At S2, parent fully read both files. Native risk assessment was unavailable (empty native output), requiring independent verification; no native approval or receipt existed at that stage.

Independent verifier `mu7g7nnw-o-t9xz` reran the exact focused command once: 265 tests / 334 assertions passed, no errors/failures/skips. Both lints passed and 20/20 selected protected hashes matched observation 5120. Source SHA-256 was `867c466e177b1d273a92fce3ffbcf7abaf9d66006b3120c5dc4db2a8f55fe54b`; test SHA-256 was `dffff134385ae18d3dc69dd6df218a3f583b24fb4a9f67ef097dadb8a35051e6`.

At the first independent review, S2 remained incomplete: the verifier found that owned paused/unavailable snapshots accepted `committedAt=null`. Continuations must preserve a previously released Run's timestamp; only preparing may lack it. Add regression cases for owned paused, owned unavailable with known identity, and owned unavailable with unknown identity; observe RED before correcting the invariant. Keep valid preparing snapshots accepted. These cases were source-derived, not executed by the verifier. Resolve this within the same two files before S3; do not change design or silently defer it to decoding.

Correction writer `mu7gdsb2-p-n1k2` added the three timestamp regressions first and observed exactly three expected failures (268 tests / 337 assertions). A one-line phase-based invariant correction then passed all 268 tests / 337 assertions, with no errors/failures/skips; both syntax checks passed. Existing preparing and timestamp-preserving continuation cases passed unchanged. Parent read the corrected invariant and new regression method/provider. Independent verifier `mu7gikk4-q-fmyj` then confirmed the correction and reran 268 tests / 337 assertions plus both lints successfully; 20/20 protected hashes matched. Parent's independent hash readback matched source `4d56890103edc308179a4256f5c75ed8bfd982429841fb4ac8a4decfc24c2748` and tests `d1d0de8ff4a0ea87f594fc14579bd1e792a58d07b1035f88c8bda51e2b167a0b`. S2 is complete; this is not native approval or full-codec readiness.

S3 writer `mu7iv46p-r-w2y6` implemented `decode()` with strict object/list checks, pre-parse byte limits, shared explicit-limit validation and exact canonical re-encoding equality. Observed RED for missing API: 547 tests / 594 assertions, 22 errors and 257 failures. Three subsequent fixture failures required preserving float notation in test-only JSON serialization. GREEN: 547 tests / 644 assertions, then two runs of 553 tests / 651 assertions after boundary cases/shared-limit refactoring. Five focused invocations total; both final lints passed. Final size: 355 source + 694 test = 1,049 lines. Parent read the decoder/helpers, shared limits and decoder tests. Writer model/effort unknown; native assessment unavailable again, so independent S4 is required.

Initial native inspection found no existing lineages and required intended-untracked selection. Parent selected only the two new codec/test paths; the native workspace projection also included five preexisting tracked modifications. After consent, native review `review-7e19b391505dc449` covered seven paths / 1,403 changed lines, medium tier, with one `review-reliability` run. It approved the candidate and exact acknowledgement completed (`native-approved-acknowledgement-completed`), target `sha256:1471e0b37e625bb6659a25696ebaffd2fe296b2c06248af33ddc22fe3676a201`, consumed revision `sha256:0c396c9b1320be2860f4dc3a3d387de9fb5212b157f359bc32236c75a3d55375`. No correction opened. Informational WARNING `R3-inconsistent-retained-counts` at source lines 294–295 is non-blocking, separate later work; it does not reopen this candidate. No delivery or unrelated-edit authority follows from this review.

Independent verifier `mu7j4pyw-s-fj5w` found no reliable bounded-codec defects and reran the focused suite once: 553 tests / 651 assertions, no errors/failures/skips. Both targeted lints and `composer syntax` passed; parent had inspected Composer configuration and the entire lint-only script first. Integration fixtures were linted, not executed. All 20 protected hashes matched observation 5120. Parent's final status/hash readback matched the reported candidate: source `06c2cd790fb9c630e9e9b23be24ccefd945527a1aa189761e0eabbb20f648aad`, tests `79ef9fba2260768bc40d7405731289856a34f3fd54aa781968f8b7fbc9d4efac`. Selected preservation evidence is not a whole-repository snapshot. Runtime was PHP 8.4.4 / PHPUnit 10.5.64; no PHP 8.1/32-bit runtime, full-suite or integration verification is claimed.

The historical 17-test/241-assertion concurrency run is unrelated evidence and will not be rerun. The prior experiment's candidate-only native-review omission does not apply to this component.

## Acceptance and rollback

Acceptance: all allowed snapshot shapes round-trip deterministically; invalid canonical bytes/types/invariants and explicit-limit overflow are rejected; immutable values do not retain caller aliases; no I/O or storage authority is introduced; required checks pass with observed evidence.

Rollback boundary is only the two new codec/test files, after checking no unrelated edits were added to them. Preserve this progress/evidence record and every preexisting file; do not use Git reset, stash, checkout or destructive cleanup. No rollback command is authorized automatically.

Outcome: the bounded pure state value and canonical codec unit is complete and verified, with no commit or publication. Next work needs a separately bounded authorization; do not connect storage implicitly. R1 stays open: this component alone does not prove CAS, reconnect behavior, no-overlap coordination, topology or production readiness. Retain the native informational finding for separate later consideration.
