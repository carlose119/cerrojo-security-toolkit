# Candidate core-integrity persistence adapter

## Objective and authority

Implement an unwired storage candidate with isolated tests, following [the design](../../openspec/changes/core-integrity-checker/design.md). The user explicitly approved the three paths below and a bounded exception to the design's production implementation gate. This is ODD, not SDD, full-plan approval or R1 closure.

The completed codec validates bytes; this candidate reads and conditionally persists them without manufacturing transition/dispatch authority. R1 stays OPEN. No real DB, WordPress bootstrap, integration execution, plugin wiring, UI, network, installs, Git mutations, commits or publication. Preserve all existing dirty work and OpenSpec artifacts.

## Exact surfaces

Only writer surfaces (new at mapping):
- `src/CoreIntegrity/CoreIntegrityRunStore.php`
- `src/CoreIntegrity/CoreIntegrityRunStoreResult.php`
- `tests/Unit/CoreIntegrityRunStoreTest.php`

Parent alone owns this document and full Engram mirror `5162`, topic `odd/core-integrity-persistence-adapter/tasks`. Protect every other file, especially codec/tests, runner/tests, Composer/PHPUnit/config/bootstrap, design and historical integration prototypes. No automatic rollback: only these three new paths form the rollback boundary, after checking for unrelated edits. Preserve progress evidence; never reset, stash, checkout or delete automatically.

## Bounded API and contract

- Constructor: `__construct(object $wpdb, string $optionsTable, int $maxEncodedBytes, int $maxFindings)`. Validate without I/O; limits are explicit, no defaults. Trusted server-side table identifier is validated/quoted by component, with prepare-safe literal percent handling; no browser input, fixed prefix or `%i` assumption.
- Operations: `readAuthoritative()`, `createInitial(CoreIntegrityRunState $initial)`, `replaceExact(CoreIntegrityRunState $expected, CoreIntegrityRunState $replacement)` return immutable `CoreIntegrityRunStoreResult`.
- Results carry operation, outcome, nullable validated state, writeAttempted, applicationUnresolved, safe mutation/read cause and separate readbackCause. No raw diagnostics. Observed state and applied/created outcomes never grant transition or dispatch authority.
- Reserved key: `bastion_security_wp_core_integrity_control`. Direct prepared SQL only; no option/cache APIs, transactions over work, delete/reset/upsert/INSERT IGNORE or automatic write retries.
- SELECT keeps key-collation matching to expose collisions. Strict fresh integer 0/1 acknowledgement precedes metadata; rows must match cardinality. Require exactly three string columns, byte-identical key, autoload `no`, canonical bounded codec bytes. Collisions/malformed rows fail closed; false/exception/unexpected return is not absence. Test stale metadata remains unread after failed acknowledgement.
- INSERT accepts only exact never-claimed initial shape and encodes within limits before SQL. Submit once; exact intended readback required. No differently fenced initial-row adoption, including after unknown failure; positive collision adoption is deferred from this conservative low-level slice.
- CAS encodes expected/successor once, enforces limits and rejects identical bytes before SQL. Bind the full original state with normal key predicate plus binary comparisons/byte lengths for key, autoload and old payload. Never refresh/rebuild/retarget. Snapshot validity is not transition legality: revision reservation/increment, sticky eligibility, claim/commit and original-action permissions belong to a later coordinator.
- Mutations returning 1 still need exact successor readback. For 0/false/exception or possible reconnect/reissue, only exact intended bytes may reconcile; absent/old/different/newer/invalid/unavailable readback stays ambiguous/unresolved, no second write. No known-conflict claim without proven non-reissue semantics.
- Unexpected mutation types or >1 are contract failure and cannot become success even with matching readback. Preserve attempted-write uncertainty, mutation cause and readback cause separately. Valid differing state is observational, never an adopted target.
- Backend eligibility, honest routing/hooks, actual freshness, InnoDB/unique key, collation/charset/byte round trips, wpdb formatting and real reconnect/reissue remain unproven preconditions. Unit doubles cannot certify them.

## Checks and execution limits

TDD ON: parent reread `openspec/config.yaml`, `strict_tdd: true`; PHPUnit 10.5 via Composer/`phpunit.xml.dist`. Each slice needs observed behavioral RED before implementation, GREEN and justified refactoring. Missing API is valid RED; runner/environment failure is not. Stop and diagnose incidents rather than invent workarounds.

Authorized focused commands:
```
composer test -- --do-not-cache-result --filter CoreIntegrityRunStoreTest tests/Unit/CoreIntegrityRunStoreTest.php
php -l src/CoreIntegrity/CoreIntegrityRunStore.php
php -l src/CoreIntegrity/CoreIntegrityRunStoreResult.php
php -l tests/Unit/CoreIntegrityRunStoreTest.php
```

Final verifier is also authorized to run `composer syntax`: parent reread `composer.json` and all of `tools/check-syntax.php`, confirming it only invokes `php -l`. Integration files may be linted, never executed. No full suite, composer check/audit, install or DB command. Fakes must not instantiate real wpdb/bootstrap/connections/services. Optional CodeGraph timed out; parent authorized direct named-file reads, not index retry/rebuild or runtime workarounds.

Runtime harness: DEFERRED, not N/A, because a real DB boundary exists but the user forbids its execution. Isolated tests prove SQL/result interactions only. Real storage/CAS/reconnect/no-overlap and production evidence need separate authorization.

## Tasks and routes

- [x] P1 — Map contracts/surfaces/TDD and obtain explicit candidate-only gate exception.
- [x] P2 — Immutable results and strict reads; independent 83 tests / 436 assertions and three lints passed.
- [x] P3 — Initial creation/exact readback; independent 1,086 tests / 9,638 assertions and three lints passed.
- [x] P4 — Exact CAS/shared reconciliation; independent verification passed 2,102 tests / 19,946 assertions, three lints and composer syntax. User-approved expanded native review closed approved and acknowledged; candidate-only scope complete.

P1 used delegated mapping (4+ inputs). P2/P3/P4 each used one sequential bounded writer (multi-file changes plus preparation); parent performs structural readback and native assessment determines independent verification. No overlapping writers or SDD agents. Initial forecast ~960 source/test additions; final writer candidate 967 lines. The ~400-line heuristic is advisory: retain coherent behavior and safety tests, no minification/artificial files. Delivery `ask-on-risk`, chain deferred; explicit no-Git/no-commit restriction controls delivery.

## Evidence

All executed test slices used PHP 8.4.4 / PHPUnit 10.5.64. Writer model reported gpt-6-astra, effort unavailable. Native assessments after each writer were unassessable (empty output), requiring independent verification, not implying low risk or approval.

| Task | Observed evidence |
|---|---|
| P1 mapper `mubfhlly-1-d8qi` | No path collisions or product contradiction apart from production gate; user explicitly authorized candidate exception. |
| P2 writer `mublejf6-2-a69o` | RED 82 tests, 81 errors/1 failure missing adapter; GREEN 82/434 then 83/436; three lints. 451 lines total. Parent read three files. |
| P2 verifier `mublq6s1-3-5vwl` | Independent 83/436 and three lints PASS, no concrete defect; candidate/15 protected hashes matched before/after. |
| P3 writer `mublwxch-4-eqs6` | RED 1,083/436 with 1,000 missing-method errors; GREEN 1,083/9,550 then 1,086/9,638; three lints. Delta +258/-7. Parent read creation/result/tests. |
| P3 verifier `mubmbvjn-6-5v59` | Independent 1,086/9,638 and three lints PASS, no concrete defect; candidate/15 protected hashes and taskdoc unchanged. Prior task `mubm8a34-5-zx0n` stopped before tests on optional index timeout; parent checked six hashes/status then authorized direct reads, no retry/rebuild. |
| P4 writer `mubmo9ot-7-sugv` | RED 2,102/9,639 with 1,016 missing-method errors; GREEN 2,102/19,936 then 2,102/19,946 with owner variants; three lints. Delta +267/-2, final 967 lines. Result file unchanged. Parent read CAS/shared helper/new tests. |
| P4 verifier `mubtk312-1-p5to` | Independent PASS 2,102/19,946, three lints and composer syntax on PHP 8.4.4 / PHPUnit 10.5.64; no concrete candidate defect. Candidate hashes matched P4; taskdoc, 20 protected paths from observation 5120, both codec paths and syntax tool remained unchanged; historical baselines matched. Before/after git status identical. Integration files linted only; runtime DEFERRED. |

P3 candidate hashes (independently matched): store `6318fc9f25349200124f67d6660cf3cf3c157f2286b67bc085a942b86a731c60`; result `e25f80e0bae46eb3fc1e3658aba141ad5a40f4b7828a9a63f0709d5e536f1b5b`; test `74df7b1b3c4c08a7e16a934c3f79937d31e8b5efaae78d883ce5889f60006156`.

Current P4 writer hashes: store `b2f622336a62dba75c3f17d544c29725d0521165ae0a9207e384928986293b32`; result `e25f80e0bae46eb3fc1e3658aba141ad5a40f4b7828a9a63f0709d5e536f1b5b`; test `fba3a2aae4cce651245be947fe1759ac0d4cae118fa8e148203a9a8f05599a6e`.

Protected baseline: observation `5120` for design, composer.json/lock, phpunit.xml.dist, plugin entrypoint, src/Bootstrap.php, openspec/config.yaml, existing CoreExpectedFileRunner/test and the four CoreIntegrityRunStore integration files. Add completed codec source hash `06c2cd790fb9c630e9e9b23be24ccefd945527a1aa189761e0eabbb20f648aad` and codec test `79ef9fba2260768bc40d7405731289856a34f3fd54aa781968f8b7fbc9d4efac`: 15 selected protected paths, not a whole-repo snapshot. Parent observed the five preexisting tracked modifications unchanged. Completed codec task/mirror5121 stays untouched.

## Acceptance and next step

Bounded unwired candidate COMPLETE: required focused checks, independent verification and native review disposition are recorded. No stale metadata authority, retries, implicit dispatch, consumer wiring or real DB execution. No full-suite/PHP8.1/32-bit/actual-wpdb proof.

Resume reconciled local document and full mirror 5162; parent matched the three P4 hashes and refreshed strict_tdd from openspec/config.yaml. No prior settled P4 verifier evidence was recoverable, so a fresh independent verifier ran. No source changes were needed.

Initial INSPECT required intended-untracked selection and showed the five preexisting tracked changes. User explicitly selected Revisar alcance ampliado: native review includes README.md, openspec/changes/core-integrity-checker/exploration.md, openspec/config.yaml, src/CoreIntegrity/CoreExpectedFileRunner.php and tests/Unit/CoreExpectedFileRunnerTest.php plus the three adapter candidate paths. This authorized review, not corrections to protected files or Git delivery.

INSPECT selected exactly the three adapter untracked paths. Native START/interactive consent created lineage `review-853564ec41e4a9f3`, medium tier, one review-reliability lens, eight files and 1,323 authored changed lines, logical correction budget 200. Target `sha256:1c9d5a29fca9f2bbde740b784c079435ed9c686701c4377296278a328d68e810`; candidate tree `31cc18b3c8524bf0d9657f9b9307bf1bdc417ff7`. One forecast/acknowledged capture closed APPROVED; exact acknowledgement completed and consumed revision `sha256:6ffd8a00d936631b0bd8d6bae0ad4db30cc167186cbab63ca7932626a7393303` (`authority: burned`). No corrections occurred. This is expanded-scope approval, not adapter-only review or production evidence. No further capture or review restart is needed for this unchanged candidate.

Parent spot check `php -l src/CoreIntegrity/CoreIntegrityRunStore.php` passed after review; all three P4 hashes still matched and git status retained the same five tracked modifications and untracked paths. Only this progress document/mirror changed during closure; native review wrote its own authority metadata. No source edits, commits, staging, push, DB or integration execution.

Next: choose a separately authorized bounded follow-up, such as planning real-backend validation in a disposable test environment or mapping coordinator contracts. Neither is authorized by this completion. Keep R1 and real-backend validation OPEN; do not wire this candidate into the plugin or claim no-overlap guarantees.
