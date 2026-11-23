# Disposable backend harness authoring

## Objective and authority

Author a default-off real-backend harness for the completed, unwired CoreIntegrityRunStore candidate. ODD, not SDD or production/R1 approval. User approved the two new harness paths, then isolated safety-control tests without WordPress loading or database connections. Completed adapter taskdoc and full Engram 5162 were reconciled; its prior review is closed and must not be restarted.

User selected **provisioner-owned launcher** after writer clarification: a separately authorized launcher loads original WordPress dependencies; these two files only verify stock wpdb is already loaded. They must not autoload wpdb, define substitute WordPress functions, include external PHP or load the site bootstrap. Launcher authoring/execution is outside this scope.

No provisioning, installs, network, services, WordPress loading/bootstrap, DB connections/operations or integration execution now. Preserve dirty master, all preexisting tracked/untracked work and OpenSpec. No Git mutations, staging, commits, push or plugin wiring; commit evidence is deferred under the existing restriction.

## Edit and rollback boundary

Writer may create only:
- `tests/Integration/CoreIntegrityRunStoreBackendTest.php`
- `tests/Integration/CoreIntegrityRunStoreBackendBootstrap.php`

Parent alone owns this document and full Engram mirror 5175, topic `odd/core-integrity-backend-harness/tasks`. Protect source, Composer/PHPUnit config, CI, existing integration prototypes and prior tasks. Both writer targets were absent before authoring. Rollback only covers those two paths after checking for unrelated edits; no automatic deletion/reset/stash/checkout.

## First-slice contract

- Pure guards are test-first and executable offline. File loading, discovery, data providers and safety setup/methods must never connect or load WordPress, regardless of ambient flags.
- Later integration requires explicit opt-in, a separately provisioned fixture outside the current site/worktree, dedicated credentials/resource identity and matching ownership metadata. Never inspect site wp-config.php, discover credentials or reuse the historical Laragon bootstrap.
- Reject mismatches before mutation. Check loaded wpdb without triggering autoload; require the original class rather than a subclass. Class identity alone does not prove vendor bytes, runtime isolation or database grants: provenance and least privilege are provisioner preconditions, not claims these guards establish.
- No hidden provisioner or automatic destructive cleanup; fixture/resource lifecycle stays externally owned. Do not create a launcher or add helper files outside the two approved paths.
- Author initial backend cases for real prepare/query identifier and literal-percent behavior, canonical bytes/key/autoload, creation/readback, exact CAS and stale expected target. Negative malformed-row cases pass when correctly rejected.
- One adapter submission is not proof against internal wpdb reissue. Storage results/readback do not confer coordinator dispatch/no-overlap authority.
- Real two-process contention, native reconnect/reissue and wider backend matrix remain explicitly DEFERRED in this first slice, not simulated proof or an excuse for unrelated expansion.

## Checks and limits

TDD ON: `openspec/config.yaml` has `strict_tdd: true`, refreshed for H1. Composer `test` invokes PHPUnit 10.5; `phpunit.xml.dist` discovers only `tests/Unit`. Observe behavioral RED for pure guard tests, then GREEN/refactor. Missing API is valid RED; tooling/environment failure is not. Backend scenarios are authored only: runtime RED/GREEN is DEFERRED, not passed or N/A.

Exact authorized checks:
```
composer test -- --do-not-cache-result --filter testSafety tests/Integration/CoreIntegrityRunStoreBackendTest.php
php -l tests/Integration/CoreIntegrityRunStoreBackendTest.php
php -l tests/Integration/CoreIntegrityRunStoreBackendBootstrap.php
```

Prove file-level execution, providers/setup and every `testSafety*` method are WordPress/DB-free before running the filter. Essential temporary DATA fixtures must be unique, outside repository/site, contain no executable PHP/downloads and be removed only within their owned boundary. Never run the unfiltered integration file, full suite, composer check/audit/install or historical probes.

Runtime harness: DEFERRED because actual WordPress/wpdb/database execution needs a separately identified disposable runtime profile and explicit approval. Offline tests/lint cannot prove runtime compatibility, isolation or real-backend semantics. R1 stays OPEN.

## Tasks and routes

- [x] H1 — Authored the two-file default-off harness; offline RED/GREEN and two lints passed. Runtime remains deferred.
- [x] H2 — Independent offline safety tests/lints and isolation readback passed; no concrete defects found. Runtime remains deferred.
- [x] H3 — User-authorized seven-file native review approved and acknowledged without corrections; authoring-only scope complete.

H1: one sequential gentle-ai-worker (multi-file/preparation trigger). H2: gentle-ai-verify for commands; native assessment also follows writer return. H3: parent native facade, never reusing prior closed review. No overlapping writers.

Forecast: approximately 350-550 authored lines. The ~400-line heuristic is advisory, never a reason to omit checks/minify. Delivery `ask-on-risk`; chaining deferred because Git delivery is unauthorized. Stop before material scope expansion. Native scope including protected existing work needs a fresh user decision.

## Progress and next step

Baseline: master has five preexisting tracked modifications plus recorded untracked source/prototype/ODD/OpenSpec paths. The two targets and taskdoc were absent before this authoring phase. Scout mud7nvst-1-i7xe mapped reusable CI fixture shape and unsafe historical assumptions.

Writer mud8f5st-2-tws0 read prerequisites and returned `interaction_required` before any file write or test. Protected hash capture and RED/GREEN were still pending. User answered option 1: provisioner-owned dependency loading. This unblocks H1; it does not authorize writing/running a launcher or any integration operation.

Writer continuation mud8w62o-3-th62 completed H1: 428 new lines (test 254, bootstrap 174). Observed RED: 7 tests/25 assertions, seven missing-guard-class errors. GREEN: 7/76, then ancestor-overlap coverage/refactor 7/78. Exact safety filter and both lints passed on PHP 8.4.4 / PHPUnit 10.5.64. Writer reports all 18 protected hashes unchanged and Git status changed only by the two new paths; scoped evidence Engram 5180. Parent read both complete files and confirmed safety/runtime structural separation.

Native ASSESS returned risk unassessable because undeclared untracked files prevented native assessment; rddLine on, outcome unknown, fail-closed independentVerifier required. No approval or review lineage was created by this assessment. Backend runtime and backend RED/GREEN remain deferred; none of the executed checks loaded WordPress or performed database operations. Native review scope was resolved separately under H3.

H2 verifier mud98irh-4-sa0e independently PASS: exact safety filter 7 tests/78 assertions and both lints on PHP 8.4.4 / PHPUnit 10.5.64. No concrete coding defects; static readback confirmed no setup/provider/autoload route into WordPress/DB, target checks before mutations and compatibility with current candidate APIs. Marker symlink/size guards were inspected, not individually tested; positive stock wpdb and all backend behavior remain unexecuted.

H2 before/after hashes matched for 21 paths: both new files, this taskdoc, the five preexisting tracked modifications, composer.json/lock, phpunit.xml.dist, the three candidate/state source files, both unit tests, four historical integration prototypes and completed adapter taskdoc. Full Git status was identical: dirty master ahead 10, five tracked modifications and 20 untracked paths. This proves H2 preservation only: original H1 18-path/hash values were unavailable. Test SHA-256 `88e500b73c355e31c1009801c8c63efcdf6d59208455e22fc1dd5e39aa6ac920`; bootstrap `a14bdfb507a424298b3d6c28cd107801f8703bf26568d13b12593163bc96dfc8`. Verifier memory saves failed on ambiguous active sessions; parent retains the returned evidence here.

H3 initial INSPECT required intended-untracked selection. User explicitly selected Autorizar revisión ampliada (`review_expanded_scope`): the two harness files plus five preexisting tracked changes (README.md, openspec/changes/core-integrity-checker/exploration.md, openspec/config.yaml, src/CoreIntegrity/CoreExpectedFileRunner.php and tests/Unit/CoreExpectedFileRunnerTest.php). This authorized review only, not corrections to the five protected paths. No other untracked paths were selected.

Fresh selected INSPECT and START/interactive consent created `review-6d74cc9fe8971cfe`, medium, one review-reliability lens, seven files/784 authored changed lines and logical correction budget 200. Target `sha256:e76b359e27f213ecf5deca29b03fc4e8c0521e01a417463ec65d88835fed508e`; candidate tree `3d2857d573bd60e2ff0cd909314f653e03f5098b`. One forecast/acknowledged capture closed APPROVED, with no correction. Exact native acknowledgement completed and consumed revision `sha256:02bc17105709eb11f32e25c6bfdcc080428c093148a37f6c87095fbd74e2735e`, authority burned. This is expanded-scope review, not harness-only approval or backend proof. Do not restart this closed review for the unchanged candidate.

Parent post-review `php -l tests/Integration/CoreIntegrityRunStoreBackendBootstrap.php` passed. Both candidate hashes still matched H2; full Git status retained the same five tracked modifications/20 untracked paths on preexisting master ahead 10. No source changes followed writer completion. Only parent tracking/memory and native authority metadata changed during verification/closure.

Bounded authoring COMPLETE: H1-H3 satisfied with offline checks and expanded review. Next separately authorized unit may design/author the provisioner-owned launcher and choose a disposable runtime profile. Neither that implementation nor provisioning/integration execution is authorized by this completion. Keep all real-runtime evidence and R1 OPEN; no commits, production readiness or no-overlap claims.
