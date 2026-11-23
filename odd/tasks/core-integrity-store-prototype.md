# Isolated core integrity store prototype

## Objective and authority

Validate a test-only candidate for authoritative `wpdb` claims and commits with the default WordPress object cache. This experiment addresses part of SDD design R1; it is not plugin implementation, an SDD apply/tasks phase, or completed-design approval.

The user authorized trial code only under `tests/Integration`, necessary read-only local WordPress source access, and creation/deletion of a new exclusive disposable database. Docker is explicitly forbidden. The parent owns this ODD progress document and its Engram mirror.

## Confirmed context

- PHP CLI 8.4.4 with mysqli; localhost MariaDB 10.11.9, InnoDB, autocommit enabled.
- Local WordPress source reports 7.1 / es_ES. No site bootstrap is allowed.
- Seven earlier isolated SQL primitive checks passed; independent metadata read confirmed cleanup. They did not validate a production adapter, WordPress cache or automatic reconnect.
- CodeGraph maps internal plugin persistence callbacks, not an ownership primitive. Local core is outside this workspace's graph scope and needs bounded direct reads.
- Core `plugin.php` loads the hook implementation and the small filter-sentinel marker. Prefer real hooks over reimplementing placeholder-escape filters.
- Full prototype estimate was 500–650 authored lines before using real hooks. Keep coherent behavior and tests together; do not compress code or omit tests for a line target. No commit or delivery is authorized.

## Allowed source edit surfaces

- `tests/Integration/CoreIntegrityRunStorePrototype.php`
- `tests/Integration/CoreIntegrityRunStoreTest.php`

No edits to `src/`, existing tests, README, composer/PHPUnit/CI configuration, OpenSpec, WordPress core or site configuration. Preserve all preexisting changes. No source autoload or production wiring.

## Isolation and safety

- Default invocation must skip safely unless the explicit experiment gate is enabled.
- Tests receive credentials through a private process-only channel. Never read or execute wp-config.php from committed test code, print credentials, persist credentials, or pass passwords in command arguments.
- An authorized launcher may parse static connection literals from the confirmed local config without evaluating it. Dynamic/duplicate definitions fail closed.
- Never select the site database or load wp-load.php/wp-settings.php. Instantiate real wpdb only after creating a new disposable schema and pass that exact schema explicitly.
- Use a random `cerrojo_integrity_probe_<16 lowercase hex>` schema name, no `CREATE IF NOT EXISTS`, and an ownership marker. Drop only the acknowledged schema with a matching marker; report uncertain cleanup instead of deleting unknown resources.
- Real core hooks and default cache are desired. Any unavoidable test-only environment shim must be explicit, minimal and fail closed; do not call this a complete WordPress installation.
- No Docker, downloads, global installs, new services, arbitrary drop-ins or real-site plugin activation.
- No timed ownership takeover or force unlock. No claim of general hosting compatibility, persistent-cache coherence, real network-fault recovery or full R1 closure from this limited experiment.

## TDD and verification

Strict TDD is enabled by `openspec/config.yaml` (`strict_tdd: true`). Configured runner: `composer test` (PHPUnit 10.5).

Focused command: `composer test -- --do-not-cache-result tests/Integration/CoreIntegrityRunStoreTest.php`. Disable the result cache to avoid repository output outside the authorized test files.

The verifier, not the writer, runs the parent-authorized private launcher with `CERROJO_STORE_PROBE=1`, the approved local core root, and process-only credentials. The writer's role absolutely forbids secret reads and deletion operations; its permissions are not changed. The verifier may execute the exact approved command and owned-schema cleanup but may not edit source. Any PHPUnit result-cache output must be explicitly identified or disabled in that command.

The parent coordinates test-first stages: writer authors tests and minimal contract scaffold; verifier observes behavioral RED; writer implements only after receiving that evidence; verifier observes GREEN, triangulation and refactor checks. Do not count missing dependencies, parse errors, leaked site bootstrap or skips as behavioral RED. Default invocation without the experiment gate must skip and must not connect; a skipped run is not integration evidence.

Additional authorized checks: verifier-owned `composer test` for the existing unit suite, and writer-owned `php -l` for each new file. Do not run `composer check`/audit/install or new commands without parent authorization. Every database-bearing invocation needs owned-resource cleanup evidence.

## Tasks

- [x] P1 — Build the gated isolated bootstrap and candidate store with tests for creation, direct reads, conditional claims/commits, byte-exact comparison and stale default cache.
- [x] P2 — Add bounded write-return-loss/replay/conflict tests and fail-closed handling, distinguishing simulation from real network failures.
- [x] P3 — Run final checks, independently confirm database cleanup, inspect the actual diff and follow the enabled native review boundary before reporting the experimental candidate complete.

## Acceptance criteria

- Real wpdb and real default cache execute only against a fresh owned schema; nothing boots the site.
- An existing cached value never authorizes or confirms ownership; exact authoritative state controls transitions.
- Another owner, epoch or revision cannot claim, overwrite or release current execution.
- A replay cannot commit twice. Ambiguous outcomes are resolved by exact authoritative readback or fail closed; unknown owner liveness is never cleared by age.
- Credential handling and cleanup are independently reviewable. Default-off, RED and GREEN observations are recorded separately.
- No shipping-adapter or broader compatibility claim is made; remaining R1 gaps are explicit.

## Progress and evidence

- Mapping complete: real core hooks, wpdb and default cache; minimal single-site/fail-closed translation shims. Writer cannot read credentials or execute database cleanup; its role remains unchanged.
- The first enabled fixture failed in PHPUnit infrastructure because lifecycle STDERR bypassed result decoding. Mapper confirmed the installed source path. Parent removed three diagnostic writes and retained uncertain-cleanup failure with its owned schema. No SQL/ownership guard was weakened.
- Initial behavioral RED, verifier `mu4na05a-m-12ge`: enabled exit 1, 5 tests / 1 assertion / 1 intended failure / 0 errors / 4 skips. Message: `Valid initial state must be created.` Independent metadata before/after `[]`. The four dependent tests had no separately observed RED.
- Writer `mu4ndlsu-n-yue1` implemented only the 201-line prototype. Both PHP syntax checks passed. Parent read the full implementation: schema-qualified SQL, canonical state, BINARY comparison, instance-owned token and overflow guards. No write-loss reconciliation yet.
- P1 GREEN, independent verifier `mu4nhg3t-o-pi3i`: default-off exit 0 with 5 skips; enabled exit 0 with 5 tests / 78 assertions / 0 skips / 0 errors / 0 failures. Fresh unselected-connection metadata before/after both `[]`; no cleanup uncertainty. No success lifecycle output is emitted by the corrected fixture.
- Initial native risk assessments returned `unassessable` (empty native output), so their high-risk independent-verifier plan was followed. Native ordinary review subsequently completed as recorded below; assessment availability and review approval are distinct observations.
- P2 initial RED, verifier `mu4nt1ha-q-agfv`: 14 tests / 81 assertions / 1 intended lost-claim failure / 0 errors / 8 skips; independent metadata before/after `[]`.
- A bounded local-core read exposed stale `wpdb::last_result` after queries rejected before `flush()`. Regression RED, verifier `mu4nzrq8-s-6z4u`: 15 tests / 81 assertions / 1 intended stale-read failure / 0 errors / 9 skips; metadata before/after `[]`. Actual stale idle JSON was returned instead of null.
- Writer `mu4o31uk-t-fbcc` changed only the prototype: successful fresh SELECT required before inspecting results; attempted conditional writes may reconcile exact fresh replacement bytes without another write; INSERT remains affected-row-only; commit authority stays consumed. Both syntax checks passed. Final prototype/test size is 225 + 595 = 820 lines; safety/tests were not compressed for the estimate.
- P2 GREEN, verifier `mu4o5nl8-u-21ay`: default-off exit 0 with 15 skips; enabled exit 0 with 15 tests / 192 assertions / 0 errors / 0 failures / 0 skips. Independent metadata before/after both `[]`; no cleanup uncertainty. All nine fault methods ran. Both stale-read branches executing is inferred from passing source structure, not instrumented coverage.
- P3 verifier `mu4oblyg-v-cp0w`: unit suite exit 0, 766 tests / 4,273 assertions / 9 capability skips (7 symlink permission, 2 ineffective chmod restrictions); no errors/failures. Final enabled spot-check: 15 tests / 192 assertions / no skips/errors/failures, independent metadata before/after `[]`. Both lints passed.
- All three supplied preservation hashes matched before testing; all five checked source/test hashes and Git status were unchanged afterward. Both prototype files remain untracked. `git diff --check` passed for tracked changes only, with LF/CRLF warnings; it did not cover untracked files.
- Native review `review-9b2c2a6fcf5b90a2` approved the frozen target `sha256:e207e6bab817f54faea3f9dea104a91c67f45ca7bbcda7948d9521a46218bb09`; exact acknowledgement completed and authority was consumed. Its seven-path scope included the two new prototype files and five preexisting tracked changes, totaling 1,174 frozen changed lines. The single reliability reviewer required no source correction. One caller-copied binding was rejected without mutation; fresh STATUS and its exact binding completed the single reviewer run. This progress document and untracked SDD drafts were excluded.
- P1/P2/P3 are complete for this experiment only. No commit, publication, production wiring, SDD tasks/apply or design approval occurred. R1 remains open: real worker concurrency, persistent-cache/read routing, automatic reconnect, network-failure and production-adapter compatibility are not established.

## Rollback boundary

Only the two new test-only files may be removed to withdraw this prototype, after proving no test process remains active. Preserve this progress record and all unrelated/preexisting changes. Disposable database cleanup is restricted to the acknowledged current schema and its matching ownership marker; unknown resources are never reset or dropped.

## Next step

Report the experimental evidence and limitations. Incorporating it into the SDD design is separate work; do not treat this prototype or its review as full R1 closure or authorization for SDD tasks/apply. Preserve the two test-only files and all preexisting changes; no delivery action is authorized.
