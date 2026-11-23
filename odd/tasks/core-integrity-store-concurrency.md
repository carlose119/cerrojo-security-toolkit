# Isolated two-process core integrity store experiment

## Objective and authority

Extend the completed [storage prototype](core-integrity-store-prototype.md) with a real two-process claim/commit characterization. The user explicitly approved test-only changes, progress tracking, and a new exclusive disposable local MariaDB database with ownership-checked cleanup. Work follows ODD; no SDD phase or production implementation is authorized.

The existing prototype proves sequential competition and injected ambiguous results, not independent workers. This experiment addresses that specific gap; it does not close R1 or prove network recovery, production eligibility, routing, scheduler fairness or all hosting configurations.

## Scope and constraints

Source edit surfaces:
- `tests/Integration/CoreIntegrityRunStoreTest.php`
- `tests/Integration/CoreIntegrityRunStoreProbeBootstrap.php` (new)
- `tests/Integration/CoreIntegrityRunStoreConcurrentWorker.php` (new)

Runtime-only exception explicitly approved after the launcher incident: `C:/Users/carlo/AppData/Local/Temp/cerrojo-concurrency-launcher-5063.php` may contain generic launcher code, never credential values. The parent must refuse overwrite, read back/lint it, authorize one controlled invocation, then remove only that owned file after known termination. No automatic repeat after failure.

The parent owns this progress document and its full Engram mirror. Preserve `CoreIntegrityRunStorePrototype.php`, all production source, the five preexisting tracked changes, OpenSpec documents, README and Composer/PHPUnit configuration. No Docker, installs, site bootstrap, site database access, production wiring, commits or publication.

Writer authors fixture code and runs only authorized PHP syntax checks. Its role does not permit credentials or destructive runtime commands. An independent verifier owns the exact approved private launcher, disposable-resource lifecycle and cleanup observations. Connection literals may be extracted privately from the previously approved local config without evaluating it; never print or persist credentials or put them in command arguments.

## Chosen experimental topology

- Coordinator exclusively creates a random `cerrojo_integrity_probe_<16 lowercase hex>` schema without IF NOT EXISTS and retains its ownership marker. Children receive the acknowledged schema, not the marker; they never create/drop schemas or tables.
- Reuse real core hooks, real wpdb and default cache through one test-only bootstrap; do not load wp-load.php/wp-settings.php or configuration.
- Spawn two PHP processes with argument-array proc_open and independent wpdb connections. Supply a restricted process-only environment. Standard streams go to the OS null device: no Windows nonblocking-pipe assumption, sensitive output or PHPUnit STDERR interference.
- A separate coordination table inside the owned schema carries fixed worker events and gates only. No credentials, diagnostics or owner-token copies. Use autocommit and short statements; no transaction or lock spans the tested claim/work interval.
- Both workers report independent readiness before one common claim gate opens. Winner is not predetermined. Exactly one enters protected work and retains the claim while the loser confirms claim rejection and inability to commit a foreign claim. The coordinator verifies the held state before permitting winner release.
- Winner commits once; duplicate commit cannot advance revision. Final canonical state is idle at revision 2 with expected progress. Record distinct process/connection identities without treating them as routing proof.
- Polling deadlines are cooperative, supplemented by configured driver connect/read and InnoDB lock timeouts. These are not a hard end-to-end wall-clock guarantee. Require mysqlnd for this local experimental path if using mysqlnd.net_read_timeout; fail clearly before schema creation when required capabilities cannot be established.
- Do not drop until both children have observably terminated and process handles are closed. A termination request or expired deadline is not termination proof. Ambiguous settlement preserves the schema and reports its safe identity as a blocker; do not retry enabled runs automatically.
- Verify ownership marker before DROP, then independently verify absence using a fresh unselected mysqli connection. Preserve existing setup/cleanup safeguards and all original 15 test behaviors.

## Evidence basis and limits

Read-only mapper tasks `mu617z6b-7-0qcf` and `mu61e4ty-8-uu3d` inspected the fixture and proposed the three-file scope. Parent read the fixture bootstrap/cleanup and official PHP manual bodies (not user notes):
- https://www.php.net/manual/en/function.proc-open.php — command arrays bypass shell; process environment and descriptors are explicit.
- https://www.php.net/manual/en/function.stream-set-blocking.php — not a basis for assuming portable nonblocking process pipes.
- https://www.php.net/manual/en/mysqlnd.config.php — mysqlnd.net_read_timeout applies to extensions using mysqlnd; configurable INI_ALL on the relevant PHP generation.
- https://www.php.net/manual/en/mysqli.options.php — connect/read result timeouts are set before real_connect; MYSQLI_OPT_READ_TIMEOUT is documented from PHP 7.2.
- https://www.php.net/manual/en/function.proc-get-status.php — running=false reports termination; exit-code caching is documented from PHP 8.3.

These facts guide the harness, not a claim that its runtime has already been verified. No experiment worker or DB operation had run at the end of C1; later runtime observations and uncertainty are recorded below.

## Testing and work-unit boundary

Strict TDD remains ON from `openspec/config.yaml`; configured runner is `composer test` (PHPUnit 10.5). This addition characterizes existing atomic behavior: write assertions first, but the first enabled run may pass. Do not fabricate RED or break the prototype to manufacture failure. Spawn/bootstrap/timeout/cleanup failures are harness failures, not behavioral RED. Any later behavior fix requires observed behavioral RED and separately bounded edit authority if the prototype must change.

Focused command: `composer test -- --do-not-cache-result tests/Integration/CoreIntegrityRunStoreTest.php`. Default-off skips must involve no connections or children. Enabled skip/capability failure is not concurrency evidence. Enabled invocation uses the verifier-only private launcher; its exact command will be finalized after source inspection, before execution. No full suite, Composer audit/install or other runtime command is authorized by this document.

One coherent uncommitted work unit: concurrent characterization, shared bootstrap and safe cleanup. Forecast: roughly 430–610 additions plus 10–30 deletions. Exceeding the advisory 400-line task heuristic is justified by cohesive safety/tests; do not compress or omit checks. Delivery strategy remains ask-on-risk, chaining deferred; user explicitly forbids commits/publication, so no delivery or chain operation occurs.

## Tasks

- [x] C1 — Map existing fixture and choose isolated two-process coordination without Windows pipe assumptions.
- [x] C2 — Author the three-file test-only harness and assertions; pass each authorized syntax check; preserve unrelated files.
- [x] C3a — Diagnose the incomplete enabled-launcher outcome and establish current process/schema state read-only before any further enabled invocation.
- [x] C3b — Add bounded, non-sensitive failure-stage and child-exit diagnostics; do not rerun the enabled experiment automatically.
- [x] C3c — Diagnose and correct empty-password environment transport; add regression coverage and validate with fictitious data without a DB before requesting another enabled run. Keep ownership behavior unchanged.
- [x] C3 — Independently run default-off and enabled characterization, verify both child exits and fresh-connection database cleanup. Post-correction authorized run passed 17 tests / 241 assertions; fresh before/after metadata empty.
- [x] C4 — Inspect source changes and independent verification, reconcile remaining limits and preserve final evidence. Closed with the user's explicit candidate-only native-review omission; independent checks passed. No native approval, R1 closure or delivery.

## Progress

C1 and C2 are complete for mapping and authoring/lint only. Writer `mu61lzdy-9-ccg4` changed exactly the three authorized source paths; sizes are 775 + 192 + 88 lines. All three PHP syntax checks passed after correcting an initial nested-class parse error; that error was not behavioral RED. At the end of C2, no enabled behavior had been observed.

Parent read all three files, repeated bootstrap lint successfully, and confirmed all nine protected hashes against observation 5064. The 15 existing test bodies are retained. Core query/prepare/cache code remains real, but a test-only wpdb subclass overrides connection creation/reconnect setup to install read/connect timeouts. This is an explicit harness seam, not evidence for unmodified WordPress reconnect behavior. Polling uses 20-second cooperative budgets and settlement 25 seconds; no hard wall-clock claim.

Stage 1 verifier `mu622h6p-a-kvs6` observed PHP 8.4.4 with all requested driver/process capabilities and PHPUnit 10.5.64 default-off: 16 skipped tests, 0 assertions. Git path status matched. No experiment connections/workers are inferred from the source gate, not instrumented. Normal PHPUnit isolation uses framework-managed temporary config/result files; inspected configuration serialization uses CLI/XML data, not a general environment dump. Credentials must remain function-local and process-only putenv, never XML, argv, test data or superglobal assignments. Temporary deletion was not independently instrumented.

One parent-approved inline enabled launcher, task `mu62g583-c-mjlz`, returned exit 255 with a Bash heredoc EOF warning at line 202 and no safe JSON. Enabled counts, schemas before/after, test outcome and cleanup are UNKNOWN. This is a launcher/transport failure, not behavioral RED. No retry occurred. Diagnosis `mu62kuzh-d-skct` found the exact PHP closure and final delimiter present in the retained submitted argument (no trailing newline); actual bytes consumed are unavailable, so truncation or non-execution cannot be asserted.

C3a completed: independent verifier `mu62my7v-e-0zmq` observed no matching PHP processes and an empty probe-schema list through a fresh unselected connection. No cleanup or termination was needed. This establishes current resource absence, not prior test success or non-execution; the underlying transport cause is unproven.

The user then approved the exact runtime-only temporary path above. Parent observed ABSENT before creation, materialized generic code only, fully read it back and passed `php -l`; SHA-256 was `f2dd522d5d9f483d507144a851327d19948770924aa0175503768c98aa4947fb`. One hash-guarded file-based invocation returned launcher exit 2 / PHPUnit exit 1: 16 tests, 194 assertions, 0 errors, 1 failure, 0 skipped/incomplete/risky tests. Fresh independent metadata was empty before and after. The failed assertion was suppressed and remains unidentified; no behavioral RED or concurrency success is established. No retry occurred.

After known launcher completion, parent rechecked its exact hash, removed only that user-authorized temporary file, and confirmed absence. All nine protected hashes plus all three candidate hashes remained unchanged through verification. A separately authorized no-DB child capability probe observed PHP 8.4.4, mysqli/mysqlnd present and matching loaded-INI-path hashes in parent and restricted-environment child; the child exited/closed with 0. This rules out that narrow capability mismatch, not all startup causes or the test failure.

C3b completed: writer `mu63ilb0-i-mop1` added fixed coordinator stages and bounded child status reporting in the test, plus worker failure codes 10–16 (success remains 0). Both authorized lints passed; parent read changes and repeated worker lint. Independent source-only verification passed: one nonwaiting status observation, no alternate success/cleanup path, no exception text, credentials, SQL or state bytes in diagnostics. This is not behavioral verification or a fix for the unidentified failure.

Current diagnostic candidate hashes: test `97f4b239c77e0b434384fe8d807f001251126d202d38c3bf8ad7e21983fe34f4`; worker `26d3aceb721889c039d1ee86c8c67d01739ca2e60ac5a4203b325fdb61116ca1`. Bootstrap and prototype retain their previous hashes. A future launcher may expose only the exact bounded `Concurrency probe failed; stage=<allowlisted>; workers=1:<status>,2:<status>.` message, never surrounding exceptions/output; status is pending, unknown or unsigned integer 0–4294967295. The first failing run remained unresolved when these diagnostics were prepared. No further enabled invocation was authorized automatically. C3 and C4 remain incomplete; native assessment remains unassessable/empty and independent verification is retained.

The user then explicitly approved one diagnostic invocation with recreation/removal of the same runtime-only helper. Parent checked absence, materialized code with strict failure-event extraction, read the changed portion, linted and pinned SHA-256 `a10b6179625a2f3c5cf4e8685ffff792057232a3076cff82def6923d51677ac5`. That single invocation returned launcher exit 2 / PHPUnit exit 1: 16 tests, 194 assertions, 1 failure, no errors/skips/incomplete/risky results; metadata before/after both empty. Safe diagnostics were `stage=wait_ready`, `worker1=10`, `worker2=10`: both workers failed in environment/bootstrap before their database/claim stages. This localizes a harness precondition failure, not a failure of claim exclusivity. Parent rechecked and removed only the owned helper and confirmed absence.

A separately authorized, fictitious-credential no-DB bootstrap probe returned 255 with no output; it provides no verified failure location and was not repeated. Source inspection confirms the selected boot() path itself does not construct/connect wpdb. C3c mapper `mu646x4t-m-22l2` completed read-only harness/local-core mapping without finding a missing declared core dependency. A subsequent credential-free child probe using the restricted environment/cwd observed nonempty dummy password → O (bootstrap completed), empty dummy password → E (environment rejected), both child exits/closes 0. No real credentials or DB were used. This reproduces a harness transport defect against its empty-password-allowed contract; it does not establish the actual configured password or concurrency behavior.

Bounded C3c correction: use a versioned, nonempty process-only password envelope for experiment children; strict decoding must preserve empty values while rejecting missing, malformed or NUL-containing input. Encoding is not encryption: treat the envelope as secret and never log it, serialize it into runner configuration or place it in argv/files. Ordinary fixture credential input remains unchanged. Add a focused regression in the existing test file and preserve the old 15 bodies, all coordination/ownership/cleanup checks and the protected prototype. Writer may touch only the existing three test surfaces and lint them; no real DB run or temporary launcher recreation. Validate the fix later with fictitious nonempty/empty/missing/malformed envelope cases, no DB.

C3c completed for transport correction and no-DB validation. Writer `mu66vbxk-o-gn5b` changed only Test and Bootstrap; Worker remained unchanged. The versioned canonical envelope is decoded centrally for worker environment reads, including the connection seam's repeated read. All three lints passed. One new regression method brings the focused suite to 17 methods, with dependency tail original final test → envelope regression → concurrency. At that point, its enabled PHPUnit execution remained pending; the subsequent C3 result is recorded below.

Independent verifier `mu670q27-p-lv72` observed default-off 17 skips / 0 assertions, 18 passing pure helper checks and six settled no-DB children: nonempty and empty envelopes completed bootstrap; missing, malformed, noncanonical and decoded-NUL envelopes were rejected at environment validation. Each child exit/close was 0. All nine protected hashes matched the prior baselines. Current Test SHA-256 `2d14867424b6c88dba0b56e8dc53dbb6a489aac0aead522083b51795ef74d03d`; Bootstrap `f1a9a721007d8c2d364a3656c2b5c5014c9d60548d9931851d7566d3483470d1`; Worker remains `26d3aceb721889c039d1ee86c8c67d01739ca2e60ac5a4203b325fdb61116ca1`.

Source inspection found the current ownership, cleanup and default-off safeguards present; it does not independently establish byte-identical old test bodies without a retained source snapshot. The raw-present invalid-wire fallback rejection is source-verified, not exercised by the child matrix. Those C3c checks did not use actual credentials or test database/claim behavior. Native assessment remained unassessable; independent verification was used. No commits, as explicitly prohibited.

C3 completed after the user explicitly approved one post-correction enabled invocation. Parent confirmed the temporary launcher absent, recreated generic code, read it fully and obtained verifier lint/hash evidence (`c1eb65e5079e92e8f3ec56f7fe741549944495d0a114151d1640226bc148925a`). Its count guard was updated to 17 tests and at least 210 assertions. The verifier ran the exact hash-guarded command once: PHPUnit exit 0, 17 tests / 241 assertions, zero errors/failures/skips/incomplete/risky results, no diagnostic failures. Fresh unselected metadata reported before `[]` and after `[]`; cleanup outcome `absence_observed`. Numeric outer command exit was not separately rendered; successful completion and PHPUnit exit 0 were observed. Parent rechecked the helper hash, removed only that owned file and confirmed absence. A separate read-only post-run check matched all 12 candidate/protected hashes against the pre-run output. No further invocation is authorized; the emitted `stop_enabled_runs=false` is an outcome field, not permission to repeat.

C4: independent source and runtime verification now support this bounded experiment, not production eligibility or unmodified WordPress reconnect/routing. Native `inspect` succeeded but returned `intended_untracked_selection_required`; its ambient tracked projection contains five preexisting paths outside this work unit: README, exploration, OpenSpec config, CoreExpectedFileRunner and its unit test. The three experiment sources are untracked. No selection or START was submitted, no lineage was created, and no native review approval is claimed. Do not silently broaden the candidate or commit/stash/reset protected work to obtain a clean projection. At that point, a narrowly scoped native-review strategy remained unresolved and C4 stayed open.

C4 disposition: read-only tooling investigation confirmed native CLI support for staged projection but found no documented staged selector in the installed callable Pi facade. No unsupported field, shell lifecycle bypass or Git mutation was attempted. The user then explicitly chose to close C4 with independent verification and omit native review only for this candidate. This closes the isolated experiment with a recorded review limitation; it is not native approval, a receipt, an authority burn or a change to the RDD switch. No lineage existed. The technical scope limitation remains unresolved for future candidates. The source work unit remains uncommitted at the user's explicit request; R1 and production design/implementation remain outside this closure.

## Acceptance criteria

1. Both children establish independent readiness before the common gate; only one work-entry occurs while its claim is held.
2. Loser cannot release or overwrite the owner. Winner release is conditional and duplicate/stale attempts do not advance state.
3. Existing default-off and 15-test behaviors remain intact; reported counts distinguish characterization from historical tests and genuine RED.
4. No site database/bootstrap, credential leakage, scratch output files or unknown-schema deletion.
5. Child settlement precedes owner-checked cleanup; fresh independent metadata confirms absence. Any uncertainty is reported, never converted to a pass.

## Rollback and next step

Rollback only the new concurrency changes to the three authorized test paths, preserving the original fixture and prototype; first prove no experiment processes remain. Keep this evidence record. Unknown schemas/processes are never reset or dropped. Next: retain this bounded experimental evidence for the separately scoped R1 design work. The temporary launcher is absent and its one-run authorization is consumed. C3 and C4 are closed for this isolated characterization; R1 remains open. Native review was explicitly omitted for this candidate only. No repeat, commit, publication or production implementation is implied.
