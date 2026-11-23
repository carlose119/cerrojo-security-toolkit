# Core-integrity feature withdrawal — closed

## Decision and final scope

The user withdrew both the resumable WordPress core-integrity checker and its suggested simplified variant, then explicitly selected `remove_entire_core_integrity_module`. The exact33files below were deleted, including15untracked files and local changes to tracked CoreExpectedFileRunner.php and its test. This is completed withdrawal, NOT completed feature/runtime verification.

ODD, not SDD. No commits, staging, reset, clean, branches, push, CI dispatch, WSL or Docker. Parent owns this document and full Engram5227 under odd/core-integrity-diagnostic-supervisor/tasks. Historical OpenSpec/ODD documents remain. Previous review authority stayed closed; no new review approval was claimed.

## Removed files (exact authorized boundary)

Source13:
- src/CoreIntegrity/CoreChecksumManifest.php
- src/CoreIntegrity/CoreExpectedFileBudget.php
- src/CoreIntegrity/CoreExpectedFileRunBudget.php
- src/CoreIntegrity/CoreExpectedFileRunProgress.php
- src/CoreIntegrity/CoreExpectedFileRunner.php
- src/CoreIntegrity/CoreExpectedFileSummary.php
- src/CoreIntegrity/CoreExpectedFileVerification.php
- src/CoreIntegrity/CoreExpectedFileVerifier.php
- src/CoreIntegrity/InstalledCoreIdentity.php
- src/CoreIntegrity/WordPressCoreChecksumClient.php
- src/CoreIntegrity/CoreIntegrityRunState.php
- src/CoreIntegrity/CoreIntegrityRunStore.php
- src/CoreIntegrity/CoreIntegrityRunStoreResult.php

Unit11:
- tests/Unit/CoreChecksumManifestTest.php
- tests/Unit/CoreExpectedFileRunBudgetTest.php
- tests/Unit/CoreExpectedFileRunProgressTest.php
- tests/Unit/CoreExpectedFileRunnerTest.php
- tests/Unit/CoreExpectedFileSummaryTest.php
- tests/Unit/CoreExpectedFileVerifierTest.php
- tests/Unit/InstalledCoreIdentityTest.php
- tests/Unit/WordPressCoreChecksumClientTest.php
- tests/Unit/CoreIntegrityRunStateTest.php
- tests/Unit/CoreIntegrityRunStoreTest.php
- tests/Unit/CoreIntegrityDiagnosticSupervisorTest.php

Integration7:
- tests/Integration/CoreIntegrityRunStoreBackendBootstrap.php
- tests/Integration/CoreIntegrityRunStoreBackendTest.php
- tests/Integration/CoreIntegrityRunStoreConcurrentWorker.php
- tests/Integration/CoreIntegrityRunStoreProbeBootstrap.php
- tests/Integration/CoreIntegrityRunStorePrototype.php
- tests/Integration/CoreIntegrityRunStoreTest.php
- tests/Integration/CoreIntegrityDiagnosticSupervisor.php

Fixture/workflow2:
- tests/Fixtures/CoreIntegrityDiagnosticChild.php
- .github/workflows/core-integrity-supervisor.yml

Only these files were authorized for deletion; no recursive directory deletion. Proposal status/withdrawal notice was updated in openspec/changes/core-integrity-checker/proposal.md; its historical body remains. README has no feature advertisement and was not edited for withdrawal. Generic PSR-4 configuration and current ci.yml needed no change. Historical docs may name removed files; they are not active development instructions.

## Verification and accepted incident

TDD ON from openspec/config.yaml strict_tdd:true. Writer mueoahpc-g-91qn observed all33regular files present before deletion and absent after; this is structural evidence, not behavioral RED/GREEN. Reported regression280tests/2522assertions passed, but artifact preservation FAILED during that run.

REVOKED command, evidence only — DO NOT RUN:
```
composer test -- --do-not-cache-result --filter '/^(?!.*PackagingTest::)/'
```

The protected .build/cerrojo-security-toolkit.zip was replaced:
- Before SHA256:8d334113337384769f9a50235d0fee1521df1fe702c860235a74deab142f4ebd
- Accepted current SHA256:4ed1f774b39d71bec675b6d2272f078200e09d0801e2f8f6dc46fb48976b52dc
- Current size:89829bytes.

The preservation assertion stopped at ZIP after8preceding hashes matched; it did not establish all original survivor hashes. Parent immediately disclosed the incident and halted executions. No repair, rebuild, ZIP deletion or restoration was attempted; no verified original backup exists. Committed history cannot recover removed untracked contents or uncommitted changes.

Read-only diagnosis mueofakh-h-fkqw established that installed PHPUnit filters before suite execution and checks filtered class-suite emptiness before setup. Class setup alone does NOT explain the mutation if the valid regex arrived unchanged. Actual Windows argv/Composer forwarding was not observed; root cause remains unknown. Packaging source deletes .build and invokes child Composer, but external cache/network effects were not independently established.

User explicitly selected `accept_current_zip_readonly_finish` (memory5252): accept the replaced ZIP, preserve it unchanged, and finish ONLY in read-only mode. This resolves disposition, not historical preservation. No further tests, PHPUnit listing, builds, installations, workflow operations or repairs were authorized/executed.

Native assessment returned unassessable due untracked scope and required independent verification; no lineage/approval created. Runtime harness not applicable to removal because no execution boundary was added. No original-feature readiness claim.

## Final independent evidence

Verifier mueosg44-i-c6jw settled bounded READ-ONLY PASS:
- Exact33unique paths absent;18tracked deletions exactly match authorized paths,15previously untracked paths absent.
- No removed class/namespace/file/workflow references in active src, tests, tools, .github, composer.json/lock, phpunit.xml.dist or plugin entrypoint. Additional dynamic include/class/path search found only unrelated uses. External consumers and other surfaces are not covered.
- Proposal withdraws both variants and retains historical body.
- Before/after21protected hashes and scoped Git status identical during W2, including the accepted ZIP. This does NOT establish preservation back to the original writer baseline.
- No tests, PHP, builds or mutations during W2. CodeGraph timed out; directed source search supplied evidence. Initial guessed path/search errors were corrected read-only, with no mutation.

Parent spot-read proposal and reconfirmed accepted ZIP hash/Git status. Master remains ahead10 with18tracked deletions plus the original unrelated README/exploration/config modifications and historical untracked documents. No delivery occurred.

## Closure

- S1 previous supervisor implementation: CANCELLED/PARTIAL, not passed by deletion.
- S2 previous offline verification and S3 progress recording: historical completed evidence only.
- S4 runtime/publication/validator acquisition: CANCELLED; download was declined.
- S5 manual workflow authoring: CANCELLED/PARTIAL; never published or executed.
- [x] W1 Remove33files and mark proposal withdrawn.
- [x] I1 Diagnose incident in read-only mode and record user's current-ZIP acceptance; root cause remains unconfirmed.
- [x] W2 Independently verify removal/reference boundary and current-state preservation.
- [x] W3 Record withdrawal closure and limitations.

No active workers or remaining feature tasks. Do not resume checker, supervisor, workflow validation or prototype development without a new explicit product decision. Further tests/publication/artifact changes need separate authorization. Preserve all remaining historical documents and unrelated work.

## Subsequent authorized delivery

After the withdrawal closure above, the user explicitly requested `haz commit y push`. This superseded the earlier no-commit/no-push restriction for this delivery only; tests, builds, artifact changes and feature development remained prohibited.

- Created and pushed `chore/remove-core-integrity`, preserving the ten prior local commits without rewriting history.
- Commit: `340547edfdb2f9116fb440a292b9859d1830174f` (`refactor(integrity): remove withdrawn core integrity checker`), parent `32b3d414bc76b97805b4d9e455f60cd76028aeac`.
- Exact commit scope:18tracked deletions plus the historical proposal with its withdrawal notice;19paths,98insertions,2272deletions. Previously untracked removals cannot appear as Git deletions.
- Native committed-range START failed before authority creation (`candidate-target-projection-drift`, no lineage or mutation); subsequent assessment was unassessable due untracked scope. No repair/retry or native approval was claimed; cause remains unknown.
- Independent verifier `muepiaga-k-60jn` returned bounded structural PASS for the exact commit, empty index, removed-reference boundary and accepted ZIP. `git diff --check HEAD^ HEAD` passed. No tests, PHP or builds ran.
- `git push -u origin chore/remove-core-integrity` succeeded. Remote readback confirmed the exact commit on that branch; remote master stayed `b57c5d01299457919337a343921cf84de4ced86c`. No PR or release was created, and this branch push does not match the current master-only CI trigger.
- GitHub reported the repository moved to `https://github.com/carlose119/cerrojo-security-toolkit.git`; the existing origin URL was not changed.
- Post-push ZIP SHA256 still `4ed1f774b39d71bec675b6d2272f078200e09d0801e2f8f6dc46fb48976b52dc`. Unrelated README/config/exploration edits and other historical untracked documents remain local. This parent-owned delivery record is also local.

Delivery is complete; source withdrawal remains closed. The earlier no-delivery statements describe the initial withdrawal closure, not this separately authorized delivery.
