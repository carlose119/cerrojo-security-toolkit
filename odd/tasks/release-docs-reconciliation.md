# Release documentation and withdrawn-context reconciliation

## Authorization and delivery boundary

The user authorized documentation commits and reconciliation of OpenSpec after Core Integrity withdrawal, then explicitly requested the result on master WITH push. Work-unit commits were prepared on local `docs/release-evidence`, based on release merge `7fdf3543479f8554a9c7f9f84a5cda33a47f3897`. Delivery is a fast-forward of local master and a normal master push; the temporary branch is not published. No production-code, tag, release or SVN changes are authorized by this task.

## Completed source work

- [x] D1 — Record accurate release/compatibility evidence and the README source link. Commit `29abd8842f84d40f8abec2cd1d8bee84e49e5209`:3 paths,104 additions. Mechanical record corrections distinguish historical authorization/branch state from verified release completion. Parent read-back, exact staged-path checks and `git diff --cached --check` passed. Native review was skipped for this passive documentation-only unit; runtime checks are N/A.
- [x] D2 — Reconcile inactive OpenSpec context separately. Commit `18e53687591a37d5a761cbc02a057f9141037224`:2 paths,2 additions/11 deletions. Removed only obsolete `feature_context` from `openspec/config.yaml`; replaced only exploration's initial notice with withdrawal status linked to `proposal.md`. Historical body, strict TDD and unrelated settings remain unchanged. Writer `muewismq-15-6g3o` and parent scoped diff/whitespace checks passed.

Native D2 review `review-51276e545563dfe2` covered exactly the two OpenSpec paths and13 changed lines. The single reliability reviewer approved the immutable candidate; exact acknowledgement returned `native-approved-acknowledgement-completed` with authority burned. Immediately following acknowledgement, ASSESS with explicit `nativeReviewOutcome: closed` required no separate verifier. ASSESS itself remained unassessable because of excluded untracked history; no broader assessment success or retroactive release approval is claimed.

## Scope and preservation

The source units total117 authored diff lines, below400. This parent-owned tracking snapshot is committed separately after recording both work-unit identities, avoiding self-referential commit hashes. It adds documentation only.

Old untracked Core Integrity task/design/spec records are neither staged, modified nor deleted. The protected local ZIP was independently read by the parent after review and remains SHA-256 `4ed1f774b39d71bec675b6d2272f078200e09d0801e2f8f6dc46fb48976b52dc`. Earlier preservation constraints for README/config/exploration were superseded only by the user's explicit documentation/context authorization.

No local PHP, Composer, test suite, build, installation, WordPress, database or downloaded-code execution occurred. Runtime RED/GREEN is N/A because only documentation and inactive planning context changed; no executable plugin behavior or runner setting changed. Existing GitHub CI may run on the authorized master push. Its final run and remote-head read-back are delivery evidence recorded separately in session memory, not invented in this pre-push source-completion snapshot.

## Rollback and finalization

The two isolated source commits can be reverted independently if later authorized; preserve unrelated history and files. No reset, clean, stash, force push or old-tag replacement is allowed. Release0.3.0 and WordPress SVN r3710374 are not republished.

Both source tasks and their applicable checks are complete. The final tracking commit, fast-forward to master, normal push and authoritative remote read-back follow this snapshot under the user's explicit delivery authorization. No unresolved product decision or runtime modification remains.
