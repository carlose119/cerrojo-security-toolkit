# Proposal: manual, resumable WordPress core integrity checks

**Status: Withdrawn from current product scope.** By explicit user authorization, the entire exclusive core-integrity implementation, tests, prototype, and workflow were removed. Both the resumable design and suggested simplified checker are withdrawn. The historical proposal below is retained for context only; it is not authorization to resume implementation or evidence of runtime verification. See the [historical withdrawal index](../../../odd/tasks/core-integrity-withdrawal-index.md).

## Intent

Give single-site administrators an explicit, read-only way to assess expected WordPress core files over bounded manual batches without losing progress between visits. The existing bounded runner restarts the same prefix on repeated calls; repeating it alone cannot provide resumable coverage. Results must distinguish verified matches, changes, and unverified coverage rather than imply that a partial scan is clean.

This is an integrity comparison, not proof that a site is uncompromised. No unexpected-file detection or repair is promised.

## Scope and product rules

| Area | Confirmed policy |
|---|---|
| Entry point | Dedicated Core integrity tab for currently authorized administrators; unavailable on multisite. |
| Execution | Explicit Start, then explicit Continue for every bounded batch. Preserve temporary progress across visits; visiting a page never starts or continues verification. |
| Shared ownership | One shared per-site run; any currently authorized administrator may continue. Independently validate capability and nonce on every action request. |
| Concurrency | Protect both execution and result commitment against simultaneous or stale requests; temporary DB state and locking are accepted in principle. **Bloquear por seguridad:** uncertain execution termination blocks all new batches and replacement until safe recovery is confirmed; elapsed time never unlocks. Unavailability and possible technical intervention are accepted, not a force-unlock procedure or proven backend. |
| New run | `Iniciar nuevo` asks explicit confirmation warning that prior progress will be lost. Only a confirmed POST may replace a non-executing run; recheck under ownership and preserve any executing batch. No separate discard-first step. |
| Observation | Read only expected core files using the official checksum/manifest boundary; retain existing advisory route/handle checks without weakening or alternate reads. No absolute hostile-race containment guarantee is added. No repair, deletion, file writes, or upload of local contents. |
| Results | **Informar No verificable:** aggregate match/modified/unverifiable counts with bounded relative-path findings. Ambiguous absence/access/read failure is unverifiable and coverage incomplete, never confirmed or suspected missing. This supersedes the earlier missing-category requirement for this version. No absolute paths, contents, or permanent history. |
| Changed identity | If version or manifest changes at Continue, stop, retain the old incomplete summary, and require explicit Start from zero. Never silently migrate progress. |
| Budget exhaustion | Retry a file that exhausts an already used batch at the start of a fresh manually triggered batch. If it exhausts that fresh batch too, mark it not verified due to limit and advance, preserving incomplete coverage. |

Do not automatically raise limits or interpret timeout as evidence of an oversized, modified, or clean file. Exact caps, expiry, and lock mechanisms remain design proposals, not user-approved facts. Retaining a stopped summary remains subject to the temporary-state policy; it does not create permanent history.

### Out of scope

- Automatic continuation, cron/scheduled execution, email notifications, and Site Health integration.
- Multisite, unexpected-file enumeration, repair/deletion, and filesystem writes.
- Permanent history, a malware verdict, or a guarantee of a point-in-time filesystem snapshot.
- Implementation or changes to source, tests, README, or runtime configuration during this launch.

## Existing foundation and proposed direction

Supplied current evidence identifies a reusable identity reader, official checksum client, canonical manifest, contained verifier, and bounded runner. The runner returns scalar counts without a cursor; repeated calls restart the prefix. Bootstrap/admin wiring was not verified by the proposal phase; current design inspection is recorded separately in `design.md`.

Preserve the current runner and its tests unchanged. A later design must define a separate resumable progress/state contract, including deterministic position, findings, budget retry state, identity binding, and guarded commitment. Reuse needs validation; this proposal does not promise a trivial adapter or a hard synchronous I/O deadline. Prior candidate-specific RDD approval does not approve integration.

Network and filesystem failures, unavailable identity, expired/corrupt state, and uncertain coverage must not become clean results. Interruption policy is now settled: block while execution termination is unknown. `design.md` retains the concrete atomic storage/replay/compatibility proof gap; elapsed time and technical-intervention acceptance do not establish safe recovery. A plugin lock cannot prevent WordPress updates or external file changes.

## Affected areas — future candidates, not edit authorization

| Area | Expected impact |
|---|---|
| Core integrity services | Separately designed resumable orchestration around reusable identity, checksum, manifest, and containment behavior; leave the current runner/tests unchanged. |
| Temporary state | Shared per-site progress, bounded findings, expiry, lock ownership/recovery, and stale-commit protection. |
| `src/Bootstrap.php` and admin integration | Explicit action wiring, per-request authorization/nonce checks, dedicated tab and honest result states; no passive scanning. |
| Future unit tests and public documentation | Cover state transitions, adversarial concurrency, budget retry, identity change, output privacy, and single-site/manual-only scope. No edits now. |
| Planning artifacts | Earlier proposal reconciliation covered config/preproposal/exploration. Current design continuation may edit only this proposal, preproposal, change-local spec, and design; no canonical specs or config changes. |

## Risks and safeguards

| Risk | Required response |
|---|---|
| Duplicate/stale requests corrupt progress | Prove atomic execution ownership and guarded commits, including transport replay/ambiguous writes. Never take over because of age; uncertain termination is explicitly fail-closed. |
| Budget exhaustion repeatedly blocks one file | Persist the confirmed fresh-batch retry distinction; advance with explicit incomplete coverage after fresh-batch exhaustion. |
| Blocking I/O exceeds a request budget | Do not advertise a hard deadline; design interruption-safe state handling and candid limit outcomes. |
| Core/manifest changes or files change mid-run | Stop on confirmed identity change; preserve incomplete summary. Detect uncertainty where feasible and never claim a stable snapshot. |
| State expiry or bounded detail hides gaps | Keep completeness and category counts explicit; distinguish omitted findings from assessed coverage. Exact expiry/caps remain open. |
| Path or diagnostic leakage | Persist/render only bounded approved relative paths and safe summaries, never contents or raw absolute-path errors. |
| Historical context overstates authority | Historical exploration is superseded where noted; no completed research, verified provenance fix, or integration approval is claimed. |
| Future work exceeds review budget | Ask the user under ask-on-risk at 400 changed lines; chain strategy remains deferred and no exception is inferred. |

## Rollback

This phase changes planning documents only; no runtime rollout or data migration occurs. Revert only this reconciliation/proposal delta if rejected, preserving unrelated work and the preexisting untracked preproposal. Do not reset the modified README, runner, or runner tests.

A future implementation plan must define how to disable the new entry points and safely expire/clean temporary state without touching core files. That operational rollback design is outstanding, not implemented here.

## Success criteria for a later approved implementation

- Administrators can Start and explicitly Continue a shared single-site run across visits; no passive/background continuation occurs.
- Every action independently enforces current authorization and nonce validation; concurrent/stale requests cannot duplicate committed progress or overwrite a newer run.
- Resume progresses through expected files without restarting the already verified prefix or double-counting results.
- Version/manifest changes stop the run with the old incomplete summary retained and require explicit Start from zero.
- Used-batch exhaustion causes one fresh-batch retry; fresh-batch exhaustion advances with a not-verified-due-to-limit result and incomplete coverage, without raising limits.
- Only aggregate counts and bounded relative-path findings are exposed; incomplete or failed coverage is never presented as clean.
- No repair, file writes, extra-file enumeration, multisite operation, cron, email, permanent history, or Site Health integration is introduced.
- Existing runner and tests remain unchanged; future approved work follows configured strict TDD with `composer test`, with `composer check` and `composer syntax` retained. No tests were run or authorized in this proposal phase.

## Outstanding design and research questions

1. What separate resumable contract provides deterministic traversal, bounded findings/counts, retry state, and interruption recovery without modifying the existing runner?
2. Which compatible authoritative store proves unique creation, conditional claims/commits and replay handling? Fail-closed abandoned-worker availability is approved; automatic ownership expiry is prohibited. Do not reopen that policy as an unresolved choice.
3. What exact batch/network/storage caps, temporary-state expiry, and cleanup rules fit supported hosting constraints? No numeric limits are approved yet.
4. How should package-locale trust and manifest identity/freshness be established, including unavailable checksum data and updates during execution?
5. Which permitted official evidence supports the remaining technical assumptions? The user expanded sources from WordPress-only to official WordPress/PHP/MySQL/MariaDB. `design.md` records parent-read PHP failure/cache semantics, MySQL 8.4 locking, unpinned MariaDB named-lock semantics, and WordPress tag-7.1 query reconnection/replay, alongside earlier option/nonce evidence. This does not prove deployment compatibility, full CAS safety, formal research completion or provenance remediation; no research artifact is created.

## Proposal question round

These optional product questions are for user review to improve the proposal by uncovering business rules, implications, edge cases, and tradeoffs; they do not reopen the confirmed scope. The delegated proposal phase records them here rather than inventing answers.

1. Is the main use case routine reassurance, investigating a suspected change, or checking after an update? Assumption pending review: report integrity evidence without presenting any use case as a security guarantee.
2. **Resolved during design continuation:** Start replaces a non-executing shared run only after explicit confirmation warning that prior progress will be lost. Reject replacement while a batch executes, including when confirmation UI is stale. No separate discard-first action is required. The original confirmation-versus-discard question is retained here as history, not an open decision.
3. When temporary progress expires, what loss-of-progress notice would make starting again understandable? Confirmed boundary: temporary state only; exact expiry is a later design proposal.

The remaining optional questions may be answered, skipped, or corrected without reopening the resolved replacement policy. Specification is completed and design continuation is now explicitly authorized; persistence and auto pacing do not authorize tasks or implementation. `design.md` records draft technical choices and blockers requiring resolution before a completed plan can be approved.
