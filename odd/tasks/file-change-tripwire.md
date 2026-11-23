# File change tripwire — implementation

Cerrojo can already say what plugins and administrators changed, but nothing watches the executable code itself. This feature adds a bounded baseline of plugin, mu-plugin and theme files plus a delta that reports files added, removed or changed since that baseline, with an email alert and an acknowledgement in the panel. It is a tripwire, not an integrity guarantee and not malware removal.

Risk: item 1 pending assessment — the feature stores a baseline derived from files on disk and reports changed bytes; no data is deleted and no file is modified. Re-assessed before the candidate is reported complete.

## Specs

- S1 (verbatim, user): "ok hagamos eso" — accept the four-point strategy proposed in the previous message.
- S2 (verbatim, parent proposal, accepted by S1): "**Convertir el tripwire en el corazón**: alertas de cambio de archivos del plugin/tema, con baseline y reporte acotado. Reusa el molde stateless que ya existe (inventario + snapshot + delta), no necesita locks ni reanudación, y es lo que de verdad atrapa un incidente."
- S3 (verbatim, parent proposal, accepted by S1): "**No re-autorizar el core-integrity completo**; si acaso, el "integrity-lite" stateless sobre archivos críticos — mismo molde, sin estado, sin locks."
- S4 (verbatim, parent proposal, accepted by S1): "**Login throttling y headers**: dejarlos como están, sin invertir más."
- S5 (verbatim, parent proposal, accepted by S1): "**Mantener y profundizar REST exposure**: es lo único que no encontrás hecho."
- S6 (selection, user): "Plugins, mu-plugins y themes" — watch `wp-content/plugins/**`, `wp-content/mu-plugins/**` and `wp-content/themes/**`; never `uploads/`.
- S7 (selection, user): "Email + panel, con reconocimiento" — a detected change sends an email and appears in the panel; the administrator can acknowledge a change so the same hash stops alerting.
- S8 (constraint, repository): a new stored option must be derivable by the uninstall guard, which derives plugin-owned option names from declaration shape rather than an enumerated list; the name must match that rule or the cleanup silently misses it.
- S9 (constraint, repository): the packaging contract and the Site Health registry pin the shipped surface; new classes under `src/` must be autoloadable by the existing convention and the build must still produce a valid package.
- S10 (scope): this feature never writes, moves, deletes or repairs a watched file, never uploads content, and never claims that an unchanged baseline means the site is uncompromised.
- S11 (scope): no lock, no resumable multi-visit run and no cross-request ownership. Each capture is bounded and independent, so a partial capture reports incomplete coverage instead of implying a clean result.
- S12 (honesty): a file the capture cannot read is reported as unverifiable, never as unchanged. Bounded or truncated coverage is stated in the result.

## Tasks

- T0 — Map the existing molds (snapshot/delta, alert policy, uninstall derivation, admin surface, test harness) before authoring. Route: `gentle-ai-explore`. Done.
- T1 — Author the feature document and its Engram mirror from the reconciled evidence. Route: parent. Done.
- T2 — Bounded baseline manifest, delta and PHP scanner over `plugins`, `mu-plugins` and `themes`, test-first. Route: two writers on disjoint paths (manifest/delta and scanner), plus the parent for the uninstall entries the new option constant requires. One commit.
- T3 — Alert policy: stored configuration, bounded check, email on unacknowledged changes, per-hash acknowledgement, recorded cycle outcome. Route: parent. One commit.
- T4 — Admin panel section, `Bootstrap` wiring, daily bounded scheduled check, `Uninstall::OPTIONS` entries and the user documentation of the honest limits, in one commit with its tests. Route: parent.
- T5 — Checks: full PHPUnit suite, `composer syntax`, `composer validate`, `composer audit`, `package:verify`. Route: parent.
- T6 — Independent verification of the file-read boundary, the option derivation and the alert path. Route: `gentle-ai-verify`.

### Non-goals for this feature

- No Site Health diagnostic for the tripwire in this unit; the panel and the alert are the surface.
- No coverage of `uploads/`, of WordPress core files, or of non-PHP files; `S6` and `S10` bound it.
- No fix of the unwired `RestExposurePanel`; that defect is separate and keeps its own decision.

## Progress and evidence

- T2 landed in `72cdd1a` (scanner: 13 tests / 2,089 assertions) and `7c30cb3` (baseline manifest + delta: 30 tests / 228 assertions). Full suite after both: 451 tests / 5,881 assertions green, syntax clean.
- The uninstall boundary moved with the new option: `bastion_security_wp_file_integrity_baseline` added to `Uninstall::OPTIONS` and to `UninstallTest::PINNED_OPTIONS`, whose explicit count went from 14 to 15 so a future option cannot slip in silently.
- Separate defect found while mapping the molds and fixed in `f7748d7`: `Bootstrap` never constructed the REST exposure panel, so it rendered nothing in production.

## Log

- L1 (verbatim, user): "ok hagamos eso"
- L2 (selection, user): "Plugins, mu-plugins y themes"
- L3 (selection, user): "Email + panel, con reconocimiento"
- L4 (evidence, parent, read-only): the candidate code from the withdrawn `core-integrity-*` experiments does not exist in the worktree or in tracked history — `git log --all -S "CoreIntegrityRunStore"` matches only `bfb3ad2`, and the seven `src/CoreIntegrity` files removed in `340547e` are the older withdrawn checker. S3 therefore forbids re-authorizing that line rather than restoring files.
- L5 (evidence, parent): both writers' artefacts were re-verified by the parent — the test files were re-run independently and the source read — instead of trusting the completion reports.
- L6 (decision, parent): the scanner's additive strictness is accepted: `total` counts every candidate that passed the surface and extension filters before the bound, including size-skipped and unreadable ones; extensions match case-insensitively; a file that vanishes between the walk and the hash is unreadable, never unchanged.
- L7 (decision, parent): the baseline's stricter read rules are accepted (positive `captured_at`, non-negative `total`, empty path refused), because they mirror the mold and reject shapes its own writer cannot produce.
