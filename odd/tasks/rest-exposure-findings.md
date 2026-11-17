# REST exposure findings — WordPress 7.1.4 era

Deepen the plugin's REST axis, the only surface where an edge WAF structurally cannot compete. User authorized improving the plugin and selected this axis. Findings surface in the existing REST diagnostic plus a read-only dashboard panel; a persisted baseline snapshot enables a surface diff. No runtime control is added, no callback is ever invoked, and no existing pinned count changes.

## Specs

- S1 (verbatim, user): "ok ayudame a mejorarla entonces" — improvement authorized; axis A (REST exposure depth) selected by the user.
- S2 (decision, user): findings appear inside the existing REST Site Health diagnostic and in a read-only panel on the dashboard `rest-api` tab. No fourteenth Site Health test is added, and the pinned diagnostic counts stay at 13 with `Good 4` / `Needs attention 9`.
- S3 (decision, user): a persisted snapshot is kept so the plugin can show which routes appeared or disappeared since the baseline, captured explicitly by an administrator and clearable by them.
- S4 (constraint, repository): the inventory path must not initialize REST and must never invoke route or permission callbacks (`README.md:251`; pinned by `tests/Unit/RestSurfaceInventoryTest.php:171-177`). The new layer inherits both guarantees, and a source-level assertion extends the second one to any new class.
- S5 (constraint, honesty): no claim that a route "is public" or "is authorised". Classification is structural only, from the registered value: `absent` (no effective permission check — the key is missing, `null`, or any empty value such as `false` or `''`, which WordPress skips because dispatch tests `! empty( $permission_callback )`), `public` (`__return_true`), `denied` (`__return_false`), `opaque` (any other non-empty value — authorisation unknown and never invoked). Closures, array callables and invokable objects are all `opaque`. A registered `false` is therefore `absent`, not `opaque`: WordPress does not deny on it, it skips the check, and reporting it as "unknown" would under-report anonymous exposure.
- S6 (constraint, repository): existing pinned output strings and diagnostic counts keep their meaning. Where a test asserts a full string that now carries additional evidence, the test moves with the code; no assertion is deleted or weakened.
- S7 (constraint, data): the snapshot is a single schema-versioned option, validated on read, bounded by a documented cap with an explicit truncation flag, and removable by an administrator. This change introduces no uninstall cleanup; that stays a separate decision.

## Tasks

- T1 — Permission-callback classification (S5) plus a proof that no classification invokes the callback. Route: delegated writer on this document. Commit: one work unit.
- T2 — Aggregate exposure evidence inside the existing REST diagnostic (S2, S6): counts per class, with the honest wording. Route: same writer as T1. Commit: with T1.
- T3 — Snapshot store (S3, S7): bounded, schema-versioned, validated reads, capability and nonce gated writes and clears. Route: delegated writer. Commit: one work unit.
- T4 — Surface delta (S3): added, removed and permission-class-changed entries between snapshot and live registry. Route: same writer as T3. Commit: with T3.
- T5 — Read-only dashboard panel on the `rest-api` tab with explicit capture and clear forms (S2, S3). Route: delegated writer. Commit: one work unit.
- T6 — Verification: full suite, packaging test, README coverage-limit text for the new claims, and confirmation that no diagnostic count moved. Route: parent. Commit: docs with T5.

## Design notes (parent-owned)

- Reuse the existing registry read in `RestSurfaceInventory` (`src/RestSurfaceInventory.php:114-166`), widening the copied handler keys at `:163` from `methods` alone to `methods` plus the permission-callback class. Do not call `get_routes()` and do not initialize REST.
- Delta comparison keys are `METHOD route` (endpoint keys already carry the namespace), so the snapshot stays a flat map `key => class` plus capture metadata.
- The panel attaches beside `renderCatalog()` at `src/Admin/SecurityDashboard.php:96-98`, leaving `renderCatalog()` and `RestRouteCatalog` untouched.
- The new panel is read-only except for capture and clear, both target-bound nonce protected like `RestRouteControlsAdmin::hiddenFields()`.

## Log

- L1 (verbatim, user): "ok ayudame a mejorarla entonces"
- L2 (decision, user): axis A — REST exposure depth, chosen from four offered slices.
- L3 (decision, user): existing REST diagnostic plus dashboard panel; no fourteenth Site Health test.
- L4 (decision, user): persisted snapshot with a surface diff, administrator-captured.
- L5 (evidence, exploration): `$wp_rest_server->endpoints` already carries `permission_callback` per handler, and the inventory currently copies only `methods` (`src/RestSurfaceInventory.php:163`); `permission_callback` is read nowhere in `src/`.
- L6 (evidence, exploration): adding a fourteenth Site Health test would break `tests/Unit/SiteHealthDiagnosticsTest.php:60-120` and `tests/Unit/SecurityDashboardTest.php:251-253`, which is why S2 keeps the count at 13.
- L7 (evidence, T1+T2 delivered, commit `711fb28`): permission-callback classification plus per-class counts in the existing diagnostic. Parent review corrected a semantic gap the writer introduced: `false`, `''`, `0` and `[]` were classified `opaque`, but WordPress runs the callback only when `! empty( $permission_callback )`, so an empty registered value skips the check rather than denying. They are now `absent`, which turns "I set false expecting a denial" into a visible finding instead of an under-reported one. S5 amended accordingly.
- L8 (evidence, follow-up commit `e030de1`): the writer reported one full-suite failure as environmental. Verified true but not inevitable: the working-tree `readme.txt` has 102 CR while the blob has 0, and the short-description pattern anchored on a bare LF pair. The delimiter is now `\r?\n\r?\n` and the limit was proven to still bite — a synthetic 151-character description is captured under both CRLF and LF and would still fail the 150-character assertion.
- L9 (evidence, T3+T4 delivered, commit `bc88380`): snapshot store and delta, 20 new tests. Parent review moved the exposure ordering from `RestSurfaceDelta` to `RestExposureClassification`: storage was depending on the comparison layer to rank classes, and the delta's own `severity()` had no production caller besides the snapshot. Full suite 313 tests, 2830 assertions, green.

- L10 (evidence, T5 delivered, commit `eb0a1f8`): read-only REST Exposure Findings panel plus `RestSurfaceInventory::rawEndpoints()`, extracted into shared helpers so no second registry read path exists. 20 new tests; suite 333 tests, 2965 assertions. Parent review confirmed the write path order (capability gate, then action/target match, then command whitelist, then nonce, then write) and that `--filter SecurityDashboardTest` passes standalone here, so the writer's reported pre-existing stub errors did not reproduce.
- L11 (evidence, T6): README gains the structural-classification and baseline-diff boundaries, including the `! empty()` reasoning behind `absent`, the 500-key comparison bound, the request-local registry limit, and the explicit statement that an empty diff is not a security verdict. An isolated LF build from HEAD produces 49 files and contains all four new classes; the full suite and `PackagingTest` are green and Site Health stays at 13 diagnostics.

## Outcome

T1-T6 are complete and committed locally: `711fb28` (classification), `e030de1` (CRLF-portable metadata assertion), `0213262` (spec), `bc88380` (snapshot and delta), `eb0a1f8` (panel), plus this documentation commit. Nothing is pushed: the Pi pre-delivery guard still refuses every delivery command for provider defect Gentle AI #6156, so push and PR remain human steps. Not claimed: authorization quality, callback correctness, proxy or CDN reachability, or coverage beyond the registry visible in one request.
