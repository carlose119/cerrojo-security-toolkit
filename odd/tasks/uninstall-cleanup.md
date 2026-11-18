# Uninstall cleanup — implementation

Cerrojo deletes its own stored data when the plugin is deleted. Scope is the 14 plugin-owned options plus the two hashed login-protection transient families, removed unconditionally; nothing else in the database is touched.

Risk: item 1 (irreversible deletion of stored data) — independently verified by `gentle-ai-verify`, PASS with four minor findings, all three actionable ones corrected here.

## Specs

- S1 (verbatim, user): "continua" — resume work.
- S2 (verbatim, user): "los puntos que quedaron pendiente de desarrollo" — continue the pending development points, not the withdrawn `core-integrity-*` historical records.
- S3 (selection, user): "Todo lo propio: 14 opciones + transients", with the selected detail "delete_option() de las 14 claves + purge LIKE acotado a _transient_bastion_lpu_* / _transient_bastion_lpi_* (+ sus _transient_timeout_)".
- S4 (selection, user): "Siempre, al desinstalar" — no opt-in setting, no consent checkbox, WordPress convention only.
- S5 (constraint, repository): the packaging contract pins the allowed top-level entries. A root `uninstall.php` requires updating `tools/build.php` (its top-level copy list), `tests/Unit/PackagingTest.php` (allowed and required entries), and the smoke fixture `cp -a` in `.github/workflows/ci.yml`.
- S6 (constraint, repository): `tests/Unit/WordPressOrgMetadataTest.php:51` pins `= 0.4.0 =` as the first changelog entry. No unreleased changelog entry and no version bump in this feature.
- S7 (scope): only plugin-owned keys are removed — exactly the 14 options below plus transients whose name starts with `_transient_bastion_lpu_`, `_transient_timeout_bastion_lpu_`, `_transient_bastion_lpi_`, `_transient_timeout_bastion_lpi_`. No other option row, no custom table, no user meta, no network option.
- S8 (evidence, inventory): configuration options `bastion_security_wp_security_headers`, `_security_header_groups`, `_xmlrpc_pingback_protection`, `_login_protection`, `_file_editor_lock`, `_rest_route_controls`, `_plugin_activity_alerts`, `_critical_settings_alerts`, `_administrator_account_alerts`; operational records `_login_protection_metrics`, `_rest_surface_snapshot`, `_plugin_activity_alert_result`, `_critical_settings_alert_result`, `_administrator_account_alert_result`. Zero usermeta, zero site options, zero plugin tables.
- S9 (not stored): `bastion_notice`, `bastion_login_notice`, `bastion_critical_settings_alert_notice`, `bastion_plugin_alert_notice`, `bastion_administrator_alert_notice`, `bastion_rest_route_controls_notice`, `bastion_xmlrpc_pingback_notice`, `bastion_rest_route_disabled`, `bastion_login_throttled` are query arguments or error codes. `bastion_security_wp_transport`, `_file_editor`, `_file_modifications`, `_runtime`, `_debug_display` are Site Health test identifiers. None may appear in the removal list.
- S10 (correction, from verification): the whole literal part of every transient probe is escaped, including the underscores of the `_transient_` and `_transient_timeout_` forms. The trailing `%` is the only wildcard, so no option name outside the two families can match.
- S11 (correction, from the native review): a skipped or failed cleanup is never silent. `run()` returns the problems it met, and the entry reports each one through `wp_trigger_error()` when WordPress provides it, so an autoloader that is missing, a class that does not load, an unusable database layer and a failed statement are all observable instead of looking like a clean uninstall.
- S12 (correction, from the native review): the transient comparison is case-sensitive, because MySQL's default collation makes `LIKE` case-insensitive and the previous probe would have matched a case variant of a plugin transient name. The class docblock states what the statement actually does.
- S13 (correction, from the native review): the transient deletion is bounded in rows per statement and in batches, and reaching the batch cap is reported as a problem rather than passing as success.

## Tasks

- T1 — Author the RED unit tests for the removal inventory and the cleanup semantics. Route: parent. Commit `86ced29`.
- T2 — Implement `src/Uninstall.php` and the root `uninstall.php` guard entry. Route: parent. Commit `86ced29`.
- T3 — Extend the packaging contract, the CI smoke fixture and the real-WordPress smoke. Route: parent. Commit `86ced29`.
- T4 — Update the three documented statements (`readme.txt:34`, `readme.txt:66-68`, `README.md:310`) and the README pin in `tests/Unit/LoginProtectionAdminTest.php`. Route: parent. Commit `86ced29`.
- T5 — Run the checks: PHPUnit suite, syntax, `package:verify`, `php -l` on the new files. Route: parent. Commit `86ced29`.
- T6 — Independent verification of the deletion boundary. Route: `gentle-ai-verify`. Commit `86ced29`.
- T7 — Work-unit commits on the feature branch, then native assessment of the candidate. Route: parent. Commit `86ced29`.
- T8 — Correct the actionable advisory findings from the native review: observable cleanup problems (S11), case-sensitive comparison (S12) and bounded batches (S13). Route: parent. Commit `0201634`.
- T9 — Re-run the checks and the native review over the corrective candidate. Route: `gentle-ai-verify`. Commit `0201634`.

## Progress and evidence

- T1 RED, observed: 8 tests, 7 errors (`Class "BastionSecurityWP\Uninstall" not found`) and 1 failure (`The plugin needs a root uninstall.php entry`). T2 GREEN: 8 tests, 94 assertions. After adding the entry-wiring test: 9 tests, 106 assertions.
- T1 RED for the verified widening, observed before the fix: `UninstallBoundaryTest::testTransientPatternsReachOnlyTheLiteralTransientForms` failed with `A probe reaches a key it does not own: xtransient_bastion_lpu_1_abc`, matched by `_transient_bastion\_lpu\_%`.
- T3: `tools/build.php` produced a 51-file archive (49 before the change) and the archive contains both `uninstall.php` and `src/Uninstall.php`; `PackagingTest` 9 tests / 793 assertions green.
- T5: `php vendor/bin/phpunit` 392 tests / 3405 assertions green; `tools/check-syntax.php` clean over 76 files; `composer validate --strict` valid; `php -l` clean on the entry, the class and the integration script.
- T6 (verifier, `gentle-ai-verify`, PASS): confirmed byte-identical `escapeLike()` against `wpdb::esc_like()` over nine adversarial inputs by reflection, placeholders and arguments aligned, 4/4 patterns in stable order, deletion boundary executed against SQLite, guard probes A/B/C, and that the pinned inventory matches the 14 option-name constants derived from `src/` with no divergence in either direction.
- T6 finding 1 (minor, corrected): the `_transient_` form was not escaped, so its underscores were LIKE single-character wildcards. Fixed by escaping `$form . $prefix`, pinned by the boundary test above and by the lookalike sentinels added to the integration smoke.
- T6 finding 2 (minor, corrected): nothing cross-checked the pinned list against the write sites. Closed by `UninstallBoundaryTest::testOptionInventoryMatchesEverySourceDeclaration`, which derives both the option names and the hashed transient prefixes from `src/`.
- T6 finding 3 (minor, corrected): the docs claimed the transient blocks are removed without qualifying a persistent object cache. `readme.txt` and `README.md` now state that those blocks are cache entries there and expire with their own timeout, at most 30 minutes.
- T6 advisory (open follow-up): the sibling `wc` package under `.svn-staging/` shares the same option names and transient prefixes. Deleting one package while the other is installed would remove state the other reads. This is a pre-existing shared namespace, not introduced here.
- T7: the feature lands as one commit, `86ced29`, 871 authored changed lines including two new test files and the fixtures. The advisory ~400-line slice is exceeded deliberately: the code, its safety tests, the packaging contract and the documentation of one data-deletion behaviour do not separate without leaving an intermediate commit whose production build lacks the entry.
- Publication shape: the branch carries two code commits — `86ced29` (feature) and `0201634` (everything verification required, 513 lines) — plus this document. The three corrective rounds are folded into `0201634` so a reviewer reads them as one pass, with the round-by-round detail kept below.

## Native review

- Lineage `review-324d722cac32f1f2`, ordinary review of target `sha256:7871cde265e1f1602095017cf1e2390b5834cc9f8403d7ccfeb9d9a80e2720be` over the feature range (`ae843e4..86ced29` in the published history), twenty-one paths excluded as withdrawn history (the six `core-integrity-*` records).
- Four lenses ran: `review-risk`, `review-resilience`, `review-readability`, `review-reliability` on `nan/glm5.3-flash`.
- Outcome: approved, exact acknowledgement completed, authority burned under `gentle-ai.review-acknowledged/v1`. No correction was requested.
- Eleven advisory findings, all informational and non-blocking: R1-001, R2-001, R2-002, R2-003, R3-inventory-regex-shapes, R3-like-case-collation, R3-real-sql-unproved, R3-uninstall-silent-noop, R4-1, R4-2, R4-3.
- R3-real-sql-unproved restates the open condition in "Not claimed": the CI smoke job's exact success-line assertion is the merge condition for real-WordPress execution of the purge.
- R3-like-case-collation is recorded as a follow-up: MySQL's default collation makes `LIKE` case-insensitive, so a case variant of a plugin transient name would also match, which the class docblock and the case-sensitive boundary test do not model.
- The dominant theme across R1-001, R2-001, R2-002, R3-uninstall-silent-noop, R4-1 and R4-2 is one behaviour: the entry degrades to a silent partial or skipped cleanup when the autoloader, the class or `$wpdb` is unavailable, and the discarded `$wpdb->query()` result hides a failed `DELETE`. Recorded as follow-up work, not corrected here.
- Review delivery note: four START attempts were rejected as input-invalid before this one succeeded. The cause was the length of `lensesReason` (about 700 characters), not the lens selection or their order.
- Corrective assess (`86ced29..0201634`): risk medium, `reviewDue: false` (`under_budget`), so no second native review applies to the corrective candidate.

## Corrective rounds after the review

- Round 1 (in `0201634`): S11 (problems returned and reported), S12 (binary comparison) and S13 (bounded batches) implemented. Verified independently and **FAILED** on one blocker: the integration smoke verified the purge with a collation-sensitive `LIKE`, so the case-variant sentinel added in this same round looked like a survivor and the CI gate would have failed with a message that mimics a real defect. Six further findings were reported.
- Round 2 (in `0201634`): the blocker closed (the survivor query now compares bytes, like the statement under test), the report made reachable (`wp_trigger_error()` is inert without `WP_DEBUG`, so `error_log()` now runs unconditionally and the WordPress call is additional), a non-integer statement result rejected, the loop changed to delete until nothing matches and to probe once past the cap, and the index trade-off and the `delete_option()` false documented. Four tests added, including the log channel through an explicit `error_log` destination. Re-verified independently: **PASS**, blocker closed, boundary unchanged.
- Round 3 (in `0201634`): the two behaviours verification found unpinned are pinned (the smoke's binary comparison by a source assertion, the report's function name through the stub), and the cap message and both documentation sentences now match the code: twenty statements of 500 rows plus one confirming statement, reported as more than ten thousand matching rows.
- Final checks after round 3: `php vendor/bin/phpunit` 404 tests / 3491 assertions green; `PackagingTest` 9 tests / 793 assertions; archive 51 files; `tools/check-syntax.php` clean over 77 files.
- Still unpinned by design: the docblock-only claims (a failed `delete_option()` is indistinguishable from an absent row, and the binary cast gives up the `option_name` index).

## Not claimed

- `tests/Integration/UninstallSmoke.php` was written but never executed here: this repository sits inside a live site and no isolated WordPress fixture exists locally. The runtime SQL path is proven by the stub-based subprocess test, the verifier's SQLite execution of the same statement, and by CI, which owns the real-WordPress run. Until that job passes, real-WordPress execution of the uninstall routine is unverified.
- No claim that the routine reaches other sites of a multisite installation, or that any object-cache entry is invalidated. The plugin writes no network option and the routine uses the single-site option API.

## Log

- L1 (verbatim, user): "continua"
- L2 (verbatim, user): "los puntos que quedaron pendiente de desarrollo"
- L3 (selection, user): "1. Limpieza al desinstalar (value: uninstall)" — chosen first among the four verified pending points.
- L4 (selection, user): question 1 "¿Qué borra la desinstalación?" answered "Todo lo propio: 14 opciones + transients"; question 2 "¿Cuándo se ejecuta la limpieza?" answered "Siempre, al desinstalar".
- L5 (evidence, parent, read-only): inventory derived from `src/` constant declarations, not from memory. `src/Security/LoginProtectionPolicy.php:261,268` builds the hashed transient keys with prefixes `bastion_lpu_` and `bastion_lpi_`.
- L6 (evidence, parent, read-only): at start the tree had no `uninstall.php`; `master` was clean at `ae843e4` except six withdrawn `core-integrity-*` documents, which stayed untouched.
- L7 (decision, parent): the four rejected pending points (real-WP matrix on PHP 8.1–8.3, behavioural smoke of the REST panel and alert result, WooCommerce init noise) remain open follow-ups, not part of this feature.
- L8 (evidence, verifier): `wp-admin/includes/plugin.php` defines `WP_UNINSTALL_PLUGIN` and includes `WP_PLUGIN_DIR . '/' . dirname($file) . '/uninstall.php'`, and loops over no sites, which is why the entry at the plugin root and the per-site scope statement are both correct.
- L9 (correction, parent): three verifier findings corrected and pinned before the commit; the fourth item (the shared namespace with the sibling `wc` package) recorded as an open follow-up instead of an in-scope change.
- L10 (verbatim, user): "dale" — proceed with the corrections to the actionable advisory findings, which is the new candidate T8 contains.
