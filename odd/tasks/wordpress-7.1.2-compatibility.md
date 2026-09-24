# WordPress 7.1.2 isolated CI verification

## Authority and scope at the compatibility phase

User authorized test changes, a branch/draft PR and isolated GitHub CI (`verify_wp712_in_isolated_github_ci`), then explicitly permitted a normal PR without adopting the global approved-issue/template/label scheme. At that stage, no merge or release was authorized. Subsequent authorization and publication are recorded in [release 0.3.0](release-0.3.0.md). Local tests, PHP, Composer, builds, installations, WordPress and database execution remain prohibited. Preserve the local site, accepted ZIP, unrelated dirty README/config/exploration and historical untracked documents. CoreIntegrity remains withdrawn.

ODD, not SDD. Parent owns this file and full Engram mirror5281 (`odd/wordpress-7.1.2-compatibility/tasks`). Base: `340547edfdb2f9116fb440a292b9859d1830174f`. Branch: `ci/wordpress-7.1.2-compatibility`. PR at phase completion: https://github.com/carlose119/cerrojo-security-toolkit/pull/1 (base master, then OPEN and draft/unmerged).

Reuse existing PHP8.4/MariaDB/WordPress/WooCommerce integration and archive validation. Verify activation, administrator dashboard PHP rendering and representative observable controls. No production behavior changes without a proven incompatibility and separate authorization. This is not browser/HTTP/proxy/CDN or exhaustive compatibility certification.

## Checks and delivery

Strict TDD is ON from `openspec/config.yaml`. Configured `composer test`, `composer check` and `composer syntax` may execute only in GitHub. This is a test/infrastructure change to existing behavior: write smoke assertions before changing the target fixture; do not fabricate production RED evidence. Local Git diff/read/hash checks are permitted. Runtime smoke must execute in the isolated CI fixture after plugin activation and report an explicit success marker.

Strategy: ask-on-risk; one PR forecast at approximately100–250 authored additions/deletions, with400 as the delivery planning threshold. Keep coherent tests with workflow changes; no artificial splitting or line shrinking. Each implementation task records its work-unit commit and checks. Native review is candidate-scoped; unavailable review requires independent verification, not invented approval.

## Tasks and evidence

- [x] C1 — Derive the official archive SHA-256 in GitHub without extraction/execution. Delegated writer `mueqt9bs-n-pob8`; commit `68ce562ce939049b1dc6a7ddea4cccfb34e4e86b` adds20 workflow lines only. Writer/parent diff checks passed and four protected hashes matched. Native assessment was unassessable (untracked scope); fresh committed-range START failed `candidate-target-projection-drift` before lineage/mutation. No repair or approval claimed. Independent verifier `mueqxskj-o-50r6` passed the exact structural change. Published draft PR1. External verifier `muer2rpk-p-54vv` confirmed all6 jobs passed in run35935039881 at exact68ce562. Parent reread checksum job107430060593 logs; SHA-1 check and actual SHA-256 output matched. Existing integration in this run still used7.0.4, not7.1.2.
- [x] C2 — Add bounded smoke assertions, pin WordPress7.1.2 plus the observed SHA-256, remove temporary checksum discovery, and execute CI. Delegated writer `muer9tel-q-h9s9` prepared workflow plus a93-line `tests/Integration/WordPressSmoke.php`; FixtureLifecycle stayed unchanged. Commit `8b19b00b605743fcef8eca54ca3c47e8733109bb`, parent68ce562:98additions/22deletions in2paths. Static diff checks and four protected hashes passed; final runtime evidence is recorded below. Smoke covers activation/bootstrap,13 registered diagnostics,4 dashboard tabs and disabled/enabled header/pingback filters, restoring two options. No local execution. Native C2 assessment/START again failed before authority creation (untracked scope/projection drift). Independent verifier `muerircw-r-men8` blocked publication: dashboard rendering needs the admin template helpers, including `submit_button()`. Parent made one mechanical harness-only correction in commit `2d4360f51a53f3b8d07a9e8f6d0dc636ecf1457e`: explicitly require `wp-admin/includes/admin.php` instead of only `plugin.php`. Its static diff check passed; native correction review remained unavailable before authority creation. Targeted verifier `muerpz9s-s-zeuo` passed the exact correction; parent then published C2 and its fix to the existing draft PR. External verifier `mueru38b-t-otau` confirmed the final runtime PASS below.
- [x] C3 — Independently inspect final CI results and exact source scope; report measured coverage and limits in PR/local record. All five GitHub checks attached to PR1 passed at exact final head. Parent reread run metadata, timestamped execution markers, PR draft state and all four protected hashes. At phase completion, the PR was draft/unmerged, with no release or production edits.

## Archive provenance

Official release: https://wordpress.org/documentation/wordpress-version/version-7-1-2/ (2026-09-22). ZIP: https://downloads.wordpress.org/release/wordpress-7.1.2.zip.

Published SHA-1 from https://wordpress.org/wordpress-7.1.2.zip.sha1: `fab6ce3a905a1f4085ffff7fd9920bc693f5dd94`. No official SHA-256 endpoint was verified (WordPress.org `.sha256` returned an oversized archive response; downloads `.sha256` returned404). CI verified the published SHA-1 before deriving SHA-256: `8fc96c59a78b7219e4a130222b7fadb51b03e503e8b0123beaa7e28961c21ce2`.

Evidence: https://github.com/carlose119/cerrojo-security-toolkit/actions/runs/35935039881/job/107430060593. This digest identifies downloaded bytes, not plugin compatibility; integration must retain SHA-256 verification before validated extraction.

## Preservation baseline and rollback

SHA-256:
- `README.md`: `13d0b0967c4d9404a224f255f80e2d2c9d3dcf644d587e6fc53eb83fd8fbadc7`.
- `openspec/config.yaml`: `e87e661761023bda09f398cca19a78d066c1fb9681b731db0477189cdd93dc85`.
- `openspec/changes/core-integrity-checker/exploration.md`: `9455d279f2cb19782d8743f6fe3c6d5b5ba793b175283f8ec9962bf3e78d7873`.
- `.build/cerrojo-security-toolkit.zip`: `4ed1f774b39d71bec675b6d2272f078200e09d0801e2f8f6dc46fb48976b52dc`.

Rollback boundary is this feature's workflow/smoke commits only; reverting requires separate authorization. Never reset, clean or stash unrelated work. This phase did not authorize committing local task/history documents or the ZIP. Later documentation-commit authorization does not include the protected ZIP.

## Current state

C1–C3 are complete. The compatibility phase ended at `2d4360f51a53f3b8d07a9e8f6d0dc636ecf1457e`, with cumulative work-unit scope of142 authored lines and only the workflow/93-line smoke fixture in its net PR diff. Subsequently, the user authorized release preparation, merge and publication. PR #1 was merged into master at `7fdf3543479f8554a9c7f9f84a5cda33a47f3897`; version0.3.0 is published and verified on GitHub and WordPress.org (SVN r3710374). See [the release record](release-0.3.0.md) for the later commits, final CI and download verification. Historical phase authorizations and preservation hashes above are not new implementation authority.

## Final runtime evidence and limitations

Run https://github.com/carlose119/cerrojo-security-toolkit/actions/runs/35936770677 completed SUCCESS at exact head2d4360f; all5 jobs passed. External verifier and parent independently read actual timestamped execution output, not echoed shell commands:
- 00:06:56Z: `wordpress.zip: OK` (pinned SHA-256 verified).
- 00:06:59Z: `BASTION_WP_INSTALL_OK: WordPress installed`.
- 00:07:01Z: `BASTION_WP_712_SMOKE_OK: activation, dashboard and representative controls passed`.
- 00:07:03Z: `BASTION_WC_COMPAT_OK: inventory assertions passed`.

Each PHP8.1–8.4 unit job reported280 tests/2522 assertions; audit and syntax steps succeeded. Filtered logs had no fatal/uncaught/warning matches; the runner-image migration annotation was informational. No tests or builds ran locally; all four protected hashes matched at compatibility-phase completion.

Measured integration coverage is WordPress7.1.2 on PHP8.4 with MariaDB and WooCommerce11.0.1: activation/bootstrap,13 registered diagnostics,4 CLI-rendered dashboard tabs, disabled/enabled header and XML-RPC pingback filters, restored settings and WooCommerce REST inventory. Registration does not mean every diagnostic was executed. This does not establish browser, real HTTP-edge, proxy/CDN, every control, or WordPress integration on PHP8.1–8.3. No incompatibility was observed within this scope, and no production plugin change was needed. Native review remained unavailable; independent structural checks and observed CI results are not a native approval.
