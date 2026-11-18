# Release 0.5.0 — preparation

The uninstall cleanup is on `master` but no published version carries it: `Stable tag` still reads 0.4.0 and the changelog ends at that entry, while the readme FAQ already describes behaviour only `master` has. This release makes the published artifact match.

Risk: item 5 (delivery and release) — the tag, the GitHub release and the two WordPress.org SVN commits are the user's, and the SVN credentials are never handled by the agent.

## Specs

- S1 (verbatim, user): "si dale" — prepare the 0.5.0 release.
- S2 (decision, parent, accepted by the user): 0.5.0 rather than 0.4.1, because uninstall cleanup is a new capability and not a fix.
- S3 (constraint, provider): `svn commit` requires the site owner's WordPress.org credentials. The agent must never request, store or handle that password, so the SVN commits stay human-run.
- S4 (constraint, repository): the canonical artifact is the one CI builds, never a local build, and the SVN trunk and tag must be byte-identical to it.
- S5 (constraint, repository): the version lives in four places that must move together — the plugin header, `Stable tag`, the first changelog entry, and `WordPressOrgMetadataTest::EXPECTED_VERSION` plus its changelog-shape regex.
- S6 (scope): no changelog entry for any other change, no version bump of any dependency, no packaging change beyond what the feature already required.

## Tasks

- T1 — Bump the four version pins and add the `= 0.5.0 =` changelog entry. Route: parent. Commit `3990136`.
- T2 — Run the full suite, syntax, package build and `package:verify`. Route: parent. Commit `3990136`.
- T3 — Push the release commit and observe CI on `master`. Route: human (Pi's pre-delivery guard blocks the push). Commit `9ae6c40`.
- T4 — Tag `v0.5.0` from the CI-built artifact commit. Route: parent, through the GitHub release. Commit `9ae6c40`.
- T5 — GitHub release with the CI artifact as the asset. Route: parent. Commit `9ae6c40`.
- T6 — Stage the SVN working copy from the same artifact. Route: parent. Commit `9ae6c40`.
- T7 — The two SVN commits (trunk, then the tag). Route: human, per S3. Commit —
- T8 — Verify the published state read-only and record it here. Route: parent. Commit —

## Progress and evidence

- T1: `cerrojo-security-toolkit.php:6`, `readme.txt:6`, `readme.txt` changelog head and `tests/Unit/WordPressOrgMetadataTest.php` moved to 0.5.0 together; the changelog entry lists the uninstall cleanup and its limits.
- T2: 405 tests / 3504 assertions green; `PackagingTest` 9 / 793; archive 51 files carrying 0.5.0 in both headers with `uninstall.php` inside; `tools/check-syntax.php` clean over 78 files.
- Native review of the release candidate: lineage `review-a5360d464f926e04`, lenses readability and reliability, approved and authority burned. One advisory, R2-1: this file ended without a trailing newline, corrected here.
- T3: pushed by the human as `9ae6c40`; CI run 44418239528 concluded success on that commit.
- T4/T5: release `v0.5.0` published at https://github.com/carlose119/cerrojo-security-toolkit/releases/tag/v0.5.0, target `9ae6c4068369baf06201472f782b499677f47f2f`, not a draft and not a prerelease. The asset is the CI artifact, not a local build: `cerrojo-security-toolkit.zip`, 110271 bytes, `sha256:536544d01f3d5b598bd71a9a75c09528b3c594b423e9d5fd5402344961444b29`, verified to carry 51 files, 0.5.0 in the header, `Stable tag` and changelog head, and `uninstall.php`.
- T6: trunk checked out at revision 3810386 into a temporary working copy and synchronised with that same artifact; `diff -r` against the artifact is empty. `svn status` shows exactly two additions (`uninstall.php`, `src/Uninstall.php`) and five modifications (the plugin file, `readme.txt` and three generated `vendor/composer` files that now list the new class).
- T7 and T8 remain open: the two SVN commits need the site owner's credentials, and the published WordPress.org state can only be verified after them.
- Open follow-ups from the native review of the feature, deliberately not part of this release: the `$wpdb` guard could inspect `last_error` after the option deletions instead of documenting that a failed `delete_option()` is indistinguishable from an absent row; `CAST(... AS BINARY)` gives up the `option_name` index and is deprecated on MySQL 8.0.17+, so a future release should exercise the MySQL 8.4 matrix for the deprecation note.

## Log

- L1 (verbatim, user): "si dale" — prepare the release after the post-merge defects were fixed.
- L2 (verbatim, user, earlier): "corrige el defecto 1" — the duplicate-copy defect, fixed in `5eb9682` before this release.
- L3 (evidence, parent): the published readme on WordPress.org comes from the tagged release, so the new FAQ sentence reaches users only with this release. Nothing is publicly inconsistent until then.
