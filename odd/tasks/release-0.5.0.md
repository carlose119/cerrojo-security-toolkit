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

- T1 — Bump the four version pins and add the `= 0.5.0 =` changelog entry. Route: parent. Commit —
- T2 — Run the full suite, syntax, package build and `package:verify`. Route: parent. Commit —
- T3 — Push the release commit and observe CI on `master`. Route: human (Pi's pre-delivery guard blocks the push). Commit —
- T4 — Tag `v0.5.0` from the CI-built artifact commit. Route: human, for the same reason. Commit —
- T5 — GitHub release with the CI artifact as the asset. Route: parent if the guard allows, otherwise human. Commit —
- T6 — Stage the SVN working copy from the same artifact. Route: parent. Commit —
- T7 — The two SVN commits (trunk, then the tag). Route: human, per S3. Commit —
- T8 — Verify the published state read-only and record it here. Route: parent. Commit —

## Progress and evidence

- T1: `cerrojo-security-toolkit.php:6`, `readme.txt:6`, `readme.txt` changelog head and `tests/Unit/WordPressOrgMetadataTest.php` moved to 0.5.0 together; the changelog entry lists the uninstall cleanup and its limits.
- T2: 405 tests / 3504 assertions green before the bump; re-run after it.
- Open follow-ups from the native review of the feature, deliberately not part of this release: the `$wpdb` guard could inspect `last_error` after the option deletions instead of documenting that a failed `delete_option()` is indistinguishable from an absent row; `CAST(... AS BINARY)` gives up the `option_name` index and is deprecated on MySQL 8.0.17+, so a future release should exercise the MySQL 8.4 matrix for the deprecation note.

## Log

- L1 (verbatim, user): "si dale" — prepare the release after the post-merge defects were fixed.
- L2 (verbatim, user, earlier): "corrige el defecto 1" — the duplicate-copy defect, fixed in `5eb9682` before this release.
- L3 (evidence, parent): the published readme on WordPress.org comes from the tagged release, so the new FAQ sentence reaches users only with this release. Nothing is publicly inconsistent until then.