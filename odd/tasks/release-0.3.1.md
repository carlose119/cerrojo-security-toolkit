# Release 0.3.1 — complete

WordPress 7.1.4 declaration plus the 0.3.1 release, published to GitHub and to the WordPress.org SVN. Every acceptance check below was observed, not inferred. Delivery commands were human-run because the Pi RDD pre-delivery guard fails for provider defect #6156.

## Specs

- S1: "dale y tambien quiero subir los cambios al svn de wordpress"
- S2: "Merge commit de PR #2, después rama de release"
- S3: "Completo: GitHub release + SVN trunk + tag 0.3.1"
- S4 (constraint already in the repository, README.md Build): the preserved `.build/cerrojo-security-toolkit.zip` must not be overwritten in this checkout; build and validate an extracted production artifact, never the development checkout.
- S5 (constraint already in the repository, readme.txt): a changelog entry is historical record. The published 0.3.0 entry keeps its "Verified integration smoke on WordPress 7.1.2 with PHP 8.4." line unchanged; the 7.1.4 verification belongs to the new 0.3.1 entry.

## Tasks

- T1 — Feature document and tracked todo list. Route: parent, inline. Commit: none (bookkeeping).
- T2 — Merge PR #2 with a merge commit, then branch `release/0.3.1` from the updated master. Route: human (RDD delivery guard blocks the parent). Commit: merge commit on master.
- T3 — Bump the plugin to 0.3.1 test-first: header `Version`, readme `Stable tag`, new `= 0.3.1 =` changelog entry stating the 7.1.4 verification, `EXPECTED_VERSION` and the changelog assertion in `WordPressOrgMetadataTest`. Route: parent, inline. Commit: one work unit on `release/0.3.1`.
- T4 — Build the production ZIP from an isolated copy of the exact release tree and verify it, recording bytes, entries and SHA-256. Route: parent, inline, outside the checkout. Commit: none (artifact evidence).
- T5 — Stage the WordPress.org SVN working copy: trunk content replaced with the built artifact, `tags/0.3.1` copied from trunk, `svn status` reviewed. Route: parent, inline, outside the checkout. Commit: none (staged for the human commit).
- T6 — Human delivery: merge PR #2, merge the release branch, publish GitHub release v0.3.1 with the asset, then the authenticated SVN commit of trunk and tags/0.3.1. Route: human. Commit: remote operations.
- T7 — Verify the published state read-only: release asset SHA-256, SVN revision and exported tree equality, public version and download. Route: parent, inline.

## Log

- L1 (verbatim, user): "dale y tambien quiero subir los cambios al svn de wordpress"
- L2 (decision, user): merge commit of PR #2, then a release branch created from the updated master.
- L3 (decision, user): publish completely — GitHub release plus SVN trunk and tags/0.3.1.
- L4 (evidence): `gh pr merge 2 --merge` was refused by the Pi pre-delivery guard with "Native preflight is unavailable; resolve it before delivery." Same provider defect as Gentle AI #6156, already reported. No merge, push or release was performed by the parent; the merge was not retried.
- L5 (evidence): remote `plugins.svn.wordpress.org/cerrojo-security-toolkit` lists `assets/`, `trunk/`, `tags/0.2.2/`, `tags/0.3.0/`; local `svn` is 1.14.5; `.svn-staging/{trunk,tags}` are plain directories, not a working copy, and are preserved untouched.
- L6 (T3 evidence): RED observed before the fix — 3 failures (`testPublicPluginHeaderUsesWordPressOrgIdentity`, `testReadmePublishesRequiredWordPressOrgMetadata`, `testReadmeStartsChangelogWithCurrentRelease`) at `WordPressOrgMetadataTest.php:23,39,51`. GREEN after updating `EXPECTED_VERSION` and the changelog assertion: 281 tests, 2524 assertions, PHP 8.4.4; `tools/check-syntax.php` clean; `composer validate --strict` valid. Commit `306e61a`, 3 files, +9/−4, no runtime change.
- L7 (T4 evidence): `tools/build.php` begins with `removeTree($build)`, so it destroys `.build/` wholesale. Building in this checkout would delete the preserved historical 0.2.2 archive, so the build ran from an isolated copy at `%TEMP%`. First attempt used `git archive` and produced a CRLF `LICENSE` (Windows `core.autocrlf`), failing `PackagingTest:149` on an environmental artifact, not a packaging defect. Rebuilt from a `core.autocrlf=false` export: 45 files, 90419 bytes, SHA-256 `3b84436fe3e0ec07481ae2cdcc648617429d1b274c5354a36a9298001f739b6a`, `PackagingTest` 9 tests / 713 assertions PASS, packaged metadata `Version 0.3.1`, `Stable tag 0.3.1`, `Tested up to 7.1.4`.
- L8 (T5 evidence, rehearsal only): a depth-immediates checkout of the SVN root at r3806222 plus infinite update of `trunk` holds exactly 45 files — the same file set as the artifact, so no adds or removals, only 5 content modifications (`cerrojo-security-toolkit.php`, `composer.json`, `readme.txt`, `vendor/composer/autoload_static.php`, `vendor/composer/installed.php`). All 45 staged files are byte-identical to the local artifact.
- L9 (decision, parent): the two `vendor/composer/*.php` differences are Composer-generated and environment-dependent. SVN `trunk` and the GitHub release asset must therefore be staged from the **CI-built** artifact (`Upload production package`, name `cerrojo-security-toolkit-<sha>-<attempt>`), which is the Linux-built canonical one and the same evidence standard 0.3.0 used (45/45 byte-identical). The local Windows build is local verification only.
- L10 (open): delivery remains blocked for the parent by the same provider defect. Pushing `release/0.3.1`, creating and merging its PR, `gh release create`, and both authenticated `svn commit` calls are human steps.
- L11 (evidence, human delivery of the merges): PR #2 merged as `896c6d3` and PR #3 merged as `497d5c5`; `origin/master` = `497d5c5`. Parent verified read-only; the parent performed no delivery.
- L12 (evidence, T9): CI run `43975054825` at `497d5c531d928c6fbb0095103b01b32d71e80923` concluded `success`. Artifact `cerrojo-security-toolkit-497d5c5…-1` (id `14280826472`) downloaded by the parent: `cerrojo-security-toolkit.zip`, 89952 bytes, SHA-256 `e79a63dcb6196415515796ade03eaaf233111e988d21ca59361aa807e6456a43`. Packaged metadata confirmed `Version 0.3.1`, `Stable tag 0.3.1`, `Tested up to: 7.1.4`, 45 files.
- L13 (evidence): artifact content compared against the `origin/master` tree — 33 packaged tracked files compared, exactly 1 mismatch (`composer.json`), which is the documented production-manifest rewrite (`942` → `368` bytes). No source drift between the reviewed tree and the published artifact.
- L14 (evidence, SVN restaged from CI artifact): trunk staged with the CI artifact is 45/45 byte-identical to it and shows exactly 3 modifications against r3806222: `cerrojo-security-toolkit.php`, `readme.txt`, `vendor/composer/installed.php`. The earlier Windows-build staging showed 5 modifications; the 2 extra were Composer-generated files, confirming that only the CI artifact is the correct SVN source.
- L15 (open): remaining human steps are `gh release create v0.3.1` with the CI artifact and the two authenticated SVN commits from the staged working copy at `%TEMP%\gp36rYPO\bastion-svn-031-97N2Vq`. Both SVN commits must run back to back: between them the directory advertises `Stable tag: 0.3.1` with no matching tag.
- L16 (evidence, published): GitHub release `v0.3.1` is published (not draft, not prerelease) at target `497d5c531d928c6fbb0095103b01b32d71e80923`, asset `cerrojo-security-toolkit.zip`, 89952 bytes, digest `sha256:e79a63dcb6196415515796ade03eaaf233111e988d21ca59361aa807e6456a43` — identical to the CI artifact.
- L17 (evidence, SVN): `r3806232` modifies exactly `trunk/cerrojo-security-toolkit.php`, `trunk/readme.txt`, `trunk/vendor/composer/installed.php`; `r3806233` adds `/tags/0.3.1` from `/trunk:3806232`. Both authored by `carlose119`.
- L18 (evidence, exports): exports at those revisions hold 45 files each, with **0 mismatches** against the CI artifact for both trunk and `tags/0.3.1`. Published tag metadata: `Stable tag: 0.3.1`, `Tested up to: 7.1.4`, `Version: 0.3.1`.
- L19 (evidence, public): `api.wordpress.org/plugins/info/1.0/cerrojo-security-toolkit.json` reports `version 0.3.1`, `tested 7.1.4`, `requires 6.8`. Public download `cerrojo-security-toolkit.0.3.1.zip` returns HTTP 200, 91360 bytes, container SHA-256 `34c8872b0e6259490864d6922b96682e1862d587d675f234306f65db122494c9` (a different container hash is expected; WordPress.org repackages), and its 45 extracted files are **byte-identical** to the CI artifact with 0 mismatches.

## Outcome

`Tested up to: 7.1.4` is now published and backed by an observed CI smoke run on WordPress 7.1.4 with PHP 8.4. No runtime code changed across the whole release. Not claimed: browser, proxy/CDN edge, every-control or non-7.1 WordPress coverage; those remain outside this evidence.
