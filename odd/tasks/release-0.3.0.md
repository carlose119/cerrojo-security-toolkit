# Release 0.3.0 — complete

User explicitly authorized merge, GitHub release and WordPress.org publication and selected 0.3.0. Both destinations are published and independently verified. Parent owns this ODD document/full Engram mirror5285/todo. No further publication action is pending.

## Completed tasks

- [x] A1: GitHub browser authentication completed by user; inherited environment-token overrides excluded for agent commands.
- [x] R1: Test-first metadata and CI package preparation, commits `996c283` and `9ab70eb`, independently verified.
- [x] R2: PR #1 merged, final master CI/package verified, GitHub v0.3.0 published with exact tag/artifact.
- [x] A2: User completed secure interactive SVN commit, confirmed as r3710374 by carlose119.
- [x] R3: Pinned remote SVN trees, public WordPress.org version/page/download and all production file contents verified.

## GitHub and CI evidence

Repository `carlose119/cerrojo-security-toolkit`. RED commit `996c28320c0919cf3080bada2a799c76cc7b0ef1`, run35938573309: three expected metadata failures per PHP job. Implementation `9ab70ebb49a3f302be1cbb685a74100f633c0e45`, PR run35941232281: five jobs PASS. PR scope +136/-7 across five files; no new production runtime logic in this PR.

PR https://github.com/carlose119/cerrojo-security-toolkit/pull/1 merged into `7fdf3543479f8554a9c7f9f84a5cda33a47f3897`. Merge and reviewed head share tree `6dacf083b1ceb4fbb575e898eb940c1acf332b31`.

Final master CI https://github.com/carlose119/cerrojo-security-toolkit/actions/runs/35941756547 passed five jobs: PHP8.1–8.4 each281tests/2524assertions, clean audit/syntax, actual WordPress7.1.2/PHP8.4.26/WooCommerce smoke and inventory. Strict TDD was ON. Independent artifact/source/preservation verification passed.

Release https://github.com/carlose119/cerrojo-security-toolkit/releases/tag/v0.3.0 (ID395213483) is published, not draft/prerelease. Tag and target are exact merge commit7fdf354. Asset584911337 `cerrojo-security-toolkit.zip`:89901bytes; server/CI/local SHA-256 `092f1c750a9ab3b75e2878d44e5e4e22463f859382c77e3a0afbbda8681474a8`.

## WordPress.org publication evidence

Independent verifier `muevhve5-13-dwp8` confirmed **r3710374**, author `carlose119`, timestamp `2026-09-24T01:45:19Z`, message `Release 0.3.0`. Commit scope: six trunk modifications plus new tags/0.3.0 copied from trunk@3710368 with the same six modifications. Assets and older tags were untouched. Working copy is clean and without remote drift.

Both remote trunk and tags/0.3.0 were exported at pinned r3710374:45/45 files byte-identical and SHA-identical to the final master ZIP, no extras, metadata0.3.0/Tested up to7.1.2, no SVN properties altering export.

Public API reports version0.3.0. Page https://wordpress.org/plugins/cerrojo-security-toolkit/ and download https://downloads.wordpress.org/plugin/cerrojo-security-toolkit.0.3.0.zip returned HTTP200. Public ZIP:91309bytes, SHA-256 `50b4e8f551023cc7b44cf2450fd40838a166a71479c314239d9ad62d12d15a59`; CRC/safe paths verified. Its53 entries comprise45 files plus8 directories; all45 file contents match the GitHub/master artifact. Different ZIP container hashes are expected and do not indicate file-content drift.

## Constraints, failures and preservation

No local PHP, Composer, test suites, builds, installs, WordPress/database or downloaded code execution occurred. Archive data inspection and SVN staging used isolated OS-temp directories only. Four protected project hashes matched at final verification; baselines are in `odd/tasks/wordpress-7.1.2-compatibility.md`. Existing local `.build/cerrojo-security-toolkit.zip` remains SHA-256 `4ed1f774b39d71bec675b6d2272f078200e09d0801e2f8f6dc46fb48976b52dc`.

Native review remained unavailable: candidate-target-projection-drift before lineage creation/mutation. No native approval or repair is claimed; independent verification and actual CI passed. The expected metadata RED was resolved by GREEN. GitHub workflow authentication and SVN authentication initially failed, then were resolved by secure user interaction. No secrets were exposed or credential stores inspected. No destructive cleanup, force pushes, old-tag replacement or blind commit retries occurred.

The external-temp writer launch was rejected before execution; parent mechanically transported verified archive bytes. An initial Python quoting SyntaxError ran no body, confirmed by clean SVN status before correction. User terminal paste errors were resolved with short semicolon-terminated PowerShell statements, explicit TortoiseSVN svn.exe and array-splatted flags. Password was entered only by the user, with no-auth-cache.

## State recorded at release completion

At release completion, the local Git branch was `ci/wordpress-7.1.2-compatibility`; origin/master had been fetched without checkout. Remote tag v0.3.0 was created through GitHub; do not infer remote release state from older local tags. README/config/exploration and historical files were still uncommitted and preserved. This is a historical release snapshot, not the current documentation-maintenance branch or authorization.

- Final GitHub archive and manifest: `C:/Users/carlo/AppData/Local/Temp/r2-master-artifact-u7sdshur/` (CI artifact10785052923).
- Clean SVN WC: `C:/Users/carlo/AppData/Local/Temp/cerrojo-svn-030-16NJxZ/wc`.
- Public WordPress archive: `C:/Users/carlo/AppData/Local/Temp/r3-published-116g8j82/public-cerrojo-security-toolkit.0.3.0.zip`.

All agents are settled. All task acceptance checks are complete; no publication or propagation checks remain pending. Browser/proxy/CDN/every-control certification and local runtime execution were outside scope. Future gh commands should use `env -u GITHUB_TOKEN -u GH_TOKEN` to avoid the inherited old PAT.
