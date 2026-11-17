# Release 0.4.0 — complete

User selected 0.4.0 after the REST exposure and alert honesty work. GitHub release and WordPress.org SVN are both published and independently verified against the CI-built artifact. The agent created the GitHub release; the two SVN commits were human-run because WordPress.org requires the site owner's credentials, which this project never caches.

## Specs

- S1 (verbatim, user): "0.4.0" — selected as the next release after the REST and alerting work, with four offered fronts on the table.
- S2 (verbatim, user): "ejecuta tu los comandos" — the agent attempts the delivery commands itself and reports what it cannot do.
- S3 (constraint, provider): `svn commit` requires the site owner's WordPress.org credentials. The agent must never request, store, or handle that password, so the two SVN commits remain human-run.
- S4 (constraint, repository): the canonical release artifact is the one CI builds, never a local build; the SVN trunk and tag must be byte-identical to it.

## Tasks

- T1 — Prepare the 0.4.0 bump test-first: header `Version`, `Stable tag`, a `= 0.4.0 =` changelog entry, and the metadata test pins. Route: parent. Commit `63606d0`.
- T2 — Fix the independent verification findings before tagging: exposure severity ordering, bounded alert timestamps, the unverifiable-record state. Route: two delegated writers with disjoint surfaces, parent review. Commits `c08b247`, `96b6458`, `0275fef`.
- T3 — Push and observe CI. Route: human push, parent read-only verification of the run.
- T4 — Download the CI artifact and verify it. Route: parent.
- T5 — GitHub release with the CI artifact as the asset. Route: parent (see L5).
- T6 — Stage the SVN working copy from the same artifact. Route: parent.
- T7 — The two SVN commits. Route: human, per S3.
- T8 — Verify the published state read-only and record it here. Route: parent.

## Log

- L1 (verbatim, user): "0.4.0"
- L2 (verbatim, user): "listo" — after the push and CI were confirmed green.
- L3 (verbatim, user): "ejecuta tu los comandos" — the agent ran the delivery commands instead of handing them over.
- L4 (evidence, CI): run `43997026146` at `0275fef8a0c678326cad7ad36392b693a92ffd46` concluded success with five jobs: `test (8.1)`, `test (8.2)`, `test (8.3)`, `test (8.4)`, `woocommerce-compatibility`.
- L5 (evidence, agent-run delivery): `gh release create` succeeded. Unlike `git push` and `gh pr merge`, this command was **not** refused by the Pi pre-delivery guard. Release `v0.4.0` is published, not draft and not prerelease, targeting `0275fef`, with asset `cerrojo-security-toolkit.zip`, 105498 bytes, digest `sha256:18710d73aba0a3be99923a79c31cdfd93172e6cde31d380038bef44c3b03bb9b` — identical to the CI artifact.
- L6 (evidence, the one thing the agent could not do): `svn commit trunk -m "Release 0.4.0" --non-interactive --no-auth-cache` failed with `E215004: Authentication failed and interactive prompting is disabled`. Nothing was committed, trunk stayed at r3806372 and the staged working copy kept its 17 pending entries. The credential was never requested.
- L7 (evidence, SVN, human-run): `r3806375` modifies exactly 17 trunk paths — 4 added (`src/RestExposureClassification.php`, `src/RestSurfaceDelta.php`, `src/RestSurfaceSnapshot.php`, `src/Admin/RestExposurePanel.php`) and 13 modified, including the three alert policies, the three alert admins, the inventory, the dashboard, the plugin header, the readme and three generated `vendor/composer` files that now list the new classes. `r3806376` adds `/tags/0.4.0` from `/trunk:3806375`. Both authored by `carlose119`.
- L8 (evidence, exports): exports at those revisions hold 49 files each, with **0 mismatches** against the CI artifact for both trunk and `tags/0.4.0`. Published tag metadata: `Stable tag: 0.4.0`, `Tested up to: 7.1.4`.
- L9 (evidence, public): `api.wordpress.org` reports `version 0.4.0`, `tested 7.1.4`, `requires 6.8`. `cerrojo-security-toolkit.0.4.0.zip` returns HTTP 200, 106978 bytes, container SHA-256 `3f1bd72d4cf4767cd0c9408e2447c334708674a38e29694142af8ebbfe3c5645` (a different container hash is expected because WordPress.org repackages), and its 49 extracted files are byte-identical to the CI artifact with 0 mismatches.

## Outcome

0.4.0 ships structural REST permission-callback exposure findings with a baseline surface diff, and the observed result of the most recent alert send cycle. Every pin moved in lockstep, the artifact is the CI one on both destinations, and the public download matches it file by file.

Independent verification before tagging found a real security defect the implementers' own tests had missed: severity ranked `opaque` below `denied`, so a route registered twice could be reported as closed while WordPress would dispatch the permissive handler. It is fixed and pinned by regression tests.

Not claimed: delivery of any email, authorization quality of any callback, truth of any permission decision, coverage beyond the registry visible in one request, or behaviour under a proxy, cache, CDN or edge. The new features were verified by unit tests and one independent source review; no live-WordPress smoke exercised the exposure panel or the alert outcome line.
