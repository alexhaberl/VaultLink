# v0.7.1 native-package release checklist

Status: unreleased preparation. **Target publication date: 2026-09-22 (UTC).**
This is a planned date, not a publication record or a qualification result.
[`release/release-state.json`](../release/release-state.json) is authoritative.
The candidate has its own [qualification ledger](../release/qualification-0.7.1.json)
and [finding inventory](../release/qualification-findings-0.7.1.json).
The published 0.7.0 evidence and assets remain historical records.

## Scope and current blockers

The release includes the rustls 0.23.45 handshake-validation fix from
`5ed3535f95c741af031205c39825c7a2ce860ef0` and the dependency/build-tool updates
merged since the immutable 0.7.0 package commit
`0af4612bd3c32a995b19de4cd19ca05ac4fd4855`. Schema 10, the target matrix,
signing key, native-package layout, and application feature contracts remain
unchanged. The [security notice](../SECURITY.md#pending-tls-security-release)
explains the difference between the patched source and published binaries.

**QUAL-001** records the maintainer's 2026-09-17 decision to retire the
comparative 19-metric performance test for every release from 0.7.0 onward.
No baseline lock, comparative measurements or `vaultlink/performance` receipt
is required or claimed. See the [performance policy](../release/performance/README.md).

**QUAL-006** remains open: re-run the native, nine-target package, fuzz,
reproducibility, full-system VM, CIFS/load, and full 72-hour soak qualification
against the final candidate. Previous-release or different-commit success is
insufficient.

For publication on Tuesday 22 September, plan to complete the image refresh,
freeze the candidate, finish its prerequisite gates,
and start the soak by Friday 18 September where possible. A Saturday
19 September start leaves only the corresponding time on Tuesday plus the
remaining UTC publication window for collection, evidence verification and
signing. Any failed gate or candidate change can move the release date.
Commit a changed date before freezing a new candidate; editing the date after
the soak creates a different commit and requires fresh qualification.

## Prepare and freeze the candidate

- [ ] Review all changes since v0.7.0, including Cargo.lock and pinned build
  tooling. Confirm rustls is at least 0.23.45 and the lockfile contains no new
  unaccepted advisory. The existing constrained RSA exception remains the
  only reviewed audit exception.
- [ ] Verify the immutable builder, VM, QEMU and Arch snapshot locks with
  `python3 tools/package-targets.py validate`. The Dockerfile frontend changed
  to 1.27.0 in PR #208; complete the corresponding builder, QEMU and nine-guest
  refresh and review the generated pins under the
  [image refresh procedure](../release/README.md#refresh-procedure) before
  freezing. Update the signing-image variable to match the new manifest.
  Static lock validation alone does not prove that refresh has happened;
  do not change locks during qualification.
- [ ] Confirm that QUAL-001 records the accepted retirement decision and
  QUAL-006 remains open for real final-candidate qualification.
- [ ] Keep `development_version=0.7.1`, its status `unreleased`, Cargo.toml,
  Cargo.lock, package names and the dated changelog consistent. Keep 0.7.0's
  immutable release records intact until the post-publication transition.
- [ ] Run version consistency, supply-chain policy, Actionlint, format,
  Clippy, locked tests, coverage, dependency audits and security regressions.
- [ ] Retain the source-level contracts from the 0.7.0 checklist: schema-1
  through schema-9 migrations to 10, service-token authentication/redaction,
  required audit, admission limits, stream/ZIP bounds and package recovery.
  A copied closed source finding does not certify fresh runtime measurements.
- [ ] Freeze one reviewed main commit with the final date. All package,
  binary, build-input and orchestration identities must remain fixed.

## Exact-commit qualification

1. Run both native CI gates, both full thirteen-target fuzz campaigns,
   the nine native packages and their signed test-only update/recovery fixtures.
   The fixture upgrade is 0.7.1 to 0.7.2; the fixture is never a release asset.
2. Run the unsigned release dry-run, package reproducibility and all nine
   distro VMs. Validate the 50/20/5 native CI smoke and the full 100/40/10 VM
   workload, package operations, rollback and SELinux evidence. Native smoke
   latency remains strict; VM latency remains diagnostic. Neither substitutes
   for the full-load 72-hour soak.
3. Run the release candidate preflight. Only QUAL-006 may remain open;
   other open findings block it. QUAL-001 is accepted under the retirement
   policy. Do not treat candidate preflight as
   permission to publish.
4. Update the dedicated Debian 13 amd64 soak host with the candidate package,
   service unit and all seven orchestration files from the frozen commit,
   following [SOAK-RUNNER.md](SOAK-RUNNER.md). Record the extracted payload hash
   and verify the running executable, orchestration hash and health version
   0.7.1. Keep the 8-vCPU/16-GiB resource requirement.
5. Start the soak only after the exact-commit prerequisite gates and a fresh
   audit of the candidate's committed Cargo.lock pass. Run the entire 72 hours
   with at least twelve full load profiles, strict p95 below two seconds,
   unchanged RSS bounds, complete transfers, SQLite integrity and no restarts.
   Audit the same candidate again during collection.
6. Run final evidence preflight against the same package and binary. Re-fetch
   and verify the complete soak artifact, and archive effective qualification
   externally. Its schema-v2 report records the performance retirement with
   a null performance receipt. Do not commit closed measurement flags or
   generated results after the soak.

## Publish only after all gates pass

- [ ] Confirm the frozen candidate is still current main and the UTC date
  matches the committed 2026-09-22 changelog heading. If either changed,
  stop and prepare a new candidate instead of bypassing the check.
- [ ] Create the signed annotated `v0.7.1` tag at that exact commit only after
  all eleven required release gates are successful.
- [ ] Let the protected workflow assemble and verify exactly 21 assets:
  nine native packages, nine direct signatures, the SBOM bundle,
  `SHA256SUMS` and its signature. Re-download and verify the draft assets.
- [ ] Pass the final fresh dependency audit immediately before publication.
  Audit/database/network failures must leave the release a draft.
- [ ] Confirm the public release is stable, non-draft, immutable and selected
  by GitHub's `/releases/latest` endpoint. Never overwrite the v0.7.0 tag/assets.

## After verified publication

- [ ] Record the actual signed tag object, commit, publication timestamp,
  immutable asset inventory and all eleven required gate run URLs in
  `release/release-state.json`. Mark 0.7.1 supported and 0.7.0 superseded;
  do not invent those records in this preparation PR.
- [ ] In a subsequent documentation change, switch README, SECURITY,
  installation commands, package references and API/runtime examples to the
  verified release. Resolve the pending security notice and record the actual
  publication date. Preserve the pre-publication qualification ledger.
- [ ] Run `python3 tools/verify-supported-release.py --repository alexhaberl/VaultLink`
  against the new lifecycle state and live GitHub evidence.
- [ ] Verify existing 0.6.0 and 0.7.0 installations discover 0.7.1, and test
  the signed package upgrade, configuration/schema-10 preservation, runtime
  parity and authenticated recovery. Retain older signed packages because
  the updater needs them for rollback; documentation alone does not alter
  the release selected by already-installed updaters.
