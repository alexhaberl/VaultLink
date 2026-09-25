# v0.7.2 native-package release checklist

Status: **unreleased development**. VaultLink 0.7.1 remains the supported,
immutable release. [`release/release-state.json`](../release/release-state.json)
is authoritative for lifecycle state. This checklist and the
[qualification ledger](../release/qualification-0.7.2.json) track work for the
next candidate; no final candidate or release date has been selected.

The [0.7.1 checklist](RELEASE-CHECKLIST-0.7.1.md) and its publication evidence
remain historical records. The comparative 19-metric performance test is retired
for this release under the [performance policy](../release/performance/README.md).
The full-load and soak requirements still apply.

## Prepare build inputs and freeze

- [ ] Review changes since v0.7.1, including schema 11 and 12 migrations,
  NixOS 26.05 support, the OCI runtime image, Cargo.lock, and all build inputs.
- [ ] Complete any required builder, QEMU, and nine-guest image refreshes before
  qualification. A Dockerfile frontend change requires all eleven images.
  Verify provenance, architectures, package inventories, generated manifest,
  all four QEMU locks, and the Debian-amd64 signing-image pin. Review and merge
  the pin PR before the final candidate is frozen.
- [ ] Finish source, documentation, version, and pin changes. Record the exact
  `main` commit and package, binary, builder, guest, and orchestration hashes.
  Treat any subsequent commit as a new candidate.
- [ ] Review and resolve open findings in the
  [0.7.2 ledger](../release/qualification-0.7.2.json), with a fresh audit of the
  committed Cargo.lock. Keep final qualification evidence tied to one commit.

## Qualify the exact candidate

- [ ] Run native amd64/arm64 CI, nine packages, and both complete fuzz campaigns.
  Run the NixOS and Docker amd64/arm64 gates for the same commit.
- [ ] After packages pass, run reproducibility and distro VMs. After native,
  package, and fuzz gates pass, run the release dry run, then candidate preflight.
  Validate each gate's workflow path, event, successful conclusion, and commit.
- [ ] Install the final Debian-amd64 package on the staging VM. Match its payload,
  running executable, health version, service unit, and all seven orchestration
  files to the frozen commit. Verify at least eight CPUs, 16 GiB provisioned RAM
  and at least 15 GiB Linux MemTotal, storage, quotas, and preserved archives.
- [ ] Start the 72-hour soak through `soak-start.yml` only after its exact gates
  and fresh audit pass. Enable the collector and verify the active VM monitor,
  commit, binary SHA, and start/end times.
- [ ] Collect at least 72 hours and twelve 100/40/10 profiles. Verify p95 under
  two seconds, RSS bounds, transfers and hashes, SQLite integrity, and zero
  restarts. Run the collection audit and final evidence preflight.

## Publish only after qualification

- [ ] Keep `main` frozen through qualification. A commit, including a date or
  documentation change, requires fresh gates and a new 72-hour soak.
- [ ] Verify the signed tag and nine native packages plus required release
  assets against the exact commit. Run the final audit immediately before
  publication and record the publication receipt. Publish the OCI image only
  through its follow-on workflow and verify public multiarch pulls.
- [ ] After publication is verified, update the supported-version status and
  installation guidance without rewriting the frozen candidate evidence.
