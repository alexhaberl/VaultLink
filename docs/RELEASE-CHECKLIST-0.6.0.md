# v0.6.0 native-package release checklist

Status: unreleased. No release date is selected and no candidate commit is
frozen until every pre-soak gate below is green.

Goal: a signed, package-only GitHub release for the exact nine targets in
`release/package-targets.json`. Every checkbox is fail-closed release evidence;
a skipped, neutral, missing, stale, or wrong-commit result is not success.

## Withdrawal and compatibility boundary

- [x] The public `v0.5.0` GitHub release and all of its assets were removed on
  2026-08-25.
- [x] The annotated `v0.5.0` tag, target commit, workflow evidence, and
  historical [`RELEASE-CHECKLIST.md`](RELEASE-CHECKLIST.md) remain available.
- [x] README, changelog, security policy, and package documentation describe
  0.5.0 as withdrawn and unsupported.
- [ ] Confirm that no release, README, installer, updater, or documentation
  offers archive adoption or migration from 0.5.0 to 0.6.0.

## Immutable target provisioning

- [x] The secret-free `release-image-refresh` Environment was created on
  2026-08-25 with a custom deployment-branch policy restricted to `main`.
- [ ] Validate `release/package-targets.json` as the sole nine-target source:
  Debian 13 and Ubuntu 24.04/26.04 amd64/arm64, Fedora 44
  x86_64/aarch64, and release-snapshot Arch x86_64.
- [ ] Select and commit the Arch release snapshot date.
- [ ] Run the protected image-refresh workflow from reviewed `main`.
- [ ] Build and push every native builder image and every same-architecture
  QEMU guest image to GHCR.
- [ ] Verify fixed Rust version, complete target package closure, OS identity,
  package tools, boot assets, and native platform for every image.
- [ ] Review the generated manifest artifact in a separate pull request and
  replace every `UNPROVISIONED` value with a full immutable digest reference;
  commit the reviewed `qemu-runner-image.lock`,
  `qemu-runner-base-image.lock`, `qemu-runner-packages-amd64.lock`, and
  `qemu-runner-packages-arm64.lock` atomically in that same pinning PR and run
  the strict combined target/QEMU-lock validator.
- [ ] Set `VAULTLINK_PACKAGE_SIGNING_IMAGE` to the exact pinned Debian 13
  amd64 builder reference, verify the protected signing job's equality check,
  and then remove the obsolete `VAULTLINK_RELEASE_BUILDER_IMAGE` variable.
- [ ] Re-run policy validation and prove every pinned image can be pulled for
  its declared runner architecture.

## Package contract

- [ ] All nine package names exactly match the manifest and documented naming
  scheme.
- [ ] Every package owns `/usr/lib/vaultlink/package/vaultlink`, while the
  active binary is `/opt/vaultlink/vaultlink`.
- [ ] Every package contains the approved service/update units, Sysusers and
  Tmpfiles rules, pinned Minisign public key, updater, upgrade/rollback helpers,
  examples, licence, and its target SBOM.
- [ ] DEB/RPM/Arch metadata declares only the target-specific runtime
  dependency set; `cifs-utils` remains optional.
- [ ] Fresh installation creates the exact root-owned package marker and
  initial active binary but no production `config.toml`, service enablement,
  service start, updater enablement, or updater start.
- [ ] Upgrade preserves `/etc/vaultlink/update.conf` and does not activate the
  package candidate in a maintainer script.
- [ ] Reinstall and ordinary remove preserve configuration, database, keyring,
  backups, logs, mounts, and the `vaultlink` user.
- [ ] Existing package paths or `/opt/vaultlink/vaultlink` without a valid
  matching marker make installation fail before mutation.
- [ ] `lintian`, `rpmlint`, and `namcap` pass as applicable; the common positive
  allowlist independently accepts every path, owner, mode, dependency,
  scriptlet, and unit line.

## Package updater and recovery

- [ ] `vaultlink-update check`, `install`, and `auto` reject non-root mutation,
  malformed config, unsupported release, pre-release, downgrade, wrong target,
  marker/package-database mismatch, and candidate/active version mismatch.
- [ ] Both the new and installed-version packages are downloaded only from the
  fixed official HTTPS origin and verified by direct Minisign signatures plus
  the signed global `SHA256SUMS`.
- [ ] Safe inspection rejects wrong name/version/architecture, unsafe package
  content, unexpected metadata, embedded-key replacement, malformed helpers,
  and payload/version mismatch.
- [ ] A missing new runtime dependency fails before package installation and
  reports the required manual package update; the transaction never contacts a
  distro repository.
- [ ] Offline `dpkg`, `rpm`, and `pacman` success paths preserve configuration,
  migrate state, activate the exact package payload, retain backups, and prove
  package/candidate/active/readiness version parity.
- [ ] Injected package-manager, migration, activation, start, readiness, and
  integrity failures reinstall the verified old package and restore the exact
  old runtime unit.
- [ ] A deliberately stopped service remains stopped. `auto_install=false` is
  the default and an enabled timer is still check-only until explicit opt-in.
- [ ] Injected failed recovery becomes a terminal error, leaves the service
  stopped, preserves evidence, and cannot report update success.

## Commit-bound build and test gates

- [ ] Existing `vaultlink/ci`, security, audit, policy, coverage, Fuzz, SMB,
  proxy/TLS, upload/quota/parallelism, migration, backup, and rollback gates are
  green for one exact candidate commit.
- [ ] `vaultlink/packages` is green and accounts for all nine target rows.
- [ ] Every target is compiled in its own distribution builder on a native
  matching-architecture GitHub runner; QEMU is not used for compilation.
- [ ] Every target passes offline container installation, user/path/mode,
  no-autostart, setup, `systemd-analyze verify`, API smoke, upgrade, migration,
  backup, rollback, reinstall, and state-preserving remove tests.
- [ ] Every target runs the unchanged 100-metadata-client, 40-range-stream, and
  ten-upload/readback workload against the exact installed package payload in
  its digest-pinned distribution builder on a native matching-architecture
  GitHub runner. The job qualifies the public runner for four available vCPUs,
  at least 8 GiB of host RAM, and a Docker cpuset of logical CPUs 0-3. It
  restricts the server to CPUs 0-1 and the load generator to CPUs 2-3, gives
  the clients a dedicated hardened 4-GiB tmpfs, and keeps server storage
  separate. Before service startup, the empty server volume passes the
  evidenced four-writer/128-transaction `synchronous=FULL` SQLite WAL probe
  with a concurrent reader, `integrity_check=ok`, writer p95 `<1 s`, writer
  maximum `<5 s`, reader p95 `<250 ms`, reader maximum `<2 s`, checkpoint
  `<5 s`, and total runtime `<30 s`. Its evidence records both qualifications,
  resource placement, exact workload counts, latency, RSS, and integrity
  results. A missing or different layout is a gate failure. Qualification
  failure is not automatically retried. This is a reproducible harness
  contract, not a claim of deterministic timing from arbitrary standard
  runners. The qualified native package run passes strict p95 `<2 s`, has no
  invalid response or corruption, and remains within the approved RSS limit.
- [ ] Managed `ubuntu-24.04-arm` jobs provide the authoritative arm64 p95
  evidence; no private ARM host is part of the release boundary.
- [ ] `vaultlink/package-reproducibility` is green and accounts for all nine
  target rows; two clean builds have byte-identical payload binaries, target
  SBOMs, and final packages.
- [ ] `vaultlink/distro-vms` is green and accounts for all nine target rows.
- [ ] Every guest evidence bundle records kernel, OS, package database version,
  verified `/dev/vdb` ext4 mount source and label, payload and active hashes,
  service/timer enablement, systemd status, journal, exact readiness response,
  SQLite integrity, and test result.
- [ ] Guests receive the package only over the isolated host channel and have
  no unrestricted Internet access. The unchanged complete load workload and
  every functional, security, integrity, RSS, upgrade, backup, migration, and
  rollback assertion pass without KVM. Each of the nine commit-bound evidence
  bundles records `acceleration_policy=force-tcg`, `acceleration=tcg`, and a
  not-requested KVM probe; the workflow does not expose `/dev/kvm`.
- [ ] Every QEMU guest records a numeric p95 and whether `<2 s` was met as
  diagnostic evidence. QEMU timing does not replace
  or override the authoritative native package p95 gate.
- [ ] Fedora 44 reports SELinux `Enforcing` and no VaultLink-related AVC denial.
- [ ] Arch builder and VM use the selected dated snapshot; the weekly current-
  rolling compatibility workflow is installed and read-only.

## Candidate freeze and Debian reference soak

- [ ] All three new aggregate gates are required by candidate, soak-start, and
  tag workflows in addition to existing exact-commit gates.
- [ ] Choose the release date only now and update every release-facing document
  in the final candidate commit.
- [ ] Freeze one clean `main` commit; record its SHA, the Debian 13 amd64 DEB
  hash, package-extracted binary hash, target manifest hash, and gate run URLs.
- [ ] The staging deploy and soak install the exact final Debian 13 amd64 DEB;
  the monitored `/proc/.../exe` hash equals the binary extracted from that DEB.
- [ ] Run the single uninterrupted 72-hour Debian 13 amd64 soak with hourly
  collection, 100-user load profile, p95 `<2 s`, no 5xx/corruption, RSS within
  limit, `NRestarts=0`, readiness success, and SQLite integrity.
- [ ] Collect terminal evidence exactly once, verify its checksums and commit,
  archive the host state, and ensure the collector cannot consume minutes after
  a terminal result.
- [ ] Any code, package, manifest, builder/guest digest, workflow, dependency,
  or release-document change after freeze invalidates the candidate and soak.

## Signing and verified publication

- [ ] Confirm the annotated `v0.6.0` tag is signed, points to the frozen current
  `origin/main`, and matches `Cargo.toml` and every package version.
- [ ] Confirm only the protected `release-signing` job receives
  `MINISIGN_SECRET_KEY`, `MINISIGN_PASSWORD`, the repository-scoped read-only
  Administration token `RELEASE_ADMIN_READ_TOKEN`, and job-scoped
  `contents: write`.
- [ ] Confirm `RELEASE_ADMIN_READ_TOKEN` cannot write repository contents or
  administration settings and that both pre-publication Immutable Releases
  checks report `enabled=true` before the draft is made public.
- [ ] Assemble exactly nine manifest-named packages and their nine direct
  `.minisig` files, one deterministic all-target SBOM bundle, one global
  `SHA256SUMS`, and `SHA256SUMS.minisig`—exactly 21 project assets.
- [ ] Confirm there are no project tar archives, raw standalone binaries,
  architecture-specific checksum manifests, or extra signatures.
- [ ] Create a draft release; download all assets from GitHub into a clean
  root, and independently verify count, exact names, sizes, checksums, every
  signature, every package identity/inventory, embedded key, target SBOM, and
  payload hash.
- [ ] Confirm GitHub's generated source archives are labelled unsupported and
  are not referenced by installation/update instructions.
- [ ] Publish the already verified draft without rebuilding, replacing, or
  deleting assets.
- [ ] Record the release URL, tag verification, workflow run, asset digests,
  final SBOM bundle hash, and release time in this checklist.
- [x] Repository-level GitHub release immutability was enabled on 2026-08-25
  for all future releases. Retain it and never delete an entire package
  release, because authenticated rollback depends on its assets.
