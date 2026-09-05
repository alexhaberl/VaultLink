# v0.5.0 release checklist

Status: released on 2026-08-24, withdrawn on 2026-08-25, and unsupported. The
GitHub release and its archive assets were removed; the annotated tag, commit,
workflow evidence, and this historical checklist are intentionally retained.
There is no supported upgrade path from this archive layout to 0.6.0.
The lifecycle record in [`release/release-state.json`](../release/release-state.json)
is authoritative; this file remains historical evidence only.

Goal: signed public GitHub release for Debian 13 amd64 and arm64. The repository is already public as an explicitly unreleased development tree so standard GitHub-hosted CI remains ephemeral and does not consume private-repository minutes. Only the signed `v0.5.0` tag and release assets are published after merge to `main`, with a clean worktree and every release gate green.

## Release outcome

The signed, annotated `v0.5.0` tag targets exact `main` commit
`60bfb9c60c5df408890b4a645218e2b99ff0906f`. GitHub verified its SSH
signature, the exact-commit 72-hour soak and evidence preflight succeeded, and
the tag workflow built both native architectures successfully. The amd64
release binary retained the soak-verified SHA-256
`fd6bc4fb6c4fe405fdffdb738300d9546bcf2006941201082e93b2cc25aae319`.

The tag workflow's protected publish job stopped before downloading, signing,
or publishing assets because Git rejected the container-mounted checkout as a
repository with dubious ownership. The owner completed a controlled recovery
from only the two successful, CI-produced architecture artifacts from that tag
run: all architecture-specific checksum manifests and the soak binary hash
were verified locally, the six intended assets were signed with the same
offline Minisign key represented by `release/minisign.pub`, every signature was
verified, and the 14 uploaded asset names, sizes, and GitHub SHA-256 digests
were compared byte-for-byte with the verified local files. No tag, source,
binary, archive, SBOM, or checksum manifest was rebuilt or modified during the
recovery. The failed workflow run remains part of the audit trail, while the
workflow now explicitly trusts only its ephemeral checked-out workspace before
performing Git-based release checks.

## Feature scope for 0.5.0

- [x] Administrator login, TOTP MFA, sessions, logout, and CSRF.
- [x] My account password changes with current-password verification and staged MFA replacement; the old secret remains valid until the new TOTP code is confirmed.
- [x] Local `recover-admin` emergency path through SSH/host access using `--config` or direct `--database`, with atomic credential replacement, session/pending revocation, and secret-free audit.
- [x] German and English setup/auth/admin/public flows. A valid locale cookie selects the language; without one, English is used and `Accept-Language` is ignored. Date, number, and JavaScript output is locale-aware.
- [x] Session-based JSON API exclusively under `/api/v2`, with English-only backend error messages and no API tokens in 0.5.0.
- [x] Administrator file operations for directory creation, no-clobber rename, and permanent recursive deletion with server confirmation and client exact-match gating.
- [x] Bounded restartable tombstone cleanup with one global signal-coalescing worker and automatic adjustment or deactivation of affected Shares.
- [x] API and UI share authentication, session, CSRF, SecureFS, SQLite, runtime-settings, and audit logic.
- [x] API errors use the stable JSON envelope; streaming routes return binary data only on success.
- [x] Root-confined file browser with breadcrumbs, parent navigation, pagination, search, and Share creation from the current selection.
- [x] File/directory Shares with `download_only`, `upload_only`, and `download_upload`.
- [x] Argon2id-protected Shares with unlock cookies and rate limiting.
- [x] Optional short aliases.
- [x] Streamed downloads with `HEAD`, `Accept-Ranges`, one byte range, `206`, and `416`; HEAD checks quota without reserving or counting, fixed grants count complete responses, and range resumes do not extend expiry.
- [x] Secure uploads through a temporary file, `fsync`, atomic no-replace publication, and global/per-Share limits.
- [x] Optional overwrite per upload directory Share. With `external_writers=true`, UI, API, and publication default to no-replace; `allow_external_writer_replace=true` explicitly accepts tested last-writer-wins behavior.
- [x] Upload into navigated subdirectories for `download_upload` Shares.
- [x] Upload-only Shares do not list, preview, or download content.
- [x] Incremental ZIP64 directory downloads with file, scan, source-size, temporary-space, and backpressure limits.
- [x] Bounded case-insensitive filename search; listing, search, and ZIP count filtered raw directory entries and continue without offset rescans.
- [x] Escaped text preview for allowlisted extensions and fixed-MIME `nosniff` preview for allowlisted raster images and PDFs.
- [x] Administrator UI for additional admins; TOTP secrets are shown once. Initial setup can recover an unconfirmed secret locally after password verification.
- [x] Runtime-editable policy settings in SQLite rather than `/etc/vaultlink/config.toml`.
- [x] Paginated, action-filterable audit dashboard.
- [x] Loopback-only setup UI with documented IPv4 SSH tunnel: `ssh -4 -N -L 127.0.0.1:8090:127.0.0.1:8090 user@server`.
- [x] Setup never overwrites configuration; config-without-admin and committed-admin-before-lost-TOTP-response states are resumable.
- [x] Per-Share SecureFS capabilities prevent symlink switching into sibling Shares for listing, preview, download, ZIP, and upload.
- [x] Linux-only x86_64/aarch64 support while retaining Windows filename interoperability for standard SMB clients.
- [x] External CIFS co-writer mode with checked direct Share root, reserved pre-provisioned `.vaultlink-internal`, mount ID/source/options, local SQLite, and crash-safe pending/committed delete protocol.
- [x] Separate root-only non-overwriting `/mnt/storage` CIFS provisioner with interactive credentials and rollback; unprivileged browser setup detects secure active SMB mounts.
- [x] Exclusive non-blocking lifetime lock in shared `internal_directory`, acquired and semantics-tested before recovery/cleanup.
- [x] Every production configuration requires exact fail-closed mount identity; local audited production storage may keep SQLite outside the visible tree on the same supported local mount.
- [x] Setup and `init-admin` validate root/internal/data mounts and canonical paths before writing config, database, or credentials.
- [x] Upgrade/rollback backups and recovery always use a validated binary/config/SQLite/keyring unit. Candidate configuration never changes live configuration before downtime.
- [x] Fresh databases use schema 6; validated schemas 1 through 5 migrate transactionally. Schema 3→4 revokes existing administrator sessions, and schema 6 reclassifies existing upload-related audits under the centralized priority policy. Forward-only rollback restores the matching full old backup.
- [x] Small buffered form/JSON body limits; only upload routes receive the large streaming allowance. Multipart preamble, headers, field count, and metadata are bounded.
- [x] Reverse-proxy mode, standalone TLS, SIGHUP PEM reload, and optional built-in Let's Encrypt `tls-alpn-01` standalone TLS.
- [x] UI polish with separate auth/public/admin shells, logo/favicon, locale-aware date/time inputs, decimal MB/GB units, and consistent controls.
- [x] Public upload error pages for validation errors, blocked types, conflicts, limits, missing names, and storage errors.
- [x] Fuzzing for production parsers and isolated policy/state components: paths, byte ranges, filenames, ZIP/search/preview paths, overwrite policy, upload request state, Share policy, file mutation, and multipart envelope streaming. Router/DB/async/filesystem races remain integration/smoke gates; see [FUZZING.md](FUZZING.md).

## Explicit non-goals for 0.5.0

- DEB package.
- API tokens or third-party API clients as a stable public contract.
- Inline preview for other file types.
- Built-in ACME behind Nginx/Caddy; automatic TLS is for direct standalone port 443 only.
- Unlimited ZIPs or compression; ZIP64 does not remove configured file, scan, or size limits.
- Administrator deletion; admins can be deactivated and reactivated.

## Mandatory native Linux gates

- [ ] `cargo check --locked` on amd64 and arm64.
- [ ] `cargo fmt --all -- --check` on amd64 and arm64.
- [ ] `cargo clippy --locked --all-targets --all-features -- -D warnings` on amd64 and arm64.
- [ ] `cargo test --locked --all-targets` on amd64 and arm64.
  - Native Linux runs are authoritative; earlier Windows runs are not release evidence.
  - Coverage includes account password/MFA, recovery races, German/English main routes and setup, English-only API errors, login/MFA/session/CSRF, secret redaction, setup recovery, UTF-8, SecureFS, preview, transfers, ZIP, multipart, body limits, upload atomicity, limiter partitioning, and schema migration.
- [ ] `cargo check --manifest-path fuzz/Cargo.toml --locked --all-targets`.
  - Includes `zip_search_preview_paths`, `upload_overwrite_policy`, `upload_request_state`, `share_request_policy`, `file_mutation_policy`, and `multipart_guard`.
- [ ] `cargo build --release --locked` on amd64 and arm64.
- [ ] Checksum-pinned Gitleaks 8.30.0 full-history scan is green with redacted output; `.gitleaksignore` contains only the two reviewed RFC 6238 TOTP test-vector fingerprints.
- [ ] Run `cargo audit --deny warnings --ignore RUSTSEC-2023-0071` against the shared workspace lockfile; consciously re-review the compensated RSA exception and remove it as soon as the dependency permits.
- [ ] `shellcheck deploy/*.sh deploy/docker/*.sh tools/*.sh` and `make policy-check` on amd64 and arm64.
- [ ] `make docker-smoke` on the final 0.5.0 source on amd64 and arm64.
- [ ] Weekly/manual reproducibility workflow builds twice per architecture with empty targets and identical `SOURCE_DATE_EPOCH`; binary and archive SHA-256 values match bit-for-bit.
- [x] Debian image, snapshot, and direct/transitive packages match `debian-snapshot.sources` and `debian-packages.lock`; the source-independent release builder was built natively by the manual GitHub workflow and published as a linux/amd64+linux/arm64 manifest on 2026-08-09.
- [x] After the base-digest update in PR #101, rebuilt and published the native amd64/arm64 release-builder image from `main` commit `013b2f5e2ee514e9f02dda9b3d3d2c86cd69bc2c` in [workflow run 31480630773](https://github.com/alexhaberl/VaultLink/actions/runs/31480630773). Pinned the resulting multiarch manifest `sha256:a2ce314620196c1d5ded1fd514910337878e888a6550be91d33519be4190f7ba` in `release-builder-image.lock` and `VAULTLINK_RELEASE_BUILDER_IMAGE` on 2026-08-11.
- [ ] Verify Actions package read access and the updated builder through the locked release dry-run before selecting the final candidate.

## Historical observation before the 0.3.2 upgrade

- [x] Existing `0.3.0` binary checked on both test systems with identical SHA-256 `d6def1640bf8c93ddb5f30689731c4f3f2efb62d13c949b75a0012bd0cfb2946`.
- [x] Reverse-proxy system remained active for 10 h 11 min and standalone TLS for 10 h 08 min, both with `NRestarts=0` and no failed systemd units.
- [x] `PRAGMA integrity_check = ok`, empty WAL files, and successful local/public `/api/v2/health/ready` responses reporting the release version.
- [x] RSS was 10.5 MiB and 13.0 MiB respectively, with no VaultLink warnings, panics, or errors in the reviewed journal.
- [ ] This was not a formal soak: neither `soak-monitor.sh` nor the load profile ran. The final 72-hour soak has not yet started.

## Historical 0.3.x Debian/Docker verification

- [x] Digest-pinned Debian-13-amd64 image with container build and read-only workspace for fuzz/shell checks:
  - `cargo fmt --all -- --check`
  - `cargo test --locked --all-targets`
  - `cargo clippy --locked --all-targets --all-features -- -D warnings`
  - `cargo build --release --locked`
  - `cargo check --manifest-path fuzz/Cargo.toml --locked --all-targets`
  - `shellcheck deploy/*.sh deploy/docker/*.sh tools/*.sh`
  - `sh tools/check-supply-chain-policy.sh`
- [x] Reverse-proxy test system upgraded transactionally to `0.3.2` with verified backup `/var/lib/vaultlink/backups/20260710T173328Z`; SHA-256 `d382903ff9d238cbc44f616c6af39c9d27d6afb61e1bea5d1ac3706e55fa6e2c`, no restarts, SQLite `ok`, exact health response, login HTTP 200.
- [x] Standalone system upgraded with verified backup `/var/lib/vaultlink/backups/20260710T173409Z`; identical binary hash, no restarts, SQLite `ok`, exact HTTPS health response, login HTTP 200, cached Let's Encrypt certificate loaded.
- [x] Extended isolated runtime smoke on both Debian-13 systems: setup, login/MFA/CSRF, exact-match deletion, directory creation, Share creation/path adjustment, confirmation, subtree deletion, deactivation, and tombstone recovery after restart.

## Remaining release gates

- [ ] Fifteen-minute fuzz campaign on amd64 and arm64 for all thirteen targets in `docs/FUZZING.md`, including authentication headers, journal recovery, directory cursors, and real ZIP/preview I/O. Each campaign restores validated corpora, replays inputs, fuzzes every target for 900 seconds, and minimizes the result. The existing `fuzz-600s` status contexts remain the release gates; the longer campaigns exceed that historical minimum. The weekly native matrix uses two workers while private and four when public, with a 180-minute timeout including bounded builds/replays/minimization; the manual final-commit run remains the release gate. Retain both corpus snapshots and inspect the per-target statistics. The separate AMD64 source-coverage report is informational.
- [ ] Repeat `cargo-audit 0.22.2 --deny warnings --ignore RUSTSEC-2023-0071`, inspect the shared `Cargo.lock`, and confirm no additional exception exists.
- [ ] GitHub Actions CI green on final `main`.
- [ ] Locked release dry-run green on GitHub-hosted `ubuntu-24.04` and `ubuntu-24.04-arm`, using exactly the digest-pinned multi-arch Debian 13 builder with no runtime APT/Cargo installation. The tag-only signing and publishing job runs on a fresh `ubuntu-24.04` VM behind the protected `release-signing` environment.
- [x] Generated a password-protected Minisign Ed25519 key offline, committed only `release/minisign.pub`, and provisioned both signing secrets in the main-restricted `release-signing` environment on 2026-08-09. Do not change keys or builder pins after soak begins.
- [x] After the repository became public and before creating any `v*` tag, restricted `release-signing` to the existing `main` branch and `v*` tag policies and activated a `v*` tag ruleset that restricts creation, update, and deletion to the repository owner on 2026-08-11. A required reviewer is intentionally not configured: this personal repository has only one authorized release approver, so preventing self-review would deadlock publication. The workflow's public-visibility gate remains present.
- [ ] amd64 and arm64 reproducibility evidence belongs to the exact final commit and contains equal hashes for both independent builds.
- [x] Provisioned `MINISIGN_SECRET_KEY` and `MINISIGN_PASSWORD` in `release-signing`; tag publication fails without all three key materials.
- [ ] The repository owner pushes the signed, annotated `v0.5.0` tag only after merge and all gates. The owner-only tag ruleset, exact tag/main equality and the tag-only `contents: write` job complete the approval chain.
- [ ] Verify versioned amd64/arm64 archives, standalone binaries, README, LICENSE, examples, systemd/deploy files, `SHA256SUMS-*`, architecture-specific CycloneDX SBOMs, deterministic `tar.gz`, and tag-only Minisign signatures.

## Staging and public gates before final soak

- [ ] Deploy the final candidate to Debian-13 amd64 and arm64 staging systems.
- [x] Create a stopped-service SQLite/keyring backup before upgrade.
- [x] Upgrade test:
  - validate separate old/new binary/config pairs before downtime;
  - backup contains `vaultlink`, `config.toml`, `data.sqlite`, and matching `secrets.keyring` with restrictive ownership/modes;
  - candidate failure restores the full old unit and verifies its own health endpoint;
  - concurrent upgrade/rollback fails on the maintenance lock before service stop;
  - real schema-1 through schema-5 fixtures migrate once to schema 6; upload-related legacy audits receive security priority, and rollback restores the complete pre-migration backup.
- [x] Password-protected public uploads accept the unlock-bound CSRF value as multipart field or `X-VaultLink-Upload-CSRF` and reject missing/foreign values.
- [x] Upload Shares enforce per-file, cumulative byte, and file-count limits under parallel queue uploads and overwrite attempts.
- [x] Rollback test stops the service, restores matching binary/config/database/keyring, starts it, verifies exact local health/version, and remains stopped after failed recovery stop or incomplete emergency restore.
- [x] Real SMB 3.1.1 co-writer gate (operator-confirmed on 2026-08-09):
  - compare every visible entry including dotfiles with snapshots/hashes;
  - use a separate VaultLink SMB account and normal Windows/macOS/Linux co-writer accounts;
  - require SMB 3.1.1 signing/encryption for the mount and every direct client session;
  - allow required root user-data access but no administrative or `.vaultlink-internal` access;
  - pre-create `.vaultlink-internal/{uploads,tombstones}` and deny read/write/delete/rename, parent `DELETE_CHILD`, `WRITE_DAC`, `WRITE_OWNER`, and chmod/chown/setfacl equivalents to co-writers;
  - confirm `vers=3.1.1`, `seal`, `cache=strict`, `nosuid`, `nodev`, `noexec`, and no forbidden options in `/proc/self/mountinfo`;
  - keep SQLite on a separate local filesystem;
  - parallel SMB put and VaultLink no-replace yield exactly one winner with no mixed content or clobber;
  - overwrite Shares return 409/400 in safe co-writer mode;
  - disconnect/reconnect, restart, pending-delete recovery, and mount races fail safely or recoverably;
  - complete CIFS unmount with a local fallback mountpoint is rejected before secret/database access;
  - local ext4/XFS production accepts root/internal/data on one mount outside the visible tree and rejects group/other/ACL-writable roots;
  - direct SMB changes appear in SMB-server audit and their VaultLink-audit/quota bypass is accepted.
- [x] Debian-13-amd64 load profile: 100 concurrent users, 40 download streams, 50-GiB sparse file, parallel uploads, no 5xx or corruption, metadata p95 below 2 seconds, at most 256 MiB additional RSS (operator-confirmed successful on native Debian 13 amd64 on 2026-08-09).
  - Docker evidence on `cf5f405` (2026-08-09): 2,000/2,000 metadata requests returned 200, all 40 parallel 64-MiB ranges returned 206 with identical hashes, and all ten parallel 64-MiB uploads were created and read back without corruption. Maximum RSS was 53,168 KiB. Metadata p95 was 1.463 seconds cold and 1.371 seconds warm, both below the current 2-second threshold; Docker Desktop remains historical, non-authoritative evidence.
  - The later native Debian 13 amd64 run met the release thresholds, including metadata p95 below 2 seconds; the slower Docker Desktop timing is retained only as historical, non-authoritative evidence.
- [x] Public reverse-proxy endpoint (operator-confirmed on 2026-08-09): TLS/redirect, headers, cookies, login/MFA/logout, two real FIDO2 keys, admins, settings, audit, password/limit Shares, search, ZIP, previews, range/HEAD, subdirectory upload, authorized confirmed replacement only, upload-only restrictions, revoke/expiry/limit, and all JSON API flows.
- [x] Standalone automatic TLS only with Let's Encrypt staging on a directly reachable standalone endpoint, never behind a reverse proxy (operator-confirmed on 2026-08-09).

Docker validation on GitHub `main` commit `cf5f405` also passed the pinned Debian-13-amd64 image build, all 499 Rust tests, setup/API/load-fixture/soak-evidence smokes, schema-1-through-schema-5 migration coverage, and the complete upgrade/backup/rollback safety script. Native GitHub CI for the same commit remains green on amd64 and arm64. This evidence does not replace deployment of the final candidate to both staging systems.

## Final 72-hour soak

The exact `a0c6361cde8079e9e7b29f30450e819023e4f177` candidate completed
259,200 seconds from 2026-08-12 through 2026-08-15 with all twelve load
profiles, hashes, health checks, SQLite integrity checks, journals and restart
checks passing. It is diagnostic evidence, not release evidence: the former
relative-only RSS rule rejected a 35,836-KiB warm median and 46,336-KiB final
median even though absolute RSS stayed below 50 MiB and the final 24-hour trend
was approximately 1 MiB. The replacement gate keeps the 256-MiB cap, permits
only `max(15%, 16 MiB)` from warm to final, and independently permits only
`max(5%, 4 MiB)` from hours 48–54 to final. A new exact-commit soak is required.

Two follow-up series then ran twelve additional load profiles against the same
long-lived PID, each with a ten-minute cooldown. All profiles passed with
metadata p95 below 2 seconds and a 53,628-KiB maximum RSS. The final four
cooldown values were 51,264, 51,252, 51,072 and 51,016 KiB, confirming a stable
plateau rather than continuing per-profile growth. These diagnostics justify
the bounded warmup allowance but do not replace the new exact-commit soak.

- [ ] Before soak, replace `Unreleased release candidate` in the top changelog entry with the real planned UTC date (`YYYY-MM-DD`). Candidate-mode manual release workflow succeeds for that exact commit and sets `vaultlink/release-candidate-preflight`.
- [ ] Start only after the final runtime deployment.
- [ ] Provision the dedicated SSH host, port, user, exact trusted `known_hosts` entry, and distinct mode-restricted start/collect private keys in protected `release-soak` and branch-restricted `release-soak-collector`; only the manual start environment requires approval so the collector can run hourly.
- [ ] Start the dedicated Debian-13 amd64 soak host only through the protected GitHub-hosted workflow on exact `origin/main`; require candidate preflight, pinned SSH host keys, the forced-command bridge, and fail closed on OS/architecture mismatch.
- [ ] Run at least 259200 seconds with no unplanned restarts, `PRAGMA integrity_check = ok`, continuous version `0.5.0`, no 5xx/panic/database journal errors, metadata p95 below 2 seconds at the specified load, RSS at most 256 MiB, final growth from the warm median at most `max(15%, 16 MiB)`, and final growth from the hour-48-through-54 median at most `max(5%, 4 MiB)`.
- [ ] Scheduled collector runs at minute 17 of every hour and uploads atomic result, CSV, load reports, journal, commit, and full binary hash as `soak-evidence-COMMIT`, setting `vaultlink/72h-soak` to success.
- [ ] Any commit change after soak begins, including docs/CI/deploy/config/version, invalidates the evidence and restarts the full gate.

## Tag release

- [ ] Clean worktree and green CI on final `main`.
- [ ] Release dry-run, `cargo-audit`, and `make policy-check` remain green; Dependabot pin updates are checked against upstream.
- [ ] Staging/public gates are green.
- [ ] `vaultlink/72h-soak` succeeds for the exact commit and the release workflow verifies duration, metrics, load runs, and full amd64 binary hash.
- [ ] Evidence-mode manual workflow downloads soak/reproducibility evidence, compares binary/archive hashes with both rebuilds, and sets `vaultlink/release-evidence-preflight`.
- [ ] Changelog date equals the current UTC date during tagging. A missed date requires a new commit, candidate preflight, and full soak.
- [ ] Create annotated `v0.5.0`; tag commit exactly equals approved `origin/main` and release secrets are authorized.
- [ ] Offline `release/minisign.pub` is committed and both signing secrets are provisioned.
- [ ] Tag workflow creates the GitHub Release from CI-only artifacts; verify both archives, binaries, and architecture-specific `SHA256SUMS`/Minisign files against `release/minisign.pub`.
