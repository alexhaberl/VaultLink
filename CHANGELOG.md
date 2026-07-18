# Changelog

## 0.5.0 — Unreleased release candidate

This work was developed under the internal `0.4.9` hardening candidate. That candidate is not published or tagged; the first releasable artifact containing these changes is 0.5.0.

- Added server-authoritative request IDs, split liveness/readiness probes, a bounded descriptor-based DB/storage readiness check, and a 30-minute default administrator idle-session timeout with schema-4 activity tracking.
- Centralized WebAuthn RSA rejection at registration, persistence and authentication boundaries and documented the narrowly compensated `RUSTSEC-2023-0071` exception.
- Added forward-only, transactional schema 1→2→3→4 migrations with durable migration history, fingerprint validation, share-list indexes, deliberate administrator-session revocation at schema 4, and complete binary/config/database/keyring rollback requirements.
- Added bounded cursor pagination for large directory and historical Share listings, immutable versioned-asset caching, explicit Argon2id parameters, and non-root container smoke execution.
- Partitioned administrator password-login limits so active accounts use isolated exact counters while unknown or invalid usernames remain in fixed process-local buckets.
- Made English the default UI language unless an explicit locale cookie exists, made backend/API error messages English-only, and moved the complete JSON API to `/api/v2` without a v1 compatibility router.
- Documented the SQLite/keyring, backup, host-log, audit, and network-rate-limit trust boundaries.
- Removed the privileged load-fixture staging race by moving every storage mutation to the unprivileged `vaultlink` account and adding no-clobber adversarial smoke coverage.
- Revalidated live MFA authorization at admin-upload publication and serialized public overwrite policy changes with quota commit and filesystem publication.
- Replaced unbounded tombstone retry tasks with one coalescing, lifecycle-managed cleanup coordinator.
- Added poisoned-lock recovery for unwind builds while retaining fail-fast `panic=abort` release behavior.
- Split public-upload and ZIP-transfer ownership into consuming prepared states and moved fuzz targets from copied models to the production request/share policy facade.
- Made the development storage boundary explicit: `internal_directory`, `require_mount`, `external_writers`, and `allow_external_writer_replace` are now mandatory configuration fields.
- Added immutable Debian package inputs, reproducibility checks, exact-commit soak evidence and version-consistency release policy.
- Added a fixed-boundary, root-only CIFS provisioner plus token-protected setup discovery that can use the hardened SMB share root directly while reserving an unreachable in-tree `.vaultlink-internal`, without granting the browser setup process mount privileges, with an explicit last-writer-wins opt-in for Replace uploads alongside external SMB clients.
- Added a container setup entrypoint that preserves VaultLink's loopback-only listener behind a distinct proxy port and carries the same connection across the setup-to-serve transition without a port collision.

## 0.4.3 — 2026-07-14

- Prevented TOTP replay across concurrent sessions with an atomic per-admin counter claim (schema 11).
- Unified admin password validation across setup, CLI, UI and API, including the 1024-byte login boundary.
- Added HTTP header/body idle limits, bounded concurrent uploads, safer WebAuthn reauthentication, and hard share-password input limits.
- Added cumulative byte/file quotas for public upload shares and bound password-protected public uploads to their unlock session with a dedicated CSRF value.
- Hardened semantic pre-0.4.1 storage-layout migration and rollback gates, rejected downgrades through the upgrade entry point and roll-forwards through the rollback entry point, and removed obsolete UI/SecureFS compatibility symbols.
- Added a canonical per-storage lifetime lock, acquired before recovery and cleanup, with cross-process contention, backend-semantics, lock-file identity and locked-directory capability-handoff checks; overlapping serving instances and handoff replacements now fail startup.
- Bound SQLite, SecureFS, cleanup and mutation work to the validated storage directory capabilities, closed mount/path replacement races, and made rename/delete recovery durable across intent, publish, rollback and cancellation boundaries.
- Made successful login, MFA, logout, administrator, settings, audit-purge, share-unlock and WebAuthn mutations cancellation-safe; security-key deletion now validates the live MFA session and credential snapshot while replay claim, deletion policy and audit commit atomically.
- Added fail-closed upload policy epochs, persistent reservations and cumulative quotas, corrected transfer accounting before the first response payload, and bounded request, multipart, preview, Argon2, connection and response resources.
- Removed the remaining external certificate-renewal and staging deployment components, added regression policy against their return, and hardened release, upgrade and rollback gates around exact SemVer, binary/config/database pairing and readiness recovery.
- Rejected non-startable empty preview-extension configurations and fixed expiry-offset and growing-text-preview edge cases.
- Added WebAuthn ceremony-state invariants, injected deletion-cleanup retry tests, and production multipart-stream fuzzing.
- Capped accepted HTTP connections and in-flight response bodies, added systemd FD/task ceilings, rotated short share aliases during upgrades and retired their lookup path, removed the legacy CSS delivery path, and replaced the placeholder PNG with a real 32×32 favicon.
- Removed the deprecated `share_password_max_bytes` parser alias; schema 12 atomically renames the persisted runtime key while candidate TOML files must use `share_password_max_length`.

## 0.4.1 — 2026-07-12

- Added native Linux aarch64 support with dedicated Self-hosted amd64 and arm64 runners; architecture-independent Actions jobs run on arm64 and no workflow uses GitHub-hosted compute.
- Removed Windows host support and retained Windows-compatible filename rules for standard SMB clients.
- Added fail-closed external CIFS storage validation for mount identity, source, filesystem type, read-write state, SMB 3.1.1 encryption/strict-cache options, local SQLite separation and mount-race detection.
- Required every production deployment to declare and verify an exact active mount identity; setup and `init-admin` now reject unmounted fallbacks, network SQLite, unsafe ownership/modes and canonical data-path aliases before storing credentials.
- Split the visible shared tree from pre-provisioned sibling staging protected by server-side SMB ACLs; external-writer paths reject symlinks, nested mounts and overwrite publication.
- Moved uploads into protected flat staging with cross-directory atomic no-replace publication, rustix-backed `openat2`/`renameat2` operations and startup mutation probes.
- Made deletion recovery crash-safe by separating uncommitted pending entries from committed cleanup tombstones; rollback conflicts preserve both objects for operator recovery.
- Added architecture-specific archives, binaries, SBOMs, checksums and Minisign signatures for Debian 13 amd64 and arm64 releases.
- Upgrades and rollbacks now validate, back up, activate, restore and health-check matching binary/config/SQLite/keyring units under a shared maintenance lock.

## 0.4.0 — 2026-07-11

- Added WebAuthn/FIDO2 security keys such as YubiKey as an alternative admin second factor, with multiple named keys per account, password-confirmed enrollment, TOTP-protected removal, session-bound single-use ceremonies, and stable RP-ID/origin configuration.
- Added a German/English interface with explicit language selection, browser-language detection, localized server-rendered pages and locale-aware browser behavior.
- Added “My account” for current-user password changes and response-loss-safe, two-step MFA replacement that keeps the previous authenticator valid until the new code is confirmed.
- Added the local `recover-admin` break-glass command for atomic password and/or MFA recovery through SSH/host access, including session and pending-enrollment revocation plus secret-free auditing.
- Kept the privileged setup UI loopback-only while adding an explicit IPv4 SSH-tunnel workflow, clearer post-setup listen-address labeling, and hardened setup boundary validation.
- Bound Web and API session creation atomically to the still-current password hash and active administrator state so concurrent credential rotation or deactivation cannot create a stale session.
- Renamed the product tagline to “Secure file sharing”, restricted `init-admin` to initial bootstrap, and made CLI command/option parsing fail closed.
- Made the ZIP source-size and file-count limits independently optional with `0`, while retaining scan, overflow, ZIP64, and temporary-storage safeguards.

## 0.3.5 — 2026-07-11

- Rebuilt the server-rendered setup, admin, and public interfaces around a shared dark VaultLink design system with responsive navigation, accessible controls, inline SVG icons, and self-hosted assets.
- Added dedicated share creation, searchable and paginated link management, improved public download/upload views, mobile upload-only privacy, and a sequential multi-file upload queue with single-request fallback.
- Added UTC monthly transfer statistics for downloads, ZIP downloads, and previews, plus opt-in trusted-proxy-aware audit IP storage, display, and confirmed deletion.
- Added hardened admin uploads, richer audit details, improved setup mode/TLS field switching and filesystem pickers, and same-process transition from setup into the configured server mode.
- Corrected admin table, action-menu, date/time-picker, preview, form alignment, spacing, and long-value rendering issues found during visual QA.
- Simplified ZIP generation to always stream full ZIP64 records for every entry and archive while retaining the configured ZIP size, file-count, and scan limits.

## 0.3.2 — 2026-07-10

- Added admin-only directory creation and no-clobber file/directory renaming to the browser and session API.
- Added permanent recursive deletion with exact-name confirmation for non-empty directories, immediate tombstoning, bounded background cleanup, and restart recovery.
- Kept share paths consistent across renames and automatically deactivated active shares below deleted paths.
- Serialized storage mutations with share creation and upload publication, added audit events, and expanded Windows/Linux, database, UI, API, and cleanup coverage.
- Added exact-name delete-button gating with autofocus and serialized all background tombstone/startup cleanup through one global worker slot to avoid storage I/O bursts.
- Added filename/private-namespace and file-mutation/share-subtree fuzz coverage, executing all eight targets across four workers on the self-hosted arm64 runner.

## 0.3.1 — 2026-07-10

- Fixed UTF-8 mojibake in the admin and setup interfaces so German labels, punctuation, and icons render correctly.
- Added rendered-response and source-level regression checks for UTF-8 metadata and common Windows-1252/UTF-8 corruption patterns.
- Updated the pinned GitHub workflow actions to `checkout` v7 and `upload-artifact` v7.0.1, aligned the stable Rust, CI, Docker, and release toolchains on Rust 1.97.0, and added a policy check that keeps the stable image pins synchronized.
- Fixed release dry-runs on branch names containing slashes by deriving artifact versions from `Cargo.toml`, and validated every required dry-run output before artifact upload.
- Hardened upgrades with a bounded local HTTP readiness gate, exact candidate-version health responses, DNS/proxy-independent standalone-TLS probing, and verified automatic restore after readiness failures.

## 0.3.0 — 2026-07-10

- Added session-based JSON API under `/api/v1` for automated feature tests and future CLI integration.
- Extracted shared HTTP auth helpers for sessions, cookies, CSRF, runtime settings, blocking SQLite work, share unlock cookies, and audit logging.
- API and UI now share the same session/MFA/CSRF basis instead of maintaining duplicate authentication logic.
- Added API integration tests for login/MFA/session/CSRF, share creation, secret redaction, admin creation, and CSRF enforcement.
- Public API download/upload/preview/ZIP routes delegate to the existing secure streaming handlers to avoid duplicated filesystem and permission logic.
- Delegated API errors are normalized to JSON while successful streaming responses remain binary.
- Added API request policy fuzz target and manual GitHub fuzz gate.
- Bound public directory shares to per-share SecureFS capabilities. Descriptor-relative access now blocks sibling-share symlink escapes across listing, preview, download, ZIP, and upload while still allowing safe in-share traversal.
- Replaced RAM-built ZIP responses with bounded incremental ZIP generation, capped source reads, anonymous temporary-file spooling when capacity permits, and a backpressured direct-stream fallback.
- Added transfer grants and request leases in SQLite. Completed downloads count exactly once, including HTTP/1 responses that stop polling at `Content-Length`; aborted streams release reservations, Range resumes share one fixed 15-minute grant, and independent heartbeats protect slow or backpressured transfers without creating an indefinitely sliding free window.
- Made runtime setting updates canonical, all-or-nothing, restart-safe, and serialized across SQLite and memory. Production runtime URLs remain HTTPS-only.
- Made admin deactivation transactional so concurrent administrators cannot deactivate the final active account.
- Made first setup non-overwriting and recoverable across config/admin commit and TOTP response-loss windows; the initial TOTP recovery marker is removed only after explicit local confirmation.
- Added graceful server draining and resumable, cycle-aware background cleanup for stale private upload fragments. Batches continue fairly through large directories while an active-fragment registry protects uploads running in this process.
- Distinguished a published upload with uncertain directory-sync durability from a failed upload, preventing unsafe client retries after the destination is already visible.
- Hardened request handling with small default buffered-body limits, upload-only streaming limits, constant-memory multipart preamble/header guards, bounded field counts and metadata, cross-platform upload filenames, FIFO/special-file rejection, and literal-percent filename round trips.
- Directory listings, searches, and ZIP planning now count every raw directory item against their scan budget, including filtered fragments, symlinks, non-UTF-8 names, and special files, while continuation cursors avoid offset rescans.
- Fixed API-scoped unlock/transfer cookies, media-preview raw URLs, upload redirects, alias URLs, filtered pagination, and legacy per-share upload-limit parsing.
- Expanded concurrency, fault-injection, Windows, Linux/openat2, HTTP, restart, ZIP, setup-recovery, body-limit, and API integration coverage.
- Hardened upgrade and rollback scripts so backup, activation, health-check, and restore failures recover the previous running state instead of leaving VaultLink stopped.
- Pinned CI actions and build images immutably, added push/PR audits for both lockfiles, and made setup, API, upgrade, and rollback Docker smokes normal CI gates.

## 0.2.0 — 2026-07-08

- Linux storage access is descriptor-relative through `openat2` with `RESOLVE_BENEATH` and `RESOLVE_NO_MAGICLINKS`.
- Uploads use private temporary files, `fsync`, and `renameat2(RENAME_NOREPLACE)` publication.
- Added per-share upload conflict strategy: default uploads still reject name conflicts, while upload-capable folder links can allow explicit per-upload replacement.
- Added public upload error pages for validation failures, including blocked file types, conflicts, size limits, aborted uploads, missing filenames, unavailable target folders, and storage exhaustion.
- Added password-protected shares with Argon2id, one-hour unlock sessions, and per-share/IP throttling.
- Added paginated directory views, `HEAD`, and single-range downloads (`206`/`416`).
- Added local loopback-only setup UI for initial config and first admin bootstrap.
- Added admin UI for additional admins, runtime policy settings, and paginated audit events.
- Added folder breadcrumbs, bounded search, limited ZIP downloads, per-share upload limits, safe escaped text preview, and inline browser preview for allowlisted raster images and PDFs.
- Added UI polish: dedicated auth/public/admin shells, VaultLink logo/favicon, German date/time picker, decimal MB/GB units, mountpoint storage display, clearer buttons/switches, and removable Load display.
- Added transactional SQLite schema migrations and explicit rejection of newer schemas.
- Added standalone TLS certificate reload through `SIGHUP` for PEM files.
- Added optional built-in Let's Encrypt standalone TLS via `rustls-acme` and `tls-alpn-01`.
- Added manual fuzz targets for upload overwrite and upload validation policy in addition to path, range, filename, and preview path fuzzing.

This private release targets Debian 13 amd64. DEB packaging, ARM64 builds, public repository publication, Office/HTML/SVG/audio/video preview, and unbounded ZIP streaming are deferred.
