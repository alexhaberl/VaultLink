# Changelog

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
