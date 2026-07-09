# Changelog

## 0.3.0 — 2026-07-09

- Added session-based JSON API under `/api/v1` for automated feature tests and future CLI integration.
- Extracted shared HTTP auth helpers for sessions, cookies, CSRF, runtime settings, blocking SQLite work, share unlock cookies, and audit logging.
- API and UI now share the same session/MFA/CSRF basis instead of maintaining duplicate authentication logic.
- Added API integration tests for login/MFA/session/CSRF, share creation, secret redaction, admin creation, and CSRF enforcement.
- Public API download/upload/preview/ZIP routes delegate to the existing secure streaming handlers to avoid duplicated filesystem and permission logic.
- Delegated API errors are normalized to JSON while successful streaming responses remain binary.
- Added API request policy fuzz target and manual GitHub fuzz gate.

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
