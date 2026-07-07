# Changelog

## 0.1.0-beta.1 — unreleased

- Linux storage access is descriptor-relative through `openat2` with `RESOLVE_BENEATH` and `RESOLVE_NO_MAGICLINKS`.
- Uploads use private temporary files, `fsync`, and `renameat2(RENAME_NOREPLACE)` publication.
- Added password-protected shares with Argon2id, one-hour unlock sessions, and per-share/IP throttling.
- Added paginated directory views, `HEAD`, and single-range downloads (`206`/`416`).
- Added local loopback-only setup UI for initial config and first admin bootstrap.
- Added admin UI for additional admins, runtime policy settings, and paginated audit events.
- Added folder breadcrumbs, bounded search, limited ZIP downloads, per-share upload limits, safe escaped text preview, and inline browser preview for allowlisted raster images and PDFs.
- Added transactional SQLite schema migrations and explicit rejection of newer schemas.
- Added standalone TLS certificate reload through `SIGHUP` for PEM files.
- Added optional built-in Let's Encrypt standalone TLS via `rustls-acme` and `tls-alpn-01`.

This prerelease targets Debian 13 amd64. DEB packaging, ARM64 builds, public repository publication, Office/HTML/SVG/media preview, and unbounded ZIP streaming are deferred.
