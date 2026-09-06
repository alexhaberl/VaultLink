# Architecture and security internals

[Back to README](../README.md)

This reference describes the current **0.7.0 development branch**, which is unreleased.
The supported release is **0.6.0**; its schema and feature differences are called
out below. For supported versions and vulnerability reporting, see
[Security Policy](../SECURITY.md).

## Security model

The project-wide [threat model](../THREAT_MODEL.md) maps protected assets,
attacker capabilities, deployment and release trust boundaries, testable
security invariants, and explicitly accepted residual risks.

Successful security-relevant SQLite mutations and their audit rows share an `IMMEDIATE` transaction. An audit failure rolls back the mutation; the JSON API returns `503 audit_unavailable`. Rejected logins and other observations remain best effort because there is no domain mutation to roll back.

If a file operation is already visible in the filesystem, a later audit failure is not reported as a failed operation. API and queue clients receive `202` with `audit_durability_uncertain`; browsers display a warning. Clients must not retry that response automatically. Rename/delete operations remain in the unchanged SecureFS journal and are completed once as actor `system` without a client IP.

Application-owned password, TOTP, and Share-secret buffers use a zeroizing wrapper without general `Clone`, `Display`, or `Serialize` implementations. Unavoidable copies are explicit. Framework, Serde, SQLite, formatting, and response buffers cannot all be guaranteed to be wiped; this measure reduces lifetime and avoidable copying.

- File access is descriptor-relative on Linux. `openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)` confines administrator access to the storage root and public access to a per-share directory or file capability. Co-writer mode also uses `RESOLVE_NO_SYMLINKS`. VaultLink refuses to start on a kernel without the required APIs.
- Relative user paths are validated after exactly one HTTP decode and reject absolute paths, `..`, backslashes, and NUL. Upload names also follow a cross-platform policy so Windows prefixes and reserved names cannot escape the target directory.
- Uploads are written to random `0600` temporary files in protected internal staging, flushed and synced, then atomically published with `renameat2(RENAME_NOREPLACE)`. With `external_writers = true`, overwrite remains disabled by default in the UI, API, and upload path. The separate `allow_external_writer_replace = true` opt-in accepts last-writer-wins behavior and its risk of losing a newer parallel SMB change.
- Abandoned upload fragments and only committed delete tombstones are removed in resumable background batches. Uncommitted deletes and rollback conflicts remain recovery entries instead of risking data loss at restart.
- Administrator passwords use Argon2id. Password verification is followed by TOTP or a registered WebAuthn/FIDO2 security key such as a YubiKey. Sessions are random server-side bearer tokens whose hashes are stored in SQLite; `session_hours` is the absolute cap and `session_idle_minutes` defaults to a 30-minute inactivity limit.
- Since 0.7.0 (unreleased), instance-wide service tokens are restricted to the fixed `monitoring:read` scope. VaultLink stores only a SHA-256 hash, displays the random token once, accepts it only in the `Authorization` header on the two monitoring routes, and never grants it access to existing Share, file, administration, session, public, or HTML routes.
- Cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` in production.
- Mutating administrator actions require CSRF. Login and Share unlock are rate-limited. Login counters are process-local; reverse-proxy or network limits are still required for volumetric attacks.
- In reverse-proxy mode, `trusted_proxies` is an exact TCP-peer allowlist. Forwarded headers are evaluated only for those peers.
- Security headers include CSP, `X-Content-Type-Options: nosniff`, frame protection, Referrer-Policy, Permissions-Policy, and HSTS on HTTPS only.
- Audit data is stored in a bounded 100,000-row SQLite index and mirrored in structured form to journald. SQLite retention removes routine events before security-priority events and warns if capacity pressure reaches security events; priority controls eviction order but is not indefinite or tamper-proof retention. journald has an independent host retention policy that operators must size for their forensic requirements. Passwords, TOTP secrets, session tokens, Share tokens, and client IPs are not written to journald.

File links are `download_only`; upload permission applies to directories. Without external writers, an existing file can be replaced only when an administrator enables replacement for that upload link and the public uploader explicitly confirms it. Directory shares support bounded incremental ZIP64 downloads, search, subdirectory uploads, and previews when download permission is present. Small default body limits protect buffered form and JSON routes. Upload routes retain a large streamed body limit behind a constant-memory multipart guard. Upload-only shares never list content or allow preview/download.

## Project layout

```text
VaultLink/
├── src/
│   ├── main.rs             CLI, server startup, TLS/ACME
│   ├── cli/, server/       command parsing, recovery, listeners, shutdown
│   ├── config.rs           TOML and startup validation
│   ├── api.rs              stable JSON API facade and /api/v2 router
│   ├── api/                authentication, files, shares, admins, settings, public handlers
│   ├── auth.rs             Argon2id, TOTP, rate limiting
│   ├── cifs_provision.rs   privileged, tightly scoped CIFS/systemd provisioning
│   ├── db.rs               database facade, shared types, transaction core
│   ├── db/                 auth, share, transfer, settings, audit operations and keyring
│   ├── file_ops.rs         transactional rename/delete operations
│   ├── http_auth.rs        shared session, cookie, CSRF, and audit helpers
│   ├── i18n.rs             server-side German/English localization
│   ├── multipart_guard.rs  streaming multipart-header bounds
│   ├── path_security.rs    path validation
│   ├── secure_fs.rs        SecureFS facade for openat2/renameat2
│   ├── secure_fs/          capability, identity, journal, upload, recovery components
│   ├── sensitive.rs        zeroizing SecretString abstraction
│   ├── services/           transport-neutral auth, share, admin, file services
│   ├── state/              typed route dependencies and shared state
│   ├── share_search.rs     shared Share-search validation
│   ├── storage_mount.rs    mount and SMB trust boundary
│   ├── range.rs            single HTTP byte-range parser
│   ├── proxy.rs            trusted proxy headers
│   ├── runtime.rs          SQLite overrides for policy settings
│   ├── setup.rs            local bootstrap setup UI
│   ├── ui.rs               shared styles, icons, UI components
│   ├── webauthn.rs         WebAuthn ceremony state and credentials
│   ├── web.rs              stable HTML facade, router, API re-exports
│   └── web/                middleware, rendering, browsing, transfer, upload domains
├── config/                 example configurations
├── deploy/                 systemd, Caddy, signed updates, upgrade/rollback
├── packaging/              deterministic DEB, RPM, and Arch package inputs
├── release/                declarative target and immutable image manifest
├── docs/                   upgrade, rollback, release gates
├── fuzz/                   path, range, multipart, preview, upload, API-policy fuzzing
├── Makefile
└── Cargo.toml
```

## Data and persistence

The following table inventory describes the 0.7.0 development schema.

SQLite provides unique aliases, concurrent sessions, atomic transfer limits, and crash-safe transactions. WAL is enabled. Core tables include `admins`, `sessions`, `service_tokens`, `shares`, `public_unlock_sessions`, `public_preview_sessions`, `public_transfer_grants`, `public_transfer_leases`, `public_upload_usage`, `public_upload_reservations`, `runtime_settings`, `audit`, `transfer_monthly_counts`, `transfer_statistics`, `admin_mfa_enrollments`, `admin_webauthn_credentials`, `admin_totp_replay`, `vaultlink_schema`, and `vaultlink_schema_migrations`.

`shares.max_upload_size` is the optional per-file limit; `NULL` uses the global runtime limit. Upload shares also have cumulative `max_upload_total_size` and `max_upload_files` limits, with baseline defaults of 100,000,000,000 bytes and 1,000 fail-closed accounted files. Byte and file usage is recorded atomically before visible publication; if publication later fails, quota use deliberately remains so a visible file can never be unaccounted.

The supported 0.6.0 release uses schema 6. Fresh installations of the 0.7.0 development build create schema 10 and version-2 through version-10 migration records. Valid schema-1 through schema-9 databases are migrated through atomic `IMMEDIATE` transactions; schema 3 adds the bounded share-listing indexes, schema 4 adds administrator-session activity tracking while revoking pre-migration sessions, schema 5 adds audit-retention priority, schema 6 applies the centralized audit policy to existing upload-related records, schema 7 adds hash-only monitoring service tokens, schema 8 adds normalized trigram Share search plus composite audit-pagination indexes, schema 9 adds an index for pending transfer cleanup, and schema 10 adds partial indexes for protected and exhausted Shares plus expiry indexes. Future, unknown, corrupt, and non-empty unversioned schemas are rejected. Migrations are forward-only; rollback restores a matching old binary/config/database/keyring backup.

Concurrent filesystem renames can temporarily prevent a confined lookup.
VaultLink retries that lookup at most eight times without weakening path
confinement. Exhausted contention returns HTTP `503` and `Retry-After: 1`;
JSON file/transfer endpoints use error code `storage_busy`. Clients may retry
reads after that delay. An already-started transfer retains its existing
partial-response and retry semantics.

The database defaults to `/var/lib/vaultlink/data.sqlite`; its required matching keyring is `/var/lib/vaultlink/secrets.keyring`. Both must be owned by `vaultlink:vaultlink` with mode `0600`. The database contains encrypted secrets, but the matching keyring can decrypt them, so the pair and every complete backup are production credentials.

Install a newer signed native package through the package-bound updater:

```sh
sudo vaultlink-update check
sudo vaultlink-update install
```

Do not call the packaged upgrade helper with a raw binary. The updater verifies
the package, signatures, package database, candidate, and rollback package
before the helper can activate anything. Every verified backup and automatic
restore contains the matching binary, `config.toml`, SQLite database, and
`secrets.keyring`.

Signed update, restore, and rollback details: [docs/UPGRADE-ROLLBACK.md](../docs/UPGRADE-ROLLBACK.md).

## UI and authentication

The administrator UI includes login, MFA, files, Shares, administrators, settings, audit, and My account. Users can reauthenticate to change their password, replace TOTP in two stages, and register multiple WebAuthn/FIDO2 security keys. Hardware MFA is enabled only with at least two registered keys; the set cannot be reduced from two to one. TOTP and the local SSH recovery path remain available.

WebAuthn credentials are bound to RP ID and browser origin. Registration must use the final public HTTPS URL. The setup tunnel on `127.0.0.1:8090` is only for bootstrap/TOTP and cannot register a key for the later public domain.

Setup, login, administrator, and public pages support German and English. A valid `vaultlink_locale` cookie selects the language; without it, English is always used and `Accept-Language` is ignored. The DE/EN switch stores the cookie for one year. Dynamic usernames, filenames, aliases, and audit values are never translated.

Text previews use an extension allowlist and escaped `<pre>` output. Image previews use an allowlist, fixed content types, and `nosniff`. PDF previews are served as `application/pdf` inline without server rendering. Public raw previews require a short-lived Share/path-bound token. Counted transfers are committed only after complete delivery; range requests share a fixed 15-minute resume grant that repeated requests cannot extend indefinitely.
