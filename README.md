# VaultLink

VaultLink is a server-rendered Rust web application that securely exposes an already mounted Linux directory through public download and upload links. Supported host platforms are Linux x86_64 and aarch64; Windows host support was removed in 0.4.1. Windows, macOS, and Linux clients remain interoperable through an external standard SMB server.

Status: `0.6.0` is the current package-only release candidate, planned for 2026-08-31, for Debian 13, Ubuntu 24.04/26.04 LTS, Fedora 44, and an Arch Linux release snapshot. The `v0.5.0` GitHub release and its archive assets were withdrawn on 2026-08-25 and are unsupported; its annotated tag, commit, workflow evidence, and [historical checklist](docs/RELEASE-CHECKLIST.md) remain for audit purposes. There is currently no supported public VaultLink release until the signed `v0.6.0` release is published. See the [package contract](docs/PACKAGING.md), [0.6.0 release checklist](docs/RELEASE-CHECKLIST-0.6.0.md), and [changelog](CHANGELOG.md).

## 1. Security model

The project-wide [threat model](THREAT_MODEL.md) maps protected assets,
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
- Cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` in production.
- Mutating administrator actions require CSRF. Login and Share unlock are rate-limited. Login counters are process-local; reverse-proxy or network limits are still required for volumetric attacks.
- In reverse-proxy mode, `trusted_proxies` is an exact TCP-peer allowlist. Forwarded headers are evaluated only for those peers.
- Security headers include CSP, `X-Content-Type-Options: nosniff`, frame protection, Referrer-Policy, Permissions-Policy, and HSTS on HTTPS only.
- Audit data is stored in a bounded 100,000-row SQLite index and mirrored in structured form to journald. SQLite retention removes routine events before security-priority events and warns if capacity pressure reaches security events; priority controls eviction order but is not indefinite or tamper-proof retention. journald has an independent host retention policy that operators must size for their forensic requirements. Passwords, TOTP secrets, session tokens, Share tokens, and client IPs are not written to journald.

File links are `download_only`; upload permission applies to directories. Without external writers, an existing file can be replaced only when an administrator enables replacement for that upload link and the public uploader explicitly confirms it. Directory shares support bounded incremental ZIP64 downloads, search, subdirectory uploads, and previews when download permission is present. Small default body limits protect buffered form and JSON routes. Upload routes retain a large streamed body limit behind a constant-memory multipart guard. Upload-only shares never list content or allow preview/download.

## 2. Project layout

```text
VaultLink/
├── src/
│   ├── main.rs             CLI, server startup, TLS/ACME
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

## 3. Data and persistence

SQLite provides unique aliases, concurrent sessions, atomic transfer limits, and crash-safe transactions. WAL is enabled. Core tables include `admins`, `sessions`, `shares`, `public_unlock_sessions`, `public_preview_sessions`, `public_transfer_grants`, `public_transfer_leases`, `public_upload_usage`, `public_upload_reservations`, `runtime_settings`, `audit`, `transfer_monthly_counts`, `transfer_statistics`, `admin_mfa_enrollments`, `admin_webauthn_credentials`, `admin_totp_replay`, `vaultlink_schema`, and `vaultlink_schema_migrations`.

`shares.max_upload_size` is the optional per-file limit; `NULL` uses the global runtime limit. Upload shares also have cumulative `max_upload_total_size` and `max_upload_files` limits, with baseline defaults of 100,000,000,000 bytes and 1,000 fail-closed accounted files. Byte and file usage is recorded atomically before visible publication; if publication later fails, quota use deliberately remains so a visible file can never be unaccounted.

Fresh installations create schema 6 and version-2 through version-6 migration records. Valid schema-1 through schema-5 databases are migrated through atomic `IMMEDIATE` transactions; schema 3 adds the bounded share-listing indexes, schema 4 adds administrator-session activity tracking while revoking pre-migration sessions, schema 5 adds audit-retention priority, and schema 6 applies the centralized audit policy to existing upload-related records. Future, unknown, corrupt, and non-empty unversioned schemas are rejected. Migrations are forward-only; rollback restores a matching old binary/config/database/keyring backup.

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

Signed update, restore, and rollback details: [docs/UPGRADE-ROLLBACK.md](docs/UPGRADE-ROLLBACK.md).

## 4. Configuration model

Examples:

- [config/development.toml](config/development.toml)
- [config/production-reverse-proxy.toml](config/production-reverse-proxy.toml)
- [config/production-standalone-tls.toml](config/production-standalone-tls.toml)
- [config/production-standalone-letsencrypt.toml](config/production-standalone-letsencrypt.toml)

Startup rules:

- `development`: loopback only, HTTP, no HSTS.
- `reverse_proxy`: production, HTTPS `public_base_url`, `reverse_proxy.enabled = true`, at least one trusted proxy, no application TLS.
- `standalone_tls` with `certificate_source = "files"`: production HTTPS, TLS enabled, certificate and key present; optional SIGHUP reload.
- `standalone_tls` with `certificate_source = "letsencrypt"`: production HTTPS, TLS enabled, reverse proxy disabled, DNS host in `public_base_url`, contact email, and a secure ACME cache below `data_directory`.

Every production mode requires `require_mount = true`, a pre-provisioned private internal directory, and the exact active mount source and filesystem type. This prevents startup on a local fallback directory when the intended mount is unavailable. Example local-storage policy:

```toml
[storage]
root_mount_path = "/srv/vaultlink/shared"
data_directory = "/var/lib/vaultlink"
internal_directory = "/srv/vaultlink/.vaultlink-internal"
require_mount = true
external_writers = false
allow_external_writer_replace = false
expected_filesystem_type = "ext4"
expected_mount_source = "/dev/mapper/vaultlink"
```

`expected_mount_source` must exactly match the source field in the active `/proc/self/mountinfo` row; a `UUID=` entry in `/etc/fstab` is not automatically the same value. Supported audited local filesystems are ext2/3/4, XFS, Btrfs, F2FS, Bcachefs, and ZFS. The root, internal directory, and data directory belong to the `vaultlink` service user and must not be writable through group/other mode bits or the POSIX ACL mask. SQLite may share that local mount only outside the visible tree. With CIFS/SMB, SQLite must be on a separate local filesystem.

`public_base_url` uses canonical `http://` or `https://` authority syntax without a trailing slash. Base paths, credentials, query strings, and fragments are unsupported.

### External SMB server with standard clients

VaultLink does not host an SMB server. It mounts an existing Share as a Linux SMB client while Windows, macOS, and Linux clients continue to access the root directly:

```text
//fileserver.example/vaultlink  ->  /mnt/storage = root_mount_path
├── <user data directly in the Share root, writable by normal SMB clients>
└── .vaultlink-internal/        -> internal_directory, VaultLink SMB account only
    ├── .vaultlink-instance.lock
    ├── uploads/
    └── tombstones/
```

The internal directories must be provisioned server-side before first start. Their server ACL grants read, write, delete, and rename only to the separate VaultLink SMB service account. Co-writers receive only the required Modify access to user data. They must be denied access to `.vaultlink-internal`, parent `DELETE_CHILD`, `WRITE_DAC`, `WRITE_OWNER`, and chmod/chown/setfacl equivalents. Local CIFS modes `0700`/`0600` are an additional check, not proof of the server ACL.

Exactly one VaultLink instance may own a storage root. VaultLink opens `.vaultlink-instance.lock`, verifies locking with independent descriptors, and holds an exclusive non-blocking Linux `flock` for the server lifetime before recovery or cleanup. Active/active replicas, overlapping rolling starts, and separate copies of the internal directory are unsupported.

Audited co-writer mode requires:

- `require_mount = true`, `external_writers = true`, `expected_filesystem_type = "cifs"`, and the exact UNC source. `allow_external_writer_replace = false` is the safe default.
- Linux statx mount IDs (Linux 5.8 or newer), coherent exclusive locks, and the same checked mount ID for root/internal paths.
- `vers=3.1.1`, `seal`, `cache=strict`, `serverino`, `nosuid`, `nodev`, `noexec`, read-write status, and none of `cache=loose`, `nostrictsync`, `noperm`, `noserverino`, or `multiuser`.
- No symlinks, nested mounts, or DFS submounts in user paths.
- `data_directory` and SQLite/WAL on a separately supported local filesystem; CIFS/NFS SQLite is rejected.
- External writers are trusted content publishers. Their changes bypass VaultLink authentication, audit, quotas, and link policy and therefore require SMB-server audit.
- `allow_external_writer_replace = true` explicitly accepts last-writer-wins lost-update risk.
- The SMB server must require SMB 3.1.1 signing and encryption for every direct client session; VaultLink's `seal` protects only its own Linux mount.

Other network filesystems with external writers are not approved in 0.6.0. Runtime-editable settings under `/admin/settings` include `public_base_url`, upload limits, blocked extensions, Share-password policy, unlock duration, ZIP/search/text/media preview limits and extensions, and PDF-preview status. Server mode, bind address, TLS paths, trusted proxies, storage paths, and ACME mode remain file/restart based.

## 5. Routes and API design

| Route | Method | Purpose |
|---|---:|---|
| `/login`, `/mfa`, `/logout` | GET/POST | two-stage administrator authentication |
| `/locale` | POST | store German/English selection in the hardened locale cookie |
| `/admin` | GET | root-confined file browser |
| `/admin/account` | GET | current user and own credential actions |
| `/admin/account/password` | POST | change own password after reauthentication |
| `/admin/account/mfa/start`, `/admin/account/mfa/confirm` | POST | staged TOTP replacement |
| `/admin/account/security-keys/register/start`, `/finish` | POST | register WebAuthn/FIDO2 security keys |
| `/admin/preview`, `/admin/preview/raw` | GET/HEAD | administrator preview page/raw media |
| `/admin/shares` | GET/POST | list and create Shares |
| `/admin/admins` | GET/POST | list and create administrators |
| `/admin/settings`, `/admin/audit` | GET/POST | runtime settings and audit |
| `/v/:token`, `/s/:alias` | GET | public Share landing page |
| `/v/:token/unlock` | POST | unlock a password-protected Share |
| `/v/:token/download`, `/download.zip` | GET/HEAD | streamed file or ZIP transfer |
| `/v/:token/upload` | POST | streamed public upload |

`max_downloads` counts completed content transfers (download, ZIP, counted preview), not public metadata/landing requests or uploads. `HEAD` returns metadata only when the equivalent `GET` could begin under the current transfer session and does not itself consume quota.

The session-based JSON API under `/api/v2` uses the same secure cookies, MFA sessions, CSRF rules, SecureFS access, SQLite operations, and audit events as the HTML UI. Version 0.6.0 intentionally has no API tokens. Mutating administrator API routes require `X-CSRF-Token`. Every `/api/v2` error message is English regardless of locale cookie or `Accept-Language`.

After `/api/v2/session/mfa`, clients must retain both the rotated `Set-Cookie` value and returned `csrf_token`; the pre-MFA token becomes invalid. Before a password-protected Share is unlocked, public metadata returns only `{"locked":true}`. The unlock response returns an upload CSRF token sent as multipart field `csrf` by browser forms or `X-VaultLink-Upload-CSRF` by API clients.

Important API routes:

| Route | Method | Purpose |
|---|---:|---|
| `/api/v2/health` | GET | compatible process/version liveness alias |
| `/api/v2/health/live` | GET | cheap process/version liveness |
| `/api/v2/health/ready` | GET | database and descriptor-bound storage readiness |
| `/api/v2/session/login`, `/mfa`, `/logout`, `/me` | GET/POST | session lifecycle |
| `/api/v2/files` | GET/PATCH/DELETE | JSON file browser and mutations |
| `/api/v2/shares`, `/api/v2/shares/:id` | GET/POST/PATCH/DELETE | Share lifecycle |
| `/api/v2/admins` | GET/POST | administrator lifecycle |
| `/api/v2/settings` | GET/PUT | runtime settings |
| `/api/v2/audit` | GET | paginated audit events |
| `/api/v2/public/shares/:token` | GET | public Share metadata |
| `/api/v2/public/shares/:token/unlock` | POST | unlock protected Share |
| `/api/v2/public/shares/:token/download` | GET/HEAD | safe streamed download |
| `/api/v2/public/shares/:token/upload` | POST | safe streamed upload |
| `/api/v2/public/shares/:token/preview` | GET | safe preview |
| `/api/v2/public/shares/:token/download.zip` | GET | safe ZIP transfer |

`GET /api/v2/shares` accepts `limit` (default 50, range 1–200), `cursor`, `q`,
`status=all|active|protected|expired|limit|inactive`, and
`sort=newest|oldest`. It returns
`{"shares":[...],"next_cursor":<id|null>}`. All other v2 response schemas match
their former v1 counterparts; the v1 router is intentionally absent.

JSON errors have this envelope:

```json
{ "error": { "code": "forbidden", "message": "..." } }
```

Internal absolute paths, password hashes, session/unlock/preview/transfer hashes, and TOTP secrets are not returned. TOTP secrets are shown once after administrator creation or MFA reset.

All three health routes are unauthenticated. Liveness does not touch SQLite or storage. Readiness returns `503` with `{"ok":false,"version":"..."}` when either dependency is unavailable, while details are written only to structured logs. Operators and orchestrators should use `/health/live` for liveness and `/health/ready` for traffic admission and upgrade checks.

## 6. UI and UX

The administrator UI includes login, MFA, files, Shares, administrators, settings, audit, and My account. Users can reauthenticate to change their password, replace TOTP in two stages, and register multiple WebAuthn/FIDO2 security keys. Hardware MFA is enabled only with at least two registered keys; the set cannot be reduced from two to one. TOTP and the local SSH recovery path remain available.

WebAuthn credentials are bound to RP ID and browser origin. Registration must use the final public HTTPS URL. The setup tunnel on `127.0.0.1:8090` is only for bootstrap/TOTP and cannot register a key for the later public domain.

Setup, login, administrator, and public pages support German and English. A valid `vaultlink_locale` cookie selects the language; without it, English is always used and `Accept-Language` is ignored. The DE/EN switch stores the cookie for one year. Dynamic usernames, filenames, aliases, and audit values are never translated.

Text previews use an extension allowlist and escaped `<pre>` output. Image previews use an allowlist, fixed content types, and `nosniff`. PDF previews are served as `application/pdf` inline without server rendering. Public raw previews require a short-lived Share/path-bound token. Counted transfers are committed only after complete delivery; range requests share a fixed 15-minute resume grant that repeated requests cannot extend indefinitely.

## 7. HTTPS and operating modes

### Reverse proxy (recommended)

VaultLink listens locally, for example on `127.0.0.1:8080`, while Caddy or Nginx terminates HTTPS. `trusted_proxies` is both the exact direct-peer allowlist and the Forwarded-header trust boundary. For an external proxy, explicitly enable non-loopback binding and include the real proxy IP plus the local readiness peer:

```toml
[server]
mode = "reverse_proxy"
listen_address = "0.0.0.0:8080"

[reverse_proxy]
enabled = true
allow_non_loopback = true
trusted_proxies = ["192.0.2.10", "127.0.0.1"]
trust_x_forwarded_headers = true
```

Replace `192.0.2.10` with the real proxy IP. See [deploy/vaultlink-external-proxy-network.conf](deploy/vaultlink-external-proxy-network.conf). For large uploads through Nginx/Nginx Proxy Manager:

```nginx
client_max_body_size 1g;
proxy_request_buffering off;
proxy_buffering off;
```

### Standalone TLS with PEM files

`certificate_source = "files"` reads `cert_file` and `key_file`. The private key must use mode `0400`, `0440`, `0600`, or `0640`. `root:vaultlink` with group-read-only access is supported; other members of that dedicated group are inside the administrative trust boundary. With `reload_on_cert_change = true`, `systemctl reload vaultlink` reloads PEM files through SIGHUP and keeps the previous TLS configuration if the replacement is invalid.

For port 443 without root:

```sh
sudo install -m 0644 deploy/vaultlink-standalone-capability.conf /etc/systemd/system/vaultlink.service.d/standalone-capability.conf
sudo systemctl daemon-reload
sudo systemctl restart vaultlink
```

### Standalone TLS with built-in Let's Encrypt

`certificate_source = "letsencrypt"` uses `rustls-acme` with `tls-alpn-01` on port 443. The ACME cache is below `data_directory`, for example `/var/lib/vaultlink/acme`. The runtime `public_base_url` cannot diverge from the certificate domain in `config.toml`.

```toml
[server]
mode = "standalone_tls"
listen_address = "0.0.0.0:443"
public_base_url = "https://files.example.com"
production_mode = true

[reverse_proxy]
enabled = false

[tls]
enabled = true
certificate_source = "letsencrypt"
hsts_enabled = false
reload_on_cert_change = false
letsencrypt_contact_email = "admin@example.com"
letsencrypt_cache_dir = "acme"
letsencrypt_staging = true
```

Test first with `letsencrypt_staging = true` and `hsts_enabled = false`. For production, set staging to false and then enable HSTS. VaultLink must itself be publicly reachable on port 443.

## 8. Native package deployment

VaultLink 0.6.0 supports only the exact native packages listed in
[docs/PACKAGING.md](docs/PACKAGING.md): Debian 13 and Ubuntu 24.04/26.04 on
amd64/arm64, Fedora 44 on x86_64/aarch64, and the release-date Arch snapshot on
x86_64. Install the matching package from the GitHub release after verifying
both its direct Minisign signature and its digest in the signed global
`SHA256SUMS`:

```sh
# Set PACKAGE to exactly one matching release asset, for example
# vaultlink_0.6.0-1+deb13_amd64.deb,
# vaultlink_0.6.0-1+ubuntu24.04_arm64.deb,
# vaultlink-0.6.0-1.fc44.x86_64.rpm, or
# vaultlink-0.6.0-1-x86_64.pkg.tar.zst.
: "${PACKAGE:?set PACKAGE to the exact asset for this host}"
# Obtain minisign.pub through a separately trusted copy of this repository;
# its key ID is EC6AEC772F7CDDEC.
PUBLIC_KEY=/path/to/trusted/minisign.pub

# Freeze every input in one root-only staging directory *before* verification.
# PACKAGE must be a basename, not a path containing '/'.
case "$PACKAGE" in */*|'') exit 64 ;; esac
STAGE=$(sudo mktemp -d /var/tmp/vaultlink-release-0.6.0.XXXXXXXX)
test "$(sudo stat -c '%u:%g:%a' "$STAGE")" = 0:0:700
sudo install -o root -g root -m 0600 \
  "$PACKAGE" "$PACKAGE.minisig" SHA256SUMS SHA256SUMS.minisig \
  "$PUBLIC_KEY" "$STAGE/"
ROOT_PACKAGE="$STAGE/$PACKAGE"
ROOT_PUBLIC_KEY="$STAGE/$(basename -- "$PUBLIC_KEY")"
test "$(sudo sha256sum "$ROOT_PUBLIC_KEY" | awk '{ print $1 }')" = \
  200d64c2f2e42ace790a6d74f8b101801065b2d9a51c8fdda5b47b4f2b2f9809

sudo env STAGE="$STAGE" PACKAGE="$PACKAGE" ROOT_PUBLIC_KEY="$ROOT_PUBLIC_KEY" \
  sh -eu -c '
    cd "$STAGE"
    minisign -V -q -p "$ROOT_PUBLIC_KEY" -m SHA256SUMS -x SHA256SUMS.minisig
    awk -v package="$PACKAGE" \
      '\''NF == 2 && $2 == package && $1 ~ /^[0-9a-f]{64}$/ { print }'\'' \
      SHA256SUMS > package.sha256
    test "$(wc -l < package.sha256)" -eq 1
    sha256sum -c package.sha256
    minisign -V -q -p "$ROOT_PUBLIC_KEY" -m "$PACKAGE" -x "$PACKAGE.minisig"
    rm -f package.sha256
  '

# Debian or Ubuntu: require the exact signed-package dependency set and prove
# every dependency fully installed before dpkg is allowed to unpack anything.
DEB_DEPENDS=$(sudo dpkg-deb -f "$ROOT_PACKAGE" Depends)
test "$DEB_DEPENDS" = \
  'ca-certificates, curl, libc6, libgcc-s1, mawk, minisign, sqlite3, systemd'
for dependency in ca-certificates curl libc6 libgcc-s1 mawk minisign sqlite3 systemd; do
  test "$(dpkg-query -W -f='${db:Status-Status}' "$dependency" 2>/dev/null)" = \
    installed
done
sudo dpkg -i "$ROOT_PACKAGE"

# Fedora
sudo rpm -Uvh "$ROOT_PACKAGE"

# Arch Linux: extract the installer from that same verified root-owned copy.
ROOT_INSTALLER="$STAGE/vaultlink-package-install.sh"
sudo sh -eu -c '
  bsdtar -xOf "$1" \
    usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh >"$2"
  chown root:root "$2"
  chmod 0700 "$2"
' sh "$ROOT_PACKAGE" "$ROOT_INSTALLER"
sudo "$ROOT_INSTALLER" "$ROOT_PACKAGE"
```

Remove the staging directory after the package manager or Arch wrapper has
completed. Never verify a user-writable pathname and later pass that pathname
to a privileged package operation; the verified object and installed object
must be the same root-owned file.

These commands do not use a VaultLink package repository. The DEB dependency
check above is a mandatory offline preflight of the exact `Depends` field; do
not run `dpkg -i` until every listed package reports `installed`. If `dpkg -i`
nevertheless fails for a missing dependency after leaving `vaultlink`
unpacked, keep the application service and update timer inactive and disabled,
install the missing dependency manually with the operating system's package
manager, and continue that same transaction only with
`sudo dpkg --configure vaultlink`. Do not run `dpkg -i` again over the unpacked
package. Stop for manual recovery if the package database, candidate, marker,
or runtime cannot subsequently prove exact parity. RPM and Arch likewise
require their complete dependencies before the offline VaultLink package
transaction. `cifs-utils` is required only when VaultLink itself provisions or
mounts SMB storage.

Do not use a direct initial `pacman -U`. Pacman 7 can register a package even
when an `.INSTALL` hook rejects unsafe pre-existing state, so VaultLink's
signed, embedded Arch wrapper performs the fail-closed preflight and verifies
the postconditions around `pacman -U`. Package updates are still performed by
the verified VaultLink updater through Pacman.

On Arch, ordinary removal must use the installed, signed
`/usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh` wrapper. A
later reinstall must use `vaultlink-package-install.sh` extracted from the
new, root-staged, Minisign-verified package as shown above. Direct
`pacman -R vaultlink` and direct manual reinstall with `pacman -U` are
unsupported. Removal, reinstall, and signed updates preserve both the
intentional absence of `/etc/vaultlink/update.conf` and, when it is present,
the same file, inode, bytes, owner, mode, and modification time.

The package installs a candidate under `/usr/lib/vaultlink/package`, creates a
package-bound installation marker, and places the initial runtime under
`/opt/vaultlink`. It never creates or overwrites a production `config.toml` and
does not enable or start the service or updater timer. Existing markerless
archive installations are rejected; the withdrawn 0.5.0 archive has no
supported in-place upgrade path to 0.6.0.

Adjust `ReadWritePaths=/mnt/storage` with a systemd drop-in when using another
validated mount base. Packaged examples include the equivalent of
[deploy/mnt-storage.mount.example](deploy/mnt-storage.mount.example) and
[deploy/vaultlink-external-storage.conf](deploy/vaultlink-external-storage.conf).

The package also installs the root-owned updater as
`/usr/sbin/vaultlink-update`. Its daily timer and automatic installation remain
disabled until the administrator explicitly opts in:

```sh
sudo vaultlink-update check
sudo vaultlink-update install

# Optional unattended updates: bootstrap the packaged example once, then review it.
if sudo test ! -e /etc/vaultlink/update.conf && \
   sudo test ! -L /etc/vaultlink/update.conf; then
  sudo install -o root -g root -m 0644 \
    /usr/share/vaultlink/update.conf.example /etc/vaultlink/update.conf
fi
sudoedit /etc/vaultlink/update.conf
sudo systemctl enable --now vaultlink-update.timer
```

Set exactly `auto_install=true` to permit `auto` to install a newer signed
package, and only while `vaultlink.service` was already active. A deliberately
stopped service remains stopped. Signed updater installation and its automatic
recovery verify both the new and currently installed release packages and use
no distro repository during the transaction. A standalone rollback first requires
the matching signed target package to be installed, then binds the frozen
root-only backup to that package's database record, candidate, and runtime
guard before activation. Both paths preserve state and require package
database, candidate, active binary, and readiness versions to agree.

Every service start first runs the root-owned package/runtime parity guard.
`StartLimitIntervalSec=1h` and `StartLimitBurst=3` bound repeated fail-closed
starts after a crash or power loss. The root updater needs
`ProtectSystem=false` because native package-manager hooks have distro-owned
write sets. `NoNewPrivileges=true` remains active. Exactly the six bounded
transaction capabilities are carried across package-manager and scriptlet
execs; the `vaultlink` credential boundary drops all permitted, effective, and
ambient capabilities before a candidate is executed. Full-system gates verify
that boundary on every target. All unrelated namespace, device, kernel,
process, and network hardening remains enabled, and the oneshot is bounded by
`TimeoutStartSec=90min` and `TimeoutStopSec=30min`.

Fedora updater transactions use RPM's `--nocontexts` option because RPM's
scriptlet-specific SELinux domain transition is incompatible with the retained
`NoNewPrivileges=true` boundary. SELinux itself remains `Enforcing`; this
narrow transaction mode is entered only after the signed RPM, exact reviewed
scriptlets, metadata, payload allowlist, and dependencies have passed the
updater's fail-closed validation. Initial manual RPM installation continues to
use normal SELinux context handling, and the booted Fedora gate verifies the
actual update-unit path with no VaultLink-related AVC denial.

### Provision a CIFS mount safely

First create `.vaultlink-internal/{uploads,tombstones}` on the SMB server with the ACLs described above. Then provision the mount as root; the password is read interactively from the terminal and is never a CLI argument:

```sh
sudo /opt/vaultlink/vaultlink provision-cifs \
  --source //fileserver.example/vaultlink \
  --username vaultlink-service \
  --domain EXAMPLE
```

This command is intentionally confined to `/mnt/storage`, creates only new files, and refuses to overwrite existing credentials or systemd units. It enforces SMB 3.1.1 signing, encryption, strict caching, and the hardened mount flags described above.

### Initial browser setup through an SSH tunnel

Open a normal SSH session:

```sh
ssh admin@server.example.com
```

Start setup as the eventual service user in a private staging directory:

```sh
sudo install -d -o vaultlink -g vaultlink -m 0700 /var/lib/vaultlink/setup
sudo -u vaultlink /opt/vaultlink/vaultlink setup \
  --config /var/lib/vaultlink/setup/config.toml \
  --listen 127.0.0.1:8090
```

Open the printed IPv4 tunnel in a second local terminal:

```sh
ssh -4 -N -L 127.0.0.1:8090:127.0.0.1:8090 admin@server.example.com
```

Open `http://127.0.0.1:8090/?token=...` locally. After safely storing the TOTP secret, stop setup with Ctrl+C instead of starting the server directly, then install the generated configuration and start the service:

```sh
sudo install -o root -g vaultlink -m 0640 \
  /var/lib/vaultlink/setup/config.toml /etc/vaultlink/config.toml
sudo -u vaultlink rm /var/lib/vaultlink/setup/config.toml
sudo rmdir /var/lib/vaultlink/setup
sudo -u vaultlink test -r /etc/vaultlink/config.toml
sudo systemctl enable --now vaultlink
```

Never expose setup with `--listen 0.0.0.0:8090`; no non-loopback exception exists.

### Configuration without browser setup

```sh
sudo install -o root -g vaultlink -m 0640 config/production-reverse-proxy.toml /etc/vaultlink/config.toml
sudo -u vaultlink /opt/vaultlink/vaultlink init-admin --config /etc/vaultlink/config.toml --username admin
sudo systemctl enable --now vaultlink
```

### Local administrator recovery

Always run recovery as `vaultlink` so SQLite/WAL/SHM ownership stays correct:

```sh
# Reset only the password
sudo -u vaultlink /opt/vaultlink/vaultlink recover-admin \
  --config /etc/vaultlink/config.toml \
  --username admin \
  --reset-password

# Reset only MFA
sudo -u vaultlink /opt/vaultlink/vaultlink recover-admin \
  --config /etc/vaultlink/config.toml \
  --username admin \
  --reset-mfa

# Replace password and MFA atomically
sudo -u vaultlink /opt/vaultlink/vaultlink recover-admin \
  --config /etc/vaultlink/config.toml \
  --username admin \
  --reset-password \
  --reset-mfa
```

If the configuration cannot be validated, address the database directly:

```sh
sudo -u vaultlink /opt/vaultlink/vaultlink recover-admin \
  --database /var/lib/vaultlink/data.sqlite \
  --username admin \
  --reset-password \
  --reset-mfa
```

Recovery revokes the administrator's sessions and pending MFA enrollments and writes an audit event without credentials. It does not reactivate a deactivated administrator. There is intentionally no public password/MFA reset endpoint.

## 9. Linux development

```sh
sudo apt update && sudo apt install -y build-essential coreutils curl libssl-dev pkg-config sqlite3 util-linux
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
make dev-setup
cargo run -- init-admin --config config/development.toml --username admin
make run
```

`make sample-data` creates `dev/mount` and `dev/data`. With Docker available, `make docker-smoke` builds the digest-pinned Debian-13/Rust image and runs setup, API, load-fixture, soak-evidence, upgrade, and rollback tests without external container networking. Individual Docker targets remain available. The [container setup entrypoint](docs/CONTAINER-SETUP.md) keeps VaultLink on loopback and publishes a separate proxy port. `make policy-check` validates project supply-chain rules.

## Troubleshooting

- Startup refused: verify config mode, HTTPS URL, loopback/trusted proxies, PEM/ACME settings, and the storage mount identity.
- Built-in ACME fails: DNS must point to the server, VaultLink must terminate port 443 itself, and Nginx/Caddy must not be in front.
- File request returns 403: path validation or the symlink boundary rejected it.
- Upload returns 409: no-overwrite is the default. Without external writers, replacement must be enabled per link and confirmed per upload; co-writer mode keeps it disabled unless its explicit risk opt-in is set.
- SMB startup refused: verify source/type/options in `/proc/self/mountinfo`, the pre-existing `.vaultlink-internal` layout, mode `0700`, server ACL, and local SQLite filesystem.
- TLS remains old after renewal: inspect `systemctl status vaultlink`, PEM permissions, and the journal.

## License

MIT.
