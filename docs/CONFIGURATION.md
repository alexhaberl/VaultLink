# Configuration and storage

[Back to README](../README.md)

Choose the storage layout and HTTPS mode before completing
[installation](INSTALLATION.md). Examples in this checkout describe the 0.7.0
development branch; the configurable `[admission]` section is new in 0.7.0.
Use configuration examples from the matching release when installing 0.6.0.

Known 0.6.0 limitation: CIFS startup can fail with `missing required security
option "sign"` even when the SMB session is signed and encrypted. That release
checks for a standalone mountinfo entry that Linux does not emit. Changing only
the mount command cannot fix the application check. Local ext4 installations
are unaffected by this defect. The correction is included in the unreleased
0.7.0 branch; 0.6.0 remains the supported release until its replacement is published.

## Configuration model

Examples:

- [config/development.toml](../config/development.toml)
- [config/production-reverse-proxy.toml](../config/production-reverse-proxy.toml)
- [config/production-standalone-tls.toml](../config/production-standalone-tls.toml)
- [config/production-standalone-letsencrypt.toml](../config/production-standalone-letsencrypt.toml)

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

**Since 0.7.0 (unreleased):** the optional `[admission]` section protects the reserved administrator capacity and slow-client boundaries. Omitted sections use the shown defaults. Operators may only tighten them: reduce parallelism/duration or increase minimum DATA-byte throughput. The global ceilings remain 32 uploads and 128 streams, leaving at least four upload and 32 stream slots outside the public pools.

```toml
[admission]
max_public_uploads = 28
max_uploads_per_share = 2
upload_min_bytes_per_second = 65536
upload_max_duration_seconds = 21600
max_public_streams = 96
max_streams_per_share = 16
stream_min_bytes_per_second = 16384
stream_max_duration_seconds = 21600
```

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
- `vers=3.1.1`, `sec=ntlmsspi` (or `sec=krb5i` for Kerberos), `seal`, `cache=strict`, `serverino`, `nosuid`, `nodev`, `noexec`, read-write status, and none of `cache=loose`, `nostrictsync`, `noperm`, `noserverino`, `multiuser`, or `signloosely`.
- No symlinks, nested mounts, or DFS submounts in user paths.
- `data_directory` and SQLite/WAL on a separately supported local filesystem; CIFS/NFS SQLite is rejected.
- External writers are trusted content publishers. Their changes bypass VaultLink authentication, audit, quotas, and link policy and therefore require SMB-server audit.
- `allow_external_writer_replace = true` explicitly accepts last-writer-wins lost-update risk.
- The SMB server must require SMB 3.1.1 signing and encryption for every direct client session; VaultLink's `seal` protects only its own Linux mount.

Other network filesystems with external writers are not approved in 0.7.0. Runtime-editable settings under `/admin/settings` include `public_base_url`, upload limits, blocked extensions, Share-password policy, unlock duration, ZIP/search/text/media preview limits and extensions, and PDF-preview status. Server mode, bind address, TLS paths, trusted proxies, storage paths, and ACME mode remain file/restart based.

Set the signed authentication mode explicitly when mounting CIFS. Linux reports
negotiated signing in `/proc/self/mountinfo` as the `i` suffix in `sec=ntlmsspi`
or `sec=krb5i`, rather than a standalone `sign` entry. With an unspecified mode,
the kernel can omit `sec=` entirely even for a signed session. VaultLink rejects
that ambiguous state; update the mount options and unmount/remount before
starting the service. The generated mount unit and example pin `sec=ntlmsspi`.
See the kernel's [CIFS security option reporting](https://github.com/torvalds/linux/blob/v6.12/fs/smb/client/cifsfs.c#L446-L478).

## HTTPS and operating modes

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

Replace `192.0.2.10` with the real proxy IP. See [deploy/vaultlink-external-proxy-network.conf](../deploy/vaultlink-external-proxy-network.conf). For large uploads through Nginx/Nginx Proxy Manager:

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
