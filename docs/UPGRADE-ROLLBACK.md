# Upgrade and rollback

Never upgrade a running process in place. Select the release matching the host architecture and verify its Minisign signatures and checksum manifest first.

## Mandatory 0.4.0 to 0.4.1 storage migration

Before upgrading a deployment whose visible tree is on SMB/CIFS, quiesce public traffic, stop VaultLink and stop every direct SMB writer. Keep the service inactive for the entire storage migration. Take a server-side snapshot or metadata-preserving backup of the complete SMB tree and save the complete 0.4.0 configuration. A 0.4.0 binary cannot parse the new 0.4.1 storage fields.

Inventory the old visible root before creating anything. Resolve every existing `shared`, `.vaultlink-internal`, case-insensitive/trailing-dot/space alias of those names, old `.vaultlink-*.part` upload fragment and delete-tombstone collision as user data; never let 0.4.1 mistake an old user entry for its private namespace. Create a new empty `shared/`, then move every existing visible entry, including dotfiles, into it with one quiesced server-side operation that preserves ownership, ACLs and extended attributes. Verify counts, paths and content hashes against the snapshot before changing the SMB client export or starting VaultLink.

Provision the sibling `.vaultlink-internal/{uploads,tombstones}` only after the inventory is clean. Use a dedicated VaultLink SMB account. Co-writers receive Modify rights only within `shared/` and no administrative rights on the share root. Server ACLs must deny them read, write, delete, rename, parent `DELETE_CHILD`, ACL/owner changes (`WRITE_DAC`/`WRITE_OWNER`) and chmod/chown/setfacl-equivalent access to the internal tree. Then install the hardened mount unit/drop-in and prepare a **separate candidate configuration** with:

```toml
root_mount_path = "/mnt/storage/shared"
data_directory = "/var/lib/vaultlink"
internal_directory = "/mnt/storage/.vaultlink-internal"
require_mount = true
external_writers = true
expected_filesystem_type = "cifs"
expected_mount_source = "//fileserver.example/vaultlink"
```

Verify the visible-tree migration and server ACLs with the VaultLink account and with every co-writer account before starting the candidate. The candidate requires an explicit mount identity in every production mode, rejects an unmounted local fallback, and rejects SQLite/WAL on a network filesystem. Do not replace `/etc/vaultlink/config.toml` manually: it must remain the old live configuration until the upgrade script activates the new Binary/Config pair with the service stopped.

For rollback to 0.4.0, stop VaultLink and every SMB writer first. Reverse the server-side layout from the snapshot, restore the previous export/ACL boundary and verify it before invoking the rollback script. Do not point 0.4.0 at the new Co-Writer layout: its old in-tree staging model is not safe for this mode. The rollback backup contains the matching 0.4.0 Binary/Config/SQLite triple, but it cannot reverse an external SMB-server migration.

## Upgrade

1. Map `x86_64` to the `amd64` release and `aarch64`/`arm64` to the `arm64` release. Download the matching archive, standalone binary, SBOM, `SHA256SUMS-ARCH`, and their available `.minisig` files. Reject all other host architectures.
2. Extract it outside `/opt/vaultlink`.
3. Keep the current live configuration untouched and run `sudo deploy/vaultlink-upgrade.sh /path/to/new/vaultlink /path/to/new-config.toml`. For the 0.4.0-to-0.4.1 migration the script verifies that `vaultlink.service` was already stopped; it refuses to perform this external-storage migration from an active service.
4. The script requires an existing executable, configuration, and database plus `curl`, `flock`, `runuser`, `sqlite3`, and GNU `timeout`. A shared non-blocking maintenance lock excludes concurrent upgrades and rollbacks. Before downtime it stages both Binary/Config pairs on their destination filesystems, validates each pair as the unprivileged `vaultlink` account and derives separate old/new readiness targets. It stops VaultLink, creates and verifies a consistent SQLite backup, publishes a complete old `vaultlink`/`config.toml`/`data.sqlite` backup set below the root-only `/var/lib/vaultlink-backups/` (`0700`, files `0700/0600/0600`), then activates the staged candidate Binary and Config with per-file atomic renames before starting the service.
5. After the local gate succeeds, verify the exact public HTTP status and candidate health body from an external vantage with the separate check below. Then check `systemctl status vaultlink`, the journal, login/MFA, one protected share, upload, full download, and range download through the public URL.

Use a previously pinned copy of `release/minisign.pub`; a public key obtained
only from the same unverified download is not a trust anchor. From the directory
containing all four architecture-specific release inputs, verify before
extraction:

```sh
version=0.4.1
case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "unsupported architecture" >&2; exit 1 ;;
esac
archive="VaultLink-${version}-debian13-${arch}.tar.gz"
binary="vaultlink-${version}-debian13-${arch}"
checksums="SHA256SUMS-${arch}"
minisign -V -p /path/to/pinned/minisign.pub -m "$archive" -x "$archive.minisig"
minisign -V -p /path/to/pinned/minisign.pub -m "$binary" -x "$binary.minisig"
minisign -V -p /path/to/pinned/minisign.pub -m "$checksums" -x "$checksums.minisig"
sha256sum -c "$checksums"
```

```sh
expected_version=0.4.1
response=$(curl --disable --silent --show-error --noproxy '*' --proto '=https' \
    --connect-timeout 5 --max-time 15 --header 'Accept: application/json' \
    --output - --write-out '\n%{http_code}' \
    https://PUBLIC_HOST/api/v1/health) || exit
expected=$(printf '{"ok":true,"version":"%s"}\n200' "$expected_version")
test "$response" = "$expected"
```

Schema migrations run in one SQLite transaction. A database with a schema newer than the binary supports is rejected at startup.

If staging or Binary/Config pairing fails, the service is never stopped and the live configuration is unchanged. If backup or integrity validation fails after the stop, the incomplete backup is removed and a previously active service is restarted with the unchanged installation. If activation, startup, local readiness, or the post-start database check fails, the script restores the verified old Binary/Config/SQLite triple and checks it against the old readiness target. A `CRITICAL` message means automatic recovery itself failed and the reported backup path must be used manually.

The three live files reside on different filesystems and cannot be committed by one POSIX rename. The service is stopped and every replacement is pre-staged and renamed atomically on its own filesystem, which handles normal command errors and trapped signals. It does not claim power-loss or `SIGKILL` atomicity between those renames. After an interrupted host-level activation, keep the service and SMB writers stopped and restore one complete verified backup triple before continuing.

### Local readiness gate

The automatic rollback decision uses only a direct request to the local VaultLink listener. It retries for up to 30 attempts within an overall 60-second budget, with a one-second interval, a two-second connect timeout, and a three-second total timeout per request. Responses are capped at 4 KiB. Success requires HTTP 200 and the candidate's exact compact response, for example `{"ok":true,"version":"0.4.1"}`. A delayed listener is retried; HTTP 500, malformed JSON, a wrong version, oversized responses, and transport timeouts fail the gate.

In reverse-proxy mode the request goes directly to local HTTP. In standalone-TLS mode curl keeps the public hostname for the TLS SNI value but uses `--connect-to` to reach the local listener, `--noproxy '*'` to bypass proxy environment variables, and `--insecure` for this local application gate only. Public DNS, proxy routing, certificate trust, and certificate expiry therefore cannot trigger a database rollback.

The retry values can be overridden for controlled tests with `VAULTLINK_READINESS_ATTEMPTS`, `VAULTLINK_READINESS_TIMEOUT_SECONDS`, `VAULTLINK_READINESS_INTERVAL_SECONDS`, `VAULTLINK_READINESS_CONNECT_TIMEOUT_SECONDS`, and `VAULTLINK_READINESS_MAX_TIME_SECONDS`. The public URL must still be tested separately from an external vantage after the script succeeds because that check intentionally does not participate in automatic recovery.

## Rollback

Run `sudo deploy/vaultlink-rollback.sh /var/lib/vaultlink-backups/TIMESTAMP`. The requested Binary/Config pair and SQLite database are verified and pre-staged before downtime under the shared maintenance lock. After stopping VaultLink, the script first creates a complete verified `rollback-pre-TIMESTAMP` emergency triple of the current state, restores the requested Binary, Config and database, removes stale WAL sidecars, starts VaultLink, and verifies systemd, exact local health JSON and SQLite integrity. It prints the emergency-backup path on success. If rollback activation fails, the complete emergency triple is restored automatically; a failed recovery stop or incomplete restore remains fail-closed and is never restarted.

Retain backups until the soak gate has passed. Backups contain the full configuration plus password hashes, TOTP secrets, sessions, share tokens and audit data and must be protected like the live database.

Every `.vaultlink-internal/tombstones/*.pending` entry has a durable sibling `*.pending.manifest` containing the original relative path as a JSON string. VaultLink normally restores an uncommitted pending delete with a no-clobber rename during startup and removes the manifest only after both directory renames are durable. If a co-writer reused the visible name, both objects and the manifest are retained and the journal reports `private recovery entry was preserved` with the full path.

For manual recovery, stop VaultLink, validate the manifest and both objects, then restore only with a no-clobber rename after confirming the visible destination is free. Never automatically delete pending entries or orphan manifests: a manifest can be deliberately retained after an uncertain directory sync and is the crash journal if the server later exposes the pending state again.

An automatic rollback restores the database snapshot taken before the candidate started. Writes accepted during the short candidate health-check window can therefore be lost. Quiesce public traffic for upgrades where that window is unacceptable.
