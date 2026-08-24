# Upgrade, backup and rollback

VaultLink currently uses schema 6. Fresh databases are created directly at schema 6. Validated schema-1 through schema-5 databases advance through separate `IMMEDIATE` transactions. Schema 3 adds the share indexes `(active,id)` and `(active,expires_at)`; schema 4 adds administrator-session activity tracking; schema 5 adds audit retention priority; schema 6 reclassifies existing upload, replacement, upload-directory and durability-warning records as security priority under the centralized audit policy. The schema-3-to-4 migration deliberately revokes existing administrator sessions instead of guessing prior activity, while preserving all administrators, credentials, Shares and audit data. Each migration updates the schema fingerprint and changes `PRAGMA user_version` last. Startup rejects future versions, unknown versions, non-empty unversioned databases, fingerprint mismatches and legacy plaintext-secret layouts.

Schema migrations are forward-only. VaultLink does not migrate legacy plaintext WebAuthn or secret columns and does not perform an in-place schema downgrade. A rollback must restore the old binary, matching configuration, database and keyring from the same backup.

## The indivisible backup unit

Treat these four files as one security and recovery unit:

- `/opt/vaultlink/vaultlink`
- `/etc/vaultlink/config.toml`
- `/var/lib/vaultlink/data.sqlite`
- `/var/lib/vaultlink/secrets.keyring`

The SQLite database contains encrypted Share tokens and encrypted TOTP secrets. It is unusable without its matching keyring. The keyring must remain owned by `vaultlink:vaultlink`, mode `0600`; backup copies remain `root:root`, mode `0600`. Never copy only `data.sqlite`, and never combine a database with a keyring from another installation or backup.

## Upgrade

Run:

```sh
sudo deploy/vaultlink-upgrade.sh /path/to/new/vaultlink /path/to/new-config.toml
```

The script takes an exclusive maintenance lock, validates the installed and candidate Binary/Config pairs as the unprivileged service account, stages replacements, stops the service, creates a consistent SQLite backup, copies the matching keyring, verifies integrity and restrictive permissions, then activates the candidate. Readiness must return the exact candidate version before the upgrade succeeds.

If activation, startup, readiness or the post-start integrity check fails, the script restores the complete four-file backup. A `CRITICAL` message means automatic recovery failed; keep the service stopped and restore the reported backup directory manually.

The candidate binary performs any supported forward schema migration when it starts. The upgrade script does not edit schemas, aliases, credentials or storage layouts itself. Because startup can advance the database to schema 6, keep the complete pre-upgrade backup until the candidate has been accepted. Advancing from schema 3 signs out all administrators once.

## Signed GitHub release updater

The optional root-owned updater uses the fixed
`https://github.com/alexhaberl/VaultLink/releases/latest` endpoint. It accepts
only a stable `vMAJOR.MINOR.PATCH` tag, Debian 13, and the host's exact
`amd64`/`x86_64` or `arm64`/`aarch64` pairing. It does not accept a repository,
URL, channel, public key, architecture, or release version from its
configuration.

Before executing release content it downloads the architecture-specific
archive, its Minisign signature, `SHA256SUMS-ARCH`, and that manifest's
signature into a root-controlled temporary directory. Both signatures must verify
against `/usr/share/vaultlink/minisign.pub`; the signed checksum must match the
archive; every archive path must remain below its exact versioned root; links
and special files are rejected; the embedded public key must equal the pinned
installed key; and the candidate binary must report the tagged version.
Only root can modify the workspace or its contents. The exact candidate binary
is made traversable and executable by the unprivileged `vaultlink` account only
for its bounded version preflight; signatures, manifests, and helpers remain
root-only.

Install it from a previously verified release archive:

```sh
sudo apt install -y curl minisign
sudo install -d -o root -g root -m 0755 /usr/local/sbin /usr/share/vaultlink
sudo install -o root -g root -m 0755 deploy/vaultlink-update.sh /usr/local/sbin/vaultlink-update
sudo install -o root -g root -m 0644 minisign.pub /usr/share/vaultlink/minisign.pub
sudo install -o root -g root -m 0644 deploy/vaultlink-update.service deploy/vaultlink-update.timer /etc/systemd/system/
sudo test -e /etc/vaultlink/update.conf || sudo install -o root -g root -m 0644 deploy/vaultlink-update.conf.example /etc/vaultlink/update.conf
sudo systemctl daemon-reload
sudo systemctl enable --now vaultlink-update.timer
```

The commands are:

```sh
sudo /usr/local/sbin/vaultlink-update check
sudo /usr/local/sbin/vaultlink-update install
sudo /usr/local/sbin/vaultlink-update auto
```

`check` reports the installed and latest versions without downloading or
executing release assets. `install` installs only a newer verified release.
`auto` is used by the timer: it remains check-only when the configuration is
absent or contains `auto_install=false`, and installs when it contains exactly
`auto_install=true` and `vaultlink.service` is currently active. A deliberately
stopped service is never updated or started by the timer. Unknown, duplicate,
writable, non-root-owned, or malformed
configuration is rejected. Timer results are available through
`journalctl -u vaultlink-update.service`.

The updater executes the upgrade helper from the already verified release
archive so a candidate may carry its matching migration orchestration. That
helper still validates both Binary/Config pairs before downtime, holds the
shared maintenance lock, preserves the existing configuration, creates the
complete four-file backup, checks readiness and database integrity, and
automatically restores the previous unit on failure. A missing release,
network error, signature/checksum mismatch, unsupported host, downgrade,
pre-release, malformed archive, or failed upgrade leaves the installed service
unchanged. The Minisign trust key is never rotated automatically.

## Rollback

Run:

```sh
sudo deploy/vaultlink-rollback.sh /var/lib/vaultlink-backups/TIMESTAMP
```

Rollback accepts only a complete backup containing all four files. Before replacement it creates a complete emergency backup of the current state. The requested binary must not be newer than the installed binary. The database and keyring are staged and replaced together while the service is stopped; stale WAL sidecars are removed before restart.

If rollback activation fails, the emergency four-file unit is restored automatically. Never point an old binary at a database that a newer binary has migrated. To roll back across a schema migration, restore the matching old binary/config/database/keyring backup as one unit. Do not use this workflow to combine files from different backups or to install the former plaintext layout.

## Secret rotation

Rotate Share-token and TOTP encryption keys with exactly one database source:

```sh
sudo -u vaultlink /opt/vaultlink/vaultlink rotate-secrets \
  --database /var/lib/vaultlink/data.sqlite
```

Alternatively pass `--config /etc/vaultlink/config.toml`. Rotation requires exclusive access to `secrets.keyring`; stop the service first. The new key is made durable before ciphertexts are rewritten in an `IMMEDIATE` transaction, and the previous key is removed only after the database commit.

## Recovery rules

- Restore only a matching database/keyring pair from the same backup directory.
- Across a schema rollback, restore the matching binary and configuration from that directory as well; schema downgrades are not supported.
- Keep the service stopped while manually replacing either file.
- Preserve owner and mode, remove stale `data.sqlite-wal` and `data.sqlite-shm`, then start VaultLink.
- Startup authenticates all persisted Share and TOTP ciphertexts. A missing key, wrong key, modified nonce, modified AAD or corrupt ciphertext aborts startup.
- `recover-admin --database /var/lib/vaultlink/data.sqlite` loads the adjacent keyring automatically.

Backups contain password hashes, encrypted credentials, sessions, audit data and the keys needed to decrypt persistent secrets. Protect them like production credentials and retain them only as long as operationally required.
