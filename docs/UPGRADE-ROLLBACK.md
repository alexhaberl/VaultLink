# Upgrade, backup and rollback

VaultLink currently uses schema 2. Fresh databases are created directly at schema 2, and a validated schema-1 database is migrated once to schema 2 in an `IMMEDIATE` transaction. The migration adds `vaultlink_schema_migrations`, records target version 2, updates the schema fingerprint and changes `PRAGMA user_version` last. Startup rejects future versions, unknown versions, non-empty unversioned databases, fingerprint mismatches and legacy plaintext-secret layouts.

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

The candidate binary performs any supported forward schema migration when it starts. The upgrade script does not edit schemas, aliases, credentials or storage layouts itself. Because startup can advance the database to schema 2, keep the complete pre-upgrade backup until the candidate has been accepted.

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
