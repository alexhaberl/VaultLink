# Upgrade, backup and rollback

VaultLink has one database baseline: schema 1. There is no supported migration from an older schema, no legacy WebAuthn credential conversion and no rollback to a plaintext-secret database. A database whose `PRAGMA user_version` or table shape differs from the expected schema is rejected at startup.

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

The script intentionally performs no schema, alias, credential or storage-layout migration. Use it only between builds that operate on this schema-1 baseline.

## Rollback

Run:

```sh
sudo deploy/vaultlink-rollback.sh /var/lib/vaultlink-backups/TIMESTAMP
```

Rollback accepts only a complete backup containing all four files. Before replacement it creates a complete emergency backup of the current state. The requested binary must not be newer than the installed binary, and both must use the schema-1 baseline. The database and keyring are staged and replaced together while the service is stopped; stale WAL sidecars are removed before restart.

If rollback activation fails, the emergency four-file unit is restored automatically. Do not use this workflow to install a binary expecting another schema or the former plaintext layout.

## Secret rotation

Rotate Share-token and TOTP encryption keys with exactly one database source:

```sh
sudo -u vaultlink /opt/vaultlink/vaultlink rotate-secrets \
  --database /var/lib/vaultlink/data.sqlite
```

Alternatively pass `--config /etc/vaultlink/config.toml`. Rotation requires exclusive access to `secrets.keyring`; stop the service first. The new key is made durable before ciphertexts are rewritten in an `IMMEDIATE` transaction, and the previous key is removed only after the database commit.

## Recovery rules

- Restore only a matching database/keyring pair from the same backup directory.
- Keep the service stopped while manually replacing either file.
- Preserve owner and mode, remove stale `data.sqlite-wal` and `data.sqlite-shm`, then start VaultLink.
- Startup authenticates all persisted Share and TOTP ciphertexts. A missing key, wrong key, modified nonce, modified AAD or corrupt ciphertext aborts startup.
- `recover-admin --database /var/lib/vaultlink/data.sqlite` loads the adjacent keyring automatically.

Backups contain password hashes, encrypted credentials, sessions, audit data and the keys needed to decrypt persistent secrets. Protect them like production credentials and retain them only as long as operationally required.
