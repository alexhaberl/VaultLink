# Upgrade and rollback

Never upgrade a running process in place. Verify the release checksum and Minisign signature first.

## Upgrade

1. Download and verify the new amd64 artifact.
2. Extract it outside `/opt/vaultlink`.
3. Run `sudo deploy/vaultlink-upgrade.sh /path/to/new/vaultlink`.
4. The script stops VaultLink, stores the previous binary and a consistent SQLite backup below `/var/lib/vaultlink/backups/`, verifies the backup, installs the binary atomically, and starts the service.
5. Check `systemctl status vaultlink`, the journal, login/MFA, one protected share, upload, full download, and range download through the public Nginx URL.

Schema migrations run in one SQLite transaction. A database with a schema newer than the binary supports is rejected at startup.

## Rollback

Run `sudo deploy/vaultlink-rollback.sh /var/lib/vaultlink/backups/TIMESTAMP`. The service is stopped before the previous binary and database are restored. The script removes stale WAL sidecars, starts VaultLink, and verifies that systemd reports it active.

Retain backups until the soak gate has passed. Backups contain password hashes, TOTP secrets, sessions, share tokens, and audit data and must be protected like the live database.
