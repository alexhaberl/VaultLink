# Upgrade and rollback

Never upgrade a running process in place. Verify the release checksum and Minisign signature first.

## Upgrade

1. Download and verify the new amd64 artifact.
2. Extract it outside `/opt/vaultlink`.
3. Run `sudo deploy/vaultlink-upgrade.sh /path/to/new/vaultlink`.
4. The script requires an existing executable and database. Before downtime it stages the candidate and previous binary on their destination filesystems. It then stops VaultLink, creates a consistent SQLite backup below `/var/lib/vaultlink/backups/`, verifies it, installs the binary atomically, and starts the service.
5. Check `systemctl status vaultlink`, the journal, login/MFA, one protected share, upload, full download, and range download through the public Nginx URL.

Schema migrations run in one SQLite transaction. A database with a schema newer than the binary supports is rejected at startup.

If staging fails, the service is never stopped. If backup or integrity validation fails after the stop, the incomplete backup is removed and a previously active service is restarted with the unchanged installation. If activation, startup, service health, or the post-start database check fails, the script restores the verified binary and database backup before restarting. A `CRITICAL` message means automatic recovery itself failed and the reported backup path must be used manually.

## Rollback

Run `sudo deploy/vaultlink-rollback.sh /var/lib/vaultlink/backups/TIMESTAMP`. The requested backup is verified and pre-staged before downtime. After stopping VaultLink, the script first creates a verified `rollback-pre-TIMESTAMP` emergency backup of the current state, restores the requested binary and database, removes stale WAL sidecars, starts VaultLink, and verifies systemd and SQLite health. It prints the emergency-backup path on success. If the rollback fails, that emergency backup is restored automatically and a previously active service is restarted.

Retain backups until the soak gate has passed. Backups contain password hashes, TOTP secrets, sessions, share tokens, and audit data and must be protected like the live database.

An automatic rollback restores the database snapshot taken before the candidate started. Writes accepted during the short candidate health-check window can therefore be lost. Quiesce public traffic for upgrades where that window is unacceptable.
