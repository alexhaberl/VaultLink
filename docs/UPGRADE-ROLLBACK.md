# Upgrade and rollback

Never upgrade a running process in place. Verify the release checksum and Minisign signature first.

## Upgrade

1. Download and verify the new amd64 artifact.
2. Extract it outside `/opt/vaultlink`.
3. Run `sudo deploy/vaultlink-upgrade.sh /path/to/new/vaultlink`.
4. The script requires an existing executable, configuration, and database plus `curl`, `runuser`, `sqlite3`, and GNU `timeout`. Before downtime it stages root-owned copies of the candidate and previous binary on the destination filesystem, then asks the staged candidate as the unprivileged `vaultlink` account to validate the configuration and derive its local readiness target. It stops VaultLink, creates a consistent SQLite backup below `/var/lib/vaultlink/backups/`, verifies it, installs the binary atomically, and starts the service.
5. After the local gate succeeds, verify the exact public HTTP status and candidate health body from an external vantage with the separate check below. Then check `systemctl status vaultlink`, the journal, login/MFA, one protected share, upload, full download, and range download through the public URL.

```sh
expected_version=0.3.2
response=$(curl --disable --silent --show-error --noproxy '*' --proto '=https' \
    --connect-timeout 5 --max-time 15 --header 'Accept: application/json' \
    --output - --write-out '\n%{http_code}' \
    https://PUBLIC_HOST/api/v1/health) || exit
expected=$(printf '{"ok":true,"version":"%s"}\n200' "$expected_version")
test "$response" = "$expected"
```

Schema migrations run in one SQLite transaction. A database with a schema newer than the binary supports is rejected at startup.

If staging fails, the service is never stopped. If backup or integrity validation fails after the stop, the incomplete backup is removed and a previously active service is restarted with the unchanged installation. If activation, startup, local readiness, or the post-start database check fails, the script restores the verified binary and database backup before restarting and checking the restored service locally. A `CRITICAL` message means automatic recovery itself failed and the reported backup path must be used manually.

### Local readiness gate

The automatic rollback decision uses only a direct request to the local VaultLink listener. It retries for up to 30 attempts within an overall 60-second budget, with a one-second interval, a two-second connect timeout, and a three-second total timeout per request. Responses are capped at 4 KiB. Success requires HTTP 200 and the candidate's exact compact response, for example `{"ok":true,"version":"0.3.2"}`. A delayed listener is retried; HTTP 500, malformed JSON, a wrong version, oversized responses, and transport timeouts fail the gate.

In reverse-proxy mode the request goes directly to local HTTP. In standalone-TLS mode curl keeps the public hostname for the TLS SNI value but uses `--connect-to` to reach the local listener, `--noproxy '*'` to bypass proxy environment variables, and `--insecure` for this local application gate only. Public DNS, proxy routing, certificate trust, and certificate expiry therefore cannot trigger a database rollback.

The retry values can be overridden for controlled tests with `VAULTLINK_READINESS_ATTEMPTS`, `VAULTLINK_READINESS_TIMEOUT_SECONDS`, `VAULTLINK_READINESS_INTERVAL_SECONDS`, `VAULTLINK_READINESS_CONNECT_TIMEOUT_SECONDS`, and `VAULTLINK_READINESS_MAX_TIME_SECONDS`. The public URL must still be tested separately from an external vantage after the script succeeds because that check intentionally does not participate in automatic recovery.

## Rollback

Run `sudo deploy/vaultlink-rollback.sh /var/lib/vaultlink/backups/TIMESTAMP`. The requested backup is verified and pre-staged before downtime. After stopping VaultLink, the script first creates a verified `rollback-pre-TIMESTAMP` emergency backup of the current state, restores the requested binary and database, removes stale WAL sidecars, starts VaultLink, and verifies systemd and SQLite health. It prints the emergency-backup path on success. If the rollback fails, that emergency backup is restored automatically and a previously active service is restarted.

Retain backups until the soak gate has passed. Backups contain password hashes, TOTP secrets, sessions, share tokens, and audit data and must be protected like the live database.

An automatic rollback restores the database snapshot taken before the candidate started. Writes accepted during the short candidate health-check window can therefore be lost. Quiesce public traffic for upgrades where that window is unacceptable.
