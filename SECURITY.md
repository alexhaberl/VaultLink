# Security Policy

## Supported versions

`0.3.0` is a private release. Security fixes are made only on the latest private release.

## Reporting a vulnerability

Do not open a public issue. Use GitHub's private vulnerability reporting for this repository or contact the repository owner privately. Include affected version, reproduction steps, impact, and any suggested mitigation. Do not include production credentials, share tokens, TOTP secrets, passwords, or private keys.

## Operational assumptions

- VaultLink runs as the dedicated `vaultlink` user on Debian 13 amd64.
- Production traffic is HTTPS, preferably terminated by a trusted reverse proxy.
- The mountpoint and data directory are not writable by unrelated users.
- Configuration, SQLite data, TLS keys, and ACME credentials use the documented restrictive permissions.
- Linux kernels must support `openat2(2)`; VaultLink refuses to start otherwise.
