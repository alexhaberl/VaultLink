# Security Policy

## Supported versions

`0.3.0` is a private release. Security fixes are made only on the latest private release.

## Build and release security

- GitHub Actions are pinned to full commit SHAs and build containers to SHA-256 manifest digests. Human-readable versions remain beside the pins and Dependabot proposes reviewed updates.
- Rust toolchains and CI-installed Cargo tools use exact versions. `tools/check-supply-chain-policy.sh` rejects mutable workflow references, remote `curl | sh`, and missing Docker build-context exclusions.
- Push and pull-request CI audits both `Cargo.lock` and `fuzz/Cargo.lock`, compiles every fuzz target, and runs setup, API, upgrade, and rollback Docker smokes without external runtime networking.
- Local `.env`, root `config.toml`, and SQLite files are excluded from the Docker context; the smoke image copies only build inputs and deploy tests explicitly.
- Debian APT packages still come from the signed live Debian repositories. The image digest fixes the starting filesystem, but bit-for-bit rebuilds require a separately maintained Debian snapshot and are not claimed yet.

## Reporting a vulnerability

Do not open a public issue. Use GitHub's private vulnerability reporting for this repository or contact the repository owner privately. Include affected version, reproduction steps, impact, and any suggested mitigation. Do not include production credentials, share tokens, TOTP secrets, passwords, or private keys.

## Operational assumptions

- VaultLink runs as the dedicated `vaultlink` user on Debian 13 amd64.
- Production traffic is HTTPS, preferably terminated by a trusted reverse proxy.
- The mountpoint and data directory are not writable by unrelated users.
- One VaultLink process owns a storage-root/data-directory pair; active-active multi-process operation on the same pair is unsupported.
- Configuration, SQLite data, TLS keys, and ACME credentials use the documented restrictive permissions.
- Linux kernels must support `openat2(2)`; VaultLink refuses to start otherwise.
