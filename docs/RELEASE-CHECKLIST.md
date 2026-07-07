# v0.1.0-beta.1 release checklist

- [ ] Clean `main` worktree and green CI with `--locked`.
- [ ] Formatting, Clippy, unit tests, HTTP integration tests, migration tests, and shellcheck pass.
- [ ] Path, range, and filename fuzz targets each run for ten minutes without findings.
- [ ] `cargo-audit 0.22.2` reports no known vulnerabilities.
- [ ] Debian 13 amd64 load gate: 100 users, 40 download streams, 50 GiB sparse file, parallel uploads; no 5xx/corruption, metadata p95 <750 ms, added RSS <=256 MiB.
- [ ] Upgrade and rollback tested from the previous deployed schema and binary.
- [ ] `vaultlink.haberl.tech`: TLS, redirect, Secure/HttpOnly/SameSite cookies, headers, password unlock, upload, full download, Range, revoke, and expiry verified.
- [ ] 72-hour VM soak: no unplanned restart, `PRAGMA integrity_check` is `ok`, no continuous memory growth >15%.
- [ ] CycloneDX SBOM, SHA-256 file, binary, README, license, configurations, and systemd files present in the tarball.
- [ ] Binary and checksum file verify against the repository Minisign public key.
- [ ] Annotated `v0.1.0-beta.1` tag is created only after all preceding boxes are checked.
- [ ] GitHub release is private/prerelease and contains only CI-produced artifacts.
