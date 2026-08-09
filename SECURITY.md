# Security Policy

The [threat model](THREAT_MODEL.md) defines protected assets, attacker
capabilities, trust boundaries, security invariants, abuse cases, and accepted
residual risks. This policy remains authoritative for supported versions,
operational requirements, advisory exceptions, and vulnerability reporting.

## Supported versions

Release line: `0.5.0` for Linux x86_64 and aarch64. Its hardening work passed through the internal, untagged 0.4.9 candidate. Only artifacts attached to the signed, annotated `v0.5.0` tag are supported; if that tag is absent, no published version is supported. Windows hosts are not supported.

## Build and release security

- GitHub Actions are pinned to full commit SHAs and build containers to SHA-256 manifest digests. Human-readable versions remain beside the pins and Dependabot proposes reviewed updates.
- Rust toolchains and CI-installed Cargo tools use exact versions. `tools/check-supply-chain-policy.sh` rejects mutable workflow references, remote `curl | sh`, and missing Docker build-context exclusions.
- Push and pull-request CI audits the shared workspace `Cargo.lock`, compiles every fuzz target, and runs setup, API, upgrade, and rollback Docker smokes without external runtime networking.
- Native CI runs checksum-pinned Gitleaks 8.30.0 over the complete fetched Git history with redacted output, recursive decoding, and archive inspection. `.gitleaksignore` contains only two commit-bound findings for the public RFC 6238 Appendix B TOTP test vector.
- Local `.env`, root `config.toml`, and SQLite files are excluded from the Docker context; the smoke image copies only build inputs and deploy tests explicitly.
- Debian build packages come exclusively from the checked-in, timestamped Debian snapshot and an exact direct/transitive package lock. The weekly and manually dispatched native reproducibility gate compares two clean binary and archive builds per architecture before release.

### Compensated WebAuthn RSA advisory

`webauthn_rp 0.3.0` unconditionally depends on `rsa 0.9.10`, which is affected by `RUSTSEC-2023-0071`. The advisory concerns timing leakage from RSA private-key operations. VaultLink is a WebAuthn relying party: authenticator private keys never enter the server, and VaultLink performs no RSA private-key operation for WebAuthn credentials.

VaultLink nevertheless makes the affected RS256 path unreachable. Registration options never advertise RS256, and one central runtime invariant rejects RSA credential state after registration, while decoding persisted credentials, and immediately before authentication. Regression tests cover each boundary. `RUSTSEC-2023-0071` is the sole explicit `cargo-audit` exception and must be reviewed for every release.

The exception must be removed or reassessed if `webauthn_rp` drops or updates `rsa`, VaultLink enables RS256, a deserialization path bypasses the central check, or VaultLink begins handling RSA private keys. This statement is limited to VaultLink's current relying-party use and does not claim that the affected crate is generally safe.

## Reporting a vulnerability

Do not open a public issue. Use GitHub's private vulnerability reporting for this repository or contact the repository owner privately. Include affected version, reproduction steps, impact, and any suggested mitigation. Do not include production credentials, share tokens, TOTP secrets, passwords, or private keys.

## Operational assumptions

- VaultLink runs as the dedicated `vaultlink` user on Debian 13 x86_64 or aarch64.
- Production traffic is HTTPS, preferably terminated by a trusted reverse proxy.
- Every production configuration uses `require_mount=true` with a pre-provisioned service-owned root, private internal directory and data directory plus an exact filesystem type and active `/proc/self/mountinfo` source. CIFS may place the reserved internal directory directly below the share root; other required mounts use a private sibling. This remains fail-closed when a remote mount disappears and exposes its local fallback directory.
- Without `external_writers`, the visible root, private sibling and data directory are owned by the VaultLink service uid and are not writable through group/other mode bits or a POSIX ACL mask. Other local writers are unsupported in this mode.
- An external-writer deployment uses the audited CIFS policy only: SMB 3.1.1 with encryption, strict caching, a dedicated VaultLink SMB identity, verified mount source/type/options and no nested mounts or symlink traversal.
- The external SMB server/share mandates SMB 3.1.1 signing and encryption for every direct Windows, macOS and Linux co-writer session. VaultLink's `seal` option protects only its own Linux mount and cannot enforce the transport policy of other clients.
- Standard SMB clients may have the required Modify rights for user data directly in the share root but never administrative rights. The reserved `.vaultlink-internal/{uploads,tombstones}` child is pre-provisioned and protected by server-side ACLs so every other SMB principal is denied read, write, delete, rename, parent `DELETE_CHILD`, ACL/owner changes (`WRITE_DAC`/`WRITE_OWNER`) and chmod/chown/setfacl-equivalent access. VaultLink rejects the reserved name and its case-insensitive/trailing-dot-or-space aliases in every user path, filters it from scans, and disables symlink traversal for this nested layout. Synthetic CIFS mode bits do not establish the server-side boundary.
- External SMB writers are trusted content publishers. Their direct changes bypass VaultLink authentication, audit, quotas and link policy; SMB-server audit and account lifecycle controls are therefore part of the security boundary.
- Overwrite publication is disabled by default whenever external writers are enabled. `allow_external_writer_replace=true` is an explicit last-writer-wins exception: atomic VaultLink publication can overwrite a newer concurrent SMB-client change because standard clients do not participate in VaultLink's storage lock. Operators accepting this mode must treat that undetectable lost-update risk as part of their storage policy.
- SQLite/WAL, configuration, TLS keys and ACME credentials remain on an audited local filesystem and use the documented restrictive permissions. SQLite must be on a filesystem separate from CIFS/SMB storage and may share an audited local ext*/XFS/Btrfs/F2FS/Bcachefs/ZFS mount only when it is outside the visible tree.
- SQLite stores Share tokens, TOTP seeds and WebAuthn credentials encrypted at rest. The adjacent matching `secrets.keyring` contains the keys needed to decrypt them. A complete database/keyring pair or upgrade/rollback backup is therefore a production credential and must remain restricted to audited root/service access, encrypted storage and protected backup handling.
- Upgrade and rollback backups are inseparable Binary/Config/SQLite/Keyring units. The live configuration is never rewritten for a candidate before downtime; automatic recovery restores and health-checks the matching old unit.
- One VaultLink process owns a storage-root/data-directory pair; active-active multi-process operation on the same pair is unsupported.
- Administrator sessions have both the configured absolute lifetime and a 30-minute inactivity limit by default. Activity updates are coalesced to one SQLite write per minute, so an idle session expires conservatively after 29 to 30 minutes and can never outlive its absolute expiry.
- Administrator recovery assumes SSH/host access and is performed locally with `recover-admin` as the `vaultlink` service user; VaultLink deliberately exposes no public password-reset endpoint.
- CIFS provisioning is a separate local root-only command with a fixed `/mnt/storage` boundary. The browser setup remains unprivileged, passwords are read from the terminal rather than arguments, existing system files are never overwritten, and failed activation rolls back files created by that attempt. Server-side SMB ACL provisioning and verification remain an administrator responsibility.
- Linux kernels must support `openat2(2)`, `renameat2(2)` and statx mount IDs (Linux 5.8 or newer for the hardened external-mount mode); VaultLink refuses to start otherwise.

## Audit and rate-limit trust boundaries

- Web administrators cannot delete general audit entries through VaultLink. The dedicated privacy operation can remove stored client-IP values only after client-IP logging has been disabled, and that operation is itself audited.
- SQLite audit events are mirrored as structured events to journald. Client IP addresses are intentionally excluded from the journald mirror.
- Service administrators, root administrators and administrators who can alter or delete host logs are inside the audit trust boundary. VaultLink has no cryptographic audit chain and no immutable external audit sink.
- Deployments that require tamper-resistant audit evidence must forward journald events to an independently administered append-only or WORM-capable logging system.
- Login limits are process-local and reset whenever the VaultLink process restarts. They limit application work but are not a volumetric network defense; reverse-proxy and network-layer rate limits remain required.
- `audit_client_ip_enabled = false` is the privacy-preserving default. It reduces retained personal data but limits forensic correlation of requests, and client IPs are intentionally not mirrored to journald even when SQLite capture is enabled.
