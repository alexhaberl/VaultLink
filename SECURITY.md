# Security Policy

## Supported versions

`0.4.2` is currently a private release candidate for Linux x86_64 and aarch64. No published version is supported until the signed artifacts, native release gates, and annotated tag in the release checklist are complete. Security fixes are prepared on the latest private candidate; Windows hosts are not supported.

## Build and release security

- GitHub Actions are pinned to full commit SHAs and build containers to SHA-256 manifest digests. Human-readable versions remain beside the pins and Dependabot proposes reviewed updates.
- Rust toolchains and CI-installed Cargo tools use exact versions. `tools/check-supply-chain-policy.sh` rejects mutable workflow references, remote `curl | sh`, and missing Docker build-context exclusions.
- Push and pull-request CI audits the shared workspace `Cargo.lock`, compiles every fuzz target, and runs setup, API, upgrade, and rollback Docker smokes without external runtime networking.
- Local `.env`, root `config.toml`, and SQLite files are excluded from the Docker context; the smoke image copies only build inputs and deploy tests explicitly.
- Debian APT packages still come from the signed live Debian repositories. The image digest fixes the starting filesystem, but bit-for-bit rebuilds require a separately maintained Debian snapshot and are not claimed yet.

## Reporting a vulnerability

Do not open a public issue. Use GitHub's private vulnerability reporting for this repository or contact the repository owner privately. Include affected version, reproduction steps, impact, and any suggested mitigation. Do not include production credentials, share tokens, TOTP secrets, passwords, or private keys.

## Operational assumptions

- VaultLink runs as the dedicated `vaultlink` user on Debian 13 x86_64 or aarch64.
- Production traffic is HTTPS, preferably terminated by a trusted reverse proxy.
- Every production configuration uses `require_mount=true` with a pre-provisioned service-owned root, private sibling and data directory plus an exact filesystem type and active `/proc/self/mountinfo` source. This remains fail-closed when a remote mount disappears and exposes its local fallback directory.
- Without `external_writers`, the visible root, private sibling and data directory are owned by the VaultLink service uid and are not writable through group/other mode bits or a POSIX ACL mask. Other local writers are unsupported in this mode.
- An external-writer deployment uses the audited CIFS policy only: SMB 3.1.1 with encryption, strict caching, a dedicated VaultLink SMB identity, verified mount source/type/options and no nested mounts or symlink traversal.
- The external SMB server/share mandates SMB 3.1.1 signing and encryption for every direct Windows, macOS and Linux co-writer session. VaultLink's `seal` option protects only its own Linux mount and cannot enforce the transport policy of other clients.
- Standard SMB clients may have Modify rights only below the visible `shared/` tree, never administrative/share-root rights. The sibling `.vaultlink-internal/{uploads,tombstones}` tree is pre-provisioned and protected by server-side ACLs so every other SMB principal is denied read, write, delete, rename, parent `DELETE_CHILD`, ACL/owner changes (`WRITE_DAC`/`WRITE_OWNER`) and chmod/chown/setfacl-equivalent access. Synthetic CIFS mode bits do not establish this boundary.
- External SMB writers are trusted content publishers. Their direct changes bypass VaultLink authentication, audit, quotas and link policy; SMB-server audit and account lifecycle controls are therefore part of the security boundary.
- Overwrite publication is disabled whenever external writers are enabled. Existing link paths can still serve content replaced directly on the SMB server.
- SQLite/WAL, configuration, TLS keys and ACME credentials remain on an audited local filesystem and use the documented restrictive permissions. SQLite must be on a filesystem separate from CIFS/SMB storage and may share an audited local ext*/XFS/Btrfs/F2FS/Bcachefs/ZFS mount only when it is outside the visible tree.
- Upgrade and rollback backups are inseparable Binary/Config/SQLite triples. The live configuration is never rewritten for a candidate before downtime; automatic recovery restores and health-checks the matching old triple.
- One VaultLink process owns a storage-root/data-directory pair; active-active multi-process operation on the same pair is unsupported.
- Administrator recovery assumes SSH/host access and is performed locally with `recover-admin` as the `vaultlink` service user; VaultLink deliberately exposes no public password-reset endpoint.
- Linux kernels must support `openat2(2)`, `renameat2(2)` and statx mount IDs (Linux 5.8 or newer for the hardened external-mount mode); VaultLink refuses to start otherwise.
