# Upgrade, backup, and rollback

VaultLink 0.6.0 supports upgrades only between native packages for the exact
same distribution, release, and architecture. There is no supported adoption,
upgrade, or migration path from the withdrawn 0.5.0 archive installation. A
markerless or mismatched installation fails closed before package files or
runtime state are changed.

## Installation and package identity

The native package owns the release candidate at
`/usr/lib/vaultlink/package/vaultlink`; the activated runtime remains
`/opt/vaultlink/vaultlink`. The root-owned
`/usr/share/vaultlink/install-method.env` marker binds the installation to:

- package format (`deb`, `rpm`, or `pkg.tar.zst`);
- exact `ID` and `VERSION_ID` from `/etc/os-release` (Arch uses
  `rolling`);
- package-manager architecture; and
- the package database name `vaultlink`.

The marker, package database, candidate version, active binary version, and
health version must agree. They are checked before and after every update.

Package installation never creates or replaces
`/etc/vaultlink/config.toml`, never enables or starts
`vaultlink.service` or `vaultlink-update.timer`, and preserves both the
intentional absence of `/etc/vaultlink/update.conf` and an existing valid file
without changing its inode, bytes, owner, mode, or modification time. Removal
preserves configuration, database, keyring, service identity, logs, mounts,
and backups.

For a first Debian or Ubuntu installation, the administrator must read the
exact `Depends` field from the already Minisign-verified, root-staged DEB and
prove every named package is in the `installed` state before running
`dpkg -i`. This preflight is offline. If `dpkg -i` nevertheless fails for a
missing dependency after leaving `vaultlink` unpacked, leave VaultLink
inactive, install the dependency manually, and continue only with
`dpkg --configure vaultlink`; do not run `dpkg -i` again over that unpacked
transaction. Any package-database or package/runtime ambiguity remains
fail-closed.

## The indivisible runtime backup

Treat these four files as one security and recovery unit:

- `/opt/vaultlink/vaultlink`
- `/etc/vaultlink/config.toml`
- `/var/lib/vaultlink/data.sqlite`
- `/var/lib/vaultlink/secrets.keyring`

The SQLite database contains encrypted Share tokens and TOTP secrets and is
unusable without its matching keyring. The live keyring must remain
`vaultlink:vaultlink`, mode `0600`. Every rollback source must be inside a
canonical, absolute, symlink-free subtree of `/var/lib/vaultlink-backups`;
that root and every directory down to the selected backup must be
`root:root`, mode `0700`. The backup binary must be `root:root`, mode `0700`,
and the configuration, database, and keyring copies must each be `root:root`,
mode `0600`.

Before reading their contents for rollback, the helper records each source's
filesystem identity and hash, copies all four files into a new private
`root:root` mode-`0700` freeze directory beneath the same backup root, and
rechecks the original identities, hashes, and frozen copies. It then operates
only on that frozen set. A source change, link, wrong owner/mode, unsafe parent,
or path outside the backup root fails before live-state mutation. Never copy
only `data.sqlite`, combine files from different backups, or point an older
binary at a database migrated by a newer binary.

A package update has one additional recovery input: the exact previously
installed native package. The updater downloads that package together with
its existing direct signature and the signed global `SHA256SUMS`, verifies and
extracts it, and retains the verified inputs in its root-only transaction
workspace before it allows the package database to change. The updater never
has access to a signing key.

## Signed package updater

The root-owned `/usr/sbin/vaultlink-update` uses the fixed
`https://github.com/alexhaberl/VaultLink/releases` origin and the installed
`/usr/share/vaultlink/minisign.pub`. Configuration cannot override the
repository, URL, channel, public key, distribution, architecture, or version.

Commands:

```sh
sudo vaultlink-update check
sudo vaultlink-update install
sudo vaultlink-update auto
```

`check` compares the installed package with the latest stable strict
`vMAJOR.MINOR.PATCH` release without executing downloaded content.
`install` installs only a newer release for the exact package target.
`auto` remains check-only unless the root-owned configuration contains
exactly `auto_install=true`. Even then it updates only a service that was
active before the transaction; a deliberately stopped service is neither
updated nor started.

Before any mutation, `install`:

1. validates root execution, the marker, OS release, architecture, active
   runtime, package candidate, and package database;
2. downloads the new package and the package for the currently installed
   release, their direct `.minisig` files, the global `SHA256SUMS`, and
   `SHA256SUMS.minisig` into a root-only bounded workspace;
3. verifies the global manifest and both direct signatures against the pinned
   key, rejects redirects outside the fixed HTTPS origin, and verifies exact
   asset names and checksums;
4. safely inspects both packages, rejecting links, special files, unexpected
   paths, metadata, architecture, version, package name, helper, or embedded-key
   differences;
5. executes each payload binary's bounded `--version` preflight as the
   unprivileged service user; and
6. proves all dependencies of the new package are already installed.

No distro repository is contacted by the update transaction. Missing new
dependencies stop the update before activation and require the administrator to
install the complete dependency set manually.

`vaultlink-update.service` is a root oneshot with explicit
`TimeoutStartSec=90min` and `TimeoutStopSec=30min`. It deliberately uses
`ProtectSystem=false`: native package managers execute distribution-owned
sysusers, tmpfiles, SELinux, and transaction hooks whose write set cannot be
represented safely by a VaultLink-only `ReadWritePaths` list. The signed
package, exact metadata and payload allowlists, dependency preflight, locks,
and final parity checks form that write boundary. All unrelated namespace,
device, kernel, process, and network hardening remains enabled.

## Transaction and automatic recovery

The updater holds the shared maintenance lock and records whether the service
was active. It creates and verifies the complete four-file backup before
downtime. It then installs the verified package without repository access:

- DEB: `dpkg -i`
- RPM: `rpm -Uvh`
- Arch updater-driven update or authenticated recovery reinstall: `pacman -U`

An initial Arch installation is different: the administrator must execute the
root-owned installer embedded in the already verified package. Direct initial
`pacman -U` is unsupported because Pacman 7 can ignore a failing `.INSTALL`
hook's status while still registering the package. The embedded wrapper runs
the same package-manager command only after a locked preflight and checks all
installation postconditions before reporting success. Subsequent signed
updates already have a valid persistent package marker and are safely driven
through Pacman by `vaultlink-update`.

Normal Arch removal must use the installed, signed
`vaultlink-package-remove.sh` wrapper, and normal reinstall must use
`vaultlink-package-install.sh` extracted from the new, root-staged,
Minisign-verified package. Direct `pacman -R vaultlink` and direct manual
reinstall with `pacman -U` are unsupported. These transactions preserve the
exact presence/absence of `update.conf` and, when present, its inode and
content metadata.

Package maintainer scripts install the new candidate but do not activate it on
an existing installation. The helper extracted from the already verified new
package stages and activates that exact candidate, performs any supported
forward migration, and checks startup, exact-version readiness, SQLite
integrity, ownership, modes, and hashes.

Any package-manager, migration, activation, startup, readiness, or integrity
failure enters recovery. Recovery keeps the service stopped, reinstalls the
already verified old package without repository access, atomically restores the
complete old runtime backup, and starts the service only if it was active
before. It then rechecks SQLite integrity and requires the package database,
package candidate, active binary, and readiness endpoint to report the same old
version.

If that parity cannot be re-established, recovery is terminal: the service
remains stopped, the transaction workspace and backup path are reported, and a
trusted host administrator must recover manually. A failed update is never
reported as success merely because the process returned to an executable
state.

Every application start first runs the root-owned package/runtime guard, which
requires marker, operating system, package database, candidate, and active
binary parity. It blocks a mixed state after an interrupted transaction or
power loss. `StartLimitIntervalSec=1h` and `StartLimitBurst=3` bound repeated
guard failures rather than creating an unbounded restart loop.

## Manual restore

`vaultlink-rollback.sh` accepts only the canonical protected backup subtree and
exact four-file ownership/mode contract described above, freezes and rechecks
those inputs, and creates an emergency backup of the current state first. It is
a state-recovery primitive, not a package-version switch. To cross a package
version manually:

1. obtain and verify the exact target package, its direct signature, and the
   signed checksum manifest;
2. stop VaultLink and reinstall that package with the native package manager;
3. run the packaged rollback helper against the backup created for that exact
   version; and
4. prove package/candidate/active/readiness parity and SQLite integrity before
   returning the host to service.

Do not use the normal forward-upgrade helper to force a downgrade. A terminal
recovery error warrants preserving the reported workspace and journal before
making further changes.

## Secret rotation

Rotate Share-token and TOTP encryption keys with exactly one database source:

```sh
sudo -u vaultlink /opt/vaultlink/vaultlink rotate-secrets \
  --database /var/lib/vaultlink/data.sqlite
```

Alternatively pass `--config /etc/vaultlink/config.toml`. Rotation requires
exclusive access to `secrets.keyring`; stop the service first. The new key is
made durable before ciphertexts are rewritten in an `IMMEDIATE` transaction,
and the previous key is removed only after the database commit.

## Recovery rules

- Restore only a matching binary/config/database/keyring set from one backup.
- Keep the service stopped while replacing any member of that set.
- Preserve owner and mode and remove stale SQLite WAL sidecars before restart.
- Startup authenticates all persisted Share and TOTP ciphertexts; a missing
  key, wrong key, modified nonce/AAD, or corrupt ciphertext aborts startup.
- `recover-admin --database /var/lib/vaultlink/data.sqlite` loads the adjacent
  keyring automatically.
- Protect packages, backups, and retained recovery workspaces as production
  credentials and remove temporary recovery material only after acceptance.
