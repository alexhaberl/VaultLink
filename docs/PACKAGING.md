# Native package support

VaultLink 0.6.0 is distributed only as a native, signed operating-system
package. GitHub's automatically generated source archives are source material,
not supported installation artifacts. VaultLink does not publish a package
repository, a standalone binary, or a project tar archive.

## Supported targets

The checked-in `release/package-targets.json` manifest is the sole source of
truth for target IDs, operating-system versions, runner architectures, package
architectures, immutable builder and VM images, package formats, and release
asset names. Generated matrices and release jobs must consume that file rather
than repeat target lists in workflow YAML.

| Operating system | Architectures | Package |
| --- | --- | --- |
| Debian 13 | amd64, arm64 | DEB |
| Ubuntu 24.04 LTS | amd64, arm64 | DEB |
| Ubuntu 26.04 LTS | amd64, arm64 | DEB |
| Fedora 44 | x86_64, aarch64 | RPM |
| Arch Linux, release-date snapshot | x86_64 | `.pkg.tar.zst` |

For version 0.6.0 the manifest resolves those targets to these exact assets:

| Target | Release asset |
| --- | --- |
| Debian 13 amd64 | `vaultlink_0.6.0-1+deb13_amd64.deb` |
| Debian 13 arm64 | `vaultlink_0.6.0-1+deb13_arm64.deb` |
| Ubuntu 24.04 amd64 | `vaultlink_0.6.0-1+ubuntu24.04_amd64.deb` |
| Ubuntu 24.04 arm64 | `vaultlink_0.6.0-1+ubuntu24.04_arm64.deb` |
| Ubuntu 26.04 amd64 | `vaultlink_0.6.0-1+ubuntu26.04_amd64.deb` |
| Ubuntu 26.04 arm64 | `vaultlink_0.6.0-1+ubuntu26.04_arm64.deb` |
| Fedora 44 x86_64 | `vaultlink-0.6.0-1.fc44.x86_64.rpm` |
| Fedora 44 aarch64 | `vaultlink-0.6.0-1.fc44.aarch64.rpm` |
| Arch Linux x86_64 | `vaultlink-0.6.0-1-x86_64.pkg.tar.zst` |

Each binary is compiled inside its target distribution on a native runner of
the same CPU architecture. Arch Linux ARM, distributions derived from the
listed targets, later rolling Arch snapshots, and every unlisted OS/version
combination are unsupported. QEMU is used for full-system tests, never for
compilation.

## Filesystem and lifecycle contract

Every package owns the immutable release candidate at
`/usr/lib/vaultlink/package/vaultlink`. The transactionally activated runtime
remains `/opt/vaultlink/vaultlink`. Packages also contain the service and
update units, Sysusers and Tmpfiles definitions, the Minisign public key,
update/upgrade/rollback helpers, configuration examples, licence material, and
the target SBOM.

The updater's executable path is `/usr/sbin/vaultlink-update` on DEB and RPM
systems. Arch packages own `/usr/bin/vaultlink-update`, because Arch's
`filesystem` package owns `/usr/sbin` as a merged-`/usr` symlink; the systemd
unit's `/usr/sbin/vaultlink-update` path therefore resolves to that same file.

The package lifecycle deliberately has no activation side effect:

- it never installs or replaces `/etc/vaultlink/config.toml`;
- it preserves both the intentional absence of `/etc/vaultlink/update.conf`
  and an existing root-owned file without changing its inode, bytes, owner,
  mode, or modification time;
- it leaves `vaultlink.service` and `vaultlink-update.timer` disabled after a
  first installation;
- package removal does not delete the service user, configuration, database,
  keyring, logs, mounts, or backups; and
- `cifs-utils` is an optional operational dependency, not a mandatory runtime
  dependency.

`/usr/share/vaultlink/install-method.env` is root-owned, mode `0644`, and
contains exactly these five installation-bound fields:

```text
FORMAT=deb|rpm|pkg.tar.zst
OS_ID=debian|ubuntu|fedora|arch
OS_VERSION=13|24.04|26.04|44|rolling
ARCH=amd64|arm64|x86_64|aarch64
PACKAGE_NAME=vaultlink
```

Package installation aborts if package-owned runtime paths already exist but
the marker is absent, malformed, writable by another user, or names another
installation method. This intentionally rejects the withdrawn 0.5.0 archive
layout. There is no supported in-place adoption or migration from that layout.

Before every service start, the root-executed package-owned
`vaultlink-runtime-guard.sh` binds the exact host marker, native package
database version and architecture, candidate version and canonical checksum,
and active binary bytes. A crash or power loss after package installation but
before activation can leave the already-running old process alive, but any
later restart is rejected while package/runtime parity is mixed. The guard is
deliberately fail-closed; it does not claim automatic power-loss recovery. The
signed updater must complete or restore the verified old package before the
service can start again.
`StartLimitIntervalSec=1h` and `StartLimitBurst=3` cap repeated parity-guard
failures, so a mixed state cannot create an unbounded restart loop.

DEB and RPM package managers temporarily remove their package-owned public
marker before the post-remove scriptlet restores it. Before removal, VaultLink
persists an exact root-only recovery copy at
`/var/lib/vaultlink-backups/install-method.env`. If power is lost in that
window, reinstalling the previously verified matching package restores the
marker from that host-bound copy before evaluating markerless legacy paths.
Configuration, database, keyring, and service identity are never adopted from
an unbound markerless installation.

### Trusted staging and DEB initial-install boundary

First create a new root-owned mode-`0700` staging directory with
`sudo mktemp -d /var/tmp/vaultlink-release-0.6.0.XXXXXXXX`; never reuse a fixed
or pre-existing path. Copy the package, its direct signature, `SHA256SUMS`, its
signature, and the separately trusted public key into it. Bind the staged key
to SHA-256
`200d64c2f2e42ace790a6d74f8b101801065b2d9a51c8fdda5b47b4f2b2f9809`
before using it. Perform both Minisign checks and the signed-checksum check against
those root-owned copies, and pass that exact staged package to `dpkg`, `rpm`,
or the Arch wrapper. Verifying a user-writable pathname and later reopening it
as root is unsupported because it creates a source-swap race.

On Fedora, updater-driven RPM transactions add `--nocontexts`. RPM's SELinux
plugin otherwise requests a scriptlet domain transition that Linux rejects
under the update unit's retained `NoNewPrivileges=true` boundary. This option
does not disable SELinux: the host remains `Enforcing`, initial manual package
installation uses RPM's normal context handling, and the exception is reached
only after the candidate's Minisign signature, complete metadata, fixed payload
allowlist, dependencies, and exact reviewed scriptlets have all been verified.
The Fedora full-system gate exercises that exact path and requires no
VaultLink-related AVC denials plus final package/runtime parity.

For Debian and Ubuntu, read `Depends` from that exact verified, root-owned DEB
with `dpkg-deb -f`. Version 0.6.0 requires the exact field
`ca-certificates, curl, libc6, libgcc-s1, mawk, minisign, sqlite3, systemd`.
Before running `dpkg -i`, query every one of those package names with
`dpkg-query` and require the state `installed`; this is an offline preflight
and must not be replaced by an online dependency-repair command. If `dpkg -i`
nevertheless returns a missing-dependency failure after unpacking VaultLink,
leave its service and update timer inactive, install the missing dependency
manually, and resume only with `dpkg --configure vaultlink`. Re-running
`dpkg -i` over the already unpacked package is unsupported. Any ambiguous
package-database, marker, candidate, or runtime state remains fail-closed and
requires operator recovery.

### Arch initial-install boundary

Pacman 7 may return success and register a package even when an `.INSTALL`
hook reports failure. A direct initial `pacman -U` therefore cannot provide
VaultLink's required fail-closed legacy-installation boundary and is not a
supported installation procedure.

For Arch, after that root-owned verification, extract
`usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh` from that same
staged package into the same trusted directory at mode `0700`, and run it as
root with the mode-`0600` staged package as its sole argument. The script
requires a root-owned safe parent chain (a root-owned sticky `/var/tmp` is
allowed), binds source identity and digest across its private copy, proves
that it belongs to the selected package,
validates the complete archive allowlist, metadata, dependencies, payload
hash, key, platform, and legacy paths, holds the installation lock, invokes
`pacman -U`, and verifies the package database, active binary, marker, key,
inventory, and no-autostart postconditions. It creates the persistent marker
only after Pacman has installed the signed payload. The Arch package does not
own that marker, so removal and later reinstall can preserve provenance just
like DEB and RPM.

### Arch removal boundary

Direct `pacman -R vaultlink` is unsupported. It cannot hold VaultLink's update
and maintenance locks across the complete Pacman transaction and therefore
has an unavoidable check/use race. Run the signed, package-owned wrapper:

```sh
/usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh
```

The wrapper exclusively holds the install, update, and maintenance locks for
the whole transaction, stops `vaultlink-update.service`, and makes the timer
and application service exactly inactive and disabled. The package-owned
libalpm `PreTransaction` guard is read-only and requires those inherited locks
and states; a direct Pacman removal therefore aborts before mutation. If a
later Pacman hook aborts while the package database, candidate, marker, and
runtime can still be restored to exact parity, the wrapper restores the prior
service/timer state. A mixed or already-removed state is terminal and leaves
all VaultLink units inactive and disabled.

An ordinary reinstall is also a wrapper operation: root-stage and verify the
new package and invoke its embedded `vaultlink-package-install.sh` exactly as
for the initial installation. Direct `pacman -R vaultlink` and direct manual
reinstall with `pacman -U` are unsupported. Ordinary removal, wrapper
reinstall, and updater-driven Pacman transactions preserve the exact
presence/absence of `/etc/vaultlink/update.conf`; when present, its inode,
bytes, owner, mode, and modification time must remain unchanged.

If an unsupported direct initial `pacman -U` was rejected by the package's
markerless legacy guard but Pacman nevertheless registered it, recover without
deleting the pre-existing archive runtime by running the installed wrapper as
`vaultlink-package-remove.sh --recover-failed-install`. The supported initial
installer performs this cleanup automatically and retains its verified package
copy with a terminal diagnostic if cleanup itself cannot be proven complete.

After installing a package, the administrator creates a production
configuration with the packaged example or the loopback setup command, then
explicitly enables the service. Fresh installation already copies the exact
package candidate to `/opt/vaultlink/vaultlink`; use that active path for the
setup command while the candidate remains the package/updater reference.

## Package updates and recovery

`vaultlink-update check`, `install`, and `auto` are available only for a valid
package installation. Before an installation the updater binds the host to the
exact marker, OS release, package architecture, package database record, and
running VaultLink version. It downloads both the new package and the currently
installed release package, their direct Minisign signatures, and the globally
signed `SHA256SUMS` from the fixed official GitHub repository.

Both packages are verified and extracted in a root-only workspace before any
package-manager change. The updater checks asset names, versions,
architectures, payload binaries, embedded public keys, and package metadata.
It preflights all declared runtime dependencies and does not contact a distro
repository. An unmet new dependency therefore requires a manual package
installation instead of allowing partial activation.

Before downtime, the updater creates a protected recovery unit below the
canonical root-owned mode-`0700` `/var/lib/vaultlink-backups` tree. The four
runtime members are copied as `root:root` (`vaultlink` mode `0700`;
configuration, database, and keyring mode `0600`), hashed, and revalidated
against their source identities before package mutation. The standalone
rollback helper accepts only a canonical, symlink-free `root:root` mode-`0700`
subtree of that backup root with those exact four file owners and modes,
freezes all four inputs into a new private directory, and rechecks source
identity and content before it uses the frozen copies.

The local package manager (`dpkg`, `rpm`, or `pacman`) installs the verified
file. The verified release helper then creates a complete runtime backup,
performs migration and activation, and proves exact-version readiness and
SQLite integrity. On package-manager, migration, startup, readiness, or
integrity failure, the updater reinstalls the already verified previous
package and restores the complete previous runtime state. Package database,
package candidate, active binary, and health version must agree afterward. A
failure to re-establish that parity is a terminal recovery error and leaves the
service stopped for operator recovery. The updater retains the verified old
package, signatures, checksums, and protected workspace below
`/var/lib/vaultlink-backups/update-evidence/`; it never relies on a systemd
`PrivateTmp` path for terminal recovery evidence.

Automatic installation defaults to `false`. `auto` updates only a service that
was active before the transaction. It neither updates nor starts a deliberately
stopped service.

The update oneshot has explicit `TimeoutStartSec=90min` and
`TimeoutStopSec=30min`. These bounds exceed the updater's cumulative bounded
downloads plus package, migration, readiness, and authenticated recovery work;
they avoid systemd's 90-second default terminating a valid transaction while
still placing a finite manager-level ceiling on execution and stop recovery.
The service account is created through `systemd-sysusers` only on a fresh
installation. Package upgrades validate the complete existing service identity
without taking `/etc/passwd` locks, so they remain compatible with the update
unit.

The root update oneshot deliberately uses `ProtectSystem=false`. Native package
managers execute distribution-owned sysusers, tmpfiles, SELinux, and transaction
hooks whose complete write set cannot be represented by a VaultLink-owned
`ReadWritePaths` list. The signed package, complete metadata/payload allowlists,
preflight, locks, and post-transaction parity checks are therefore the write
boundary for this unit. `NoNewPrivileges=true` remains active. The exact six
bounded transaction capabilities are ambient only across the root package
execution chain; after the `vaultlink` UID/GID transition, permitted,
effective, and ambient capability sets must all be empty. Its unrelated
namespace, device, kernel, process, and network hardening remains enabled.
Booted distro-VM gates inspect that credential boundary and exercise the real
unit and package-manager hooks for every target.

## Deterministic build and release assets

Every target uses a digest-pinned, source-independent builder with a fixed Rust
toolchain, locked distro package closure, and commit-derived
`SOURCE_DATE_EPOCH`. Two clean builds must produce identical payload binaries,
target SBOMs, and final packages. `lintian`, `rpmlint`, or `namcap` runs as
appropriate; a common allowlist independently checks paths, ownership, modes,
dependencies, maintainer scripts, and systemd content.
Because Namcap can exit successfully while reporting `E:` findings, the Arch
lint gate parses its complete output and fails on every `E:` line. `W:` lines
remain visible as reviewed advisory output and do not by themselves fail the
gate.

A release has exactly 21 project-provided assets:

- nine native packages;
- nine direct package `.minisig` signatures;
- one deterministic SBOM bundle covering every target and payload hash;
- one global `SHA256SUMS`; and
- one `SHA256SUMS.minisig`.

The protected signing job alone receives the Minisign secret. It first creates
a draft release, downloads every asset back from GitHub, verifies names,
counts, hashes, signatures, package metadata, and the embedded public key, and
only then makes the release public. Starting with 0.6.0, published package
assets must not be deleted because a supported updater may require an old
release package for authenticated rollback.

Repository-level [GitHub release immutability](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes)
was enabled on 2026-08-25. The tag workflow verifies that the published release
reports `immutable=true`; the operational policy additionally forbids deleting
an entire published package release, because doing so would remove
authenticated rollback inputs.

## Test authority

Local Docker covers the complete x86_64 package matrix. Native GitHub arm64
results are authoritative for arm64. Fast container gates install packages
without network access and exercise ownership, modes, no-autostart, setup,
systemd analysis, API smoke, upgrade, migration, backup, rollback,
reinstallation, and state-preserving removal. For each of the nine targets,
the same gate runs the unchanged overlapping workload of 100 metadata clients,
40 range streams, and ten upload/readback clients against the exact installed
package payload. It executes inside the target's digest-pinned distribution
builder on a native matching-architecture GitHub runner. Before its timing is
accepted, the job qualifies the public hosted runner for four available vCPUs
and at least 8 GiB of host RAM, then restricts its Docker container to logical
CPUs 0-3. The server is restricted to CPUs 0-1 and uses a separate server-
storage mount; the load generator is restricted to CPUs 2-3 and uses a
dedicated hardened 4-GiB client tmpfs. Before VaultLink starts, the otherwise
empty server-storage volume must also pass a fail-closed SQLite WAL probe with
four writers, 128 `synchronous=FULL` transactions, and a concurrent reader.
The probe rejects SQLite errors or failed integrity, writer p95 at or above one
second, writer maximum at or above five seconds, reader p95 at or above 250 ms,
reader maximum at or above two seconds, a checkpoint at or above five seconds,
or a total runtime at or above 30 seconds. Its evidence is retained separately
from the application result and the probe directory is removed before the
runtime fixture is created. Evidence records both qualifications, container
and process CPU placement, memory and storage separation, exact workload
counts, latency, RSS, and integrity results. A runner that cannot prove this
resource and storage layout fails the gate. The qualified native run is
authoritative for p95 strictly below two seconds and also fails on invalid
response statuses, corruption, or exceeding the RSS ceiling. The harness's
resource contract is reproducible, but it does not assert deterministic timing
for arbitrary GitHub standard-runner executions. A failed qualification is not
automatically retried into a passing result. The managed arm64 GitHub runner
supplies the same qualified evidence for arm64; private ARM hardware is not
required.

Full-system gates boot digest-pinned target images on a same-architecture
GitHub runner. Guests receive packages over an isolated host channel and have
no unrestricted Internet access. Fedora must remain SELinux `Enforcing` and
must produce no VaultLink-related AVC denial. Every guest runs the exact same
100-user/range/upload workload without reducing its concurrency or transfer
sizes. QEMU remains authoritative for full-system functionality, request
counts and statuses, hashes and absence of corruption, RSS, process health,
package-manager behavior, migration, upgrade, backup, rollback, readiness,
SQLite integrity, systemd confinement, and Fedora SELinux assertions. Its p95
and `<2 s` threshold comparison are recorded as diagnostic evidence regardless
of acceleration; emulation speed is not a release-performance gate. The
commit-bound nine-target workflow forces and records TCG for every target, so
its aggregate result proves the complete workload passed without KVM. A guest-
image refresh may select KVM on amd64 only after a bounded QMP query proves it
is present and enabled; every failed or unavailable probe selects TCG.

Only Debian 13 amd64 runs the 72-hour soak. Its runtime binary must be extracted
from the exact final DEB and hash-bound to the candidate commit. Every soak
load profile continues to enforce p95 strictly below two seconds. Arch is
built and boot-tested against the release-date snapshot; a weekly read-only
job checks the current rolling image without changing published support claims.
