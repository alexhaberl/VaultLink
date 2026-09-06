# Installation and operation

[Back to README](../README.md)

This guide installs the supported **VaultLink 0.6.0** native packages.
Start with [configuration and storage](CONFIGURATION.md) to prepare the mounted
storage, private internal directory, local database directory, and HTTPS endpoint.
Package installation leaves the service and automatic updates disabled.

Follow [package verification and installation](#native-package-deployment), then
[initial browser setup](#initial-browser-setup-through-an-ssh-tunnel).
[Administrator recovery](#local-administrator-recovery) is available over SSH.

## Native package deployment

VaultLink 0.6.0 supports only the exact native packages listed in
[docs/PACKAGING.md](../docs/PACKAGING.md): Debian 13 and Ubuntu 24.04/26.04 on
amd64/arm64, Fedora 44 on x86_64/aarch64, and the release-date Arch snapshot on
x86_64. Install the matching package from the GitHub release after verifying
both its direct Minisign signature and its digest in the signed global
`SHA256SUMS`.

### Install prerequisites for your operating system

Use an administrator account with `sudo`. Run only the subsection matching
your host, before verifying or installing VaultLink. These commands install
tools and runtime dependencies from your operating system's repositories;
the subsequent VaultLink package transaction is offline.

#### Debian 13 or Ubuntu 24.04 / 26.04

```sh
sudo apt-get update && sudo apt-get install -y \
  ca-certificates curl libc6 libgcc-s1 mawk minisign sqlite3 systemd
```

#### Fedora 44

```sh
sudo dnf install -y \
  bash ca-certificates coreutils cpio curl diffutils findutils gawk glibc \
  grep gzip libgcc minisign rpm sed sqlite systemd tar util-linux
```

#### Arch Linux, supported release-date snapshot

Use repositories and a host synchronized to the supported release-date
snapshot. Later rolling snapshots are unsupported; do not change snapshots
or perform a partial system upgrade as part of this installation.

```sh
sudo pacman -S --needed \
  bash ca-certificates coreutils curl diffutils findutils gawk gcc-libs \
  glibc grep gzip libarchive minisign sed sqlite systemd tar util-linux zstd
```

Install `cifs-utils` separately with your operating system's package manager
if VaultLink will provision or mount SMB storage.

### Download the package and verification files

From the [supported release](https://github.com/alexhaberl/VaultLink/releases/tag/v0.6.0),
download the package for your host, its matching `.minisig`, `SHA256SUMS`, and
`SHA256SUMS.minisig` into one directory. Obtain `minisign.pub` through a
separately trusted copy of this repository; its key ID is `EC6AEC772F7CDDEC`.
Open a terminal in the download directory and set these two values:

```sh
# Replace this Debian 13 amd64 example with the exact asset for your host:
# vaultlink_0.6.0-1+ubuntu24.04_arm64.deb,
# vaultlink-0.6.0-1.fc44.x86_64.rpm, or
# vaultlink-0.6.0-1-x86_64.pkg.tar.zst.
PACKAGE=vaultlink_0.6.0-1+deb13_amd64.deb
PUBLIC_KEY=/path/to/trusted/minisign.pub
```

### Verify and install the matching package

Run this entire block in the same terminal. It selects only the installer for
the detected operating system and checks the exact package name for its
architecture. Verification and installation run in one error-stopping shell:
a failed key, signature, checksum, or dependency check prevents installation.
The block runs in child shells, so a failure does not close your terminal.

```sh
sh -eu -s -- "${PACKAGE:?set PACKAGE}" "${PUBLIC_KEY:?set PUBLIC_KEY}" <<'INSTALL'
PACKAGE=$1
PUBLIC_KEY=$2
. /etc/os-release
case "$ID:${VERSION_ID:-}" in
  debian:13)
    FORMAT=deb
    EXPECTED="vaultlink_0.6.0-1+deb13_$(dpkg --print-architecture).deb"
    ;;
  ubuntu:24.04|ubuntu:26.04)
    FORMAT=deb
    EXPECTED="vaultlink_0.6.0-1+ubuntu${VERSION_ID}_$(dpkg --print-architecture).deb"
    ;;
  fedora:44)
    FORMAT=rpm
    EXPECTED="vaultlink-0.6.0-1.fc44.$(uname -m).rpm"
    ;;
  arch:*)
    FORMAT=arch
    test "$(uname -m)" = x86_64
    EXPECTED=vaultlink-0.6.0-1-x86_64.pkg.tar.zst
    ;;
  *) echo 'Unsupported operating system or version' >&2; exit 64 ;;
esac
test "$PACKAGE" = "$EXPECTED"

# Freeze every input before verification, then install that same root-owned file.
STAGE=$(sudo mktemp -d /var/tmp/vaultlink-release-0.6.0.XXXXXXXX)
test "$(sudo stat -c '%u:%g:%a' "$STAGE")" = 0:0:700
printf 'Verification and recovery directory: %s\n' "$STAGE"
sudo install -o root -g root -m 0600 \
  -- "$PACKAGE" "$PACKAGE.minisig" SHA256SUMS SHA256SUMS.minisig "$STAGE/"
sudo install -o root -g root -m 0600 -- "$PUBLIC_KEY" "$STAGE/minisign.pub"

sudo env STAGE="$STAGE" PACKAGE="$PACKAGE" FORMAT="$FORMAT" \
  sh -eu <<'VERIFY_AND_INSTALL'
cd "$STAGE"
ROOT_PACKAGE="$STAGE/$PACKAGE"
test "$(sha256sum minisign.pub | awk '{ print $1 }')" = \
  200d64c2f2e42ace790a6d74f8b101801065b2d9a51c8fdda5b47b4f2b2f9809
minisign -V -q -p minisign.pub -m SHA256SUMS -x SHA256SUMS.minisig
awk -v package="$PACKAGE" \
  'NF == 2 && $2 == package && length($1) == 64 && $1 ~ /^[0-9a-f]+$/ { print }' \
  SHA256SUMS > package.sha256
test "$(wc -l < package.sha256)" -eq 1
sha256sum -c package.sha256
minisign -V -q -p minisign.pub -m "$PACKAGE" -x "$PACKAGE.minisig"

case "$FORMAT" in
  deb)
    # Require the exact dependency set and installed state before unpacking.
    DEB_DEPENDS=$(dpkg-deb -f "$ROOT_PACKAGE" Depends)
    test "$DEB_DEPENDS" = \
      'ca-certificates, curl, libc6, libgcc-s1, mawk, minisign, sqlite3, systemd'
    for dependency in ca-certificates curl libc6 libgcc-s1 mawk minisign sqlite3 systemd; do
      test "$(dpkg-query -W -f='${db:Status-Status}' "$dependency" 2>/dev/null)" = \
        installed
    done
    dpkg -i "$ROOT_PACKAGE"
    ;;
  rpm)
    # Check dependencies and transaction validity before the normal SELinux install.
    rpm -Uvh --test "$ROOT_PACKAGE"
    rpm -Uvh "$ROOT_PACKAGE"
    ;;
  arch)
    # The signed wrapper checks dependencies and state before invoking Pacman.
    ROOT_INSTALLER="$STAGE/vaultlink-package-install.sh"
    bsdtar -xOf "$ROOT_PACKAGE" \
      usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh >"$ROOT_INSTALLER"
    chown root:root "$ROOT_INSTALLER"
    chmod 0700 "$ROOT_INSTALLER"
    "$ROOT_INSTALLER" "$ROOT_PACKAGE"
    rm -- "$ROOT_INSTALLER"
    ;;
  *) exit 64 ;;
esac

# Clean up only after successful installation; retain inputs on any failure.
rm -- "$PACKAGE" "$PACKAGE.minisig" SHA256SUMS SHA256SUMS.minisig \
  minisign.pub package.sha256
cd /
rmdir -- "$STAGE"
VERIFY_AND_INSTALL
INSTALL
```

If the block fails, stop and use the printed staging directory for diagnosis
and recovery. Do not run a package-manager command to bypass a failed check.
Never verify a user-writable pathname and later pass that pathname to a
privileged package operation; the verified object and installed object must
be the same root-owned file.

These commands do not use a VaultLink package repository. The DEB dependency
check above is a mandatory offline preflight of the exact `Depends` field; do
not run `dpkg -i` until every listed package reports `installed`. If `dpkg -i`
nevertheless fails for a missing dependency after leaving `vaultlink`
unpacked, keep the application service and update timer inactive and disabled,
install the missing dependency manually with the operating system's package
manager, and continue that same transaction only with
`sudo dpkg --configure vaultlink`. Do not run `dpkg -i` again over the unpacked
package. Stop for manual recovery if the package database, candidate, marker,
or runtime cannot subsequently prove exact parity. RPM and Arch likewise
require their complete dependencies before the offline VaultLink package
transaction. `cifs-utils` is required only when VaultLink itself provisions or
mounts SMB storage.

Do not use a direct initial `pacman -U`. Pacman 7 can register a package even
when an `.INSTALL` hook rejects unsafe pre-existing state, so VaultLink's
signed, embedded Arch wrapper performs the fail-closed preflight and verifies
the postconditions around `pacman -U`. Package updates are still performed by
the verified VaultLink updater through Pacman.

On Arch, ordinary removal must use the installed, signed
`/usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh` wrapper. A
later reinstall must use `vaultlink-package-install.sh` extracted from the
new, root-staged, Minisign-verified package as shown above. Direct
`pacman -R vaultlink` and direct manual reinstall with `pacman -U` are
unsupported. Removal, reinstall, and signed updates preserve both the
intentional absence of `/etc/vaultlink/update.conf` and, when it is present,
the same file, inode, bytes, owner, mode, and modification time.

The package installs a candidate under `/usr/lib/vaultlink/package`, creates a
package-bound installation marker, and places the initial runtime under
`/opt/vaultlink`. It never creates or overwrites a production `config.toml` and
does not enable or start the service or updater timer. Existing markerless
archive installations are rejected; the withdrawn 0.5.0 archive has no
supported in-place adoption path into the native 0.6.0-and-newer release line.

Adjust `ReadWritePaths=/mnt/storage` with a systemd drop-in when using another
validated mount base. Packaged examples include the equivalent of
[deploy/mnt-storage.mount.example](../deploy/mnt-storage.mount.example) and
[deploy/vaultlink-external-storage.conf](../deploy/vaultlink-external-storage.conf).

The package also installs the root-owned updater as
`/usr/sbin/vaultlink-update`. Its daily timer and automatic installation remain
disabled until the administrator explicitly opts in.

The upcoming GUI controls are documented separately in the
[upgrade guide](UPGRADE-ROLLBACK.md#gui-updates-starting-with-070-unreleased).
For the currently published version, use the command line:

```sh
sudo vaultlink-update check
sudo vaultlink-update install

# Optional unattended updates: bootstrap the packaged example once, then review it.
if sudo test ! -e /etc/vaultlink/update.conf && \
   sudo test ! -L /etc/vaultlink/update.conf; then
  sudo install -o root -g root -m 0644 \
    /usr/share/vaultlink/update.conf.example /etc/vaultlink/update.conf
fi
sudoedit /etc/vaultlink/update.conf
sudo systemctl enable --now vaultlink-update.timer
```

Set exactly `auto_install=true` to permit `auto` to install a newer signed
package, and only while `vaultlink.service` was already active. A deliberately
stopped service remains stopped. Signed updater installation and its automatic
recovery verify both the new and currently installed release packages and use
no distro repository during the transaction. A standalone rollback first requires
the matching signed target package to be installed, then binds the frozen
root-only backup to that package's database record, candidate, and runtime
guard before activation. Both paths preserve state and require package
database, candidate, active binary, and readiness versions to agree.

Every service start first runs the root-owned package/runtime parity guard.
`StartLimitIntervalSec=1h` and `StartLimitBurst=3` bound repeated fail-closed
starts after a crash or power loss. The root updater needs
`ProtectSystem=false` because native package-manager hooks have distro-owned
write sets. `NoNewPrivileges=true` remains active. Exactly the six bounded
transaction capabilities are carried across package-manager and scriptlet
execs; the `vaultlink` credential boundary drops all permitted, effective, and
ambient capabilities before a candidate is executed. Full-system gates verify
that boundary on every target. All unrelated namespace, device, kernel,
process, and network hardening remains enabled, and the oneshot is bounded by
`TimeoutStartSec=90min` and `TimeoutStopSec=30min`.

Fedora updater transactions use RPM's `--nocontexts` option because RPM's
scriptlet-specific SELinux domain transition is incompatible with the retained
`NoNewPrivileges=true` boundary. SELinux itself remains `Enforcing`; this
narrow transaction mode is entered only after the signed RPM, exact reviewed
scriptlets, metadata, payload allowlist, and dependencies have passed the
updater's fail-closed validation. Initial manual RPM installation continues to
use normal SELinux context handling, and the booted Fedora gate verifies the
actual update-unit path with no VaultLink-related AVC denial.

### Provision a CIFS mount safely

First create `.vaultlink-internal/{uploads,tombstones}` on the SMB server with the ACLs in [the SMB storage guide](../docs/CONFIGURATION.md#external-smb-server-with-standard-clients). Then provision the mount as root; the password is read interactively from the terminal and is never a CLI argument:

```sh
sudo /opt/vaultlink/vaultlink provision-cifs \
  --source //fileserver.example/vaultlink \
  --username vaultlink-service \
  --domain EXAMPLE
```

This command is intentionally confined to `/mnt/storage`, creates only new files, and refuses to overwrite existing credentials or systemd units. It enforces SMB 3.1.1 signing, encryption, strict caching, and the hardened mount flags in that storage guide.

### Initial browser setup through an SSH tunnel

Open a normal SSH session:

```sh
ssh admin@server.example.com
```

Start setup as the eventual service user in a private staging directory:

```sh
sudo install -d -o vaultlink -g vaultlink -m 0700 /var/lib/vaultlink/setup
sudo -u vaultlink /opt/vaultlink/vaultlink setup \
  --config /var/lib/vaultlink/setup/config.toml \
  --listen 127.0.0.1:8090
```

Open the printed IPv4 tunnel in a second local terminal:

```sh
ssh -4 -N -L 127.0.0.1:8090:127.0.0.1:8090 admin@server.example.com
```

Open `http://127.0.0.1:8090/#token=...` locally. The fragment keeps the one-time token out of the HTTP request and browser history after bootstrap. After safely storing the TOTP secret, stop setup with Ctrl+C instead of starting the server directly, then install the generated configuration and start the service:

```sh
sudo install -o root -g vaultlink -m 0640 \
  /var/lib/vaultlink/setup/config.toml /etc/vaultlink/config.toml
sudo -u vaultlink rm /var/lib/vaultlink/setup/config.toml
sudo rmdir /var/lib/vaultlink/setup
sudo -u vaultlink test -r /etc/vaultlink/config.toml
sudo systemctl enable --now vaultlink
```

Never expose setup with `--listen 0.0.0.0:8090`; no non-loopback exception exists.

### Configuration without browser setup

Adapt the matching release's configuration example to your storage mount, public
HTTPS URL, and trusted proxy before starting VaultLink. Use the example
included in the installed package; no source checkout is needed.

```sh
sudo install -o root -g vaultlink -m 0640 \
  /usr/share/doc/vaultlink/examples/config/production-reverse-proxy.toml \
  /etc/vaultlink/config.toml
sudoedit /etc/vaultlink/config.toml
sudo -u vaultlink /opt/vaultlink/vaultlink init-admin --config /etc/vaultlink/config.toml --username admin
sudo systemctl enable --now vaultlink
```

### Local administrator recovery

Always run recovery as `vaultlink` so SQLite/WAL/SHM ownership stays correct:

```sh
# Reset only the password
sudo -u vaultlink /opt/vaultlink/vaultlink recover-admin \
  --config /etc/vaultlink/config.toml \
  --username admin \
  --reset-password

# Reset only MFA
sudo -u vaultlink /opt/vaultlink/vaultlink recover-admin \
  --config /etc/vaultlink/config.toml \
  --username admin \
  --reset-mfa

# Replace password and MFA atomically
sudo -u vaultlink /opt/vaultlink/vaultlink recover-admin \
  --config /etc/vaultlink/config.toml \
  --username admin \
  --reset-password \
  --reset-mfa
```

If the configuration cannot be validated, address the database directly:

```sh
sudo -u vaultlink /opt/vaultlink/vaultlink recover-admin \
  --database /var/lib/vaultlink/data.sqlite \
  --username admin \
  --reset-password \
  --reset-mfa
```

Recovery revokes the administrator's sessions and pending MFA enrollments and writes an audit event without credentials. It does not reactivate a deactivated administrator. There is intentionally no public password/MFA reset endpoint.
