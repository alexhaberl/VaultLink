# NixOS 26.05 deployment

The repository flake provides VaultLink for `x86_64-linux` and `aarch64-linux`.
Use a reviewed, signed VaultLink release tag and retain the exact revision in
your host's `flake.lock`. The currently published 0.7.1 release predates this
target; do not treat a checkout of `main` as a supported release.

## Host configuration

Import `vaultlink.nixosModules.default` in the host flake and pin its input to
the supported tag. For example, replace `vX.Y.Z` with that tag:

```nix
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  inputs.vaultlink.url = "github:alexhaberl/VaultLink/vX.Y.Z";
  outputs = { nixpkgs, vaultlink, ... }: {
    nixosConfigurations.my-host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux"; # or aarch64-linux
      modules = [
        vaultlink.nixosModules.default
        ({ ... }: {
          services.vaultlink = {
            enable = true;
            storageMountPath = "/mnt/storage";
            configFile = "/etc/vaultlink/config.toml";
          };
        })
      ];
    };
  };
}
```

The module creates a static `vaultlink` user and private state directories. It
does not put the TOML configuration, SMB credentials, SQLite database or
`secrets.keyring` in the Nix store. It skips startup until the configuration
exists. Once installed, package updates and automatic updates in the web UI
remain unavailable; update the pinned flake and rebuild the host instead.

Prepare an existing ext4, XFS, Btrfs or other audited local filesystem as a
real mount at `storageMountPath`, or configure a CIFS mount in the host's
`fileSystems` using the exact options in [the storage guide](CONFIGURATION.md).
For an ext4 volume, first provision the filesystem and its UUID outside Nix,
then declare the mount in the host module:

```nix
fileSystems."/mnt/storage" = {
  device = "/dev/disk/by-uuid/REPLACE-WITH-REAL-UUID";
  fsType = "ext4";
  options = [ "nosuid" "nodev" "noexec" ];
};
```

For a pre-provisioned SMB share, keep the credential file root-owned at
`/etc/vaultlink/smb.credentials` with mode `0600`; put only its **path** in the
Nix configuration:

```nix
boot.supportedFilesystems = [ "cifs" ];
fileSystems."/mnt/storage" = {
  device = "//fileserver.example/vaultlink";
  fsType = "cifs";
  options = [
    "credentials=/etc/vaultlink/smb.credentials" "_netdev"
    "vers=3.1.1" "sec=ntlmsspi" "seal" "cache=strict" "serverino"
    "nosuid" "nodev" "noexec"
    "uid=vaultlink" "gid=vaultlink" "file_mode=0600" "dir_mode=0700"
  ];
};
```

For SMB, pre-provision `.vaultlink-internal/{uploads,tombstones}` server-side
and enforce the documented server ACL. Mount with SMB 3.1.1, signing,
encryption, strict cache, stable inode numbers, `nosuid,nodev,noexec`, and the
dedicated VaultLink account. For local storage mounted at `/mnt/storage`, use
`root_mount_path = "/mnt/storage/shared"` and
`internal_directory = "/mnt/storage/.vaultlink-internal"`; the latter is the
required private sibling lock domain. Create it with private
`uploads` and `tombstones` subdirectories owned by `vaultlink:vaultlink`.

```sh
sudo install -d -o vaultlink -g vaultlink -m 0700 \
  /mnt/storage/shared /mnt/storage/.vaultlink-internal \
  /mnt/storage/.vaultlink-internal/uploads \
  /mnt/storage/.vaultlink-internal/tombstones
```

For SMB, the share root can be
`root_mount_path = "/mnt/storage"` with its reserved internal child. Put
`/var/lib/vaultlink`, SQLite and the keyring
on a separate supported local filesystem. Never run two instances on one
storage root.

Inspect the active kernel mount record, then set the **literal** filesystem
type and source it reports in the private TOML file:

```sh
findmnt --target /mnt/storage --output TARGET,FSTYPE,SOURCE,OPTIONS
mount_id=$(findmnt --target /mnt/storage --noheadings --output ID)
awk -v id="$mount_id" '$1 == id { for (i = 1; i <= NF; i++) if ($i == "-") {
  print "expected_filesystem_type = \"" $(i+1) "\""
  print "expected_mount_source = \"" $(i+2) "\""
  exit
}}' /proc/self/mountinfo
```

An `UUID=` entry in `fileSystems` is not necessarily the mount source seen by
VaultLink. The service refuses a missing mount, wrong source, wrong type,
unsafe ownership or remote SQLite filesystem. Make the shared root and reserved
internal directory owned by `vaultlink:vaultlink` and inaccessible for
group/other writes. Use a reverse proxy with HTTPS or VaultLink's standalone
TLS mode as described in [configuration](CONFIGURATION.md).

## Initial browser setup

After activating the host configuration, run setup as `vaultlink` into its
private staging directory. Expose the setup listener only through an SSH
tunnel; save the displayed TOTP secret. The commands mirror the native
[installation guide](INSTALLATION.md#initial-browser-setup-through-an-ssh-tunnel):

```sh
sudo -u vaultlink /run/current-system/sw/bin/vaultlink setup \
  --config /var/lib/vaultlink/setup/config.toml --listen 127.0.0.1:8090
# In another terminal: ssh -4 -N -L 127.0.0.1:8090:127.0.0.1:8090 host
```

After stopping setup with Ctrl+C, install the generated configuration and
start the service:

```sh
sudo install -o root -g vaultlink -m 0640 \
  /var/lib/vaultlink/setup/config.toml /etc/vaultlink/config.toml
sudo -u vaultlink rm /var/lib/vaultlink/setup/config.toml
sudo systemctl start vaultlink.service
curl --fail http://127.0.0.1:8080/api/v2/health/ready
```

## Guided upgrade and recovery

Build the new pinned host generation **before** touching the live instance.
Keep the old system generation and the old VaultLink flake lock. Schedule a
maintenance window, close external ingress and stop `vaultlink.service`.
After changing the host flake input to the reviewed new release tag and
updating its committed lock, build without activation:

```sh
sudo nixos-rebuild build --flake /etc/nixos#my-host
```

With the process stopped, run a SQLite checkpoint and integrity check, then
copy the current executable, `/etc/vaultlink/config.toml`,
`/var/lib/vaultlink/data.sqlite` and `/var/lib/vaultlink/secrets.keyring` into
one new root-owned mode-`0700` backup directory. Record SHA-256 hashes and
owners/modes of every member. Protect the directory as credential material.
Do not copy an active SQLite database or combine files from separate backups.

```sh
sudo systemctl stop vaultlink.service
sudo sqlite3 /var/lib/vaultlink/data.sqlite 'PRAGMA wal_checkpoint(TRUNCATE); PRAGMA integrity_check;'
sudo install -d -o root -g root -m 0700 /var/backups/vaultlink
sudo install -d -o root -g root -m 0700 /var/backups/vaultlink/BEFORE-NEW-TAG
sudo cp -L /run/current-system/sw/bin/vaultlink /var/backups/vaultlink/BEFORE-NEW-TAG/vaultlink
sudo cp -a /etc/vaultlink/config.toml /var/lib/vaultlink/data.sqlite \
  /var/lib/vaultlink/secrets.keyring /var/backups/vaultlink/BEFORE-NEW-TAG/
sudo sh -c 'cd /var/backups/vaultlink/BEFORE-NEW-TAG && sha256sum vaultlink config.toml data.sqlite secrets.keyring > SHA256SUMS'
sudo stat -c '%n %U:%G %a' /var/backups/vaultlink/BEFORE-NEW-TAG/*
```

Activate the already built generation with `nixos-rebuild switch --flake
/etc/nixos#my-host`. Verify the running executable and health version, the
readiness endpoint, and `PRAGMA integrity_check` before reopening ingress.
For example:

```sh
sudo nixos-rebuild switch --flake /etc/nixos#my-host
/run/current-system/sw/bin/vaultlink --version
systemctl show -p ExecStart --value vaultlink.service
curl --fail http://127.0.0.1:8080/api/v2/health/ready
sudo sqlite3 /var/lib/vaultlink/data.sqlite 'PRAGMA integrity_check;'
```

If any check fails, close ingress and run the recovery commands below as one
root shell operation. A NixOS generation switch can start an enabled unit even
after a runtime mask, so move the active config file aside **before** switching
back. The module's `ConditionPathExists` then keeps VaultLink stopped while the
old generation is activated and its matching database and keyring are restored.
Remove stale SQLite WAL sidecars only as part of that stopped, verified
restore. The shell stops VaultLink on any failure; keep ingress closed and
recover manually if a generation or backup member is missing. Check ownership
and modes before reopening access. **Never use generation rollback alone after
a schema migration.** An older manual database restore also requires revoking
service tokens as described in [recovery rules](UPGRADE-ROLLBACK.md#recovery-rules).
Before any later rebuild, restore the host flake input and lock to the previous
VaultLink tag so the next generation does not reactivate the failed version.

```sh
sudo sh -eu <<'SH'
backup=/var/backups/vaultlink/BEFORE-NEW-TAG
failed=/var/backups/vaultlink/FAILED-NEW-TAG
trap 'systemctl stop vaultlink.service || true' 0
systemctl stop vaultlink.service
systemctl mask --runtime vaultlink.service
install -d -o root -g root -m 0700 "$failed"
test ! -e "$failed/config.toml"
mv /etc/vaultlink/config.toml "$failed/config.toml"
test ! -e /etc/vaultlink/config.toml
nixos-rebuild switch --rollback
test ! -e /etc/vaultlink/config.toml
if systemctl is-active --quiet vaultlink.service; then exit 1; fi
(cd "$backup" && sha256sum -c SHA256SUMS)
cmp "$backup/vaultlink" /run/current-system/sw/bin/vaultlink
rm -f /var/lib/vaultlink/data.sqlite-wal /var/lib/vaultlink/data.sqlite-shm
cp -a "$backup/data.sqlite" "$backup/secrets.keyring" /var/lib/vaultlink/
cp -a "$backup/config.toml" /etc/vaultlink/config.toml
cmp /etc/vaultlink/config.toml "$backup/config.toml"
cmp /var/lib/vaultlink/data.sqlite "$backup/data.sqlite"
cmp /var/lib/vaultlink/secrets.keyring "$backup/secrets.keyring"
test "$(sqlite3 /var/lib/vaultlink/data.sqlite 'PRAGMA integrity_check')" = ok
stat -c '%n %U:%G %a' /etc/vaultlink/config.toml \
  /var/lib/vaultlink/data.sqlite /var/lib/vaultlink/secrets.keyring
systemctl unmask --runtime vaultlink.service
systemctl reset-failed vaultlink.service
systemctl start vaultlink.service
curl --fail http://127.0.0.1:8080/api/v2/health/ready
trap - 0
SH
```

The native DEB/RPM/Pacman updater, GUI host controller, installation marker and
package-runtime guard do not apply to NixOS. NixOS package builds and local/SMB
VM tests are performed on both architectures by the repository's GitHub
workflow before a release can claim support.
