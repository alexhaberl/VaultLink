# One-time proxy migration from 0.7.1

VaultLink 0.7.1 accepts an IP-only reverse-proxy configuration. New releases
require an authenticated Unix socket or mTLS proxy connection. Keep the old
binary and `/etc/vaultlink/config.toml` paired and running while preparing a
**separate** candidate. Never replace the live configuration before the
signed update transaction. Close external ingress before activation and keep
it closed if either side of the proxy pair fails validation.

The updater already installed with 0.7.1 has no candidate-config argument.
Its automatic timer cannot safely perform this migration. The new package's
preinstall script rejects the legacy configuration and missing proxy group
before unpacking it, so an accidental old-updater attempt fails closed. For
the first transition, use the **new updater extracted from the separately
Minisign-verified release package**. Do not run an updater downloaded as an
unverified standalone script.

The following Debian 13 amd64 example assumes a chosen, immutable release
`vNEW_VERSION` and a root-only staging directory. Adjust the exact package
name for the target using the signed release manifest. These commands operate
only on the local host; perform them in a scheduled maintenance window.

```sh
sudo -s
sudo install -d -o root -g root -m 0700 /var/lib/vaultlink-backups/proxy-migration
cd /var/lib/vaultlink-backups/proxy-migration
# Download the chosen release's package, PACKAGE.minisig, SHA256SUMS and
# SHA256SUMS.minisig from the official release into this protected directory.
sudo minisign -Vm SHA256SUMS -x SHA256SUMS.minisig \
  -p /usr/share/vaultlink/minisign.pub
sudo minisign -Vm PACKAGE.deb -x PACKAGE.deb.minisig \
  -p /usr/share/vaultlink/minisign.pub
sudo awk '$2 == "PACKAGE.deb" { print; found=1 } END { if (!found) exit 1 }' \
  SHA256SUMS | sudo sha256sum -c -
sudo install -d -o root -g root -m 0700 extracted
sudo dpkg-deb -x PACKAGE.deb extracted
sudo systemd-sysusers extracted/usr/lib/sysusers.d/vaultlink.conf
exit
```

Use the real package filename in place of `PACKAGE.deb`; do not literally
execute the placeholder. On RPM or Arch, extract the equivalent verified
package with the native archive tool into the same protected directory. The
signed package contains `usr/sbin/vaultlink-update` on DEB/RPM and
`usr/bin/vaultlink-update` on Arch. The process requires the updater's existing
exact-package verification, so the extracted script validates the release,
installed package, marker and signatures again before mutation.

Prepare one of these transports:

- **Local Unix:** provision the dedicated `vaultlink-proxy` group; run the
  proxy as a dedicated non-root UID, grant it only that group, and set
  `proxy_uids = [ACTUAL_UID]`. The package unit creates
  `/run/vaultlink-proxy` as service UID, proxy GID, mode `0750`; the socket
  becomes `0660`. The proxy must have no `vaultlink` data-group membership.
- **Network mTLS:** place the server key, certificate, and dedicated proxy CA
  in protected local files readable by the VaultLink service. Pin the proxy
  client leaf certificate's DER SHA-256 in `client_fingerprints`. Configure the
  proxy to validate the backend certificate and its name. Keep the network
  ingress closed until a valid client certificate succeeds.

Copy the live config to `/etc/vaultlink/proxy-next.toml`, owned by
`root:vaultlink` with mode `0640`, and edit only the candidate. Keep
`/etc/vaultlink` at `root:vaultlink` mode `0750`. The
[configuration guide](CONFIGURATION.md#reverse-proxy-recommended) contains
the exact Unix and mTLS fields. Then preflight both pairs without stopping the
service:

```sh
sudo install -o root -g vaultlink -m 0640 \
  /etc/vaultlink/config.toml /etc/vaultlink/proxy-next.toml
sudoedit /etc/vaultlink/proxy-next.toml
sudo -u vaultlink /opt/vaultlink/vaultlink readiness-target \
  --config /etc/vaultlink/config.toml
sudo sh -c 'exec 7</var/lib/vaultlink-backups/proxy-migration/extracted/usr/lib/vaultlink/package/vaultlink; \
  runuser -u vaultlink -- /proc/self/fd/7 readiness-target \
  --config /etc/vaultlink/proxy-next.toml'
sudo stat -c '%U:%G:%a' /etc/vaultlink/proxy-next.toml
```

Run the verified new updater with an expected version and explicit candidate
path after external ingress is closed. The new updater validates both pairs,
the candidate's path and permissions, the signed old and new packages, and
dependencies **before package installation or service downtime**. Its backup,
activation, readiness check and failure recovery keep Binary, configuration,
SQLite and keyring paired. It does not open the external proxy for you.

```sh
sudo VAULTLINK_EXPECTED_VERSION=NEW_VERSION \
  /var/lib/vaultlink-backups/proxy-migration/extracted/usr/sbin/vaultlink-update \
  install --candidate-config /etc/vaultlink/proxy-next.toml
sudo systemctl is-active vaultlink.service
sudo -u vaultlink /opt/vaultlink/vaultlink readiness-target \
  --config /etc/vaultlink/config.toml
sudo -u vaultlink /opt/vaultlink/vaultlink health-check --ready
sudo sqlite3 /var/lib/vaultlink/data.sqlite 'PRAGMA integrity_check;'
```

For Unix, verify the proxy's actual UID, group, socket ownership, and
forwarded-header behavior over the socket. For mTLS, verify that missing and
unlisted client certificates fail and a listed client certificate succeeds;
the proxy must reject the wrong backend server name. Only then reopen external
ingress. If recovery fails, keep ingress closed and restore the complete
verified backup with its old package; never point the old binary at a migrated
database. Automatic updates can resume only after the installed configuration
passes the new preflight. Future certificate rotation requires overlapping
fingerprints and a coordinated restart.
