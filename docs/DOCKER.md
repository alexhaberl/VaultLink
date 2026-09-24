# Docker Engine deployment (Linux amd64 and arm64)

The first official container image is planned for the next release. The
published 0.7.1 release has no VaultLink runtime image. Use the signed release
tag, its matching immutable GHCR image digest, and the Compose file from that
same tag. The image is built natively for `linux/amd64` and `linux/arm64`; the
release workflow publishes its multiarch index only after the signed, immutable
native release is published. Do not deploy an image built from a development
branch as a production release.

## Host storage

Use a dedicated Linux host with Docker Engine and Compose. Provision two
different paths before starting the container:

- `VAULTLINK_STATE_DIR`: a private directory on a local ext4, XFS, Btrfs or
  other supported local filesystem. It holds `config.toml`, SQLite and
  `secrets.keyring`. Back them up together.
- `VAULTLINK_STORAGE_DIR`: the root of a mounted local filesystem or a CIFS
  3.1.1 share. VaultLink audits its actual mount identity and refuses startup
  when the configured source or type changes.

For an ext4 volume mounted at `/srv/vaultlink/storage`, prepare ownership on
the host. The container runs as UID/GID `10001:10001` without capabilities.
The state and storage paths must not overlap.

```sh
sudo install -d -o 10001 -g 10001 -m 0700 /srv/vaultlink/state
sudo install -d -o 10001 -g 10001 -m 0700 \
  /srv/vaultlink/storage/shared \
  /srv/vaultlink/storage/.vaultlink-internal \
  /srv/vaultlink/storage/.vaultlink-internal/uploads \
  /srv/vaultlink/storage/.vaultlink-internal/tombstones
findmnt --target /srv/vaultlink/storage --output TARGET,FSTYPE,SOURCE,OPTIONS
```

Mount the ext4 volume with `nosuid,nodev,noexec` and make it available before
Docker starts VaultLink. If using SMB, mount the share **on the Linux host**
before starting Compose. Use a root-owned `0600` credentials file and the
audited options `vers=3.1.1,sec=ntlmsspi,seal,cache=strict,serverino,nosuid,
nodev,noexec,uid=10001,gid=10001,file_mode=0600,dir_mode=0700`. The SMB
server must provide the private `.vaultlink-internal/{uploads,tombstones}`
layout and ACL described in [configuration](CONFIGURATION.md). Keep SQLite in
`VAULTLINK_STATE_DIR` on a **local** filesystem; never put it on SMB. A second
VaultLink instance must not use the same storage root.

## Image and Compose

After the release is published, inspect its multiarch index and record the
immutable digest. Replace `vX.Y.Z` with the actual supported signed tag:

```sh
docker buildx imagetools inspect ghcr.io/alexhaberl/vaultlink:vX.Y.Z
# Confirm both linux/amd64 and linux/arm64, then copy the top-level Digest.
```

Create a private environment file outside the repository. The example digest
below is a placeholder; do not use it literally.

```sh
sudo install -d -m 0700 /etc/vaultlink
sudo editor /etc/vaultlink/docker.env
```

```dotenv
VAULTLINK_IMAGE=ghcr.io/alexhaberl/vaultlink@sha256:REPLACE_WITH_RELEASE_INDEX_DIGEST
VAULTLINK_STATE_DIR=/srv/vaultlink/state
VAULTLINK_STORAGE_DIR=/srv/vaultlink/storage
VAULTLINK_HOST_PORT=18080
```

Use `deploy/docker/compose.yaml` from the same tag:

```sh
docker compose --env-file /etc/vaultlink/docker.env \
  -f deploy/docker/compose.yaml config --quiet
docker compose --env-file /etc/vaultlink/docker.env \
  -f deploy/docker/compose.yaml up -d
docker compose --env-file /etc/vaultlink/docker.env \
  -f deploy/docker/compose.yaml ps
```

The Compose file binds port 8081 to host loopback only, keeps the root
filesystem read-only, drops capabilities, and allows writes only in the two
explicit bind mounts and a small private `/tmp`. Do not publish port 8081 on a
public address. Place a TLS reverse proxy in front of the host-local port.
The container proxy routes setup and service traffic to VaultLink's loopback
listener. In the browser setup select **reverse proxy**, use an `https://`
public URL, set the service listener to `127.0.0.1:8080`, and configure the
exact trusted proxy peer addresses. See the
[container proxy guide](CONTAINER-SETUP.md) for forwarded-header behavior.

Before committing setup, inspect the **container's** mount record and put its
literal filesystem type and source into `expected_filesystem_type` and
`expected_mount_source`. The host's `findmnt` output may normalize a device
name differently.

```sh
container=$(docker compose --env-file /etc/vaultlink/docker.env \
  -f deploy/docker/compose.yaml ps -q vaultlink)
docker exec "$container" cat /proc/self/mountinfo \
  | awk '$5 == "/mnt/storage" {for (i=1; i<=NF; i++) if ($i == "-") {
      print "expected_filesystem_type = \"" $(i+1) "\""
      print "expected_mount_source = \"" $(i+2) "\""
      exit
    }}'
```

For a local ext4 volume, set `root_mount_path=/mnt/storage/shared`,
`internal_directory=/mnt/storage/.vaultlink-internal`, and
`data_directory=/var/lib/vaultlink`. For an SMB share, the root can be
`/mnt/storage` with its private direct child; retain the server ACL.
VaultLink verifies the mount, ownership, CIFS options, and SQLite location at
startup. An absent or wrong mount is a failed deployment, not a reason to
disable `require_mount`.

## Browser setup and access

The setup URL with its one-time token is printed by `docker compose logs
vaultlink`. Reach the host-local port through an SSH tunnel:

```sh
ssh -4 -N -L 127.0.0.1:18080:127.0.0.1:18080 USER@SERVER
```

Open the tokenized URL on your workstation with port `18080`, complete setup,
and save the displayed TOTP secret. VaultLink then starts within the same
container. After a container restart, the entrypoint sees the existing private
`config.toml` and starts the service directly. Check readiness:

```sh
curl --fail http://127.0.0.1:18080/api/v2/health/ready
```

Terminate TLS at a reverse proxy that reaches only the host-local port. Keep
its proxy IP allowlist narrow; Docker NAT can make the observed TCP peer a
bridge or host-gateway address. Add that exact address only when the published
port remains host-local. Follow the [HTTPS configuration guide](CONFIGURATION.md)
for secure cookies and trusted headers.

## Backup, upgrade and recovery

The GUI does not install or schedule updates for a container. Pin a new signed
release image digest and update the Compose file from the same release tag.
Build or pull the new image **before** the maintenance window. Record the old
image digest and retain its tag checkout. Stop external ingress, then stop the
container before backing up data:

```sh
docker pull ghcr.io/alexhaberl/vaultlink@sha256:NEW_RELEASE_INDEX_DIGEST
docker compose --env-file /etc/vaultlink/docker.env \
  -f deploy/docker/compose.yaml stop vaultlink
sudo sqlite3 /srv/vaultlink/state/data.sqlite \
  'PRAGMA wal_checkpoint(TRUNCATE); PRAGMA integrity_check;'
sudo install -d -o root -g root -m 0700 /var/backups/vaultlink/BEFORE-NEW-TAG
sudo cp -a /srv/vaultlink/state/. /var/backups/vaultlink/BEFORE-NEW-TAG/
sudo cp /etc/vaultlink/docker.env /var/backups/vaultlink/BEFORE-NEW-TAG/docker.env
sudo sh -c 'cd /var/backups/vaultlink/BEFORE-NEW-TAG && \
  sha256sum config.toml data.sqlite secrets.keyring docker.env > SHA256SUMS'
```

The state backup contains the matching configuration, SQLite database and
keyring. Protect it as credential material and back up the mounted file store
consistently as well. Replace the image digest in `/etc/vaultlink/docker.env`,
start Compose, and verify the binary version, readiness, and SQLite integrity
before reopening ingress. Check hashes and ownership of the backup.

If an upgrade fails, keep ingress closed and stop the container. Restore the
**previous image digest and its matching entire stopped state backup**
including config, database and keyring; remove the failed SQLite WAL sidecars
only during this stopped restore. Start the old image and confirm readiness,
version, file access and `PRAGMA integrity_check` before reopening ingress.
Keep the service stopped if any restore or check fails. Rolling back only the
image after a database migration is unsafe. A database rollback may require
revoking service tokens as described in
[recovery rules](UPGRADE-ROLLBACK.md#recovery-rules).

## Docker Desktop development preview

Docker Desktop on Windows is supported only as a development preview. A
Windows bind mount appears as `9p` inside the Linux container and fails the
production mount audit. Use Docker-managed Linux volumes and development mode
for local experiments; the [setup smoke guide](CONTAINER-SETUP.md) shows the
existing preview. It is not evidence of an official Linux server deployment.
