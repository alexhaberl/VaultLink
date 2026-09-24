# Rootless Docker Engine deployment (Linux amd64 and arm64)

The official rootless variant runs both the Docker daemon and the VaultLink
container as unprivileged users. Use the signed release tag, its immutable GHCR
index digest, and `deploy/docker/compose.rootless.yaml` from that tag. The
published 0.7.1 release predates this image.

## Host and storage

Install Docker Engine Rootless mode for a dedicated service account following
the [Docker Rootless guide](https://docs.docker.com/engine/security/rootless/).
Ensure `newuidmap`, `newgidmap`, and at least 65,536 subordinate UIDs and GIDs
are configured. Enable the per-user systemd service and lingering for startup.
Confirm that `docker info` lists `rootless` under Server Security Options and
that `docker context show` selects that daemon. Being in the `docker` group or
setting `user: 10001:10001` alone does not make the daemon rootless.

The rootless Compose file uses two **Docker-managed volumes** on the daemon's
local ext4/XFS/Btrfs backing filesystem. Keep Docker's data root on a local
filesystem; `vaultlink-state` contains the private config, SQLite database and
keyring, while `vaultlink-storage` holds shared files. The two volumes must
remain distinct. This variant is for **local storage**. For a host-mounted SMB
share, follow the standard [Docker Engine deployment](DOCKER.md) or the
[NixOS guide](NIXOS.md); rootless bind mounts and CIFS UID mapping require
separate host-specific qualification.

After recording the release index digest in a private environment file, create
the private directory layout through the rootless daemon. Replace the digest
placeholder and run these commands as the dedicated rootless service account:

```sh
cat > "$HOME/vaultlink-docker.env" <<'EOF'
VAULTLINK_IMAGE=ghcr.io/alexhaberl/vaultlink@sha256:REPLACE_WITH_RELEASE_INDEX_DIGEST
VAULTLINK_HOST_PORT=18080
EOF
chmod 0600 "$HOME/vaultlink-docker.env"
docker info --format '{{json .SecurityOptions}}'
docker compose --env-file "$HOME/vaultlink-docker.env" \
  -f deploy/docker/compose.rootless.yaml run --rm --user 0 \
  --entrypoint bash vaultlink -ec \
  'install -d -o 10001 -g 10001 -m 0700 \
   /var/lib/vaultlink /mnt/storage/shared \
   /mnt/storage/.vaultlink-internal \
   /mnt/storage/.vaultlink-internal/uploads \
   /mnt/storage/.vaultlink-internal/tombstones'
docker compose --env-file "$HOME/vaultlink-docker.env" \
  -f deploy/docker/compose.rootless.yaml up -d
```

The bootstrap helper runs as UID 0 **inside the rootless user namespace** to
prepare Docker-managed volumes. The VaultLink service still runs as UID 10001
with all capabilities dropped and a read-only root filesystem.

Inspect the container's `/proc/self/mountinfo` for `/mnt/storage` and enter its
literal filesystem type and source in setup. Set
`root_mount_path=/mnt/storage/shared`,
`internal_directory=/mnt/storage/.vaultlink-internal`, and
`data_directory=/var/lib/vaultlink`. Follow the browser and TLS steps in the
[standard deployment guide](DOCKER.md#browser-setup-and-access). The port binds
to host loopback; expose VaultLink through a separately managed HTTPS reverse
proxy. Keep one service instance per storage volume pair.

## Upgrade and recovery

Pin the new release digest and Compose file from the same signed tag. Before
activating it, stop external ingress and the container, then back up the
**entire** stopped `vaultlink-state` and `vaultlink-storage` volumes together
with the previous digest and Compose file. A temporary helper container on the
same rootless daemon can archive each volume to a protected local directory.
Verify the database with `PRAGMA integrity_check`, the new binary version,
readiness and file hashes before opening ingress. On failure, stop the service,
restore both previous volumes and the previous digest from the paired backup,
then repeat those checks. An image-only rollback after a schema migration is
unsafe. See [recovery rules](UPGRADE-ROLLBACK.md#recovery-rules).
