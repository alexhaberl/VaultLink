# Container setup entrypoint

VaultLink intentionally binds its bootstrap setup UI and development server to
loopback. Docker port publishing cannot reach a listener on the container's
loopback interface directly. The container entrypoint keeps that boundary and
exposes a separate TCP proxy port instead of changing VaultLink to a wildcard
listener.

The default topology is:

- container proxy: `0.0.0.0:8081`
- setup and default development listener: `127.0.0.1:8080`
- host example: `127.0.0.1:18080` published to container port `8081`

The proxy first connects to the setup listener. After setup has committed the
configuration and transitioned in the same process, it reads only
`server.listen_address` from that configuration and forwards to the configured
loopback listener. Non-loopback configured targets are never proxied.

The repository's digest-pinned smoke image can exercise this flow locally. It
is a test image with build tools, not the final minimal runtime image:

```sh
docker build -f deploy/docker/Dockerfile.setup-smoke -t vaultlink:smoke .
docker volume create vaultlink-state
docker volume create vaultlink-storage
docker run --rm --name vaultlink-preview \
  --publish 127.0.0.1:18080:8081 \
  --volume vaultlink-state:/var/lib/vaultlink \
  --volume vaultlink-storage:/mnt/storage \
  --env VAULTLINK_BIN=/work/target/release/vaultlink \
  vaultlink:smoke bash deploy/docker/container-entrypoint.sh
```

Open the tokenized URL printed by the container. For a persistent local
development preview, choose `/mnt/storage` as the root and keep
`/var/lib/vaultlink` as the data directory. Do not expose host port `18080`
beyond loopback: the setup token grants bootstrap access.

The entrypoint accepts these overrides:

- `VAULTLINK_BIN` (default `/opt/vaultlink/vaultlink`)
- `VAULTLINK_CONFIG_PATH` (default `/var/lib/vaultlink/config.toml`)
- `VAULTLINK_SETUP_ADDR` (default `127.0.0.1:8080`)
- `VAULTLINK_CONTAINER_ADDR` (default `0.0.0.0:8081`)

Production CIFS deployments still require their server-side ACL and reserved
`.vaultlink-internal` layout to be provisioned before VaultLink starts. A
standalone-TLS service with a non-loopback configured listener must publish its
service port directly; the loopback proxy deliberately refuses that target.
