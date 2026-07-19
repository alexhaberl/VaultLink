# Container setup entrypoint

VaultLink intentionally binds its bootstrap setup UI and development server to
loopback. Docker port publishing cannot reach a listener on the container's
loopback interface directly. The container entrypoint keeps that boundary and
starts VaultLink's Rust/Hyper `container-proxy` subcommand on a separate port
instead of changing the application listener to a wildcard address. The same
VaultLink binary provides both processes; there is no second HTTP runtime.

The default topology is:

- container proxy: `0.0.0.0:8081`
- setup and default development listener: `127.0.0.1:8080`
- host example: `127.0.0.1:18080` published to container port `8081`

The proxy first connects to the setup listener. It refreshes a fail-closed
configuration snapshot every 250 ms on a blocking worker. After setup has
committed the configuration and transitioned in the same process, new
connections therefore use `server.listen_address` from that snapshot and are
forwarded to the configured loopback listener. Non-loopback configured targets
are never proxied.

The proxy is HTTP-aware at the container boundary and applies one of two trust
paths to each connection. A direct or otherwise untrusted peer cannot supply
its own identity: the proxy removes client-supplied `Forwarded` and
`X-Forwarded-For` headers and sets `X-Forwarded-For` to the TCP peer address.
This is the fail-closed default before setup and whenever the runtime
configuration is missing or invalid.

In production behind Caddy, Nginx, or another trusted proxy, configure that
proxy's exact container-facing TCP address in `reverse_proxy.trusted_proxies`
alongside the loopback peer used by VaultLink. When reverse-proxy header trust
is enabled, the container proxy accepts a forwarding chain only from an exact
allowlist match, validates every address, normalizes the chain, and appends the
immediate peer. Malformed trusted chains are rejected; an unlisted peer still
uses the direct-peer path. Docker NAT can make the observed peer a bridge or
host-gateway address instead of the proxy's service address. In that topology,
the gateway is the trust boundary and must be allowlisted explicitly only when
the published port remains host-local.

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
beyond loopback: the setup token grants bootstrap access. A production reverse
proxy may connect to this host-local port after setup; publishing the port on a
public host address is not a replacement for an authenticated TLS proxy.

The entrypoint accepts these overrides:

- `VAULTLINK_BIN` (default `/opt/vaultlink/vaultlink`)
- `VAULTLINK_CONFIG_PATH` (default `/var/lib/vaultlink/config.toml`)
- `VAULTLINK_SETUP_ADDR` (default `127.0.0.1:8080`)
- `VAULTLINK_CONTAINER_ADDR` (default `0.0.0.0:8081`)

Production CIFS deployments still require their server-side ACL and reserved
`.vaultlink-internal` layout to be provisioned before VaultLink starts. A
standalone-TLS service with a non-loopback configured listener must publish its
service port directly; the loopback proxy deliberately refuses that target.
