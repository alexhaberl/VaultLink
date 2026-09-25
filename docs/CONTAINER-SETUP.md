# Container setup and production listener

The official container exposes port `8081`. With no configuration, the
entrypoint starts a temporary HTTP bootstrap proxy on that port, the setup UI
on container loopback `127.0.0.1:8080`, and a separate loopback health listener
on `127.0.0.1:8082`. The health CLI reports live during setup and not ready.
Keep the published bootstrap port bound to host loopback and use an SSH tunnel
for the one-time setup token.

The setup form must select **reverse proxy**, `mtls`, a production listener of
`0.0.0.0:8081`, an HTTPS public URL, a server certificate and key, a dedicated
proxy-client CA, and the SHA-256 fingerprints of authorized client certificate
DER files. Store certificate material in a protected container volume owned by
the container UID `10001`; private keys must never be copied to the image.
The upstream proxy verifies the server certificate and server name and presents
its allowed client certificate. VaultLink validates both the CA chain and the
leaf fingerprint before serving HTTP.

After the operator confirms setup and selects Start, the entrypoint stops the
bootstrap proxy and its setup process completely before starting the production
mTLS listener. A pre-existing configuration is loaded directly: invalid or
legacy IP-only configuration terminates the container instead of reopening
bootstrap HTTP. The only production health endpoint is the container-local
`127.0.0.1:8082`; use `vaultlink health-check --live` or `--ready` through
Docker/Kubernetes exec. That listener has no application routes and ignores
forwarding headers. The CLI uses bounded local HTTP requests.

`VAULTLINK_BIN`, `VAULTLINK_CONFIG_PATH`, `VAULTLINK_SETUP_ADDR`, and
`VAULTLINK_CONTAINER_ADDR` customize the bootstrap process. The container proxy
only serves bootstrap and local development; it is absent from production.

The local runtime smoke generates short-lived test certificates, verifies
no-certificate and unpinned-certificate rejection, verifies the server name,
then exercises authenticated transfer and restart through the published port.
The [Docker Engine guide](DOCKER.md) covers volumes, host proxy, and recovery;
the [configuration guide](CONFIGURATION.md) covers Unix sockets and mTLS.
