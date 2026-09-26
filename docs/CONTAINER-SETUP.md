# Container setup and production listener

The official container exposes port `8081`. With incomplete setup, the
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

The entrypoint runs the internal `container-start --config PATH --listen LOOPBACK`
mode. It checks the configuration, administrator database and pending setup
marker. Missing configuration, zero administrators or a valid
`.vaultlink-initial-setup.pending` marker reopen the token-protected setup.
A damaged, inaccessible or legacy IP-only configuration stops startup. A
confirmed installation with an administrator starts the normal service.

After a restart during setup, submit the same configuration again. If the
administrator was already stored, its password is required and the saved TOTP
secret is shown again. The configuration and secret are preserved. Confirm
that the secret has been saved before starting the service; this confirmation
is not an additional TOTP-code challenge. Calling `/complete` before successful
creation or recovery cannot remove the pending marker. The persisted state is
checked again before the service starts.

After the operator confirms setup and selects Start, `container-start` stops
and joins all bootstrap processes before starting the production mTLS listener.
The production health endpoint is the container-local `127.0.0.1:8082`; use
`vaultlink health-check --live` or `--ready` through Docker/Kubernetes exec.
That listener has no application routes and ignores forwarding headers. The
CLI uses bounded local HTTP requests.

The bootstrap proxy shares the main server's transport deadlines: 30 seconds
without write progress and a maximum connection lifetime of 24 hours.
Successful writes renew the idle allowance. Timeouts release both global and
peer connection slots.

`VAULTLINK_BIN`, `VAULTLINK_CONFIG_PATH`, `VAULTLINK_SETUP_ADDR`, and
`VAULTLINK_CONTAINER_ADDR` customize the bootstrap process. The container proxy
only serves bootstrap; it is absent after normal service startup.

The local runtime smoke generates short-lived test certificates, verifies
no-certificate and unpinned-certificate rejection, verifies the server name,
then exercises authenticated transfer and restart through the published port.
The [Docker Engine guide](DOCKER.md) covers volumes, host proxy, and recovery;
the [configuration guide](CONFIGURATION.md) covers Unix sockets and mTLS.
