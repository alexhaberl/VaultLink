# Dedicated 72-hour soak host

The soak system is a Debian 13 amd64 staging host, not a GitHub Actions runner.
The protected manual workflows run on ephemeral GitHub-hosted Ubuntu VMs and
connect through a dedicated, host-key-pinned SSH key. That key is restricted by
`authorized_keys` to `vaultlink-soak-remote`, which accepts only validated
`start` and `collect` requests. Do not place signing keys, GitHub tokens,
production credentials, or unrelated workloads on the host.

## Host provisioning

Deploy the exact 0.5.0 candidate through the normal verified upgrade procedure
before starting a soak. The running `/proc/MAINPID/exe` hash must match the
64-character hash supplied to the manual start workflow. Provision `curl`,
`sqlite3`, GNU coreutils, OpenSSH server, `sudo`, and systemd. Create a locked,
key-only bridge account and evidence group:

```sh
sudo addgroup --system vaultlink-soak
sudo adduser --system --ingroup vaultlink-soak \
  --home /var/lib/vaultlink-soak-bridge --shell /bin/sh vaultlink-soak-bridge
sudo install -d -o vaultlink-soak-bridge -g vaultlink-soak -m 0700 \
  /var/lib/vaultlink-soak-bridge/.ssh
```

Install the root-owned orchestration files from the same reviewed commit:

```sh
sudo install -d -o root -g root -m 0755 /usr/local/libexec/vaultlink
sudo install -m 0755 tools/soak-monitor.sh /usr/local/libexec/vaultlink/soak-monitor.sh
sudo install -m 0755 tools/load-test.sh /usr/local/libexec/vaultlink/load-test.sh
sudo install -m 0755 tools/collect-soak-evidence.sh /usr/local/libexec/vaultlink/collect-soak-evidence.sh
sudo install -m 0755 deploy/vaultlink-soak-control.sh /usr/local/sbin/vaultlink-soak-control
sudo install -m 0755 deploy/vaultlink-soak-remote.sh /usr/local/sbin/vaultlink-soak-remote
sudo install -m 0644 deploy/vaultlink-soak@.service /etc/systemd/system/vaultlink-soak@.service
sudo install -d -o root -g vaultlink-soak -m 2750 /var/lib/vaultlink-soak
sudo systemctl daemon-reload
```

Generate separate Ed25519 key pairs for start and collection outside the
repository. Install only their public keys on the host, with mode-specific
forced commands and OpenSSH restrictions:

```text
restrict,command="/usr/local/sbin/vaultlink-soak-remote start" ssh-ed25519 AAAA... vaultlink-soak-start
restrict,command="/usr/local/sbin/vaultlink-soak-remote collect" ssh-ed25519 AAAA... vaultlink-soak-collector
```

Save that line as
`/var/lib/vaultlink-soak-bridge/.ssh/authorized_keys`, owned by
`vaultlink-soak-bridge:vaultlink-soak` with mode `0600`. Disable password and
keyboard-interactive authentication for this account in `sshd_config`; the
account must not have any other SSH key. The collector key cannot invoke
`start`, and the approval-gated start key cannot invoke `collect`.

Grant only the validated root control entry through `/etc/sudoers.d/vaultlink-soak`:

```text
vaultlink-soak-bridge ALL=(root) NOPASSWD: /usr/local/sbin/vaultlink-soak-control start *
```

The root control independently requires exactly three lowercase hexadecimal
arguments and rejects any other invocation. Do not grant general `systemctl`,
file installation, shell, or editor access.

Create two GitHub Environments with five SSH secrets each:

- `release-soak` is used only by the manual start workflow. Require maintainer
  approval for this environment.
- `release-soak-collector` is used by the hourly collector. Do not configure a
  required reviewer because scheduled jobs cannot receive an approval every
  hour. Restrict deployments to the protected `main` branch instead.

Store in both environments, using the corresponding distinct private key:

- `SOAK_SSH_HOST`: exact DNS name or IP address
- `SOAK_SSH_PORT`: SSH port, normally `22`
- `SOAK_SSH_USER`: `vaultlink-soak-bridge`
- `SOAK_SSH_PRIVATE_KEY`: the dedicated private key
- `SOAK_SSH_HOST_KEYS`: an exact `known_hosts` entry copied through a trusted
  administrative channel, never obtained with `ssh-keyscan` inside the job

Rotate the bridge key if its private half is ever exposed and verify the host
key out of band before updating `SOAK_SSH_HOST_KEYS`. The collector environment
has no approval gate, but its dedicated credential is limited by its forced SSH
command to the read-only `collect` operation.

Create `/etc/vaultlink/soak.env` as root with mode `0600`. It supplies the
staging-only public share tokens and local paths without placing secrets in
Actions logs:

```text
VAULTLINK_BASE_URL=http://127.0.0.1:8080
VAULTLINK_HEALTH_URL=http://127.0.0.1:8080/api/v2/health/ready
VAULTLINK_DATABASE=/var/lib/vaultlink/data.sqlite
VAULTLINK_CONFIG=/etc/vaultlink/config.toml
DOWNLOAD_TOKEN=REPLACE_WITH_STAGING_DOWNLOAD_TOKEN
UPLOAD_TOKEN=REPLACE_WITH_STAGING_UPLOAD_TOKEN
UPLOAD_VERIFY_TOKEN=REPLACE_WITH_STAGING_READBACK_TOKEN
```

The soak listener must run in `reverse_proxy` mode with `enabled=true`,
`trust_x_forwarded_headers=true`, and the direct peer `127.0.0.1` explicitly in
`trusted_proxies`. The load script refuses a public base URL. Before applying
load it saturates one forwarded stream key and proves that a different
forwarded identity still receives an independent admission slot. The benchmark
then assigns separate RFC 2544 identities to all 100 metadata clients, 40 range
streams, and ten upload clients; an untrusted public `X-Forwarded-For` shortcut
is never used. Every profile requires metadata p95 to remain strictly below
2 seconds while all three pressure groups overlap.

`UPLOAD_VERIFY_TOKEN` must be a staging-only download share rooted at exactly
the same directory as `UPLOAD_TOKEN`, without a password or download limit.
Every uploaded namespaced file is downloaded through that share and hashed;
the profile fails unless the server-side bytes equal the local payload hash.
Provision the upload share with at least 16 GiB of remaining quota and capacity
for at least 200 additional files. The twelve required profiles retain 120
namespaced 64 MiB random-payload files (7.5 GiB before filesystem overhead);
the larger limits provide retry and operational reserve.

Re-provision every changed orchestration file before starting the final run.
The control compares all installed orchestration hashes with the approved
commit; changing them afterwards invalidates the evidence.

## Start, collection, and release binding

1. Run the complete native, Docker, fuzz, upgrade, and reproducibility gates.
2. Dispatch `Start 72-hour release soak` from `main` with the exact 40-character
   `origin/main` commit and SHA-256 of the already running amd64 binary. The
   supplied hash is only an explicit confirmation: the workflow downloads the
   successful Candidate-Preflight's `vaultlink-release-amd64` artifact, verifies
   its checksum manifest, derives the binary hash, and requires all three values
   (artifact, input, live executable) to match.
3. The hosted job opens the restricted SSH bridge. The root control verifies
   the live executable, creates a single locked state
   directory and a commit/start/random upload namespace, and starts
   `vaultlink-soak@COMMIT.service`. The GitHub job exits;
   the systemd monitor and repeated load profiles continue without an Actions
   token.
4. The scheduled GitHub-hosted collector runs at minute 17 of every hour and
   requests a tar stream from the forced
   bridge. The remote collector reads only group-readable evidence and uses unprivileged
   `systemctl is-active`/`is-failed` queries for the exact commit-bound monitor
   unit. While running it
   refreshes the `vaultlink/72h-soak` pending status. At completion it verifies
   and uploads `soak-evidence-COMMIT`, then records success or failure on that
   exact commit with a link to the collector run. The bridge account can read
   systemd unit state over the system bus but receives no general sudo or
   unit-control permission. The hosted job rejects archive traversal, links,
   malformed metadata, or files outside the fixed evidence envelope. Missing results from an inactive/failed unit, or
   from a unit more than 15 minutes past its persisted deadline, become partial
   failure evidence instead of remaining pending.
5. The tag workflow follows that link, downloads the artifact, revalidates at
   least 72 hours of metrics and load reports, and compares the complete
   evidence hash with its newly built amd64 binary. A status from another
   commit, an expired/missing artifact, or any hash mismatch blocks release.

The monitor rejects restarts, inactive health, non-0.5.0 health responses,
SQLite integrity failures, error-priority service journal entries, RSS over
256 MiB, more than 15 percent median RSS growth, failed load profiles, and a
changed executable hash. Each load profile samples RSS every second, retains
pre-/post-load state and the absolute peak, and uses its run-unique namespace so
restarted soaks cannot collide with old uploads. Each collector job supplies a
fresh GitHub token; neither the bridge nor the long-running service ever receives
one.

After the tag is published, archive the evidence outside the host and remove
the `active` state under an administrator-controlled maintenance procedure.
Never remove or replace active evidence while the systemd unit is running.
