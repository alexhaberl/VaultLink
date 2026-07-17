# Dedicated 72-hour soak runner

The `vaultlink-soak` runner is a Debian 13 amd64 staging host, not a general CI
worker. Register it at repository scope with the labels
`self-hosted,Linux,X64,vaultlink-soak`, disable default-label job routing where
possible, and allow only workflows from the protected `main` branch. Do not
place signing keys, production credentials, or unrelated workloads on it.

## Host provisioning

Deploy the exact 0.5.0 candidate through the normal verified upgrade procedure
before starting a soak. The running `/proc/MAINPID/exe` hash must match the
64-character hash supplied to the manual start workflow. Provision `curl`,
`gh`, `sqlite3`, GNU coreutils, systemd, and a repository runner account/group
named `github-runner`.

Install the root-owned orchestration files from the same reviewed commit:

```sh
sudo install -d -o root -g root -m 0755 /usr/local/libexec/vaultlink
sudo install -m 0755 tools/soak-monitor.sh /usr/local/libexec/vaultlink/soak-monitor.sh
sudo install -m 0755 tools/load-test.sh /usr/local/libexec/vaultlink/load-test.sh
sudo install -m 0755 deploy/vaultlink-soak-control.sh /usr/local/sbin/vaultlink-soak-control
sudo install -m 0644 deploy/vaultlink-soak@.service /etc/systemd/system/vaultlink-soak@.service
sudo install -d -o root -g github-runner -m 2750 /var/lib/vaultlink-soak
sudo systemctl daemon-reload
```

Create `/etc/vaultlink/soak.env` as root with mode `0600`. It supplies the
staging-only public share tokens and local paths without placing secrets in
Actions logs:

```text
VAULTLINK_BASE_URL=http://127.0.0.1:8080
VAULTLINK_HEALTH_URL=http://127.0.0.1:8080/api/v2/health
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
is never used.

`UPLOAD_VERIFY_TOKEN` must be a staging-only download share rooted at exactly
the same directory as `UPLOAD_TOKEN`, without a password or download limit.
Every uploaded namespaced file is downloaded through that share and hashed;
the profile fails unless the server-side bytes equal the local payload hash.
Provision the upload share with at least 16 GiB of remaining quota and capacity
for at least 200 additional files. The twelve required profiles retain 120
namespaced 64 MiB random-payload files (7.5 GiB before filesystem overhead);
the larger limits provide retry and operational reserve.

Grant the runner passwordless sudo only for the fixed root-owned command
`/usr/local/sbin/vaultlink-soak-control start` with its three validated hexadecimal
arguments. Do not grant general `systemctl`, file-installation, shell, or editor
access. Re-provision changed orchestration files before starting the final run;
changing them afterwards changes the candidate commit and invalidates evidence.

## Start, collection, and release binding

1. Run the complete native, Docker, fuzz, upgrade, and reproducibility gates.
2. Dispatch `Start 72-hour release soak` from `main` with the exact 40-character
   `origin/main` commit and SHA-256 of the already running amd64 binary. The
   supplied hash is only an explicit confirmation: the workflow downloads the
   successful Candidate-Preflight's `vaultlink-release-amd64` artifact, verifies
   its checksum manifest, derives the binary hash, and requires all three values
   (artifact, input, live executable) to match.
3. The root control verifies the live executable, creates a single locked state
   directory and a commit/start/random upload namespace, and starts
   `vaultlink-soak@COMMIT.service`. The GitHub job exits;
   the systemd monitor and repeated load profiles continue without an Actions
   token.
4. The hourly collector reads only group-readable evidence and uses unprivileged
   `systemctl is-active`/`is-failed` queries for the exact commit-bound monitor
   unit. While running it
   refreshes the `vaultlink/72h-soak` pending status. At completion it verifies
   and uploads `soak-evidence-COMMIT`, then records success or failure on that
   exact commit with a link to the collector run. Ensure the runner service can
   read systemd unit state over the system bus; it receives no general sudo or
   unit-control permission. Missing results from an inactive/failed unit, or
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
restarted soaks cannot collide with old uploads. A fresh last-hour collector job supplies a fresh
GitHub token; the long-running service never depends on token lifetime.

After the tag is published, archive the evidence outside the runner and remove
the `active` state under an administrator-controlled maintenance procedure.
Never remove or replace active evidence while the systemd unit is running.
