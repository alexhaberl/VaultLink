# GitHub Actions runner strategy

VaultLink uses native Linux runners for both supported release architectures.
The existing repository-scoped runner remains the only amd64/x86-64 runner:

- Debian 13 amd64: `[self-hosted, Linux, X64, vaultlink]`
- Ubuntu 24.04 arm64: `ubuntu-24.04-arm` (GitHub-hosted)

The arm64 runner is intentionally GitHub-hosted until a dedicated arm64 host is
available. No x64 CI or release build is moved to a GitHub-hosted runner.

## Self-hosted amd64 baseline

- Debian 13, 8 vCPU, 8 GiB RAM, and at least 100 GiB SSD storage
- Docker Engine from Docker's official Debian repository
- `build-essential`, `clang`, `git`, `libssl-dev`, `make`, `pkg-config`,
  `python3`, `shellcheck`, `sqlite3`, and `util-linux`
- a dedicated `github-runner` service account in the `docker` group
- GitHub Actions runner installed in `/opt/actions-runner` as a systemd service

The Docker group is root-equivalent. The VM must therefore be dedicated to CI,
must not contain unrelated secrets or services, and must only run trusted
private-repository changes. Do not route pull requests from untrusted forks to
this runner.

## Workflow behavior

The CI workflow uses an amd64/arm64 include matrix. Formatting, Clippy, tests,
fuzz-crate compilation, dependency audits, Docker smoke tests, and release
builds run natively on both architectures. Each job verifies `uname -m` and the
Rust host triple before compiling. Superseded pull-request runs are cancelled
automatically.

The weekly and manually dispatched fuzz campaign remains on the dedicated
self-hosted amd64 runner. It runs all eight ten-minute fuzz targets concurrently
(`FUZZ_JOBS=8`). A single registered runner service serializes amd64 CI, fuzz,
and release work so that CPU-intensive workloads cannot compete on that host.

Release builds use the same digest-pinned Debian 13/Rust OCI index selected by
`rust-toolchain.toml` on
both native runners. The pin contains both linux/amd64 and linux/arm64 images.
The build jobs have read-only repository permissions and upload separate,
short-lived unsigned inputs. The final self-hosted job downloads both immutable
workflow artifacts, verifies `SHA256SUMS-amd64` and `SHA256SUMS-arm64`, and only
then accesses the Minisign secret for a tag release.

Release asset names identify version, Debian baseline, and architecture, for
example:

- `VaultLink-0.4.1-debian13-amd64.tar.gz`
- `VaultLink-0.4.1-debian13-arm64.tar.gz`
- `vaultlink-0.4.1-debian13-ARCH`
- `vaultlink-0.4.1-debian13-ARCH.cdx.json`
- `SHA256SUMS-ARCH`

Archives, standalone binaries, and checksum manifests receive separate
architecture-specific `.minisig` files. The signed checksum manifest also
covers the architecture-specific SBOM.

## Operations

Check the self-hosted service and recent logs:

```sh
systemctl list-unit-files 'actions.runner.*.service'
sudo systemctl status 'actions.runner.*.service'
sudo journalctl --unit='actions.runner.*.service' -n 100
```

Check disk usage periodically because Rust and Docker caches are persistent:

```sh
df -h /
docker system df
```

The runner application updates itself automatically. Operating-system and
Docker security updates remain the administrator's responsibility. Rebuild the
VM instead of restoring cached work directories from backup; register a new
repository runner after rebuilding.
