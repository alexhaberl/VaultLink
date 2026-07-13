# GitHub Actions runner strategy

VaultLink uses dedicated repository-scoped native Linux runners for both
supported release architectures:

- Debian 13 amd64: `[self-hosted, Linux, X64, vaultlink]`
- Ubuntu 24.04 arm64: `[self-hosted, Linux, ARM64, vaultlink]`

No workflow uses GitHub-hosted compute. Jobs that require a native amd64 result
run on the x64 runner, jobs that require a native arm64 result run on the arm64
runner, and architecture-independent jobs default to the lower-cost arm64
runner.

## Self-hosted runner baselines

- Debian 13 amd64: 8 vCPU, 8 GiB RAM, and 118 GB disk
- Ubuntu 24.04 arm64: 4 vCPU, 24 GiB RAM, and 193 GB disk
- Docker Engine and Buildx from the distribution-appropriate package source
- `build-essential`, `clang`, `git`, `libssl-dev`, `make`, `pkg-config`,
  `python3`, `shellcheck`, `sqlite3`, and `util-linux`
- a dedicated `github-runner` service account in the `docker` group
- GitHub Actions runner installed in `/opt/actions-runner` as a systemd service

The Docker group is root-equivalent. The VM must therefore be dedicated to CI,
must not contain unrelated secrets or services, and must only run trusted
private-repository changes. Do not route pull requests from untrusted forks to
this runner.

## Workflow behavior

The CI workflow uses an amd64/arm64 include matrix. Clippy, tests, fuzz-crate
compilation, Docker smoke tests, and release builds run natively on both
architectures. Formatting, shell validation, supply-chain policy, and dependency
audits run only in the arm64 entry because their results are architecture
independent. Each job verifies `uname -m` and the Rust host triple before
compiling. Superseded pull-request runs are cancelled automatically.

The weekly and manually dispatched fuzz campaign runs on the self-hosted arm64
runner. It runs all eight targets for ten minutes each across four workers
(`FUZZ_JOBS=4`), matching the runner's four vCPUs. Security auditing,
release-environment resolution, combined
artifact verification, signing, publishing, and release dry runs also use the
arm64 runner because they do not require an amd64 host. The amd64 runner is
reserved for the native amd64 CI and release-build matrix entries.

Release builds use the same digest-pinned Debian 13/Rust OCI index selected by
`rust-toolchain.toml` on
both native runners. The pin contains both linux/amd64 and linux/arm64 images.
The build jobs have read-only repository permissions and upload separate,
short-lived unsigned inputs. The final self-hosted arm64 job downloads both
immutable workflow artifacts, verifies `SHA256SUMS-amd64` and
`SHA256SUMS-arm64`, and only then accesses the Minisign secret for a tag release.

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
