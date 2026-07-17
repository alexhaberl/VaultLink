# GitHub Actions runner strategy

VaultLink uses dedicated repository-scoped native Linux runners for both
supported release architectures:

- Debian 13 amd64: `[self-hosted, Linux, X64, vaultlink]`
- Ubuntu 24.04 arm64: `[self-hosted, Linux, ARM64, vaultlink]`

The final release additionally uses an isolated Debian 13 amd64 staging runner
labelled `[self-hosted, Linux, X64, vaultlink-soak]`. It never accepts pull
requests and follows the provisioning and evidence procedure in
[`SOAK-RUNNER.md`](SOAK-RUNNER.md).

No workflow uses GitHub-hosted compute. Jobs that require a native amd64 result
run on the x64 runner, jobs that require a native arm64 result run on the arm64
runner, and architecture-independent jobs default to the lower-cost arm64
runner.

## Self-hosted runner baselines

- Debian 13 amd64: 8 vCPU, 8 GiB RAM, and 118 GB disk
- Ubuntu 24.04 arm64: 4 vCPU, 24 GiB RAM, and 193 GB disk
- Docker Engine and Buildx from the distribution-appropriate package source
- `build-essential`, `clang`, `curl`, `git`, `libssl-dev`, `make`, `pkg-config`,
  `python3`, `shellcheck`, `sqlite3`, and `util-linux`
- a dedicated `github-runner` service account in the `docker` group
- GitHub Actions runner installed in `/opt/actions-runner` as a systemd service

The Docker group is root-equivalent. The VM must therefore be dedicated to CI,
must not contain unrelated secrets or services, and must only run trusted
private-repository changes. Do not route pull requests from untrusted forks to
this runner.

## Workflow behavior

The CI workflow uses an amd64/arm64 include matrix. Formatting, shell validation,
supply-chain policy, Clippy, tests, fuzz-crate compilation, Docker smoke tests,
and release builds run natively on both architectures. The dependency audit and
coverage report remain single-run gates because they operate on the shared
lockfile and source tree. Each native job verifies `uname -m` and the Rust host
triple before compiling. Superseded pull-request runs are cancelled
automatically.

The weekly and manually dispatched fuzz campaign runs as a native amd64/arm64
matrix. Each architecture runs all nine targets for ten minutes each across four
workers (`FUZZ_JOBS=4`) and publishes its own exact-commit status. Each matrix
entry has a 120-minute timeout so a cold instrumented Nightly build and all three
target waves have sufficient headroom. Security auditing, release-environment
resolution, combined
artifact verification, signing, publishing, and release dry runs also use the
arm64 runner because they do not require an amd64 host. The amd64 runner is
reserved for the native amd64 CI and release-build matrix entries.

The Rust WebAuthn tests cover server-side challenge replacement, account and
session binding, expiry, single-use state, and invalid finish responses. They do
not emulate a hardware authenticator or browser ceremony with a private key;
end-to-end device interoperability therefore remains a release smoke test with
a real FIDO2 security key.

Release and reproducibility builds use the same prebuilt, digest-pinned Debian
13/Rust OCI index selected through the required repository variable
`VAULTLINK_RELEASE_BUILDER_IMAGE`. The image is built from the source-independent
`deploy/docker/Dockerfile.release-builder`, published as a linux/amd64 and
linux/arm64 manifest, and must contain the exact Debian package closure and
Cargo build/signing tools verified by `tools/verify-release-builder.sh`. Release
jobs perform no APT or Cargo tool installation. The complete manifest reference
must be committed in `deploy/docker/release-builder-image.lock` and copied
unchanged to the repository variable. The initial `UNPROVISIONED` marker, any
mismatch, a mutable tag, or image content that differs from the checked-in
snapshot and package lock fails before container startup. Private GHCR pulls use
explicit Actions token credentials and `packages: read`.
The build jobs have read-only repository permissions and upload separate,
short-lived unsigned inputs. The final self-hosted arm64 job downloads both
immutable workflow artifacts, verifies `SHA256SUMS-amd64` and
`SHA256SUMS-arm64`, and only then accesses the Minisign secret for a tag release.

Release asset names identify version, Debian baseline, and architecture, for
example:

- `VaultLink-0.5.0-debian13-amd64.tar.gz`
- `VaultLink-0.5.0-debian13-arm64.tar.gz`
- `vaultlink-0.5.0-debian13-ARCH`
- `vaultlink-0.5.0-debian13-ARCH.cdx.json`
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
