# GitHub Actions runner strategy

VaultLink runs every GitHub Actions job on an ephemeral, GitHub-hosted Ubuntu
24.04 runner:

- amd64: `ubuntu-24.04`
- arm64: `ubuntu-24.04-arm`

No workflow targets a persistent self-hosted runner. This keeps pull-request
code away from long-lived hosts when the repository is public. Every native job
checks `uname -m` and, where Rust is used, its compiler host triple before
building.

## Workflow behavior

CI, fuzzing, release, and reproducibility use native amd64/arm64 matrices.
Architecture-independent security, coverage, release-environment, combined
artifact, and status-publication work runs on arm64. Signing and publishing runs
on `ubuntu-24.04` with job-scoped `contents: write`; all other release jobs are
read-only.

Public standard runners provide four vCPUs and 16 GiB RAM. Private standard
runners provide two vCPUs and 8 GiB RAM. The fuzz campaign therefore runs all
nine targets for 600 seconds each with `FUZZ_JOBS=2` while the repository is
private and `FUZZ_JOBS=4` when it is public. `CARGO_BUILD_JOBS=2` bounds the
memory-intensive instrumented build on both runner sizes.

The real Debian 13 amd64 staging deployment and 72-hour soak are not GitHub
runners. The manual start and collector workflows use an environment-protected,
host-key-pinned SSH connection to a forced-command bridge described in
[`SOAK-RUNNER.md`](SOAK-RUNNER.md). The host never executes arbitrary workflow
shell commands and stores no Actions token.

## Reproducible Debian 13 builds

Release and reproducibility jobs use the same prebuilt, digest-pinned Debian
13/Rust OCI index selected through the required repository variable
`VAULTLINK_RELEASE_BUILDER_IMAGE`. The image is built from the source-independent
`deploy/docker/Dockerfile.release-builder`, published as a linux/amd64 and
linux/arm64 manifest, and contains the exact Debian package closure and Cargo
build/signing tools verified by `tools/verify-release-builder.sh`.

Release jobs perform no APT or Cargo tool installation. The full manifest
reference must be committed in `deploy/docker/release-builder-image.lock` and
copied unchanged to the repository variable. `UNPROVISIONED`, a mutable tag, a
variable mismatch, an unavailable image, or content that differs from the
checked-in snapshot and package lock fails before release building begins.

The build jobs upload separate short-lived unsigned inputs. The publish job
downloads both artifacts, verifies `SHA256SUMS-amd64` and
`SHA256SUMS-arm64`, and only then receives the Minisign key for a tag release.
Its container image is resolved directly from the GitHub-managed variable, not
from another job's output.

Release asset names identify version, Debian baseline, and architecture:

- `VaultLink-0.5.0-debian13-amd64.tar.gz`
- `VaultLink-0.5.0-debian13-arm64.tar.gz`
- `vaultlink-0.5.0-debian13-ARCH`
- `vaultlink-0.5.0-debian13-ARCH.cdx.json`
- `SHA256SUMS-ARCH`

Archives, standalone binaries, and checksum manifests receive separate
architecture-specific `.minisig` files. The signed checksum manifest also
covers the architecture-specific SBOM.
