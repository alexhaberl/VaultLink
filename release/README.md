# Release signing key

Before tagging, generate the project key once on an offline trusted system:

```sh
minisign -G -p minisign.pub -s vaultlink-release.key
```

Commit the public key as `release/minisign.pub`. Store the complete private key only in the GitHub Actions secret `MINISIGN_SECRET_KEY`; store its password in `MINISIGN_PASSWORD`. Never place the private key in the repository, VM, release artifact, or logs. The release workflow intentionally fails when the public key or either secret is absent.

The tag-only publish job uses the protected `release-signing` GitHub Environment.
Only an authorized maintainer may approve it and push the annotated release tag
after every checklist gate is complete. The workflow independently requires the
tag version to match Cargo metadata, verifies that the tagged commit equals the
current `origin/main`, rebuilds/tests that commit on both native architectures,
and grants `contents: write` only to the publish job. Branch dry-runs remain
read-only.

## Supply-chain pin maintenance

Release and test workflows pin external actions to full commit SHAs and container images to manifest digests. Keep the adjacent version comments when reviewing Dependabot updates, verify that each SHA belongs to the named upstream repository, and run `make policy-check` plus the release dry-run before merging a pin refresh. Release-time jobs install neither APT packages nor Cargo tools.

The required `VAULTLINK_RELEASE_BUILDER_IMAGE` is a multi-architecture,
digest-pinned image built only from `deploy/docker/Dockerfile.release-builder`
and the immutable Debian snapshot in `deploy/docker/debian-snapshot.sources`.
The builder Dockerfile deliberately copies no application source, workflow, or
`release-builder-image.lock`, so its digest can safely be pinned by the same
source commit. Its direct and transitive package
closure is exact-versioned in `debian-packages.lock`; the image build compares
the base-image dpkg manifest before and after installation and rejects every
changed package absent from that lock. Cargo audit/SBOM tools are baked into the
builder at pinned versions. Reproducibility jobs generate and normalize an
independent SBOM for each clean build, then require both the binary and complete
final release archive to have identical SHA-256 values. A tag build must match
those exact binary and archive hashes for its architecture.

`deploy/docker/release-builder-image.lock` is the reviewed source of truth. It
starts as `UNPROVISIONED` and remains blocked until a maintainer performs an
explicit dependency refresh. Build and push the builder as one linux/amd64+linux/arm64
manifest with Buildx, record the resulting full
`ghcr.io/alexhaberl/vaultlink-release-builder@sha256:<64-hex>` reference in the
lock, and set the repository variable `VAULTLINK_RELEASE_BUILDER_IMAGE` to that
exact same string. Release and reproducibility environment resolvers compare
the two before any job container starts and require `packages: read` plus GHCR
credentials. An unset marker, mismatch, mutable tag, different repository, or
unavailable private image is an intentional external release blocker.

The refresh is performed from reviewed `main` by manually dispatching
`Refresh release builder`. Its matrix builds natively on GitHub-hosted amd64
and arm64 runners, pushes platform images by digest, and publishes their joint
manifest under the temporary `dependency-refresh` tag. No release job uses
that tag.

```sh
gh workflow run release-builder.yml --ref main
```

Copy the manifest reference reported in the workflow summary, not either
platform-child digest, into the checked-in lock and the repository variable,
then rerun both native
reproducibility jobs. For a private package, explicitly grant this repository's
Actions token read access to the GHCR package. Updating the temporary tag later
cannot affect the pinned jobs.

## Multi-architecture assets

Release builds are native: amd64 runs on GitHub-hosted `ubuntu-24.04` and arm64
on `ubuntu-24.04-arm`. Architecture-independent verification and preflight jobs
run on arm64. The tag-only signing and publishing job uses a fresh
`ubuntu-24.04` VM, so the release key and write token are discarded with that
job. Both builds use the same digest-pinned multi-platform Debian 13/Rust OCI
index selected by `rust-toolchain.toml` and verify the host architecture before
compiling.

Each architecture produces a versioned archive, standalone binary, CycloneDX
SBOM, and `SHA256SUMS-ARCH`. The tag workflow signs and verifies the archive,
binary, and checksum manifest separately. The signed checksum manifest covers
the SBOM as well. Never rename one architecture's files to make them appear to
belong to the other architecture.
