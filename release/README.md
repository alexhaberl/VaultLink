# Release signing key

Before tagging, generate the project key once on an offline trusted system:

```sh
minisign -G -p minisign.pub -s vaultlink-release.key
```

Commit the public key as `release/minisign.pub`. Store the complete private key only in the GitHub Actions secret `MINISIGN_SECRET_KEY`; store its password in `MINISIGN_PASSWORD`. Never place the private key in the repository, VM, release artifact, or logs. The release workflow intentionally fails when the public key or either secret is absent.

The current private GitHub Free repository does not rely on an Actions Environment as an approval boundary. Only an authorized maintainer may push the annotated release tag after every checklist gate is complete. The workflow independently requires the tag version to match Cargo metadata, verifies that the tagged commit is contained in `origin/main`, rebuilds/tests that commit on both native architectures, and grants `contents: write` only to the tag-only publish job. Branch dry-runs remain read-only.

## Supply-chain pin maintenance

Release and test workflows pin external actions to full commit SHAs and container images to manifest digests. Keep the adjacent version comments when reviewing Dependabot updates, verify that each SHA belongs to the named upstream repository, and run `make policy-check` plus the release dry-run before merging a pin refresh. Cargo-installed release tools require exact `--version` values.

The current release container starts from an immutable Debian-13/Rust image, but APT packages are installed from Debian's signed live repositories. Do not describe builds as bit-for-bit reproducible until the repository is moved to a dated, maintained Debian snapshot.

## Multi-architecture assets

Release builds are native: amd64 runs on the dedicated self-hosted x64 runner,
while arm64 runs on GitHub's `ubuntu-24.04-arm` runner. Both jobs use the same
digest-pinned multi-platform Debian 13/Rust OCI index selected by
`rust-toolchain.toml` and verify the host
architecture before compiling.

Each architecture produces a versioned archive, standalone binary, CycloneDX
SBOM, and `SHA256SUMS-ARCH`. The tag workflow signs and verifies the archive,
binary, and checksum manifest separately. The signed checksum manifest covers
the SBOM as well. Never rename one architecture's files to make them appear to
belong to the other architecture.
