# Release signing key

Before tagging, generate the project key once on an offline trusted system:

```sh
minisign -G -p minisign.pub -s vaultlink-release.key
```

Commit the public key as `release/minisign.pub`. Store the complete private key only in the GitHub Actions secret `MINISIGN_SECRET_KEY`; store its password in `MINISIGN_PASSWORD`. Never place the private key in the repository, VM, release artifact, or logs. The release workflow intentionally fails when the public key or either secret is absent.

## Supply-chain pin maintenance

Release and test workflows pin external actions to full commit SHAs and container images to manifest digests. Keep the adjacent version comments when reviewing Dependabot updates, verify that each SHA belongs to the named upstream repository, and run `make policy-check` plus the release dry-run before merging a pin refresh. Cargo-installed release tools require exact `--version` values.

The current release container starts from an immutable Debian-13/Rust image, but APT packages are installed from Debian's signed live repositories. Do not describe builds as bit-for-bit reproducible until the repository is moved to a dated, maintained Debian snapshot.
