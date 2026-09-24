# First Docker runtime release checklist

Apply this to the first release that claims Linux Docker Engine support. The
published 0.7.1 release and its 21 assets remain unchanged.

1. Finalize `Dockerfile.runtime`, the pinned Debian builder and runtime image
   digests, pinned Dockerfile frontend and BuildKit, Rust toolchain,
   `Cargo.lock`, Compose file, browser update behavior, setup and recovery
   documentation **before** freezing the candidate. Any builder, frontend or
   toolchain change must follow the image-refresh order in
   [release/README.md](../release/README.md#refresh-procedure).
2. On native `ubuntu-24.04` and `ubuntu-24.04-arm` runners, build the runtime
   image twice, compare binary hashes, and run the production container smoke
   with real audited local storage. Review setup, unprivileged UID, missing
   mount and unsafe-rights rejection, second-instance lockout, upload/download
   hashes, restart, stopped-state backup/recovery, readiness and SQLite integrity. Require the
   commit-bound `vaultlink/docker-amd64` and `vaultlink/docker-arm64` status
   contexts and inspect their workflow run, conclusion, branch, path, commit
   and artifacts. A failed or absent runner blocks the release.
3. Require both Docker gates in release dry-run, candidate and evidence
   preflights, soak-start, tag checks, supply-chain policy and release-state
   validation. Run the existing native package, fuzz, reproducibility,
   distro-VM, NixOS and 72-hour soak gates on the exact frozen commit.
4. Sign and publish the native immutable release with its existing 21 assets.
   The `docker-publish.yml` workflow must then verify the successful tag
   workflow, the GitHub-verified annotated tag, the immutable published
   release and exact `main` commit. Keep `main` frozen until the subsequent
   GHCR build and public-pull checks finish. It builds each image child
   natively with pinned BuildKit and Syft SBOM scanner, pushes by digest,
   assembles the
   `vX.Y.Z` multiarch index and
   records the index and child digests as a workflow artifact.
5. Confirm `linux/amd64` and `linux/arm64` on the **top-level** GHCR index.
   The `verify_public` jobs on native amd64 and arm64 runners must pull the
   digest without Registry credentials and verify version and source revision
   labels. The first GHCR package may need its visibility set to public by the
   repository owner; rerun the failed public verification after that change.
   Keep ingress closed until both platform checks pass.
   Record the index digest and publish workflow URL in the new release notes.
6. From the released digest, repeat installation, setup, transfer/readback,
   restart, backup and recovery checks on Linux amd64 and arm64 with local
   storage and an audited SMB mount before marking Docker officially
   supported. Restore image and matching config, SQLite and keyring together;
   a bare image rollback after schema migration is invalid.
