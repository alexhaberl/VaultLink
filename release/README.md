# Release signing and immutable package inputs

VaultLink 0.7.0 publishes only the nine native packages declared in
`package-targets.json`. The release workflow must not publish project tar
archives or standalone binaries. GitHub's automatic source archives are
unsupported source material.

## Signing key

Generate the project key once on an offline trusted system:

```sh
minisign -G -p minisign.pub -s vaultlink-release.key
```

Commit only the public key as `release/minisign.pub`. Keep the private key
offline and inject its complete encrypted value only through
`MINISIGN_SECRET_KEY`; store its password in `MINISIGN_PASSWORD`. Never place
the private key in the repository, a builder, guest, staging VM, package,
artifact, or log. Missing or mismatched key material fails closed.

The same protected Environment contains `RELEASE_ADMIN_READ_TOKEN`, a
fine-grained token restricted to this repository with read-only
**Administration** permission. It cannot publish or alter contents; it exists
only because the normal Actions token cannot read the repository-level
Immutable Releases setting. The signing job checks that setting before draft
creation and again immediately before publication. A missing token, inadequate
scope, or disabled policy leaves the verified release as a non-public draft.

The tag-only job uses the protected `release-signing` Environment. The
owner-only `v*` tag ruleset permits only the repository owner to create,
update, or delete release tags. The personal repository intentionally has no
required reviewer because disabling self-review with no second authorized
reviewer would deadlock publication. The workflow independently requires:

- a public repository;
- a signed annotated tag whose strict version matches Cargo and all packages;
- the tag commit to equal current `origin/main`;
- all commit-bound CI, Fuzz, package, reproducibility, VM, load, and soak
  evidence; and
- signing secrets, the read-only release-policy token, and job-scoped
  `contents: write` only in the final protected job.

A tag pushed while any requirement is absent cannot publish. Branch and pull-
request runs remain secret-free and read-only.

## Target and image lock

`release/package-targets.json` is the only target matrix and names all nine
supported packages, native GitHub runner architecture, package architecture,
package format and asset name, immutable builder, and immutable QEMU guest.
For Arch it also binds the `rolling` host identity to one dated source
snapshot selected for the candidate.

The QEMU harness has a separate four-file commit-bound lock under
`deploy/docker`: its multiarch image digest, exact Ubuntu 24.04 base digest,
and the complete installed Debian package inventory for amd64 and arm64.
Every VM refresh and full-system gate compares the running harness marker,
embedded inventory, and live package database with those reviewed files.

Every image reference ends in an OCI `sha256` digest. `UNPROVISIONED`, a
mutable tag, a repository mismatch, an unavailable platform, or an unselected
Arch snapshot stops package and release work before compilation.

The package-builder, QEMU-runner, and guest-image Dockerfiles also use one
reviewed `docker.io/docker/dockerfile` patch release pinned to its multiarch
index digest. The supply-chain policy requires that exact first-line directive
in all three recipes, rejects any additional frontend directive, and forbids
`BUILDKIT_SYNTAX` overrides in every workflow. Each protected refresh workflow
is also bound to exactly its reviewed recipe and build-argument allowlist, so a
different `--file`, an extra argument, Bake, or direct `buildctl` cannot bypass
the pinned frontend.

The currently reviewed frontend identity is:

```text
docker.io/docker/dockerfile:1.7.1@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
```

That digest is the top-level multi-architecture index, not an amd64 or arm64
child manifest. Verify a proposed replacement with the normal
`docker buildx imagetools inspect docker.io/docker/dockerfile:<patch>` output
and record its displayed top-level `Digest`. Then use `docker buildx
imagetools inspect docker.io/docker/dockerfile:<patch> --raw | jq
'.manifests[].platform'` to confirm both `linux/amd64` and `linux/arm64`.
Cross-check the index digest against the verified
[`docker/dockerfile` publisher and exact tag in Docker Hub](https://hub.docker.com/r/docker/dockerfile/tags?name=1.7.1).
Update the patch version, digest, all three first-line directives, and the
policy constant in one change.

Builder and guest images are source-independent: their Dockerfiles and locked
package inputs do not copy application source, workflows, the target manifest,
or generated release artifacts. They contain a fixed Rust toolchain and the
complete target-specific package/build/test tool closure. Release jobs do not
install mutable distro or Cargo tools.

## Refresh procedure

A full builder-and-VM image refresh is a protected two-pull-request operation:

Before changing the Dockerfile frontend, select an exact stable patch tag and
use normal `docker buildx imagetools inspect` output to verify the displayed
top-level index digest. Inspect the raw manifest list separately to confirm the
`linux/amd64` and `linux/arm64` entries, and cross-check that index on Docker
Hub before updating the three Dockerfile directives and the policy's reviewed
frontend reference atomically. Never substitute a platform-specific child
manifest digest. A real frontend digest change requires fresh builder,
QEMU-runner, and all nine guest-image candidates and invalidates any active
release freeze or soak just like another build dependency change.

1. merge reviewed recipe/manifest changes with image fields still
   `UNPROVISIONED`;
2. manually dispatch the builder and QEMU image refresh workflows from that
   reviewed `main` commit;
3. pass the exact successful QEMU refresh run ID to each of the nine VM-image
   refreshes. The VM workflow accepts that bootstrap input only when GitHub
   reports a successful manual QEMU refresh on `main` at the same commit, and
   it downloads and verifies that run's immutable four-lock artifact. Its
   aggregate lock hash is carried across jobs to reject artifact replacement
   between validation and native provisioning. With input `0`, the workflow
   instead requires the already committed four-file lock;
4. verify native platform, OS identity, Rust version, package closure, guest
   boot, and the reported GHCR child/manifest digests;
5. download the QEMU-runner lock artifact, the builder lock artifact, plus all
   nine `vm-image.tsv` artifacts; review every complete package-closure
   attachment, and combine the nine VM records in manifest order; and
6. derive the final manifest from the builder candidate (never from an
   independently edited JSON file), require that all nine VM records and every
   lock field are complete, then pin that exact output in a separate reviewed
   pull request:

   ```sh
   cat vm-locks/debian13-amd64/vm-image.tsv \
       vm-locks/debian13-arm64/vm-image.tsv \
       vm-locks/ubuntu2404-amd64/vm-image.tsv \
       vm-locks/ubuntu2404-arm64/vm-image.tsv \
       vm-locks/ubuntu2604-amd64/vm-image.tsv \
       vm-locks/ubuntu2604-arm64/vm-image.tsv \
       vm-locks/fedora44-amd64/vm-image.tsv \
       vm-locks/fedora44-arm64/vm-image.tsv \
       vm-locks/archlinux-amd64/vm-image.tsv >all-vm-images.tsv
   for lock in \
       qemu-runner-image.lock \
       qemu-runner-base-image.lock \
       qemu-runner-packages-amd64.lock \
       qemu-runner-packages-arm64.lock; do
       install -m 0644 "qemu-lock/$lock" "deploy/docker/$lock"
   done
   python3 tools/update-package-target-images.py vm all-vm-images.tsv \
       package-targets.final.json \
       --input builder-lock/package-targets.json --require-complete
   install -m 0644 package-targets.final.json release/package-targets.json
   python3 tools/package-targets.py validate
   ```

   The strict final validator accepts neither `UNPROVISIONED` nor a malformed
   QEMU-runner image/base/package locks and enforces one shared multiarch
   builder/base digest for each two-architecture distribution. Partial QEMU
   provisioning is invalid even in bootstrap mode. Stage all four QEMU locks
   and the target manifest together in the same pinning pull request. This
   same-commit run-ID path permits the initial nine guest images to be built
   before that atomic pinning pull request; it never permits an unprovisioned
   harness to run.

Builder and VM image references are independent all-nine atomic lock families:
within either family, all targets use reviewed digests or all targets use
`UNPROVISIONED`. A refresh that changes only the shared Rust stage or native
package-builder recipe invalidates all builder-image references but preserves
the reviewed VM and QEMU locks. After that recipe pull request lands:

1. dispatch `package-builders-refresh.yml` from that exact `main` commit with
   the reviewed distro base digests and the committed Arch snapshot date;
2. review all nine emitted package-closure locks and the generated
   `package-targets.json` artifact;
3. verify that the candidate changes only builder image/base/package evidence,
   then pin that generated file unchanged in a second reviewed pull request;
4. run strict target validation, policy, the full package matrix, package
   reproducibility, and distro-VM gates; and
5. update `VAULTLINK_PACKAGE_SIGNING_IMAGE` to the newly pinned Debian 13 amd64
   builder reference.

The old builder digests must never be copied across a Rust-toolchain change,
and builder generation remains restricted to the protected `main` workflow.

Refresh workflows push immutable images and emit proposed pins but never modify
`main`. After pinning, run `make policy-check`, the full package matrix,
package reproducibility, and distro-VM gates.

The secret-free `release-image-refresh` Environment is restricted to `main`.
After the reviewed builder manifest is pinned, set the repository variable
`VAULTLINK_PACKAGE_SIGNING_IMAGE` to the exact Debian 13 amd64
`builder_image` reference; the signing job rejects any mismatch. The refresh
Environment never receives the Minisign key.

## Reproducibility and evidence

Each target compiles inside its own distribution on a native matching CPU
runner. Two empty build roots use the same commit-derived
`SOURCE_DATE_EPOCH`; payload binary, normalized target SBOM, and final package
must be byte-identical. Format-specific lint and the common package allowlist
run independently of the builder. The exact installed package payload also
runs the unchanged overlapping workload of 100 metadata clients, 40 range
streams, and ten upload/readback clients inside that digest-pinned distribution
builder on the matching native GitHub runner. The job first qualifies its
public hosted runner for four available vCPUs and at least 8 GiB of host RAM,
then restricts Docker to logical CPUs 0-3. It restricts the server to CPUs 0-1
and the load generator to CPUs 2-3, keeps server storage separate, and provides
the clients a dedicated hardened 4-GiB tmpfs. Its evidence records the
qualification, placement, exact workload, latency, RSS, and integrity results;
inability to prove the layout fails the gate. That qualified run is
authoritative for strict p95 `<2 s` for all nine targets, including arm64 on
the managed arm64 runner; private ARM hardware is not required. The resource
contract is reproducible, but it does not make arbitrary standard-runner
timing deterministic.

The full-system gate boots the pinned target guest with QEMU on the same
architecture. The guest receives its package over an isolated host channel,
has no unrestricted Internet access, and records kernel/OS identity, package
version, hashes, systemd state, journal, readiness, load result, and SQLite
integrity. Fedora evidence is invalid unless SELinux remains `Enforcing` with
no VaultLink-related AVC denial. Every guest runs the same complete load
workload without lowering concurrency or transfer sizes. The QEMU result is
authoritative for full-system functionality, security, integrity, RSS,
package-manager operations, upgrade, backup, migration, rollback, and SELinux;
its numeric p95 and `<2 s` comparison are diagnostic. The commit-bound
nine-target workflow forces and records TCG for every target without a second
matrix. Guest-image refreshes may use KVM on amd64 only after a bounded QMP
probe reports it present and enabled; otherwise they select TCG.

The dedicated Debian 13 amd64 72-hour soak remains a strict p95 `<2 s` gate
against the binary extracted from the exact final DEB.

The aggregate checks `vaultlink/packages`,
`vaultlink/package-reproducibility`, and `vaultlink/distro-vms` account for
all nine manifest targets. Candidate, soak-start, and tag workflows reject a
missing, skipped, stale, or wrong-commit aggregate.

## Asset assembly and publication

The protected signing job accepts exactly:

- nine manifest-named packages;
- nine direct package `.minisig` signatures;
- one deterministic all-target SBOM bundle containing every target SBOM and
  payload hash;
- one global `SHA256SUMS`; and
- `SHA256SUMS.minisig`.

It creates a draft with exactly those 21 project assets, downloads them again
from GitHub into a clean workspace, and verifies count, exact names, hashes,
both signature layers, package metadata/inventory, target identity, embedded
public key, SBOM contents, and payload versions. Only the already verified
draft is then made public; no asset is rebuilt or replaced during publication.

Published native packages from 0.6.0 onward are authenticated rollback inputs.
Repository-level GitHub release immutability is enabled, and the tag workflow
requires the newly published release to report `immutable=true`. Never delete
an entire package release: if an installed version's old package cannot be
downloaded and verified, the updater intentionally refuses the update.
