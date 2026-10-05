# 0.7.2 pre-freeze review (2026-09-26 UTC)

This record covers build inputs, image pins, and source security review before
the final candidate is frozen. It does not claim exact-commit release gates,
full-load measurements, or a completed 72-hour soak. Any later change to a
build recipe, base image, frontend, package lock, or image pin requires the
refresh decision to be repeated before final qualification.
The 2026-09-26 hashes below describe the earlier build inputs; the dated
addendum records the refreshed 0.7.2 inputs before the final freeze.

## CI-001: build inputs and image pins

- The eleven image-refresh workflows succeeded from the same `main` source
  commit `f583cd53de769ee68b3ddcf07bcfaf272c696f05`: builder
  [35330817734](https://github.com/alexhaberl/VaultLink/actions/runs/35330817734),
  QEMU [35330823197](https://github.com/alexhaberl/VaultLink/actions/runs/35330823197),
  and guest runs `35331186896`, `35331191069`, `35331195025`, `35331198752`,
  `35331202571`, `35331206070`, `35331209608`, `35331213573`, and `35331217215`.
  Each run's workflow path, `workflow_dispatch` event, commit, and successful
  conclusion were checked against the GitHub run metadata.
- The builder candidate manifest and all nine VM guest records reconstruct
  `release/package-targets.json` byte for byte with
  `tools/update-package-target-images.py`. Its SHA-256 is
  `6c470da76fb92103b0847cd29951f2bde46da4efc8f25e7532ac94a91e9f4f76`.
  The artifact review checked provenance, architecture, virtual image size,
  complete package inventories, and the per-target builder/guest lock hashes.
- The four QEMU lock files exactly match the QEMU candidate artifact. Their
  SHA-256 values, in base-image / amd64-packages / arm64-packages / image order,
  are `0931255bcc8a35136d91f8f890d987ceda00d8c80798ac487f5510826c1d8b83`,
  `50d7066389d47182f51871360cedcafea3af36ebb32924d35014f5382c634206`,
  `f5b9e6477bc4171fdf2556b8adf517860a5285bcae12ddeca54113396f4f0893`,
  and `c5d17a00126d058958e3e590f1e467ce1d75af4b62968ae38a99e748fb4609d4`.
- Pins merged at `460818026c60bb7f5f7258cc0120b55ff73197e7`. A diff from the
  refresh source commit through this preparation found no later change to the
  builder, QEMU, or guest image recipes, their refresh workflows, pinned
  Dockerfile frontend, Rust, BuildKit, or base-image inputs. The separate
  Docker runtime recipe uses the existing pinned builder. The live
  `VAULTLINK_PACKAGE_SIGNING_IMAGE` variable matched the pinned Debian-amd64
  builder `ghcr.io/alexhaberl/vaultlink-package-builder-debian13@sha256:3e8d5deac3091310a98ce33edfc0aecfc7eada6a9a4f560dc9a45a3cd0bddb14`.

## SEC-001: lockfile audit and migration review

- On 2026-09-26, `cargo audit` 0.22.2 passed with `--deny warnings`, a newly
  fetched advisory database at `e2111519ba6d14a5da59a7b2e5c8083ae8a37c01`,
  and the existing documented `RUSTSEC-2023-0071` exception. The audited
  `Cargo.lock` SHA-256 is
  `0fef460bf1473661a5d1b22130039b9d1aca8ad28a37544521a9e760e5d1e049`.
  The JSON audit reported zero unignored vulnerabilities. The soak-start,
  collection, and pre-publication workflows require new audits of the exact
  committed candidate; this preparatory audit does not replace them.
- Reviewed schema 10 to 11 and 11 to 12 in `src/db/schema/migrations.rs`:
  each uses an immediate transaction, validates the old and new schema,
  records a migration fingerprint, and commits only after database validation.
  Failure-injection rollback and shape checks are in `src/db/schema.rs`, with
  historical fixture coverage in `src/db/tests/schema_migrations.rs`.
- The candidate threat-model review at `e71a9bb4fd58d5fbddbda06d115ed4865d59b81a`
  records CR-01 through CR-03 for upload uncertainty, deployment trust, and
  post-release OCI provenance. Its conditions remain binding. The current
  source documents `outcome_unknown` after an interrupted upload commit and
  manual inspection instead of an automatic resend.

The final exact-commit gates and soak evidence remain open in the checklist
and qualification ledger.

## 2026-10-01 UTC: dependency refresh and candidate reset

- PR #237 merged as `216d594551e14acc8637afad1b16d3c0f11ea2e6`. It updated
  the committed `Cargo.lock`, the Debian release-tool snapshot and package lock,
  and the shared `rust:1.98.1-trixie` digest in the package-builder and setup-smoke
  Dockerfiles. `rust-toolchain.toml` remains at 1.98.1; the proposed 1.99.0
  update in PR #236 is excluded from this candidate. The Dockerfile frontend,
  BuildKit pin, distro base references, QEMU runner recipe and four locks, and
  all nine guest-image recipes and pins did not change. A builder-only refresh
  was therefore required before final package qualification.
- The protected [builder refresh run 36923045886](https://github.com/alexhaberl/VaultLink/actions/runs/36923045886)
  completed successfully as `.github/workflows/package-builders-refresh.yml`,
  `workflow_dispatch`, attempt 1, on exact `main` commit `216d594551e14acc8637afad1b16d3c0f11ea2e6`.
  Its nine platform digest and complete package-inventory artifacts were checked
  against the generated candidate. The inventories are sorted, unique and
  versioned; their SHA-256 values match the per-target locks. Inventory counts
  are Debian 372/371, Ubuntu 24.04 368/367, Ubuntu 26.04 380/379, Fedora 44
  384/385, and Arch 243 (amd64/arm64 where applicable). The five published
  OCI indices contain the nine exact platform digests for Debian 13, Ubuntu
  24.04, Ubuntu 26.04, Fedora 44, and Arch Linux. The generated manifest Git
  blob has SHA-256 `c518b96a6bff1c905f75f883872705bb81d67d3db67b42178a458f54271a66a3`.
  It changes only nine builder-image references and eight builder-package
  inventory hashes; the Arch inventory is unchanged. All guest, base and QEMU
  evidence remains as previously reviewed. Strict target and lock policy
  validation pass.
- The generated manifest was pinned unchanged by PR #238 at
  `8354dcbe1abaf758ffb621dda6f43b8a49b991cf`. Its nine package builds and
  nine real-package smokes passed, along with both native CI, NixOS, and Docker
  architecture checks on the PR head. These PR checks are preliminary and do
  not replace final gates on the frozen `main` commit. PR #235 merged at
  `be96548b3ccef5cc7d20200034aef9f3a183451e` and changed only
  `docs/CONFIGURATION.md`; it did not change a build input. The live
  `VAULTLINK_PACKAGE_SIGNING_IMAGE` variable was read back after the pin merge
  and matches the committed Debian-amd64 builder
  `ghcr.io/alexhaberl/vaultlink-package-builder-debian13@sha256:9565e0d9db61d46bfdaf0d9b7f44e092f3fdac36e07177c2f18da25c1c39a5b8`.
- A fresh `cargo audit` 0.22.2 run with
  `--deny warnings --ignore RUSTSEC-2023-0071` passed on 2026-10-01 with 347
  crates and advisory database commit
  `6de4455103aced2cba86e3b86e5c090b22827cf1`. The committed `Cargo.lock`
  SHA-256 is `9ca9730642e5c89dcaeee7589faa52a9e1ab8043b63650ad85a10047b499d438`.
  The documented RSA exception remains conditional on the reviewed RS256
  rejection. Soak start, collection and publication each require their own
  fresh audit of the exact candidate.
- Source changes since the 2026-09-26 review bounded the full-load mTLS
  handshake budget to 192, below the 256-connection cap, and allowed a
  configurable 10-180-second handshake timeout only on loopback (10 seconds
  remains the default). The threat model records the increased unauthenticated
  CPU exposure and the isolated TCG exception. The soak load script now `exec`s
  its admission-holder Curl process so cleanup releases the actual connection;
  its regression test verifies termination. Upload-operation, directory-quota
  and schema-migration sources did not change. CR-01 through CR-03 retain their
  release conditions; neither the source review nor PR checks satisfy the
  exact-commit gates, staging-host verification or complete 72-hour soak.

The planned release date is 2026-10-05 UTC. The final candidate is not frozen
until this documentation change is merged, all build inputs and image pins are
confirmed unchanged, and the exact `main` commit is recorded. Any later commit
requires a new candidate and new gates.
