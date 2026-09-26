# 0.7.2 pre-freeze review (2026-09-26 UTC)

This record covers build inputs, image pins, and source security review before
the final candidate is frozen. It does not claim exact-commit release gates,
full-load measurements, or a completed 72-hour soak. Any later change to a
build recipe, base image, frontend, package lock, or image pin requires the
refresh decision to be repeated before final qualification.

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
