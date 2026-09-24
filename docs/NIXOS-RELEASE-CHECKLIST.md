# NixOS 26.05 first-release checklist

Apply this checklist to the next VaultLink release that claims NixOS support.
It does not amend the immutable 0.7.1 release or its eleven-gate history.

1. Freeze `flake.lock`, the Rust toolchain, package derivation, module,
   documentation and local/SMB VM tests before selecting the final commit.
   Pin one reviewed Nixpkgs 26.05 revision. Update the upgrade fixture's
   source pin to the actual immediately preceding supported VaultLink release
   before the candidate freeze. Check current NixOS support dates.
2. Build the package twice, without reusing its output, on native GitHub
   amd64 and arm64 runners. Compare binary and Nix output hashes. Boot the
   local-storage, SMB and old-version upgrade guests on both architectures and review evidence for
   mount identity, access control, readiness, transfer integrity, SQLite,
   restart and recovery behavior.
3. Require `vaultlink/nixos-amd64` and `vaultlink/nixos-arm64` from successful
   `.github/workflows/nixos.yml` runs for the exact candidate commit. Confirm
   workflow path, event, branch, conclusion, commit and artifact hashes. Missing
   KVM, runner storage or one guest result blocks the gate. The standard
   `ubuntu-24.04-arm` runner lacked KVM in the 2026-09-24 qualification run.
   Use `VAULTLINK_NIXOS_ARM_RUNNER` only for a reviewed GitHub-managed ARM64
   runner that demonstrably exposes KVM; do not attach a persistent private
   self-hosted runner to public pull requests.
4. Preserve the existing nine native packages and exactly 21 release assets.
   Run native, package, fuzz, reproducibility and distro VM gates in their
   existing dependency order. Include both NixOS gates in dry-run,
   candidate/evidence preflights and soak-start checks. Run the existing full
   72-hour Debian soak before publication.
5. Sign only the reviewed, frozen commit. Check the published tag's signature
   and immutability, then document how users pin the tag and their host lock.
   Record both NixOS gate URLs in the new release-state entry. Keep earlier
   release entries and receipts unchanged.
