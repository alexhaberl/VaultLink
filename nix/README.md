# Nix build inputs and CI cache

`source.nix` selects the application source, embedded assets/templates and storage
configuration, installed production examples/license, and Cargo workspace inputs.
Documentation, release image pins and workflows do not change the package source.
The pinned previous package used by the upgrade test keeps its original source
override. Add any new compile-time or installed input to this selection.

The NixOS workflow restores an architecture-specific GitHub Actions Nix-store
cache. Only successful pushes to `main` save caches; pull requests only restore.
Keys prefer the current flake/toolchain lock and fall back within the same
architecture. Before saving, garbage collection targets a 4 GiB store per
architecture. A miss or eviction affects speed, not the qualification gates. The
first successful `main` run populates the cache; no external cache account is used.

Every run still builds the application twice. If the first output is already in
the restored store, that attempt also uses `--rebuild`; the second always does.
Both binary and complete output hashes must match as before.

`prepare-nix-vm-tests.sh` removes only the existing result leaves of the local,
SMB and upgrade tests before their normal builds. This forces all three tests to
execute again while retaining dependency closures. Nix's root/referrer protection
is preserved: an undeletable result fails the job rather than reusing old evidence.
Native architecture checks, KVM/TCG selection, guest assertions, evidence upload
and exact-commit gate publication remain in place.

Run these regression checks on a Linux host with Nix and Python 3:

```sh
python3 tools/test-nix-source.py
python3 tools/test-nix-qualification.py
```

The source check evaluates actual source and derivation identities on both
architectures, including unrelated edits and changes to required build inputs.
The helper checks cover cold/warm results and unsafe or undeletable store paths.
