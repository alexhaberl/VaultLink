{ lib, root }:
lib.fileset.toSource {
  inherit root;
  fileset = lib.fileset.unions [
    (root + /Cargo.toml)
    (root + /Cargo.lock)
    (root + /rust-toolchain.toml)
    (root + /LICENSE)
    (root + /src)
    (root + /templates)
    (root + /assets)
    (root + /deploy/vaultlink-external-storage.conf)
    # Cargo resolves the workspace even when building only the application bin.
    (root + /fuzz/Cargo.toml)
    (root + /fuzz/fuzz_targets)
    (lib.fileset.fileFilter
      (file: lib.hasPrefix "production-" file.name && lib.hasSuffix ".toml" file.name)
      (root + /config))
    (lib.fileset.maybeMissing (root + /build.rs))
    (lib.fileset.maybeMissing (root + /.cargo/config))
    (lib.fileset.maybeMissing (root + /.cargo/config.toml))
  ];
}
