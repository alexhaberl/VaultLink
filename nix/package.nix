{ lib, makeRustPlatform, rust-bin }:
let
  toolchain = rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;
  rustPlatform = makeRustPlatform { cargo = toolchain; rustc = toolchain; };
  manifest = builtins.fromTOML (builtins.readFile ../Cargo.toml);
in rustPlatform.buildRustPackage {
  pname = "vaultlink";
  version = manifest.package.version;
  src = lib.cleanSource ../.;
  cargoLock.lockFile = ../Cargo.lock;
  cargoBuildFlags = [ "--bin" "vaultlink" ];
  # Native CI runs the Rust suite on both architectures. The Nix derivation
  # builds the release payload; booted NixOS tests exercise that exact output.
  doCheck = false;
  postInstall = ''
    install -Dm0644 LICENSE "$out/share/licenses/vaultlink/LICENSE"
    for example in config/production-*.toml; do
      install -Dm0644 "$example" "$out/share/doc/vaultlink/examples/$example"
    done
  '';
  meta = {
    description = "Secure file sharing for an existing Linux mountpoint";
    homepage = "https://github.com/alexhaberl/VaultLink";
    license = lib.licenses.mit;
    mainProgram = "vaultlink";
    platforms = [ "x86_64-linux" "aarch64-linux" ];
  };
}
