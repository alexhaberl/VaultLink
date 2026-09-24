{
  description = "VaultLink for NixOS 26.05";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    previous = {
      url = "github:alexhaberl/VaultLink/0af4612bd3c32a995b19de4cd19ca05ac4fd4855";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, rust-overlay, previous }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forSystems = f: nixpkgs.lib.genAttrs systems
        (system: f system (import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        }));
    in {
      packages = forSystems (system: pkgs:
        let vaultlink = pkgs.callPackage ./nix/package.nix { };
        in { inherit vaultlink; default = vaultlink; });

      nixosModules.default = import ./nix/module.nix { inherit self; };

      checks = forSystems (system: pkgs:
        let
          vaultlink = self.packages.${system}.vaultlink;
          oldPackage = pkgs.callPackage ./nix/package.nix {
            source = previous;
            packageVersion = "0.7.0";
            cargoLockFile = "${previous}/Cargo.lock";
          };
          mkTest = name: import (./nix/tests + "/${name}.nix") {
            inherit pkgs self system;
          };
        in {
          package = vaultlink;
          inherit oldPackage;
          local = mkTest "local";
          smb = mkTest "smb";
          upgrade = import ./nix/tests/upgrade.nix {
            inherit pkgs self system oldPackage;
          };
        });
    };
}
