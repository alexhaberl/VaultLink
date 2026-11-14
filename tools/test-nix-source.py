#!/usr/bin/env python3
"""Exercise the real Nix source and derivation identities with changed inputs."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
SYSTEMS = ("x86_64-linux", "aarch64-linux")


def evaluate(root: Path, system: str, attribute: str) -> str:
    return subprocess.check_output([
        "nix", "eval", "--raw", "--no-write-lock-file",
        f"path:{root}#packages.{system}.vaultlink.{attribute}",
    ], text=True).strip()


def identity(root: Path) -> tuple[str, ...]:
    return tuple(evaluate(root, system, attribute)
                 for system in SYSTEMS for attribute in ("src", "drvPath"))


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="vaultlink-nix-source-") as temporary:
        fixture = Path(temporary) / "checkout-one"
        fixture.mkdir()
        for name in ("src", "templates", "assets", "config", "nix", "fuzz/fuzz_targets"):
            shutil.copytree(ROOT / name, fixture / name)
        for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "LICENSE", "README.md",
                     "flake.nix", "flake.lock", "fuzz/Cargo.toml", "release/package-targets.json",
                     ".github/workflows/nixos.yml", "deploy/vaultlink-external-storage.conf"):
            target = fixture / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)

        baseline = identity(fixture)
        source = Path(baseline[0])
        for name in ("src/main.rs", "templates", "assets", "LICENSE", "fuzz/Cargo.toml",
                     "fuzz/fuzz_targets", "deploy/vaultlink-external-storage.conf"):
            assert (source / name).exists(), f"required source is missing: {name}"
        for name in ("README.md", "release", ".github", "nix", "deploy/docker", "config/development.toml"):
            assert not (source / name).exists(), f"unneeded source was included: {name}"

        for name in ("README.md", "release/package-targets.json", ".github/workflows/nixos.yml"):
            path = fixture / name
            original = path.read_bytes()
            path.write_bytes(original + b"\n# unrelated change\n")
            assert identity(fixture) == baseline, f"unrelated edit invalidated the package: {name}"
            path.write_bytes(original)

        second = Path(temporary) / "different-checkout-name"
        shutil.copytree(fixture, second)
        assert identity(second) == baseline, "checkout directory name invalidated the package"

        required = ("src/main.rs", "assets/web/setup.js", "assets/branding/favicon-32.png",
                    "templates/setup/form.html", "deploy/vaultlink-external-storage.conf",
                    "config/production-reverse-proxy.toml", "LICENSE", "Cargo.toml", "Cargo.lock",
                    "rust-toolchain.toml", "fuzz/Cargo.toml", "fuzz/fuzz_targets/path_normalization.rs")
        for name in required:
            path = fixture / name
            original = path.read_bytes()
            path.write_bytes(original + b"\n# changed build input\n")
            assert evaluate(fixture, SYSTEMS[0], "src") != baseline[0], f"edit was lost: {name}"
            path.write_bytes(original)
        for name, content in (("build.rs", "fn main() {}\n"),
                              (".cargo/config.toml", "[net]\noffline = true\n")):
            path = fixture / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            assert evaluate(fixture, SYSTEMS[0], "src") != baseline[0], f"implicit input was lost: {name}"
            path.unlink()

        assert identity(fixture) == baseline
        print(json.dumps({"systems": SYSTEMS, "unrelated_edits_preserve_derivations": 3,
                          "required_input_changes_detected": len(required) + 2,
                          "checkout_name_independent": True}))


if __name__ == "__main__":
    main()
