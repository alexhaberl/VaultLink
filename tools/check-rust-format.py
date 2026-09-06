#!/usr/bin/env python3
"""Format Cargo modules and every tracked Rust fragment with the repository pin."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import tomllib


def check(root: Path, fix: bool = False) -> None:
    toolchain = tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    edition = manifest["package"]["edition"]
    if isinstance(edition, dict):
        edition = manifest["workspace"]["package"]["edition"]
    cargo = ["cargo", f"+{toolchain}", "fmt", "--all"]
    if not fix:
        cargo += ["--", "--check"]
    cargo_result = subprocess.run(cargo, cwd=root, check=False)
    files = subprocess.check_output(
        ["git", "ls-files", "-z", "--", "*.rs"], cwd=root
    ).decode("utf-8").split("\0")
    files = [name for name in files if name]
    if not files:
        raise SystemExit("format check: no tracked Rust files")
    rustfmt = ["rustfmt", f"+{toolchain}", "--edition", edition, "--config", "skip_children=true"]
    if not fix:
        rustfmt += ["--check"]
    failed = cargo_result.returncode != 0
    # Keep command lengths bounded on Windows as well as Linux.
    for offset in range(0, len(files), 32):
        result = subprocess.run(rustfmt + files[offset:offset + 32], cwd=root, check=False)
        failed |= result.returncode != 0
    if failed:
        raise SystemExit(1)
    print(f"Rust formatting passed: Cargo modules and {len(files)} tracked files ({toolchain}, edition {edition})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--fix", action="store_true")
    args = parser.parse_args()
    check(args.root.resolve(), args.fix)
