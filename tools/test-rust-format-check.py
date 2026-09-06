#!/usr/bin/env python3
"""Regression for Cargo fmt's include! blind spot, using a tracked fixture."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="vaultlink-format-fixture-") as temporary:
    fixture = Path(temporary)
    (fixture / "src").mkdir()
    (fixture / "Cargo.toml").write_text('[package]\nname="format-fixture"\nversion="0.0.0"\nedition="2021"\n')
    shutil.copyfile(root / "rust-toolchain.toml", fixture / "rust-toolchain.toml")
    (fixture / "src/lib.rs").write_text('include!("fragment.rs");\n')
    (fixture / "src/fragment.rs").write_text('pub fn included( )->usize{1}\n')
    subprocess.run(["git", "init", "--quiet"], cwd=fixture, check=True)
    subprocess.run(["git", "add", "."], cwd=fixture, check=True)
    subprocess.run(["cargo", "fmt", "--all", "--", "--check"], cwd=fixture, check=True)
    command = [sys.executable, str(root / "tools/check-rust-format.py"), "--root", str(fixture)]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode != 0 and "fragment.rs" in result.stdout, result
    subprocess.run(command + ["--fix"], check=True)
    subprocess.run(command, check=True)
print("Included unformatted fixture is rejected and its formatted version passes")
