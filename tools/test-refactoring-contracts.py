#!/usr/bin/env python3
"""Negative tests for the refactoring contract checker."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


CHECKER = Path(__file__).with_name("check-refactoring-contracts.py")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class RefactoringContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "release").mkdir()
        (self.root / "src" / "domain").mkdir(parents=True)
        (self.root / "src" / "contract.rs").write_text("contract\n", encoding="utf-8")
        (self.root / "src" / "domain" / "one.rs").write_text("one\n", encoding="utf-8")
        (self.root / "src" / "domain" / "two.rs").write_text("two\n", encoding="utf-8")
        self.manifest = {
            "schema_version": 1,
            "release_version": "0.7.0",
            "required_paths": {
                "files": ["src/domain/one.rs", "src/domain/two.rs"],
                "directories": ["src/domain"],
            },
            "locked_files": [
                {
                    "path": "src/contract.rs",
                    "sha256": digest(b"contract\n"),
                    "contract": "fixture",
                }
            ],
            "logical_sources": [
                {
                    "name": "domain",
                    "parts": ["src/domain/one.rs", "src/domain/two.rs"],
                    "sha256": digest(b"one\ntwo\n"),
                }
            ],
        }
        self.write_manifest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_manifest(self) -> None:
        (self.root / "release" / "refactoring-contracts-0.7.0.json").write_text(
            json.dumps(self.manifest), encoding="utf-8"
        )

    def run_checker(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECKER), "--root", str(self.root)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def test_valid_manifest_passes(self) -> None:
        self.assertEqual(self.run_checker().returncode, 0)

    def test_modified_locked_contract_fails(self) -> None:
        (self.root / "src" / "contract.rs").write_text("changed\n", encoding="utf-8")
        self.assertNotEqual(self.run_checker().returncode, 0)

    def test_reordered_split_parts_fail(self) -> None:
        self.manifest["logical_sources"][0]["parts"].reverse()
        self.write_manifest()
        self.assertNotEqual(self.run_checker().returncode, 0)

    def test_wrapper_stripping_is_exact(self) -> None:
        wrapped = self.root / "src" / "domain" / "wrapped.rs"
        wrapped.write_text("impl Domain {\none\n}\n", encoding="utf-8")
        logical = self.manifest["logical_sources"][0]
        logical["parts"] = [
            {
                "path": "src/domain/wrapped.rs",
                "strip_prefix": "impl Domain {\n",
                "strip_suffix": "}\n",
            }
        ]
        logical["sha256"] = digest(b"one\n")
        self.write_manifest()
        self.assertEqual(self.run_checker().returncode, 0)

        logical["parts"][0]["strip_prefix"] = "impl Other {\n"
        self.write_manifest()
        self.assertNotEqual(self.run_checker().returncode, 0)

    def test_parent_traversal_fails(self) -> None:
        self.manifest["required_paths"]["files"][0] = "../outside.rs"
        self.write_manifest()
        self.assertNotEqual(self.run_checker().returncode, 0)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_symlinked_contract_fails(self) -> None:
        target = self.root / "target.rs"
        target.write_text("contract\n", encoding="utf-8")
        link = self.root / "src" / "contract-link.rs"
        try:
            os.symlink(target, link)
        except OSError as error:
            self.skipTest(f"cannot create symlink: {error}")
        self.manifest["locked_files"][0]["path"] = "src/contract-link.rs"
        self.write_manifest()
        self.assertNotEqual(self.run_checker().returncode, 0)


if __name__ == "__main__":
    unittest.main()
