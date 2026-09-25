#!/usr/bin/env python3
"""Offline negative cases for the final Docker binary identity receipt."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "docker_release_proof", Path(__file__).with_name("docker-release-proof.py"))
assert spec and spec.loader
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)


class DockerReleaseProofTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.commit = "a" * 40
        self.hashes = {"amd64": "b" * 64, "arm64": "c" * 64}
        self.artifact_hashes = {"amd64": "d" * 64, "arm64": "e" * 64}
        self.reference = "ghcr.io/alexhaberl/vaultlink@sha256:" + "f" * 64
        self.children = {"amd64": "sha256:" + "1" * 64,
                         "arm64": "sha256:" + "2" * 64}
        lines = [
            self.reference, "tag=v0.7.2", f"commit={self.commit}",
            f"amd64={self.children['amd64']}", f"arm64={self.children['arm64']}",
            "qualification_run=123", "qualification_attempt=2",
        ]
        for architecture in ("amd64", "arm64"):
            lines.append(f"qualified_{architecture}_sha256={self.hashes[architecture]}")
            lines.append(f"qualified_{architecture}_artifact_sha256="
                         f"{self.artifact_hashes[architecture]}")
            (self.root / f"public-binary-{architecture}.txt").write_text(
                f"reference={self.reference}\narchitecture={architecture}\n"
                f"child_digest={self.children[architecture]}\n"
                f"qualified_sha256={self.hashes[architecture]}\n"
                f"public_sha256={self.hashes[architecture]}\n")
        (self.root / "image-reference.txt").write_text("\n".join(lines) + "\n")
        (self.root / "platforms.actual").write_text("linux/amd64\nlinux/arm64\n")

    def verify(self) -> dict:
        return proof.create_proof(self.root, "alexhaberl/VaultLink", self.commit,
                                  "v0.7.2", 123, 2, self.hashes,
                                  self.artifact_hashes)

    def edit(self, file: str, old: str, new: str) -> None:
        path = self.root / file
        value = path.read_text()
        assert old in value
        path.write_text(value.replace(old, new, 1))

    def test_valid_two_architecture_receipt(self) -> None:
        result = self.verify()
        self.assertEqual(result["index_digest"], "sha256:" + "f" * 64)
        self.assertEqual(result["architectures"]["arm64"]["published_binary_sha256"],
                         self.hashes["arm64"])

    def test_rejects_wrong_commit(self) -> None:
        self.edit("image-reference.txt", f"commit={self.commit}", "commit=" + "0" * 40)
        with self.assertRaises(ValueError):
            self.verify()

    def test_rejects_wrong_attempt(self) -> None:
        self.edit("image-reference.txt", "qualification_attempt=2", "qualification_attempt=1")
        with self.assertRaises(ValueError):
            self.verify()

    def test_rejects_changed_child_digest(self) -> None:
        self.edit("public-binary-amd64.txt", self.children["amd64"], "sha256:" + "3" * 64)
        with self.assertRaises(ValueError):
            self.verify()

    def test_rejects_changed_public_binary(self) -> None:
        self.edit("public-binary-arm64.txt", "public_sha256=" + self.hashes["arm64"],
                  "public_sha256=" + "0" * 64)
        with self.assertRaises(ValueError):
            self.verify()

    def test_rejects_changed_qualification_artifact(self) -> None:
        self.edit("image-reference.txt", self.artifact_hashes["amd64"], "0" * 64)
        with self.assertRaises(ValueError):
            self.verify()

    def test_rejects_duplicate_evidence_field(self) -> None:
        with (self.root / "image-reference.txt").open("a") as handle:
            handle.write("qualification_run=123\n")
        with self.assertRaises(ValueError):
            self.verify()

    def test_rejects_missing_architecture(self) -> None:
        (self.root / "public-binary-arm64.txt").unlink()
        with self.assertRaises(FileNotFoundError):
            self.verify()

    def test_rejects_platform_drift(self) -> None:
        (self.root / "platforms.actual").write_text("linux/amd64\n")
        with self.assertRaises(ValueError):
            self.verify()


if __name__ == "__main__":
    unittest.main()
