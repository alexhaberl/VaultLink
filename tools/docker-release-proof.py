#!/usr/bin/env python3
"""Bind qualified binary hashes to both child images and the anonymous pull."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REFERENCE = re.compile(r"ghcr\.io/alexhaberl/vaultlink@sha256:[0-9a-f]{64}\Z")


def parse_fields(lines: list[str], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in lines:
        if "=" not in line:
            raise ValueError(f"malformed evidence line in {label}")
        key, value = line.split("=", 1)
        if not key or key in result:
            raise ValueError(f"duplicate or empty evidence field in {label}: {key}")
        result[key] = value
    return result


def fields(path: Path) -> dict[str, str]:
    return parse_fields(path.read_text(encoding="utf-8").splitlines(), path.name)


def create_proof(root: Path, repository: str, commit: str, tag: str,
                 run_id: int, run_attempt: int,
                 hashes: dict[str, str], artifact_hashes: dict[str, str]) -> dict:
    if repository != "alexhaberl/VaultLink" or not COMMIT.fullmatch(commit):
        raise ValueError("invalid repository or full commit identity")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("invalid release tag")
    if run_id <= 0 or run_attempt <= 0:
        raise ValueError("invalid qualification run or attempt")
    lines = (root / "image-reference.txt").read_text(encoding="utf-8").splitlines()
    if not lines or not REFERENCE.fullmatch(lines[0]):
        raise ValueError("missing immutable index reference")
    reference = lines[0]
    image = parse_fields(lines[1:], "image-reference.txt")
    expected = {
        "tag": tag,
        "commit": commit,
        "qualification_run": str(run_id),
        "qualification_attempt": str(run_attempt),
    }
    proof = {
        "schema_version": 1,
        "repository": repository,
        "commit": commit,
        "tag": tag,
        "qualification_run": run_id,
        "qualification_attempt": run_attempt,
        "index_digest": reference.split("@", 1)[1],
        "architectures": {},
    }
    for architecture in ("amd64", "arm64"):
        qualified = hashes[architecture]
        artifact = artifact_hashes[architecture]
        if not SHA256.fullmatch(qualified) or not SHA256.fullmatch(artifact):
            raise ValueError(f"invalid {architecture} binary or artifact hash")
        child = image.get(architecture, "")
        if not DIGEST.fullmatch(child):
            raise ValueError(f"invalid {architecture} child digest")
        expected[architecture] = child
        expected[f"qualified_{architecture}_sha256"] = qualified
        expected[f"qualified_{architecture}_artifact_sha256"] = artifact
        public = fields(root / f"public-binary-{architecture}.txt")
        if public != {
            "reference": reference,
            "architecture": architecture,
            "child_digest": child,
            "qualified_sha256": qualified,
            "public_sha256": qualified,
        }:
            raise ValueError(f"public {architecture} binary does not match qualification")
        proof["architectures"][architecture] = {
            "child_digest": child,
            "qualified_binary_sha256": qualified,
            "published_binary_sha256": public["public_sha256"],
            "qualification_artifact_sha256": artifact,
        }
    if image != expected:
        raise ValueError("index evidence contains missing or unexpected identity fields")
    if (root / "platforms.actual").read_text(encoding="utf-8").splitlines() != [
        "linux/amd64", "linux/arm64"
    ]:
        raise ValueError("index platform evidence differs from required architectures")
    return proof


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--qualification-run", type=int, required=True)
    parser.add_argument("--qualification-attempt", type=int, required=True)
    for architecture in ("amd64", "arm64"):
        parser.add_argument(f"--{architecture}-hash", required=True)
        parser.add_argument(f"--{architecture}-artifact-sha", required=True)
    args = parser.parse_args()
    proof = create_proof(args.evidence, args.repository, args.commit, args.tag,
                         args.qualification_run, args.qualification_attempt,
                         {arch: getattr(args, f"{arch}_hash") for arch in ("amd64", "arm64")},
                         {arch: getattr(args, f"{arch}_artifact_sha")
                          for arch in ("amd64", "arm64")})
    (args.evidence / "docker-release-proof.json").write_text(
        json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
