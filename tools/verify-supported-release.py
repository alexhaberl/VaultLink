#!/usr/bin/env python3
"""Verify the supported release against live, read-only GitHub metadata."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def fail(message: str) -> None:
    raise SystemExit(f"supported-release verification: {message}")


def load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {path.relative_to(ROOT)}: {error}")


def gh_json(*arguments: str) -> Any:
    command = ["gh", *arguments]
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        return json.loads(completed.stdout)
    except FileNotFoundError:
        fail("gh is not installed")
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() or f"exit {error.returncode}"
        fail(f"{' '.join(command)} failed: {detail}")
    except json.JSONDecodeError as error:
        fail(f"{' '.join(command)} returned invalid JSON: {error}")


def supported_entry(state: dict[str, Any]) -> dict[str, Any]:
    version = state.get("supported_version")
    matches = [
        release
        for release in state.get("releases", [])
        if isinstance(release, dict)
        and release.get("version") == version
        and release.get("status") == "supported"
    ]
    if len(matches) != 1:
        fail("release-state does not contain exactly one supported entry")
    return matches[0]


def expected_assets(version: str) -> set[str]:
    targets = load(ROOT / "release/package-targets.json")
    try:
        packages = {
            target["asset_name"].format(version=version)
            for target in targets["targets"]
        }
    except (KeyError, TypeError, ValueError) as error:
        fail(f"package-target manifest cannot render assets: {error}")
    return (
        packages
        | {f"{package}.minisig" for package in packages}
        | {
            f"vaultlink-{version}-sbom-bundle.json",
            "SHA256SUMS",
            "SHA256SUMS.minisig",
        }
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, help="GitHub OWNER/REPOSITORY")
    args = parser.parse_args()
    if REPOSITORY.fullmatch(args.repository) is None:
        fail("repository must be OWNER/REPOSITORY")

    subprocess.run(
        [sys.executable, str(ROOT / "tools/check-release-state.py")],
        cwd=ROOT,
        check=True,
    )
    state = load(ROOT / "release/release-state.json")
    if not isinstance(state, dict):
        fail("release-state root is not an object")
    supported = supported_entry(state)
    version = supported["version"]
    tag = supported["tag"]

    reference = gh_json("api", f"repos/{args.repository}/git/ref/tags/{tag}")
    remote_object = reference.get("object", {})
    if remote_object.get("type") != "tag" or remote_object.get("sha") != supported["tag_object_sha"]:
        fail("remote annotated tag object does not match release-state")

    tag_object = gh_json("api", f"repos/{args.repository}/git/tags/{supported['tag_object_sha']}")
    verification = tag_object.get("verification", {})
    if (
        tag_object.get("tag") != tag
        or tag_object.get("object", {}).get("type") != "commit"
        or tag_object.get("object", {}).get("sha") != supported["commit_sha"]
        or verification.get("verified") is not True
        or verification.get("reason") != "valid"
    ):
        fail("remote tag target or signature verification does not match release-state")

    release = gh_json(
        "release",
        "view",
        tag,
        "--repo",
        args.repository,
        "--json",
        "assets,isDraft,isImmutable,isPrerelease,publishedAt,tagName",
    )
    assets = release.get("assets", [])
    names = {asset.get("name") for asset in assets if isinstance(asset, dict)}
    if (
        release.get("tagName") != tag
        or release.get("isDraft") is not False
        or release.get("isPrerelease") is not False
        or release.get("isImmutable") is not True
        or release.get("publishedAt") != supported["published_at"]
        or len(assets) != supported["asset_count"]
        or names != expected_assets(version)
    ):
        fail("remote immutable release or exact 21-asset set does not match release-state")
    for asset in assets:
        if not isinstance(asset, dict) or not asset.get("digest") or not asset.get("size"):
            fail("remote release contains an asset without digest or content")

    combined = gh_json("api", f"repos/{args.repository}/commits/{supported['commit_sha']}/status")
    statuses = [status for status in combined.get("statuses", []) if isinstance(status, dict)]
    for expected in supported["required_commit_gates"]:
        if not any(
            actual.get("context") == expected["context"]
            and actual.get("state") == "success"
            and actual.get("target_url") == expected["run_url"]
            for actual in statuses
        ):
            fail(f"remote commit gate does not match release-state: {expected['context']}")

    print(
        f"supported release verified: {tag} {supported['commit_sha']} "
        f"({len(assets)} immutable assets)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
