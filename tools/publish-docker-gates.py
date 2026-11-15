#!/usr/bin/env python3
"""Publish independent Docker gates from verified qualification evidence."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile


SPEC = importlib.util.spec_from_file_location(
    "release_evidence", Path(__file__).with_name("release-evidence.py")
)
assert SPEC and SPEC.loader
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)
ARCHITECTURES = ("amd64", "arm64")
EVIDENCE_ERRORS = (
    EVIDENCE.EvidenceError, OSError, ValueError, KeyError, TypeError,
    EOFError, zipfile.BadZipFile,
)


def evaluate(api, run_id: int, run_attempt: int, commit: str,
             version: str, destination: Path) -> dict:
    result = {
        "schema_version": 1, "repository": api.repository, "commit": commit,
        "version": version, "workflow": EVIDENCE.DOCKER_WORKFLOW,
        "run_id": run_id, "run_attempt": run_attempt, "architectures": {},
    }
    try:
        EVIDENCE.positive(run_id, "run ID")
        EVIDENCE.positive(run_attempt, "run attempt")
        EVIDENCE.PERF._commit(commit, "Docker candidate commit")
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
            raise EVIDENCE.EvidenceError("invalid Docker candidate version")
        run = api.request(f"actions/runs/{run_id}")
        EVIDENCE.docker_run_identity(api, run, commit)
        if run["id"] != run_id or run["run_attempt"] != run_attempt:
            raise EVIDENCE.EvidenceError("caller does not identify the current workflow attempt")
    except EVIDENCE_ERRORS as error:
        result["architectures"] = {
            architecture: {"state": "failure", "reason": str(error)}
            for architecture in ARCHITECTURES
        }
    else:
        for architecture in ARCHITECTURES:
            try:
                qualification = EVIDENCE.docker_architecture_qualification(
                    api, run, commit, version, architecture, destination / architecture
                )
                result["architectures"][architecture] = {
                    "state": "success", "qualification": qualification,
                }
            except EVIDENCE_ERRORS as error:
                result["architectures"][architecture] = {
                    "state": "failure", "reason": str(error),
                }
    result["state"] = (
        "success" if all(entry["state"] == "success"
                         for entry in result["architectures"].values()) else "failure"
    )
    return result


def publish(result: dict) -> bool:
    """Attempt both contexts even if evidence or the first API request fails."""
    EVIDENCE.PERF._commit(result["commit"], "Docker status commit")
    EVIDENCE.positive(result["run_id"], "run ID")
    repository = EVIDENCE.GitHub(result["repository"]).repository
    target = f"https://github.com/{repository}/actions/runs/{result['run_id']}"
    succeeded = True
    for architecture in ARCHITECTURES:
        entry = result["architectures"][architecture]
        state = entry["state"]
        description = (
            "Verified native image, rootless Docker and Kubernetes deployment"
            if state == "success" else "Docker qualification evidence is invalid or incomplete"
        )
        command = [
            "gh", "api", "--method", "POST",
            f"repos/{repository}/statuses/{result['commit']}",
            "-f", f"state={state}", "-f", f"context=vaultlink/docker-{architecture}",
            "-f", f"description={description}", "-f", f"target_url={target}",
        ]
        try:
            response = subprocess.run(command, capture_output=True, text=True, check=False)
            if response.returncode:
                raise OSError("GitHub status publication failed")
        except OSError:
            succeeded = False
            entry["published"] = False
            entry["publication_error"] = "GitHub status publication failed"
        else:
            entry["published"] = True
    result["publication_state"] = "success" if succeeded else "failure"
    if not succeeded:
        result["state"] = "failure"
    return succeeded


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--run-attempt", required=True, type=int)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", "alexhaberl/VaultLink"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--publish", action="store_true", help="write both GitHub commit statuses")
    args = parser.parse_args(argv)
    try:
        api = EVIDENCE.GitHub(args.repository)
        result = evaluate(api, args.run_id, args.run_attempt, args.commit, args.version,
                          args.output.parent / (args.output.stem + "-receipts"))
        if args.publish:
            publish(result)
        encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
        print(encoded, end="")
    except EVIDENCE_ERRORS as error:
        print(f"Docker gate publisher failed: {error}", file=sys.stderr)
        return 1
    return 0 if result["state"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
