#!/usr/bin/env python3
"""Resolve release evidence from immutable Actions artifacts, never caller assertions."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("performance", ROOT / "tools/check-performance-evidence.py")
assert SPEC and SPEC.loader
PERF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PERF)
EvidenceError = PERF.EvidenceError
PERFORMANCE_WORKFLOW = ".github/workflows/performance-evidence.yml"
PRODUCER_FILES = ("tools/load-test.sh", "tools/collect-performance-evidence.py",
                  "tools/check-performance-evidence.py")


def producer_digest(root: Path = ROOT) -> str:
    digest = hashlib.sha256()
    for name in PRODUCER_FILES:
        digest.update(name.encode() + b"\0")
        digest.update(hashlib.sha256((root / name).read_bytes()).digest())
    return digest.hexdigest()


def positive(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise EvidenceError(f"{label}: expected a positive integer")
    return value


class GitHub:
    def __init__(self, repository: str):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise EvidenceError("invalid repository")
        self.repository = repository

    def request(self, suffix: str, *, raw: bool = False):
        result = subprocess.run(["gh", "api", f"repos/{self.repository}/{suffix}"],
                                capture_output=True, check=False)
        if result.returncode:
            raise EvidenceError("GitHub evidence lookup failed")
        return result.stdout if raw else json.loads(result.stdout)

    def pages(self, suffix: str, field: str | None = None):
        for page in range(1, 101):
            separator = "&" if "?" in suffix else "?"
            result = self.request(f"{suffix}{separator}per_page=100&page={page}")
            items = result[field] if field else result
            yield from items
            if len(items) < 100:
                return
        raise EvidenceError("GitHub evidence pagination exceeded its bound")

    def run(self, run_id: int, commit: str, workflow: str, event: str | None = None,
            title: str | None = None) -> dict:
        positive(run_id, "run ID")
        run = self.request(f"actions/runs/{run_id}")
        if (run.get("head_sha") != commit or run.get("head_branch") != "main"
                or run.get("status") != "completed" or run.get("conclusion") != "success"
                or run.get("path", "").split("@")[0] != workflow
                or run.get("repository", {}).get("full_name") != self.repository
                or run.get("head_repository", {}).get("full_name") != self.repository
                or (event is not None and run.get("event") != event)
                or (title is not None and run.get("display_title") != title)):
            raise EvidenceError("workflow run does not match the trusted release inputs")
        positive(run.get("run_attempt"), "run attempt")
        return run

    def gate(self, commit: str, context: str, workflow: str, event: str | None = None,
             title: str | None = None) -> dict:
        status = next((item for item in self.pages(f"commits/{commit}/statuses")
                       if item.get("context") == context), None)
        if not status or status.get("state") != "success":
            raise EvidenceError(f"required gate is not successful: {context}")
        prefix = f"https://github.com/{self.repository}/actions/runs/"
        url = status.get("target_url", "")
        if not url.startswith(prefix) or not re.fullmatch(r"[1-9][0-9]*", url[len(prefix):]):
            raise EvidenceError("gate does not identify a run in this repository")
        return self.run(int(url[len(prefix):]), commit, workflow, event, title)

    def artifact(self, run: dict, name: str, destination: Path) -> dict:
        artifacts = [item for item in self.pages(f"actions/runs/{run['id']}/artifacts", "artifacts")
                     if item.get("name") == name]
        if len(artifacts) != 1:
            raise EvidenceError("expected exactly one named evidence artifact")
        artifact = artifacts[0]
        digest = artifact.get("digest", "")
        if artifact.get("expired") is not False or not digest.startswith("sha256:"):
            raise EvidenceError("evidence artifact is expired or has no immutable digest")
        PERF._sha256(digest.removeprefix("sha256:"), "artifact digest")
        if (artifact.get("workflow_run", {}).get("id") != run["id"]
                or artifact.get("workflow_run", {}).get("head_sha") != run["head_sha"]):
            raise EvidenceError("artifact belongs to a different workflow run")
        try:
            created = datetime.fromisoformat(artifact["created_at"].replace("Z", "+00:00"))
            started = datetime.fromisoformat(run["run_started_at"].replace("Z", "+00:00"))
            if created.tzinfo is None or started.tzinfo is None or created < started:
                raise EvidenceError("artifact predates the current workflow attempt")
        except (KeyError, TypeError, ValueError) as error:
            raise EvidenceError("artifact does not identify the current workflow attempt") from error
        raw = self.request(f"actions/artifacts/{positive(artifact['id'], 'artifact ID')}/zip", raw=True)
        if hashlib.sha256(raw).hexdigest() != digest.removeprefix("sha256:"):
            raise EvidenceError("downloaded artifact digest differs from GitHub metadata")
        extract_artifact(raw, destination)
        return {"repository": self.repository, "run_id": run["id"],
                "run_attempt": run["run_attempt"], "workflow_sha": run["head_sha"],
                "artifact_id": artifact["id"], "artifact_name": name,
                "artifact_sha256": digest.removeprefix("sha256:")}


def extract_artifact(raw: bytes, destination: Path) -> None:
    if len(raw) > 512 * 1024 * 1024 or destination.exists():
        raise EvidenceError("artifact is too large or extraction destination already exists")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        seen = set()
        total = 0
        for entry in archive.infolist():
            name = entry.filename.rstrip("/")
            path = PurePosixPath(name)
            mode = entry.external_attr >> 16
            if (entry.orig_filename != entry.filename or not name or path.is_absolute() or "\\" in name or ":" in name
                    or any(part in {"", ".", ".."} for part in name.split("/"))
                    or name in seen or entry.flag_bits & 1
                    or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)
                    or entry.file_size > 64 * 1024 * 1024):
                raise EvidenceError("artifact contains an unsafe archive member")
            seen.add(name)
            total += entry.file_size
        if total > 512 * 1024 * 1024 or len(seen) > 20_000:
            raise EvidenceError("artifact expanded size exceeds its bound")
        destination.mkdir(parents=True)
        archive.extractall(destination)


def baseline_lock() -> dict:
    lock, _ = PERF._read_json(ROOT / "release/performance/baseline.lock.json")
    if lock.get("schema_version") != 1 or lock.get("commit") != PERF.BASELINE_COMMIT:
        raise EvidenceError("missing or invalid reviewed baseline lock")
    PERF._sha256(lock.get("aggregate_sha256"), "baseline aggregate digest")
    return lock


def validate_bundle(directory: Path, expected: dict) -> dict:
    lock = baseline_lock()
    _, raw = PERF._read_json(directory / "baseline.json")
    if hashlib.sha256(raw).hexdigest() != lock["aggregate_sha256"]:
        raise EvidenceError("baseline differs from the reviewed lock")
    result = PERF.compare(directory / "baseline.json", directory / "candidate.json", expected)
    if not result["passed"]:
        raise EvidenceError("performance thresholds failed: " + "; ".join(result["failures"]))
    return result


def performance_receipt(api: GitHub, commit: str, binary: str, packages_run: int,
                        candidate_run: int, destination: Path) -> dict:
    run = api.gate(commit, "vaultlink/performance", PERFORMANCE_WORKFLOW, "workflow_dispatch")
    name = f"vaultlink-performance-{commit}-{run['id']}-{run['run_attempt']}"
    receipt = api.artifact(run, name, destination)
    producer, _ = PERF._read_json(destination / "receipt.json")
    if (producer.get("schema_version") != 1 or producer.get("run_id") != run["id"] or producer.get("run_attempt") != run["run_attempt"]
            or producer.get("workflow_sha") != commit or producer.get("kind") != "candidate"):
        raise EvidenceError("performance producer receipt does not match the current run attempt")
    expected = {"commit": commit, "binary_sha256": binary, "package_target": "debian13-amd64",
                "packages_run_id": packages_run, "candidate_preflight_run_id": candidate_run,
                "producer_sha256": producer_digest()}
    if producer.get("identity") != expected:
        raise EvidenceError("producer receipt identity differs from the expected candidate")
    validate_bundle(destination, expected)
    return {**receipt, "identity": expected}


def verify_receipt(receipt: dict, commit: str, binary: str, packages_run: int) -> dict:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if receipt.get("repository") != repository:
        raise EvidenceError("receipt repository differs from the calling workflow")
    api = GitHub(repository)
    packages = api.gate(commit, "vaultlink/packages", ".github/workflows/packages.yml")
    if packages["id"] != packages_run:
        raise EvidenceError("packages run differs from the current successful gate")
    candidate = api.gate(commit, "vaultlink/release-candidate-preflight", ".github/workflows/release.yml",
                         "workflow_dispatch", f"Release candidate {commit}")
    with tempfile.TemporaryDirectory() as temporary:
        verified = performance_receipt(api, commit, binary, packages_run, candidate["id"],
                                       Path(temporary) / "performance")
    if receipt != verified:
        raise EvidenceError("receipt is stale or does not match the verified artifact")
    return verified


def verify_soak(api: GitHub, commit: str, binary: str, destination: Path) -> dict:
    run = api.gate(commit, "vaultlink/72h-soak", ".github/workflows/soak-collect.yml")
    receipt = api.artifact(run, f"soak-evidence-{commit}", destination)
    result = subprocess.run(["sh", str(ROOT / "tools/check-soak-evidence.sh"), commit, str(destination)],
                            capture_output=True, text=True, check=False)
    if result.returncode or f"binary_sha256={binary}" not in result.stdout.splitlines():
        raise EvidenceError("72-hour soak is incomplete or belongs to another binary")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("producer-digest")
    verify = commands.add_parser("performance")
    verify.add_argument("--commit", required=True)
    verify.add_argument("--binary-sha256", required=True)
    verify.add_argument("--packages-run-id", required=True, type=int)
    verify.add_argument("--output", required=True, type=Path)
    register = commands.add_parser("lock-baseline")
    register.add_argument("--run-id", required=True, type=int)
    register.add_argument("--workflow-sha", required=True)
    register.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "producer-digest":
            print(producer_digest())
            return 0
        api = GitHub(os.environ.get("GITHUB_REPOSITORY", ""))
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "evidence"
            if args.command == "performance":
                PERF._commit(args.commit, "expected commit")
                PERF._sha256(args.binary_sha256, "expected binary")
                packages = api.gate(args.commit, "vaultlink/packages", ".github/workflows/packages.yml")
                if packages["id"] != args.packages_run_id:
                    raise EvidenceError("packages run differs from the current successful gate")
                candidate = api.gate(args.commit, "vaultlink/release-candidate-preflight",
                                     ".github/workflows/release.yml", "workflow_dispatch",
                                     f"Release candidate {args.commit}")
                result = performance_receipt(api, args.commit, args.binary_sha256, args.packages_run_id,
                                             candidate["id"], destination)
            else:
                PERF._commit(args.workflow_sha, "baseline producer commit")
                run = api.run(args.run_id, args.workflow_sha, PERFORMANCE_WORKFLOW, "workflow_dispatch")
                name = f"vaultlink-performance-baseline-{PERF.BASELINE_COMMIT}-{run['id']}-{run['run_attempt']}"
                receipt = api.artifact(run, name, destination)
                producer, _ = PERF._read_json(destination / "receipt.json")
                if (producer.get("schema_version") != 1 or producer.get("kind") != "baseline" or producer.get("run_id") != run["id"]
                        or producer.get("run_attempt") != run["run_attempt"]
                        or producer.get("workflow_sha") != args.workflow_sha):
                    raise EvidenceError("baseline producer receipt differs from the workflow")
                aggregate = PERF._aggregate_file(destination / "baseline.json", "baseline")
                if producer.get("identity") != PERF.identity(aggregate, "baseline"):
                    raise EvidenceError("baseline producer identity differs from its runs")
                result = {"schema_version": 1, "commit": PERF.BASELINE_COMMIT, **receipt,
                          "aggregate_sha256": hashlib.sha256((destination / "baseline.json").read_bytes()).hexdigest(),
                          "identity": PERF.identity(aggregate, "baseline")}
        PERF._write_json(args.output, result)
        return 0
    except (EvidenceError, OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        print(f"release evidence rejected: {error}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
