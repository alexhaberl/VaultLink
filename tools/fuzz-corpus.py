#!/usr/bin/env python3
"""Restore and publish checked, content-addressed fuzz corpora (Python 3.11+)."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ARCHITECTURES = ("amd64", "arm64")
MAX_FILES = 100_000
MAX_BYTES = 512 * 1024 * 1024
NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
ARTIFACT_NAME = re.compile(r"fuzz-corpus-(amd64|arm64)-([1-9][0-9]*)\Z")


def targets(root: Path = ROOT) -> dict[str, int]:
    with (root / "fuzz/Cargo.toml").open("rb") as source:
        manifest = tomllib.load(source)
    versions = json.loads((root / "fuzz/corpus-versions.json").read_text())
    return validate_target_versions(manifest, versions)


def validate_target_versions(manifest: dict, versions: dict) -> dict[str, int]:
    names = [entry["name"] for entry in manifest["bin"]]
    if len(names) != len(set(names)) or set(names) != set(versions):
        raise ValueError("fuzz target names and corpus-versions.json must match exactly")
    if any(not NAME.fullmatch(name) or type(versions[name]) is not int or versions[name] < 1 for name in names):
        raise ValueError("invalid target name or input-schema version")
    return {name: versions[name] for name in names}


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def files(directory: Path) -> list[Path]:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError(f"expected a real corpus directory: {directory}")
    result = []
    for entry in sorted(directory.iterdir()):
        if entry.is_symlink() or not entry.is_file():
            raise ValueError(f"unexpected non-file corpus entry: {entry}")
        result.append(entry)
    if len(result) > MAX_FILES or sum(entry.stat().st_size for entry in result) > MAX_BYTES:
        raise ValueError(f"corpus exceeds safety limits: {directory}")
    return result


def add_input(destination: Path, data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    if destination.is_symlink():
        raise ValueError(f"corpus directory may not be a symlink: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / digest
    # exists() follows links and returns False for a dangling link. Reject the
    # link itself before deciding whether a digest file needs to be created.
    if path.is_symlink():
        raise ValueError(f"corpus input may not be a symlink: {path}")
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError(f"conflicting corpus input: {path}")
    else:
        path.write_bytes(data)
    return digest


def validate_snapshot(directory: Path) -> dict:
    manifest_path = directory / "manifest.json"
    if manifest_path.is_symlink():
        raise ValueError("snapshot manifest may not be a symlink")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1 or manifest.get("successful") is not True:
        raise ValueError("unsupported or unsuccessful corpus snapshot")
    if manifest.get("architecture") not in ARCHITECTURES:
        raise ValueError("invalid snapshot architecture")
    if not re.fullmatch(r"[0-9a-f]{40,64}", manifest.get("commit", "")):
        raise ValueError("invalid snapshot commit")
    for field in ("run_id", "run_attempt", "toolchain"):
        if not isinstance(manifest.get(field), str) or not manifest[field]:
            raise ValueError(f"missing snapshot {field}")
    entries = manifest.get("targets")
    if not isinstance(entries, dict) or not entries:
        raise ValueError("snapshot contains no target metadata")
    names = manifest.get("target_names")
    if not isinstance(names, list) or len(names) != len(entries) or set(names) != set(entries):
        raise ValueError("snapshot target metadata differs from its producer target list")
    expected = {"manifest.json"}
    total_bytes = 0
    total_files = 0
    for target, metadata in entries.items():
        if not NAME.fullmatch(target) or not isinstance(metadata, dict) or type(metadata.get("input_schema")) is not int or metadata["input_schema"] < 1:
            raise ValueError("invalid snapshot target schema")
        hashes = metadata.get("files")
        if not isinstance(hashes, dict) or not hashes:
            raise ValueError(f"snapshot has no input hashes for {target}")
        for digest, size in hashes.items():
            if not SHA256.fullmatch(digest) or type(size) is not int or size < 0:
                raise ValueError("invalid snapshot input metadata")
            total_bytes += size
            total_files += 1
            if total_bytes > MAX_BYTES or total_files > MAX_FILES:
                raise ValueError("snapshot exceeds safety limits")
            relative = f"corpus/{target}/{digest}"
            expected.add(relative)
            path = directory / relative
            if path.is_symlink() or not path.is_file() or path.stat().st_size != size:
                raise ValueError(f"snapshot missing or altered input: {relative}")
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError(f"snapshot checksum mismatch: {relative}")
    actual = set()
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"snapshot symlink: {path}")
        if path.is_file():
            actual.add(path.relative_to(directory).as_posix())
        elif not path.is_dir():
            raise ValueError(f"snapshot non-regular entry: {path}")
    if actual != expected:
        raise ValueError("snapshot contains missing or unlisted files")
    return manifest


def extract_snapshot(archive: Path, destination: Path) -> None:
    """Extract only regular files; reject traversal, links, duplicates and zip bombs."""
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        if len(entries) > MAX_FILES + 100 or sum(entry.file_size for entry in entries) > MAX_BYTES:
            raise ValueError("snapshot archive exceeds safety limits")
        seen = set()
        for entry in entries:
            name = entry.orig_filename
            path = PurePosixPath(name)
            mode = entry.external_attr >> 16
            if (not name or "\x00" in name or "\\" in name or ":" in name or path.is_absolute()
                    or any(part in (".", "..") for part in name.rstrip("/").split("/"))
                    or name in seen or stat.S_ISLNK(mode)
                    or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))):
                raise ValueError(f"unsafe snapshot archive entry: {name!r}")
            seen.add(name)
        destination.mkdir(parents=True, exist_ok=False)
        for entry in entries:
            output = destination / entry.filename
            if entry.is_dir():
                output.mkdir(parents=True, exist_ok=True)
            else:
                output.parent.mkdir(parents=True, exist_ok=True)
                with source.open(entry) as incoming, output.open("xb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing)


def gh_json(endpoint: str) -> object:
    result = subprocess.run(["gh", "api", endpoint], check=True, capture_output=True, text=True, timeout=90)
    return json.loads(result.stdout)


def producer_versions(repository: str, commit: str) -> dict[str, int]:
    def read(path: str) -> str:
        response = gh_json(f"repos/{repository}/contents/{path}?ref={commit}")
        if response["type"] != "file" or response["encoding"] != "base64":
            raise ValueError(f"producer schema metadata is not a regular base64 file: {path}")
        return base64.b64decode(response["content"]).decode("utf-8")
    return validate_target_versions(tomllib.loads(read("fuzz/Cargo.toml")), json.loads(read("fuzz/corpus-versions.json")))


def select_artifacts(artifacts: list[dict], run_attempt: int) -> dict[str, dict]:
    candidates = {architecture: {} for architecture in ARCHITECTURES}
    for artifact in artifacts:
        match = ARTIFACT_NAME.fullmatch(artifact["name"])
        if match is None:
            continue
        architecture, attempt_text = match.groups()
        attempt = int(attempt_text)
        if attempt > run_attempt or attempt in candidates[architecture]:
            raise ValueError("duplicate corpus artifact or artifact attempt newer than its workflow run")
        candidates[architecture][attempt] = artifact
    if any(candidates.values()) and not all(candidates.values()):
        raise ValueError("incomplete corpus artifacts in successful run")
    available = {architecture: {attempt: artifact for attempt, artifact in attempts.items() if not artifact["expired"]}
                 for architecture, attempts in candidates.items()}
    if not any(available.values()):
        return {}
    if not all(available.values()):
        raise ValueError("incomplete corpus artifacts in successful run")
    return {architecture: {**attempts[max(attempts)], "producer_attempt": max(attempts)} for architecture, attempts in available.items()}


def verify_producer_job(repository: str, run_id: int, attempt: int, architecture: str) -> None:
    jobs = []
    page = 1
    while True:
        result = gh_json(f"repos/{repository}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100&page={page}")
        jobs.extend(job for job in result["jobs"] if job["name"] == f"Fuzz all targets ({architecture})")
        if len(result["jobs"]) < 100:
            break
        page += 1
    if len(jobs) != 1 or jobs[0]["conclusion"] != "success":
        raise ValueError(f"corpus producer job did not succeed: {architecture}, attempt {attempt}")


def download_previous(repository: str, temporary: Path, run_id: str | None = None) -> tuple[list[Path], dict]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid GitHub repository")
    # Query this exact workflow, branch and conclusion. PR and failed-run artifacts
    # cannot become the trusted source, regardless of their artifact names.
    if run_id is not None and not re.fullmatch(r"[1-9][0-9]*", run_id):
        raise ValueError("invalid workflow run ID")
    workflow = gh_json(f"repos/{repository}/actions/workflows/fuzz.yml") if run_id else None
    page = 1
    current_run = os.environ.get("GITHUB_RUN_ID", "")
    while True:
        if run_id:
            runs = [gh_json(f"repos/{repository}/actions/runs/{run_id}")]
            if runs[0]["workflow_id"] != workflow["id"]:
                raise ValueError("requested run does not belong to fuzz.yml")
        else:
            response = gh_json(f"repos/{repository}/actions/workflows/fuzz.yml/runs?branch=main&status=success&per_page=100&page={page}")
            runs = response["workflow_runs"]
        for run in runs:
            if not run_id and str(run["id"]) == current_run:
                continue
            if run["head_branch"] != "main" or run["conclusion"] != "success" or run["event"] not in ("schedule", "workflow_dispatch", "push"):
                continue
            if run.get("head_repository", {}).get("full_name", "").lower() != repository.lower():
                continue
            all_artifacts = []
            artifact_page = 1
            while True:
                result = gh_json(f"repos/{repository}/actions/runs/{run['id']}/artifacts?per_page=100&page={artifact_page}")
                all_artifacts.extend(result["artifacts"])
                if len(result["artifacts"]) < 100:
                    break
                artifact_page += 1
            selected = select_artifacts(all_artifacts, run["run_attempt"])
            if not selected:
                continue
            snapshots = []
            for architecture in ARCHITECTURES:
                artifact = selected[architecture]
                attempt = artifact["producer_attempt"]
                verify_producer_job(repository, run["id"], attempt, architecture)
                archive = temporary / f"{architecture}.zip"
                with archive.open("wb") as output:
                    subprocess.run(["gh", "api", f"repos/{repository}/actions/artifacts/{artifact['id']}/zip"], stdout=output, check=True, timeout=180)
                directory = temporary / architecture
                extract_snapshot(archive, directory)
                manifest = validate_snapshot(directory)
                if (manifest["architecture"] != architecture or manifest["run_id"] != str(run["id"])
                        or manifest["run_attempt"] != str(attempt) or manifest["commit"] != run["head_sha"]):
                    raise ValueError("snapshot provenance does not match its successful workflow run")
                snapshots.append(directory)
            schemas = producer_versions(repository, run["head_sha"])
            for directory in snapshots:
                manifest = validate_snapshot(directory)
                actual = {target: entry["input_schema"] for target, entry in manifest["targets"].items()}
                if actual != schemas:
                    raise ValueError("snapshot targets or input schemas differ from the producer commit")
            return snapshots, {"kind": "successful-main", "run_id": str(run["id"]), "commit": run["head_sha"],
                               "architecture_attempts": {arch: entry["producer_attempt"] for arch, entry in selected.items()}}
        if run_id:
            raise ValueError("requested run is not a successful main campaign with retained corpora")
        if len(runs) < 100:
            return [], {"kind": "bootstrap", "reason": "No retained successful main corpus artifacts; starting with Git seeds."}
        page += 1


def restore(destination: Path, snapshots: list[Path], provenance: dict, root: Path = ROOT) -> None:
    versions = targets(root)
    checked = [(path, validate_snapshot(path)) for path in snapshots]
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("restore destination must be empty; refusing to mix stale or unchecked state")
    destination.mkdir(parents=True, exist_ok=True)
    skipped = []
    for target, version in versions.items():
        output = destination / target
        output.mkdir()
        seeds = files(root / "fuzz/corpus" / target)
        if not seeds:
            raise ValueError(f"missing Git seed inputs for {target}")
        for seed in seeds:
            add_input(output, seed.read_bytes())
        for snapshot, manifest in checked:
            metadata = manifest["targets"].get(target)
            if metadata is None or metadata["input_schema"] != version:
                skipped.append(f"{manifest['architecture']}/{target}: new target or changed input schema; Git seeds only from this source")
                continue
            for entry in files(snapshot / "corpus" / target):
                add_input(output, entry.read_bytes())
    record = {"schema_version": 1, "source": provenance, "skipped": skipped,
              "targets": {target: {"input_schema": version, "files": len(files(destination / target))} for target, version in versions.items()}}
    write_json(destination / "restore.json", record)
    print(json.dumps(record, indent=2))


def snapshot(corpus: Path, destination: Path, architecture: str, logs: Path, root: Path = ROOT) -> None:
    versions = targets(root)
    summary = json.loads((logs / "summary.json").read_text(encoding="utf-8"))
    if summary.get("successful") is not True or set(summary.get("targets", {})) != set(versions):
        raise ValueError("refusing to publish an unsuccessful or incomplete campaign")
    if summary.get("corpus_dir") != str(corpus.resolve()):
        raise ValueError("campaign summary belongs to a different corpus")
    for target in versions:
        result = summary["targets"][target]
        if result.get("exit_code") != 0 or result.get("completed_stages") != ["replay", "fuzz", "cmin"]:
            raise ValueError(f"target did not complete replay, fuzzing and minimization: {target}")
    commit = os.environ.get("GITHUB_SHA") or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    manifest = {"schema_version": 1, "successful": True, "commit": commit,
                "architecture": architecture, "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
                "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"), "toolchain": summary["toolchain"],
                "target_names": list(versions), "targets": {}}
    destination.mkdir(parents=True, exist_ok=False)
    for target, version in versions.items():
        hashes = {}
        for entry in files(corpus / target):
            data = entry.read_bytes()
            digest = add_input(destination / "corpus" / target, data)
            hashes[digest] = len(data)
        manifest["targets"][target] = {"input_schema": version, "files": hashes}
    write_json(destination / "manifest.json", manifest)
    validate_snapshot(destination)
    print(f"Validated corpus snapshot: {destination}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("targets")
    restore_parser = commands.add_parser("restore")
    restore_parser.add_argument("--destination", type=Path, required=True)
    restore_parser.add_argument("--run-id", help="require this successful main fuzz.yml producer run")
    source = restore_parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--repository")
    source.add_argument("--snapshot", type=Path, action="append")
    source.add_argument("--seed-only", action="store_true")
    snapshot_parser = commands.add_parser("snapshot")
    snapshot_parser.add_argument("--corpus", type=Path, required=True)
    snapshot_parser.add_argument("--destination", type=Path, required=True)
    snapshot_parser.add_argument("--architecture", choices=ARCHITECTURES, required=True)
    snapshot_parser.add_argument("--logs", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "targets":
        print("\n".join(targets()))
    elif args.command == "snapshot":
        snapshot(args.corpus, args.destination, args.architecture, args.logs)
    else:
        with tempfile.TemporaryDirectory(prefix="vaultlink-fuzz-restore-") as temporary:
            if args.repository:
                snapshots, provenance = download_previous(args.repository, Path(temporary), args.run_id)
            else:
                if args.run_id:
                    raise ValueError("--run-id requires --repository")
                snapshots = args.snapshot or []
                provenance = {"kind": "local-snapshots" if snapshots else "git-seeds"}
            restore(args.destination, snapshots, provenance)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        print(f"fuzz corpus error: {error}", file=sys.stderr)
        sys.exit(1)
