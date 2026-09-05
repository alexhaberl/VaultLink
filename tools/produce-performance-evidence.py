#!/usr/bin/env python3
"""Assemble a verified performance artifact in the protected producer workflow."""

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("evidence", ROOT / "tools/release-evidence.py")
assert SPEC and SPEC.loader
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)
PERF = EVIDENCE.PERF


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", required=True, choices=("baseline", "candidate"))
    parser.add_argument("--commit", required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--packages-run-id", required=True, type=int)
    parser.add_argument("--runs", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        PERF._commit(args.commit, "measurement commit")
        PERF._sha256(args.binary_sha256, "binary digest")
        workflow_sha = PERF._commit(os.environ.get("GITHUB_SHA"), "workflow SHA")
        if os.environ.get("GITHUB_REF") != "refs/heads/main":
            raise PERF.EvidenceError("producer must run from main")
        api = EVIDENCE.GitHub(os.environ.get("GITHUB_REPOSITORY", ""))
        if api.request("git/ref/heads/main")["object"]["sha"] != workflow_sha:
            raise PERF.EvidenceError("producer no longer matches current main")
        if args.commit != (workflow_sha if args.kind == "candidate" else PERF.BASELINE_COMMIT):
            raise PERF.EvidenceError("unexpected measurement commit")
        packages = api.run(args.packages_run_id, args.commit, ".github/workflows/packages.yml")
        candidate_run = None
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            if args.kind == "candidate":
                current_packages = api.gate(args.commit, "vaultlink/packages", ".github/workflows/packages.yml")
                if current_packages["id"] != args.packages_run_id:
                    raise PERF.EvidenceError("packages input differs from current gate")
                candidate = api.gate(args.commit, "vaultlink/release-candidate-preflight",
                                     ".github/workflows/release.yml", "workflow_dispatch",
                                     f"Release candidate {args.commit}")
                candidate_run = candidate["id"]
                api.artifact(candidate, f"vaultlink-release-unsigned-{args.commit}", work / "packages")
                subprocess.run(["sh", "tools/verify-package-release.sh", str(work / "packages"), "0.7.0"],
                               cwd=ROOT, check=True)
            else:
                api.artifact(packages, "vaultlink-package-debian13-amd64", work / "packages")
            debs = list((work / "packages").glob("*.deb"))
            # The final unsigned release contains multiple DEBs; choose the exact target filename.
            asset = subprocess.check_output(["python3", "tools/package-targets.py", "asset",
                                             "debian13-amd64", "0.7.0"], cwd=ROOT, text=True).strip()
            deb = work / "packages" / asset
            if deb not in debs or deb.is_symlink():
                raise PERF.EvidenceError("candidate lacks the expected Debian package")
            subprocess.run(["dpkg-deb", "-x", str(deb), str(work / "binary")], check=True)
            binary = work / "binary/usr/lib/vaultlink/package/vaultlink"
            if not binary.is_file() or binary.is_symlink() or hashlib.sha256(binary.read_bytes()).hexdigest() != args.binary_sha256:
                raise PERF.EvidenceError("measurement binary differs from the package payload")
            expected = {"commit": args.commit, "binary_sha256": args.binary_sha256,
                        "package_target": "debian13-amd64", "packages_run_id": args.packages_run_id,
                        "candidate_preflight_run_id": candidate_run,
                        "producer_sha256": EVIDENCE.producer_digest()}
            EVIDENCE.extract_artifact(args.runs.read_bytes(), work / "runs")
            raw_paths = [work / "runs" / f"run-{index}.json" for index in range(1, 6)]
            if set((work / "runs").iterdir()) != set(raw_paths):
                raise PERF.EvidenceError("collector must export exactly five run files")
            aggregate = PERF.aggregate(args.kind, raw_paths)
            if PERF.identity(aggregate, args.kind) != expected:
                raise PERF.EvidenceError("runs differ from the verified source, binary or producer")
            if args.output.exists():
                raise PERF.EvidenceError("output directory already exists")
            PERF.write_bundle(args.kind, raw_paths, args.output / f"{args.kind}.json")
            if args.kind == "candidate":
                lock = EVIDENCE.baseline_lock()
                baseline_run = api.run(lock["run_id"], lock["workflow_sha"], EVIDENCE.PERFORMANCE_WORKFLOW,
                                       "workflow_dispatch")
                receipt = api.artifact(baseline_run, lock["artifact_name"], work / "baseline")
                for key, value in receipt.items():
                    if lock.get(key) != value:
                        raise PERF.EvidenceError("baseline artifact differs from the reviewed lock")
                baseline = PERF._aggregate_file(work / "baseline/baseline.json", "baseline")
                for name in ["baseline.json", *(source["path"] for source in baseline["sources"])]:
                    shutil.copyfile(work / "baseline" / name, args.output / name)
                result = EVIDENCE.validate_bundle(args.output, expected)
                PERF._write_json(args.output / "comparison.json", result)
            PERF._write_json(args.output / "receipt.json", {
                "schema_version": 1, "kind": args.kind, "identity": expected,
                "workflow_sha": workflow_sha,
                "run_id": EVIDENCE.positive(int(os.environ["GITHUB_RUN_ID"]), "producer run"),
                "run_attempt": EVIDENCE.positive(int(os.environ["GITHUB_RUN_ATTEMPT"]), "producer attempt"),
            })
        return 0
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"performance producer rejected: {error}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
