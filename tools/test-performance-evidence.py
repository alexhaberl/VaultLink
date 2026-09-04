#!/usr/bin/env python3
"""Dependency-free contract tests for performance-evidence validation."""

from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "performance_evidence", ROOT / "tools/check-performance-evidence.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def metrics(frames: float = 1_000.0) -> dict[str, float]:
    values = {name: 0.1 for name in MODULE.REQUIRED_METRICS}
    values.update(
        {
            "range_throughput_median_bps": 100_000_000.0,
            "zip_1gib_native_ttfb_p95_seconds": 1.0,
            "zip_1gib_cifs_ttfb_p95_seconds": 2.0,
            "directory_10_page_scan_count": 1.0,
            "startup_secret_rss_delta_bytes": 8 * 1024 * 1024,
            "rss_peak_bytes": 128 * 1024 * 1024,
            "stream_frames_1gib": frames,
            "zip_plan_peak_bytes": 8 * 1024 * 1024,
            "share_decryptions_per_100": 100.0,
            "audit_temp_btree_count": 0.0,
        }
    )
    return values


def write_runs(
    directory: Path,
    kind: str,
    frames: float,
    overrides: dict[str, float] | None = None,
) -> list[Path]:
    paths = []
    for index in range(1, 6):
        path = directory / f"{kind}-{index}.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "commit": MODULE.BASELINE_COMMIT if kind == "baseline" else "b" * 40,
                    "runner": {
                        "id": "runner-0.7",
                        "image": "sha256:" + "c" * 64,
                        "cpu_model": "pinned-test-cpu",
                        "cpu_set": "0-3",
                        "memory_bytes": 8 * 1024 * 1024 * 1024,
                        "storage": "native+cifs-fixture-v1",
                    },
                    "run_index": index,
                    "metrics": {**metrics(frames), **(overrides or {})},
                }
            ),
            encoding="utf-8",
        )
        paths.append(path)
    return paths


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        baseline = MODULE.aggregate("baseline", write_runs(directory, "baseline", 1_000.0))
        candidate = MODULE.aggregate("candidate", write_runs(directory, "candidate", 100.0))
        baseline_path = directory / "baseline.json"
        candidate_path = directory / "candidate.json"
        baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        assert MODULE.compare(baseline_path, candidate_path)["passed"]

        candidate["aggregates"]["range_ttfb_p95_seconds"]["p95"] = 3.0
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        try:
            MODULE.compare(baseline_path, candidate_path)
        except MODULE.EvidenceError as error:
            assert "does not match its five hashed source runs" in str(error)
        else:
            raise AssertionError("hand-edited aggregate was accepted")

        strict_runs = write_runs(
            directory,
            "candidate-strict-boundary",
            100.0,
            {"range_ttfb_p95_seconds": 2.0},
        )
        strict_candidate = MODULE.aggregate("candidate", strict_runs)
        strict_candidate_path = directory / "candidate-strict-boundary.json"
        strict_candidate_path.write_text(json.dumps(strict_candidate), encoding="utf-8")
        report = MODULE.compare(baseline_path, strict_candidate_path)
        assert not report["passed"]
        assert any(
            "range_ttfb_p95_seconds" in failure and "must be below" in failure
            for failure in report["failures"]
        )

        inclusive_runs = write_runs(
            directory,
            "candidate-inclusive-boundary",
            100.0,
            {"rss_peak_bytes": 256 * 1024 * 1024},
        )
        inclusive_candidate = MODULE.aggregate("candidate", inclusive_runs)
        inclusive_candidate_path = directory / "candidate-inclusive-boundary.json"
        inclusive_candidate_path.write_text(json.dumps(inclusive_candidate), encoding="utf-8")
        report = MODULE.compare(baseline_path, inclusive_candidate_path)
        assert not any(
            "rss_peak_bytes" in failure and "absolute ceiling" in failure
            for failure in report["failures"]
        )

        candidate = MODULE.aggregate(
            "candidate", write_runs(directory, "candidate-hash", 100.0)
        )
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        source_path = directory / candidate["sources"][0]["path"]
        source_path.write_text("{}", encoding="utf-8")
        try:
            MODULE.compare(baseline_path, candidate_path)
        except MODULE.EvidenceError as error:
            assert "SHA-256 does not match" in str(error)
        else:
            raise AssertionError("aggregate with a modified source run was accepted")

        duplicate_runs = write_runs(directory, "candidate", 100.0)
        duplicate_runs[-1] = duplicate_runs[0]
        try:
            MODULE.aggregate("candidate", duplicate_runs)
        except MODULE.EvidenceError:
            pass
        else:
            raise AssertionError("duplicate performance runs were accepted")

    print("performance evidence tests passed")


if __name__ == "__main__":
    main()
