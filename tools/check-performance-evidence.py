#!/usr/bin/env python3
"""Aggregate and compare five pinned-runner VaultLink performance profiles."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import tempfile
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
RUN_COUNT = 5
BASELINE_COMMIT = "a390dd9a2210a2e227655a562c541b2b4ebd493c"
REQUIRED_RUNNER_FIELDS = {"id", "image", "cpu_model", "cpu_set", "memory_bytes", "storage"}
REQUIRED_METRICS = {
    "http_metadata_p95_seconds",
    "range_ttfb_p95_seconds",
    "range_throughput_median_bps",
    "range_duration_p95_seconds",
    "zip_1gib_native_ttfb_p95_seconds",
    "zip_1gib_cifs_ttfb_p95_seconds",
    "directory_10_page_scan_count",
    "sqlite_read_p95_seconds",
    "sqlite_integrity_seconds",
    "db_overload_p95_seconds",
    "startup_seconds",
    "startup_secret_rss_delta_bytes",
    "rss_peak_bytes",
    "stream_frames_1gib",
    "zip_plan_peak_bytes",
    "share_search_100k_p95_seconds",
    "share_decryptions_per_100",
    "audit_page_100k_p95_seconds",
    "audit_temp_btree_count",
}

# Absolute release gates. Values are checked against the worst of the five runs
# (nearest-rank p95), except throughput which has only a relative floor.
# `lt` reflects the plan's strict "<" gates; `le` reflects "at most" or
# "within" gates. Keeping the comparator next to the value prevents an exact
# boundary from silently changing release semantics.
ABSOLUTE_LIMITS = {
    "http_metadata_p95_seconds": (2.0, "lt"),
    "range_ttfb_p95_seconds": (2.0, "lt"),
    "zip_1gib_native_ttfb_p95_seconds": (2.0, "lt"),
    "zip_1gib_cifs_ttfb_p95_seconds": (5.0, "lt"),
    "directory_10_page_scan_count": (1.0, "le"),
    "db_overload_p95_seconds": (1.1, "le"),
    "startup_secret_rss_delta_bytes": (16 * 1024 * 1024, "le"),
    "rss_peak_bytes": (256 * 1024 * 1024, "le"),
    "zip_plan_peak_bytes": (16 * 1024 * 1024, "le"),
    "share_search_100k_p95_seconds": (0.250, "lt"),
    "share_decryptions_per_100": (101.0, "le"),
    "audit_page_100k_p95_seconds": (0.250, "lt"),
    "audit_temp_btree_count": (0.0, "le"),
}

THROUGHPUT_METRIC = "range_throughput_median_bps"
RSS_METRICS = {"rss_peak_bytes", "startup_secret_rss_delta_bytes"}
FRAME_METRIC = "stream_frames_1gib"


class EvidenceError(ValueError):
    pass


def _read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise EvidenceError(f"{path}: invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"{path}: root must be an object")
    return value, raw


def _commit(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 40 or any(c not in "0123456789abcdef" for c in value):
        raise EvidenceError(f"{label}: commit must be a lowercase 40-character SHA-1")
    return value


def _runner(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label}: runner must be an object")
    missing = REQUIRED_RUNNER_FIELDS - value.keys()
    if missing:
        raise EvidenceError(f"{label}: runner misses {', '.join(sorted(missing))}")
    if not all(isinstance(value[field], str) and value[field] for field in REQUIRED_RUNNER_FIELDS - {"memory_bytes"}):
        raise EvidenceError(f"{label}: runner string fields must be non-empty")
    memory = value.get("memory_bytes")
    if not isinstance(memory, int) or isinstance(memory, bool) or memory < 8 * 1024 * 1024 * 1024:
        raise EvidenceError(f"{label}: runner memory_bytes must prove at least 8 GiB")
    return value


def _metrics(value: Any, label: str) -> dict[str, float]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label}: metrics must be an object")
    missing = REQUIRED_METRICS - value.keys()
    extra = value.keys() - REQUIRED_METRICS
    if missing or extra:
        raise EvidenceError(
            f"{label}: metric set mismatch; missing={sorted(missing)}, extra={sorted(extra)}"
        )
    checked: dict[str, float] = {}
    for name, raw in value.items():
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise EvidenceError(f"{label}: metric {name} must be numeric")
        number = float(raw)
        if not math.isfinite(number) or number < 0:
            raise EvidenceError(f"{label}: metric {name} must be finite and non-negative")
        checked[name] = number
    return checked


def _nearest_rank(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def aggregate(kind: str, paths: list[Path]) -> dict[str, Any]:
    if kind not in {"baseline", "candidate"}:
        raise EvidenceError("kind must be baseline or candidate")
    if len(paths) != RUN_COUNT or len(set(paths)) != RUN_COUNT:
        raise EvidenceError("exactly five distinct run files are required")

    parsed: list[tuple[dict[str, Any], bytes, Path]] = []
    for path in paths:
        value, raw = _read_json(path)
        if value.get("schema_version") != SCHEMA_VERSION:
            raise EvidenceError(f"{path}: unsupported schema_version")
        parsed.append((value, raw, path))

    commit = _commit(parsed[0][0].get("commit"), str(parsed[0][2]))
    if kind == "baseline" and commit != BASELINE_COMMIT:
        raise EvidenceError(f"baseline commit must be {BASELINE_COMMIT}")
    runner = _runner(parsed[0][0].get("runner"), str(parsed[0][2]))
    indexes: set[int] = set()
    observations = {name: [] for name in REQUIRED_METRICS}
    sources = []
    for value, raw, path in parsed:
        if _commit(value.get("commit"), str(path)) != commit:
            raise EvidenceError("all five runs must use the same commit")
        if _runner(value.get("runner"), str(path)) != runner:
            raise EvidenceError("all five runs must use byte-equivalent runner metadata")
        index = value.get("run_index")
        if not isinstance(index, int) or isinstance(index, bool) or not 1 <= index <= RUN_COUNT:
            raise EvidenceError(f"{path}: run_index must be between 1 and 5")
        indexes.add(index)
        metrics = _metrics(value.get("metrics"), str(path))
        for name, number in metrics.items():
            observations[name].append(number)
        sources.append({"path": path.name, "sha256": hashlib.sha256(raw).hexdigest()})
    if indexes != set(range(1, RUN_COUNT + 1)):
        raise EvidenceError("run_index values must be exactly 1,2,3,4,5")

    aggregates = {}
    for name in sorted(REQUIRED_METRICS):
        values = observations[name]
        aggregates[name] = {
            "median": _nearest_rank(values, 0.5),
            "p95": _nearest_rank(values, 0.95),
            "min": min(values),
            "max": max(values),
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "commit": commit,
        "runner": runner,
        "run_count": RUN_COUNT,
        "sources": sorted(sources, key=lambda source: source["path"]),
        "aggregates": aggregates,
    }


def _aggregate_file(path: Path, expected_kind: str) -> dict[str, Any]:
    value, _ = _read_json(path)
    if value.get("schema_version") != SCHEMA_VERSION or value.get("kind") != expected_kind:
        raise EvidenceError(f"{path}: expected {expected_kind} aggregate schema {SCHEMA_VERSION}")
    _commit(value.get("commit"), str(path))
    _runner(value.get("runner"), str(path))
    if value.get("run_count") != RUN_COUNT:
        raise EvidenceError(f"{path}: run_count must be five")
    sources = value.get("sources")
    if not isinstance(sources, list) or len(sources) != RUN_COUNT:
        raise EvidenceError(f"{path}: sources must contain exactly five run files")
    source_paths: list[Path] = []
    source_names: set[str] = set()
    for source in sources:
        if not isinstance(source, dict) or set(source) != {"path", "sha256"}:
            raise EvidenceError(f"{path}: malformed source record")
        name = source.get("path")
        digest = source.get("sha256")
        if (
            not isinstance(name, str)
            or not name
            or Path(name).name != name
            or "/" in name
            or "\\" in name
            or name in source_names
        ):
            raise EvidenceError(f"{path}: source paths must be unique basenames")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise EvidenceError(f"{path}: source {name} has an invalid SHA-256")
        source_path = path.parent / name
        if not source_path.is_file() or source_path.is_symlink():
            raise EvidenceError(f"{path}: source {name} is missing or not a regular file")
        actual_digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
        if actual_digest != digest:
            raise EvidenceError(f"{path}: source {name} SHA-256 does not match")
        source_names.add(name)
        source_paths.append(source_path)
    aggregates = value.get("aggregates")
    if not isinstance(aggregates, dict) or set(aggregates) != REQUIRED_METRICS:
        raise EvidenceError(f"{path}: aggregate metric set mismatch")
    for name, summary in aggregates.items():
        if not isinstance(summary, dict) or set(summary) != {"median", "p95", "min", "max"}:
            raise EvidenceError(f"{path}: malformed aggregate for {name}")
        _metrics({name: summary["median"], **{key: 0 for key in REQUIRED_METRICS - {name}}}, str(path))
        for field in ("p95", "min", "max"):
            raw = summary[field]
            if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not math.isfinite(float(raw)) or raw < 0:
                raise EvidenceError(f"{path}: invalid {field} for {name}")
    rebuilt = aggregate(expected_kind, source_paths)
    if value != rebuilt:
        raise EvidenceError(f"{path}: aggregate does not match its five hashed source runs")
    return value


def compare(baseline_path: Path, candidate_path: Path) -> dict[str, Any]:
    baseline = _aggregate_file(baseline_path, "baseline")
    candidate = _aggregate_file(candidate_path, "candidate")
    failures: list[str] = []
    if baseline["commit"] != BASELINE_COMMIT:
        failures.append(f"baseline commit is not {BASELINE_COMMIT}")
    if baseline["runner"] != candidate["runner"]:
        failures.append("baseline and candidate runner metadata differ")

    base_metrics = baseline["aggregates"]
    candidate_metrics = candidate["aggregates"]
    for name, (ceiling, comparator) in ABSOLUTE_LIMITS.items():
        observed = float(candidate_metrics[name]["p95"])
        failed = observed >= ceiling if comparator == "lt" else observed > ceiling
        if failed:
            relationship = "must be below" if comparator == "lt" else "exceeds"
            failures.append(
                f"{name}: p95 {observed} {relationship} absolute ceiling {ceiling}"
            )

    for name in sorted(REQUIRED_METRICS - {THROUGHPUT_METRIC, FRAME_METRIC}):
        allowed_regression = 0.05 if name in RSS_METRICS else 0.10
        for field in ("median", "p95"):
            baseline_value = float(base_metrics[name][field])
            candidate_value = float(candidate_metrics[name][field])
            ceiling = baseline_value * (1.0 + allowed_regression)
            if candidate_value > ceiling:
                failures.append(
                    f"{name}: {field} {candidate_value} exceeds relative ceiling {ceiling}"
                )

    baseline_throughput = float(base_metrics[THROUGHPUT_METRIC]["median"])
    candidate_throughput = float(candidate_metrics[THROUGHPUT_METRIC]["median"])
    if candidate_throughput < baseline_throughput * 0.95:
        failures.append("range throughput median regressed by more than five percent")

    baseline_frames = float(base_metrics[FRAME_METRIC]["median"])
    candidate_frames = float(candidate_metrics[FRAME_METRIC]["median"])
    if candidate_frames > baseline_frames * 0.10:
        failures.append("64-KiB streaming did not reduce frame count by at least ninety percent")

    return {
        "schema_version": SCHEMA_VERSION,
        "baseline_commit": baseline["commit"],
        "candidate_commit": candidate["commit"],
        "runner": candidate["runner"],
        "passed": not failures,
        "failures": failures,
    }


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    aggregate_parser = commands.add_parser("aggregate")
    aggregate_parser.add_argument("--kind", choices=("baseline", "candidate"), required=True)
    aggregate_parser.add_argument("--output", type=Path, required=True)
    aggregate_parser.add_argument("runs", nargs=RUN_COUNT, type=Path)
    compare_parser = commands.add_parser("compare")
    compare_parser.add_argument("--baseline", type=Path, required=True)
    compare_parser.add_argument("--candidate", type=Path, required=True)
    compare_parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "aggregate":
            result = aggregate(args.kind, args.runs)
            _write_json(args.output, result)
        else:
            result = compare(args.baseline, args.candidate)
            if args.output:
                _write_json(args.output, result)
            else:
                print(json.dumps(result, indent=2, sort_keys=True))
            if not result["passed"]:
                return 1
    except (EvidenceError, OSError) as error:
        print(f"performance evidence rejected: {error}", file=__import__("sys").stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
