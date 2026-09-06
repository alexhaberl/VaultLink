#!/usr/bin/env python3
"""Enforce measured local coverage floors; missing or uninstrumented areas fail."""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "release/module-coverage.json"
MODULES = [
    "src/server/runtime.rs", "src/web/preview_zip.rs", "src/api/public_transfer/zip.rs",
    "src/web/files/preview.rs", "src/services/public_transfer/preview.rs",
    "src/db/shares/listing.rs", "src/share_search.rs", "src/share_summary_cache.rs",
    "src/db/schema/migrations.rs", "src/db/schema/validation.rs",
]


def records(path: Path) -> dict[str, dict[str, int]]:
    files: dict[str, dict[str, int]] = {}
    current = None
    for line in path.read_text().splitlines():
        if line.startswith("SF:"):
            name = line[3:].replace("\\", "/")
            if name in files:
                raise ValueError(f"duplicate LCOV file: {name}")
            current = files[name] = {}
        elif line == "end_of_record":
            current = None
        elif current is not None:
            key, separator, value = line.partition(":")
            if separator and key in {"LF", "LH", "FNF", "FNH"}:
                current[key] = int(value)
    if current is not None:
        raise ValueError("unterminated LCOV record")
    return files


def percentages(files: dict, module: str) -> dict[str, float]:
    matches = [data for name, data in files.items() if name == module or name.endswith("/" + module)]
    if len(matches) != 1:
        raise ValueError(f"{module}: expected one instrumented file, found {len(matches)}")
    result = {}
    for kind, found, hit in [("lines", "LF", "LH"), ("functions", "FNF", "FNH")]:
        total, covered = matches[0].get(found, 0), matches[0].get(hit, 0)
        if total <= 0 or covered <= 0 or covered > total:
            raise ValueError(f"{module}: missing, zero or invalid {kind} coverage")
        # LLVM's summaries account for instantiation groups. Counting FNDA names
        # or deduplicating DA rows produces a different and misleading metric.
        result[kind] = 100 * covered / total
    return result


def verify(path: Path, policy: dict) -> dict:
    if policy.get("schema_version") != 1 or set(policy.get("modules", {})) != set(MODULES):
        raise ValueError("coverage policy must retain every required area")
    files = records(path)
    measured = {module: percentages(files, module) for module in MODULES}
    for module, floors in policy["modules"].items():
        if set(floors) != {"lines", "functions"}:
            raise ValueError(f"{module}: invalid floor fields")
        for kind, floor in floors.items():
            if type(floor) is not int or not 1 <= floor <= 100:
                raise ValueError(f"{module}: invalid {kind} floor")
            if measured[module][kind] < floor:
                raise ValueError(f"{module}: {kind} {measured[module][kind]:.2f}% < {floor}%")
    return measured


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lcov", type=Path)
    parser.add_argument("--record-baseline", action="store_true", help="record floors only after all mandatory scenarios pass")
    args = parser.parse_args()
    if args.record_baseline:
        files = records(args.lcov)
        modules = {module: {kind: math.floor(value) for kind, value in percentages(files, module).items()} for module in MODULES}
        POLICY.write_text(json.dumps({"schema_version": 1, "modules": modules}, indent=2) + "\n")
    result = verify(args.lcov, json.loads(POLICY.read_text()))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
