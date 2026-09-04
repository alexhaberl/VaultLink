#!/usr/bin/env python3
"""Dependency-free negative tests for qualification manifest/evidence policy."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_state", REPOSITORY / "tools/check-release-state.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

CANONICAL = [
    {"id": "CI-001", "title": "CI contract"},
    {"id": "PERF-001", "title": "Performance contract"},
    {"id": "QUAL-001", "title": "Qualification contract"},
    {"id": "REL-001", "title": "Release contract"},
    {"id": "SEC-001", "title": "Security contract"},
]


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def qualification() -> dict[str, object]:
    return {
        "schema_version": 1,
        "release_version": "0.7.0",
        "release_status": "unreleased",
        "allowed_statuses": ["open", "closed", "accepted"],
        "findings": [
            {**finding, "status": "open", "evidence": ["evidence/proof.txt"]}
            for finding in CANONICAL
        ],
    }


def validate(root: Path, value: dict[str, object]) -> list[str]:
    write_json(root / "release/qualification-0.7.0.json", value)
    errors: list[str] = []
    MODULE.validate_qualification("0.7.0", False, errors)
    return errors


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        write_json(
            root / "release/qualification-findings-0.7.0.json",
            {"schema_version": 1, "release_version": "0.7.0", "findings": CANONICAL},
        )
        proof = root / "evidence/proof.txt"
        proof.parent.mkdir(parents=True)
        proof.write_text("immutable fixture", encoding="utf-8")
        original_root = MODULE.ROOT
        MODULE.ROOT = root
        try:
            valid = qualification()
            assert validate(root, valid) == []

            missing = copy.deepcopy(valid)
            missing["findings"].pop()  # type: ignore[union-attr]
            assert any("canonical manifest" in error for error in validate(root, missing))

            renamed = copy.deepcopy(valid)
            renamed["findings"][0]["title"] = "Renamed"  # type: ignore[index]
            assert any("title differs" in error for error in validate(root, renamed))

            stale = copy.deepcopy(valid)
            stale["findings"][0]["evidence"] = ["evidence/missing.txt"]  # type: ignore[index]
            assert any("does not exist" in error for error in validate(root, stale))

            traversal = copy.deepcopy(valid)
            traversal["findings"][0]["evidence"] = ["../outside.txt"]  # type: ignore[index]
            assert any("repository-relative" in error for error in validate(root, traversal))

            credentials = copy.deepcopy(valid)
            credentials["findings"][0]["evidence"] = ["https://token@example.test/run"]  # type: ignore[index]
            assert any("without credentials" in error for error in validate(root, credentials))

            link = root / "evidence/proof-link.txt"
            try:
                link.symlink_to(proof)
            except OSError:
                pass
            else:
                symlinked = copy.deepcopy(valid)
                symlinked["findings"][0]["evidence"] = ["evidence/proof-link.txt"]  # type: ignore[index]
                assert any("symlink" in error for error in validate(root, symlinked))
        finally:
            MODULE.ROOT = original_root

    print("release-state tests passed")


if __name__ == "__main__":
    main()
