#!/usr/bin/env python3
"""Verify byte-stable contracts and the logical source of mechanical splits."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any


DEFAULT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = "release/refactoring-contracts-0.7.0.json"


def fail(message: str) -> None:
    raise SystemExit(f"refactoring contracts: {message}")


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {path}: {error}")


def safe_path(root: Path, value: object, *, kind: str = "file") -> Path:
    if not isinstance(value, str) or not value:
        fail("manifest paths must be non-empty strings")
    logical = PurePosixPath(value)
    if (
        logical.is_absolute()
        or "\\" in value
        or ":" in value
        or any(part in ("", ".", "..") for part in logical.parts)
    ):
        fail(f"unsafe manifest path: {value}")
    candidate = root.joinpath(*logical.parts)
    current = root
    for part in logical.parts:
        current = current / part
        if current.is_symlink():
            fail(f"manifest path crosses a symlink: {value}")
    try:
        candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        fail(f"manifest path is missing or outside the repository: {value}")
    if kind == "file" and not candidate.is_file():
        fail(f"manifest path is not a regular file: {value}")
    if kind == "directory" and not candidate.is_dir():
        fail(f"manifest path is not a directory: {value}")
    return candidate


def canonical_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes().replace(b"\r\n", b"\n")
    except OSError as error:
        fail(f"cannot read {path}: {error}")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def expected_digest(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        fail(f"{name} has an invalid SHA-256 digest")
    return value


def exact_objects(value: object, name: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        fail(f"{name} must be a non-empty array")
    if not all(isinstance(entry, dict) for entry in value):
        fail(f"{name} entries must be objects")
    return value


def logical_part(root: Path, specification: object, source_name: str) -> bytes:
    if isinstance(specification, str):
        return canonical_bytes(safe_path(root, specification))
    if not isinstance(specification, dict) or "path" not in specification:
        fail(f"logical source {source_name} has an invalid part")
    if not set(specification).issubset({"path", "strip_prefix", "strip_suffix"}):
        fail(f"logical source {source_name} has an unknown part field")
    data = canonical_bytes(safe_path(root, specification["path"]))
    prefix = specification.get("strip_prefix", "")
    suffix = specification.get("strip_suffix", "")
    if not isinstance(prefix, str) or not isinstance(suffix, str):
        fail(f"logical source {source_name} strip values must be strings")
    prefix_bytes = prefix.encode("utf-8")
    suffix_bytes = suffix.encode("utf-8")
    if prefix_bytes and not data.startswith(prefix_bytes):
        fail(f"logical source {source_name} part prefix no longer matches")
    if suffix_bytes and not data.endswith(suffix_bytes):
        fail(f"logical source {source_name} part suffix no longer matches")
    start = len(prefix_bytes)
    end = len(data) - len(suffix_bytes) if suffix_bytes else len(data)
    return data[start:end]


def verify(root: Path, manifest_path: Path) -> None:
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        fail("manifest schema_version must be 1")
    if manifest.get("release_version") != "0.7.0":
        fail("manifest release_version must be 0.7.0")

    required = manifest.get("required_paths")
    if not isinstance(required, dict) or set(required) != {"files", "directories"}:
        fail("required_paths must contain exactly files and directories")
    for value in required["files"]:
        safe_path(root, value)
    for value in required["directories"]:
        safe_path(root, value, kind="directory")

    seen_files: set[str] = set()
    for entry in exact_objects(manifest.get("locked_files"), "locked_files"):
        if set(entry) != {"path", "sha256", "contract"}:
            fail("locked_files entries must contain path, sha256, and contract")
        path_value = entry["path"]
        if path_value in seen_files:
            fail(f"duplicate locked file: {path_value}")
        seen_files.add(path_value)
        path = safe_path(root, path_value)
        expected = expected_digest(entry["sha256"], str(path_value))
        actual = digest(canonical_bytes(path))
        if actual != expected:
            fail(f"locked contract changed: {path_value}")

    seen_names: set[str] = set()
    for entry in exact_objects(manifest.get("logical_sources"), "logical_sources"):
        if set(entry) != {"name", "parts", "sha256"}:
            fail("logical_sources entries must contain name, parts, and sha256")
        name = entry["name"]
        if not isinstance(name, str) or not name or name in seen_names:
            fail("logical source names must be non-empty and unique")
        seen_names.add(name)
        parts = entry["parts"]
        if not isinstance(parts, list) or not parts:
            fail(f"logical source {name} must contain at least one part")
        source = b"".join(logical_part(root, part, name) for part in parts)
        if digest(source) != expected_digest(entry["sha256"], name):
            fail(f"logical split source changed or was reordered: {name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    arguments = parser.parse_args()
    root = arguments.root.resolve(strict=True)
    manifest_path = Path(arguments.manifest)
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path
    verify(root, manifest_path)
    print("Refactoring contract checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
