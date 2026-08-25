#!/usr/bin/env python3
"""Build and verify VaultLink's deterministic all-target SBOM bundle."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path


STRICT_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PAYLOAD_PATH = "/usr/lib/vaultlink/package/vaultlink"


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"package release bundle: {message}")


def load_target_module():
    module_path = Path(__file__).with_name("package-targets.py")
    spec = importlib.util.spec_from_file_location("vaultlink_package_targets", module_path)
    if spec is None or spec.loader is None:
        fail("cannot load package-targets.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def targets_for_version(version: str) -> list[dict]:
    if not STRICT_VERSION.fullmatch(version):
        fail("version must be strict stable MAJOR.MINOR.PATCH")
    module = load_target_module()
    data = module.validate(False)
    targets = []
    for target in data["targets"]:
        item = dict(target)
        item["resolved_asset"] = target["asset_name"].replace("{version}", version)
        targets.append(item)
    if len(targets) != 9:
        fail("target manifest must resolve exactly nine packages")
    return targets


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def read_normalized_sbom(path: Path, version: str) -> tuple[dict, str]:
    if not path.is_file() or path.is_symlink():
        fail(f"missing or unsafe target SBOM: {path}")
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid target SBOM {path}: {error}")
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        fail(f"target SBOM is not CycloneDX JSON: {path}")
    metadata = document.get("metadata")
    component = metadata.get("component", {}) if isinstance(metadata, dict) else {}
    if not isinstance(component, dict) or component.get("name") != "vaultlink":
        fail(f"target SBOM does not describe VaultLink: {path}")
    if component.get("version") != version:
        fail(f"target SBOM version does not match {version}: {path}")
    normalized = canonical_bytes(document)
    if raw != normalized:
        fail(f"target SBOM is not canonical and normalized: {path}")
    return document, hashlib.sha256(raw).hexdigest()


def read_payload_records(path: Path, targets: list[dict]) -> dict[str, str]:
    records: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        fail(f"cannot read payload records: {error}")
    for line in lines:
        fields = line.split("\t")
        if len(fields) != 2:
            fail("payload records must contain TARGET_ID<TAB>SHA256")
        target_id, payload_sha256 = fields
        if target_id in records or not SHA256.fullmatch(payload_sha256):
            fail(f"duplicate or invalid payload record for {target_id!r}")
        records[target_id] = payload_sha256
    expected = [target["id"] for target in targets]
    if list(records) != expected:
        fail("payload records must contain all nine targets in manifest order")
    return records


def build_bundle(version: str, input_dir: Path, records_path: Path, output: Path) -> None:
    targets = targets_for_version(version)
    payloads = read_payload_records(records_path, targets)
    if output.exists() or output.is_symlink():
        fail(f"refusing to overwrite bundle output: {output}")
    bundle_targets = []
    for target in targets:
        target_id = target["id"]
        asset = target["resolved_asset"]
        package = input_dir / asset
        sbom_path = input_dir / f"{target_id}.cdx.json"
        if not package.is_file() or package.is_symlink():
            fail(f"missing or unsafe package input: {asset}")
        sbom, sbom_sha256 = read_normalized_sbom(sbom_path, version)
        bundle_targets.append(
            {
                "id": target_id,
                "distribution": target["distribution"],
                "distribution_version": target["version"],
                "architecture": target["package_arch"],
                "format": target["package_format"],
                "package": {"asset": asset, "sha256": sha256_file(package)},
                "payload": {"path": PAYLOAD_PATH, "sha256": payloads[target_id]},
                "sbom": {"sha256": sbom_sha256, "cyclonedx": sbom},
            }
        )
    bundle = {
        "schema": "https://github.com/alexhaberl/VaultLink/package-sbom-bundle/v1",
        "version": version,
        "targets": bundle_targets,
    }
    output.write_bytes(canonical_bytes(bundle))


def verify_bundle(version: str, release_dir: Path, bundle_path: Path, materialize: Path | None) -> None:
    targets = targets_for_version(version)
    if not bundle_path.is_file() or bundle_path.is_symlink():
        fail("SBOM bundle is missing or unsafe")
    raw = bundle_path.read_bytes()
    try:
        bundle = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"SBOM bundle is invalid JSON: {error}")
    if raw != canonical_bytes(bundle):
        fail("SBOM bundle is not canonical")
    if not isinstance(bundle, dict) or set(bundle) != {"schema", "version", "targets"}:
        fail("SBOM bundle has an unexpected top-level schema")
    if bundle["schema"] != "https://github.com/alexhaberl/VaultLink/package-sbom-bundle/v1":
        fail("SBOM bundle schema identifier is invalid")
    if bundle["version"] != version or not isinstance(bundle["targets"], list):
        fail("SBOM bundle version or target list is invalid")
    if len(bundle["targets"]) != len(targets):
        fail("SBOM bundle does not contain exactly nine targets")
    if materialize is not None:
        if materialize.exists() or materialize.is_symlink():
            fail("SBOM materialization directory already exists")
        materialize.mkdir(mode=0o700, parents=False)
    for expected, item in zip(targets, bundle["targets"], strict=True):
        if not isinstance(item, dict) or set(item) != {
            "id", "distribution", "distribution_version", "architecture",
            "format", "package", "payload", "sbom"
        }:
            fail("SBOM bundle target schema is invalid")
        expected_scalars = {
            "id": expected["id"],
            "distribution": expected["distribution"],
            "distribution_version": expected["version"],
            "architecture": expected["package_arch"],
            "format": expected["package_format"],
        }
        for key, value in expected_scalars.items():
            if item[key] != value:
                fail(f"SBOM bundle target {expected['id']} has invalid {key}")
        package = item["package"]
        payload = item["payload"]
        sbom = item["sbom"]
        if not isinstance(package, dict) or set(package) != {"asset", "sha256"}:
            fail("SBOM bundle package record is invalid")
        if package["asset"] != expected["resolved_asset"] or not SHA256.fullmatch(package["sha256"]):
            fail(f"SBOM bundle package identity is invalid for {expected['id']}")
        package_path = release_dir / package["asset"]
        if not package_path.is_file() or package_path.is_symlink():
            fail(f"release package is missing or unsafe: {package['asset']}")
        if sha256_file(package_path) != package["sha256"]:
            fail(f"release package hash differs from SBOM bundle: {package['asset']}")
        if not isinstance(payload, dict) or set(payload) != {"path", "sha256"}:
            fail("SBOM bundle payload record is invalid")
        if payload["path"] != PAYLOAD_PATH or not SHA256.fullmatch(payload["sha256"]):
            fail(f"SBOM bundle payload record is invalid for {expected['id']}")
        if not isinstance(sbom, dict) or set(sbom) != {"sha256", "cyclonedx"}:
            fail("SBOM bundle target SBOM record is invalid")
        sbom_bytes = canonical_bytes(sbom["cyclonedx"])
        if not SHA256.fullmatch(sbom["sha256"]) or hashlib.sha256(sbom_bytes).hexdigest() != sbom["sha256"]:
            fail(f"embedded target SBOM hash is invalid for {expected['id']}")
        embedded = sbom["cyclonedx"]
        if not isinstance(embedded, dict):
            fail(f"embedded target SBOM is invalid for {expected['id']}")
        embedded_metadata = embedded.get("metadata")
        component = embedded_metadata.get("component", {}) \
            if isinstance(embedded_metadata, dict) else {}
        if embedded.get("bomFormat") != "CycloneDX" \
                or component.get("name") != "vaultlink" \
                or component.get("version") != version:
            fail(f"embedded target SBOM identity is invalid for {expected['id']}")
        if materialize is not None:
            (materialize / f"{expected['id']}.cdx.json").write_bytes(sbom_bytes)
            (materialize / f"{expected['id']}.payload.sha256").write_text(
                payload["sha256"] + "\n", encoding="ascii"
            )


def print_targets(version: str) -> None:
    for target in targets_for_version(version):
        print(
            "\t".join(
                (target["id"], target["resolved_asset"], target["package_format"])
            )
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    targets_parser = subparsers.add_parser("targets")
    targets_parser.add_argument("version")
    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("version")
    build_parser.add_argument("input_dir", type=Path)
    build_parser.add_argument("payload_records", type=Path)
    build_parser.add_argument("output", type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("version")
    verify_parser.add_argument("release_dir", type=Path)
    verify_parser.add_argument("bundle", type=Path)
    verify_parser.add_argument("--materialize", type=Path)
    args = parser.parse_args()
    if args.command == "targets":
        print_targets(args.version)
    elif args.command == "build":
        build_bundle(args.version, args.input_dir, args.payload_records, args.output)
    elif args.command == "verify":
        verify_bundle(args.version, args.release_dir, args.bundle, args.materialize)


if __name__ == "__main__":
    main()
