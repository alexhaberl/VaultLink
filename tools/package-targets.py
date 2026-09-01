#!/usr/bin/env python3
"""Validate and query VaultLink's release package target lock."""

import argparse
import datetime
import json
import re
import sys
from pathlib import Path


MANIFEST = Path("release/package-targets.json")
QEMU_RUNNER_LOCK = Path("deploy/docker/qemu-runner-image.lock")
QEMU_RUNNER_BASE_LOCK = Path("deploy/docker/qemu-runner-base-image.lock")
QEMU_RUNNER_PACKAGE_LOCKS = {
    "amd64": Path("deploy/docker/qemu-runner-packages-amd64.lock"),
    "arm64": Path("deploy/docker/qemu-runner-packages-arm64.lock"),
}
IMAGE = re.compile(r"^ghcr\.io/alexhaberl/[a-z0-9-]+@sha256:[0-9a-f]{64}$")
QEMU_RUNNER_IMAGE = re.compile(
    r"^ghcr\.io/alexhaberl/vaultlink-qemu-runner@sha256:[0-9a-f]{64}$"
)
BASE_IMAGE = re.compile(r"^[a-z0-9.-]+(?:/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DEBIAN_PACKAGE_RECORD = re.compile(
    r"^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?="
    r"[A-Za-z0-9][A-Za-z0-9.+:~_-]*$"
)
ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
ASSET = re.compile(r"^[A-Za-z0-9._+{}-]+$")
EXPECTED = {
    "debian13-amd64": ("debian", "13", "amd64", "ubuntu-24.04", "deb", "amd64"),
    "debian13-arm64": ("debian", "13", "arm64", "ubuntu-24.04-arm", "deb", "arm64"),
    "ubuntu2404-amd64": ("ubuntu", "24.04", "amd64", "ubuntu-24.04", "deb", "amd64"),
    "ubuntu2404-arm64": ("ubuntu", "24.04", "arm64", "ubuntu-24.04-arm", "deb", "arm64"),
    "ubuntu2604-amd64": ("ubuntu", "26.04", "amd64", "ubuntu-24.04", "deb", "amd64"),
    "ubuntu2604-arm64": ("ubuntu", "26.04", "arm64", "ubuntu-24.04-arm", "deb", "arm64"),
    "fedora44-amd64": ("fedora", "44", "amd64", "ubuntu-24.04", "rpm", "x86_64"),
    "fedora44-arm64": ("fedora", "44", "arm64", "ubuntu-24.04-arm", "rpm", "aarch64"),
    "archlinux-amd64": ("arch", "rolling", "amd64", "ubuntu-24.04", "pkg.tar.zst", "x86_64"),
}
EXPECTED_ASSETS = {
    "debian13-amd64": "vaultlink_{version}-1+deb13_amd64.deb",
    "debian13-arm64": "vaultlink_{version}-1+deb13_arm64.deb",
    "ubuntu2404-amd64": "vaultlink_{version}-1+ubuntu24.04_amd64.deb",
    "ubuntu2404-arm64": "vaultlink_{version}-1+ubuntu24.04_arm64.deb",
    "ubuntu2604-amd64": "vaultlink_{version}-1+ubuntu26.04_amd64.deb",
    "ubuntu2604-arm64": "vaultlink_{version}-1+ubuntu26.04_arm64.deb",
    "fedora44-amd64": "vaultlink-{version}-1.fc44.x86_64.rpm",
    "fedora44-arm64": "vaultlink-{version}-1.fc44.aarch64.rpm",
    "archlinux-amd64": "vaultlink-{version}-1-x86_64.pkg.tar.zst",
}
EXPECTED_BUILDERS = {
    "debian13-amd64": "ghcr.io/alexhaberl/vaultlink-package-builder-debian13",
    "debian13-arm64": "ghcr.io/alexhaberl/vaultlink-package-builder-debian13",
    "ubuntu2404-amd64": "ghcr.io/alexhaberl/vaultlink-package-builder-ubuntu2404",
    "ubuntu2404-arm64": "ghcr.io/alexhaberl/vaultlink-package-builder-ubuntu2404",
    "ubuntu2604-amd64": "ghcr.io/alexhaberl/vaultlink-package-builder-ubuntu2604",
    "ubuntu2604-arm64": "ghcr.io/alexhaberl/vaultlink-package-builder-ubuntu2604",
    "fedora44-amd64": "ghcr.io/alexhaberl/vaultlink-package-builder-fedora44",
    "fedora44-arm64": "ghcr.io/alexhaberl/vaultlink-package-builder-fedora44",
    "archlinux-amd64": "ghcr.io/alexhaberl/vaultlink-package-builder-archlinux",
}
MULTIARCH_BUILDERS = (
    ("debian13-amd64", "debian13-arm64"),
    ("ubuntu2404-amd64", "ubuntu2404-arm64"),
    ("ubuntu2604-amd64", "ubuntu2604-arm64"),
    ("fedora44-amd64", "fedora44-arm64"),
)
FIELDS = {
    "id",
    "distribution",
    "version",
    "snapshot_date",
    "snapshot_source",
    "architecture",
    "runner",
    "uname",
    "rust_host",
    "package_format",
    "package_arch",
    "asset_name",
    "builder_repository",
    "builder_image",
    "builder_base_image",
    "builder_packages_sha256",
    "vm_repository",
    "vm_image",
    "vm_upstream_url",
    "vm_upstream_sha256",
    "vm_packages_sha256",
}


def die(message: str) -> None:
    raise SystemExit(f"package target manifest: {message}")


def read_manifest() -> dict:
    try:
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        die(str(error))
    if set(data) != {"schema", "targets"} or data["schema"] != 1:
        die("expected exactly schema=1 and targets")
    if not isinstance(data["targets"], list):
        die("targets must be an array")
    return data


def read_single_line_lock(path: Path, label: str) -> str:
    if not path.is_file() or path.is_symlink():
        die(f"{label} is missing or unsafe: {path}")
    try:
        raw = path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as error:
        die(f"cannot read {label}: {error}")
    lines = raw.splitlines()
    if len(lines) != 1 or raw != lines[0] + "\n":
        die(f"{label} must contain exactly one newline-terminated line")
    return lines[0]


def read_qemu_package_lock(path: Path, architecture: str) -> bool:
    if not path.is_file() or path.is_symlink():
        die(f"QEMU runner {architecture} package lock is missing or unsafe: {path}")
    try:
        raw = path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as error:
        die(f"cannot read QEMU runner {architecture} package lock: {error}")
    lines = raw.splitlines()
    if raw != "\n".join(lines) + "\n" or not lines:
        die(f"QEMU runner {architecture} package lock is not canonical")
    if lines == ["UNPROVISIONED"]:
        return False
    if any(not DEBIAN_PACKAGE_RECORD.fullmatch(line) for line in lines):
        die(f"QEMU runner {architecture} package lock has an invalid record")
    if lines != sorted(lines) or len(lines) != len(set(lines)):
        die(f"QEMU runner {architecture} package lock must be sorted and unique")
    return True


def validate_qemu_runner_lock(allow_unprovisioned: bool) -> bool:
    image = read_single_line_lock(QEMU_RUNNER_LOCK, "QEMU runner image lock")
    base = read_single_line_lock(QEMU_RUNNER_BASE_LOCK, "QEMU runner base-image lock")
    image_provisioned = image != "UNPROVISIONED"
    base_provisioned = base != "UNPROVISIONED"
    package_states = {
        architecture: read_qemu_package_lock(path, architecture)
        for architecture, path in QEMU_RUNNER_PACKAGE_LOCKS.items()
    }
    states = [image_provisioned, base_provisioned, *package_states.values()]
    if any(states) and not all(states):
        die("QEMU runner image, base, and both package closures must be pinned atomically")
    if not all(states):
        if not allow_unprovisioned:
            die("QEMU runner supply-chain locks are UNPROVISIONED")
        return False
    if not QEMU_RUNNER_IMAGE.fullmatch(image):
        die("QEMU runner lock is not an immutable project GHCR digest")
    if not BASE_IMAGE.fullmatch(base):
        die("QEMU runner base-image lock is not an immutable image digest")
    return True


def validate(allow_unprovisioned: bool) -> dict:
    qemu_runner_provisioned = validate_qemu_runner_lock(allow_unprovisioned)
    data = read_manifest()
    targets = data["targets"]
    ids = [target.get("id") for target in targets if isinstance(target, dict)]
    if ids != list(EXPECTED) or len(ids) != len(EXPECTED):
        die("targets must contain the nine expected IDs in release order")
    assets = set()
    image_states = {"builder": [], "vm": []}
    for target in targets:
        target_id = target["id"]
        if set(target) != FIELDS or not ID.fullmatch(target_id):
            die(f"{target_id!r} has an invalid field set or ID")
        expected = EXPECTED[target_id]
        actual = tuple(target[field] for field in (
            "distribution", "version", "architecture", "runner", "package_format", "package_arch"
        ))
        if actual != expected:
            die(f"{target_id} does not match its fixed distro/runner/package tuple")
        snapshot_date = target["snapshot_date"]
        snapshot_source = target["snapshot_source"]
        if target["distribution"] == "arch":
            if snapshot_source != "https://archive.archlinux.org/repos/{year}/{month}/{day}/$repo/os/$arch":
                die(f"{target_id} has an invalid Arch snapshot source")
            if snapshot_date == "UNPROVISIONED":
                if not allow_unprovisioned:
                    die(f"{target_id} snapshot date is UNPROVISIONED")
            else:
                try:
                    parsed_snapshot = datetime.date.fromisoformat(snapshot_date)
                except (TypeError, ValueError):
                    die(f"{target_id} has an invalid snapshot date")
                if parsed_snapshot.isoformat() != snapshot_date or parsed_snapshot.year < 2020:
                    die(f"{target_id} has an invalid snapshot date")
        elif snapshot_date is not None or snapshot_source is not None:
            die(f"{target_id} must not define rolling snapshot data")
        expected_uname = "x86_64" if target["architecture"] == "amd64" else "aarch64"
        expected_host = f"{expected_uname}-unknown-linux-gnu"
        if target["uname"] != expected_uname or target["rust_host"] != expected_host:
            die(f"{target_id} has an invalid native architecture binding")
        asset = target["asset_name"]
        if (
            asset != EXPECTED_ASSETS[target_id]
            or not ASSET.fullmatch(asset)
            or asset.count("{version}") != 1
            or asset in assets
        ):
            die(f"{target_id} has an invalid or duplicate asset name")
        assets.add(asset)
        for kind in ("builder", "vm"):
            repository = target[f"{kind}_repository"]
            image = target[f"{kind}_image"]
            image_provisioned = image != "UNPROVISIONED"
            image_states[kind].append(image_provisioned)
            expected_prefix = repository + "@sha256:"
            expected_repository = (
                EXPECTED_BUILDERS[target_id]
                if kind == "builder"
                else f"ghcr.io/alexhaberl/vaultlink-distro-vm-{target_id}"
            )
            if not re.fullmatch(r"ghcr\.io/alexhaberl/[a-z0-9-]+", repository):
                die(f"{target_id} has an invalid {kind} repository")
            if repository != expected_repository:
                die(f"{target_id} has an unexpected {kind} repository")
            if not image_provisioned:
                if not allow_unprovisioned:
                    die(f"{target_id} {kind} image is UNPROVISIONED")
            elif not IMAGE.fullmatch(image) or not image.startswith(expected_prefix):
                die(f"{target_id} has an invalid {kind} image lock")
        builder_base = target["builder_base_image"]
        package_hash = target["builder_packages_sha256"]
        builder_input_states = [
            builder_base != "UNPROVISIONED",
            package_hash != "UNPROVISIONED",
        ]
        if any(builder_input_states) and not all(builder_input_states):
            die(f"{target_id} builder base and package closure must be pinned atomically")
        if not all(builder_input_states):
            if not allow_unprovisioned:
                die(f"{target_id} builder inputs are UNPROVISIONED")
        elif not BASE_IMAGE.fullmatch(builder_base) or not SHA256.fullmatch(package_hash):
            die(f"{target_id} has invalid builder base/package locks")
        if target["builder_image"] != "UNPROVISIONED" and not all(builder_input_states):
            die(f"{target_id} has a pinned builder image without pinned inputs")
        upstream_url = target["vm_upstream_url"]
        upstream_hash = target["vm_upstream_sha256"]
        vm_packages_hash = target["vm_packages_sha256"]
        vm_input_states = [
            upstream_url != "UNPROVISIONED",
            upstream_hash != "UNPROVISIONED",
            vm_packages_hash != "UNPROVISIONED",
        ]
        if any(vm_input_states) and not all(vm_input_states):
            die(f"{target_id} VM upstream and package closure must be pinned atomically")
        if not all(vm_input_states):
            if not allow_unprovisioned:
                die(f"{target_id} VM upstream is UNPROVISIONED")
        elif (
            not re.fullmatch(r"https://[A-Za-z0-9._~:/%+-]+", upstream_url)
            or not SHA256.fullmatch(upstream_hash)
            or not SHA256.fullmatch(vm_packages_hash)
        ):
            die(f"{target_id} has an invalid VM upstream lock")
        if target["vm_image"] != "UNPROVISIONED" and not all(vm_input_states):
            die(f"{target_id} has a pinned VM image without pinned inputs")
        if (
            target["distribution"] == "arch"
            and target["snapshot_date"] == "UNPROVISIONED"
            and (
                target["builder_image"] != "UNPROVISIONED"
                or target["vm_image"] != "UNPROVISIONED"
            )
        ):
            die(f"{target_id} has a pinned image without a pinned Arch snapshot")
    for kind, states in image_states.items():
        if any(states) and not all(states):
            die(
                f"{kind} image locks must be pinned or UNPROVISIONED "
                "for all nine targets atomically"
            )
    if any(image_states["vm"]) and not qemu_runner_provisioned:
        die("pinned VM images require pinned QEMU runner supply-chain locks")
    targets_by_id = {target["id"]: target for target in targets}
    for first_id, second_id in MULTIARCH_BUILDERS:
        first = targets_by_id[first_id]
        second = targets_by_id[second_id]
        for field in ("builder_image", "builder_base_image"):
            if first[field] != second[field]:
                die(
                    f"{first_id} and {second_id} must share one multiarch {field} digest"
                )
    return data


def target_by_id(data: dict, target_id: str) -> dict:
    for target in data["targets"]:
        if target["id"] == target_id:
            return target
    die(f"unknown target {target_id!r}")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--allow-unprovisioned", action="store_true")
    matrix_parser = subparsers.add_parser("matrix")
    matrix_parser.add_argument("--allow-unprovisioned", action="store_true")
    matrix_parser.add_argument("--architecture", choices=("amd64", "arm64"))
    get_parser = subparsers.add_parser("get")
    get_parser.add_argument("target")
    get_parser.add_argument("field", choices=sorted(FIELDS))
    get_parser.add_argument("--allow-unprovisioned", action="store_true")
    asset_parser = subparsers.add_parser("asset")
    asset_parser.add_argument("target")
    asset_parser.add_argument("version")
    asset_parser.add_argument("--allow-unprovisioned", action="store_true")
    assets_parser = subparsers.add_parser("assets")
    assets_parser.add_argument("version")
    assets_parser.add_argument("--allow-unprovisioned", action="store_true")
    ids_parser = subparsers.add_parser("ids")
    ids_parser.add_argument("--allow-unprovisioned", action="store_true")
    records_parser = subparsers.add_parser("records")
    records_parser.add_argument("version")
    records_parser.add_argument("--allow-unprovisioned", action="store_true")
    arguments = parser.parse_args()
    allow = getattr(arguments, "allow_unprovisioned", False)
    data = validate(allow)
    if arguments.command == "validate":
        print("package target manifest and QEMU runner lock: OK")
    elif arguments.command == "matrix":
        targets = data["targets"]
        if arguments.architecture:
            targets = [target for target in targets if target["architecture"] == arguments.architecture]
        print(json.dumps({"include": targets}, separators=(",", ":"), sort_keys=True))
    elif arguments.command == "get":
        value = target_by_id(data, arguments.target)[arguments.field]
        print(value)
    elif arguments.command == "asset":
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", arguments.version):
            die("version must be strict MAJOR.MINOR.PATCH")
        print(target_by_id(data, arguments.target)["asset_name"].replace("{version}", arguments.version))
    elif arguments.command == "assets":
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", arguments.version):
            die("version must be strict MAJOR.MINOR.PATCH")
        for target in data["targets"]:
            print(target["asset_name"].replace("{version}", arguments.version))
    elif arguments.command == "ids":
        for target in data["targets"]:
            print(target["id"])
    elif arguments.command == "records":
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", arguments.version):
            die("version must be strict MAJOR.MINOR.PATCH")
        for target in data["targets"]:
            asset = target["asset_name"].replace("{version}", arguments.version)
            print(f"{target['id']}\t{asset}")


if __name__ == "__main__":
    main()
