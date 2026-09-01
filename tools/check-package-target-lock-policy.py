#!/usr/bin/env python3
"""Exercise the package-target bootstrap lock truth table."""

import copy
import importlib.util
import json
import sys
import tempfile
from pathlib import Path


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / "tools/package-targets.py"
spec = importlib.util.spec_from_file_location("package_targets", MODULE_PATH)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load package-targets.py")
package_targets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package_targets)

package_targets.MANIFEST = ROOT / "release/package-targets.json"
package_targets.QEMU_RUNNER_LOCK = ROOT / "deploy/docker/qemu-runner-image.lock"
package_targets.QEMU_RUNNER_BASE_LOCK = ROOT / "deploy/docker/qemu-runner-base-image.lock"
package_targets.QEMU_RUNNER_PACKAGE_LOCKS = {
    "amd64": ROOT / "deploy/docker/qemu-runner-packages-amd64.lock",
    "arm64": ROOT / "deploy/docker/qemu-runner-packages-arm64.lock",
}


def set_image_family(data: dict, kind: str, provisioned: bool) -> None:
    digest = "1" * 64 if kind == "builder" else "2" * 64
    for target in data["targets"]:
        field = f"{kind}_image"
        target[field] = (
            f"{target[f'{kind}_repository']}@sha256:{digest}"
            if provisioned
            else "UNPROVISIONED"
        )


def validate_case(
    data: dict, allow_unprovisioned: bool, qemu_provisioned: bool = True
) -> None:
    original_manifest = package_targets.MANIFEST
    original_qemu_lock = package_targets.QEMU_RUNNER_LOCK
    original_qemu_base_lock = package_targets.QEMU_RUNNER_BASE_LOCK
    original_qemu_package_locks = package_targets.QEMU_RUNNER_PACKAGE_LOCKS
    with tempfile.TemporaryDirectory(prefix="vaultlink-target-policy-") as work:
        work_path = Path(work)
        manifest = work_path / "package-targets.json"
        manifest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        package_targets.MANIFEST = manifest
        if not qemu_provisioned:
            package_targets.QEMU_RUNNER_LOCK = work_path / "qemu-runner-image.lock"
            package_targets.QEMU_RUNNER_BASE_LOCK = work_path / "qemu-runner-base.lock"
            package_targets.QEMU_RUNNER_PACKAGE_LOCKS = {
                architecture: work_path / f"qemu-runner-packages-{architecture}.lock"
                for architecture in ("amd64", "arm64")
            }
            for lock in (
                package_targets.QEMU_RUNNER_LOCK,
                package_targets.QEMU_RUNNER_BASE_LOCK,
                *package_targets.QEMU_RUNNER_PACKAGE_LOCKS.values(),
            ):
                lock.write_text("UNPROVISIONED\n", encoding="ascii")
        try:
            package_targets.validate(allow_unprovisioned)
        finally:
            package_targets.MANIFEST = original_manifest
            package_targets.QEMU_RUNNER_LOCK = original_qemu_lock
            package_targets.QEMU_RUNNER_BASE_LOCK = original_qemu_base_lock
            package_targets.QEMU_RUNNER_PACKAGE_LOCKS = original_qemu_package_locks


def expect_accept(
    label: str,
    data: dict,
    allow_unprovisioned: bool = True,
    qemu_provisioned: bool = True,
) -> None:
    try:
        validate_case(data, allow_unprovisioned, qemu_provisioned)
    except SystemExit as error:
        raise SystemExit(f"{label} was rejected: {error}") from error


def expect_reject(
    label: str, data: dict, expected: str, qemu_provisioned: bool = True
) -> None:
    try:
        validate_case(data, True, qemu_provisioned)
    except SystemExit as error:
        if expected not in str(error):
            raise SystemExit(f"{label} failed for the wrong reason: {error}") from error
    else:
        raise SystemExit(f"{label} was accepted")


baseline = json.loads(
    (ROOT / "release/package-targets.json").read_text(encoding="utf-8")
)
set_image_family(baseline, "builder", True)
set_image_family(baseline, "vm", True)
expect_accept("fully pinned target lock", baseline, False)

builder_bootstrap = copy.deepcopy(baseline)
set_image_family(builder_bootstrap, "builder", False)
expect_accept("builder-only bootstrap", builder_bootstrap)

vm_bootstrap = copy.deepcopy(baseline)
set_image_family(vm_bootstrap, "vm", False)
expect_accept("VM-only bootstrap", vm_bootstrap)

complete_bootstrap = copy.deepcopy(builder_bootstrap)
set_image_family(complete_bootstrap, "vm", False)
expect_accept("combined builder and VM bootstrap", complete_bootstrap)

expect_reject(
    "pinned VM family without QEMU runner locks",
    builder_bootstrap,
    "pinned VM images require pinned QEMU runner supply-chain locks",
    qemu_provisioned=False,
)
expect_accept(
    "unprovisioned VM family without QEMU runner locks",
    vm_bootstrap,
    qemu_provisioned=False,
)

partial_builder = copy.deepcopy(baseline)
partial_builder["targets"][0]["builder_image"] = "UNPROVISIONED"
expect_reject(
    "partial builder image family",
    partial_builder,
    "builder image locks must be pinned or UNPROVISIONED for all nine targets atomically",
)

partial_vm = copy.deepcopy(baseline)
partial_vm["targets"][0]["vm_image"] = "UNPROVISIONED"
expect_reject(
    "partial VM image family",
    partial_vm,
    "vm image locks must be pinned or UNPROVISIONED for all nine targets atomically",
)

for field in ("builder_base_image", "builder_packages_sha256"):
    mixed_builder_inputs = copy.deepcopy(builder_bootstrap)
    mixed_builder_inputs["targets"][0][field] = "UNPROVISIONED"
    expect_reject(
        f"mixed builder inputs at {field}",
        mixed_builder_inputs,
        "builder base and package closure must be pinned atomically",
    )

for field in ("vm_upstream_url", "vm_upstream_sha256", "vm_packages_sha256"):
    mixed_vm_inputs = copy.deepcopy(vm_bootstrap)
    mixed_vm_inputs["targets"][0][field] = "UNPROVISIONED"
    expect_reject(
        f"mixed VM inputs at {field}",
        mixed_vm_inputs,
        "VM upstream and package closure must be pinned atomically",
    )

pinned_builder_without_inputs = copy.deepcopy(baseline)
pinned_builder_without_inputs["targets"][0]["builder_base_image"] = "UNPROVISIONED"
pinned_builder_without_inputs["targets"][0]["builder_packages_sha256"] = "UNPROVISIONED"
expect_reject(
    "pinned builder without inputs",
    pinned_builder_without_inputs,
    "pinned builder image without pinned inputs",
)

pinned_vm_without_inputs = copy.deepcopy(baseline)
for field in ("vm_upstream_url", "vm_upstream_sha256", "vm_packages_sha256"):
    pinned_vm_without_inputs["targets"][0][field] = "UNPROVISIONED"
expect_reject(
    "pinned VM without inputs",
    pinned_vm_without_inputs,
    "pinned VM image without pinned inputs",
)

arch_index = next(
    index
    for index, target in enumerate(baseline["targets"])
    if target["distribution"] == "arch"
)
for label, data in (
    ("pinned builder and VM", baseline),
    ("pinned VM", builder_bootstrap),
    ("pinned builder", vm_bootstrap),
):
    missing_arch_snapshot = copy.deepcopy(data)
    missing_arch_snapshot["targets"][arch_index]["snapshot_date"] = "UNPROVISIONED"
    expect_reject(
        f"{label} without an Arch snapshot",
        missing_arch_snapshot,
        "pinned image without a pinned Arch snapshot",
    )

unprovisioned_arch_snapshot = copy.deepcopy(complete_bootstrap)
unprovisioned_arch_snapshot["targets"][arch_index]["snapshot_date"] = "UNPROVISIONED"
expect_accept("fully unprovisioned Arch image families and snapshot", unprovisioned_arch_snapshot)

builder_without_inputs = copy.deepcopy(builder_bootstrap)
for target in builder_without_inputs["targets"]:
    target["builder_base_image"] = "UNPROVISIONED"
    target["builder_packages_sha256"] = "UNPROVISIONED"
expect_accept("unprovisioned builders without input tuples", builder_without_inputs)

vm_without_inputs = copy.deepcopy(vm_bootstrap)
for target in vm_without_inputs["targets"]:
    target["vm_upstream_url"] = "UNPROVISIONED"
    target["vm_upstream_sha256"] = "UNPROVISIONED"
    target["vm_packages_sha256"] = "UNPROVISIONED"
expect_accept("unprovisioned VMs without input tuples", vm_without_inputs)

print("package target bootstrap lock policy: OK")
