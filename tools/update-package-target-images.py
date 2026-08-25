#!/usr/bin/env python3
"""Render a reviewed package-target lock update from target/ref pairs."""

import argparse
import importlib.util
import json
import re
from pathlib import Path


spec = importlib.util.spec_from_file_location(
    "package_targets", Path(__file__).with_name("package-targets.py")
)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load package-targets.py")
package_targets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package_targets)


IMAGE = re.compile(r"^ghcr\.io/alexhaberl/[a-z0-9-]+@sha256:[0-9a-f]{64}$")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=("builder", "vm"))
    parser.add_argument("mapping", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--input",
        type=Path,
        default=package_targets.MANIFEST,
        help="validated target manifest to update (defaults to release/package-targets.json)",
    )
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()

    if not args.mapping.is_file() or args.mapping.is_symlink():
        package_targets.die(f"mapping is missing or unsafe: {args.mapping}")
    if not args.input.is_file() or args.input.is_symlink():
        package_targets.die(f"input manifest is missing or unsafe: {args.input}")
    original_manifest = package_targets.MANIFEST
    package_targets.MANIFEST = args.input
    try:
        data = package_targets.validate(True)
    finally:
        package_targets.MANIFEST = original_manifest
    targets = {target["id"]: target for target in data["targets"]}
    seen = set()
    for raw_line in args.mapping.read_text(encoding="utf-8").splitlines():
        if not raw_line or raw_line.startswith("#"):
            continue
        fields = raw_line.split("\t")
        expected_fields = 5 if args.kind == "builder" else 6
        if len(fields) != expected_fields:
            package_targets.die(
                "image mapping must contain TARGET_ID, image, immutable source, source hash, and target lock"
            )
        target_id, image, source, source_hash, target_lock, *extra = fields
        if target_id in seen or target_id not in targets:
            package_targets.die(f"duplicate or unknown mapped target {target_id!r}")
        repository = targets[target_id][f"{args.kind}_repository"]
        if not IMAGE.fullmatch(image) or not image.startswith(repository + "@sha256:"):
            package_targets.die(f"mapped image does not match {target_id} {args.kind} repository")
        targets[target_id][f"{args.kind}_image"] = image
        if args.kind == "builder":
            if not package_targets.BASE_IMAGE.fullmatch(source):
                package_targets.die(f"invalid builder base for {target_id}")
            targets[target_id]["builder_base_image"] = source
            targets[target_id]["builder_packages_sha256"] = source_hash
            if targets[target_id]["distribution"] == "arch":
                if not re.fullmatch(r"20[0-9]{2}-[01][0-9]-[0-3][0-9]", target_lock):
                    package_targets.die("Arch builder mapping needs a snapshot date")
                existing_snapshot = targets[target_id]["snapshot_date"]
                if existing_snapshot not in ("UNPROVISIONED", target_lock):
                    package_targets.die("Arch builder and VM snapshot dates differ")
                targets[target_id]["snapshot_date"] = target_lock
            elif target_lock != "UNPROVISIONED":
                package_targets.die(f"fixed target {target_id} received a snapshot date")
        else:
            if not re.fullmatch(r"https://[A-Za-z0-9._~:/%+-]+", source):
                package_targets.die(f"invalid VM source URL for {target_id}")
            targets[target_id]["vm_upstream_url"] = source
            targets[target_id]["vm_upstream_sha256"] = source_hash
            targets[target_id]["vm_packages_sha256"] = target_lock
            snapshot_lock = extra[0]
            if targets[target_id]["distribution"] == "arch":
                if not re.fullmatch(r"20[0-9]{2}-[01][0-9]-[0-3][0-9]", snapshot_lock):
                    package_targets.die("Arch VM mapping needs a snapshot date")
                existing_snapshot = targets[target_id]["snapshot_date"]
                if existing_snapshot not in ("UNPROVISIONED", snapshot_lock):
                    package_targets.die("Arch VM and builder snapshot dates differ")
                targets[target_id]["snapshot_date"] = snapshot_lock
            elif snapshot_lock != "UNPROVISIONED":
                package_targets.die(f"fixed VM target {target_id} received a snapshot date")
        if not package_targets.SHA256.fullmatch(source_hash):
            package_targets.die(f"invalid source hash for {target_id}")
        seen.add(target_id)
    if not seen:
        package_targets.die("image mapping is empty")

    if args.require_complete and seen != set(targets):
        package_targets.die("complete pinning requires mappings for all nine targets")
    rendered = json.dumps(data, indent=2, ensure_ascii=True) + "\n"
    if args.require_complete and "UNPROVISIONED" in rendered:
        package_targets.die("final image-lock output remains UNPROVISIONED")

    candidate = args.output.with_name(args.output.name + ".candidate")
    if candidate.exists() or candidate.is_symlink():
        package_targets.die(f"refusing to overwrite staging path: {candidate}")
    candidate.write_text(rendered, encoding="utf-8")
    package_targets.MANIFEST = candidate
    try:
        package_targets.validate(not args.require_complete)
    except BaseException:
        candidate.unlink(missing_ok=True)
        raise
    finally:
        package_targets.MANIFEST = original_manifest
    candidate.replace(args.output)


if __name__ == "__main__":
    main()
