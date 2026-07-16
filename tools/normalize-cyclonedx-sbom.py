#!/usr/bin/env python3
"""Remove volatile optional CycloneDX fields and emit canonical JSON."""

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: normalize-cyclonedx-sbom.py INPUT OUTPUT", file=sys.stderr)
        return 64
    source = Path(sys.argv[1])
    destination = Path(sys.argv[2])
    document = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        print("input is not a CycloneDX JSON document", file=sys.stderr)
        return 65
    document.pop("serialNumber", None)
    metadata = document.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("timestamp", None)
    destination.write_text(
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
