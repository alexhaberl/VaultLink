#!/usr/bin/env python3
"""Recognize terminal guest failures; ordinary slow-boot warnings are not fatal."""

import argparse
from pathlib import Path
import re


MAX_LOG_BYTES = 1024 * 1024
ANSI = re.compile(rb"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]")
PREFIX = r"^\s*(?:\[\s*\d+(?:\.\d+)?\]\s*)?"
FAILURES = (
    ("systemd_manager_frozen", re.compile(PREFIX + r"systemd\[1\]: Freezing execution\.\s*$")),
    ("kernel_panic", re.compile(PREFIX + r"Kernel panic - not syncing:")),
)


def classify(log: bytes) -> str:
    # The serial console contains cursor controls and OSC boot notifications.
    # Match complete, recognizable records rather than arbitrary quoted text.
    plain = ANSI.sub(b"", log).decode("utf-8", errors="replace")
    for line in plain.splitlines():
        for reason, pattern in FAILURES:
            if pattern.search(line):
                return reason
    return ""


def classify_file(path: Path) -> str:
    with path.open("rb") as stream:
        size = stream.seek(0, 2)
        stream.seek(max(0, size - MAX_LOG_BYTES))
        # Avoid interpreting a record clipped in the middle as a complete one.
        if size > MAX_LOG_BYTES:
            stream.readline()
        return classify(stream.read(MAX_LOG_BYTES))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("serial_log", type=Path)
    args = parser.parse_args()
    print(classify_file(args.serial_log))


if __name__ == "__main__":
    main()
