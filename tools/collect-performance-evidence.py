#!/usr/bin/env python3
"""Read-only forced SSH export of five root-owned performance measurements."""

import os
from pathlib import Path
import re
import stat
import sys
import zipfile


def collect(command: str, root: Path = Path("/var/lib/vaultlink-performance")) -> list[tuple[str, bytes]]:
    match = re.fullmatch(r"performance-collect ([0-9a-f]{40}) ([0-9a-f]{64})", command)
    if not match:
        raise ValueError("expected performance-collect COMMIT BINARY_SHA256")
    directory = root / match[1] / match[2]
    for path in (directory, *directory.parents):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("performance evidence directories must be root-owned and protected")
    payloads = []
    for index in range(1, 6):
        name = f"run-{index}.json"
        path = directory / name
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                    or info.st_size > 1_048_576):
                raise ValueError("performance runs must be bounded, protected root-owned regular files")
            raw = stream.read(1_048_577)
            if len(raw) > 1_048_576:
                raise ValueError("performance run grew beyond its limit")
            payloads.append((name, raw))
    return payloads


def main() -> int:
    try:
        if not os.environ.get("SSH_CONNECTION") or len(sys.argv) != 1:
            raise ValueError("collector is a forced SSH command and accepts no shell arguments")
        payloads = collect(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
        with zipfile.ZipFile(sys.stdout.buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, raw in payloads:
                archive.writestr(name, raw)
        return 0
    except (OSError, ValueError) as error:
        print(f"performance collection rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
