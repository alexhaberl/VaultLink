#!/usr/bin/env python3
"""Regress native runners whose printed device alias differs from mountinfo."""
import importlib.util
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("runtime_smoke", Path(__file__).with_name("runtime-smoke.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

for source, expected in [("/dev/root", "/dev/root"), (r"/dev/mapper/local\040data", "/dev/mapper/local data")]:
    mountinfo = f"24 1 8:1 / / rw - ext4 {source} rw\n25 24 0:5 / /tmp/other rw - tmpfs tmpfs rw\n"
    with patch.object(smoke.subprocess, "check_output", return_value="24\n") as command:
        with patch.object(Path, "read_text", return_value=mountinfo):
            assert smoke.mount_identity(Path("/tmp/tls/shared")) == ("ext4", expected)
        assert command.call_args.args[0][-1] == "ID"

with patch.object(smoke.subprocess, "check_output", return_value="99\n"):
    with patch.object(Path, "read_text", return_value=mountinfo):
        try:
            smoke.mount_identity(Path("/tmp/tls/shared"))
        except RuntimeError:
            pass
        else:
            raise AssertionError("missing mount must fail the TLS fixture")
print("Runtime mount-source regression fixtures passed")
