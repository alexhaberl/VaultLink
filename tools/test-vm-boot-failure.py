#!/usr/bin/env python3
"""Regression coverage for fail-fast boot classification, including slow boots."""

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("classify-vm-boot-failure.py")
SPEC = importlib.util.spec_from_file_location("boot_failure", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BootFailureTests(unittest.TestCase):
    def test_observed_fedora_pid1_freeze(self):
        log = (
            b"[ 264.633191] watchdog: BUG: soft lockup - CPU#2 stuck for 23s! [systemd:1]\n"
            b"[ 318.011622] systemd[1]: Failed to fork off sandboxing environment for executing generators: Protocol error\n"
            b"[\x1b[0;1;31m!!!!!!\x1b[0m] Failed to start up manager.\r\n"
            b"[ 318.595807] systemd[1]: Freezing execution.\r\n"
        )
        self.assertEqual(MODULE.classify(log), "systemd_manager_frozen")

    def test_kernel_panic(self):
        for prefix in (b"", b"[  12.000001] "):
            with self.subTest(prefix=prefix):
                self.assertEqual(
                    MODULE.classify(prefix + b"Kernel panic - not syncing: Attempted to kill init!\n"),
                    "kernel_panic",
                )

    def test_slow_boot_can_recover(self):
        self.assertEqual(MODULE.classify(
            b"[ 20.000] watchdog: BUG: soft lockup - CPU#1 stuck for 22s!\n"
            b"[FAILED] Failed to start optional.service.\n"
            b"[ 21.000] systemd[1]: Failed to fork off sandboxing environment: Protocol error\n"
            b"VAULTLINK_VM_STORAGE_READY\nVAULTLINK_VM_READY\n"
        ), "")

    def test_only_pid1_freeze_is_terminal(self):
        for line in (b"systemd[99]: Freezing execution.\n",
                     b"example: systemd[1]: Freezing execution.\n",
                     b"application: Kernel panic - not syncing: example\n"):
            with self.subTest(line=line):
                self.assertEqual(MODULE.classify(line), "")

    def test_ansi_osc_and_invalid_utf8(self):
        self.assertEqual(MODULE.classify(
            b"\xff\n\x1b]3008;type=boot\x1b\\\x1b[31msystemd[1]: Freezing execution.\x1b[0m\r\n"
        ), "systemd_manager_frozen")

    def test_incomplete_record_is_not_terminal(self):
        self.assertEqual(MODULE.classify(b"[ 318.59] systemd[1]: Freezing exec"), "")

    def test_bounded_file_tail_and_command_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "serial.log"
            path.write_bytes(b"x" * (MODULE.MAX_LOG_BYTES + 100) +
                             b"\nsystemd[1]: Freezing execution.\n")
            self.assertEqual(MODULE.classify_file(path), "systemd_manager_frozen")
            result = subprocess.run([sys.executable, str(SCRIPT), str(path)],
                                    capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout.strip(), "systemd_manager_frozen")

    def test_empty_log(self):
        self.assertEqual(MODULE.classify(b""), "")


@unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "POSIX harness integration")
class ReadinessLoopTests(unittest.TestCase):
    def run_readiness(self, log):
        source = SCRIPT.with_name("run-distro-vm-test.sh").read_text()
        start = source.index('deadline=$(( $(date +%s) + ssh_timeout ))')
        end = source.index('if [ "$target_id" = archlinux-amd64 ]; then', start)
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            (evidence / "serial.log").write_bytes(log)
            script = '''set -eu
evidence=$CASE_EVIDENCE
ssh_readiness_error=$evidence/ssh.stderr
ssh_timeout=3600
target_id=fedora44-arm64
qemu_pid=$$
run_ssh() { echo probe >>"$evidence/probes"; return 0; }
capture_readiness_diagnostic() { printf '%s\\n' "$1" >"$evidence/captured"; }
sleep() { echo unexpected-wait >&2; exit 99; }
''' + source[start:end]
            result = subprocess.run(
                ["sh", "-c", script], cwd=SCRIPT.parent.parent,
                env={**os.environ, "CASE_EVIDENCE": str(evidence)},
                capture_output=True, text=True, timeout=5,
            )
            files = {p.name: p.read_text() for p in evidence.iterdir() if p.name != "serial.log"}
            return result, files

    def test_terminal_freeze_stops_before_ssh_or_wait(self):
        result, files = self.run_readiness(b"[ 318.595807] systemd[1]: Freezing execution.\n")
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assertIn("reason=systemd_manager_frozen", files["boot-failure.env"])
        self.assertIn("application_test_started=false", files["boot-failure.env"])
        self.assertIn("VaultLink test was not started", files["captured"])
        self.assertNotIn("probes", files)

    def test_kernel_panic_stops_before_ssh_or_wait(self):
        result, files = self.run_readiness(b"Kernel panic - not syncing: fatal failure\n")
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assertIn("reason=kernel_panic", files["boot-failure.env"])
        self.assertNotIn("probes", files)

    def test_soft_lockup_does_not_prevent_later_readiness(self):
        result, files = self.run_readiness(
            b"watchdog: BUG: soft lockup - CPU#1 stuck for 22s!\n"
            b"VAULTLINK_VM_STORAGE_READY\nVAULTLINK_VM_READY\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("boot-failure.env", files)
        self.assertNotIn("captured", files)
        self.assertEqual(files["probes"], "probe\n")


if __name__ == "__main__":
    unittest.main()
