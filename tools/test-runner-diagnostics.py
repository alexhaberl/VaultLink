#!/usr/bin/env python3
"""Exercise exit status, live samples, signal forwarding, and child cleanup."""

import contextlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT = Path(__file__).with_name("run-with-runner-diagnostics.sh")


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux host diagnostics")
class RunnerDiagnosticsTests(unittest.TestCase):
    def run_command(self, *command):
        return subprocess.run(
            ["bash", str(SCRIPT), *command],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=20,
            check=False,
        )

    def test_success_and_failure_keep_the_command_status(self):
        for status in (0, 37):
            with self.subTest(status=status):
                result = self.run_command("bash", "-c", f"exit {status}")
                self.assertEqual(result.returncode, status, result.stdout)
                self.assertIn("phase=initial", result.stdout)
                self.assertIn("phase=final", result.stdout)
                self.assertIn(f"command_exit_code={status}", result.stdout)

    def test_missing_command_is_not_reported_as_success(self):
        result = self.run_command("vaultlink-diagnostics-command-does-not-exist")
        self.assertEqual(result.returncode, 127, result.stdout)

    def check_signal(self, sig, expected_status, wait_for_sample=False):
        with tempfile.TemporaryDirectory() as work:
            marker = Path(work) / "payload.pid"
            log = Path(work) / "diagnostics.log"
            child_pid = None
            with log.open("w", encoding="utf-8") as output:
                process = subprocess.Popen(
                    [
                        "bash", str(SCRIPT), sys.executable, "-c",
                        "import os,pathlib,sys,time; "
                        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
                        "time.sleep(60)",
                        str(marker),
                    ],
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                try:
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        text = log.read_text(encoding="utf-8", errors="replace")
                        if marker.exists() and (
                            not wait_for_sample or "phase=periodic" in text
                        ):
                            break
                        if process.poll() is not None:
                            self.fail(f"wrapper stopped before signal: {text}")
                        time.sleep(0.05)
                    else:
                        self.fail(f"no live evidence: {text}")
                    child_pid = int(marker.read_text())
                    os.kill(process.pid, sig)
                    self.assertEqual(process.wait(timeout=10), expected_status)
                    text = log.read_text(encoding="utf-8", errors="replace")
                    self.assertIn(f"received_signal={sig.name.removeprefix('SIG')}", text)
                    self.assertIn(f"command_exit_code={expected_status}", text)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(child_pid, 0)
                    # The resource sampler, its sleep, and kernel reader share
                    # the wrapper's group and must all have been reaped.
                    with self.assertRaises(ProcessLookupError):
                        os.killpg(process.pid, 0)
                finally:
                    if marker.exists() and child_pid is None:
                        child_pid = int(marker.read_text())
                    if child_pid is not None:
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(child_pid, signal.SIGKILL)
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)

    def test_sigterm_preserves_live_evidence_and_stops_children(self):
        self.check_signal(signal.SIGTERM, 143, wait_for_sample=True)

    def test_sigint_is_forwarded_to_the_command(self):
        self.check_signal(signal.SIGINT, 130)


if __name__ == "__main__":
    unittest.main(verbosity=2)
