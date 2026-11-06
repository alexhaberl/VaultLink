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

    def check_signal(self, sig, expected_status, wait_for_sample=False,
                     ignore_signal=False):
        with tempfile.TemporaryDirectory() as work:
            marker = Path(work) / "payload.pid"
            log = Path(work) / "diagnostics.log"
            child_pid = None
            with log.open("w", encoding="utf-8") as output:
                process = subprocess.Popen(
                    [
                        "bash", str(SCRIPT), sys.executable, "-c",
                        "import os,pathlib,signal,sys,time; "
                        + (f"signal.signal({sig.value}, signal.SIG_IGN); " if ignore_signal else "")
                        + "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
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
                    if ignore_signal:
                        self.assertIn("signal_grace_expired", text)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(child_pid, 0)
                    # The resource sampler and its sleep share the wrapper's
                    # group; kernel and signal readers use separate groups.
                    with self.assertRaises(ProcessLookupError):
                        os.killpg(process.pid, 0)
                    for line in text.splitlines():
                        if line.startswith((
                            "[runner-diagnostics] kernel_process_group=",
                            "[runner-diagnostics] signal_process_group=",
                        )):
                            with self.assertRaises(ProcessLookupError):
                                os.killpg(int(line.rsplit("=", 1)[1]), 0)
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

    def test_sigterm_is_bounded_when_the_command_ignores_it(self):
        self.check_signal(signal.SIGTERM, 143, ignore_signal=True)

    def test_optional_signal_trace_is_restricted_and_reaped(self):
        with tempfile.TemporaryDirectory() as work:
            directory = Path(work)
            arguments = directory / "trace.args"
            trace_pid = directory / "trace.pid"
            tracer = directory / "strace"
            tracer.write_text(
                '#!/bin/sh\n'
                'printf "%s\\n" "$@" > "$RUNNER_DIAGNOSTICS_TEST_TRACE_ARGS"\n'
                'echo "$$" > "$RUNNER_DIAGNOSTICS_TEST_TRACE_PID"\n'
                "trap 'exit 0' HUP INT TERM\n"
                'while :; do sleep 0.1 & wait "$!" || true; done\n',
                encoding="utf-8",
            )
            tracer.chmod(0o755)
            sudo = directory / "sudo"
            sudo.write_text(
                '#!/bin/sh\n'
                '[ "${1-}" != -n ] || shift\n'
                '[ "${1-}" != -- ] || shift\n'
                'exec "$@"\n',
                encoding="utf-8",
            )
            sudo.chmod(0o755)
            env = {
                **os.environ,
                "PATH": f"{directory}{os.pathsep}{os.environ['PATH']}",
                "RUNNER_DIAGNOSTICS_TRACE_SIGNALS": "1",
                "RUNNER_DIAGNOSTICS_TEST_TRACE_ARGS": str(arguments),
                "RUNNER_DIAGNOSTICS_TEST_TRACE_PID": str(trace_pid),
            }
            process = subprocess.Popen(
                [
                    "bash", str(SCRIPT), sys.executable, "-c",
                    "import pathlib,sys,time\n"
                    "marker = pathlib.Path(sys.argv[1])\n"
                    "deadline = time.monotonic() + 5\n"
                    "while not marker.exists() and time.monotonic() < deadline:\n"
                    "    time.sleep(0.05)\n"
                    "sys.exit(0 if marker.exists() else 1)\n",
                    str(trace_pid),
                ],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, start_new_session=True,
            )
            try:
                output, _ = process.communicate(timeout=15)
                self.assertEqual(process.returncode, 0, output)
                self.assertIn("starting signal trace", output)
                trace_arguments = arguments.read_text().splitlines()
                self.assertIn("trace=none", trace_arguments)
                self.assertIn("signal=HUP,INT,TERM,QUIT", trace_arguments)
                self.assertNotIn("-f", trace_arguments)
                self.assertIn("-p", trace_arguments)
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(trace_pid.read_text()), 0)
                with self.assertRaises(ProcessLookupError):
                    os.killpg(int(trace_pid.read_text()), 0)
            finally:
                if trace_pid.exists():
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(int(trace_pid.read_text()), signal.SIGKILL)
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
