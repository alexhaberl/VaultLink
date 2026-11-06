#!/usr/bin/env python3
"""Exercise bounded APT retries with independent, offline fake APT processes."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("retry-apt-download.sh")


@unittest.skipUnless(sys.platform.startswith("linux"), "requires POSIX sh")
class AptDownloadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="vaultlink-apt-retry-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.calls = self.work / "apt.json"
        self.delays = self.work / "delays.json"
        self.calls.write_text("[]")
        self.delays.write_text("[]")
        apt = self.work / "apt-get"
        apt.write_text(
            "#!/usr/bin/env python3\n"
            "import json,os,pathlib,sys\n"
            "path=pathlib.Path(os.environ['TEST_APT_CALLS'])\n"
            "calls=json.loads(path.read_text())\n"
            "statuses=json.loads(os.environ['TEST_APT_STATUSES'])\n"
            "status=statuses[min(len(calls),len(statuses)-1)]\n"
            "calls.append({'pid':os.getpid(),'args':sys.argv[1:]})\n"
            "path.write_text(json.dumps(calls))\n"
            "print('fixture APT status',status,flush=True)\n"
            "sys.exit(status)\n",
            encoding="utf-8",
        )
        apt.chmod(0o755)
        sleeper = self.work / "sleep"
        sleeper.write_text(
            "#!/usr/bin/env python3\n"
            "import json,os,pathlib,sys\n"
            "path=pathlib.Path(os.environ['TEST_APT_DELAYS'])\n"
            "delays=json.loads(path.read_text())\n"
            "delays.append(int(sys.argv[1]))\n"
            "path.write_text(json.dumps(delays))\n",
            encoding="utf-8",
        )
        sleeper.chmod(0o755)

    def run_retry(self, statuses, *arguments):
        env = {
            **os.environ,
            "PATH": f"{self.work}{os.pathsep}{os.environ['PATH']}",
            "TEST_APT_CALLS": str(self.calls),
            "TEST_APT_DELAYS": str(self.delays),
            "TEST_APT_STATUSES": json.dumps(statuses),
        }
        result = subprocess.run(
            ["sh", str(SCRIPT), *arguments],
            env=env, capture_output=True, text=True, timeout=10, check=False,
        )
        calls = json.loads(self.calls.read_text())
        for call in calls:
            self.assertIn("Acquire::Retries=0", call["args"])
            self.assertFalse(any(
                arg.startswith("Acquire::Retries=") and arg != "Acquire::Retries=0"
                for arg in call["args"]
            ))
        return result, calls, json.loads(self.delays.read_text())

    def test_update_succeeds_without_an_unneeded_retry(self):
        result, calls, delays = self.run_retry([0], "update")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 1)
        self.assertEqual(delays, [])
        self.assertIn("--error-on=any", calls[0]["args"])
        self.assertIn("update", calls[0]["args"])

    def test_failure_restarts_in_a_fresh_process_with_the_same_pins(self):
        pins = ["libfixture=1:2.3-4", "fixture=5.6+deb13u1"]
        result, calls, delays = self.run_retry(
            [100, 0], "download", "-y", "--no-install-recommends", *pins,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)
        self.assertNotEqual(calls[0]["pid"], calls[1]["pid"])
        self.assertEqual(calls[0]["args"], calls[1]["args"])
        self.assertEqual(calls[0]["args"][-len(pins):], pins)
        self.assertIn("install", calls[0]["args"])
        self.assertIn("--download-only", calls[0]["args"])
        self.assertEqual(delays, [5])

    def test_persistent_failure_keeps_the_error_and_stops_after_six_attempts(self):
        result, calls, delays = self.run_retry([100], "update")
        self.assertEqual(result.returncode, 100)
        self.assertEqual(len(calls), 6)
        self.assertEqual(len({call["pid"] for call in calls}), 6)
        self.assertEqual(delays, [5, 10, 20, 30, 30])
        self.assertIn("failed after 6 attempts", result.stderr)

    def test_later_success_stops_the_backoff(self):
        result, calls, delays = self.run_retry(
            [100, 100, 0], "download", "-y", "fixture=1",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 3)
        self.assertEqual(delays, [5, 10])

    def test_unknown_operation_cannot_install_packages(self):
        result, calls, delays = self.run_retry([0], "install", "fixture=1")
        self.assertEqual(result.returncode, 64)
        self.assertEqual(calls, [])
        self.assertEqual(delays, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
