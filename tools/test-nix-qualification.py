#!/usr/bin/env python3
"""Verify that a restored store cannot skip VM qualification or widen deletion."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "tools/prepare-nix-vm-tests.sh"
CHECKS = ("local", "smb", "upgrade")
OUTPUTS = {
    name: f"/nix/store/{character * 32}-vm-test-run-{name}"
    for name, character in zip(CHECKS, "abc", strict=True)
}
STUB = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

plan = json.loads(Path(os.environ["NIX_TEST_PLAN"]).read_text())
state_path = Path(os.environ["NIX_TEST_STATE"])
state = json.loads(state_path.read_text())
command = Path(sys.argv[0]).name
args = sys.argv[1:]
with Path(os.environ["NIX_TEST_LOG"]).open("a") as log:
    log.write(json.dumps([command, *args]) + "\n")
if command == "nix":
    if len(args) != 4 or args[:2] != ["eval", "--raw"] or args[-1] != "--no-write-lock-file":
        raise SystemExit(99)
    attr = args[2]
    if attr == plan.get("eval_failure"):
        raise SystemExit(23)
    sys.stdout.write(plan["outputs"][attr])
elif command == "nix-store":
    if len(args) != 2:
        raise SystemExit(99)
    operation, path = args
    if operation == "--check-validity":
        raise SystemExit(0 if path in state["valid"] else 1)
    if operation != "--delete":
        raise SystemExit(99)
    if path == plan.get("undeletable"):
        print("path is still alive or has referrers", file=sys.stderr)
        raise SystemExit(31)
    state["valid"].remove(path)
    state_path.write_text(json.dumps(state))
else:
    raise SystemExit(99)
'''


class NixVmQualificationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="vaultlink-nix-tests-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("nix", "nix-store"):
            executable = self.bin / name
            executable.write_text(STUB, encoding="utf-8")
            executable.chmod(0o755)
        self.log = self.root / "commands.jsonl"
        self.state = self.root / "state.json"
        self.plan_path = self.root / "plan.json"

    def run_helper(self, system="x86_64-linux", valid=(), overrides=None, **options):
        outputs = {
            f".#checks.{system}.{name}.outPath": path
            for name, path in OUTPUTS.items()
        }
        if overrides:
            outputs.update(overrides)
        self.plan_path.write_text(json.dumps({"outputs": outputs, **options}))
        self.state.write_text(json.dumps({"valid": list(valid)}))
        self.log.write_text("")
        environment = {
            **os.environ,
            "PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
            "NIX_TEST_PLAN": str(self.plan_path),
            "NIX_TEST_STATE": str(self.state),
            "NIX_TEST_LOG": str(self.log),
        }
        shell = shutil.which("sh")
        self.assertIsNotNone(shell, "these POSIX-helper tests require sh")
        return subprocess.run(
            [shell, str(HELPER), system], env=environment, cwd=ROOT,
            capture_output=True, text=True, check=False,
        )

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_cold_store_checks_all_results_without_deleting_dependencies(self):
        for system in ("x86_64-linux", "aarch64-linux"):
            with self.subTest(system=system):
                result = self.run_helper(system)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = self.calls()
                self.assertEqual([call[2] for call in calls if call[0] == "nix-store"], list(OUTPUTS.values()))
                self.assertTrue(all(call[1] == "--check-validity" for call in calls if call[0] == "nix-store"))
                self.assertEqual(len([call for call in calls if call[0] == "nix"]), 3)

    def test_warm_store_deletes_exactly_the_three_results(self):
        result = self.run_helper(valid=OUTPUTS.values())
        self.assertEqual(result.returncode, 0, result.stderr)
        deletions = [call for call in self.calls() if call[:2] == ["nix-store", "--delete"]]
        self.assertEqual(deletions, [["nix-store", "--delete", path] for path in OUTPUTS.values()])
        self.assertEqual(json.loads(self.state.read_text())["valid"], [])

    def test_partially_warm_store_deletes_only_existing_results(self):
        paths = [OUTPUTS["local"], OUTPUTS["upgrade"]]
        result = self.run_helper(valid=paths)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[2] for call in self.calls() if call[:2] == ["nix-store", "--delete"]], paths)

    def test_invalid_output_paths_are_refused_before_any_store_mutation(self):
        for path in ("", "/tmp/result", "/nix/store/../result", OUTPUTS["local"] + "/child",
                     OUTPUTS["local"] + "\n" + OUTPUTS["smb"], " " + OUTPUTS["local"]):
            with self.subTest(path=path):
                result = self.run_helper(overrides={".#checks.x86_64-linux.local.outPath": path})
                self.assertEqual(result.returncode, 65, result.stderr)
                self.assertTrue(all(call[0] == "nix" for call in self.calls()))

    def test_rooted_or_referred_result_fails_closed(self):
        result = self.run_helper(valid=OUTPUTS.values(), undeletable=OUTPUTS["local"])
        self.assertEqual(result.returncode, 31, result.stderr)
        self.assertIn("referrers", result.stderr)
        self.assertEqual(json.loads(self.state.read_text())["valid"], list(OUTPUTS.values()))
        self.assertEqual(len([call for call in self.calls() if call[0] == "nix"]), 1)
        self.assertNotIn("--ignore-liveness", str(self.calls()))

    def test_evaluation_failure_is_propagated_before_any_store_operation(self):
        result = self.run_helper(eval_failure=".#checks.x86_64-linux.local.outPath")
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.calls()[0][0], "nix")

    def test_unsupported_system_is_rejected_without_evaluating(self):
        result = self.run_helper(system="unsupported-linux")
        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
