#!/usr/bin/env python3
"""Offline tests of candidate binding, fresh audits, and release transition gates."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get("BASH_BIN") or shutil.which("bash")
LOCK = 'version = 4\n\n[[package]]\nname = "example"\nversion = "1.0.0"\n'

FAKE_CARGO = r'''#!/bin/sh
set -eu
if [ "$*" = 'audit --version' ]; then
    echo "cargo-audit ${AUDIT_TEST_VERSION:-0.22.2}"
    exit 0
fi
printf '%s\n' "$@" > "$AUDIT_TEST_ARGS"
[ "$1" = audit ]
shift
database=
lockfile=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --db) database=$2; shift 2 ;;
        --file) lockfile=$2; shift 2 ;;
        --deny) [ "$2" = warnings ]; shift 2 ;;
        --ignore) [ "$2" = RUSTSEC-2023-0071 ]; shift 2 ;;
        --json) shift ;;
        *) exit 90 ;;
    esac
done
test -n "$database"
test -s "$lockfile"
test ! -e "$database"
case "$AUDIT_TEST_MODE" in
    network) echo 'database fetch failed' >&2; exit 2 ;;
    missing_database) echo '{}'; exit 0 ;;
esac
git init -q "$database"
git -C "$database" -c user.name=Test -c user.email=test@example.invalid \
    -c commit.gpgsign=false commit -q --allow-empty -m database
case "$AUDIT_TEST_MODE" in
    vulnerability|warning) echo '{"vulnerabilities":{"found":true}}'; exit 1 ;;
    mutate) printf '\nmodified\n' >> "$lockfile" ;;
esac
echo '{"vulnerabilities":{"found":false},"warnings":{}}'
'''


def job(text, name):
    match = re.search(rf"^  {re.escape(name)}:\n(.*?)(?=^  [a-zA-Z_][\w-]*:|\Z)",
                      text, re.MULTILINE | re.DOTALL)
    if not match:
        raise AssertionError(f"missing job {name}")
    return match.group(1)


def workflow_step(text, name):
    match = re.search(rf"^      - name: {re.escape(name)}\n(.*?)(?=^      - |\Z)",
                      text, re.MULTILINE | re.DOTALL)
    if not match:
        raise AssertionError(f"missing step {name}")
    return match.group(1)


def run_body(step):
    return "\n".join(line[10:] for line in step.splitlines() if line.startswith("          "))


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        (self.repo / "Cargo.lock").write_text(LOCK, encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "Cargo.lock"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Test",
                        "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
                        "commit", "-q", "-m", "candidate"], check=True)
        self.commit = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"],
                                              text=True).strip()
        (self.repo / "tools").mkdir()
        shutil.copyfile(ROOT / "tools/audit-release-candidate.sh",
                        self.repo / "tools/audit-release-candidate.sh")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, script in {
            "cargo": FAKE_CARGO,
            "gh": '#!/bin/sh\nprintf "%s\\n" "$*" >> "$AUDIT_TEST_GH"\n',
        }.items():
            path = self.bin / name
            path.write_text(script, encoding="utf-8", newline="\n")
            path.chmod(0o755)
        self.env = {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                    "AUDIT_TEST_MODE": "success", "AUDIT_TEST_ARGS": (self.root / "args").as_posix(),
                    "AUDIT_TEST_GH": (self.root / "gh-calls").as_posix(),
                    "RUNNER_TEMP": self.root.as_posix(), "GITHUB_REF_NAME": "v1.0.0"}
        self.report = self.root / "report"

    def shell(self, command):
        return subprocess.run([BASH, "-c", command], cwd=self.repo, env=self.env,
                              capture_output=True, text=True)

    def audit(self, mode="success", commit=None):
        self.env["AUDIT_TEST_MODE"] = mode
        return self.shell(f'sh tools/audit-release-candidate.sh "{commit or self.commit}" "{self.report.as_posix()}"')

    def test_audits_committed_lockfile_not_mutable_checkout(self):
        (self.repo / "Cargo.lock").write_text("changed working copy", encoding="utf-8")
        result = self.audit()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.report / "Cargo.lock").read_text(encoding="utf-8"), LOCK)
        receipt = (self.report / "receipt.env").read_text(encoding="utf-8")
        self.assertIn(f"commit={self.commit}\n", receipt)
        self.assertRegex(receipt, r"database_commit=[a-f0-9]{40}\n")
        self.assertRegex(receipt, r"lock_sha256=[a-f0-9]{64}\n")
        self.assertIn("exit_code=0\n", receipt)

    def test_finding_blocks_and_preserves_report(self):
        self.assertNotEqual(self.audit("vulnerability").returncode, 0)
        self.assertTrue((self.report / "receipt.env").is_file())
        self.assertIn('"found":true', (self.report / "audit.json").read_text(encoding="utf-8"))

    def test_warning_blocks(self):
        self.assertNotEqual(self.audit("warning").returncode, 0)

    def test_network_failure_cannot_use_previous_database(self):
        self.assertNotEqual(self.audit("network").returncode, 0)
        receipt = (self.report / "receipt.env").read_text(encoding="utf-8")
        self.assertIn("database_commit=unavailable", receipt)
        self.assertNotIn("exit_code=0", receipt)

    def test_success_without_database_evidence_fails_closed(self):
        self.assertNotEqual(self.audit("missing_database").returncode, 0)

    def test_lockfile_mutation_fails_closed(self):
        self.assertNotEqual(self.audit("mutate").returncode, 0)

    def test_wrong_tool_version_and_invalid_commit_are_rejected(self):
        self.env["AUDIT_TEST_VERSION"] = "0.22.1"
        self.assertNotEqual(self.audit().returncode, 0)
        self.assertFalse(self.report.exists())
        self.env["AUDIT_TEST_VERSION"] = "0.22.2"
        self.assertNotEqual(self.audit(commit="main").returncode, 0)
        self.assertNotEqual(self.audit(commit="0" * 40).returncode, 0)
        self.assertFalse(self.report.exists())

    def test_existing_evidence_is_not_overwritten(self):
        self.report.mkdir()
        marker = self.report / "keep"
        marker.write_text("previous evidence", encoding="utf-8")
        self.assertNotEqual(self.audit().returncode, 0)
        self.assertEqual(marker.read_text(encoding="utf-8"), "previous evidence")

    def test_final_publication_command_is_blocked_on_audit_errors(self):
        publish = job((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"), "publish")
        body = run_body(workflow_step(publish, "Create draft, verify remote assets, then publish"))
        transition = body[body.index('sh tools/audit-release-candidate.sh "$remote_tag_commit"'):]
        transition = transition[:transition.index('test "$(gh api')]
        for mode in ("vulnerability", "network", "success"):
            with self.subTest(mode=mode):
                self.env["AUDIT_TEST_MODE"] = mode
                self.env["RUNNER_TEMP"] = (self.root / mode).as_posix()
                result = self.shell(f'set -eu\nremote_tag_commit={self.commit}\n{transition}')
                self.assertEqual(result.returncode == 0, mode == "success", result.stdout + result.stderr)
                calls = self.root / "gh-calls"
                if mode == "success":
                    self.assertIn("release edit v1.0.0 --draft=false", calls.read_text(encoding="utf-8"))
                else:
                    self.assertFalse(calls.exists())

    def test_soak_start_is_blocked_on_audit_errors(self):
        start = job((ROOT / ".github/workflows/soak-start.yml").read_text(encoding="utf-8"), "start")
        step = workflow_step(start, "Fresh security audit before starting the soak")
        command = re.search(r"^        run: (.+)$", step, re.MULTILINE).group(1)
        self.env["AUDIT_COMMIT"] = self.commit
        for mode in ("vulnerability", "network", "success"):
            with self.subTest(mode=mode):
                self.env["AUDIT_TEST_MODE"] = mode
                self.env["RUNNER_TEMP"] = (self.root / mode).as_posix()
                result = self.shell(f'set -eu\n{command}\ngh test-start-monitor')
                self.assertEqual(result.returncode == 0, mode == "success", result.stdout + result.stderr)
                self.assertEqual((self.root / "gh-calls").exists(), mode == "success")


class WorkflowTests(unittest.TestCase):
    def test_start_and_publication_gates_have_no_failure_bypass(self):
        start = job((ROOT / ".github/workflows/soak-start.yml").read_text(encoding="utf-8"), "start")
        audit = workflow_step(start, "Fresh security audit before starting the soak")
        self.assertNotIn("continue-on-error", audit)
        self.assertNotIn("if:", audit)
        self.assertLess(start.index("Fresh security audit"), start.index("Start host-side systemd monitor"))
        publish = job((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"), "publish")
        transition = workflow_step(publish, "Create draft, verify remote assets, then publish")
        self.assertIn("environment: release-signing", publish)
        self.assertNotIn("continue-on-error", transition)
        self.assertNotIn("if:", transition)
        self.assertLess(transition.index("cmp local-assets.sha256"), transition.index("sh tools/audit-release-candidate.sh"))
        self.assertLess(transition.index("sh tools/audit-release-candidate.sh"), transition.index('gh release edit "$GITHUB_REF_NAME" --draft=false'))

    def test_daily_audit_binds_host_candidate_and_keeps_soak_status_separate(self):
        collector = (ROOT / ".github/workflows/soak-collect.yml").read_text(encoding="utf-8")
        collect = job(collector, "collect")
        daily = job(collector, "security_audit")
        self.assertIn("commit_sha: ${{ steps.collect.outputs.commit_sha }}", collect)
        self.assertNotIn("security-audit'", collect)
        self.assertIn("- cron: '29 3 * * *'", collector)
        self.assertIn("github.event.schedule == '29 3 * * *'", daily)
        self.assertIn("github.event_name == 'workflow_dispatch'", daily)
        self.assertIn("commit_sha: ${{ needs.collect.outputs.commit_sha }}", daily)
        self.assertIn("uses: ./.github/workflows/security-audit.yml", daily)
        security = (ROOT / ".github/workflows/security-audit.yml").read_text(encoding="utf-8")
        self.assertIn('cron: "43 3 * * *"', security)
        self.assertIn("${{ inputs.commit_sha || github.sha }}", security)
        self.assertIn("vaultlink/security-audit", security)
        self.assertNotIn("vaultlink/72h-soak", security)
        self.assertIn('git fetch --no-tags --depth=1 origin "$AUDIT_COMMIT"', security)
        self.assertNotIn("ref: ${{ inputs.commit_sha", security)

    def test_draft_retry_requires_private_draft_valid_signatures_and_identical_payload(self):
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        body = run_body(workflow_step(job(release, "publish"), "Create draft, verify remote assets, then publish"))
        self.assertIn('--json isDraft --jq .isDraft)" = true', body)
        self.assertIn('"$remote"', body)
        self.assertIn('--signed', body)
        self.assertEqual(body.count("! -name '*.minisig'"), 2)
        self.assertIn("cmp local-assets.sha256 remote-assets.sha256", body)
        self.assertNotIn("--clobber", body)
        self.assertNotIn("release delete", body)


if __name__ == "__main__":
    if not BASH:
        raise SystemExit("bash is required (set BASH_BIN when testing on Windows)")
    unittest.main()
