#!/usr/bin/env python3
"""Offline regression tests for the release artifact and phase trust boundary."""

import argparse
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EVIDENCE = load("release-evidence")
FIXTURES = load("test-performance-evidence")
STATE = load("check-release-state")
COMMIT = "b" * 40
REPO = "example/VaultLink"
EXPECTED = {**FIXTURES.EXPECTED, "producer_sha256": EVIDENCE.producer_digest()}


def archive_bytes(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            if isinstance(name, str):
                entry = zipfile.ZipInfo()
                entry.filename = name
            else:
                entry = name
            archive.writestr(entry, content)
    return buffer.getvalue()


def workflow_run():
    return {"id": 789, "head_sha": COMMIT, "head_branch": "main", "status": "completed",
            "conclusion": "success", "path": EVIDENCE.PERFORMANCE_WORKFLOW,
            "repository": {"full_name": REPO}, "head_repository": {"full_name": REPO},
            "event": "workflow_dispatch", "display_title": "Performance candidate",
            "run_attempt": 2, "run_started_at": "2026-09-05T12:00:00Z"}


class FakeGitHub(EVIDENCE.GitHub):
    def __init__(self, raw=b"", name="proof"):
        super().__init__(REPO)
        self.run_data = workflow_run()
        self.raw = raw
        self.statuses = [{"context": "vaultlink/performance", "state": "success",
                          "target_url": f"https://github.com/{REPO}/actions/runs/789"}]
        self.artifacts = [{"id": 900, "name": name, "expired": False,
                           "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                           "created_at": "2026-09-05T12:01:00Z",
                           "workflow_run": {"id": 789, "head_sha": COMMIT}}]

    def request(self, suffix, *, raw=False):
        if suffix == "actions/runs/789":
            return copy.deepcopy(self.run_data)
        if suffix.startswith("commits/"):
            return copy.deepcopy(self.statuses)
        if suffix.startswith("actions/runs/789/artifacts?"):
            return {"artifacts": copy.deepcopy(self.artifacts)}
        if suffix == "actions/artifacts/900/zip" and raw:
            return self.raw
        raise AssertionError(f"unexpected GitHub request: {suffix}")


class ReleaseEvidenceTests(unittest.TestCase):
    def test_gate_binds_repository_workflow_commit_event_and_latest_status(self):
        api = FakeGitHub()
        def gate():
            return api.gate(COMMIT, "vaultlink/performance", EVIDENCE.PERFORMANCE_WORKFLOW,
                            "workflow_dispatch", "Performance candidate")
        self.assertEqual(gate()["id"], 789)
        for field, wrong in (("head_sha", "a" * 40), ("head_branch", "topic"),
                             ("path", ".github/workflows/ci.yml"), ("status", "in_progress"),
                             ("conclusion", "failure"), ("event", "pull_request"),
                             ("display_title", "unrelated"), ("run_attempt", 0),
                             ("repository", {"full_name": "attacker/fork"}),
                             ("head_repository", {"full_name": "attacker/fork"})):
            with self.subTest(field=field), patch.dict(api.run_data, {field: wrong}):
                self.assertRaises(EVIDENCE.EvidenceError, gate)
        for wrong in ("https://github.com/attacker/fork/actions/runs/789",
                      f"https://github.com/{REPO}/actions/runs/789/jobs/1"):
            with patch.dict(api.statuses[0], {"target_url": wrong}):
                self.assertRaises(EVIDENCE.EvidenceError, gate)
        api.statuses.insert(0, {**api.statuses[0], "state": "pending"})
        self.assertRaises(EVIDENCE.EvidenceError, gate)

    def test_artifact_digest_expiry_run_and_attempt(self):
        api = FakeGitHub(archive_bytes({"proof.txt": "verified"}))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            receipt = api.artifact(api.run_data, "proof", root / "valid")
            self.assertEqual(receipt["run_attempt"], 2)
            self.assertEqual((root / "valid/proof.txt").read_text(), "verified")
            for field, wrong in (("digest", "sha256:" + "0" * 64), ("expired", True),
                                 ("created_at", "2026-09-05T11:00:00Z"),
                                 ("created_at", "invalid"),
                                 ("workflow_run", {"id": 123, "head_sha": COMMIT})):
                with self.subTest(field=field), patch.dict(api.artifacts[0], {field: wrong}):
                    self.assertRaises(EVIDENCE.EvidenceError, api.artifact,
                                      api.run_data, "proof", root / "rejected")
                    self.assertFalse((root / "rejected").exists())
            api.artifacts.append(copy.deepcopy(api.artifacts[0]))
            self.assertRaises(EVIDENCE.EvidenceError, api.artifact,
                              api.run_data, "proof", root / "duplicate")

    def test_unsafe_archives_are_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("../escape", "/absolute", "a/../b", "a\\b", "C:/escape", "a//b"):
                destination = Path(tmp) / "rejected"
                self.assertRaises(EVIDENCE.EvidenceError, EVIDENCE.extract_artifact,
                                  archive_bytes({name: "bad"}), destination)
                self.assertFalse(destination.exists())
            link = zipfile.ZipInfo("link")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            self.assertRaises(EVIDENCE.EvidenceError, EVIDENCE.extract_artifact,
                              archive_bytes({link: "../outside"}), Path(tmp) / "link")

    def test_complete_bundle_and_every_trusted_identity_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = root / "inputs"
            inputs.mkdir()
            bundle = root / "bundle"
            for kind, frames in (("baseline", 1000), ("candidate", 100)):
                paths = FIXTURES.write_runs(inputs, kind, frames)
                for path in paths:
                    run = json.loads(path.read_text())
                    run["producer_sha256"] = EXPECTED["producer_sha256"]
                    path.write_text(json.dumps(run), encoding="utf-8")
                EVIDENCE.PERF.write_bundle(kind, paths, bundle / f"{kind}.json")
            producer = {"schema_version": 1, "run_id": 789, "run_attempt": 2,
                        "workflow_sha": COMMIT, "kind": "candidate", "identity": EXPECTED}
            (bundle / "receipt.json").write_text(json.dumps(producer), encoding="utf-8")
            lock = {"aggregate_sha256": hashlib.sha256((bundle / "baseline.json").read_bytes()).hexdigest()}
            name = f"vaultlink-performance-{COMMIT}-789-2"
            raw = archive_bytes({path.name: path.read_bytes() for path in bundle.iterdir()})
            api = FakeGitHub(raw, name)
            with patch.object(EVIDENCE, "baseline_lock", return_value=lock):
                receipt = EVIDENCE.performance_receipt(api, COMMIT, EXPECTED["binary_sha256"],
                                                       123, 456, root / "downloaded")
                self.assertEqual(receipt["identity"], EXPECTED)
                for field in EXPECTED:
                    wrong = {**EXPECTED, field: 999 if field.endswith("_run_id") else "a" * 64}
                    with self.subTest(field=field):
                        self.assertRaises(EVIDENCE.EvidenceError, EVIDENCE.validate_bundle, bundle, wrong)
                with patch.dict(lock, {"aggregate_sha256": "0" * 64}):
                    self.assertRaises(EVIDENCE.EvidenceError, EVIDENCE.validate_bundle, bundle, EXPECTED)
                producer["run_attempt"] = 1
                (bundle / "receipt.json").write_text(json.dumps(producer), encoding="utf-8")
                api = FakeGitHub(archive_bytes({p.name: p.read_bytes() for p in bundle.iterdir()}), name)
                self.assertRaises(EVIDENCE.EvidenceError, EVIDENCE.performance_receipt, api,
                                  COMMIT, EXPECTED["binary_sha256"], 123, 456, root / "stale")

    def test_receipt_rechecks_packages_and_rejects_stale_metadata(self):
        receipt = {"repository": REPO, "identity": EXPECTED}
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": REPO}), \
                patch.object(EVIDENCE.GitHub, "gate", side_effect=[{"id": 124}]), \
                patch.object(EVIDENCE, "performance_receipt") as performance:
            self.assertRaises(EVIDENCE.EvidenceError, EVIDENCE.verify_receipt,
                              receipt, COMMIT, EXPECTED["binary_sha256"], 123)
            performance.assert_not_called()
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": REPO}), \
                patch.object(EVIDENCE.GitHub, "gate", side_effect=[{"id": 123}, {"id": 456}]), \
                patch.object(EVIDENCE, "performance_receipt", return_value={**receipt, "artifact_id": 2}):
            self.assertRaises(EVIDENCE.EvidenceError, EVIDENCE.verify_receipt,
                              receipt, COMMIT, EXPECTED["binary_sha256"], 123)

    def test_release_phases_defer_only_their_downstream_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt_path = Path(tmp) / "receipt.json"
            receipt_path.write_text("{}")
            args = argparse.Namespace(phase="candidate", require_ready=False, expected_commit=COMMIT,
                                      expected_binary_sha256=EXPECTED["binary_sha256"],
                                      expected_packages_run_id=123, performance_receipt=receipt_path,
                                      output=Path(tmp) / "effective.json")
            for phase in ("candidate", "soak", "evidence", "tag"):
                args.phase = phase
                errors = []
                with patch.object(STATE, "load_release_evidence", return_value=EVIDENCE), \
                        patch.object(EVIDENCE, "verify_receipt") as performance, \
                        patch.object(EVIDENCE, "verify_soak") as soak, \
                        patch.dict(os.environ, {"GITHUB_REPOSITORY": REPO}):
                    self.assertEqual(STATE.validate_phase(args, errors), {"QUAL-001", "QUAL-006"})
                    self.assertEqual(errors, [])
                    self.assertEqual(performance.call_count, int(phase != "candidate"))
                    self.assertEqual(soak.call_count, int(phase in {"evidence", "tag"}))
                    self.assertFalse(args.output.exists(), "must not publish before qualification validation")
                    if phase != "candidate":
                        self.assertEqual(args.effective_qualification["resolved_findings"],
                                         ["QUAL-001"] if phase == "soak" else ["QUAL-001", "QUAL-006"])
            for phase in ("soak", "evidence", "tag"):
                args.phase = phase
                errors = []
                with patch.object(STATE, "load_release_evidence", return_value=EVIDENCE), \
                        patch.object(EVIDENCE, "verify_receipt", side_effect=EVIDENCE.EvidenceError("stale")):
                    self.assertFalse(STATE.validate_phase(args, errors))
                    self.assertTrue(errors)
                    self.assertIsNone(args.effective_qualification)
            args.phase, args.require_ready, args.expected_commit = "development", True, None
            errors = []
            self.assertFalse(STATE.validate_phase(args, errors))
            self.assertTrue(errors, "legacy require-ready must remain strict")


if __name__ == "__main__":
    unittest.main()
