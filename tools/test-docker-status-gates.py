#!/usr/bin/env python3
"""Offline checks for independent, fail-closed Docker status publication."""

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile


SPEC = importlib.util.spec_from_file_location(
    "docker_gate_publisher", Path(__file__).with_name("publish-docker-gates.py")
)
PUBLISHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISHER)
COMMIT = "b" * 40
REPOSITORY = "example/VaultLink"
RUN = {"id": 789, "run_attempt": 2}


class FakeGitHub:
    def __init__(self, repository=REPOSITORY):
        self.repository = repository
        self.run = copy.deepcopy(RUN)
        self.request_error = None

    def request(self, path):
        if self.request_error:
            raise self.request_error
        if path != "actions/runs/789":
            raise AssertionError(f"unexpected API lookup: {path}")
        return copy.deepcopy(self.run)


def qualified(*args):
    return {"binary_sha256": "c" * 64, "artifact_id": 900, "run_attempt": 1}


class DockerStatusGatesTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="vaultlink-docker-gates-")
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / "status.json"
        self.api = FakeGitHub()
        self.identity = self.enterContext(patch.object(
            PUBLISHER.EVIDENCE, "docker_run_identity", create=True
        ))
        self.qualification = self.enterContext(patch.object(
            PUBLISHER.EVIDENCE, "docker_architecture_qualification", side_effect=qualified, create=True
        ))

    def evaluate(self):
        return PUBLISHER.evaluate(self.api, 789, 2, COMMIT, "0.7.2", self.output.parent)

    def cli(self, publish=False):
        arguments = ["--run-id", "789", "--run-attempt", "2", "--commit", COMMIT,
                     "--version", "0.7.2", "--repository", REPOSITORY, "--output", str(self.output)]
        if publish:
            arguments.append("--publish")
        with patch.object(PUBLISHER.EVIDENCE, "GitHub", return_value=self.api):
            with contextlib.redirect_stdout(io.StringIO()):
                return PUBLISHER.main(arguments)

    def test_failure_of_one_architecture_keeps_the_other_successful(self):
        self.qualification.side_effect = [qualified(), PUBLISHER.EVIDENCE.EvidenceError("missing arm receipt")]
        result = self.evaluate()
        self.assertEqual(result["state"], "failure")
        self.assertEqual(result["architectures"]["amd64"]["state"], "success")
        self.assertEqual(result["architectures"]["arm64"]["state"], "failure")
        self.assertEqual(self.qualification.call_count, 2)
        self.assertEqual(result["architectures"]["amd64"]["qualification"]["run_attempt"], 1)

    def test_archive_failure_does_not_prevent_other_architecture_validation(self):
        self.qualification.side_effect = [zipfile.BadZipFile("invalid archive"), qualified()]
        result = self.evaluate()
        self.assertEqual(result["architectures"]["amd64"]["state"], "failure")
        self.assertEqual(result["architectures"]["arm64"]["state"], "success")
        self.assertEqual(self.qualification.call_count, 2)

    def test_invalid_run_identity_fails_both_without_loading_artifacts(self):
        self.identity.side_effect = PUBLISHER.EVIDENCE.EvidenceError("wrong workflow")
        result = self.evaluate()
        self.assertEqual([entry["state"] for entry in result["architectures"].values()], ["failure", "failure"])
        self.qualification.assert_not_called()

    def test_stale_caller_attempt_fails_both(self):
        self.api.run["run_attempt"] = 3
        result = self.evaluate()
        self.assertTrue(all(entry["state"] == "failure" for entry in result["architectures"].values()))
        self.qualification.assert_not_called()

    def test_run_lookup_failure_fails_both(self):
        self.api.request_error = PUBLISHER.EVIDENCE.EvidenceError("lookup unavailable")
        result = self.evaluate()
        self.assertTrue(all(entry["state"] == "failure" for entry in result["architectures"].values()))
        self.qualification.assert_not_called()

    def test_publisher_posts_both_results_then_fails_for_mixed_evidence(self):
        self.qualification.side_effect = [qualified(), PUBLISHER.EVIDENCE.EvidenceError("arm failed")]
        with patch.object(PUBLISHER.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as command:
            self.assertEqual(self.cli(publish=True), 1)
        self.assertEqual(command.call_count, 2)
        first, second = [call.args[0] for call in command.call_args_list]
        self.assertIn("context=vaultlink/docker-amd64", first)
        self.assertIn("state=success", first)
        self.assertIn("context=vaultlink/docker-arm64", second)
        self.assertIn("state=failure", second)
        result = json.loads(self.output.read_text())
        self.assertTrue(all(entry["published"] for entry in result["architectures"].values()))

    def test_invalid_run_publishes_failure_for_both_contexts(self):
        self.identity.side_effect = PUBLISHER.EVIDENCE.EvidenceError("wrong repository")
        with patch.object(PUBLISHER.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as command:
            self.assertEqual(self.cli(publish=True), 1)
        self.assertEqual(command.call_count, 2)
        self.assertTrue(all("state=failure" in call.args[0] for call in command.call_args_list))

    def test_post_failure_does_not_suppress_second_status_and_returns_failure(self):
        for failure in (subprocess.CompletedProcess([], 1), OSError("gh unavailable")):
            with self.subTest(failure=failure):
                with patch.object(PUBLISHER.subprocess, "run", side_effect=[failure, subprocess.CompletedProcess([], 0)]) as command:
                    self.assertEqual(self.cli(publish=True), 1)
                self.assertEqual(command.call_count, 2)
                result = json.loads(self.output.read_text())
                self.assertEqual(result["publication_state"], "failure")
                self.assertFalse(result["architectures"]["amd64"]["published"])
                self.assertTrue(result["architectures"]["arm64"]["published"])

    def test_successful_dry_run_never_posts_statuses(self):
        with patch.object(PUBLISHER.subprocess, "run") as command:
            self.assertEqual(self.cli(), 0)
        command.assert_not_called()
        result = json.loads(self.output.read_text())
        self.assertEqual(result["state"], "success")
        self.assertNotIn("publication_state", result)


if __name__ == "__main__":
    unittest.main()
