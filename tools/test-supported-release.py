#!/usr/bin/env python3
"""Offline regressions for published soak evidence and current gate failures."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "supported_release", ROOT / "tools/verify-supported-release.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
REPOSITORY = "example/VaultLink"
COMMIT = "a" * 40
PREFIX = f"https://github.com/{REPOSITORY}/actions/runs/"


class SupportedGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.soak = {
            "context": "vaultlink/72h-soak", "state": "success", "run_url": PREFIX + "101",
        }
        self.packages = {
            "context": "vaultlink/packages", "state": "success", "run_url": PREFIX + "202",
        }
        self.supported = {
            "commit_sha": COMMIT, "required_commit_gates": [self.soak, self.packages],
        }
        self.current = [self.status(self.soak), self.status(self.packages)]
        self.history = [[self.status(self.soak)]]
        self.run = {
            "id": 101, "html_url": PREFIX + "101", "head_sha": COMMIT,
            "head_branch": "main", "repository": {"full_name": REPOSITORY},
            "head_repository": {"full_name": REPOSITORY},
            "path": ".github/workflows/soak-collect.yml", "event": "schedule",
            "status": "completed", "conclusion": "success",
        }
        self.requests: list[str] = []

    @staticmethod
    def status(gate: dict) -> dict:
        return {"context": gate["context"], "state": "success", "target_url": gate["run_url"]}

    def api(self, command: str, endpoint: str) -> object:
        self.assertEqual(command, "api")
        self.requests.append(endpoint)
        base = f"repos/{REPOSITORY}"
        if endpoint == f"{base}/commits/{COMMIT}/status":
            return {"statuses": self.current}
        history = f"{base}/commits/{COMMIT}/statuses?per_page=100&page="
        if endpoint.startswith(history):
            return self.history[int(endpoint.removeprefix(history)) - 1]
        if endpoint == f"{base}/actions/runs/101":
            return self.run
        self.fail(f"unexpected request: {endpoint}")

    def verify(self) -> None:
        with patch.object(MODULE, "gh_json", side_effect=self.api):
            MODULE.verify_commit_gates(REPOSITORY, self.supported)

    def later_collector(self) -> None:
        self.current[0]["target_url"] = PREFIX + "303"

    def test_recorded_success_still_validates_its_collector_run(self) -> None:
        self.verify()
        self.assertIn(f"repos/{REPOSITORY}/actions/runs/101", self.requests)
        self.assertFalse(any("?per_page=" in request for request in self.requests))

    def test_later_success_keeps_original_release_evidence_valid(self) -> None:
        self.later_collector()
        # The later run may have been removed; it is not the release's evidence.
        self.verify()
        self.assertIn(f"repos/{REPOSITORY}/actions/runs/101", self.requests)
        self.assertNotIn(f"repos/{REPOSITORY}/actions/runs/303", self.requests)

    def test_recorded_success_beyond_first_history_page(self) -> None:
        self.later_collector()
        self.history.insert(0, [copy.deepcopy(self.current[0]) for _ in range(100)])
        self.verify()
        self.assertIn(
            f"repos/{REPOSITORY}/commits/{COMMIT}/statuses?per_page=100&page=2",
            self.requests,
        )

    def test_current_failure_pending_or_missing_gate_blocks_historical_success(self) -> None:
        for index in range(2):
            for state in ("failure", "error", "pending", None):
                with self.subTest(context=self.current[index]["context"], state=state):
                    original = copy.deepcopy(self.current)
                    if state is None:
                        self.current.pop(index)
                    else:
                        self.current[index]["state"] = state
                    with self.assertRaisesRegex(SystemExit, "gate is not successful"):
                        self.verify()
                    self.current = original

    def test_other_gates_still_require_the_recorded_latest_url(self) -> None:
        self.current[1]["target_url"] = PREFIX + "404"
        self.history[0].append(self.status(self.packages))
        with self.assertRaisesRegex(SystemExit, "does not match release-state: vaultlink/packages"):
            self.verify()

    def test_missing_wrong_context_failed_or_wrong_url_history_blocks(self) -> None:
        self.later_collector()
        for history in (
            [],
            [{**self.status(self.soak), "context": "vaultlink/packages"}],
            [{**self.status(self.soak), "state": "failure"}],
            [{**self.status(self.soak), "target_url": PREFIX + "404"}],
        ):
            with self.subTest(history=history):
                self.history = [history]
                with self.assertRaisesRegex(SystemExit, "recorded soak success is missing"):
                    self.verify()

    def test_bad_history_and_pagination_exhaustion_fail_closed(self) -> None:
        self.later_collector()
        self.history = [{"statuses": [self.status(self.soak)]}]
        with self.assertRaisesRegex(SystemExit, "history is not a list"):
            self.verify()
        self.history = [[copy.deepcopy(self.current[0]) for _ in range(100)]] * 100
        with self.assertRaisesRegex(SystemExit, "pagination bound"):
            self.verify()

    def test_recorded_url_must_be_canonical_and_in_this_repository(self) -> None:
        for url in (
            "https://github.com/other/VaultLink/actions/runs/101",
            PREFIX + "101/attempts/1", PREFIX + "101?query=1", PREFIX + "0",
        ):
            with self.subTest(url=url):
                self.soak["run_url"] = url
                self.current[0]["target_url"] = url
                with self.assertRaisesRegex(SystemExit, "does not identify a run"):
                    self.verify()

    def test_wrong_commit_workflow_repository_event_or_result_blocks(self) -> None:
        for key, value in (
            ("id", 303), ("html_url", PREFIX + "303"), ("head_sha", "b" * 40),
            ("head_branch", "feature"), ("repository", {"full_name": "other/VaultLink"}),
            ("head_repository", {"full_name": "other/VaultLink"}),
            ("path", ".github/workflows/ci.yml"), ("event", "pull_request"),
            ("status", "in_progress"), ("conclusion", "failure"), ("conclusion", "cancelled"),
        ):
            with self.subTest(key=key, value=value):
                original = self.run
                self.run = {**original, key: value}
                with self.assertRaisesRegex(SystemExit, "recorded soak run does not match"):
                    self.verify()
                self.run = original

    def test_manual_collector_and_workflow_ref_suffix_are_accepted(self) -> None:
        self.run["event"] = "workflow_dispatch"
        self.run["path"] += "@refs/heads/main"
        self.verify()

    def test_missing_recorded_run_cannot_use_later_success(self) -> None:
        self.later_collector()
        def missing_run(command: str, endpoint: str) -> object:
            if endpoint == f"repos/{REPOSITORY}/actions/runs/101":
                raise SystemExit("recorded run lookup failed")
            return self.api(command, endpoint)

        with patch.object(MODULE, "gh_json", side_effect=missing_run):
            with self.assertRaisesRegex(SystemExit, "recorded run lookup failed"):
                MODULE.verify_commit_gates(REPOSITORY, self.supported)


if __name__ == "__main__":
    unittest.main()
