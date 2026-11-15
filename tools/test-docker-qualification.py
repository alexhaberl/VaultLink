#!/usr/bin/env python3
"""Offline producer-attempt and artifact trust regressions for Docker gates."""

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_evidence", ROOT / "tools/release-evidence.py")
assert SPEC and SPEC.loader
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)
REPOSITORY = "example/VaultLink"
COMMIT = "b" * 40
RUN_ID = 789
VERSION = "0.7.2"
BUILD_STEP = "Build and test the native production image"
UPLOAD_STEP = "Preserve successful qualification receipt"


def archive_bytes(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, value in files.items():
            if isinstance(name, str):
                entry = zipfile.ZipInfo()
                entry.filename = name
            else:
                entry = name
            archive.writestr(entry, value)
    return output.getvalue()


def effective_job(architecture, current_attempt=2, producer_attempt=1):
    minute = "00" if producer_attempt == 1 else "10"
    end_minute = "05" if producer_attempt == 1 else "15"
    started = f"2026-09-05T12:{minute}:00Z"
    completed = f"2026-09-05T12:{end_minute}:00Z"
    return {
        "id": 1000 if architecture == "amd64" else 1001,
        "run_id": RUN_ID,
        "run_attempt": current_attempt,
        "head_sha": COMMIT,
        "name": f"Docker runtime ({architecture})",
        "status": "completed",
        "conclusion": "success",
        "started_at": started,
        "completed_at": completed,
        "steps": [{"name": name, "status": "completed", "conclusion": "success",
                   "started_at": started, "completed_at": completed}
                  for name in (BUILD_STEP, UPLOAD_STEP)],
    }


class FakeGitHub(EVIDENCE.GitHub):
    """Use the production pagination, digest validation and ZIP extraction."""

    def __init__(self, current_attempt=2, producer_attempt=1):
        super().__init__(REPOSITORY)
        self.run_data = {
            "id": RUN_ID, "head_sha": COMMIT, "head_branch": "main",
            "status": "completed", "conclusion": "success",
            "path": EVIDENCE.DOCKER_WORKFLOW, "event": "push",
            "repository": {"full_name": REPOSITORY},
            "head_repository": {"full_name": REPOSITORY},
            "run_attempt": current_attempt,
            "run_started_at": ("2026-09-05T12:00:00Z" if current_attempt == 1
                               else "2026-09-05T12:10:00Z"),
        }
        self.jobs = [effective_job(architecture, current_attempt, producer_attempt)
                     for architecture in ("amd64", "arm64")]
        self.original_jobs = {}
        self.artifacts = []
        self.archives = {}
        self.requests = []
        for architecture in ("amd64", "arm64"):
            self.add_receipt(architecture, producer_attempt)

    def add_receipt(self, architecture, attempt, **changes):
        executions = self.original_jobs.setdefault(attempt, [])
        if not any(job["name"] == f"Docker runtime ({architecture})" for job in executions):
            original = effective_job(architecture, attempt, attempt)
            original["id"] = 2000 + attempt * 10 + (architecture == "arm64")
            executions.append(original)
        receipt = {
            "schema_version": 1, "repository": REPOSITORY, "commit": COMMIT,
            "version": VERSION, "workflow": EVIDENCE.DOCKER_WORKFLOW,
            "event": "push", "architecture": architecture,
            "run_id": RUN_ID, "run_attempt": attempt,
            "binary_sha256": ("a" if architecture == "amd64" else "c") * 64,
            **changes,
        }
        artifact_id = 900 + len(self.artifacts)
        raw = archive_bytes({"qualification.json": json.dumps(receipt)})
        self.archives[artifact_id] = raw
        artifact = {
            "id": artifact_id,
            "name": f"docker-qualification-{architecture}-{COMMIT}-{RUN_ID}-{attempt}",
            "expired": False,
            "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "created_at": ("2026-09-05T12:04:59Z" if attempt == 1
                           else "2026-09-05T12:14:59Z"),
            "workflow_run": {"id": RUN_ID, "head_sha": COMMIT},
        }
        self.artifacts.append(artifact)
        return artifact

    def replace_archive(self, artifact, files):
        raw = archive_bytes(files)
        self.archives[artifact["id"]] = raw
        artifact["digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()

    def edit_receipt(self, artifact, **changes):
        with zipfile.ZipFile(io.BytesIO(self.archives[artifact["id"]])) as source:
            receipt = json.loads(source.read("qualification.json"))
        self.replace_archive(artifact, {"qualification.json": json.dumps({**receipt, **changes})})

    def request(self, suffix, *, raw=False):
        self.requests.append((suffix, raw))
        url = urlsplit(suffix)
        query = parse_qs(url.query)
        if url.path == f"actions/runs/{RUN_ID}":
            return copy.deepcopy(self.run_data)
        if url.path == f"actions/runs/{RUN_ID}/jobs":
            if query.get("filter") != ["latest"]:
                raise AssertionError("qualifications must use effective jobs, not historical successes")
            key, values = "jobs", self.jobs
        elif (url.path.startswith(f"actions/runs/{RUN_ID}/attempts/")
              and url.path.endswith("/jobs")):
            attempt = int(url.path.split("/")[4])
            key, values = "jobs", self.original_jobs.get(attempt, [])
        elif url.path == f"actions/runs/{RUN_ID}/artifacts":
            key, values = "artifacts", self.artifacts
        elif raw and url.path.startswith("actions/artifacts/") and url.path.endswith("/zip"):
            return self.archives[int(url.path.split("/")[2])]
        else:
            raise AssertionError(f"unexpected GitHub request: {suffix}")
        page = int(query.get("page", ["1"])[0])
        per_page = int(query.get("per_page", ["100"])[0])
        start = (page - 1) * per_page
        return {"total_count": len(values), key: copy.deepcopy(values[start:start + per_page])}


class DockerArchitectureQualificationTests(unittest.TestCase):
    def verify(self, api, architecture="amd64"):
        with tempfile.TemporaryDirectory(prefix="vaultlink-docker-receipt-") as directory:
            return EVIDENCE.docker_architecture_qualification(
                api, copy.deepcopy(api.run_data), COMMIT, VERSION,
                architecture, Path(directory) / architecture,
            )

    def test_first_attempt_binds_real_artifact_and_binary_digest(self):
        api = FakeGitHub(current_attempt=1, producer_attempt=1)
        result = self.verify(api)
        self.assertEqual(result["run_attempt"], 1)
        self.assertEqual(result["run_id"], RUN_ID)
        self.assertEqual(result["artifact_id"], 900)
        self.assertEqual(result["binary_sha256"], "a" * 64)
        self.assertEqual(result["artifact_sha256"], api.artifacts[0]["digest"].removeprefix("sha256:"))

    def test_publisher_retry_preserves_the_actual_earlier_producer_attempt(self):
        api = FakeGitHub(current_attempt=2, producer_attempt=1)
        for architecture in ("amd64", "arm64"):
            with self.subTest(architecture=architecture):
                result = self.verify(api, architecture)
                self.assertEqual(result["run_attempt"], 1)
                self.assertTrue(result["artifact_name"].endswith(f"-{RUN_ID}-1"))
        self.assertEqual(api.run_data["run_attempt"], 2)

    def test_one_architecture_retry_uses_its_new_receipt_and_keeps_the_other(self):
        api = FakeGitHub()
        api.jobs[1] = effective_job("arm64", current_attempt=2, producer_attempt=2)
        artifact = api.add_receipt("arm64", 2)
        amd64 = self.verify(api, "amd64")
        arm64 = self.verify(api, "arm64")
        self.assertEqual(amd64["run_attempt"], 1)
        self.assertEqual(arm64["run_attempt"], 2)
        self.assertEqual(arm64["artifact_id"], artifact["id"])

    def test_fresh_unsuccessful_job_cannot_reuse_older_successful_receipt(self):
        for conclusion in ("failure", "cancelled", "skipped", "timed_out"):
            with self.subTest(conclusion=conclusion):
                api = FakeGitHub()
                api.jobs[0] = effective_job("amd64", current_attempt=2, producer_attempt=2)
                api.jobs[0]["conclusion"] = conclusion
                self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)
        api = FakeGitHub()
        api.jobs[0].update(status="in_progress", conclusion=None)
        self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)

    def test_missing_ambiguous_or_unqualified_effective_job_is_rejected(self):
        api = FakeGitHub()
        api.jobs.pop(0)
        self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)
        api = FakeGitHub()
        api.jobs.append({**copy.deepcopy(api.jobs[0]), "id": 1002})
        self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)
        for step in (BUILD_STEP, UPLOAD_STEP):
            for change in ("missing", "failure", "in_progress"):
                with self.subTest(step=step, change=change):
                    api = FakeGitHub()
                    item = next(item for item in api.jobs[0]["steps"] if item["name"] == step)
                    if change == "missing":
                        api.jobs[0]["steps"].remove(item)
                    elif change == "failure":
                        item["conclusion"] = "failure"
                    else:
                        item.update(status="in_progress", conclusion=None)
                    self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)

    def test_artifact_requires_unique_name_even_across_api_pages(self):
        api = FakeGitHub()
        api.artifacts.pop(0)
        self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)
        api = FakeGitHub()
        duplicate = copy.deepcopy(api.artifacts[0])
        duplicate["id"] = 1900
        api.archives[1900] = api.archives[900]
        for number in range(98):
            api.artifacts.append({"id": 2000 + number, "name": f"unrelated-{number}"})
        api.artifacts.append(duplicate)
        self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)
        self.assertTrue(any("page=2" in suffix for suffix, _ in api.requests))

    def test_foreign_or_invalid_effective_job_metadata_is_rejected(self):
        for change in (
            {"run_id": 790}, {"head_sha": "c" * 40},
            {"started_at": "invalid"}, {"completed_at": "invalid"},
            {"started_at": None}, {"started_at": 123},
            {"completed_at": None}, {"completed_at": 123},
            {"started_at": "2026-09-05T12:00:00"},
            {"completed_at": "2026-09-05T11:59:59Z"},
        ):
            with self.subTest(change=change):
                api = FakeGitHub()
                api.jobs[0].update(change)
                self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)

    def test_malformed_run_identity_fields_fail_closed(self):
        for change in ({"path": None}, {"repository": None}, {"head_repository": None}):
            with self.subTest(change=change):
                api = FakeGitHub()
                api.run_data.update(change)
                self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)
                self.assertRaises(EVIDENCE.EvidenceError, api.run,
                                  RUN_ID, COMMIT, EVIDENCE.DOCKER_WORKFLOW)

    def test_old_receipt_cannot_impersonate_a_new_execution_at_rounded_boundary(self):
        api = FakeGitHub()
        api.run_data["run_started_at"] = "2026-09-05T12:05:00Z"
        api.jobs[0] = effective_job("amd64", current_attempt=2, producer_attempt=2)
        started, completed = "2026-09-05T12:05:00Z", "2026-09-05T12:10:00Z"
        api.jobs[0].update(started_at=started, completed_at=completed)
        for step in api.jobs[0]["steps"]:
            step.update(started_at=started, completed_at=completed)
        # The old producer ended in the same API-rounded second that the new
        # execution started. Artifact timing alone cannot distinguish them.
        api.artifacts[0]["created_at"] = "2026-09-05T12:05:00.500Z"
        self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)

    def test_original_producer_job_must_match_the_effective_execution(self):
        for change in (
            {"run_id": 790}, {"head_sha": "c" * 40},
            {"name": "Docker runtime (arm64)"},
            {"status": "in_progress"}, {"conclusion": "failure"},
            {"started_at": "2026-09-05T12:00:01Z"},
            {"completed_at": "2026-09-05T12:05:01Z"},
        ):
            with self.subTest(change=change):
                api = FakeGitHub()
                api.original_jobs[1][0].update(change)
                self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)
        api = FakeGitHub()
        api.original_jobs[1].pop(0)
        self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)
        api = FakeGitHub()
        api.original_jobs[1].append(copy.deepcopy(api.original_jobs[1][0]))
        self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)

    def test_receipt_must_belong_to_effective_job_execution_window(self):
        for created in ("2026-09-05T11:59:59Z", "2026-09-05T12:05:02Z",
                        "2026-09-05T12:14:59Z", "invalid", "2026-09-05T12:04:59",
                        None, 123):
            with self.subTest(created=created):
                api = FakeGitHub()
                api.artifacts[0]["created_at"] = created
                self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)
        api = FakeGitHub()
        api.artifacts[0]["created_at"] = "2026-09-05T12:05:00.900Z"
        self.assertEqual(self.verify(api)["run_attempt"], 1)

    def test_future_zero_and_ambiguous_producer_attempts_are_rejected(self):
        for attempt in (0, 3):
            with self.subTest(attempt=attempt):
                api = FakeGitHub()
                api.artifacts[0]["name"] = f"docker-qualification-amd64-{COMMIT}-{RUN_ID}-{attempt}"
                api.edit_receipt(api.artifacts[0], run_attempt=attempt)
                self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)
        api = FakeGitHub()
        second = api.add_receipt("amd64", 2)
        second["created_at"] = api.artifacts[0]["created_at"]
        self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)

    def test_foreign_expired_and_digest_changed_artifacts_are_rejected(self):
        changes = (
            {"expired": True}, {"expired": 0},
            {"id": True}, {"id": 0},
            {"digest": "sha256:" + "0" * 64}, {"digest": "not-a-digest"},
            {"digest": None}, {"digest": 123}, {"digest": []},
            {"workflow_run": {"id": 790, "head_sha": COMMIT}},
            {"workflow_run": {"id": RUN_ID, "head_sha": "c" * 40}},
        )
        for change in changes:
            with self.subTest(change=change):
                api = FakeGitHub()
                api.artifacts[0].update(change)
                self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)
        api = FakeGitHub()
        api.archives[900] += b"changed download"
        self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)

    def test_receipt_strict_identity_and_numeric_types_are_enforced(self):
        for field, value in (
            ("schema_version", True), ("run_id", True), ("run_attempt", True),
            ("run_attempt", 2), ("repository", "attacker/fork"),
            ("commit", "c" * 40), ("version", "0.7.1"),
            ("workflow", ".github/workflows/other.yml"), ("event", "pull_request"),
            ("architecture", "arm64"), ("binary_sha256", "A" * 64),
            ("binary_sha256", False), ("unexpected", "field"),
        ):
            with self.subTest(field=field, value=value):
                api = FakeGitHub()
                api.edit_receipt(api.artifacts[0], **{field: value})
                self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)

    def test_missing_malformed_and_unsafe_archive_receipts_are_rejected(self):
        for files in ({"other.json": "{}"}, {"qualification.json": "[1, 2]"},
                      {"qualification.json": "{"}, {"qualification.json": "{}"}):
            with self.subTest(files=files):
                api = FakeGitHub()
                api.replace_archive(api.artifacts[0], files)
                self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)
        for name in ("../escape", "/absolute", "C:/escape", "a\\b"):
            with self.subTest(name=name):
                api = FakeGitHub()
                with zipfile.ZipFile(io.BytesIO(api.archives[900])) as archive:
                    receipt = archive.read("qualification.json")
                api.replace_archive(api.artifacts[0], {"qualification.json": receipt, name: "unsafe"})
                self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)
        api = FakeGitHub()
        link = zipfile.ZipInfo("qualification.json")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        api.replace_archive(api.artifacts[0], {link: "../outside"})
        self.assertRaises(EVIDENCE.EvidenceError, self.verify, api)


if __name__ == "__main__":
    unittest.main()
