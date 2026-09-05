#!/usr/bin/env python3
"""Exercise corpus integrity, trust boundaries and failure-preserving fuzz stages."""

from __future__ import annotations

from contextlib import redirect_stdout
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CORPUS = load("fuzz_corpus_test", "fuzz-corpus.py")
RUNNER = load("fuzz_runner_test", "run-fuzz-targets.py")
COVERAGE = load("fuzz_coverage_test", "run-fuzz-coverage.py")


class CorpusTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(redirect_stdout(io.StringIO()))
        self.temporary = tempfile.TemporaryDirectory(prefix="vaultlink-fuzz-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "repo"
        (self.root / "fuzz/corpus/alpha").mkdir(parents=True)
        (self.root / "fuzz/corpus/alpha/seed").write_bytes(b"fixed regression")
        (self.root / "fuzz/Cargo.toml").write_text('[[bin]]\nname = "alpha"\n', encoding="utf-8")
        CORPUS.write_json(self.root / "fuzz/corpus-versions.json", {"alpha": 1})

    def fixture(self, name="snapshot", arch="amd64", schema=1, data=b"interesting", attempt=1):
        directory = self.base / name
        digest = CORPUS.add_input(directory / "corpus/alpha", data)
        manifest = {"schema_version": 1, "successful": True, "commit": "a" * 40,
                    "architecture": arch, "run_id": "123", "run_attempt": str(attempt), "toolchain": "nightly-test",
                    "target_names": ["alpha"], "targets": {"alpha": {"input_schema": schema, "files": {digest: len(data)}}}}
        CORPUS.write_json(directory / "manifest.json", manifest)
        return directory

    def test_union_deduplicates_both_architectures_and_preserves_seeds(self):
        amd64 = self.fixture("amd64")
        arm64 = self.fixture("arm64", "arm64")
        destination = self.base / "restored"
        CORPUS.restore(destination, [amd64, arm64], {"kind": "test"}, self.root)
        self.assertEqual({path.read_bytes() for path in CORPUS.files(destination / "alpha")}, {b"interesting", b"fixed regression"})
        self.assertTrue(all(len(path.name) == 64 for path in CORPUS.files(destination / "alpha")))
        self.assertEqual((self.root / "fuzz/corpus/alpha/seed").read_bytes(), b"fixed regression")

    def test_add_input_rejects_dangling_and_existing_digest_symlinks(self):
        data = b"new regression"
        for existing in (False, True):
            with self.subTest(existing=existing):
                destination = self.base / f"runtime-{existing}"
                destination.mkdir()
                outside = self.base / f"outside-{existing}"
                if existing:
                    outside.write_bytes(b"must stay unchanged")
                link = destination / hashlib.sha256(data).hexdigest()
                try:
                    link.symlink_to(outside)
                except OSError as error:
                    if os.name == "nt" and getattr(error, "winerror", None) == 1314:
                        self.skipTest("Windows account lacks the symlink creation privilege")
                    raise
                with self.assertRaisesRegex(ValueError, "symlink"):
                    CORPUS.add_input(destination, data)
                self.assertTrue(link.is_symlink())
                if existing:
                    self.assertEqual(outside.read_bytes(), b"must stay unchanged")
                else:
                    self.assertFalse(outside.exists())

    def test_schema_change_skips_previous_inputs_with_explicit_record(self):
        old = self.fixture(schema=2)
        destination = self.base / "restored"
        CORPUS.restore(destination, [old], {"kind": "test"}, self.root)
        self.assertEqual(len(CORPUS.files(destination / "alpha")), 1)
        self.assertIn("changed input schema", json.loads((destination / "restore.json").read_text())["skipped"][0])

    def test_new_target_gets_seeds_and_target_metadata_must_match_producer_list(self):
        old = self.fixture()
        (self.root / "fuzz/Cargo.toml").write_text('[[bin]]\nname = "alpha"\n[[bin]]\nname = "beta"\n')
        CORPUS.write_json(self.root / "fuzz/corpus-versions.json", {"alpha": 1, "beta": 1})
        (self.root / "fuzz/corpus/beta").mkdir()
        (self.root / "fuzz/corpus/beta/seed").write_bytes(b"new target seed")
        CORPUS.restore(self.base / "restored", [old], {}, self.root)
        self.assertEqual(next((self.base / "restored/beta").iterdir()).read_bytes(), b"new target seed")
        manifest = json.loads((old / "manifest.json").read_text())
        manifest["target_names"].append("missing")
        CORPUS.write_json(old / "manifest.json", manifest)
        with self.assertRaisesRegex(ValueError, "producer target list"):
            CORPUS.validate_snapshot(old)

    def test_corrupt_and_extra_inputs_rejected_before_restore(self):
        original = self.fixture()
        input_path = next((original / "corpus/alpha").iterdir())
        input_path.write_bytes(b"untrusted!!")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            CORPUS.restore(self.base / "restore", [original], {}, self.root)
        self.assertFalse((self.base / "restore").exists())
        input_path.write_bytes(b"interesting")
        (original / "unlisted").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "unlisted"):
            CORPUS.validate_snapshot(original)

    def test_missing_input_and_unsuccessful_snapshot_rejected(self):
        original = self.fixture()
        next((original / "corpus/alpha").iterdir()).unlink()
        with self.assertRaisesRegex(ValueError, "missing or altered"):
            CORPUS.validate_snapshot(original)
        manifest = json.loads((original / "manifest.json").read_text())
        manifest["successful"] = False
        CORPUS.write_json(original / "manifest.json", manifest)
        with self.assertRaisesRegex(ValueError, "unsuccessful"):
            CORPUS.validate_snapshot(original)

    def test_archive_traversal_absolute_paths_and_symlinks_rejected(self):
        for index, name in enumerate(("../escape", "/absolute", "C:/escape", "corpus\\escape", "link")):
            with self.subTest(name=name):
                archive = self.base / f"bad{index}.zip"
                with zipfile.ZipFile(archive, "w") as output:
                    info = zipfile.ZipInfo(name)
                    if name == "link":
                        info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    output.writestr(info, b"outside")
                if name == "corpus\\escape":
                    # ZipInfo normalizes the OS separator on Windows when writing.
                    archive.write_bytes(archive.read_bytes().replace(b"corpus/escape", b"corpus\\escape"))
                with self.assertRaisesRegex(ValueError, "unsafe"):
                    CORPUS.extract_snapshot(archive, self.base / f"output{index}")
        self.assertFalse((self.base / "escape").exists())

    def test_archive_regular_files_round_trip(self):
        fixture = self.fixture()
        archive = self.base / "good.zip"
        with zipfile.ZipFile(archive, "w") as output:
            for path in fixture.rglob("*"):
                if path.is_file():
                    output.write(path, path.relative_to(fixture).as_posix())
        CORPUS.extract_snapshot(archive, self.base / "unpacked")
        self.assertEqual(CORPUS.validate_snapshot(self.base / "unpacked")["run_id"], "123")

    def test_restore_does_not_merge_stale_directory(self):
        destination = self.base / "restored"
        destination.mkdir()
        (destination / "stale").write_text("stale")
        with self.assertRaisesRegex(ValueError, "must be empty"):
            CORPUS.restore(destination, [], {}, self.root)

    def test_snapshot_requires_every_successful_stage(self):
        corpus = self.base / "runtime"
        CORPUS.restore(corpus, [], {}, self.root)
        logs = self.base / "logs"
        summary = {"successful": True, "toolchain": "nightly-test", "corpus_dir": str(corpus.resolve()),
                   "targets": {"alpha": {"exit_code": 0, "completed_stages": ["replay", "fuzz"]}}}
        CORPUS.write_json(logs / "summary.json", summary)
        with self.assertRaisesRegex(ValueError, "did not complete"):
            CORPUS.snapshot(corpus, self.base / "publish", "amd64", logs, self.root)
        summary["targets"]["alpha"]["completed_stages"].append("cmin")
        CORPUS.write_json(logs / "summary.json", summary)
        with patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}):
            CORPUS.snapshot(corpus, self.base / "publish", "amd64", logs, self.root)
        self.assertEqual(CORPUS.validate_snapshot(self.base / "publish")["commit"], "b" * 40)

    def run_fixture(self, **overrides):
        return {"id": 123, "head_branch": "main", "head_sha": "a" * 40, "conclusion": "success",
                "event": "schedule", "head_repository": {"full_name": "owner/repo"}, "workflow_id": 77,
                "run_attempt": 1, **overrides}

    def test_no_prior_artifacts_bootstraps_explicitly(self):
        def api(endpoint):
            if "/runs?" in endpoint:
                return {"workflow_runs": [self.run_fixture()]}
            return {"artifacts": []}
        with patch.object(CORPUS, "gh_json", side_effect=api):
            snapshots, provenance = CORPUS.download_previous("owner/repo", self.base)
        self.assertEqual(snapshots, [])
        self.assertEqual(provenance["kind"], "bootstrap")

    def test_incomplete_architecture_pair_is_error_not_bootstrap(self):
        def api(endpoint):
            if "/runs?" in endpoint:
                return {"workflow_runs": [self.run_fixture()]}
            return {"artifacts": [{"name": "fuzz-corpus-amd64-1", "expired": False}]}
        with patch.object(CORPUS, "gh_json", side_effect=api), self.assertRaisesRegex(ValueError, "incomplete"):
            CORPUS.download_previous("owner/repo", self.base)

    def test_explicit_run_rejects_wrong_workflow_failure_and_pr(self):
        for overrides in ({"workflow_id": 99}, {"conclusion": "failure"}, {"event": "pull_request"},
                          {"head_branch": "feature"}, {"head_repository": {"full_name": "attacker/repo"}}):
            with self.subTest(overrides=overrides):
                def api(endpoint):
                    if endpoint.endswith("workflows/fuzz.yml"):
                        return {"id": 77}
                    return self.run_fixture(**overrides)
                with patch.object(CORPUS, "gh_json", side_effect=api), self.assertRaises(ValueError):
                    CORPUS.download_previous("owner/repo", self.base, "123")

    def test_download_checks_producer_sha_and_attempt(self):
        fixture = self.fixture(attempt=2)
        archive = self.base / "fixture.zip"
        with zipfile.ZipFile(archive, "w") as output:
            for path in fixture.rglob("*"):
                if path.is_file():
                    output.write(path, path.relative_to(fixture).as_posix())
        def api(endpoint):
            if "/runs?" in endpoint:
                return {"workflow_runs": [self.run_fixture(run_attempt=2)]}
            if "/jobs?" in endpoint:
                return {"jobs": [{"name": f"Fuzz all targets ({arch})", "conclusion": "success"} for arch in CORPUS.ARCHITECTURES]}
            return {"artifacts": [{"id": i, "name": f"fuzz-corpus-{arch}-1", "expired": False}
                                  for i, arch in enumerate(CORPUS.ARCHITECTURES)]}
        def download(*args, **kwargs):
            kwargs["stdout"].write(archive.read_bytes())
        temporary = self.base / "download"
        temporary.mkdir()
        with patch.object(CORPUS, "gh_json", side_effect=api), patch.object(CORPUS.subprocess, "run", side_effect=download):
            with self.assertRaisesRegex(ValueError, "provenance"):
                CORPUS.download_previous("owner/repo", temporary)

    def test_download_checks_target_schemas_against_historical_producer(self):
        archives = {}
        for architecture in CORPUS.ARCHITECTURES:
            fixture = self.fixture(architecture, architecture)
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w") as output:
                for path in fixture.rglob("*"):
                    if path.is_file():
                        output.writestr(path.relative_to(fixture).as_posix(), path.read_bytes())
            archives[architecture] = archive.getvalue()
        for schema in (1, 2):
            with self.subTest(schema=schema):
                def api(endpoint):
                    if "/contents/" in endpoint:
                        content = '[[bin]]\nname = "alpha"\n' if "Cargo.toml" in endpoint else json.dumps({"alpha": schema})
                        return {"type": "file", "encoding": "base64", "content": base64.b64encode(content.encode()).decode()}
                    if "/runs?" in endpoint:
                        return {"workflow_runs": [self.run_fixture()]}
                    if "/jobs?" in endpoint:
                        return {"jobs": [{"name": f"Fuzz all targets ({arch})", "conclusion": "success"} for arch in CORPUS.ARCHITECTURES]}
                    return {"artifacts": [{"id": arch, "name": f"fuzz-corpus-{arch}-1", "expired": False} for arch in CORPUS.ARCHITECTURES]}
                def download(command, **kwargs):
                    architecture = command[-1].split("/")[-2]
                    kwargs["stdout"].write(archives[architecture])
                temporary = self.base / f"download-{schema}"
                temporary.mkdir()
                with patch.object(CORPUS, "gh_json", side_effect=api), patch.object(CORPUS.subprocess, "run", side_effect=download):
                    if schema == 1:
                        snapshots, provenance = CORPUS.download_previous("owner/repo", temporary)
                        self.assertEqual(len(snapshots), 2)
                        self.assertEqual(provenance["run_id"], "123")
                    else:
                        with self.assertRaisesRegex(ValueError, "producer commit"):
                            CORPUS.download_previous("owner/repo", temporary)

    def test_partial_rerun_reuses_successful_older_architecture_and_full_rerun_chooses_latest(self):
        def artifact(arch, attempt):
            return {"id": f"{arch}-{attempt}", "name": f"fuzz-corpus-{arch}-{attempt}", "expired": False}
        inputs = [artifact("amd64", 1), artifact("arm64", 1), artifact("arm64", 2)]
        selected = CORPUS.select_artifacts(inputs, 2)
        self.assertEqual({arch: entry["producer_attempt"] for arch, entry in selected.items()}, {"amd64": 1, "arm64": 2})
        inputs.append(artifact("amd64", 2))
        self.assertEqual(CORPUS.select_artifacts(inputs, 2)["amd64"]["producer_attempt"], 2)
        inputs.append(artifact("amd64", 2))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            CORPUS.select_artifacts(inputs, 2)

    def test_artifact_requires_successful_job_in_its_actual_producer_attempt(self):
        endpoints = []
        def api(endpoint):
            endpoints.append(endpoint)
            return {"jobs": [{"name": "Fuzz all targets (amd64)", "conclusion": "success"}]}
        with patch.object(CORPUS, "gh_json", side_effect=api):
            CORPUS.verify_producer_job("owner/repo", 123, 1, "amd64")
            with self.assertRaisesRegex(ValueError, "did not succeed"):
                CORPUS.verify_producer_job("owner/repo", 123, 2, "arm64")
        self.assertIn("/attempts/1/jobs?", endpoints[0])
        self.assertIn("/attempts/2/jobs?", endpoints[1])
        with patch.object(CORPUS, "gh_json", return_value={"jobs": [{"name": "Fuzz all targets (amd64)", "conclusion": "failure"}]}):
            with self.assertRaisesRegex(ValueError, "did not succeed"):
                CORPUS.verify_producer_job("owner/repo", 123, 1, "amd64")

    def test_expiry_fallback_requires_a_fully_expired_pair(self):
        artifacts = [{"name": f"fuzz-corpus-{arch}-1", "expired": True} for arch in CORPUS.ARCHITECTURES]
        self.assertEqual(CORPUS.select_artifacts(artifacts, 1), {})
        with self.assertRaisesRegex(ValueError, "incomplete"):
            CORPUS.select_artifacts(artifacts[:1], 1)
        artifacts[0]["expired"] = False
        with self.assertRaisesRegex(ValueError, "incomplete"):
            CORPUS.select_artifacts(artifacts, 1)

    def test_failed_stage_preserves_exit_code_inputs_and_stops_later_stages(self):
        config = {"toolchain": "test", "fuzz_seconds": 1, "replay_timeout": 5, "cmin_timeout": 5}
        for failure in ("replay", "fuzz", "cmin", None):
            with self.subTest(failure=failure):
                corpus = self.base / f"runtime-{failure}"
                CORPUS.restore(corpus, [], {}, self.root)
                calls = []
                def execute(command, log, timeout, cwd):
                    stage = log.stem
                    calls.append(stage)
                    log.write_text("#32 DONE cov: 7 ft: 12\nstat::number_of_executed_units: 32\nstat::average_exec_per_sec: 16\nstat::peak_rss_mb: 40\n")
                    if stage == "cmin":
                        # Simulate cmin modifying its input even when it fails.
                        for entry in Path(command[5]).iterdir():
                            entry.unlink()
                    return 77 if stage == failure else 0
                with patch.object(RUNNER, "run_command", side_effect=execute):
                    result = RUNNER.run_target("alpha", corpus, self.base / f"logs-{failure}", config, self.root)
                self.assertEqual(result["exit_code"], 77 if failure else 0)
                self.assertEqual(result["failed_stage"], failure)
                expected = ["replay", "fuzz", "cmin"]
                self.assertEqual(calls, expected[:expected.index(failure) + 1] if failure else expected)
                self.assertEqual({entry.read_bytes() for entry in CORPUS.files(corpus / "alpha")}, {b"fixed regression"})
                if failure != "replay":
                    self.assertEqual(result["statistics"]["executions"], 32)

    def test_subprocess_failure_and_timeout_are_not_swallowed(self):
        self.assertEqual(RUNNER.run_command([sys.executable, "-c", "raise SystemExit(77)"], self.base / "exit.log", 5), 77)
        self.assertEqual(RUNNER.run_command([sys.executable, "-c", "import time; time.sleep(30)"], self.base / "timeout.log", 1), 124)
        self.assertIn("exceeded", (self.base / "timeout.log").read_text())

    def test_coverage_scope_excludes_harnesses_and_test_support(self):
        for name in ("src/parser.rs", "src/service/mod.rs", "src/fuzzing.rs", "src/fuzzing/helpers.rs",
                     "src/service/fuzz.rs", "src/tests.rs", "src/tests/fixtures.rs", "src/service_tests.rs",
                     "src/test_support.rs", "src/service/test_support.rs"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("// fixture\n")
        self.assertEqual(COVERAGE.production_sources(self.root), sorted(str((self.root / name).resolve()) for name in ("src/parser.rs", "src/service/mod.rs")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
