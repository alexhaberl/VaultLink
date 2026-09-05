#!/usr/bin/env python3
"""Reject fuzz inventory and CI contract regressions in isolated repositories."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("fuzz_policy_test", ROOT / "tools/check-fuzz-policy.py")
assert SPEC and SPEC.loader
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class FuzzPolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="vaultlink-fuzz-policy-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        # Keep fixtures tied to the real workflow contract while reducing the
        # target inventory to a single seed. No production file is mutated.
        for relative in (
            "tools/fuzz-corpus.py", "Makefile", ".gitattributes",
            ".github/workflows/fuzz.yml", ".github/workflows/fuzz-smoke.yml",
            ".github/workflows/fuzz-coverage.yml", ".github/workflows/release.yml",
            ".github/workflows/soak-start.yml", "deploy/docker/Dockerfile.setup-smoke",
        ):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        (self.root / "fuzz/corpus/alpha").mkdir(parents=True)
        self.seed = self.root / "fuzz/corpus/alpha/regression"
        self.seed.write_bytes(b"\x00\r\n\xffbinary regression")
        (self.root / "fuzz/Cargo.toml").write_text(
            '[[bin]]\nname = "alpha"\npath = "fuzz_targets/alpha.rs"\n', encoding="utf-8")
        (self.root / "fuzz/corpus-versions.json").write_text('{"alpha": 1}\n', encoding="utf-8")

    def reject_edit(self, relative: str, old: str, new: str):
        path = self.root / relative
        original = path.read_text(encoding="utf-8")
        self.assertIn(old, original, f"fixture contract moved: {relative}: {old}")
        path.write_text(original.replace(old, new), encoding="utf-8")
        try:
            with self.assertRaises(ValueError):
                POLICY.check(self.root)
        finally:
            path.write_text(original, encoding="utf-8")

    def test_current_workflow_contract_and_binary_seed_are_valid(self):
        POLICY.check(self.root)
        self.assertEqual(self.seed.read_bytes(), b"\x00\r\n\xffbinary regression")

    def test_empty_input_is_a_valid_regression_seed(self):
        self.seed.write_bytes(b"")
        POLICY.check(self.root)

    def test_manifest_and_schema_inventory_must_match(self):
        versions = self.root / "fuzz/corpus-versions.json"
        for wrong in ({}, {"alpha": 1, "unregistered": 1}, {"renamed": 1}, {"alpha": True}, {"alpha": 0}):
            with self.subTest(versions=wrong):
                versions.write_text(json.dumps(wrong), encoding="utf-8")
                with self.assertRaises(ValueError):
                    POLICY.check(self.root)

    def test_duplicate_manifest_targets_are_rejected(self):
        manifest = self.root / "fuzz/Cargo.toml"
        manifest.write_text(manifest.read_text() + '\n[[bin]]\nname = "alpha"\n', encoding="utf-8")
        with self.assertRaises(ValueError):
            POLICY.check(self.root)

    def test_unregistered_corpus_directory_is_rejected(self):
        (self.root / "fuzz/corpus/stale_target").mkdir()
        with self.assertRaises(ValueError):
            POLICY.check(self.root)

    def test_missing_seed_directory_is_rejected(self):
        self.seed.unlink()
        self.seed.parent.rmdir()
        with self.assertRaises(ValueError):
            POLICY.check(self.root)

    def test_empty_seed_directory_is_rejected(self):
        self.seed.unlink()
        with self.assertRaises(ValueError):
            POLICY.check(self.root)

    def test_make_must_use_the_validated_complete_inventory(self):
        self.reject_edit("Makefile", "FUZZ_TARGETS = $(shell $(PYTHON) tools/fuzz-corpus.py targets)",
                         "FUZZ_TARGETS = alpha")

    def test_binary_seeds_must_disable_git_text_conversion(self):
        for replacement in ("", "fuzz/corpus/** text", "# fuzz/corpus/** -text"):
            with self.subTest(replacement=replacement):
                self.reject_edit(".gitattributes", "fuzz/corpus/** -text", replacement)

    def test_setup_smoke_image_requires_schema_seeds_and_attributes(self):
        dockerfile = "deploy/docker/Dockerfile.setup-smoke"
        for asset in (".gitattributes", "fuzz/corpus-versions.json"):
            with self.subTest(asset=asset):
                self.reject_edit(dockerfile, asset + " ", "")
        self.reject_edit(dockerfile, "COPY fuzz/corpus ./fuzz/corpus", "# COPY fuzz/corpus ./fuzz/corpus")
        self.reject_edit(dockerfile, "COPY fuzz/corpus ./fuzz/corpus", "COPY fuzz/corpus ./wrong-place")

    def test_setup_smoke_assets_must_be_copied_before_the_policy_check(self):
        dockerfile = self.root / "deploy/docker/Dockerfile.setup-smoke"
        original = dockerfile.read_text(encoding="utf-8")
        copy = "COPY fuzz/corpus ./fuzz/corpus"
        self.assertIn(copy, original)
        dockerfile.write_text(original.replace(copy, "") + "\n" + copy + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "before its policy check"):
            POLICY.check(self.root)

    def test_pr_requires_execution_instead_of_compilation(self):
        for replacement in ("run: cargo +nightly-2026-07-01 fuzz build", "run: true", "# run: make fuzz-parallel"):
            with self.subTest(replacement=replacement):
                self.reject_edit(".github/workflows/fuzz-smoke.yml", "run: make fuzz-parallel", replacement)

    def test_pr_trigger_and_current_git_seed_replay_are_required(self):
        self.reject_edit(".github/workflows/fuzz-smoke.yml", "pull_request:", "workflow_dispatch:")
        self.reject_edit(".github/workflows/fuzz-smoke.yml", "--seed-only", "--repository example/repo")

    def test_release_budget_cannot_be_replaced_by_pr_smoke_budget(self):
        for replacement in ("FUZZ_MAX_TOTAL_TIME: 30", "# FUZZ_MAX_TOTAL_TIME: 600"):
            with self.subTest(replacement=replacement):
                self.reject_edit(".github/workflows/fuzz.yml", "FUZZ_MAX_TOTAL_TIME: 600", replacement)
        self.reject_edit(".github/workflows/fuzz-smoke.yml", "FUZZ_MAX_TOTAL_TIME: 30", "FUZZ_MAX_TOTAL_TIME: 1")

    def test_both_native_architecture_release_gates_are_required(self):
        for workflow in ("release.yml", "soak-start.yml"):
            for architecture in ("amd64", "arm64"):
                command = f"validate_gate vaultlink/fuzz-600s-{architecture} .github/workflows/fuzz.yml"
                for replacement in (":", "# " + command):
                    with self.subTest(workflow=workflow, architecture=architecture, replacement=replacement):
                        self.reject_edit(f".github/workflows/{workflow}", command, replacement)

    def test_coverage_must_follow_the_fuzz_producer_and_exact_commit(self):
        changes = (
            ("workflows: [Fuzz release gate]", "workflows: [Fuzz smoke]"),
            ("branches: [main]", "branches: [feature]"),
            ("ref: ${{ needs.source.outputs.commit }}", "ref: main"),
            ('--run-id "$SOURCE_RUN_ID"', ""),
        )
        for old, replacement in changes:
            with self.subTest(fragment=old):
                self.reject_edit(".github/workflows/fuzz-coverage.yml", old, replacement)

    def test_coverage_producer_trust_checks_cannot_be_removed_or_commented(self):
        for command in ('test "$conclusion" = success', 'test "$repository" = "$GITHUB_REPOSITORY"',
                        'test "$branch" = main'):
            for replacement in (":", "# " + command):
                with self.subTest(command=command, replacement=replacement):
                    self.reject_edit(".github/workflows/fuzz-coverage.yml", command, replacement)

    def test_successful_and_failed_execution_evidence_must_be_retained(self):
        for workflow in ("fuzz.yml", "fuzz-smoke.yml"):
            with self.subTest(workflow=workflow):
                self.reject_edit(f".github/workflows/{workflow}", "if: always()", "if: success()")

    def test_pr_and_coverage_permissions_cannot_become_writable(self):
        for workflow in ("fuzz-smoke.yml", "fuzz-coverage.yml"):
            with self.subTest(workflow=workflow):
                self.reject_edit(f".github/workflows/{workflow}", "contents: read", "contents: write")

    def test_pull_request_target_must_not_execute_fuzz_code(self):
        for workflow in ("fuzz.yml", "fuzz-smoke.yml", "fuzz-coverage.yml"):
            with self.subTest(workflow=workflow):
                self.reject_edit(f".github/workflows/{workflow}", "on:\n", "on:\n  pull_request_target:\n")

    def test_reviewed_toolchain_and_cargo_fuzz_version_are_required(self):
        for workflow in ("fuzz.yml", "fuzz-smoke.yml", "fuzz-coverage.yml"):
            for old, new in (("toolchain: nightly-2026-07-01", "toolchain: nightly"),
                             ("cargo-fuzz --version 0.13.2", "cargo-fuzz --version 0.13.3")):
                with self.subTest(workflow=workflow, fragment=old):
                    self.reject_edit(f".github/workflows/{workflow}", old, new)


if __name__ == "__main__":
    unittest.main(verbosity=2)
