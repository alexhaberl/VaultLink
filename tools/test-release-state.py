#!/usr/bin/env python3
"""Dependency-free negative tests for qualification manifest/evidence policy."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_state", REPOSITORY / "tools/check-release-state.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

CANONICAL = [
    {"id": "CI-001", "title": "CI contract"},
    {"id": "PERF-001", "title": "Performance contract"},
    {"id": "QUAL-001", "title": "Qualification contract"},
    {"id": "REL-001", "title": "Release contract"},
    {"id": "SEC-001", "title": "Security contract"},
]


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def qualification() -> dict[str, object]:
    return {
        "schema_version": 1,
        "release_version": "0.7.0",
        "release_status": "unreleased",
        "allowed_statuses": ["open", "closed", "accepted"],
        "findings": [
            {**finding, "status": "open", "evidence": ["evidence/proof.txt"]}
            for finding in CANONICAL
        ],
    }


def validate(root: Path, value: dict[str, object]) -> list[str]:
    write_json(root / "release/qualification-0.7.0.json", value)
    errors: list[str] = []
    MODULE.validate_qualification("0.7.0", False, errors)
    return errors


def test_installation_docs() -> None:
    state = json.loads((REPOSITORY / "release/release-state.json").read_text(encoding="utf-8"))
    development = state["development_version"]
    supported = state["supported_version"]
    releases = {entry["version"]: entry for entry in state["releases"]}
    documents = ["README.md", "SECURITY.md", "CHANGELOG.md", "THREAT_MODEL.md",
                 "docs/INSTALLATION.md"]
    documents.extend(entry["checklist"] for entry in releases.values())
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        for name in documents:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text((REPOSITORY / name).read_text(encoding="utf-8"), encoding="utf-8")
        original_root = MODULE.ROOT
        MODULE.ROOT = root
        try:
            def errors() -> list[str]:
                result: list[str] = []
                MODULE.validate_docs(development, supported, releases, result)
                return result

            assert errors() == []
            readme = root / "README.md"
            baseline_readme = readme.read_text(encoding="utf-8")
            readme.write_text(baseline_readme.replace(
                f"The currently supported release is `v{supported}`.",
                "The currently supported release is `v0.0.0`."
            ), encoding="utf-8")
            assert any("README release status" in error for error in errors())
            readme.write_text(baseline_readme, encoding="utf-8")
            readme.write_text(baseline_readme.replace(
                "(docs/INSTALLATION.md#native-package-deployment)", "(docs/MISSING.md)"
            ), encoding="utf-8")
            assert any("must link" in error for error in errors())
            readme.write_text(baseline_readme, encoding="utf-8")

            install = root / "docs/INSTALLATION.md"
            baseline_install = install.read_text(encoding="utf-8")
            for broken, expected in [
                (baseline_install.replace("## Native package deployment", "## Other"), "section is missing"),
                (baseline_install.replace(f"VaultLink {supported} supports", "VaultLink 0.0.0 supports"), "does not use supported_version"),
                (baseline_install.replace(f"vaultlink-release-{supported}.", "vaultlink-release-0.0.0."), "staging example"),
            ]:
                install.write_text(broken, encoding="utf-8")
                assert any(expected in error for error in errors()), expected

            # A later development bump must still reject installation guidance
            # pointing at the unpublished version; fixtures do not pick a real
            # next release version for the repository.
            install.write_text(baseline_install, encoding="utf-8")
            future = "99.0.0"
            current_notice = f"`{development}` is unreleased development. " if development != supported else ""
            readme.write_text(baseline_readme.replace(
                f"Status: {current_notice}", f"Status: `{future}` is unreleased development. "
            ), encoding="utf-8")
            security = root / "SECURITY.md"
            security.write_text(security.read_text(encoding="utf-8").replace(
                f"Release line: {current_notice}", f"Release line: `{future}` is unreleased development. "
            ), encoding="utf-8")
            changelog = root / "CHANGELOG.md"
            changelog.write_text(f"## {future} — Unreleased\n\n" + changelog.read_text(encoding="utf-8"),
                                 encoding="utf-8")
            future_errors: list[str] = []
            MODULE.validate_docs(future, supported, releases, future_errors)
            assert future_errors == [], future_errors
            install.write_text(baseline_install + f"\nInstall {future} instead.\n", encoding="utf-8")
            MODULE.validate_docs(future, supported, releases, future_errors)
            assert any("offers the unreleased version" in error for error in future_errors)
            install.unlink()
            assert errors(), "a missing installation guide must fail closed"
        finally:
            MODULE.ROOT = original_root


def test_lifecycle() -> None:
    published = json.loads((REPOSITORY / "release/release-state.json").read_text(encoding="utf-8"))
    published["development_version"] = published["supported_version"]
    published["releases"] = [entry for entry in published["releases"] if entry["status"] != "unreleased"]
    superseded = next(entry["version"] for entry in published["releases"] if entry["status"] == "superseded")

    def entry(state: dict[str, object], version: str | None = None) -> dict[str, object]:
        return next(item for item in state["releases"]
                    if item["version"] == (version or state["supported_version"]))

    def errors(state: dict[str, object]) -> list[str]:
        result: list[str] = []
        MODULE.validate_state(state, result)
        return result

    assert errors(published) == []

    # Retirement persists across future versions, while all eleven remaining
    # release gates are still required and no comparative pass is recorded.
    patched = copy.deepcopy(published)
    previous = patched["supported_version"]
    patched_version = "99.0.1"
    current = entry(patched)
    current["version"] = patched_version
    current["tag"] = f"v{patched_version}"
    current["required_commit_gates"] = [
        gate for gate in current["required_commit_gates"] if gate["context"] != "vaultlink/performance"
    ]
    current["required_commit_gates"].extend({
        "context": f"vaultlink/nixos-{architecture}", "state": "success",
        "run_url": "https://github.com/example/VaultLink/actions/runs/1",
    } for architecture in ("amd64", "arm64"))
    current["required_commit_gates"].extend({
        "context": f"vaultlink/docker-{architecture}", "state": "success",
        "run_url": "https://github.com/example/VaultLink/actions/runs/1",
    } for architecture in ("amd64", "arm64"))
    patched["development_version"] = patched["supported_version"] = patched_version
    for item in patched["releases"]:
        if item.get("superseded_by") == previous:
            item["superseded_by"] = patched_version
    assert errors(patched) == []
    missing_nixos = copy.deepcopy(patched)
    entry(missing_nixos)["required_commit_gates"] = [
        gate for gate in entry(missing_nixos)["required_commit_gates"]
        if gate["context"] != "vaultlink/nixos-arm64"
    ]
    assert any("gate set is incomplete" in error for error in errors(missing_nixos))
    missing_docker = copy.deepcopy(patched)
    entry(missing_docker)["required_commit_gates"] = [
        gate for gate in entry(missing_docker)["required_commit_gates"]
        if gate["context"] != "vaultlink/docker-arm64"
    ]
    assert any("gate set is incomplete" in error for error in errors(missing_docker))
    current["required_commit_gates"].append({
        "context": "vaultlink/performance", "state": "success",
        "run_url": "https://github.com/example/VaultLink/actions/runs/1",
    })
    assert any("gate set is incomplete or contains extras" in error for error in errors(patched))

    future = copy.deepcopy(published)
    future["development_version"] = "99.0.0"
    future["releases"].insert(0, {
        "version": "99.0.0", "status": "unreleased",
        "checklist": "docs/RELEASE-CHECKLIST-0.7.0.md",
    })
    assert errors(future) == []

    missing = copy.deepcopy(future)
    missing["releases"].pop(0)
    assert any("development_version must identify" in error for error in errors(missing))

    extra_unreleased = copy.deepcopy(future)
    extra_unreleased["development_version"] = extra_unreleased["supported_version"]
    assert any("unreleased entry count" in error for error in errors(extra_unreleased))

    multiple_supported = copy.deepcopy(published)
    entry(multiple_supported, superseded)["status"] = "supported"
    assert any("exactly one release must be supported" in error for error in errors(multiple_supported))

    incorrect_current = copy.deepcopy(published)
    entry(incorrect_current)["status"] = "unreleased"
    assert any("supported_version must identify" in error for error in errors(incorrect_current))

    missing_verification = copy.deepcopy(published)
    entry(missing_verification)["tag_verification"]["verified"] = False
    assert any("valid verification evidence" in error for error in errors(missing_verification))

    missing_gate = copy.deepcopy(published)
    entry(missing_gate)["required_commit_gates"].pop()
    assert any("gate set is incomplete" in error for error in errors(missing_gate))

    for replacement in [superseded, "0.0.1", "99.0.0"]:
        invalid = copy.deepcopy(published)
        entry(invalid, superseded)["superseded_by"] = replacement
        assert errors(invalid), replacement

    cycle = copy.deepcopy(published)
    cycle["releases"].append({
        "version": "0.0.1", "checklist": "docs/RELEASE-CHECKLIST-0.6.0.md",
        "status": "superseded", "superseded_by": superseded, "superseded_at": "2026-09-16",
    })
    entry(cycle, superseded)["superseded_by"] = "0.0.1"
    assert any("replacement must be newer" in error for error in errors(cycle))


def main() -> None:
    test_lifecycle()
    test_installation_docs()
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        write_json(
            root / "release/qualification-findings-0.7.0.json",
            {"schema_version": 1, "release_version": "0.7.0", "findings": CANONICAL},
        )
        proof = root / "evidence/proof.txt"
        proof.parent.mkdir(parents=True)
        proof.write_text("immutable fixture", encoding="utf-8")
        original_root = MODULE.ROOT
        MODULE.ROOT = root
        try:
            valid = qualification()
            assert validate(root, valid) == []

            missing = copy.deepcopy(valid)
            missing["findings"].pop()  # type: ignore[union-attr]
            assert any("canonical manifest" in error for error in validate(root, missing))

            renamed = copy.deepcopy(valid)
            renamed["findings"][0]["title"] = "Renamed"  # type: ignore[index]
            assert any("title differs" in error for error in validate(root, renamed))

            stale = copy.deepcopy(valid)
            stale["findings"][0]["evidence"] = ["evidence/missing.txt"]  # type: ignore[index]
            assert any("does not exist" in error for error in validate(root, stale))

            traversal = copy.deepcopy(valid)
            traversal["findings"][0]["evidence"] = ["../outside.txt"]  # type: ignore[index]
            assert any("repository-relative" in error for error in validate(root, traversal))

            credentials = copy.deepcopy(valid)
            credentials["findings"][0]["evidence"] = ["https://token@example.test/run"]  # type: ignore[index]
            assert any("without credentials" in error for error in validate(root, credentials))

            link = root / "evidence/proof-link.txt"
            try:
                link.symlink_to(proof)
            except OSError:
                pass
            else:
                symlinked = copy.deepcopy(valid)
                symlinked["findings"][0]["evidence"] = ["evidence/proof-link.txt"]  # type: ignore[index]
                assert any("symlink" in error for error in validate(root, symlinked))
        finally:
            MODULE.ROOT = original_root

    print("release-state tests passed")


if __name__ == "__main__":
    main()
