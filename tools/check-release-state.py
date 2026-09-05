#!/usr/bin/env python3
"""Validate release-state, qualification, documentation, and package targets."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
FINDING_ID = re.compile(r"^(CI|PERF|QUAL|REL|SEC)-[0-9]{3}$")


class DuplicateKeyError(ValueError):
    pass


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, json.JSONDecodeError, DuplicateKeyError) as error:
        raise SystemExit(f"release-state policy: cannot read {path.relative_to(ROOT)}: {error}") from error


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def text(path: str, errors: list[str]) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except OSError as error:
        errors.append(f"cannot read {path}: {error}")
        return ""


def release_map(state: dict[str, Any], errors: list[str]) -> dict[str, dict[str, Any]]:
    releases = state.get("releases")
    require(isinstance(releases, list), "releases must be an array", errors)
    result: dict[str, dict[str, Any]] = {}
    if not isinstance(releases, list):
        return result
    for release in releases:
        require(isinstance(release, dict), "every release must be an object", errors)
        if not isinstance(release, dict):
            continue
        version = release.get("version")
        require(isinstance(version, str) and SEMVER.fullmatch(version) is not None,
                f"invalid release version: {version!r}", errors)
        if not isinstance(version, str):
            continue
        require(version not in result, f"duplicate release version: {version}", errors)
        result[version] = release
        require(release.get("status") in {"unreleased", "supported", "withdrawn"},
                f"invalid status for {version}", errors)
        checklist = release.get("checklist")
        require(isinstance(checklist, str) and (ROOT / checklist).is_file(),
                f"missing checklist for {version}", errors)
    return result


def validate_state(state: dict[str, Any], errors: list[str]) -> tuple[str, str, dict[str, dict[str, Any]]]:
    require(state.get("schema_version") == 1, "release-state schema_version must be 1", errors)
    development = state.get("development_version")
    supported = state.get("supported_version")
    require(isinstance(development, str) and SEMVER.fullmatch(development) is not None,
            "development_version must be semantic", errors)
    require(isinstance(supported, str) and SEMVER.fullmatch(supported) is not None,
            "supported_version must be semantic", errors)
    releases = release_map(state, errors)
    if isinstance(development, str):
        require(releases.get(development, {}).get("status") == "unreleased",
                "development_version must identify an unreleased entry", errors)
    if isinstance(supported, str):
        current = releases.get(supported, {})
        require(current.get("status") == "supported",
                "supported_version must identify the supported entry", errors)
        require(current.get("tag") == f"v{supported}", "supported tag is inconsistent", errors)
        require(current.get("immutable") is True, "supported release must be immutable", errors)
        require(current.get("asset_count") == 21, "supported release must contain 21 assets", errors)
        verification = current.get("tag_verification", {})
        require(isinstance(verification, dict) and verification.get("verified") is True
                and verification.get("reason") == "valid",
                "supported tag must have valid verification evidence", errors)
        gates = current.get("required_commit_gates")
        required_contexts = {
            "vaultlink/native-amd64",
            "vaultlink/native-arm64",
            "vaultlink/packages",
            "vaultlink/package-reproducibility",
            "vaultlink/distro-vms",
            "vaultlink/release-candidate-preflight",
            "vaultlink/fuzz-600s-amd64",
            "vaultlink/fuzz-600s-arm64",
            "vaultlink/72h-soak",
            "vaultlink/release-dry-run",
            "vaultlink/release-evidence-preflight",
        }
        observed_contexts: set[str] = set()
        if isinstance(gates, list):
            for gate in gates:
                if not isinstance(gate, dict):
                    continue
                context = gate.get("context")
                if isinstance(context, str):
                    observed_contexts.add(context)
                require(gate.get("state") == "success", f"supported gate is not successful: {context}", errors)
                require(isinstance(gate.get("run_url"), str)
                        and gate["run_url"].startswith("https://github.com/"),
                        f"supported gate lacks a run URL: {context}", errors)
        require(observed_contexts == required_contexts,
                "supported release gate set is incomplete or contains extras", errors)
    require(sum(item.get("status") == "supported" for item in releases.values()) == 1,
            "exactly one release must be supported", errors)
    require(sum(item.get("status") == "unreleased" for item in releases.values()) == 1,
            "exactly one release must be unreleased", errors)
    return str(development or ""), str(supported or ""), releases


def validate_targets(state: dict[str, Any], errors: list[str]) -> None:
    targets = load_json(ROOT / "release/package-targets.json")
    target_rows = targets.get("targets") if isinstance(targets, dict) else None
    expected = state.get("expected_package_assets")
    require(isinstance(expected, int) and expected > 0, "expected_package_assets must be positive", errors)
    require(isinstance(target_rows, list) and len(target_rows) == expected,
            "package-target manifest does not match expected_package_assets", errors)


def canonical_findings(development: str, errors: list[str]) -> list[dict[str, str]]:
    path = ROOT / f"release/qualification-findings-{development}.json"
    manifest = load_json(path)
    require(isinstance(manifest, dict), "qualification finding manifest must be an object", errors)
    if not isinstance(manifest, dict):
        return []
    require(manifest.get("schema_version") == 1,
            "qualification finding manifest schema_version must be 1", errors)
    require(manifest.get("release_version") == development,
            "qualification finding manifest release_version is inconsistent", errors)
    rows = manifest.get("findings")
    require(isinstance(rows, list) and bool(rows),
            "qualification finding manifest must be non-empty", errors)
    if not isinstance(rows, list):
        return []
    canonical: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"id", "title"},
                "canonical finding entries require exactly id and title", errors)
        if not isinstance(row, dict):
            continue
        finding_id = row.get("id")
        title = row.get("title")
        require(isinstance(finding_id, str) and FINDING_ID.fullmatch(finding_id) is not None,
                f"invalid canonical finding ID: {finding_id!r}", errors)
        require(isinstance(title, str) and bool(title.strip()),
                f"invalid canonical finding title: {finding_id!r}", errors)
        if not isinstance(finding_id, str) or not isinstance(title, str):
            continue
        require(finding_id not in seen, f"duplicate canonical finding: {finding_id}", errors)
        seen.add(finding_id)
        canonical.append({"id": finding_id, "title": title})
    categories = {row["id"].split("-", 1)[0] for row in canonical}
    require(categories == {"CI", "PERF", "QUAL", "REL", "SEC"},
            "canonical findings must cover CI, PERF, QUAL, REL, and SEC", errors)
    return canonical


def validate_evidence(value: Any, finding_id: str, errors: list[str]) -> None:
    require(isinstance(value, str) and bool(value),
            f"invalid evidence entry for {finding_id}: {value!r}", errors)
    if not isinstance(value, str) or not value:
        return
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc:
        require(parsed.scheme == "https" and bool(parsed.netloc)
                and parsed.username is None and parsed.password is None,
                f"remote evidence must be an HTTPS URL without credentials for {finding_id}: {value}",
                errors)
        return
    relative = PurePosixPath(value)
    normalized = relative.as_posix()
    valid = (
        normalized == value
        and not relative.is_absolute()
        and bool(relative.parts)
        and all(part not in {"", ".", ".."} for part in relative.parts)
        and "\\" not in value
        and ":" not in relative.parts[0]
    )
    require(valid, f"evidence path must be normalized and repository-relative for {finding_id}: {value}", errors)
    if not valid:
        return
    candidate = ROOT
    for part in relative.parts:
        candidate /= part
        if candidate.is_symlink():
            errors.append(f"evidence path must not traverse a symlink for {finding_id}: {value}")
            return
    try:
        repository = ROOT.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        errors.append(f"evidence path does not exist for {finding_id}: {value}: {error}")
        return
    require(resolved == repository or repository in resolved.parents,
            f"evidence path escapes the repository for {finding_id}: {value}", errors)
    require(resolved.is_file() or resolved.is_dir(),
            f"evidence path is not a file or directory for {finding_id}: {value}", errors)


def validate_qualification(development: str, require_ready: bool, errors: list[str], resolved: frozenset[str] = frozenset()) -> None:
    path = ROOT / f"release/qualification-{development}.json"
    qualification = load_json(path)
    require(isinstance(qualification, dict), "qualification root must be an object", errors)
    if not isinstance(qualification, dict):
        return
    require(qualification.get("schema_version") == 1, "qualification schema_version must be 1", errors)
    require(qualification.get("release_version") == development,
            "qualification release_version does not match development_version", errors)
    require(qualification.get("release_status") == "unreleased",
            "qualification release_status must remain unreleased before publication", errors)
    allowed = qualification.get("allowed_statuses")
    require(allowed == ["open", "closed", "accepted"], "qualification allowed_statuses changed", errors)
    expected_findings = canonical_findings(development, errors)
    expected_by_id = {finding["id"]: finding["title"] for finding in expected_findings}
    expected_order = [finding["id"] for finding in expected_findings]
    findings = qualification.get("findings")
    require(isinstance(findings, list) and findings, "qualification findings must be non-empty", errors)
    seen: set[str] = set()
    open_findings: list[str] = []
    categories: set[str] = set()
    if isinstance(findings, list):
        for finding in findings:
            require(isinstance(finding, dict), "qualification finding must be an object", errors)
            if not isinstance(finding, dict):
                continue
            finding_id = finding.get("id")
            require(isinstance(finding_id, str) and FINDING_ID.fullmatch(finding_id) is not None,
                    f"invalid qualification finding ID: {finding_id!r}", errors)
            if not isinstance(finding_id, str):
                continue
            require(finding_id not in seen, f"duplicate qualification finding: {finding_id}", errors)
            seen.add(finding_id)
            categories.add(finding_id.split("-", 1)[0])
            status = finding.get("status")
            require(status in {"open", "closed", "accepted"},
                    f"invalid status for {finding_id}", errors)
            require(isinstance(finding.get("title"), str) and bool(finding["title"].strip()),
                    f"missing title for {finding_id}", errors)
            require(finding.get("title") == expected_by_id.get(finding_id),
                    f"qualification title differs from canonical finding: {finding_id}", errors)
            evidence = finding.get("evidence")
            require(isinstance(evidence, list), f"evidence must be an array for {finding_id}", errors)
            if isinstance(evidence, list):
                for item in evidence:
                    validate_evidence(item, finding_id, errors)
            if status in {"closed", "accepted"}:
                require(isinstance(evidence, list) and bool(evidence),
                        f"{status} finding lacks evidence: {finding_id}", errors)
            if status == "open" and finding_id not in resolved:
                open_findings.append(finding_id)
    require(categories == {"CI", "PERF", "QUAL", "REL", "SEC"},
            "qualification must cover CI, PERF, QUAL, REL, and SEC findings", errors)
    require(seen == set(expected_order),
            "qualification finding set differs from the canonical manifest", errors)
    if isinstance(findings, list):
        observed_order = [finding.get("id") for finding in findings if isinstance(finding, dict)]
        require(observed_order == expected_order,
                "qualification finding order differs from the canonical manifest", errors)
    if require_ready and open_findings:
        errors.append("release qualification still has open findings: " + ", ".join(open_findings))


def validate_docs(development: str, supported: str, releases: dict[str, dict[str, Any]], errors: list[str]) -> None:
    readme = text("README.md", errors)
    security = text("SECURITY.md", errors)
    changelog = text("CHANGELOG.md", errors)
    threat_model = text("THREAT_MODEL.md", errors)
    require(
        f"Status: `{development}` is unreleased development. The currently supported release is `v{supported}`." in readme,
        "README release status is not derived from release-state", errors)
    require(
        f"Release line: `{development}` is unreleased development. The currently supported release is `{supported}`." in security,
        "SECURITY supported-version statement is not derived from release-state", errors)
    require(f"## {development} — Unreleased" in changelog or re.search(rf"^## {re.escape(development)} — [0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}$", changelog, re.MULTILINE),
            "CHANGELOG lacks the unreleased development heading", errors)
    supported_date = releases.get(supported, {}).get("release_date")
    require(f"## {supported} — {supported_date}" in changelog,
            "CHANGELOG lacks the supported release heading", errors)
    withdrawn = [item for item in releases.values() if item.get("status") == "withdrawn"]
    for item in withdrawn:
        version = item.get("version")
        require(f"## {version} — {item.get('release_date')}" in changelog
                and "Withdrawn and unsupported" in changelog,
                f"CHANGELOG lacks withdrawn status for {version}", errors)
    install_start = readme.find("## 8. Native package deployment")
    install_end = readme.find("\n## 9.", install_start + 1)
    require(install_start >= 0 and install_end > install_start,
            "README native package section is missing", errors)
    if install_start >= 0 and install_end > install_start:
        install = readme[install_start:install_end]
        require(f"VaultLink {supported} supports" in install,
                "README installation section does not use supported_version", errors)
        require(f"vaultlink-release-{supported}." in install,
                "README staging example does not use supported_version", errors)
        require(development not in install,
                "README installation section offers the unreleased version", errors)
    require("RA-10" in threat_model and "Closed historical risks" in threat_model,
            "THREAT_MODEL does not historicize RA-10", errors)
    require("Reconfirmed for 0.7.0" in threat_model,
            "THREAT_MODEL does not reconfirm active residual risks for 0.7.0", errors)
    for version, release in releases.items():
        checklist = text(str(release.get("checklist", "")), errors)
        require(f"# v{version}" in checklist, f"checklist heading does not match {version}", errors)
        require("release/release-state.json" in checklist,
                f"checklist for {version} does not reference release-state", errors)


def load_release_evidence():
    import importlib.util
    spec = importlib.util.spec_from_file_location("release_evidence", ROOT / "tools/release-evidence.py")
    assert spec and spec.loader
    evidence = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(evidence)
    return evidence


def validate_phase(args, errors: list[str]) -> frozenset[str]:
    args.effective_qualification = None
    phase = args.phase
    if args.require_ready and phase == "development":
        phase = "evidence"
    if phase == "development":
        return frozenset()
    if not re.fullmatch(r"[0-9a-f]{40}", args.expected_commit or ""):
        errors.append("release phases require the exact expected commit")
        return frozenset()
    if phase == "candidate":
        return frozenset({"QUAL-001", "QUAL-006"})
    try:
        import tempfile
        evidence = load_release_evidence()
        evidence.PERF._sha256(args.expected_binary_sha256, "expected binary")
        evidence.positive(args.expected_packages_run_id, "expected packages run")
        if args.performance_receipt is None:
            raise evidence.EvidenceError("a verified performance receipt is required")
        receipt, _ = evidence.PERF._read_json(args.performance_receipt)
        evidence.verify_receipt(receipt, args.expected_commit, args.expected_binary_sha256,
                                args.expected_packages_run_id)
        soak_receipt = None
        if phase in {"evidence", "tag"}:
            api = evidence.GitHub(__import__("os").environ.get("GITHUB_REPOSITORY", ""))
            with tempfile.TemporaryDirectory() as temporary:
                soak_receipt = evidence.verify_soak(api, args.expected_commit, args.expected_binary_sha256,
                                     Path(temporary) / "soak")
        if args.output:
            args.effective_qualification = {
                "schema_version": 1, "phase": phase, "commit": args.expected_commit,
                "binary_sha256": args.expected_binary_sha256,
                "packages_run_id": args.expected_packages_run_id,
                "performance_receipt": receipt,
                "soak_receipt": soak_receipt,
                "resolved_findings": ["QUAL-001"] + (["QUAL-006"] if phase != "soak" else []),
            }
        return frozenset({"QUAL-001", "QUAL-006"})
    except (OSError, ValueError, KeyError) as error:
        errors.append(f"release evidence: {error}")
        return frozenset()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("development", "candidate", "soak", "evidence", "tag"), default="development")
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-binary-sha256")
    parser.add_argument("--expected-packages-run-id", type=int)
    parser.add_argument("--performance-receipt", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-ready", action="store_true",
                        help="fail while any qualification finding is open")
    parser.add_argument("--print-supported-version", action="store_true")
    parser.add_argument("--print-development-version", action="store_true")
    args = parser.parse_args()

    state = load_json(ROOT / "release/release-state.json")
    if not isinstance(state, dict):
        raise SystemExit("release-state policy: release-state root must be an object")
    errors: list[str] = []
    development, supported, releases = validate_state(state, errors)
    validate_targets(state, errors)
    resolved = validate_phase(args, errors)
    validate_qualification(development, args.require_ready or args.phase != "development", errors, resolved)
    validate_docs(development, supported, releases, errors)
    if errors:
        for error in errors:
            print(f"release-state policy: {error}", file=sys.stderr)
        return 1
    if args.output and args.effective_qualification is not None:
        import os
        import tempfile
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=args.output.parent, delete=False) as stream:
            try:
                json.dump(args.effective_qualification, stream, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
                stream.close()
                os.replace(stream.name, args.output)
            finally:
                Path(stream.name).unlink(missing_ok=True)
    if args.print_supported_version:
        print(supported)
    elif args.print_development_version:
        print(development)
    else:
        print(f"release state: development={development} supported={supported}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
