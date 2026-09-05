#!/usr/bin/env python3
"""Keep the fuzz target inventory, seed data and CI execution contracts aligned."""

from __future__ import annotations

import importlib.util
from pathlib import Path, PurePosixPath
import re
import shlex
import sys

ROOT = Path(__file__).resolve().parents[1]


def require(text: str, fragment: str, description: str) -> None:
    active = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    if fragment not in active:
        raise ValueError(description)


def check_smoke_docker_assets(text: str) -> None:
    active = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    instructions = active.replace("\\\n", " ").splitlines()
    copies = []
    for instruction in instructions:
        # These files must already exist when the build invokes the policy
        # check, not merely be copied somewhere later in the Dockerfile.
        if "check-supply-chain-policy.sh" in instruction:
            break
        tokens = shlex.split(instruction)
        if tokens and tokens[0].upper() == "COPY":
            copies.append(tokens)
    for source, destinations in (
        (".gitattributes", {".", "/work"}),
        ("fuzz/Cargo.toml", {"fuzz", "fuzz/Cargo.toml", "/work/fuzz", "/work/fuzz/Cargo.toml"}),
        ("fuzz/corpus-versions.json", {"fuzz", "fuzz/corpus-versions.json", "/work/fuzz", "/work/fuzz/corpus-versions.json"}),
        ("fuzz/corpus", {"fuzz/corpus", "/work/fuzz/corpus"}),
    ):
        if not any(source in copy[1:-1] and str(PurePosixPath(copy[-1])) in destinations for copy in copies):
            raise ValueError(f"setup smoke Docker image must COPY {source} into /work before its policy check")


def check(root: Path = ROOT) -> None:
    spec = importlib.util.spec_from_file_location("fuzz_corpus", root / "tools/fuzz-corpus.py")
    assert spec and spec.loader
    corpus = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(corpus)
    names = corpus.targets(root)
    for name in names:
        if not corpus.files(root / "fuzz/corpus" / name):
            raise ValueError(f"missing regression seeds for {name}")
    actual = {path.name for path in (root / "fuzz/corpus").iterdir() if path.is_dir()}
    if actual != set(names):
        raise ValueError("Git corpus directories must match the Cargo target inventory")
    require((root / "Makefile").read_text(),
            "FUZZ_TARGETS = $(shell $(PYTHON) tools/fuzz-corpus.py targets)",
            "Make must discover all Cargo targets through the validated inventory")
    require((root / ".gitattributes").read_text(), "fuzz/corpus/** -text",
            "Git must preserve binary corpus bytes on every host")
    check_smoke_docker_assets((root / "deploy/docker/Dockerfile.setup-smoke").read_text())
    campaign = (root / ".github/workflows/fuzz.yml").read_text()
    smoke = (root / ".github/workflows/fuzz-smoke.yml").read_text()
    coverage = (root / ".github/workflows/fuzz-coverage.yml").read_text()
    for text in (campaign, smoke, coverage):
        require(text, "toolchain: nightly-2026-07-01", "all fuzz jobs must use the reviewed nightly")
        require(text, "cargo install --locked cargo-fuzz --version 0.13.2",
                "all fuzz jobs must use the reviewed cargo-fuzz version")
        if "pull_request_target:" in text:
            raise ValueError("fuzz workflows must not execute pull_request_target code")
    for text in (campaign, smoke):
        require(text, "run: make fuzz-parallel", "campaigns must execute the complete target inventory")
        require(text, "if: always()", "successful and failed campaign evidence must be retained")
    for architecture in ("amd64", "arm64"):
        require(campaign, f"architecture: {architecture}", "release fuzzing must run on both architectures")
    require(campaign, "FUZZ_MAX_TOTAL_TIME: 900", "release campaigns require 900 seconds per target")
    require(campaign, "retention-days: 90", "rolling corpora need 90-day retention")
    require(campaign, 'restore --destination "$FUZZ_CORPUS_DIR" --repository "$GITHUB_REPOSITORY"',
            "release campaigns must restore verified main corpora")
    require(campaign, "python3 tools/fuzz-corpus.py snapshot", "only validated snapshots may be published")
    require(campaign, "name: fuzz-corpus-${{ matrix.architecture }}-${{ github.run_attempt }}",
            "both architecture corpus artifacts must have distinct immutable attempt names")
    require(smoke, "pull_request:", "pull requests must execute fuzzing")
    require(smoke, "FUZZ_MAX_TOTAL_TIME: 30", "PR smoke budget must remain 30 seconds per target")
    require(smoke, "--seed-only", "PR smoke must replay the current Git regression corpus")
    for text in (smoke, coverage):
        if re.search(r"^\s+(?:contents|actions|statuses|packages|id-token):\s*write\s*$", text, re.M):
            raise ValueError("smoke and coverage workflows must have read-only permissions")
    require(coverage, "workflows: [Fuzz release gate]", "coverage must follow the release fuzz producer")
    require(coverage, "branches: [main]", "automatic coverage may consume only main campaigns")
    require(coverage, "ref: ${{ needs.source.outputs.commit }}", "coverage must check out the corpus producer commit")
    require(coverage, '--run-id "$SOURCE_RUN_ID"', "coverage must restore its exact validated corpus run")
    require(coverage, 'test "$conclusion" = success', "coverage must reject unsuccessful producers")
    require(coverage, 'test "$repository" = "$GITHUB_REPOSITORY"', "coverage must reject foreign producers")
    require(coverage, 'test "$branch" = main', "coverage must reject PR and branch producers")
    for path in ("release.yml", "soak-start.yml"):
        text = (root / ".github/workflows" / path).read_text()
        for architecture in ("amd64", "arm64"):
            require(text, f"validate_gate vaultlink/fuzz-600s-{architecture} .github/workflows/fuzz.yml",
                    "release and soak must retain both existing exact-commit fuzz gates")


if __name__ == "__main__":
    try:
        check()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"fuzz policy: {error}", file=sys.stderr)
        raise SystemExit(1)
    print("Fuzz corpus and workflow policy checks passed")
