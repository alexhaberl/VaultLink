#!/usr/bin/env python3
"""Produce AMD64 source coverage from restored corpora, separately from fuzz gates."""

from __future__ import annotations

import html
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("fuzz_runner", ROOT / "tools/run-fuzz-targets.py")
assert SPEC and SPEC.loader
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def export_report(command: list[str], output: Path, log: Path) -> None:
    with output.open("w", encoding="utf-8") as destination, log.open("a", encoding="utf-8") as errors:
        subprocess.run(command, cwd=ROOT, stdout=destination, stderr=errors, check=True, timeout=180)


def production_sources(root: Path = ROOT) -> list[str]:
    return sorted(str(path.resolve()) for path in (root / "src").rglob("*.rs")
                  if path.name not in ("fuzz.rs", "fuzzing.rs", "tests.rs", "test.rs")
                  and not path.stem.startswith("test_")
                  and not path.stem.endswith(("_tests", "_test", "_test_support"))
                  and not {"fuzzing", "tests"}.intersection(path.relative_to(root / "src").parts))


def main() -> int:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("this report measures native Linux AMD64 coverage; use the AMD64 coverage job")
    toolchain = os.environ.get("FUZZ_NIGHTLY_TOOLCHAIN", "nightly-2026-07-01")
    corpus = Path(os.environ.get("FUZZ_CORPUS_DIR", str(ROOT / ".tmp/fuzz-corpus"))).resolve()
    output = Path(os.environ.get("FUZZ_COVERAGE_DIR", str(ROOT / ".tmp/fuzz-coverage"))).resolve()
    timeout = RUNNER.positive_env("FUZZ_COVERAGE_TIMEOUT", 900)
    build_timeout = RUNNER.positive_env("FUZZ_BUILD_TIMEOUT", 2400)
    jobs = RUNNER.positive_env("FUZZ_JOBS", 2)
    known = RUNNER.CORPUS.targets()
    selected = sys.argv[1:] or list(known)
    if len(set(selected)) != len(selected) or any(target not in known for target in selected):
        raise ValueError("coverage targets must be distinct names from fuzz/Cargo.toml")
    rustc = ["rustc", f"+{toolchain}"]
    sysroot = Path(subprocess.check_output([*rustc, "--print", "sysroot"], text=True, timeout=30).strip())
    details = subprocess.check_output([*rustc, "-vV"], text=True, timeout=30)
    triple = next(line.removeprefix("host: ") for line in details.splitlines() if line.startswith("host: "))
    llvm_cov = sysroot / "lib/rustlib" / triple / "bin/llvm-cov"
    if not llvm_cov.is_file():
        raise ValueError(f"install llvm-tools-preview for {toolchain}")
    production = production_sources()
    if not production:
        raise ValueError("no production Rust source files found")
    output.mkdir(parents=True, exist_ok=True)
    build = ROOT / ".tmp/fuzz-coverage-build"
    summary = {"schema_version": 1, "architecture": "amd64", "toolchain": toolchain,
               "scope": "production src/**/*.rs excluding fuzz-only helper modules, per target; no cross-architecture profile merge", "targets": {}}
    provenance = corpus / "restore.json"
    if provenance.exists():
        summary["restore"] = json.loads(provenance.read_text())
    markdown = ["## Fuzz source coverage (AMD64)", "", "Each target replays the restored input corpus; source metrics cover Rust files under `src/`, excluding fuzz-only helper modules.",
                "Corpora from both architectures may contribute inputs. All profiles are generated on AMD64.", "",
                "| Target | Exit | Lines hit / total | Functions hit / total | Regions hit / total |", "| --- | --- | --- | --- | --- |"]
    links = []
    for index, target in enumerate(selected):
        RUNNER.CORPUS.files(corpus / target)
        target_output = output / target
        target_output.mkdir(parents=True, exist_ok=True)
        print(f"Generating source coverage for {target}", flush=True)
        code = RUNNER.run_command(["cargo", f"+{toolchain}", "fuzz", "coverage", "--target-dir", str(build),
                                   "--strip-dead-code=false", "--jobs", str(jobs), target, str(corpus / target),
                                   "--", "-print_final_stats=1"], target_output / "coverage.log", timeout + (build_timeout if index == 0 else 0))
        result = {"exit_code": code}
        if code == 0:
            binary = build / triple / "release" / target
            profile = ROOT / "fuzz/coverage" / target / "coverage.profdata"
            base = [str(llvm_cov), "export", str(binary), f"-instr-profile={profile}"]
            try:
                export_report([*base, "-format=lcov", *production], target_output / "coverage.lcov", target_output / "reports.log")
                export_report([*base, "-summary-only", *production], target_output / "summary.json", target_output / "reports.log")
                export_report([str(llvm_cov), "report", str(binary), f"-instr-profile={profile}", *production],
                              target_output / "summary.txt", target_output / "reports.log")
                export_report([str(llvm_cov), "show", str(binary), f"-instr-profile={profile}", "-format=html",
                               f"-output-dir={target_output / 'html'}", *production],
                              target_output / "html.log", target_output / "reports.log")
                data = json.loads((target_output / "summary.json").read_text())
                modules = []
                for unit in data["data"]:
                    for entry in unit["files"]:
                        filename = Path(entry["filename"]).resolve()
                        if str(filename) in production:
                            modules.append({"file": filename.relative_to(ROOT).as_posix(), **entry["summary"]})
                if not modules:
                    raise ValueError("coverage export contains no production module records")
                RUNNER.CORPUS.write_json(target_output / "modules.json", modules)
                totals = {name: {key: sum(module[name][key] for module in modules) for key in ("covered", "count")}
                          for name in ("lines", "functions", "regions")}
                result["production_totals"] = totals
                ratios = [f"{totals[name]['covered']} / {totals[name]['count']}" for name in ("lines", "functions", "regions")]
                markdown.append(f"| {target} | 0 | {' | '.join(ratios)} |")
                links.append(f'<li><a href="{html.escape(target)}/html/index.html">{html.escape(target)}</a></li>')
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                result.update(exit_code=1, error=str(error))
                print(f"Coverage report failed for {target}: {error}", file=sys.stderr)
        if result["exit_code"]:
            markdown.append(f"| {target} | {result['exit_code']} | — | — | — |")
        summary["targets"][target] = result
        RUNNER.CORPUS.write_json(output / "summary.json", summary)
    summary["successful"] = all(result["exit_code"] == 0 for result in summary["targets"].values())
    RUNNER.CORPUS.write_json(output / "summary.json", summary)
    (output / "index.html").write_text('<!doctype html><html lang="en"><meta charset="utf-8"><title>VaultLink fuzz coverage</title>'
                                      '<h1>Fuzz source coverage — AMD64</h1><p>Production Rust modules, per target.</p><ul>'
                                      + "".join(links) + "</ul></html>\n", encoding="utf-8")
    content = "\n".join(markdown) + "\n"
    (output / "summary.md").write_text(content, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as destination:
            destination.write(content)
    return next((result["exit_code"] for result in summary["targets"].values() if result["exit_code"]), 0)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"fuzz coverage error: {error}", file=sys.stderr)
        sys.exit(1)
