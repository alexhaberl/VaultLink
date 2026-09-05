#!/usr/bin/env python3
"""Run bounded corpus replays, mutation campaigns and corpus minimization."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
import codecs
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("fuzz_corpus", ROOT / "tools/fuzz-corpus.py")
assert SPEC and SPEC.loader
CORPUS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CORPUS)

LIVE_OUTPUT_HEARTBEAT_SECONDS = 30


def forward_log(reader, decoder, final: bool = False) -> bool:
    # Read only the bytes already present in this regular file. Unlike a pipe,
    # an inherited stdout descriptor in a descendant cannot keep this read open.
    remaining = os.fstat(reader.fileno()).st_size - reader.tell()
    received = remaining > 0
    while remaining > 0:
        data = reader.read(min(remaining, 64 * 1024))
        if not data:
            break
        remaining -= len(data)
        sys.stdout.write(decoder.decode(data))
    if final:
        sys.stdout.write(decoder.decode(b"", final=True))
    if received or final:
        sys.stdout.flush()
    return received


def wait_with_live_output(process, reader, decoder, timeout: int, started: float) -> int:
    deadline = time.monotonic() + timeout
    last_output = time.monotonic()
    while True:
        if forward_log(reader, decoder):
            last_output = time.monotonic()
        code = process.poll()
        if code is not None:
            return code
        now = time.monotonic()
        if now >= deadline:
            raise subprocess.TimeoutExpired(process.args, timeout)
        if now - last_output >= LIVE_OUTPUT_HEARTBEAT_SECONDS:
            print(f"Fuzz build still running ({now - started:.0f}s elapsed; timeout {timeout}s)", flush=True)
            last_output = now
        interval = min(1, deadline - now, LIVE_OUTPUT_HEARTBEAT_SECONDS - (now - last_output))
        try:
            return process.wait(timeout=interval)
        except subprocess.TimeoutExpired:
            continue


def positive_env(name: str, default: int) -> int:
    value = os.environ.get(name, str(default))
    if not re.fullmatch(r"[1-9][0-9]*", value):
        raise ValueError(f"{name} must be a positive integer")
    return int(value)


def configuration() -> dict:
    return {"toolchain": os.environ.get("FUZZ_NIGHTLY_TOOLCHAIN", "nightly-2026-07-01"),
            "jobs": positive_env("FUZZ_JOBS", 1),
            "codegen_units": positive_env("FUZZ_CODEGEN_UNITS", 1),
            "fuzz_seconds": positive_env("FUZZ_MAX_TOTAL_TIME", 600),
            "replay_timeout": positive_env("FUZZ_REPLAY_TIMEOUT", 120),
            "cmin_timeout": positive_env("FUZZ_CMIN_TIMEOUT", 120),
            "build_timeout": positive_env("FUZZ_BUILD_TIMEOUT", 3600)}


def cargo_command(config: dict, subcommand: str) -> list[str]:
    # cargo-fuzz supplies its own CGU flag after Cargo's profile settings. Use
    # its option consistently so replay and minimization reuse the same build.
    return ["cargo", f"+{config['toolchain']}", "fuzz", subcommand,
            "--codegen-units", str(config["codegen_units"])]


def run_command(command: list[str], log: Path, timeout: int, cwd: Path = ROOT,
                live_output: bool = False) -> int:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8") as output, (log.open("rb") if live_output else nullcontext()) as reader:
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace") if live_output else None
        output.write("Command: " + json.dumps(command) + f"\nTimeout: {timeout}s\n")
        output.flush()
        started = time.monotonic()
        try:
            process = subprocess.Popen(command, cwd=cwd, stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=os.name != "nt")
        except OSError as error:
            output.write(f"Could not start command: {error}\n")
            if live_output:
                output.flush()
                forward_log(reader, decoder, final=True)
            return 127
        try:
            code = wait_with_live_output(process, reader, decoder, timeout, started) if live_output else process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                if os.name != "nt":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                # The command may exit between its deadline and the kill.
                pass
            process.wait()
            code = 124
            output.write(f"\nStage exceeded its {timeout}s wall-clock budget.\n")
        if code < 0:
            code = 128 - code
        output.write(f"\nExit code: {code}; elapsed: {time.monotonic() - started:.3f}s\n")
        if live_output:
            output.flush()
            forward_log(reader, decoder, final=True)
        return code


def corpus_size(directory: Path) -> dict:
    inputs = CORPUS.files(directory)
    return {"files": len(inputs), "bytes": sum(path.stat().st_size for path in inputs)}


def statistics(log: Path) -> dict:
    content = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    patterns = {"executions": r"stat::number_of_executed_units:\s*(\d+)",
                "executions_per_second": r"stat::average_exec_per_sec:\s*(\d+)",
                "peak_rss_mb": r"stat::peak_rss_mb:\s*(\d+)",
                "coverage_edges": r"\bcov:\s*(\d+)", "features": r"\bft:\s*(\d+)"}
    result = {}
    for name, pattern in patterns.items():
        values = re.findall(pattern, content)
        result[name] = int(values[-1]) if values else None
    return result


def run_target(target: str, corpus: Path, logs: Path, config: dict, root: Path = ROOT) -> dict:
    inputs = corpus / target
    target_logs = logs / target
    target_logs.mkdir(parents=True, exist_ok=True)
    for name in ("replay.log", "fuzz.log", "cmin.log", "result.json"):
        (target_logs / name).unlink(missing_ok=True)
    result = {"exit_code": 1, "completed_stages": [], "failed_stage": None,
              "before": corpus_size(inputs), "stages": {}}
    stages = [("replay", [*cargo_command(config, "run"), target, str(inputs), "--", "-runs=0", "-print_final_stats=1"], config["replay_timeout"]),
              ("fuzz", [*cargo_command(config, "run"), target, str(inputs), "--", f"-max_total_time={config['fuzz_seconds']}", "-print_final_stats=1"],
               config["fuzz_seconds"] + config["replay_timeout"])]
    print(f"Starting {target}: replay, {config['fuzz_seconds']}s campaign, minimization", flush=True)
    for stage, command, timeout in stages:
        code = run_command(command, target_logs / f"{stage}.log", timeout, cwd=root)
        result["stages"][stage] = code
        if code:
            result.update(exit_code=code, failed_stage=stage)
            break
        result["completed_stages"].append(stage)
    else:
        result["after_fuzz"] = corpus_size(inputs)
        # cmin replaces its input directory. Keep the original campaign corpus
        # intact on failure or timeout by minimizing only a disposable copy.
        with tempfile.TemporaryDirectory(prefix=f"cmin-{target}-", dir=corpus) as temporary:
            minimized = Path(temporary) / "corpus"
            shutil.copytree(inputs, minimized)
            code = run_command([*cargo_command(config, "cmin"), target, str(minimized), "--", "-print_final_stats=1"],
                               target_logs / "cmin.log", config["cmin_timeout"], cwd=root)
            result["stages"]["cmin"] = code
            if code:
                result.update(exit_code=code, failed_stage="cmin")
            else:
                # Retain pinned regression seeds even when redundant for coverage.
                for seed in CORPUS.files(root / "fuzz/corpus" / target):
                    CORPUS.add_input(minimized, seed.read_bytes())
                CORPUS.files(minimized)
                original = Path(temporary) / "original"
                inputs.rename(original)
                try:
                    minimized.rename(inputs)
                except OSError:
                    original.rename(inputs)
                    raise
                result["completed_stages"].append("cmin")
                result["exit_code"] = 0
    result["after"] = corpus_size(inputs)
    result["statistics"] = statistics(target_logs / "fuzz.log")
    CORPUS.write_json(target_logs / "result.json", result)
    print(f"{target}: exit {result['exit_code']}, corpus {result['before']['files']} -> {result['after']['files']} files", flush=True)
    return result


def write_summary(logs: Path, summary: dict) -> None:
    CORPUS.write_json(logs / "summary.json", summary)
    source = summary.get("restore", {}).get("source", {"kind": "existing-local"})
    lines = ["## Fuzz campaign", "", f"Toolchain: `{summary['toolchain']}`. Corpus source: `{json.dumps(source, sort_keys=True)}`.", "",
             "libFuzzer edges/features are feedback metrics, not source line coverage. Missing statistics are shown as —.", "",
             "| Target | Exit / failed stage | Corpus before → fuzz → minimized | Executions | Exec/s | Edges | Features | Peak RSS MiB |",
             "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for target, result in summary["targets"].items():
        stats = result.get("statistics", {})
        values = [str(stats.get(key)) if stats.get(key) is not None else "—"
                  for key in ("executions", "executions_per_second", "coverage_edges", "features", "peak_rss_mb")]
        counts = [str(result.get(key, {}).get("files", "—")) for key in ("before", "after_fuzz", "after")]
        lines.append(f"| {target} | {result['exit_code']} / {result.get('failed_stage') or '—'} | {' → '.join(counts)} | {' | '.join(values)} |")
    if not summary["successful"]:
        lines.extend(["", "**Campaign failed. This corpus must not be promoted.**"])
    content = "\n".join(lines) + "\n"
    (logs / "summary.md").write_text(content, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as output:
            output.write(content)


def main() -> int:
    config = configuration()
    known = CORPUS.targets()
    selected = sys.argv[1:] or list(known)
    if len(selected) != len(set(selected)) or any(name not in known for name in selected):
        raise ValueError("targets must be distinct names from fuzz/Cargo.toml")
    corpus = Path(os.environ.get("FUZZ_CORPUS_DIR", str(ROOT / ".tmp/fuzz-corpus"))).resolve()
    logs = Path(os.environ.get("FUZZ_LOG_DIR", str(ROOT / ".tmp/fuzz-logs"))).resolve()
    seeds = (ROOT / "fuzz/corpus").resolve()
    if corpus == seeds or seeds in corpus.parents or corpus in seeds.parents:
        raise ValueError("FUZZ_CORPUS_DIR must not overlap the Git seed directory")
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "summary.json").unlink(missing_ok=True)
    if not corpus.exists() or not any(corpus.iterdir()):
        CORPUS.restore(corpus, [], {"kind": "git-seeds"})
    restore_path = corpus / "restore.json"
    provenance = json.loads(restore_path.read_text()) if restore_path.exists() else {}
    for target in selected:
        previous_version = provenance.get("targets", {}).get(target, {}).get("input_schema")
        if previous_version is not None and previous_version != known[target]:
            raise ValueError(f"input schema changed for {target}; restore into a fresh runtime corpus directory")
        (corpus / target).mkdir(parents=True, exist_ok=True)
        for seed in CORPUS.files(ROOT / "fuzz/corpus" / target):
            CORPUS.add_input(corpus / target, seed.read_bytes())
        if not CORPUS.files(corpus / target):
            raise ValueError(f"empty runtime corpus for {target}")
        provenance.setdefault("targets", {})[target] = {"input_schema": known[target], "files": len(CORPUS.files(corpus / target))}
    CORPUS.write_json(restore_path, provenance)
    summary = {"schema_version": 1, "toolchain": config["toolchain"], "corpus_dir": str(corpus),
               "successful": False, "configuration": config, "restore": provenance, "targets": {}}
    print(f"Building fuzz targets with {config['toolchain']}", flush=True)
    code = run_command(cargo_command(config, "build"), logs / "build.log", config["build_timeout"], live_output=True)
    summary["build_exit_code"] = code
    if code:
        write_summary(logs, summary)
        print(f"Fuzz build failed (exit {code}); see {logs / 'build.log'}", file=sys.stderr)
        return code
    with ThreadPoolExecutor(max_workers=config["jobs"]) as executor:
        pending = {target: executor.submit(run_target, target, corpus, logs, config) for target in selected}
        for target, future in pending.items():
            try:
                summary["targets"][target] = future.result()
            except Exception as error:
                summary["targets"][target] = {"exit_code": 1, "failed_stage": "runner", "error": str(error)}
                print(f"Runner error for {target}: {error}", file=sys.stderr)
    summary["successful"] = all(result["exit_code"] == 0 for result in summary["targets"].values())
    write_summary(logs, summary)
    for target, result in summary["targets"].items():
        if result["exit_code"]:
            print(f"{target} failed during {result['failed_stage']} (exit {result['exit_code']}); logs: {logs / target}", file=sys.stderr)
    return next((result["exit_code"] for result in summary["targets"].values() if result["exit_code"]), 0)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError) as error:
        print(f"fuzz runner error: {error}", file=sys.stderr)
        sys.exit(2)
