#!/usr/bin/env python3
"""Fail closed when a native-load runner cannot sustain SQLite WAL I/O."""

from __future__ import annotations

import math
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import threading
import time


STORAGE_ROOT = Path("/mnt/storage")
PROBE_NAME = ".vaultlink-storage-qualification"
WRITER_THREADS = 4
TRANSACTIONS_PER_WRITER = 32
MINIMUM_READER_QUERIES = 256
WRITER_P95_LIMIT_MS = 1_000.0
WRITER_MAX_LIMIT_MS = 5_000.0
READER_P95_LIMIT_MS = 250.0
READER_MAX_LIMIT_MS = 2_000.0
CHECKPOINT_LIMIT_MS = 5_000.0
WALL_LIMIT_MS = 30_000.0


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * fraction) - 1)
    return ordered[index]


def write_evidence(path: Path, fields: list[tuple[str, object]]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("x", encoding="ascii", newline="\n") as handle:
        for key, value in fields:
            handle.write(f"{key}={value}\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} /mnt/storage EVIDENCE", file=sys.stderr)
        return 64

    storage = Path(sys.argv[1])
    evidence = Path(sys.argv[2])
    if storage != STORAGE_ROOT or storage.resolve() != STORAGE_ROOT:
        print("storage qualification requires the exact /mnt/storage mount", file=sys.stderr)
        return 64
    storage_metadata = storage.lstat()
    if not stat.S_ISDIR(storage_metadata.st_mode) or stat.S_ISLNK(storage_metadata.st_mode):
        print("storage qualification root is unsafe", file=sys.stderr)
        return 1
    if storage_metadata.st_uid != 0:
        print("storage qualification root is not root-owned", file=sys.stderr)
        return 1
    if next(storage.iterdir(), None) is not None:
        print("storage qualification requires an empty server volume", file=sys.stderr)
        return 1

    evidence_parent = evidence.parent.resolve()
    if (
        evidence.name != "storage-qualification.env"
        or evidence_parent != evidence.parent
        or not str(evidence_parent).startswith("/work/offline-smoke/")
        or evidence_parent.name != "native-load"
        or evidence.exists()
        or evidence.is_symlink()
    ):
        print("storage qualification evidence path is unsafe", file=sys.stderr)
        return 64

    probe = storage / PROBE_NAME
    probe.mkdir(mode=0o700)
    database_path = probe / "probe.sqlite"
    write_durations: list[float] = []
    read_durations: list[float] = []
    errors: list[str] = []
    result_lock = threading.Lock()
    writers_done = 0
    barrier = threading.Barrier(WRITER_THREADS + 2)
    wall_started = time.monotonic_ns()

    def connect() -> sqlite3.Connection:
        connection = sqlite3.connect(
            database_path,
            isolation_level=None,
            timeout=5.0,
        )
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA wal_autocheckpoint=32")
        return connection

    setup = sqlite3.connect(database_path, isolation_level=None, timeout=5.0)
    journal_mode = setup.execute("PRAGMA journal_mode=WAL").fetchone()[0]
    setup.execute("PRAGMA synchronous=FULL")
    setup.execute("PRAGMA wal_autocheckpoint=32")
    synchronous_mode = setup.execute("PRAGMA synchronous").fetchone()[0]
    setup.execute(
        "CREATE TABLE probe (id INTEGER PRIMARY KEY, writer INTEGER NOT NULL, "
        "sequence INTEGER NOT NULL, payload BLOB NOT NULL)"
    )
    setup.close()

    def writer(writer_id: int) -> None:
        nonlocal writers_done
        connection: sqlite3.Connection | None = None
        try:
            connection = connect()
            payload = bytes([writer_id + 1]) * 4096
            barrier.wait()
            for sequence in range(TRANSACTIONS_PER_WRITER):
                started = time.monotonic_ns()
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO probe(writer,sequence,payload) VALUES(?,?,?)",
                    (writer_id, sequence, payload),
                )
                connection.execute("COMMIT")
                elapsed_ms = (time.monotonic_ns() - started) / 1_000_000
                with result_lock:
                    write_durations.append(elapsed_ms)
        except BaseException as error:  # evidence must include thread failures
            barrier.abort()
            if connection is not None:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            with result_lock:
                errors.append(f"writer_{writer_id}:{type(error).__name__}")
        finally:
            if connection is not None:
                connection.close()
            with result_lock:
                writers_done += 1

    def reader() -> None:
        connection: sqlite3.Connection | None = None
        try:
            connection = connect()
            barrier.wait()
            while True:
                started = time.monotonic_ns()
                connection.execute(
                    "SELECT COUNT(*),COALESCE(SUM(length(payload)),0) FROM probe"
                ).fetchone()
                elapsed_ms = (time.monotonic_ns() - started) / 1_000_000
                with result_lock:
                    read_durations.append(elapsed_ms)
                    finished = writers_done == WRITER_THREADS
                    enough_reads = len(read_durations) >= MINIMUM_READER_QUERIES
                if finished and enough_reads:
                    break
                time.sleep(0.001)
        except BaseException as error:
            barrier.abort()
            with result_lock:
                errors.append(f"reader:{type(error).__name__}")
        finally:
            if connection is not None:
                connection.close()

    threads = [
        threading.Thread(target=writer, args=(index,), daemon=True)
        for index in range(WRITER_THREADS)
    ]
    threads.append(threading.Thread(target=reader, daemon=True))
    for thread in threads:
        thread.start()
    try:
        barrier.wait()
    except threading.BrokenBarrierError:
        with result_lock:
            errors.append("probe:BrokenBarrierError")
    join_deadline = time.monotonic() + WALL_LIMIT_MS / 1_000
    for thread in threads:
        thread.join(timeout=max(0.0, join_deadline - time.monotonic()))
    threads_alive = any(thread.is_alive() for thread in threads)
    if threads_alive:
        errors.append("probe:Timeout")

    checkpoint_ms = WALL_LIMIT_MS
    integrity = "unavailable"
    row_count = -1
    checkpoint_busy = -1
    try:
        if threads_alive:
            raise sqlite3.OperationalError("probe threads did not terminate")
        verification = connect()
        checkpoint_started = time.monotonic_ns()
        checkpoint_busy, _, _ = verification.execute(
            "PRAGMA wal_checkpoint(TRUNCATE)"
        ).fetchone()
        checkpoint_ms = (time.monotonic_ns() - checkpoint_started) / 1_000_000
        integrity = verification.execute("PRAGMA integrity_check").fetchone()[0]
        row_count = verification.execute("SELECT COUNT(*) FROM probe").fetchone()[0]
        verification.close()
    except sqlite3.Error as error:
        errors.append(f"verification:{type(error).__name__}")

    wall_ms = (time.monotonic_ns() - wall_started) / 1_000_000
    expected_writes = WRITER_THREADS * TRANSACTIONS_PER_WRITER
    writer_p95_ms = percentile(write_durations, 0.95) if write_durations else WALL_LIMIT_MS
    writer_max_ms = max(write_durations, default=WALL_LIMIT_MS)
    reader_p95_ms = percentile(read_durations, 0.95) if read_durations else WALL_LIMIT_MS
    reader_max_ms = max(read_durations, default=WALL_LIMIT_MS)
    passed = (
        not errors
        and journal_mode == "wal"
        and synchronous_mode == 2
        and len(write_durations) == expected_writes
        and row_count == expected_writes
        and len(read_durations) >= MINIMUM_READER_QUERIES
        and checkpoint_busy == 0
        and integrity == "ok"
        and writer_p95_ms < WRITER_P95_LIMIT_MS
        and writer_max_ms < WRITER_MAX_LIMIT_MS
        and reader_p95_ms < READER_P95_LIMIT_MS
        and reader_max_ms < READER_MAX_LIMIT_MS
        and checkpoint_ms < CHECKPOINT_LIMIT_MS
        and wall_ms < WALL_LIMIT_MS
    )
    fields: list[tuple[str, object]] = [
        ("qualification", "pass" if passed else "fail"),
        ("sqlite_version", sqlite3.sqlite_version),
        ("journal_mode", journal_mode),
        ("synchronous", "FULL" if synchronous_mode == 2 else synchronous_mode),
        ("writer_threads", WRITER_THREADS),
        ("writer_transactions", len(write_durations)),
        ("writer_transactions_expected", expected_writes),
        ("writer_p95_ms", f"{writer_p95_ms:.3f}"),
        ("writer_p95_limit_ms", f"{WRITER_P95_LIMIT_MS:.3f}"),
        ("writer_max_ms", f"{writer_max_ms:.3f}"),
        ("writer_max_limit_ms", f"{WRITER_MAX_LIMIT_MS:.3f}"),
        ("reader_queries", len(read_durations)),
        ("reader_queries_minimum", MINIMUM_READER_QUERIES),
        ("reader_p95_ms", f"{reader_p95_ms:.3f}"),
        ("reader_p95_limit_ms", f"{READER_P95_LIMIT_MS:.3f}"),
        ("reader_max_ms", f"{reader_max_ms:.3f}"),
        ("reader_max_limit_ms", f"{READER_MAX_LIMIT_MS:.3f}"),
        ("checkpoint_busy", checkpoint_busy),
        ("checkpoint_ms", f"{checkpoint_ms:.3f}"),
        ("checkpoint_limit_ms", f"{CHECKPOINT_LIMIT_MS:.3f}"),
        ("wall_ms", f"{wall_ms:.3f}"),
        ("wall_limit_ms", f"{WALL_LIMIT_MS:.3f}"),
        ("rows", row_count),
        ("integrity_check", integrity),
        ("error_count", len(errors)),
        ("error_classes", ",".join(sorted(errors)) if errors else "none"),
    ]
    write_evidence(evidence, fields)

    if not threads_alive:
        shutil.rmtree(probe)
        storage_descriptor = os.open(storage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(storage_descriptor)
        finally:
            os.close(storage_descriptor)

    if not passed:
        print("native-load SQLite WAL storage qualification failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
