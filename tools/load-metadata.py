#!/usr/bin/env python3
"""Run the metadata clients with the distro's libcurl, without per-request exec.

Only the load generator changes: each exchange uses a fresh HTTP connection.
Each client has its own process and libcurl easy handle, retained for 20 requests.
Independent interpreters keep Python callbacks from serializing unrelated I/O.
See https://curl.se/libcurl/c/threadsafe.html . No third-party Python module or
build step is needed on the immutable guest or the soak host.
"""

import ctypes as C
import ctypes.util
import multiprocessing
import os
from pathlib import Path
import re
import signal
import sys
import time


class CurlFailure(Exception):
    """A numeric library error; never include a URL or raw libcurl error."""


CALLBACK = C.CFUNCTYPE(C.c_size_t, C.c_void_p, C.c_size_t, C.c_size_t, C.c_void_p)
PROGRESS = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_int64, C.c_int64, C.c_int64, C.c_int64)


class Curl:
    def __init__(self, library):
        if not library:
            raise CurlFailure("libcurl is unavailable")
        self.lib = C.CDLL(library)
        # getinfo only copies fields from this client's completed handle.
        # No other client shares this interpreter or its callback execution.
        self.info_lib = C.PyDLL(library)
        signatures = {
            "global_init": (C.c_int, [C.c_long]),
            "global_cleanup": (None, []),
            "easy_init": (C.c_void_p, []),
            "easy_perform": (C.c_int, [C.c_void_p]),
            "easy_cleanup": (None, [C.c_void_p]),
            # Only the fixed arguments of these two variadic C APIs are listed.
            "easy_setopt": (C.c_int, [C.c_void_p, C.c_int]),
            "easy_getinfo": (C.c_int, [C.c_void_p, C.c_int]),
            "slist_append": (C.c_void_p, [C.c_void_p, C.c_char_p]),
            "slist_free_all": (None, [C.c_void_p]),
        }
        for name, (result, arguments) in signatures.items():
            library_api = self.info_lib if name == "easy_getinfo" else self.lib
            function = getattr(library_api, "curl_" + name)
            function.restype, function.argtypes = result, arguments
            setattr(self, name, function)
        self.check(self.global_init(3))

    @staticmethod
    def check(code):
        if code:
            raise CurlFailure(f"libcurl API returned code {code}")

    def option(self, easy, option, value):
        if isinstance(value, int):
            value = C.c_long(value)
        elif isinstance(value, bytes):
            value = C.c_char_p(value)
        self.check(self.easy_setopt(easy, option, value))

    def info(self, easy, key, kind):
        result = kind()
        self.check(self.easy_getinfo(easy, key, C.byref(result)))
        return result.value


class Client:
    def __init__(self, curl, work, index, url, connect_timeout, request_timeout):
        self.curl, self.work, self.index = curl, work, index
        self.identity = f"198.18.1.{index + 1}"
        self.attempts = self.completed = self.started = self.retries = 0
        self.failed = False
        self.ready_at = 0.0
        self.max_pretransfer_gap = 0.0
        self.header_bytes = 0
        self.retry_headers = []
        self.easy = curl.easy_init()
        self.headers = None
        if not self.easy:
            raise CurlFailure("libcurl handle allocation failed")
        self.body_callback = CALLBACK(lambda _data, size, count, _context: size * count)
        self.header_callback = CALLBACK(self.header)
        self.results = self.capacity = None
        try:
            self.results = (work / f"metadata-{index}.csv").open("w", encoding="ascii")
            self.capacity = (work / f"capacity-retry-client-{index}.csv").open("w", encoding="ascii")
            self.headers = curl.slist_append(None, f"X-Forwarded-For: {self.identity}".encode("ascii"))
            if not self.headers:
                raise CurlFailure("libcurl header allocation failed")
            # CURLOPT_URL, HTTPHEADER, WRITEFUNCTION, HEADERFUNCTION, INTERFACE,
            # CONNECTTIMEOUT, TIMEOUT, NOSIGNAL, FRESH_CONNECT and FORBID_REUSE.
            for option, value in (
                (10002, url.encode("ascii")), (10023, C.c_void_p(self.headers)),
                (20011, self.body_callback), (20079, self.header_callback),
                (10062, b"127.0.0.1"), (78, connect_timeout), (13, request_timeout),
                (99, 1), (74, 1), (75, 1),
            ):
                curl.option(self.easy, option, value)
        except BaseException:
            self.close()
            raise

    def header(self, pointer, size, count, _context):
        length = size * count
        self.header_bytes += length
        if self.header_bytes > 65536:
            return 0
        line = C.string_at(pointer, length).rstrip(b"\r\n")
        if line.startswith(b"HTTP/"):
            self.retry_headers.clear()
        elif line.lower().startswith(b"retry-after:"):
            self.retry_headers.append(line.partition(b":")[2].strip())
        return length

    def perform(self):
        self.attempts += 1
        self.started = self.completed + 1
        self.header_bytes = 0
        self.retry_headers.clear()
        # CDLL releases the GIL during libcurl's blocking I/O. No handle is ever
        # accessed by two workers, and the main thread cleans up only after join.
        self.started_epoch = time.time()
        code = self.curl.easy_perform(self.easy)
        self.ended_epoch = time.time()
        return code

    def diagnostic(self, code, status, duration):
        curl = self.curl
        fields = {"http_status": f"{status:03}", "total_seconds": f"{duration:.6f}"}
        for name, key in (("connect_seconds", 5), ("pretransfer_seconds", 6), ("first_byte_seconds", 17)):
            fields[name] = f"{curl.info(self.easy, 0x300000 + key, C.c_double):.6f}"
        for name, key in (("download_bytes", 8), ("upload_bytes", 7)):
            fields[name] = curl.info(self.easy, 0x600000 + key, C.c_int64)
        for name, key in (("local_port", 42), ("remote_port", 40)):
            fields[name] = curl.info(self.easy, 0x200000 + key, C.c_long)
        record = (f"operation=metadata client={self.index} request={self.started} "
                  f"identity={self.identity} curl_exit={code} started_epoch={self.started_epoch:.6f} "
                  f"ended_epoch={self.ended_epoch:.6f} diagnostic_epoch={time.time():.6f} "
                  + " ".join(f"{name}={value}" for name, value in fields.items()))
        (self.work / f"transport-metadata-{self.index}-{self.started}.failure").write_text(record + "\n", encoding="ascii")
        print("load_request_failure " + record, file=sys.stderr, flush=True)

    def finish(self, code):
        status = self.curl.info(self.easy, 0x200002, C.c_long)
        duration = self.curl.info(self.easy, 0x300003, C.c_double)
        connected = self.curl.info(self.easy, 0x300005, C.c_double)
        prepared = self.curl.info(self.easy, 0x300006, C.c_double)
        self.max_pretransfer_gap = max(self.max_pretransfer_gap, prepared - connected)
        if code or not (200 <= status < 300 or status == 503):
            self.diagnostic(code, status, duration)
            self.failed = True
        elif status == 503:
            self.retries += 1
            valid = self.retry_headers == [b"1"] and 0 < duration <= 1.100
            if valid:
                self.capacity.write(f"{self.identity},{self.started},{self.retries},503,{duration:.6f},1\n")
                self.capacity.flush()
            if not valid or self.retries > 3:
                self.diagnostic(code, status, duration)
                print(f"metadata client {self.index} request {self.started}: invalid capacity response or retry budget exhausted", file=sys.stderr)
                self.failed = True
            else:
                # A per-client timer leaves the other 99 clients running.
                self.ready_at = time.monotonic() + 1
        else:
            self.results.write(f"{self.identity},{status},{duration:.6f}\n")
            self.results.flush()
            self.completed += 1
            self.ready_at = 0.0

    def close(self):
        if self.easy:
            self.curl.easy_cleanup(self.easy)
            self.easy = None
        if self.headers:
            self.curl.slist_free_all(self.headers)
            self.headers = None
        for stream in (self.results, self.capacity):
            if stream:
                stream.close()
        (self.work / f"metadata-client-{self.index}.counts").write_text(
            f"{self.index},{self.attempts},{self.started},{self.completed}\n", encoding="ascii")


def run_client(work, index, url, library, connect_timeout, request_timeout, ready, go, stop):
    # Fork only from the single-threaded supervisor; initialize libcurl in each
    # child. A client keeps its interpreter, callbacks and handle for all 20
    # requests, with no per-request exec and no shared Python GIL.
    signal.signal(signal.SIGTERM, lambda *_args: setattr(stop, "value", 1))
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM})
    curl = client = None
    cpu_started = time.process_time()
    try:
        curl = Curl(library)
        client = Client(curl, work, index, url, connect_timeout, request_timeout)
        progress = PROGRESS(lambda *_args: int(stop.value))
        curl.option(client.easy, 43, 0)
        curl.option(client.easy, 20219, progress)
        ready[index] = 1
        go.wait()
        cpu_started = time.process_time()
        while not stop.value and not client.failed and client.completed < 20:
            delay = client.ready_at - time.monotonic()
            if delay > 0:
                time.sleep(min(delay, 0.05))
                continue
            client.finish(client.perform())
        if client.failed or client.completed != 20:
            raise SystemExit(1)
    except Exception as error:
        # Child failures must follow the same redaction rule as the supervisor.
        detail = str(error) if isinstance(error, CurlFailure) else type(error).__name__
        print(f"metadata client {index} failed: {detail}", file=sys.stderr)
        raise SystemExit(1) from None
    finally:
        if client:
            client.close()
        if curl:
            curl.global_cleanup()
        (work / f"metadata-generator-{index}.env").write_text(
            f"cpu_seconds={time.process_time() - cpu_started:.6f}\n"
            f"max_pretransfer_gap_seconds={client.max_pretransfer_gap if client else 0:.6f}\n",
            encoding="ascii")


def run(work, count, connect_timeout, request_timeout, ready_timeout):
    context = multiprocessing.get_context("fork")
    ready = context.Array("b", count, lock=False)
    stop = context.Value("b", 0, lock=False)
    go = context.Event()
    processes = []
    started, cpu_started = time.monotonic(), time.process_time()
    try:
        url = os.environ["VAULTLINK_BASE_URL"] + "/v/" + os.environ["DOWNLOAD_TOKEN"]
        # Resolve the library once, avoiding 100 concurrent ldconfig probes.
        # Actual libcurl initialization remains strictly after fork.
        library = ctypes.util.find_library("curl")
        if not library:
            raise CurlFailure("libcurl is unavailable")
        for index in range(count):
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
            try:
                process = context.Process(target=run_client, args=(
                    work, index, url, library, connect_timeout, request_timeout, ready, go, stop))
                process.start()
                processes.append(process)
            finally:
                # A pending cancellation is delivered only after registration,
                # so the supervisor can join every child it started.
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        deadline = time.monotonic() + ready_timeout
        while not all(ready):
            if any(process.exitcode is not None for process in processes):
                raise CurlFailure("metadata client exited before readiness")
            if time.monotonic() >= deadline:
                raise CurlFailure("metadata client readiness timed out")
            time.sleep(0.01)
        (work / "metadata-ready").touch()
        while not (work / "profile-go").exists():
            if time.monotonic() >= deadline:
                raise CurlFailure("metadata profile start barrier timed out")
            time.sleep(0.05)
        started, cpu_started = time.monotonic(), time.process_time()
        go.set()
        for process in processes:
            process.join()
        return int(any(process.exitcode != 0 for process in processes))
    finally:
        stop.value = 1
        go.set()
        # In-flight libcurl callbacks observe stop; join before the shell can
        # aggregate partial results. No surviving clients may mutate evidence.
        for process in processes:
            process.join()
        statistics = []
        for index in range(len(processes)):
            path = work / f"metadata-generator-{index}.env"
            if path.exists():
                statistics.append(dict(line.split("=", 1) for line in path.read_text().splitlines()))
        cpu = time.process_time() - cpu_started + sum(float(s["cpu_seconds"]) for s in statistics)
        gap = max((float(s["max_pretransfer_gap_seconds"]) for s in statistics), default=0)
        (work / "metadata-generator.env").write_text(
            f"engine=libcurl-processes\nprocesses={len(processes) + 1}\nclients={count}\n"
            f"requests_per_client=20\ncpu_set={','.join(map(str, sorted(os.sched_getaffinity(0))))}\n"
            f"fresh_connections=true\nworker_processes={len(processes)}\nthreads_per_client=1\n"
            f"elapsed_seconds={time.monotonic() - started:.6f}\ncpu_seconds={cpu:.6f}\n"
            f"max_pretransfer_gap_seconds={gap:.6f}\n", encoding="ascii")


def main():
    if len(sys.argv) != 6:
        raise CurlFailure("expected work directory, client count and three deadlines")
    work = Path(sys.argv[1])
    values = [int(value) for value in sys.argv[2:]]
    if not work.is_dir() or work.is_symlink() or not all(value > 0 for value in values):
        raise CurlFailure("invalid metadata generator configuration")
    if values[0] > 100 or values[1] > 300 or values[2] > 3600 or values[3] > 900:
        raise CurlFailure("metadata generator configuration exceeds profile bounds")
    base = re.fullmatch(r"http://127\.0\.0\.1:([0-9]+)", os.environ["VAULTLINK_BASE_URL"])
    if not base or not 1 <= int(base[1]) <= 65535:
        raise CurlFailure("metadata generator requires the local HTTP listener")
    if not re.fullmatch(r"[A-Za-z0-9._~-]+", os.environ["DOWNLOAD_TOKEN"]):
        raise CurlFailure("metadata share token is invalid")
    return run(work, *values)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda _signal, _frame: sys.exit(143))
    try:
        sys.exit(main())
    except (CurlFailure, OSError, KeyError, ValueError, AttributeError, RuntimeError) as error:
        # Exception strings from environment/path parsing may contain tokens.
        detail = str(error) if isinstance(error, CurlFailure) else type(error).__name__
        print(f"metadata generator failed: {detail}", file=sys.stderr)
        sys.exit(1)
