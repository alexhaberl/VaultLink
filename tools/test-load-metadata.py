#!/usr/bin/env python3
"""Real HTTP regression checks for concurrent metadata load and fail-closed results."""
import collections
import csv
import http.server
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest


SCRIPT = Path(__file__).with_name("load-metadata.py").resolve()


class Server(http.server.ThreadingHTTPServer):
    request_queue_size = 256
    daemon_threads = True

    def __init__(self, mode, clients):
        super().__init__(("127.0.0.1", 0), Handler)
        self.mode, self.clients = mode, clients
        self.condition = threading.Condition()
        self.release = threading.Event()
        self.requests = collections.Counter()
        self.connections = 0
        self.first_seen = set()
        self.serialized = False
        self.other_completed_before_retry = False


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        with self.server.condition:
            self.server.connections += 1

    def log_message(self, *_args):
        pass

    def do_GET(self):
        server = self.server
        identity = self.headers["X-Forwarded-For"]
        with server.condition:
            server.requests[identity] += 1
            server.condition.notify_all()
            request = server.requests[identity]
            if server.mode == "concurrent" and request == 1:
                server.first_seen.add(identity)
                server.condition.notify_all()
                if not server.condition.wait_for(lambda: len(server.first_seen) == server.clients, timeout=8):
                    server.serialized = True
            if server.mode == "retry" and identity.endswith(".1") and request == 2:
                server.other_completed_before_retry = server.requests["198.18.1.2"] == 20
        if server.mode == "blocked":
            server.release.wait(timeout=20)
            self.close_connection = True
            return
        if server.mode == "empty":
            self.close_connection = True
            return
        if server.mode == "partial":
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            self.wfile.write(b"ok")
            self.close_connection = True
            return
        capacity = server.mode in ("duplicate", "missing", "budget", "late") or (
            server.mode == "retry" and identity.endswith(".1") and request == 1)
        if server.mode == "late":
            time.sleep(1.2)
        self.send_response(503 if capacity else 500 if server.mode == "error" else 200)
        if capacity and server.mode != "missing":
            self.send_header("Retry-After", "1")
            if server.mode == "duplicate":
                self.send_header("Retry-After", "1")
        self.send_header("Content-Length", "2")
        self.send_header("Set-Cookie", "SECRET_COOKIE")
        self.end_headers()
        self.wfile.write(b"ok")


class MetadataTests(unittest.TestCase):
    def test_workers_inherit_affinity_and_stop_at_barrier_without_attempts(self):
        with tempfile.TemporaryDirectory(prefix="vaultlink-metadata-stop-") as temporary:
            work = Path(temporary)
            cpu = str(min(os.sched_getaffinity(0)))
            process = subprocess.Popen(["taskset", "--cpu-list", cpu, sys.executable,
                                        str(SCRIPT), temporary, "2", "5", "15", "10"],
                env={**os.environ, "VAULTLINK_BASE_URL": "http://127.0.0.1:1", "DOWNLOAD_TOKEN": "SECRET_TOKEN"},
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 5
                while not (work / "metadata-ready").exists():
                    self.assertIsNone(process.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                threads = list(Path(f"/proc/{process.pid}/task").iterdir())
                self.assertEqual(len(threads), 3)  # Main thread and two ready clients.
                for thread in threads:
                    affinity = next(line.split(":", 1)[1].strip() for line in
                                    (thread / "status").read_text().splitlines()
                                    if line.startswith("Cpus_allowed_list:"))
                    self.assertEqual(affinity, cpu)
                process.terminate()
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 143, stderr)
                for client in range(2):
                    self.assertEqual((work / f"metadata-client-{client}.counts").read_text(), f"{client},0,0,0\n")
                self.assertNotIn("SECRET", stdout + stderr)
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate()

    def test_termination_aborts_inflight_requests_and_retains_attempts(self):
        server = Server("blocked", 2)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="vaultlink-metadata-inflight-") as temporary:
                work = Path(temporary)
                (work / "profile-go").touch()
                process = subprocess.Popen([sys.executable, str(SCRIPT), temporary, "2", "5", "300", "10"],
                    env={**os.environ, "VAULTLINK_BASE_URL": f"http://127.0.0.1:{server.server_port}",
                         "DOWNLOAD_TOKEN": "SECRET_TOKEN", "NO_PROXY": "127.0.0.1"},
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    with server.condition:
                        self.assertTrue(server.condition.wait_for(lambda: len(server.requests) == 2, timeout=5))
                    process.terminate()
                    stdout, stderr = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, 143, stderr)
                    for client in range(2):
                        self.assertEqual((work / f"metadata-client-{client}.counts").read_text(), f"{client},1,1,0\n")
                        self.assertIn("curl_exit=42 ", (work / f"transport-metadata-{client}-1.failure").read_text())
                    self.assertEqual(set(server.requests.values()), {1})
                    self.assertNotIn("SECRET", stdout + stderr)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.communicate()
        finally:
            server.release.set()
            server.shutdown()
            server.server_close()
            thread.join()

    def exercise(self, mode, clients):
        server = Server(mode, clients)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="vaultlink-metadata-") as temporary:
                work = Path(temporary)
                (work / "profile-go").touch()
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), str(work), str(clients), "5", "15", "5"],
                    env={**os.environ, "VAULTLINK_BASE_URL": f"http://127.0.0.1:{server.server_port}",
                         "DOWNLOAD_TOKEN": "SECRET_TOKEN", "NO_PROXY": "127.0.0.1"},
                    capture_output=True, text=True, timeout=45)
                files = {path.name: path.read_text() for path in work.iterdir()}
                self.assertNotIn("SECRET", result.stdout + result.stderr + "".join(files.values()))
                return result, files, server
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_all_100_clients_are_concurrent_and_each_request_connects_afresh(self):
        result, files, server = self.exercise("concurrent", 100)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(server.serialized)
        self.assertEqual(len(server.first_seen), 100)
        self.assertEqual(server.connections, 2000)
        self.assertEqual(set(server.requests.values()), {20})
        for client in range(100):
            self.assertEqual(files[f"metadata-client-{client}.counts"], f"{client},20,20,20\n")
            self.assertEqual(len(list(csv.reader(files[f"metadata-{client}.csv"].splitlines()))), 20)
        self.assertIn("engine=libcurl-threads\nprocesses=1\nclients=100\n", files["metadata-generator.env"])
        self.assertFalse(any(name.endswith(".failure") for name in files))

    def test_capacity_retry_does_not_suspend_other_clients(self):
        result, files, server = self.exercise("retry", 2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(files["metadata-client-0.counts"], "0,21,20,20\n")
        self.assertEqual(files["metadata-client-1.counts"], "1,20,20,20\n")
        self.assertTrue(server.other_completed_before_retry)
        row = next(csv.reader(files["capacity-retry-client-0.csv"].splitlines()))
        self.assertEqual(row[:4], ["198.18.1.1", "1", "1", "503"])
        self.assertEqual(row[5], "1")

    def test_invalid_capacity_responses_and_exhaustion_fail(self):
        for mode, attempts in (("duplicate", 1), ("missing", 1), ("late", 1), ("budget", 4)):
            with self.subTest(mode=mode):
                result, files, server = self.exercise(mode, 1)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(server.requests["198.18.1.1"], attempts)
                self.assertEqual(files["metadata-client-0.counts"], f"0,{attempts},1,0\n")
                metrics = dict(field.split("=", 1) for field in
                               files["transport-metadata-0-1.failure"].split())
                self.assertEqual(metrics["http_status"], "503")
                self.assertEqual(metrics["curl_exit"], "0")
                self.assertGreater(int(metrics["local_port"]), 0)
                if mode == "late":
                    self.assertGreater(float(metrics["total_seconds"]), 1.1)

    def test_transport_and_http_errors_are_never_retried(self):
        for mode, curl_code, http_status in (("empty", 52, "000"), ("partial", 18, "200"), ("error", 0, "500")):
            with self.subTest(mode=mode):
                result, files, server = self.exercise(mode, 1)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(server.connections, 1)
                self.assertEqual(files["metadata-client-0.counts"], "0,1,1,0\n")
                record = files["transport-metadata-0-1.failure"]
                metrics = dict(field.split("=", 1) for field in record.split())
                self.assertEqual(metrics["curl_exit"], str(curl_code))
                self.assertEqual(metrics["http_status"], http_status)
                self.assertGreater(int(metrics["local_port"]), 0)
                self.assertEqual(metrics["remote_port"], str(server.server_port))
                if mode == "partial":
                    self.assertEqual(metrics["download_bytes"], "2")


if __name__ == "__main__":
    unittest.main()
