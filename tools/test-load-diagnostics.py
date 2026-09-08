#!/usr/bin/env python3
"""Exercise real curl failures through the production load-test functions."""
import csv
import http.server
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time

SOURCE = Path(__file__).with_name("load-test.sh").read_text()


def function(name):
    start = SOURCE.index(f"{name}() {{")
    return SOURCE[start:SOURCE.index("\n}\n", start) + 3]


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    requests_by_client = {}

    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path.startswith("/empty"):
            self.close_connection = True
            return
        if self.path.startswith("/v/"):
            identity = self.headers.get("X-Forwarded-For")
            count = self.requests_by_client.get(identity, 0) + 1
            self.requests_by_client[identity] = count
            if identity == "198.18.1.1" and count == 10:
                self.close_connection = True
                return
        code = 404 if self.path.startswith("/missing") else 206 if self.path.startswith("/partial") else 200
        self.send_response(code)
        self.send_header("Content-Length", "1000" if self.path.startswith("/partial") else "2")
        self.send_header("Set-Cookie", "SECRET_COOKIE")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"ok")
        self.close_connection = True


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
base = f"http://127.0.0.1:{server.server_port}"
functions = "\n".join(function(name) for name in ("soak_curl", "profile_curl", "persist_load_evidence"))

try:
    with tempfile.TemporaryDirectory(prefix="vaultlink-load-diagnostics-") as temporary:
        root = Path(temporary)
        for operation, path, code, should_log in [
            ("metadata", "empty", 52, True),
            ("range", "partial", 18, True),
            ("upload", "empty", 52, True),
            ("readback", "partial", 18, True),
            ("metadata", "missing", 0, True),
            ("metadata", "healthy", 0, False),
        ]:
            work = root / f"{operation}-{path}"
            work.mkdir()
            script = "set -eu\n" + functions + "\n" + r'''
work=$TEST_WORK
profile_curl 198.18.1.3 "$TEST_OPERATION" 2 10 "$TEST_FORMAT" \
    --noproxy '*' --connect-timeout 2 --max-time 5 --output /dev/null \
    "$TEST_URL/SECRET_TOKEN?cookie=SECRET_COOKIE"
'''
            expected_fields = 4 if operation == "range" else 2 if operation == "metadata" else 1
            output_format = ("%{http_code},%{time_starttransfer},%{speed_download},%{time_total}" if operation == "range"
                             else "%{http_code},%{time_total}" if operation == "metadata" else "%{http_code}")
            result = subprocess.run(["sh", "-c", script], env={**os.environ,
                "TEST_WORK": str(work), "TEST_OPERATION": operation, "TEST_URL": f"{base}/{path}",
                "TEST_FORMAT": output_format},
                capture_output=True, text=True, timeout=15)
            assert result.returncode == code, (operation, result)
            assert len(result.stdout.split(",")) == expected_fields, result.stdout
            assert "|" not in result.stdout
            records = list(work.glob("transport-*.failure"))
            assert bool(records) == should_log, (operation, records)
            if should_log:
                record = records[0].read_text()
                assert f"curl_exit={code}" in record and "client=2 request=10" in record
                metrics = dict(field.split("=", 1) for field in record.split())
                assert int(metrics["local_port"]) > 0
                assert metrics["remote_port"] == str(server.server_port)
                assert float(metrics["total_seconds"]) >= float(metrics["connect_seconds"])
                if path == "partial":
                    assert metrics["download_bytes"] == "2", metrics
                assert "load_request_failure" in result.stderr
            else:
                assert result.stderr == ""
            assert "SECRET" not in result.stdout + result.stderr + "".join(p.read_text() for p in records)

        # Reproduce the original shape: client0 stops on request10; client1
        # completes20. Preserve one failed attempt and ten unattempted requests.
        work = root / "metadata-profile"
        work.mkdir()
        evidence = root / "evidence"
        script = "set -eu\n" + functions + "\n" + function("metadata_profile") + "\n" + r'''
work=$TEST_WORK
load_stage=parallel-profiles
metadata_clients=2
metadata_script=$TEST_METADATA_SCRIPT
profile_ready_timeout=5
: >"$work/profile-go"
connect_timeout=2
metadata_max_time=5
wait_for_profile_go() { :; }
trap 'code=$?; persist_load_evidence "$code"; exit "$code"' EXIT
metadata_profile
'''
        result = subprocess.run(["sh", "-c", script], env={**os.environ,
            "TEST_WORK": str(work), "LOAD_TEST_EVIDENCE_DIR": str(evidence),
            "TEST_METADATA_SCRIPT": str(Path(__file__).with_name("load-metadata.py").resolve()),
            "VAULTLINK_BASE_URL": base, "DOWNLOAD_TOKEN": "SECRET_TOKEN"},
            capture_output=True, text=True, timeout=30)
        assert result.returncode == 1, result
        counts = sorted(csv.reader((evidence / "metadata-request-counts.partial.csv").open()))
        assert counts == [["0", "10", "10", "9"], ["1", "20", "20", "20"]], counts
        successes = list(csv.reader((evidence / "metadata-load.partial.csv").open()))
        assert len(successes) == 29
        assert (evidence / "load-command.env").read_text() == "stage=parallel-profiles\nexit_status=1\n"
        diagnostics = (evidence / "transport-failures.log").read_text()
        assert "curl_exit=52" in diagnostics and "request=10" in diagnostics
        assert "SECRET" not in diagnostics + result.stderr

        # SIGTERM interrupts the shell's wait before the Python worker has
        # flushed counts. The profile must join it before persisting evidence.
        work = root / "metadata-cancel"
        work.mkdir()
        evidence = root / "cancel-evidence"
        process = subprocess.Popen(["sh", "-c", script.replace(': >"$work/profile-go"', ":")],
            env={**os.environ, "TEST_WORK": str(work), "LOAD_TEST_EVIDENCE_DIR": str(evidence),
                 "TEST_METADATA_SCRIPT": str(Path(__file__).with_name("load-metadata.py").resolve()),
                 "VAULTLINK_BASE_URL": base, "DOWNLOAD_TOKEN": "SECRET_TOKEN"},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not (work / "metadata-ready").exists():
                assert process.poll() is None
                assert time.monotonic() < deadline
                time.sleep(0.01)
            process.terminate()
            stdout, stderr = process.communicate(timeout=5)
            assert process.returncode == 1, stderr
            counts = sorted(csv.reader((evidence / "metadata-request-counts.partial.csv").open()))
            assert counts == [["0", "0", "0", "0"], ["1", "0", "0", "0"]], counts
            assert (evidence / "metadata-generator.env").is_file()
            assert "SECRET" not in stdout + stderr
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()
finally:
    server.shutdown()
    server.server_close()
    thread.join()

print("Load transport diagnostics: real curl52/18, HTTP errors, redaction and partial request counts passed")
