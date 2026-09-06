#!/usr/bin/env python3
"""Exercise the real server process, TLS startup and orderly SIGTERM cleanup."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
BIN = Path(os.environ.get("VAULTLINK_BIN", ROOT / "target/debug/vaultlink")).resolve()


def unused_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def rejects(config: Path, label: str) -> None:
    result = subprocess.run([str(BIN), "--config", str(config)], capture_output=True, timeout=20, check=False)
    assert result.returncode != 0, f"{label} unexpectedly started"
    print(f"runtime: rejected {label}")


def start_and_shutdown(config: Path, url: str, log: Path) -> None:
    context = ssl._create_unverified_context()  # Only this generated local test certificate.
    with log.open("wb") as output:
        process = subprocess.Popen([str(BIN), "--config", str(config)], stdout=output, stderr=output)
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                assert process.poll() is None, log.read_text()
                try:
                    with urllib.request.urlopen(url + "/api/v2/health/ready", context=context, timeout=1) as response:
                        assert json.load(response)["ok"] is True
                        break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.05)
            else:
                raise AssertionError(f"readiness timeout: {log.read_text()}")
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=40) == 0, log.read_text()
            assert "shutdown signal received; draining active connections" in log.read_text()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    print(f"runtime: readiness and orderly SIGTERM passed ({url.split(':')[0]})")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="vaultlink-runtime-") as directory:
        work = Path(directory)
        mount = work / "mount"
        mount.mkdir()
        port = unused_port()
        config = work / "config.toml"
        original = (ROOT / "config/development.toml").read_text()
        original = original.replace('"127.0.0.1:8080"', f'"127.0.0.1:{port}"')
        original = original.replace('"http://localhost:8080"', f'"http://localhost:{port}"')
        original = original.replace('"dev/mount"', json.dumps(str(mount)))
        original = original.replace('"dev/data"', json.dumps(str(work / "data")))
        original = original.replace('"dev/mount/.vaultlink-internal"', json.dumps(str(mount / ".vaultlink-internal")))
        config.write_text(original)
        start_and_shutdown(config, f"http://127.0.0.1:{port}", work / "http.log")
        # Reopening also verifies that shutdown has released runtime and storage ownership.
        start_and_shutdown(config, f"http://127.0.0.1:{port}", work / "restart.log")
        with sqlite3.connect(work / "data/data.sqlite") as database:
            assert database.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        with socket.socket() as occupied:
            occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            occupied.bind(("127.0.0.1", port))
            occupied.listen()
            rejects(config, "occupied port")
        config.write_text("invalid = [")
        rejects(config, "invalid configuration")
        cert, key = work / "cert.pem", work / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True, timeout=20)
        key.chmod(0o600)
        tls = original.replace('mode = "development"', 'mode = "standalone_tls"')
        tls = tls.replace("production_mode = false", "production_mode = true")
        tls = tls.replace("http://localhost:", "https://localhost:").replace("secure_cookie = false", "secure_cookie = true")
        tls = tls.replace("[tls]\nenabled = false", "[tls]\nenabled = true")
        tls = tls.replace("[logging]", f"cert_file = {json.dumps(str(cert))}\nkey_file = {json.dumps(str(key))}\n\n[logging]")
        # Native CI uses its audited local filesystem; Docker supplies an isolated
        # ext4 volume via VAULTLINK_TLS_FIXTURE_DIR. No mount-policy bypass is used.
        with tempfile.TemporaryDirectory(prefix="vaultlink-tls-", dir=os.environ.get("VAULTLINK_TLS_FIXTURE_DIR")) as tls_directory:
            tls_root = Path(tls_directory)
            shared = tls_root / "shared"
            shared.mkdir(mode=0o700)
            internal = tls_root / ".vaultlink-internal"
            internal.mkdir(mode=0o700)
            tls_data = tls_root / "data"
            tls_data.mkdir(mode=0o700)
            for child in ["uploads", "tombstones"]:
                (internal / child).mkdir(mode=0o700)
            identity = subprocess.check_output(["findmnt", "--target", str(shared), "--noheadings",
                                               "--output", "FSTYPE,SOURCE", "--nofsroot"], text=True, timeout=5)
            filesystem, source = identity.strip().split(maxsplit=1)
            tls = tls.replace(json.dumps(str(mount)), json.dumps(str(shared)))
            tls = tls.replace(json.dumps(str(mount / ".vaultlink-internal")), json.dumps(str(internal)))
            tls = tls.replace(json.dumps(str(work / "data")), json.dumps(str(tls_data)))
            tls = tls.replace("require_mount = false", f"require_mount = true\nexpected_filesystem_type = {json.dumps(filesystem)}\nexpected_mount_source = {json.dumps(source)}")
            config.write_text(tls)
            start_and_shutdown(config, f"https://127.0.0.1:{port}", work / "tls.log")
            valid_certificate = cert.read_bytes()
            cert.write_text("invalid certificate")
            rejects(config, "invalid TLS certificate")
            cert.write_bytes(valid_certificate)
            key.write_text("invalid private key")
            rejects(config, "invalid TLS private key")
    print("Runtime process smoke passed")


if __name__ == "__main__":
    main()
