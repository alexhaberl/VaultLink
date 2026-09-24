#!/usr/bin/env python3
"""Exercise the production image, setup, mount guard and persistent SQLite."""
from __future__ import annotations

import json
import os
from pathlib import Path
from contextlib import closing
import re
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

IMAGE = os.environ.get("VAULTLINK_TEST_IMAGE", "vaultlink:runtime-dev")
IDENT = f"vaultlink-runtime-{uuid.uuid4().hex[:12]}"
STATE = f"{IDENT}-state"
STORAGE = f"{IDENT}-storage"
CONTAINER = IDENT
PASSWORD = "Docker runtime smoke password 123!"


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], text=True, capture_output=True, check=check, timeout=90
    )


def request(url: str, method: str = "GET", data: dict[str, str] | None = None,
            token: str | None = None, json_body: dict[str, str] | None = None) -> tuple[int, str]:
    headers = {}
    if token:
        headers["x-vaultlink-setup-token"] = token
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if json_body is not None:
        body = json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, method=method, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def wait_http(url: str, expected: int, timeout: float = 35,
              token: str | None = None) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, body = request(url, token=token)
            if status == expected:
                return body
        except OSError:
            pass
        time.sleep(0.2)
    log_result = docker("logs", CONTAINER, check=False)
    raise AssertionError(f"{url} did not return HTTP {expected}: {log_result.stdout + log_result.stderr}")


def mount_identity() -> tuple[str, str]:
    mountinfo = docker("exec", CONTAINER, "cat", "/proc/self/mountinfo").stdout
    for line in mountinfo.splitlines():
        fields = line.split()
        if fields[4] == "/mnt/storage":
            separator = fields.index("-")
            return fields[separator + 1], fields[separator + 2]
    raise AssertionError("storage bind mount absent from container mountinfo")


def main() -> None:
    try:
        for volume in (STATE, STORAGE):
            docker("volume", "create", volume)
        docker("run", "--rm", "--user", "0:0", "--entrypoint", "bash",
               "--volume", f"{STATE}:/var/lib/vaultlink",
               "--volume", f"{STORAGE}:/mnt/storage", IMAGE, "-ec",
               "install -d -o 10001 -g 10001 -m 0700 "
               "/var/lib/vaultlink /mnt/storage/shared /mnt/storage/.vaultlink-internal "
               "/mnt/storage/.vaultlink-internal/uploads "
               "/mnt/storage/.vaultlink-internal/tombstones")
        docker("run", "--detach", "--name", CONTAINER,
               "--user", "10001:10001", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--init",
               "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,uid=10001,gid=10001,mode=0700",
               "--publish", "127.0.0.1::8081",
               "--volume", f"{STATE}:/var/lib/vaultlink",
               "--volume", f"{STORAGE}:/mnt/storage", IMAGE)
        published = docker("port", CONTAINER, "8081/tcp").stdout.strip()
        host_port = int(published.rsplit(":", 1)[1])
        url = f"http://127.0.0.1:{host_port}"
        assert docker("exec", CONTAINER, "id", "-u").stdout.strip() == "10001"
        filesystem, source = mount_identity()
        assert filesystem in {"ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "bcachefs", "zfs"}, (filesystem, source)
        wait_http(url + "/", 401)
        log_result = docker("logs", CONTAINER)
        logs = log_result.stdout + log_result.stderr
        tokens = re.findall(r"#token=([^\s]+)", logs)
        assert tokens, logs
        token = tokens[-1]
        status, _ = request(url + "/bootstrap", "POST", json_body={"token": token})
        assert status == 204, status
        wait_http(url + "/", 200, token=token)
        fields = {
            "server_mode": "reverse_proxy",
            "listen_address": "127.0.0.1:8080",
            "public_base_url": "https://vaultlink.example.test",
            "root_mount_path": "/mnt/storage/shared",
            "data_directory": "/var/lib/vaultlink",
            "internal_directory": "/mnt/storage/.vaultlink-internal",
            "expected_filesystem_type": filesystem,
            "expected_mount_source": source,
            "max_upload_size_mb": "100", "blocked_extensions": "exe,sh,php",
            "max_zip_size_gb": "1", "max_zip_files": "10000",
            "max_search_entries": "50000", "max_search_results": "500",
            "max_preview_size_mb": "1",
            "preview_extensions": "txt,log,md,csv,json,toml,yaml,yml,ini,conf",
            "image_preview_extensions": "jpg,jpeg,png,gif,webp,bmp,avif",
            "max_media_preview_size_mb": "100",
            "trusted_proxies": "127.0.0.1,::1",
            "certificate_source": "files", "tls_cert_file": "", "tls_key_file": "",
            "letsencrypt_contact_email": "", "letsencrypt_cache_dir": "acme",
            "log_level": "info", "admin_username": "admin",
            "admin_password": PASSWORD, "admin_password_confirm": PASSWORD,
        }
        status, body = request(url + "/", "POST", fields, token)
        assert status == 200 and "Setup complete" in body, (status, body[:500])
        status, body = request(url + "/complete", "POST", token=token)
        assert status == 200 and "Setup confirmed" in body, (status, body[:500])
        status, body = request(url + "/start", "POST", token=token)
        assert status == 200 and "VaultLink is starting" in body, (status, body[:500])
        ready = wait_http(url + "/api/v2/health/ready", 200)
        assert json.loads(ready)["ok"] is True
        assert docker("exec", CONTAINER, "test", "-s", "/var/lib/vaultlink/data.sqlite").returncode == 0
        assert docker("exec", CONTAINER, "test", "-s", "/var/lib/vaultlink/secrets.keyring").returncode == 0
        docker("stop", CONTAINER)
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "data.sqlite"
            docker("cp", f"{CONTAINER}:/var/lib/vaultlink/data.sqlite", str(database))
            with closing(sqlite3.connect(database)) as connection:
                assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        missing_mount = f"{IDENT}-missing-mount"
        try:
            docker("run", "--detach", "--name", missing_mount,
                   "--user", "10001:10001", "--read-only", "--cap-drop", "ALL",
                   "--volume", f"{STATE}:/var/lib/vaultlink", IMAGE)
            exit_code = docker("wait", missing_mount).stdout.strip()
            assert exit_code != "0", "service accepted a missing storage mount"
            failure = docker("logs", missing_mount)
            assert "mount" in (failure.stdout + failure.stderr).lower()
        finally:
            docker("rm", "--force", missing_mount, check=False)
        docker("start", CONTAINER)
        published = docker("port", CONTAINER, "8081/tcp").stdout.strip()
        host_port = int(published.rsplit(":", 1)[1])
        url = f"http://127.0.0.1:{host_port}"
        wait_http(url + "/api/v2/health/ready", 200)
        log_result = docker("logs", CONTAINER)
        assert PASSWORD not in log_result.stdout + log_result.stderr
        print(f"Docker runtime smoke passed: {filesystem} {source}, setup, missing mount, restart, SQLite")
    finally:
        docker("rm", "--force", CONTAINER, check=False)
        for volume in (STATE, STORAGE):
            docker("volume", "rm", "--force", volume, check=False)


if __name__ == "__main__":
    main()
