#!/usr/bin/env python3
"""Exercise VaultLink setup, transfers and persistence through a Kubernetes pod."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import time
from pathlib import Path

common_path = Path(__file__).with_name("docker-runtime-smoke.py")
common_spec = importlib.util.spec_from_file_location("docker_runtime_smoke", common_path)
assert common_spec and common_spec.loader
common = importlib.util.module_from_spec(common_spec)
common_spec.loader.exec_module(common)
api = common.api
merge_cookies = common.merge_cookies
request = common.request
totp = common.totp
upload = common.upload

URL = "http://127.0.0.1:18081"
PASSWORD = "Docker runtime smoke password 123!"


def kubectl(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["kubectl", *args], text=True, capture_output=True,
                          check=check, timeout=90)


def pod() -> str:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        data = json.loads(kubectl("get", "pods", "-l", "app=vaultlink", "-o", "json").stdout)
        for item in data["items"]:
            if item["status"].get("phase") == "Running":
                return item["metadata"]["name"]
        time.sleep(2)
    raise AssertionError("VaultLink Kubernetes pod did not reach Running")


def wait_http(path: str, status: int, timeout: float = 50) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            actual, body = request(URL + path)
            if actual == status:
                return body
        except OSError:
            pass
        time.sleep(0.25)
    raise AssertionError(f"{path} did not return {status}: {kubectl('logs', pod(), check=False).stdout}")


def main(mode: str) -> None:
    name = pod()
    uid = kubectl("exec", name, "--", "id", "-u").stdout.strip()
    assert uid == "10001", uid
    mountinfo = kubectl("exec", name, "--", "cat", "/proc/self/mountinfo").stdout
    mount = next((line for line in mountinfo.splitlines()
                  if line.split()[4] == "/mnt/storage"), None)
    assert mount, "storage volume absent from pod mountinfo"
    fields = mount.split()
    separator = fields.index("-")
    filesystem, source = fields[separator + 1:separator + 3]
    assert filesystem == "ext4", (filesystem, source)
    if mode == "verify":
        ready = json.loads(wait_http("/api/v2/health/ready", 200))
        assert ready["ok"] is True
        print(f"Kubernetes restart and readiness passed: {filesystem} {source}")
        return

    wait_http("/", 401)
    logs = kubectl("logs", name).stdout
    tokens = re.findall(r"#token=([^\s]+)", logs)
    assert tokens, logs
    token = tokens[-1]
    status, _ = request(URL + "/bootstrap", "POST", json_body={"token": token})
    assert status == 204, status
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        status, _ = request(URL + "/", token=token)
        if status == 200:
            break
        time.sleep(0.2)
    assert status == 200, status
    fields = {
        "server_mode": "reverse_proxy", "listen_address": "127.0.0.1:8080",
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
    status, body = request(URL + "/", "POST", fields, token)
    assert status == 200 and "Setup complete" in body, (status, body[:500])
    secrets = re.findall(r"[A-Z2-7]{32}", body)
    assert secrets, "setup response omitted TOTP secret"
    for path in ("/complete", "/start"):
        status, body = request(URL + path, "POST", token=token)
        assert status == 200, (path, status, body[:300])
    ready = json.loads(wait_http("/api/v2/health/ready", 200))
    assert ready["ok"] is True
    kubectl("exec", name, "--", "bash", "-ec",
            "printf 'VaultLink Kubernetes transfer smoke\\n' > /mnt/storage/shared/readme.txt")
    status, body, cookies = api(URL + "/api/v2/session/login", "POST", {
        "username": "admin", "password": PASSWORD,
    })
    assert status == 200, (status, body[:300])
    cookie = merge_cookies("", cookies)
    csrf = json.loads(body)["csrf_token"]
    status, body, cookies = api(URL + "/api/v2/session/mfa", "POST", {
        "code": totp(secrets[0]),
    }, cookie, csrf)
    assert status == 200, (status, body[:300])
    cookie = merge_cookies(cookie, cookies)
    csrf = json.loads(body)["csrf_token"]
    status, body, _ = api(URL + "/api/v2/shares", "POST", {
        "path": "readme.txt", "permission": "download_only", "overwrite_allowed": False,
    }, cookie, csrf)
    assert status == 200, (status, body[:300])
    token = json.loads(body)["token"]
    status, content, _ = api(URL + f"/v/{token}/download", "GET")
    assert status == 200, (status, content[:100])
    assert hashlib.sha256(content).digest() == hashlib.sha256(
        b"VaultLink Kubernetes transfer smoke\n").digest()
    kubectl("exec", name, "--", "install", "-d", "-m", "0700",
            "/mnt/storage/shared/uploads")
    share_tokens: dict[str, str] = {}
    for permission in ("upload_only", "download_upload"):
        status, body, _ = api(URL + "/api/v2/shares", "POST", {
            "path": "uploads", "permission": permission, "overwrite_allowed": False,
        }, cookie, csrf)
        assert status == 200, (status, body[:300])
        share_tokens[permission] = json.loads(body)["token"]
    status, body, _ = api(
        URL + f"/v/{share_tokens['upload_only']}/upload/operations", "POST")
    assert status == 201, (status, body[:300])
    upload_id = json.loads(body)["upload_id"]
    payload = b"VaultLink Kubernetes upload and readback smoke\n"
    assert upload(URL + f"/v/{share_tokens['upload_only']}/upload", upload_id,
                  payload) == 303
    status, readback, _ = api(URL + f"/v/{share_tokens['download_upload']}/download?path=upload.bin", "GET")
    assert status == 200 and hashlib.sha256(readback).digest() == hashlib.sha256(payload).digest()
    print(f"Kubernetes setup, readiness and transfer hashes passed: {filesystem} {source}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "setup")
