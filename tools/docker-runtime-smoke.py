#!/usr/bin/env python3
"""Exercise the production image, setup, mount guard and persistent SQLite."""
from __future__ import annotations

import json
import os
from pathlib import Path
from contextlib import closing
import base64
import hashlib
import hmac
from http.cookies import SimpleCookie
import re
import sqlite3
import struct
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
CLONE = f"{IDENT}-clone"
CONTAINER = IDENT
PASSWORD = "Docker runtime smoke password 123!"
HOST_NETWORK = os.environ.get("VAULTLINK_TEST_HOST_NETWORK") == "1"


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    if HOST_NETWORK and args and args[0] == "run":
        run_args = list(args)
        if "--publish" in run_args:
            index = run_args.index("--publish")
            del run_args[index:index + 2]
        listener = ([] if any(value.startswith("VAULTLINK_CONTAINER_ADDR=")
                              for value in run_args) else
                    ["--env", "VAULTLINK_CONTAINER_ADDR=127.0.0.1:8081"])
        args = ("run", "--network", "host", *listener, *run_args[1:])
    result = subprocess.run(
        ["docker", *args], text=True, capture_output=True, check=False, timeout=90
    )
    if check and result.returncode:
        raise AssertionError(
            f"Docker {args[0]} failed (exit {result.returncode}): {result.stderr[-3000:]}"
        )
    return result


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
              token: str | None = None, container: str = CONTAINER) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, body = request(url, token=token)
            if status == expected:
                return body
        except OSError:
            pass
        time.sleep(0.2)
    log_result = docker("logs", container, check=False)
    raise AssertionError(f"{url} did not return HTTP {expected}: {log_result.stdout + log_result.stderr}")


def mount_identity() -> tuple[str, str]:
    mountinfo = docker("exec", CONTAINER, "cat", "/proc/self/mountinfo").stdout
    for line in mountinfo.splitlines():
        fields = line.split()
        if fields[4] == "/mnt/storage":
            separator = fields.index("-")
            return fields[separator + 1], fields[separator + 2]
    raise AssertionError("storage bind mount absent from container mountinfo")


def totp(secret: str) -> str:
    key = base64.b32decode(secret)
    digest = hmac.new(key, struct.pack(">Q", int(time.time() // 30)), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000:06d}"


def api(url: str, method: str, payload: dict[str, object] | None = None,
        cookie: str = "", csrf: str = "") -> tuple[int, bytes, list[str]]:
    headers = {}
    if cookie:
        headers["Cookie"] = cookie
    if csrf:
        headers["x-csrf-token"] = csrf
    body = None
    if payload is not None:
        body = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, method=method, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, response.read(), response.headers.get_all("Set-Cookie", [])
    except urllib.error.HTTPError as error:
        return error.code, error.read(), error.headers.get_all("Set-Cookie", [])


def merge_cookies(previous: str, set_cookie: list[str]) -> str:
    values = dict(part.split("=", 1) for part in previous.split("; ") if part)
    for header in set_cookie:
        parsed = SimpleCookie()
        parsed.load(header)
        for key, morsel in parsed.items():
            values[key] = morsel.value
    return "; ".join(f"{key}={value}" for key, value in values.items())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def upload(url: str, upload_id: str, payload: bytes) -> int:
    boundary = "vaultlink-runtime-smoke-boundary"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="upload.bin"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + payload + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(url, method="POST", data=body, headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Idempotency-Key": upload_id,
    })
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=10) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def main() -> None:
    try:
        if os.environ.get("VAULTLINK_TEST_EXPECT_ROOTLESS") == "1":
            daemon = json.loads(docker("info", "--format", "{{json .SecurityOptions}}").stdout)
            assert any("rootless" in option for option in daemon), daemon
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
        published = ("127.0.0.1:8081" if HOST_NETWORK else
                     docker("port", CONTAINER, "8081/tcp").stdout.strip())
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
        totp_secrets = re.findall(r"[A-Z2-7]{32}", body)
        assert totp_secrets, "setup response did not contain the initial TOTP secret"
        totp_secret = totp_secrets[0]
        status, body = request(url + "/complete", "POST", token=token)
        assert status == 200 and "Setup confirmed" in body, (status, body[:500])
        status, body = request(url + "/start", "POST", token=token)
        assert status == 200 and "VaultLink is starting" in body, (status, body[:500])
        ready = wait_http(url + "/api/v2/health/ready", 200)
        assert json.loads(ready)["ok"] is True
        docker("exec", CONTAINER, "bash", "-ec",
               "printf 'VaultLink container transfer smoke\\n' > /mnt/storage/shared/readme.txt")
        status, body, cookies = api(url + "/api/v2/session/login", "POST", {
            "username": "admin", "password": PASSWORD,
        })
        assert status == 200, (status, body[:300])
        cookie = merge_cookies("", cookies)
        csrf = json.loads(body)["csrf_token"]
        status, body, cookies = api(url + "/api/v2/session/mfa", "POST", {
            "code": totp(totp_secret),
        }, cookie, csrf)
        assert status == 200, (status, body[:300])
        cookie = merge_cookies(cookie, cookies)
        csrf = json.loads(body)["csrf_token"]
        status, body, _ = api(url + "/api/v2/shares", "POST", {
            "path": "readme.txt", "permission": "download_only", "overwrite_allowed": False,
        }, cookie, csrf)
        assert status == 200, (status, body[:300])
        download_token = json.loads(body)["token"]
        status, downloaded, _ = api(url + f"/v/{download_token}/download", "GET")
        assert status == 200, (status, downloaded[:100])
        expected_hash = hashlib.sha256(b"VaultLink container transfer smoke\n").hexdigest()
        assert hashlib.sha256(downloaded).hexdigest() == expected_hash
        docker("exec", CONTAINER, "install", "-d", "-m", "0700", "/mnt/storage/shared/uploads")
        share_tokens = {}
        for permission in ("upload_only", "download_upload"):
            status, body, _ = api(url + "/api/v2/shares", "POST", {
                "path": "uploads", "permission": permission, "overwrite_allowed": False,
            }, cookie, csrf)
            assert status == 200, (status, body[:300])
            share_tokens[permission] = json.loads(body)["token"]
        status, body, _ = api(
            url + f"/v/{share_tokens['upload_only']}/upload/operations", "POST"
        )
        assert status == 201, (status, body[:300])
        upload_id = json.loads(body)["upload_id"]
        upload_payload = b"VaultLink container upload and readback smoke\n"
        status = upload(url + f"/v/{share_tokens['upload_only']}/upload", upload_id, upload_payload)
        assert status == 303, status
        readback_path = f"/v/{share_tokens['download_upload']}/download?path=upload.bin"
        status, readback, _ = api(url + readback_path, "GET")
        assert status == 200, (status, readback[:100])
        upload_hash = hashlib.sha256(upload_payload).hexdigest()
        assert hashlib.sha256(readback).hexdigest() == upload_hash
        assert docker("exec", CONTAINER, "test", "-s", "/var/lib/vaultlink/data.sqlite").returncode == 0
        assert docker("exec", CONTAINER, "test", "-s", "/var/lib/vaultlink/secrets.keyring").returncode == 0
        docker("stop", CONTAINER)
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "data.sqlite"
            # SQLite may leave committed pages in the WAL at shutdown. Copy the
            # complete stopped state so the integrity check sees one snapshot.
            docker("cp", f"{CONTAINER}:/var/lib/vaultlink/.", directory)
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
        docker("run", "--rm", "--user", "0:0", "--entrypoint", "chmod",
               "--volume", f"{STORAGE}:/mnt/storage", IMAGE, "0777", "/mnt/storage/shared")
        unsafe_permissions = f"{IDENT}-unsafe-permissions"
        try:
            docker("run", "--detach", "--name", unsafe_permissions,
                   "--user", "10001:10001", "--read-only", "--cap-drop", "ALL",
                   "--volume", f"{STATE}:/var/lib/vaultlink",
                   "--volume", f"{STORAGE}:/mnt/storage", IMAGE)
            exit_code = docker("wait", unsafe_permissions).stdout.strip()
            assert exit_code != "0", "service accepted a group/world-writable storage root"
        finally:
            docker("rm", "--force", unsafe_permissions, check=False)
            docker("run", "--rm", "--user", "0:0", "--entrypoint", "chmod",
                   "--volume", f"{STORAGE}:/mnt/storage", IMAGE, "0700", "/mnt/storage/shared")
        docker("volume", "create", CLONE)
        docker("run", "--rm", "--user", "0:0", "--entrypoint", "bash",
               "--volume", f"{STATE}:/source:ro", "--volume", f"{CLONE}:/target",
               IMAGE, "-ec", "cp -a /source/. /target/ && chown -R 10001:10001 /target")
        recovery = f"{IDENT}-recovery"
        try:
            docker("run", "--detach", "--name", recovery,
                   "--user", "10001:10001", "--read-only", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges", "--init",
                   "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,uid=10001,gid=10001,mode=0700",
                   "--publish", "127.0.0.1::8081",
                   "--volume", f"{CLONE}:/var/lib/vaultlink",
                   "--volume", f"{STORAGE}:/mnt/storage", IMAGE)
            recovered_port = (8081 if HOST_NETWORK else int(
                docker("port", recovery, "8081/tcp").stdout.strip().rsplit(":", 1)[1]))
            recovered_url = f"http://127.0.0.1:{recovered_port}"
            wait_http(recovered_url + "/api/v2/health/ready", 200, container=recovery)
            status, recovered_file, _ = api(recovered_url + readback_path, "GET")
            assert status == 200 and hashlib.sha256(recovered_file).hexdigest() == upload_hash
        finally:
            docker("rm", "--force", recovery, check=False)
        docker("start", CONTAINER)
        published = ("127.0.0.1:8081" if HOST_NETWORK else
                     docker("port", CONTAINER, "8081/tcp").stdout.strip())
        host_port = int(published.rsplit(":", 1)[1])
        url = f"http://127.0.0.1:{host_port}"
        wait_http(url + "/api/v2/health/ready", 200)
        status, readback, _ = api(url + readback_path, "GET")
        assert status == 200 and hashlib.sha256(readback).hexdigest() == upload_hash
        second = f"{IDENT}-second-instance"
        try:
            if HOST_NETWORK:
                docker("run", "--rm", "--user", "0:0", "--entrypoint", "sed",
                       "--volume", f"{CLONE}:/var/lib/vaultlink", IMAGE,
                       "-i", "s/127\\.0\\.0\\.1:8080/127.0.0.1:18083/",
                       "/var/lib/vaultlink/config.toml")
            docker("run", "--detach", "--name", second,
                   "--user", "10001:10001", "--read-only", "--cap-drop", "ALL",
                   *(["--env", "VAULTLINK_CONTAINER_ADDR=127.0.0.1:18082",
                      "--env", "VAULTLINK_SETUP_ADDR=127.0.0.1:18083"]
                     if HOST_NETWORK else []),
                   "--volume", f"{CLONE}:/var/lib/vaultlink",
                   "--volume", f"{STORAGE}:/mnt/storage", IMAGE)
            for _ in range(50):
                if docker("inspect", second, "--format", "{{.State.Running}}").stdout.strip() == "false":
                    break
                time.sleep(0.2)
            assert docker("inspect", second, "--format", "{{.State.ExitCode}}").stdout.strip() != "0", \
                "second instance accepted the same storage root"
            if HOST_NETWORK:
                failure = docker("logs", second)
                failure_log = failure.stdout + failure.stderr
                assert "storage instance lock" in failure_log.lower(), \
                    "second instance failed for a reason other than the shared storage lock: " \
                    + failure_log[-2000:]
        finally:
            docker("rm", "--force", second, check=False)
        log_result = docker("logs", CONTAINER)
        assert PASSWORD not in log_result.stdout + log_result.stderr
        print(f"Docker runtime smoke passed: {filesystem} {source}, setup, transfer hashes, mount and rights guards, backup recovery, second instance, restart, SQLite")
    finally:
        docker("rm", "--force", CONTAINER, check=False)
        for volume in (STATE, STORAGE, CLONE):
            docker("volume", "rm", "--force", volume, check=False)


if __name__ == "__main__":
    main()
