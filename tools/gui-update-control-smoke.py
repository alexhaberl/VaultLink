#!/usr/bin/env python3
"""Exercise the real root controller and systemd jobs in the disposable gate VM.

The VM is offline. Disable automatic installation, verify the privileged IPC
boundary and durable results, then exercise both controller and application
restarts. Native package signature/transaction tests run in the package gate.
"""

import json
import os
from contextlib import contextmanager
from pathlib import Path
import pwd
import socket
import stat
import subprocess
import sys
import time


SOCKET = "/run/vaultlink-update-control/control.sock"
CONTROLLER = "vaultlink-update-control.service"
STATE = Path("/var/lib/vaultlink-update-control/status.json")


def command(*args):
    return subprocess.check_output(args, text=True, timeout=90).strip()


def request(value):
    # Drop all supplementary groups and the real/effective identity before
    # connecting. Passing JSON on argv exercises the actual SO_PEERCRED check.
    account = pwd.getpwnam("vaultlink")

    def drop_identity():
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)

    client = """
import json, socket, sys
with socket.socket(socket.AF_UNIX) as stream:
    stream.settimeout(20)
    stream.connect(sys.argv[1])
    stream.sendall(sys.argv[2].encode() + b'\\n')
    value = stream.makefile('rb').readline(8193)
    assert len(value) <= 8192 and value.endswith(b'\\n')
    print(json.dumps(json.loads(value)))
"""
    return json.loads(subprocess.check_output(
        [sys.executable, "-c", client, SOCKET, json.dumps(value)],
        preexec_fn=drop_identity, text=True, timeout=25,
    ))


def status():
    return request({"command": "status"})


def wait_ready():
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if Path(SOCKET).exists():
            result = status()
            if result["available"]:
                return result
        time.sleep(1)
    raise AssertionError("controller did not become ready")


@contextmanager
def delayed_job_start():
    # This disposable VM deliberately exceeds the controller's five-second
    # launch deadline. PID 1 must still finish the already submitted job.
    directory = Path("/run/systemd/system/vaultlink-gui-update.service.d")
    directory.mkdir(mode=0o700)
    dropin = directory / "start-delay.conf"
    try:
        dropin.write_text("[Service]\nExecStartPre=/usr/bin/sleep 7\n")
        command("systemctl", "daemon-reload")
        yield
    finally:
        dropin.unlink(missing_ok=True)
        directory.rmdir()
        command("systemctl", "daemon-reload")


def submit_and_wait(submission):
    accepted = request(submission)
    assert accepted["request_id"] == submission["request_id"]
    assert accepted["phase"] in ("queued", "running", "complete"), accepted
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        result = status()
        if result["phase"] not in ("queued", "running"):
            break
        time.sleep(1)
    assert result["phase"] == "complete", result
    assert result["error"] is None and not result["automatic"]


def main():
    assert os.geteuid() == 0
    assert command("systemd-detect-virt", "--vm") == "qemu"
    initial = wait_ready()
    assert initial["installed"] == command("/opt/vaultlink/vaultlink", "--version")
    metadata = os.stat(SOCKET)
    assert stat.S_ISSOCK(metadata.st_mode)
    assert metadata.st_uid == 0
    assert metadata.st_gid == pwd.getpwnam("vaultlink").pw_gid
    assert stat.S_IMODE(metadata.st_mode) == 0o660
    assert command("systemctl", "show", "-p", "User", "--value", CONTROLLER) == "root"
    assert command("systemctl", "show", "-p", "NoNewPrivileges", "--value", CONTROLLER) == "yes"
    assert command("systemctl", "show", "-p", "CapabilityBoundingSet", "--value", CONTROLLER) == ""
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(5)
        stream.connect(SOCKET)
        try:
            stream.sendall(b'{"command":"status"}\n')
            assert stream.recv(1) == b"", "root is not the authorized IPC client"
        except ConnectionResetError:
            pass
    assert not request({"command": "status", "path": "/etc/shadow"})["available"]
    assert not request({"command": "submit", "request_id": "vm-invalid-operation",
                        "action": {"operation": "check", "url": "https://invalid.test"}})["available"]
    rejected = request({"command": "submit", "request_id": "vm-unchecked-install",
                        "action": {"operation": "install", "version": "999.0.0"}})
    assert rejected["error"] == "check_required"
    assert status()["request_id"] == initial["request_id"]
    submission = {"command": "submit", "request_id": "vm-disable-automatic",
                  "action": {"operation": "automatic", "enabled": False}}
    submit_and_wait(submission)
    submission["request_id"] = "vm-delayed-automatic"
    with delayed_job_start():
        submit_and_wait(submission)
    assert Path("/etc/vaultlink/update.conf").read_text() == "auto_install=false\n"
    assert stat.S_IMODE(STATE.stat().st_mode) == 0o600
    assert STATE.stat().st_uid == 0
    original = STATE.read_bytes()
    assert request(submission)["phase"] == "complete"
    assert STATE.read_bytes() == original, "duplicate submission started another job"
    command("systemctl", "restart", CONTROLLER)
    assert wait_ready()["request_id"] == submission["request_id"]
    assert STATE.read_bytes() == original
    command("systemctl", "restart", "vaultlink.service")
    assert wait_ready()["phase"] == "complete"
    assert STATE.read_bytes() == original
    command("systemctl", "reset-failed", "vaultlink.service")
    print("gui_update_control=passed")
    print("peer_identity=checked\nstrict_protocol=checked\ndurable_result=checked")
    print("duplicate_submission=checked\ncontroller_restart=checked\nservice_restart=checked")
    print("delayed_job_start=checked")


if __name__ == "__main__":
    main()
