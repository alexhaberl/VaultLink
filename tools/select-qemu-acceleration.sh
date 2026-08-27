#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG

[ "$#" -eq 3 ] || {
    echo "usage: $0 ARCHITECTURE QEMU_BINARY EVIDENCE_FILE" >&2
    exit 64
}

architecture=$1
qemu=$2
evidence=$3
acceleration_policy=${ACCELERATION_POLICY:-force-tcg}

case "$architecture:$qemu" in
    amd64:qemu-system-x86_64 | arm64:qemu-system-aarch64) ;;
    *) exit 65 ;;
esac
case "$acceleration_policy" in
    force-tcg | auto) ;;
    *)
        echo "unsupported ACCELERATION_POLICY: $acceleration_policy" >&2
        exit 64
        ;;
esac
[ ! -e "$evidence" ] && [ ! -L "$evidence" ] || exit 66
evidence=$(cd -- "$(dirname -- "$evidence")" && pwd)/$(basename -- "$evidence")
probe_log=$evidence.kvm-probe.log
[ ! -e "$probe_log" ] && [ ! -L "$probe_log" ] || exit 66

selected_acceleration=tcg
kvm_probe_result=not-requested
kvm_probe_exit_status=not-run
probe_pid=
probe_directory=

stop_probe() {
    if [ -n "$probe_pid" ] && kill -0 "$probe_pid" 2>/dev/null; then
        kill "$probe_pid" 2>/dev/null || true
        sleep 1
        if kill -0 "$probe_pid" 2>/dev/null; then
            kill -KILL "$probe_pid" 2>/dev/null || true
        fi
    fi
    if [ -n "$probe_pid" ]; then
        wait "$probe_pid" 2>/dev/null || true
        probe_pid=
    fi
}
cleanup() {
    stop_probe
    if [ -n "$probe_directory" ]; then
        rm -rf "$probe_directory"
    fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$acceleration_policy" = auto ]; then
    if [ "$architecture" != amd64 ]; then
        kvm_probe_result=not-applicable
    elif [ ! -c /dev/kvm ] || [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
        kvm_probe_result=device-unavailable
    elif ! "$qemu" -accel help 2>/dev/null | grep -F -x -q kvm; then
        kvm_probe_result=accelerator-unavailable
    else
        probe_directory=$(mktemp -d)
        probe_socket=$probe_directory/qmp.sock
        "$qemu" \
            -machine q35,accel=kvm -cpu host -smp 1 -m 128 \
            -nodefaults -display none -S \
            -qmp "unix:$probe_socket,server=on,wait=off" \
            >"$probe_log" 2>&1 &
        probe_pid=$!
        socket_ready=false
        for _probe_second in 1 2 3 4 5; do
            if [ -S "$probe_socket" ]; then
                socket_ready=true
                break
            fi
            kill -0 "$probe_pid" 2>/dev/null || break
            sleep 1
        done
        probe_status=1
        if [ "$socket_ready" = true ]; then
            probe_status=0
            python3 - "$probe_socket" <<'PY' || probe_status=$?
import json
import socket
import sys

path = sys.argv[1]
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(3)
client.connect(path)
stream = client.makefile("rwb", buffering=0)

def read_reply():
    while True:
        line = stream.readline()
        if not line:
            raise RuntimeError("QMP closed before a reply")
        message = json.loads(line)
        if "return" in message or "error" in message:
            return message

greeting = json.loads(stream.readline())
if "QMP" not in greeting:
    raise RuntimeError("missing QMP greeting")
stream.write(b'{"execute":"qmp_capabilities"}\n')
if "return" not in read_reply():
    raise RuntimeError("QMP capability negotiation failed")
stream.write(b'{"execute":"query-kvm"}\n')
reply = read_reply()
state = reply.get("return", {})
if state.get("present") is not True or state.get("enabled") is not True:
    raise RuntimeError("QEMU did not enable KVM")
PY
        fi
        stop_probe
        kvm_probe_exit_status=$probe_status
        if [ "$probe_status" -eq 0 ]; then
            selected_acceleration=kvm
            kvm_probe_result=passed
        else
            kvm_probe_result=failed
        fi
    fi
fi

printf '%s\n' \
    "acceleration_policy=$acceleration_policy" \
    "selected_acceleration=$selected_acceleration" \
    "kvm_probe_result=$kvm_probe_result" \
    "kvm_probe_exit_status=$kvm_probe_exit_status" \
    >"$evidence"
chmod 0644 "$evidence"
if [ -f "$probe_log" ]; then
    chmod 0644 "$probe_log"
fi
printf '%s\n' "$selected_acceleration"
