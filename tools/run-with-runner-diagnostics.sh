#!/usr/bin/env bash
# Stream host evidence before a runner shutdown can skip post-job uploads.
set -uo pipefail
export LC_ALL=C TZ=UTC

if [[ $# -eq 0 ]]; then
    echo "usage: $0 command [argument ...]" >&2
    exit 64
fi

payload_pid=
resources_pid=
kernel_pid=

snapshot() {
    local phase=$1 cgroup file
    printf '\n[runner-diagnostics] phase=%s utc=%s\n' "$phase" "$(date -u +%FT%TZ)"
    uptime || true
    awk '/^(MemTotal|MemAvailable|SwapTotal|SwapFree):/ {print}' /proc/meminfo || true
    df -h / /var/lib/docker 2>&1 || true
    df -i / /var/lib/docker 2>&1 || true
    cgroup=$(awk -F: '$1 == "0" {print $3}' /proc/self/cgroup 2>/dev/null) || true
    for file in /proc/pressure/cpu /proc/pressure/memory /proc/pressure/io \
        "/sys/fs/cgroup$cgroup/memory.current" \
        "/sys/fs/cgroup$cgroup/memory.max" \
        "/sys/fs/cgroup$cgroup/memory.events"; do
        if [[ -r "$file" ]]; then
            printf '[runner-diagnostics] %s\n' "$file"
            cat "$file" || true
        fi
    done
    # comm reports executable names, without command arguments or environment.
    ps -eo pid,ppid,comm,pcpu,pmem,rss --sort=-rss | head -n 12 || true
}

monitor_resources() {
    trap - EXIT
    local sleep_pid=
    trap 'if [[ -n "$sleep_pid" ]]; then kill "$sleep_pid" 2>/dev/null || true; wait "$sleep_pid" 2>/dev/null || true; fi; exit 0' HUP INT TERM
    while :; do
        sleep 10 &
        sleep_pid=$!
        wait "$sleep_pid" || true
        sleep_pid=
        snapshot periodic
    done
}

finish() {
    local status=$? pid
    trap - EXIT
    trap '' HUP INT TERM
    for pid in "$resources_pid" "$kernel_pid"; do
        if [[ -n "$pid" ]]; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    for pid in "$resources_pid" "$kernel_pid"; do
        if [[ -n "$pid" ]]; then
            wait "$pid" 2>/dev/null || true
        fi
    done
    snapshot final
    printf '[runner-diagnostics] command_exit_code=%s\n' "$status"
    exit "$status"
}

forward_signal() {
    local signal=$1 status=$2
    trap '' HUP INT TERM
    printf '[runner-diagnostics] received_signal=%s\n' "$signal"
    snapshot signal
    if [[ -n "$payload_pid" ]]; then
        kill -s "$signal" -- "-$payload_pid" 2>/dev/null || true
        wait "$payload_pid" 2>/dev/null || true
        payload_pid=
    fi
    exit "$status"
}

trap finish EXIT
trap 'forward_signal HUP 129' HUP
trap 'forward_signal INT 130' INT
trap 'forward_signal TERM 143' TERM

snapshot initial
kernel_command=()
if command -v sudo >/dev/null 2>&1 \
    && sudo -n journalctl --dmesg --no-pager --lines=0 >/dev/null 2>&1; then
    kernel_command=(sudo -n journalctl --dmesg --follow --no-pager --lines=40 --output=short-iso)
elif journalctl --dmesg --no-pager --lines=0 >/dev/null 2>&1; then
    kernel_command=(journalctl --dmesg --follow --no-pager --lines=40 --output=short-iso)
elif command -v sudo >/dev/null 2>&1 && sudo -n dmesg >/dev/null 2>&1; then
    kernel_command=(sudo -n dmesg --follow-new --time-format iso --color=never)
elif dmesg >/dev/null 2>&1; then
    kernel_command=(dmesg --follow-new --time-format iso --color=never)
fi
if [[ ${#kernel_command[@]} -gt 0 ]]; then
    printf '[runner-diagnostics] starting kernel log stream\n'
    "${kernel_command[@]}" &
    kernel_pid=$!
else
    printf '[runner-diagnostics] kernel log unavailable; continuing resource sampling\n'
fi

monitor_resources &
resources_pid=$!
# A separate process group lets cancellation reach make and all its children.
# Restore SIGINT/SIGQUIT, which noninteractive shells ignore for background jobs.
setsid env --default-signal=INT,QUIT "$@" &
payload_pid=$!
printf '[runner-diagnostics] command_process_group=%s\n' "$payload_pid"
wait "$payload_pid"
status=$?
payload_pid=
exit "$status"
