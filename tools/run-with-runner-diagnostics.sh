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
signals_pid=

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
    if [[ "$phase" == signal ]]; then
        ps -eo pid,ppid,pgid,sid,comm || true
    fi
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

# A child that ignores cancellation must not keep the runner's log upload open.
# Invoked indirectly by the signal and EXIT traps.
# shellcheck disable=SC2317
stop_child() {
    local pid=$1 target=$2 signal=$3 attempts=$4 attempt
    kill -s "$signal" -- "$target" 2>/dev/null || true
    for ((attempt=0; attempt<attempts; attempt++)); do
        kill -0 -- "$target" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 -- "$target" 2>/dev/null; then
        printf '[runner-diagnostics] signal_grace_expired target=%s; sending SIGKILL\n' "$target"
        kill -KILL -- "$target" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
}

start_signal_trace() {
    [[ ${RUNNER_DIAGNOSTICS_TRACE_SIGNALS:-0} == 1 ]] || return 0
    local strace_path ancestor=$PPID parent name hop pid thread
    local -a trace_pids=("$$") trace_command trace_arguments=()
    strace_path=$(command -v strace) || {
        printf '[runner-diagnostics] signal tracing unavailable: strace missing\n'
        return 0
    }
    # Restrict tracing to this wrapper and its runner ancestors. Do not follow
    # children or collect syscall arguments, command lines, or environment.
    for ((hop=0; hop<8 && ancestor>1; hop++)); do
        [[ -r /proc/$ancestor/comm && -r /proc/$ancestor/status ]] || break
        name=$(cat "/proc/$ancestor/comm") || break
        parent=$(awk '/^PPid:/ {print $2}' "/proc/$ancestor/status") || break
        printf '[runner-diagnostics] ancestor pid=%s ppid=%s comm=%s\n' "$ancestor" "$parent" "$name"
        case "$name" in Runner.Worker|Runner.Listener) trace_pids+=("$ancestor") ;; esac
        [[ "$parent" =~ ^[0-9]+$ ]] || break
        ancestor=$parent
    done
    # Include existing threads: process-directed signals may use any thread.
    for pid in "${trace_pids[@]}"; do
        for thread in /proc/"$pid"/task/[0-9]*; do
            [[ -d "$thread" ]] || continue
            trace_arguments+=(-p "${thread##*/}")
        done
    done
    trace_command=("$strace_path")
    if [[ $EUID -ne 0 ]]; then
        if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            trace_command=(sudo -n -- "$strace_path")
        else
            printf '[runner-diagnostics] signal tracing unavailable: passwordless sudo missing\n'
            return 0
        fi
    fi
    printf '[runner-diagnostics] starting signal trace (signal metadata only)\n'
    setsid "${trace_command[@]}" -tt -e trace=none -e signal=HUP,INT,TERM,QUIT "${trace_arguments[@]}" &
    signals_pid=$!
    printf '[runner-diagnostics] signal_process_group=%s\n' "$signals_pid"
}

# Invoked indirectly by the EXIT trap; integration tests exercise cleanup.
# shellcheck disable=SC2317
finish() {
    local status=$?
    trap - EXIT
    trap '' HUP INT TERM
    if [[ -n "$resources_pid" ]]; then
        stop_child "$resources_pid" "$resources_pid" TERM 10
    fi
    if [[ -n "$kernel_pid" ]]; then
        stop_child "$kernel_pid" "-$kernel_pid" TERM 10
    fi
    if [[ -n "$signals_pid" ]]; then
        stop_child "$signals_pid" "-$signals_pid" TERM 10
    fi
    snapshot final
    printf '[runner-diagnostics] command_exit_code=%s\n' "$status"
    exit "$status"
}

# Invoked indirectly by signal traps; integration tests exercise both signals.
# shellcheck disable=SC2317
forward_signal() {
    local signal=$1 status=$2
    trap '' HUP INT TERM
    printf '[runner-diagnostics] received_signal=%s\n' "$signal"
    snapshot signal
    if [[ -n "$payload_pid" ]]; then
        stop_child "$payload_pid" "-$payload_pid" "$signal" 30
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
    setsid "${kernel_command[@]}" &
    kernel_pid=$!
    printf '[runner-diagnostics] kernel_process_group=%s\n' "$kernel_pid"
else
    printf '[runner-diagnostics] kernel log unavailable; continuing resource sampling\n'
fi

start_signal_trace
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
