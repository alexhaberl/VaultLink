#!/bin/sh
set -eu

nightly_toolchain=${FUZZ_NIGHTLY_TOOLCHAIN:-nightly-2026-07-01}
max_total_time=${FUZZ_MAX_TOTAL_TIME:-600}
jobs=${FUZZ_JOBS:-1}
log_dir=${FUZZ_LOG_DIR:-/tmp/vaultlink-fuzz-logs}

case "$jobs" in
    ''|*[!0-9]*|0)
        echo "FUZZ_JOBS must be a positive integer" >&2
        exit 2
        ;;
esac

case "$max_total_time" in
    ''|*[!0-9]*|0)
        echo "FUZZ_MAX_TOTAL_TIME must be a positive integer" >&2
        exit 2
        ;;
esac

run_target() {
    target=$1
    log_path="$log_dir/$target.log"
    failed_path="$log_dir/$target.failed"

    rm -f "$failed_path"
    echo "Starting fuzz target $target for ${max_total_time}s"
    if cargo "+$nightly_toolchain" fuzz run "$target" -- \
        "-max_total_time=$max_total_time" >"$log_path" 2>&1; then
        echo "Fuzz target $target passed"
    else
        status=$?
        : >"$failed_path"
        echo "Fuzz target $target failed (exit $status)" >&2
        return "$status"
    fi
}

if [ "${1:-}" = "--target" ]; then
    if [ "$#" -ne 2 ]; then
        echo "internal usage: $0 --target TARGET" >&2
        exit 2
    fi
    mkdir -p "$log_dir"
    run_target "$2"
    exit $?
fi

if [ "$#" -eq 0 ]; then
    echo "usage: $0 TARGET..." >&2
    exit 2
fi

mkdir -p "$log_dir"
echo "Building all fuzz targets with $nightly_toolchain"
cargo "+$nightly_toolchain" fuzz build
printf '%s\n' "$@" | xargs -n 1 -P "$jobs" sh "$0" --target || status=$?
status=${status:-0}

if [ "$status" -ne 0 ]; then
    for target in "$@"; do
        if [ -f "$log_dir/$target.failed" ]; then
            echo "===== $target =====" >&2
            cat "$log_dir/$target.log" >&2
        fi
    done
    echo "One or more fuzz targets failed; logs: $log_dir" >&2
    exit "$status"
fi

echo "All fuzz targets passed; logs: $log_dir"
