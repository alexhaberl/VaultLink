#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="$PWD/target/coverage"
report_dir="$PWD/coverage"
mkdir -p "$report_dir"
# External-test workflow for the pinned cargo-llvm-cov 0.8.6.
eval "$(cargo llvm-cov show-env --sh)"
cargo llvm-cov clean --workspace
cargo test --locked --package vaultlink --all-targets --all-features
cargo build --locked --package vaultlink --bin vaultlink --all-features
cargo llvm-cov report --lcov --output-path "$report_dir/unit.lcov"
mkdir -p "$CARGO_TARGET_DIR/unit-profiles"
for profile in "$CARGO_TARGET_DIR"/*.profraw; do
    [ ! -f "$profile" ] || mv -- "$profile" "$CARGO_TARGET_DIR/unit-profiles/"
done

process_work=$(mktemp -d "${TMPDIR:-/tmp}/vaultlink-coverage.XXXXXXXXXX")
trap 'rm -rf -- "$process_work"' EXIT
export VAULTLINK_BIN="$CARGO_TARGET_DIR/debug/vaultlink"
export VAULTLINK_CONTAINER_ENTRYPOINT="$PWD/deploy/docker/container-entrypoint.sh"
run_process() {
    local name=$1
    shift
    local work="$process_work/$name"
    mkdir -p "$work/profiles"
    if [ "$(id -u)" = 0 ]; then
        chown -R vaultlink:vaultlink "$process_work"
        runuser -u vaultlink -- env LLVM_PROFILE_FILE="$work/profiles/process-%p-%m.profraw" \
            VAULTLINK_BIN="$VAULTLINK_BIN" VAULTLINK_SMOKE_DIR="$work/smoke" \
            VAULTLINK_CONTAINER_ENTRYPOINT="$VAULTLINK_CONTAINER_ENTRYPOINT" timeout 240 "$@"
    else
        LLVM_PROFILE_FILE="$work/profiles/process-%p-%m.profraw" VAULTLINK_SMOKE_DIR="$work/smoke" timeout 240 "$@"
    fi
    cp "$work/profiles/"*.profraw "$CARGO_TARGET_DIR/"
}
run_process runtime python3 tools/runtime-smoke.py
run_process setup bash deploy/docker/setup-smoke.sh
run_process api bash deploy/docker/api-smoke.sh
cargo llvm-cov report --lcov --output-path "$report_dir/process.lcov"
cp "$CARGO_TARGET_DIR/unit-profiles/"*.profraw "$CARGO_TARGET_DIR/"
cargo llvm-cov report --lcov --output-path "$report_dir/combined.lcov" --fail-under-lines 81
python3 tools/check-module-coverage.py "$report_dir/combined.lcov" "$@"
