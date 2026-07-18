#!/usr/bin/env bash
set -euo pipefail
umask 077

BIN="${VAULTLINK_BIN:-/opt/vaultlink/vaultlink}"
CONFIG_PATH="${VAULTLINK_CONFIG_PATH:-/var/lib/vaultlink/config.toml}"
SETUP_ADDR="${VAULTLINK_SETUP_ADDR:-127.0.0.1:8080}"
CONTAINER_ADDR="${VAULTLINK_CONTAINER_ADDR:-0.0.0.0:8081}"

if [[ ! -x "$BIN" ]]; then
    echo "VaultLink binary is not executable: $BIN" >&2
    exit 1
fi
mkdir -p "$(dirname -- "$CONFIG_PATH")"

"$BIN" container-proxy \
    --listen "$CONTAINER_ADDR" \
    --setup-upstream "$SETUP_ADDR" \
    --config "$CONFIG_PATH" &
PROXY_PID="$!"

"$BIN" setup --config "$CONFIG_PATH" --listen "$SETUP_ADDR" &
VAULTLINK_PID="$!"

# Invoked indirectly by the EXIT/INT/TERM traps.
# shellcheck disable=SC2317
cleanup() {
    kill "$VAULTLINK_PID" "$PROXY_PID" 2>/dev/null || true
    wait "$VAULTLINK_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

status=0
wait -n "$VAULTLINK_PID" "$PROXY_PID" || status=$?
if kill -0 "$VAULTLINK_PID" 2>/dev/null; then
    echo "VaultLink container proxy exited unexpectedly" >&2
    if [[ "$status" -eq 0 ]]; then
        status=1
    fi
    exit "$status"
fi
exit "$status"
