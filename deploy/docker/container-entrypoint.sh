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

if [[ -e "$CONFIG_PATH" || -L "$CONFIG_PATH" ]]; then
    exec "$BIN" --config "$CONFIG_PATH"
fi

"$BIN" health-bootstrap &
HEALTH_PID=$!
"$BIN" container-proxy \
    --listen "$CONTAINER_ADDR" \
    --setup-upstream "$SETUP_ADDR" \
    --config "$CONFIG_PATH" &
PROXY_PID="$!"
"$BIN" setup-once --config "$CONFIG_PATH" --listen "$SETUP_ADDR" &
SETUP_PID=$!

cleanup() {
    kill "$SETUP_PID" "$PROXY_PID" "$HEALTH_PID" 2>/dev/null || true
    wait "$SETUP_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
    wait "$HEALTH_PID" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

completed=
status=0
wait -n -p completed "$SETUP_PID" "$PROXY_PID" "$HEALTH_PID" || status=$?
if [[ "$completed" != "$SETUP_PID" || "$status" -ne 0 || ! -f "$CONFIG_PATH" ]]; then
    echo "VaultLink bootstrap stopped before a complete configuration was accepted" >&2
    exit 1
fi

kill "$PROXY_PID" "$HEALTH_PID" 2>/dev/null || true
wait "$PROXY_PID" 2>/dev/null || true
wait "$HEALTH_PID" 2>/dev/null || true
trap - EXIT INT TERM
exec "$BIN" --config "$CONFIG_PATH"
