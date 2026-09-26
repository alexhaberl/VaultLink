#!/usr/bin/env bash
set -euo pipefail
umask 077

BIN="${VAULTLINK_BIN:-/opt/vaultlink/vaultlink}"
CONFIG_PATH="${VAULTLINK_CONFIG_PATH:-/var/lib/vaultlink/config.toml}"
SETUP_ADDR="${VAULTLINK_SETUP_ADDR:-127.0.0.1:8080}"

if [[ ! -x "$BIN" ]]; then
    echo "VaultLink binary is not executable: $BIN" >&2
    exit 1
fi
mkdir -p "$(dirname -- "$CONFIG_PATH")"
exec "$BIN" container-start --config "$CONFIG_PATH" --listen "$SETUP_ADDR"
