#!/usr/bin/env bash
set -euo pipefail
umask 077

WORK_DIR="${VAULTLINK_SMOKE_DIR:-/tmp/vaultlink-setup-smoke}"
BIN="${VAULTLINK_BIN:-/work/target/release/vaultlink}"
ENTRYPOINT="${VAULTLINK_CONTAINER_ENTRYPOINT:-/work/deploy/docker/container-entrypoint.sh}"
INTERNAL_ADDR="127.0.0.1:18080"
PROXY_ADDR="127.0.0.1:18081"
CONFIG_PATH="$WORK_DIR/config.toml"
ROOT_DIR="$WORK_DIR/root"
DATA_DIR="$WORK_DIR/data"
CONTAINER_LOG="$WORK_DIR/container.log"
ADMIN_PASSWORD="VaultLink setup smoke password 123!"

cleanup() {
    if [[ -n "${CONTAINER_PID:-}" ]] && kill -0 "$CONTAINER_PID" 2>/dev/null; then
        kill "$CONTAINER_PID" 2>/dev/null || true
        wait "$CONTAINER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

wait_http() {
    local url="$1"
    local expected="$2"
    for _ in $(seq 1 80); do
        local status
        status="$(curl -sS -o /dev/null -w '%{http_code}' "$url" || true)"
        if [[ "$status" == "$expected" ]]; then
            return 0
        fi
        sleep 0.25
    done
    echo "Timed out waiting for $url to return HTTP $expected" >&2
    return 1
}

rm -rf "$WORK_DIR"
mkdir -p "$ROOT_DIR/uploads" "$DATA_DIR"
printf '%s\n' 'VaultLink setup smoke test file' > "$ROOT_DIR/readme.txt"

VAULTLINK_BIN="$BIN" \
VAULTLINK_CONFIG_PATH="$CONFIG_PATH" \
VAULTLINK_SETUP_ADDR="$INTERNAL_ADDR" \
VAULTLINK_CONTAINER_ADDR="$PROXY_ADDR" \
    "$ENTRYPOINT" >"$CONTAINER_LOG" 2>&1 &
CONTAINER_PID="$!"

wait_http "http://$PROXY_ADDR/" "401"
TOKEN="$(sed -n 's#^http://[^?]*?token=##p' "$CONTAINER_LOG" | tail -n 1)"
if [[ -z "$TOKEN" ]]; then
    echo "Setup token was not printed" >&2
    cat "$CONTAINER_LOG" >&2
    exit 1
fi
wait_http "http://$PROXY_ADDR/?token=$TOKEN" "200"

curl -sS -f -X POST "http://$PROXY_ADDR/" \
    -H "Accept-Language: de" \
    --data-urlencode "token=$TOKEN" \
    --data-urlencode "server_mode=development" \
    --data-urlencode "listen_address=$INTERNAL_ADDR" \
    --data-urlencode "public_base_url=http://localhost:18081" \
    --data-urlencode "root_mount_path=$ROOT_DIR" \
    --data-urlencode "data_directory=$DATA_DIR" \
    --data-urlencode "internal_directory=$ROOT_DIR/.vaultlink-internal" \
    --data-urlencode "expected_filesystem_type=" \
    --data-urlencode "expected_mount_source=" \
    --data-urlencode "max_upload_size_mb=100" \
    --data-urlencode "blocked_extensions=exe,sh,php" \
    --data-urlencode "max_zip_size_gb=1" \
    --data-urlencode "max_zip_files=10000" \
    --data-urlencode "max_search_entries=50000" \
    --data-urlencode "max_search_results=500" \
    --data-urlencode "max_preview_size_mb=1" \
    --data-urlencode "preview_extensions=txt,log,md,csv,json,toml,yaml,yml,ini,conf" \
    --data-urlencode "image_preview_extensions=jpg,jpeg,png,gif,webp,bmp,avif" \
    --data-urlencode "pdf_preview_enabled=on" \
    --data-urlencode "max_media_preview_size_mb=100" \
    --data-urlencode "trusted_proxies=127.0.0.1,::1" \
    --data-urlencode "certificate_source=files" \
    --data-urlencode "tls_cert_file=" \
    --data-urlencode "tls_key_file=" \
    --data-urlencode "letsencrypt_contact_email=" \
    --data-urlencode "letsencrypt_cache_dir=acme" \
    --data-urlencode "letsencrypt_staging=on" \
    --data-urlencode "log_level=info" \
    --data-urlencode "admin_username=admin" \
    --data-urlencode "admin_password=$ADMIN_PASSWORD" \
    --data-urlencode "admin_password_confirm=$ADMIN_PASSWORD" \
    | grep -q "Setup abgeschlossen"

curl -sS -f -X POST "http://$PROXY_ADDR/complete" \
    -H "Accept-Language: de" \
    --data-urlencode "token=$TOKEN" \
    | grep -q "Setup best"

test -s "$CONFIG_PATH"
test -s "$DATA_DIR/data.sqlite"
test ! -e "$DATA_DIR/.vaultlink-initial-setup.pending"
grep -q 'mode = "development"' "$CONFIG_PATH"
grep -q "root_mount_path" "$CONFIG_PATH"

# Upgrade/rollback preflight must fail closed on every storage field that
# became mandatory in 0.5.0, while the current setup process is still running.
for required_storage_field in internal_directory require_mount external_writers allow_external_writer_replace; do
    incomplete_config="$WORK_DIR/missing-$required_storage_field.toml"
    incomplete_log="$WORK_DIR/missing-$required_storage_field.log"
    sed "/^${required_storage_field}[[:space:]]*=/d" \
        "$CONFIG_PATH" >"$incomplete_config"
    if "$BIN" readiness-target --config "$incomplete_config" \
        >"$incomplete_log" 2>&1; then
        echo "readiness-target accepted missing storage.$required_storage_field" >&2
        exit 1
    fi
    grep -F -q "$required_storage_field" "$incomplete_log" || {
        echo "readiness-target did not identify missing storage.$required_storage_field" >&2
        cat "$incomplete_log" >&2
        exit 1
    }
done

curl -sS -f -X POST "http://$PROXY_ADDR/start" \
    -H "Accept-Language: de" \
    --data-urlencode "token=$TOKEN" \
    | grep -q "VaultLink wird gestartet"

wait_http "http://$PROXY_ADDR/login" "200"
wait_http "http://$PROXY_ADDR/api/v1/health" "200"
kill -0 "$CONTAINER_PID"

if grep -Fq "$ADMIN_PASSWORD" "$CONTAINER_LOG"; then
    echo "Smoke logs contain sensitive setup data" >&2
    exit 1
fi

echo "VaultLink Docker setup smoke passed"
