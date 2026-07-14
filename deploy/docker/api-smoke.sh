#!/usr/bin/env bash
set -euo pipefail
umask 077

WORK_DIR="${VAULTLINK_SMOKE_DIR:-/tmp/vaultlink-api-smoke}"
BIN="${VAULTLINK_BIN:-/work/target/release/vaultlink}"
SETUP_ADDR="127.0.0.1:8091"
APP_ADDR="127.0.0.1:18081"
CONFIG_PATH="$WORK_DIR/config.toml"
ROOT_DIR="$WORK_DIR/root"
DATA_DIR="$WORK_DIR/data"
COOKIE_JAR="$WORK_DIR/cookies.txt"
SETUP_LOG="$WORK_DIR/setup.log"
APP_LOG="$WORK_DIR/app.log"
SETUP_RESPONSE="$WORK_DIR/setup-response.html"
ADMIN_PASSWORD="VaultLink api smoke password 123!"

cleanup() {
    if [[ -n "${SETUP_PID:-}" ]] && kill -0 "$SETUP_PID" 2>/dev/null; then
        kill "$SETUP_PID" 2>/dev/null || true
        wait "$SETUP_PID" 2>/dev/null || true
    fi
    if [[ -n "${APP_PID:-}" ]] && kill -0 "$APP_PID" 2>/dev/null; then
        kill "$APP_PID" 2>/dev/null || true
        wait "$APP_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

fail() {
    echo "API smoke failed: $*" >&2
    if [[ -f "$SETUP_LOG" ]]; then
        echo "--- setup log ---" >&2
        tail -n 80 "$SETUP_LOG" >&2 || true
    fi
    if [[ -f "$APP_LOG" ]]; then
        echo "--- app log ---" >&2
        tail -n 120 "$APP_LOG" >&2 || true
    fi
    exit 1
}

wait_http() {
    local url="$1"
    local expected="$2"
    for _ in $(seq 1 100); do
        local status
        status="$(curl -sS -o /dev/null -w '%{http_code}' "$url" || true)"
        if [[ "$status" == "$expected" ]]; then
            return 0
        fi
        sleep 0.2
    done
    fail "timed out waiting for $url to return HTTP $expected"
}

json_get() {
    local key="$1"
    python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$key"
}

totp_now() {
    local secret="$1"
    python3 - "$secret" <<'PY'
import base64
import hashlib
import hmac
import struct
import sys
import time

secret = sys.argv[1].strip().replace(" ", "")
padding = "=" * ((8 - len(secret) % 8) % 8)
key = base64.b32decode((secret + padding).upper(), casefold=True)
counter = int(time.time() // 30)
digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
offset = digest[-1] & 0x0F
code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
print(f"{code % 1_000_000:06d}")
PY
}

assert_json_error() {
    local file="$1"
    local code="$2"
    grep -q '"error"' "$file" || fail "response does not contain JSON error"
    grep -q "\"code\":\"$code\"" "$file" || fail "response does not contain error code $code"
    if grep -qi '<html' "$file"; then
        fail "API error response contains HTML"
    fi
}

assert_health_json() {
    python3 -c '
import json
import sys

raw = sys.stdin.read()
try:
    response = json.loads(raw)
except json.JSONDecodeError as error:
    raise SystemExit(f"invalid health JSON: {error}")

if not isinstance(response, dict) or set(response) != {"ok", "version"}:
    raise SystemExit("health JSON must contain exactly ok and version")
if response["ok"] is not True:
    raise SystemExit("health JSON ok must be true")
if not isinstance(response["version"], str) or not response["version"]:
    raise SystemExit("health JSON version must be a non-empty string")

expected = "{\"ok\":true,\"version\":" + json.dumps(
    response["version"], ensure_ascii=False, separators=(",", ":")
) + "}"
if raw != expected:
    raise SystemExit("health JSON is not in the handler compact response form")
'
}

rm -rf "$WORK_DIR"
mkdir -p "$ROOT_DIR/uploads" "$DATA_DIR"
printf '%s\n' 'VaultLink API smoke test file' > "$ROOT_DIR/readme.txt"

"$BIN" setup --config "$CONFIG_PATH" --listen "$SETUP_ADDR" >"$SETUP_LOG" 2>&1 &
SETUP_PID="$!"

wait_http "http://$SETUP_ADDR/" "401"
SETUP_TOKEN="$(sed -n 's#^http://[^?]*?token=##p' "$SETUP_LOG" | tail -n 1)"
[[ -n "$SETUP_TOKEN" ]] || fail "setup token was not printed"
wait_http "http://$SETUP_ADDR/?token=$SETUP_TOKEN" "200"

curl -sS -f -X POST "http://$SETUP_ADDR/" \
    -H "Accept-Language: de" \
    --data-urlencode "token=$SETUP_TOKEN" \
    --data-urlencode "server_mode=development" \
    --data-urlencode "listen_address=$APP_ADDR" \
    --data-urlencode "public_base_url=http://localhost:18081" \
    --data-urlencode "root_mount_path=$ROOT_DIR" \
    --data-urlencode "data_directory=$DATA_DIR" \
    --data-urlencode "internal_directory=" \
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
    >"$SETUP_RESPONSE"

grep -q "Setup abgeschlossen" "$SETUP_RESPONSE" || fail "setup did not complete"
TOTP_SECRET="$(grep -Eo '[A-Z2-7]{32}' "$SETUP_RESPONSE" | head -n 1)"
[[ -n "$TOTP_SECRET" ]] || fail "TOTP secret was not rendered"
curl -sS -f -X POST "http://$SETUP_ADDR/complete" \
    -H "Accept-Language: de" \
    --data-urlencode "token=$SETUP_TOKEN" \
    | grep -q "Setup best" || fail "setup confirmation failed"

cleanup
unset SETUP_PID

"$BIN" --config "$CONFIG_PATH" >"$APP_LOG" 2>&1 &
APP_PID="$!"
wait_http "http://$APP_ADDR/login" "200"
if ! HEALTH_JSON="$(curl -sS -f "http://$APP_ADDR/api/v1/health")"; then
    fail "health endpoint did not return HTTP success"
fi
if ! printf '%s' "$HEALTH_JSON" | assert_health_json; then
    fail "health endpoint returned an invalid response"
fi

LOGIN_JSON="$(
    curl -sS -f -c "$COOKIE_JAR" \
        -H "content-type: application/json" \
        -X POST "http://$APP_ADDR/api/v1/session/login" \
        -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASSWORD\"}"
)"
CSRF="$(printf '%s' "$LOGIN_JSON" | json_get csrf_token)"
[[ -n "$CSRF" ]] || fail "login response did not contain csrf_token"

MFA_CODE="$(totp_now "$TOTP_SECRET")"
MFA_JSON="$(
    curl -sS -f -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
        -H "content-type: application/json" \
        -H "x-csrf-token: $CSRF" \
        -X POST "http://$APP_ADDR/api/v1/session/mfa" \
        -d "{\"code\":\"$MFA_CODE\"}"
)"
printf '%s' "$MFA_JSON" | grep -q '"mfa_verified":true' || fail "MFA did not verify"
CSRF="$(printf '%s' "$MFA_JSON" | json_get csrf_token)"

curl -sS -f -b "$COOKIE_JAR" "http://$APP_ADDR/api/v1/session/me" | grep -q '"username":"admin"' \
    || fail "session/me did not return admin"

curl -sS -f -b "$COOKIE_JAR" "http://$APP_ADDR/api/v1/files?path=" | grep -q '"readme.txt"' \
    || fail "files API did not list readme.txt"

CREATE_DIRECTORY_JSON="$(
    curl -sS -f -b "$COOKIE_JAR" \
        -H "content-type: application/json" \
        -H "x-csrf-token: $CSRF" \
        -X POST "http://$APP_ADDR/api/v1/files/directories" \
        -d '{"parent":"","name":"managed"}'
)"
printf '%s' "$CREATE_DIRECTORY_JSON" | grep -q '"path":"managed"' \
    || fail "directory create did not return the managed path"
printf '%s\n' 'managed mutation smoke file' > "$ROOT_DIR/managed/child.txt"

DELETE_CONFIRMATION_HTML="$(
    curl -sS -f -b "$COOKIE_JAR" \
        "http://$APP_ADDR/admin/files/delete?path=managed"
)"
printf '%s' "$DELETE_CONFIRMATION_HTML" | grep -q 'data-confirm-input autofocus' \
    || fail "delete confirmation did not autofocus the exact-name input"
printf '%s' "$DELETE_CONFIRMATION_HTML" | grep -q 'data-delete-confirmation data-required-name="managed"' \
    || fail "delete confirmation did not expose the exact required name"
printf '%s' "$DELETE_CONFIRMATION_HTML" | grep -q 'data-confirm-delete disabled' \
    || fail "delete confirmation button was not initially disabled"

MUTATION_SHARE_JSON="$(
    curl -sS -f -b "$COOKIE_JAR" \
        -H "content-type: application/json" \
        -H "x-csrf-token: $CSRF" \
        -X POST "http://$APP_ADDR/api/v1/shares" \
        -d '{"path":"managed/child.txt","permission":"download_only"}'
)"
MUTATION_SHARE_TOKEN="$(printf '%s' "$MUTATION_SHARE_JSON" | json_get token)"
[[ -n "$MUTATION_SHARE_TOKEN" ]] || fail "mutation share create did not return token"

RENAME_JSON="$(
    curl -sS -f -b "$COOKIE_JAR" \
        -H "content-type: application/json" \
        -H "x-csrf-token: $CSRF" \
        -X PATCH "http://$APP_ADDR/api/v1/files" \
        -d '{"path":"managed","name":"renamed"}'
)"
printf '%s' "$RENAME_JSON" | grep -q '"path":"renamed"' \
    || fail "directory rename did not return the renamed path"
printf '%s' "$RENAME_JSON" | grep -q '"updated_shares":1' \
    || fail "directory rename did not update the affected share"
curl -sS -f "http://$APP_ADDR/api/v1/public/shares/$MUTATION_SHARE_TOKEN" \
    | grep -q '"path":"renamed/child.txt"' \
    || fail "renamed share did not expose its updated path"
curl -sS -f "http://$APP_ADDR/api/v1/public/shares/$MUTATION_SHARE_TOKEN/download" \
    -o "$WORK_DIR/renamed-child.txt"
cmp "$WORK_DIR/renamed-child.txt" "$ROOT_DIR/renamed/child.txt" \
    || fail "renamed share download returned unexpected content"

UNCONFIRMED_DELETE_STATUS="$(
    curl -sS -o "$WORK_DIR/unconfirmed-delete.json" -w '%{http_code}' \
        -b "$COOKIE_JAR" \
        -H "content-type: application/json" \
        -H "x-csrf-token: $CSRF" \
        -X DELETE "http://$APP_ADDR/api/v1/files" \
        -d '{"path":"renamed"}'
)"
[[ "$UNCONFIRMED_DELETE_STATUS" == "409" ]] \
    || fail "unconfirmed tree delete returned $UNCONFIRMED_DELETE_STATUS instead of 409"
assert_json_error "$WORK_DIR/unconfirmed-delete.json" "confirmation_required"

DELETE_JSON="$(
    curl -sS -f -b "$COOKIE_JAR" \
        -H "content-type: application/json" \
        -H "x-csrf-token: $CSRF" \
        -X DELETE "http://$APP_ADDR/api/v1/files" \
        -d '{"path":"renamed","confirm_name":"renamed"}'
)"
printf '%s' "$DELETE_JSON" | grep -q '"cleanup_pending":true' \
    || fail "non-empty tree delete was not queued for background cleanup"
[[ ! -e "$ROOT_DIR/renamed" ]] || fail "deleted tree remained visible"
INACTIVE_SHARE_STATUS="$(
    curl -sS -o "$WORK_DIR/inactive-share.json" -w '%{http_code}' \
        "http://$APP_ADDR/api/v1/public/shares/$MUTATION_SHARE_TOKEN"
)"
[[ "$INACTIVE_SHARE_STATUS" == "410" ]] \
    || fail "deleted tree share returned $INACTIVE_SHARE_STATUS instead of 410"
assert_json_error "$WORK_DIR/inactive-share.json" "share_inactive"

DOWNLOAD_SHARE_JSON="$(
    curl -sS -f -b "$COOKIE_JAR" \
        -H "content-type: application/json" \
        -H "x-csrf-token: $CSRF" \
        -X POST "http://$APP_ADDR/api/v1/shares" \
        -d '{"path":".","permission":"download_only"}'
)"
DOWNLOAD_SHARE_TOKEN="$(printf '%s' "$DOWNLOAD_SHARE_JSON" | json_get token)"
[[ -n "$DOWNLOAD_SHARE_TOKEN" ]] || fail "download share create did not return token"
curl -sS -f \
    "http://$APP_ADDR/api/v1/public/shares/$DOWNLOAD_SHARE_TOKEN/download.zip" \
    -o "$WORK_DIR/download.zip"
python3 - "$WORK_DIR/download.zip" <<'PY'
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as archive:
    assert archive.testzip() is None
    assert "readme.txt" in archive.namelist()
    assert archive.read("readme.txt") == b"VaultLink API smoke test file\n"
PY

NO_CSRF_STATUS="$(
    curl -sS -o "$WORK_DIR/no-csrf.json" -w '%{http_code}' -b "$COOKIE_JAR" \
        -H "content-type: application/json" \
        -X POST "http://$APP_ADDR/api/v1/shares" \
        -d '{"path":"uploads","permission":"upload_only"}'
)"
[[ "$NO_CSRF_STATUS" == "403" ]] || fail "share create without CSRF returned $NO_CSRF_STATUS instead of 403"
assert_json_error "$WORK_DIR/no-csrf.json" "forbidden"

SHARE_JSON="$(
    curl -sS -f -b "$COOKIE_JAR" \
        -H "content-type: application/json" \
        -H "x-csrf-token: $CSRF" \
        -X POST "http://$APP_ADDR/api/v1/shares" \
        -d '{"path":"uploads","permission":"upload_only","overwrite_allowed":false}'
)"
SHARE_TOKEN="$(printf '%s' "$SHARE_JSON" | json_get token)"
[[ -n "$SHARE_TOKEN" ]] || fail "share create did not return token"

curl -sS -f "http://$APP_ADDR/api/v1/public/shares/$SHARE_TOKEN" | grep -q '"permission":"upload_only"' \
    || fail "public share API did not return upload_only"

printf 'blocked' > "$WORK_DIR/blocked.exe"
UPLOAD_STATUS="$(
    curl -sS -o "$WORK_DIR/upload-error.json" -w '%{http_code}' \
        -X POST "http://$APP_ADDR/api/v1/public/shares/$SHARE_TOKEN/upload" \
        -F "file=@$WORK_DIR/blocked.exe;filename=blocked.exe"
)"
[[ "$UPLOAD_STATUS" == "415" ]] || fail "blocked upload returned $UPLOAD_STATUS instead of 415"
assert_json_error "$WORK_DIR/upload-error.json" "unsupported_media_type"

if grep -Fq "$ADMIN_PASSWORD" "$SETUP_LOG" "$APP_LOG"; then
    fail "logs contain sensitive setup data"
fi

TOMBSTONE="$ROOT_DIR/.vaultlink-internal/tombstones/.vaultlink-delete-AAAAAAAAAAAAAAAAAAAAAAAA.tombstone"
mkdir -p "$TOMBSTONE/nested"
printf '%s\n' 'restart cleanup' > "$TOMBSTONE/nested/child.txt"
kill "$APP_PID"
wait "$APP_PID"
unset APP_PID

"$BIN" --config "$CONFIG_PATH" >>"$APP_LOG" 2>&1 &
APP_PID="$!"
wait_http "http://$APP_ADDR/login" "200"
for _ in $(seq 1 100); do
    [[ -e "$TOMBSTONE" ]] || break
    sleep 0.02
done
[[ ! -e "$TOMBSTONE" ]] || fail "startup did not resume tombstone cleanup"

echo "VaultLink Docker API smoke passed"
