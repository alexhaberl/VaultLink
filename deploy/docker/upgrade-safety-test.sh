#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ ! -f /.dockerenv ]] || [[ "$(id -u)" -ne 0 ]]; then
    echo "upgrade safety tests must run as root in a disposable container" >&2
    exit 1
fi

TEST_ROOT=/tmp/vaultlink-upgrade-safety
MOCK_BIN="$TEST_ROOT/bin"
MOCK_STATE_DIR="$TEST_ROOT/state"
CONFIG_PATH=/etc/vaultlink/config.toml
HEALTH_PORT=18082
HEALTH_URL="http://127.0.0.1:$HEALTH_PORT/api/v1/health"
REAL_SQLITE3="$(command -v sqlite3)"
REAL_CURL="$(command -v curl)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
UPGRADE="$REPO_ROOT/deploy/vaultlink-upgrade.sh"
ROLLBACK="$REPO_ROOT/deploy/vaultlink-rollback.sh"

export MOCK_STATE_DIR REAL_SQLITE3
export VAULTLINK_READINESS_ATTEMPTS=4
export VAULTLINK_READINESS_INTERVAL_SECONDS=0
export VAULTLINK_READINESS_CONNECT_TIMEOUT_SECONDS=1
export VAULTLINK_READINESS_MAX_TIME_SECONDS=1

fail() {
    echo "upgrade safety test failed: $*" >&2
    exit 1
}

cleanup() {
    if [[ -n "${HEALTH_SERVER_PID:-}" ]] && kill -0 "$HEALTH_SERVER_PID" 2>/dev/null; then
        kill "$HEALTH_SERVER_PID" 2>/dev/null || true
        wait "$HEALTH_SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

create_service_account() {
    if ! getent group vaultlink >/dev/null; then
        groupadd --system vaultlink
    fi
    if ! id vaultlink >/dev/null 2>&1; then
        useradd --system --gid vaultlink --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin vaultlink
    fi
}

create_mocks() {
    rm -rf "$TEST_ROOT"
    mkdir -p "$MOCK_BIN" "$MOCK_STATE_DIR"

    cat >"$MOCK_BIN/systemctl" <<'SH'
#!/bin/sh
set -eu

printf '%s\n' "$*" >>"$MOCK_STATE_DIR/systemctl.log"

service_is_active() {
    state=$(cat "$MOCK_STATE_DIR/service.state" 2>/dev/null || printf '%s\n' inactive)
    if [ "$state" = active ]; then
        return 0
    fi
    if [ "$state" != activating ]; then
        return 1
    fi

    remaining=$(cat "$MOCK_STATE_DIR/active-checks-remaining")
    if [ "$remaining" -le 1 ]; then
        printf '%s\n' active >"$MOCK_STATE_DIR/service.state"
        rm -f "$MOCK_STATE_DIR/active-checks-remaining"
        return 0
    fi
    printf '%s\n' "$((remaining - 1))" >"$MOCK_STATE_DIR/active-checks-remaining"
    return 1
}

if [ "${1:-}" = "--quiet" ] && [ "${2:-}" = "is-active" ]; then
    if service_is_active; then
        exit 0
    fi
    exit 1
fi

case "${1:-}" in
    stop)
        stop_count=$(cat "$MOCK_STATE_DIR/stop.count" 2>/dev/null || printf '%s\n' 0)
        stop_count=$((stop_count + 1))
        printf '%s\n' "$stop_count" >"$MOCK_STATE_DIR/stop.count"
        if [ -f "$MOCK_STATE_DIR/fail-second-stop-once" ] && [ "$stop_count" -eq 2 ]; then
            rm -f "$MOCK_STATE_DIR/fail-second-stop-once"
            exit 1
        fi
        printf '%s\n' inactive >"$MOCK_STATE_DIR/service.state"
        ;;
    start)
        if [ -f "$MOCK_STATE_DIR/fail-start-once" ]; then
            rm -f "$MOCK_STATE_DIR/fail-start-once"
            exit 1
        fi
        if [ -f "$MOCK_STATE_DIR/delayed-active-checks" ]; then
            cp "$MOCK_STATE_DIR/delayed-active-checks" "$MOCK_STATE_DIR/active-checks-remaining"
            rm -f "$MOCK_STATE_DIR/delayed-active-checks"
            printf '%s\n' activating >"$MOCK_STATE_DIR/service.state"
        else
            printf '%s\n' active >"$MOCK_STATE_DIR/service.state"
        fi
        ;;
    is-active)
        service_is_active
        ;;
    *)
        echo "unexpected systemctl invocation: $*" >&2
        exit 2
        ;;
esac
SH

    cat >"$MOCK_BIN/sqlite3" <<'SH'
#!/bin/sh
set -eu

case "$*" in
    *".backup "*)
        if [ -f "$MOCK_STATE_DIR/fail-backup-once" ]; then
            rm -f "$MOCK_STATE_DIR/fail-backup-once"
            exit 1
        fi
        ;;
esac

if [ "${1:-}" = "/var/lib/vaultlink/data.sqlite" ] \
    && printf '%s\n' "$*" | grep -q 'PRAGMA integrity_check' \
    && [ -f "$MOCK_STATE_DIR/fail-live-integrity-once" ]; then
    rm -f "$MOCK_STATE_DIR/fail-live-integrity-once"
    printf '%s\n' corrupt
    exit 0
fi

exec "$REAL_SQLITE3" "$@"
SH

    chmod 0755 "$MOCK_BIN/systemctl" "$MOCK_BIN/sqlite3"
    : >"$MOCK_STATE_DIR/systemctl.log"
    install -d -o root -g vaultlink -m 0750 "$(dirname "$CONFIG_PATH")"
    printf '%s\n' '# disposable readiness config' >"$CONFIG_PATH"
    chown root:vaultlink "$CONFIG_PATH"
    chmod 0640 "$CONFIG_PATH"
}

write_binary() {
    path=$1
    marker=$2
    readiness_url=${3:-$HEALTH_URL}
    readiness_connect_to=${4:--}
    readiness_insecure=${5:-0}
    if [[ "$marker" == candidate ]]; then
        version=0.3.2
    else
        version=0.3.0
    fi
    {
        printf '%s\n' '#!/bin/sh'
        printf '%s\n' "# binary-marker:$marker"
        printf "MARKER='%s'\n" "$marker"
        printf "VERSION='%s'\n" "$version"
        printf "READINESS_URL='%s'\n" "$readiness_url"
        printf "READINESS_CONNECT_TO='%s'\n" "$readiness_connect_to"
        printf "READINESS_INSECURE='%s'\n" "$readiness_insecure"
        cat <<'SH'
set -eu

require_service_user() {
    [ "$(id -un)" = vaultlink ]
}

case "${1:-}" in
    --version)
        require_service_user
        printf '%s\n' "$VERSION"
        ;;
    readiness-target)
        require_service_user
        [ "$#" -eq 3 ] && [ "${2:-}" = "--config" ] \
            && [ -f "${3:-}" ] && [ -r "${3:-}" ] || exit 1
        printf '%s\n' "$READINESS_URL" "$READINESS_CONNECT_TO" "$READINESS_INSECURE"
        ;;
    *)
        printf '%s\n' "binary-marker:$MARKER"
        ;;
esac
SH
    } >"$path"
    chmod 0755 "$path"
}

start_health_server() {
    cat >"$TEST_ROOT/health-server.py" <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import sqlite3
import sys
import threading
import time

state_dir = Path(os.environ["MOCK_STATE_DIR"])
live_binary = Path("/opt/vaultlink/vaultlink")
database = "/var/lib/vaultlink/data.sqlite"
counter_lock = threading.Lock()


def read_text(path, default):
    try:
        return path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return default


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def respond(self, status, body):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        if self.path != "/api/v1/health":
            self.respond(404, '{"ok":false}')
            return

        installed = read_text(live_binary, "")
        if "binary-marker:candidate" not in installed:
            self.respond(200, '{"ok":true,"version":"0.3.0"}')
            return

        mode = read_text(state_dir / "health.mode", "success")
        with counter_lock:
            count = int(read_text(state_dir / "health.count", "0")) + 1
            (state_dir / "health.count").write_text(str(count), encoding="utf-8")

        if mode == "delayed":
            ready_after = int(read_text(state_dir / "health.ready-after", "2"))
            if count <= ready_after:
                self.respond(503, '{"ok":false}')
                return
            self.respond(200, '{"ok":true,"version":"0.3.2"}')
            return
        if mode == "http500":
            self.respond(500, '{"ok":false,"version":"0.3.2"}')
            return
        if mode == "wrong-version":
            self.respond(200, '{"ok":true,"version":"0.3.0"}')
            return
        if mode == "invalid-json":
            self.respond(200, '{"ok":true')
            return
        if mode == "timeout":
            time.sleep(3)
            self.respond(200, '{"ok":true,"version":"0.3.2"}')
            return
        if mode == "mutate-then-500":
            if count == 1:
                with sqlite3.connect(database) as connection:
                    connection.execute("UPDATE marker SET value='candidate-write'")
                (state_dir / "health-mutation.done").write_text("yes", encoding="utf-8")
            self.respond(500, '{"ok":false,"version":"0.3.2"}')
            return
        if mode != "success":
            self.respond(500, '{"ok":false,"error":"unknown test mode"}')
            return
        self.respond(200, '{"ok":true,"version":"0.3.2"}')


server = ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler)
server.daemon_threads = True
server.serve_forever()
PY

    python3 "$TEST_ROOT/health-server.py" "$HEALTH_PORT" \
        >"$TEST_ROOT/health-server.log" 2>&1 &
    HEALTH_SERVER_PID=$!
    for _ in $(seq 1 50); do
        if curl --silent --show-error --noproxy '*' --max-time 1 \
            "$HEALTH_URL" >/dev/null 2>&1; then
            return 0
        fi
        if ! kill -0 "$HEALTH_SERVER_PID" 2>/dev/null; then
            break
        fi
        sleep 0.05
    done
    cat "$TEST_ROOT/health-server.log" >&2 || true
    fail "readiness fixture did not start"
}

set_health_mode() {
    mode=$1
    ready_after=${2:-2}
    printf '%s\n' "$mode" >"$MOCK_STATE_DIR/health.mode"
    printf '%s\n' 0 >"$MOCK_STATE_DIR/health.count"
    printf '%s\n' "$ready_after" >"$MOCK_STATE_DIR/health.ready-after"
    rm -f "$MOCK_STATE_DIR/health-mutation.done"
}

initialize_live() {
    binary_marker=$1
    database_marker=$2

    rm -rf /opt/vaultlink /var/lib/vaultlink
    mkdir -p /opt/vaultlink /var/lib/vaultlink/backups
    chown root:vaultlink /opt/vaultlink /var/lib/vaultlink /var/lib/vaultlink/backups
    chmod 0750 /opt/vaultlink /var/lib/vaultlink /var/lib/vaultlink/backups
    write_binary /opt/vaultlink/vaultlink "$binary_marker"
    "$REAL_SQLITE3" /var/lib/vaultlink/data.sqlite \
        "CREATE TABLE marker(value TEXT NOT NULL); INSERT INTO marker VALUES('$database_marker');"
    chown vaultlink:vaultlink /var/lib/vaultlink/data.sqlite
    chmod 0600 /var/lib/vaultlink/data.sqlite
    printf '%s\n' active >"$MOCK_STATE_DIR/service.state"
    printf '%s\n' 0 >"$MOCK_STATE_DIR/stop.count"
    : >"$MOCK_STATE_DIR/systemctl.log"
    rm -f "$MOCK_STATE_DIR"/fail-*-once \
        "$MOCK_STATE_DIR/delayed-active-checks" \
        "$MOCK_STATE_DIR/active-checks-remaining"
    set_health_mode success
}

make_candidate() {
    write_binary "$TEST_ROOT/candidate" candidate
}

make_source_backup() {
    source_backup="$TEST_ROOT/source-backup"
    rm -rf "$source_backup"
    mkdir -p "$source_backup"
    install -m 0755 /opt/vaultlink/vaultlink "$source_backup/vaultlink"
    "$REAL_SQLITE3" /var/lib/vaultlink/data.sqlite ".backup '$source_backup/data.sqlite'"
    printf '%s\n' "$source_backup"
}

assert_binary() {
    expected=$1
    grep -q "binary-marker:$expected" /opt/vaultlink/vaultlink \
        || fail "expected $expected binary"
}

assert_database() {
    expected=$1
    actual=$("$REAL_SQLITE3" /var/lib/vaultlink/data.sqlite "SELECT value FROM marker")
    [[ "$actual" == "$expected" ]] || fail "expected database marker $expected, got $actual"
}

assert_service_active() {
    grep -qx active "$MOCK_STATE_DIR/service.state" || fail "service was not active"
}

assert_no_incomplete_backup() {
    if find /var/lib/vaultlink/backups -mindepth 1 -maxdepth 1 -type d -name '*.incomplete.*' -print -quit | grep -q .; then
        fail "incomplete backup directory was not cleaned"
    fi
}

assert_health_requests() {
    expected=$1
    actual=$(cat "$MOCK_STATE_DIR/health.count")
    [[ "$actual" == "$expected" ]] \
        || fail "expected $expected candidate health requests, got $actual"
}

assert_automatic_upgrade_restore() {
    log_name=$1
    assert_binary original
    assert_database original
    assert_service_active
    assert_no_incomplete_backup
    [[ ! -e /opt/vaultlink/.vaultlink.new ]] || fail "staged upgrade binary was not removed"
    grep -q 'upgrade failed; restoring verified backup' "$TEST_ROOT/$log_name.log" \
        || fail "$log_name did not report automatic backup restoration"

    stop_count=$(grep -c '^stop vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)
    start_count=$(grep -c '^start vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)
    [[ "$stop_count" -eq 2 ]] || fail "$log_name expected two service stops, got $stop_count"
    [[ "$start_count" -eq 2 ]] || fail "$log_name expected two service starts, got $start_count"

    backup_dir=$(find /var/lib/vaultlink/backups -mindepth 1 -maxdepth 1 -type d \
        ! -name '*.incomplete.*' -print -quit)
    [[ -n "$backup_dir" ]] || fail "$log_name did not keep its verified backup"
    grep -q 'binary-marker:original' "$backup_dir/vaultlink" \
        || fail "$log_name backup did not contain the original binary"
    backup_marker=$("$REAL_SQLITE3" "$backup_dir/data.sqlite" "SELECT value FROM marker")
    [[ "$backup_marker" == original ]] || fail "$log_name backup database was not original"
}

expect_failure() {
    name=$1
    shift
    if "$@" >"$TEST_ROOT/$name.log" 2>&1; then
        fail "$name unexpectedly succeeded"
    else
        status=$?
    fi
    [[ "$status" -ne 124 && "$status" -ne 137 ]] \
        || fail "$name exceeded its outer timeout"
}

test_upgrade_success() {
    initialize_live original original
    make_candidate
    backup_dir=$("$UPGRADE" "$TEST_ROOT/candidate")
    [[ -d "$backup_dir" ]] || fail "upgrade did not return a backup directory"
    assert_binary candidate
    assert_database original
    assert_service_active
    assert_no_incomplete_backup
    assert_health_requests 1
    echo "upgrade success case passed"
}

test_upgrade_backup_failure() {
    initialize_live original original
    make_candidate
    touch "$MOCK_STATE_DIR/fail-backup-once"
    expect_failure upgrade-backup-failure "$UPGRADE" "$TEST_ROOT/candidate"
    assert_binary original
    assert_database original
    assert_service_active
    assert_no_incomplete_backup
    echo "upgrade backup-failure recovery passed"
}

test_upgrade_start_failure() {
    initialize_live original original
    make_candidate
    touch "$MOCK_STATE_DIR/fail-start-once"
    expect_failure upgrade-start-failure "$UPGRADE" "$TEST_ROOT/candidate"
    assert_binary original
    assert_database original
    assert_service_active
    assert_no_incomplete_backup
    echo "upgrade start-failure rollback passed"
}

test_upgrade_integrity_failure() {
    initialize_live original original
    make_candidate
    touch "$MOCK_STATE_DIR/fail-live-integrity-once"
    expect_failure upgrade-integrity-failure "$UPGRADE" "$TEST_ROOT/candidate"
    assert_binary original
    assert_database original
    assert_service_active
    assert_no_incomplete_backup
    echo "upgrade post-start integrity rollback passed"
}

test_upgrade_delayed_start_and_health() {
    initialize_live original original
    make_candidate
    printf '%s\n' 2 >"$MOCK_STATE_DIR/delayed-active-checks"
    set_health_mode delayed 2
    backup_dir=$(VAULTLINK_READINESS_ATTEMPTS=4 "$UPGRADE" "$TEST_ROOT/candidate")
    [[ -d "$backup_dir" ]] || fail "delayed upgrade did not return a backup directory"
    assert_binary candidate
    assert_database original
    assert_service_active
    assert_no_incomplete_backup
    assert_health_requests 3
    active_checks=$(grep -c '^--quiet is-active vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)
    [[ "$active_checks" -ge 3 ]] \
        || fail "delayed upgrade did not poll systemd activation"
    echo "upgrade delayed systemd and readiness recovery passed"
}

test_upgrade_standalone_tls_curl_arguments() {
    initialize_live original original
    tls_health_url=https://files.example.test/api/v1/health
    tls_connect_to=files.example.test:443:127.0.0.1:443
    write_binary "$TEST_ROOT/candidate" candidate "$tls_health_url" "$tls_connect_to" 1

    tls_mock_root=/tmp/vaultlink-upgrade-tls-curl
    tls_mock_bin="$tls_mock_root/bin"
    tls_capture="$tls_mock_root/capture"
    rm -rf "$tls_mock_root"
    install -d -o root -g root -m 0755 "$tls_mock_root" "$tls_mock_bin"
    install -d -o vaultlink -g vaultlink -m 0700 "$tls_capture"
    cat >"$tls_mock_bin/curl" <<'SH'
#!/bin/sh
set -eu

count=$(cat "$TLS_CURL_CAPTURE_DIR/count" 2>/dev/null || printf '%s\n' 0)
count=$((count + 1))
printf '%s\n' "$count" >"$TLS_CURL_CAPTURE_DIR/count"
printf '%s\n' "$(id -un)" >"$TLS_CURL_CAPTURE_DIR/user"
: >"$TLS_CURL_CAPTURE_DIR/args"
for argument do
    printf '%s\n' "$argument" >>"$TLS_CURL_CAPTURE_DIR/args"
done
printf '%s' '{"ok":true,"version":"0.3.2"}VAULTLINK_HTTP_STATUS:200'
SH
    chmod 0755 "$tls_mock_bin/curl"

    tls_stdout="$TEST_ROOT/upgrade-standalone-tls.stdout"
    tls_log="$TEST_ROOT/upgrade-standalone-tls.log"
    if PATH="$tls_mock_bin:$PATH" TLS_CURL_CAPTURE_DIR="$tls_capture" \
        "$UPGRADE" "$TEST_ROOT/candidate" >"$tls_stdout" 2>"$tls_log"; then
        tls_status=0
    else
        tls_status=$?
    fi
    tls_curl_count=$(cat "$tls_capture/count" 2>/dev/null || true)
    tls_curl_user=$(cat "$tls_capture/user" 2>/dev/null || true)
    tls_curl_args=$(cat "$tls_capture/args" 2>/dev/null || true)
    rm -rf "$tls_mock_root"

    [[ "$(command -v curl)" == "$REAL_CURL" ]] \
        || fail "standalone TLS test did not restore the real curl"
    if [[ "$tls_status" -ne 0 ]]; then
        cat "$tls_log" >&2
        fail "standalone TLS upgrade failed with status $tls_status"
    fi
    [[ "$tls_curl_count" == 1 ]] \
        || fail "standalone TLS upgrade expected one curl call, got ${tls_curl_count:-none}"
    [[ "$tls_curl_user" == vaultlink ]] \
        || fail "standalone TLS curl ran as ${tls_curl_user:-an unknown user}"

    expected_tls_curl_args=$(cat <<'ARGS'
--disable
--silent
--show-error
--noproxy
*
--proto
=http,https
--connect-timeout
1
--max-time
1
--max-filesize
4096
--header
Accept: application/json
--output
-
--write-out
VAULTLINK_HTTP_STATUS:%{http_code}
--connect-to
files.example.test:443:127.0.0.1:443
--insecure
--
https://files.example.test/api/v1/health
ARGS
)
    if [[ "$tls_curl_args" != "$expected_tls_curl_args" ]]; then
        printf 'expected standalone TLS curl arguments:\n%s\nactual arguments:\n%s\n' \
            "$expected_tls_curl_args" "$tls_curl_args" >&2
        fail "standalone TLS curl arguments were not exact"
    fi

    backup_dir=$(find /var/lib/vaultlink/backups -mindepth 1 -maxdepth 1 -type d \
        ! -name '*.incomplete.*' -print -quit)
    [[ -n "$backup_dir" ]] || fail "standalone TLS upgrade did not keep its verified backup"
    printf '%s\n' "$backup_dir" >"$TEST_ROOT/upgrade-standalone-tls.expected-stdout"
    cmp -s "$TEST_ROOT/upgrade-standalone-tls.expected-stdout" "$tls_stdout" \
        || fail "standalone TLS upgrade stdout contained more than the backup path"
    assert_binary candidate
    assert_database original
    assert_service_active
    assert_no_incomplete_backup
    echo "upgrade standalone TLS curl arguments passed"
}

test_upgrade_health_http_500() {
    initialize_live original original
    make_candidate
    set_health_mode http500
    expect_failure upgrade-health-http-500 env \
        VAULTLINK_READINESS_ATTEMPTS=2 "$UPGRADE" "$TEST_ROOT/candidate"
    grep -q 'candidate readiness failed after 2 attempts (HTTP 500)' \
        "$TEST_ROOT/upgrade-health-http-500.log" \
        || fail "HTTP 500 readiness failure was not reported"
    assert_health_requests 2
    assert_automatic_upgrade_restore upgrade-health-http-500
    echo "upgrade HTTP 500 readiness rollback passed"
}

test_upgrade_health_invalid_json() {
    initialize_live original original
    make_candidate
    set_health_mode invalid-json
    expect_failure upgrade-health-invalid-json env \
        VAULTLINK_READINESS_ATTEMPTS=2 "$UPGRADE" "$TEST_ROOT/candidate"
    grep -q 'candidate readiness failed after 2 attempts (HTTP 200 with unexpected health JSON)' \
        "$TEST_ROOT/upgrade-health-invalid-json.log" \
        || fail "invalid readiness JSON failure was not reported"
    assert_health_requests 2
    assert_automatic_upgrade_restore upgrade-health-invalid-json
    echo "upgrade invalid readiness JSON rollback passed"
}

test_upgrade_health_wrong_version() {
    initialize_live original original
    make_candidate
    set_health_mode wrong-version
    expect_failure upgrade-health-wrong-version env \
        VAULTLINK_READINESS_ATTEMPTS=2 "$UPGRADE" "$TEST_ROOT/candidate"
    grep -q 'candidate readiness failed after 2 attempts (HTTP 200 with unexpected health JSON)' \
        "$TEST_ROOT/upgrade-health-wrong-version.log" \
        || fail "wrong candidate health version was not reported"
    assert_health_requests 2
    assert_automatic_upgrade_restore upgrade-health-wrong-version
    echo "upgrade wrong health version rollback passed"
}

test_upgrade_health_timeout() {
    initialize_live original original
    make_candidate
    set_health_mode timeout
    expect_failure upgrade-health-timeout timeout --kill-after=2 8 env \
        VAULTLINK_READINESS_ATTEMPTS=1 \
        VAULTLINK_READINESS_CONNECT_TIMEOUT_SECONDS=1 \
        VAULTLINK_READINESS_MAX_TIME_SECONDS=1 \
        "$UPGRADE" "$TEST_ROOT/candidate"
    grep -q 'candidate readiness failed after 1 attempts (transport failure)' \
        "$TEST_ROOT/upgrade-health-timeout.log" \
        || fail "curl readiness timeout was not reported"
    assert_health_requests 1
    assert_automatic_upgrade_restore upgrade-health-timeout
    echo "upgrade real curl timeout rollback passed"
}

test_upgrade_health_failure_restores_candidate_write() {
    initialize_live original original
    make_candidate
    set_health_mode mutate-then-500
    expect_failure upgrade-health-mutating-failure env \
        VAULTLINK_READINESS_ATTEMPTS=1 "$UPGRADE" "$TEST_ROOT/candidate"
    [[ -f "$MOCK_STATE_DIR/health-mutation.done" ]] \
        || fail "candidate readiness fixture did not mutate the live database"
    assert_health_requests 1
    assert_automatic_upgrade_restore upgrade-health-mutating-failure
    echo "upgrade readiness failure restored candidate database writes"
}

test_upgrade_recovery_stop_failure_requires_manual_recovery() {
    initialize_live original original
    make_candidate
    set_health_mode mutate-then-500
    touch "$MOCK_STATE_DIR/fail-second-stop-once"
    expect_failure upgrade-recovery-stop-failure env \
        VAULTLINK_READINESS_ATTEMPTS=1 \
        VAULTLINK_READINESS_TIMEOUT_SECONDS=5 \
        "$UPGRADE" "$TEST_ROOT/candidate"

    [[ -f "$MOCK_STATE_DIR/health-mutation.done" ]] \
        || fail "recovery stop fixture did not mutate the live database"
    assert_health_requests 1
    assert_binary candidate
    assert_database candidate-write
    assert_service_active
    assert_no_incomplete_backup
    [[ ! -e /opt/vaultlink/.vaultlink.new ]] \
        || fail "recovery stop failure left the staged upgrade binary behind"

    log_name=upgrade-recovery-stop-failure
    grep -q 'upgrade failed; restoring verified backup' "$TEST_ROOT/$log_name.log" \
        || fail "recovery stop failure did not enter automatic recovery"
    grep -q 'CRITICAL: vaultlink.service could not be stopped; recover manually from ' \
        "$TEST_ROOT/$log_name.log" \
        || fail "recovery stop failure did not require manual recovery"

    stop_count=$(grep -c '^stop vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)
    start_count=$(grep -c '^start vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)
    [[ "$stop_count" -eq 2 ]] \
        || fail "recovery stop failure expected two service stops, got $stop_count"
    [[ "$start_count" -eq 1 ]] \
        || fail "recovery stop failure restarted the service ($start_count starts)"

    backup_dir=$(find /var/lib/vaultlink/backups -mindepth 1 -maxdepth 1 -type d \
        ! -name '*.incomplete.*' -print -quit)
    [[ -n "$backup_dir" ]] || fail "recovery stop failure did not keep its verified backup"
    grep -q 'binary-marker:original' "$backup_dir/vaultlink" \
        || fail "recovery stop failure backup did not contain the original binary"
    backup_marker=$("$REAL_SQLITE3" "$backup_dir/data.sqlite" "SELECT value FROM marker")
    [[ "$backup_marker" == original ]] \
        || fail "recovery stop failure backup database was not original"

    echo "upgrade recovery stop failure preserved candidate state for manual recovery"
}

prepare_rollback_case() {
    initialize_live original original
    source_backup=$(make_source_backup)
    write_binary /opt/vaultlink/vaultlink candidate
    "$REAL_SQLITE3" /var/lib/vaultlink/data.sqlite "UPDATE marker SET value='candidate'"
    printf '%s\n' "$source_backup"
}

test_rollback_success() {
    source_backup=$(prepare_rollback_case)
    output=$("$ROLLBACK" "$source_backup")
    printf '%s\n' "$output" | grep -q 'pre-rollback backup:' \
        || fail "rollback did not report its emergency backup"
    assert_binary original
    assert_database original
    assert_service_active
    assert_no_incomplete_backup
    echo "rollback success case passed"
}

test_rollback_start_failure() {
    source_backup=$(prepare_rollback_case)
    touch "$MOCK_STATE_DIR/fail-start-once"
    expect_failure rollback-start-failure "$ROLLBACK" "$source_backup"
    assert_binary candidate
    assert_database candidate
    assert_service_active
    assert_no_incomplete_backup
    echo "rollback start-failure recovery passed"
}

create_service_account
create_mocks
export PATH="$MOCK_BIN:$PATH"
start_health_server

test_upgrade_success
test_upgrade_backup_failure
test_upgrade_start_failure
test_upgrade_integrity_failure
test_upgrade_delayed_start_and_health
test_upgrade_standalone_tls_curl_arguments
test_upgrade_health_http_500
test_upgrade_health_invalid_json
test_upgrade_health_wrong_version
test_upgrade_health_timeout
test_upgrade_health_failure_restores_candidate_write
test_upgrade_recovery_stop_failure_requires_manual_recovery
test_rollback_success
test_rollback_start_failure

echo "VaultLink upgrade and rollback safety tests passed"
