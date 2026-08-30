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
HEALTH_URL="http://127.0.0.1:$HEALTH_PORT/api/v2/health/ready"
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

seed_inherited_nonfixture_binary() {
    install -d -o root -g vaultlink -m 0750 /opt/vaultlink
    # Deliberately invalid UTF-8 models the real ELF left by package smoke and
    # makes the fixture fail if startup ever reads inherited live state again.
    printf '\177ELF\377package-smoke\n' >/opt/vaultlink/vaultlink
    chown root:vaultlink /opt/vaultlink/vaultlink
    chmod 0755 /opt/vaultlink/vaultlink
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
        if service_is_active; then
            printf '%s\n' active
            exit 0
        fi
        printf '%s\n' inactive
        exit 3
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
    write_config "$CONFIG_PATH" original
}

write_binary() {
    path=$1
    marker=$2
    readiness_url=${3:-$HEALTH_URL}
    readiness_connect_to=${4:--}
    readiness_insecure=${5:-0}
    version_override=${6:-}
    if [[ -n "$version_override" ]]; then
        version=$version_override
    elif [[ "$marker" == candidate ]]; then
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
        grep -qx "# config-marker:$MARKER" "$3" || exit 1
        printf '%s\n' "$READINESS_URL" "$READINESS_CONNECT_TO" "$READINESS_INSECURE"
        ;;
    verify-backup-database)
        require_service_user
        [ "$#" -eq 3 ] && [ "${2:-}" = "--database" ] \
            && [ -f "${3:-}" ] && [ -r "${3:-}" ] \
            && [ -s "$(dirname -- "$3")/secrets.keyring" ] || exit 1
        "$REAL_SQLITE3" "$3" "PRAGMA integrity_check" | grep -qx ok
        printf '%s\n' "mock backup database authenticated"
        ;;
    *)
        printf '%s\n' "binary-marker:$MARKER"
        ;;
esac
SH
    } >"$path"
    chmod 0755 "$path"
}

write_config() {
    path=$1
    marker=$2
    printf '# config-marker:%s\n' "$marker" >"$path"
    chown root:vaultlink "$path"
    chmod 0640 "$path"
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


def binary_version(binary_text):
    for line in binary_text.splitlines():
        if line.startswith("VERSION='") and line.endswith("'"):
            return line[len("VERSION='"):-1]
    return "0.0.0-invalid-fixture"


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
        if self.path != "/api/v2/health/ready":
            self.respond(404, '{"ok":false}')
            return

        installed = read_text(live_binary, "")
        version = binary_version(installed)
        if "binary-marker:candidate" not in installed:
            self.respond(200, f'{{"ok":true,"version":"{version}"}}')
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
            self.respond(200, f'{{"ok":true,"version":"{version}"}}')
            return
        if mode == "http500":
            self.respond(500, f'{{"ok":false,"version":"{version}"}}')
            return
        if mode == "wrong-version":
            self.respond(200, '{"ok":true,"version":"0.3.0"}')
            return
        if mode == "invalid-json":
            self.respond(200, '{"ok":true')
            return
        if mode == "timeout":
            time.sleep(3)
            self.respond(200, f'{{"ok":true,"version":"{version}"}}')
            return
        if mode == "mutate-then-500":
            if count == 1:
                with sqlite3.connect(database) as connection:
                    connection.execute("UPDATE marker SET value='candidate-write'")
                (state_dir / "health-mutation.done").write_text("yes", encoding="utf-8")
            self.respond(500, f'{{"ok":false,"version":"{version}"}}')
            return
        if mode != "success":
            self.respond(500, '{"ok":false,"error":"unknown test mode"}')
            return
        self.respond(200, f'{{"ok":true,"version":"{version}"}}')


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

    rm -rf /opt/vaultlink /var/lib/vaultlink /var/lib/vaultlink-backups
    mkdir -p /opt/vaultlink /var/lib/vaultlink
    chown root:vaultlink /opt/vaultlink /var/lib/vaultlink
    chmod 0750 /opt/vaultlink /var/lib/vaultlink
    write_binary /opt/vaultlink/vaultlink "$binary_marker"
    "$REAL_SQLITE3" /var/lib/vaultlink/data.sqlite \
        "CREATE TABLE marker(value TEXT NOT NULL);
         INSERT INTO marker VALUES('$database_marker');"
    chown vaultlink:vaultlink /var/lib/vaultlink/data.sqlite
    chmod 0600 /var/lib/vaultlink/data.sqlite
    printf '%s\n' '{"version":1,"active_key_id":1,"keys":[{"id":1,"key":"test-keyring-fixture"}]}' \
        >/var/lib/vaultlink/secrets.keyring
    chown vaultlink:vaultlink /var/lib/vaultlink/secrets.keyring
    chmod 0600 /var/lib/vaultlink/secrets.keyring
    write_config "$CONFIG_PATH" "$binary_marker"
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
    write_config "$TEST_ROOT/candidate.toml" candidate
}

make_source_backup() {
    install -d -o root -g root -m 0700 /var/lib/vaultlink-backups
    source_backup=/var/lib/vaultlink-backups/source-backup
    rm -rf "$source_backup"
    install -d -o root -g root -m 0700 "$source_backup"
    install -o root -g root -m 0700 /opt/vaultlink/vaultlink "$source_backup/vaultlink"
    install -o root -g root -m 0600 "$CONFIG_PATH" "$source_backup/config.toml"
    "$REAL_SQLITE3" /var/lib/vaultlink/data.sqlite ".backup '$source_backup/data.sqlite'"
    chown root:root "$source_backup/data.sqlite"
    chmod 0600 "$source_backup/data.sqlite"
    install -o root -g root -m 0600 \
        /var/lib/vaultlink/secrets.keyring "$source_backup/secrets.keyring"
    printf '%s\n' "$source_backup"
}

prepare_package_rollback_target() {
    package_backup=$1
    install -d -o root -g root -m 0755 /usr/lib/vaultlink/package/deploy
    install -o root -g root -m 0755 \
        "$package_backup/vaultlink" /usr/lib/vaultlink/package/vaultlink
    runuser -u vaultlink -- /usr/lib/vaultlink/package/vaultlink --version \
        >/usr/lib/vaultlink/package/version
    chown root:root /usr/lib/vaultlink/package/version
    chmod 0644 /usr/lib/vaultlink/package/version
    cat >/usr/lib/vaultlink/package/deploy/vaultlink-runtime-guard.sh <<'SH'
#!/bin/sh
set -eu
[ "$#" -eq 1 ] && [ "$1" = --package-only ]
[ -x /usr/lib/vaultlink/package/vaultlink ]
[ -f /usr/lib/vaultlink/package/version ]
[ "$(runuser -u vaultlink -- /usr/lib/vaultlink/package/vaultlink --version)" = \
    "$(cat /usr/lib/vaultlink/package/version)" ]
SH
    chown root:root /usr/lib/vaultlink/package/deploy/vaultlink-runtime-guard.sh
    chmod 0755 /usr/lib/vaultlink/package/deploy/vaultlink-runtime-guard.sh
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

assert_config() {
    expected=$1
    grep -qx "# config-marker:$expected" "$CONFIG_PATH" \
        || fail "expected $expected configuration"
}

assert_backup_unit() {
    backup_dir=$1
    expected=$2
    grep -q "binary-marker:$expected" "$backup_dir/vaultlink" \
        || fail "backup binary was not $expected"
    grep -qx "# config-marker:$expected" "$backup_dir/config.toml" \
        || fail "backup configuration was not $expected"
    backup_marker=$("$REAL_SQLITE3" "$backup_dir/data.sqlite" "SELECT value FROM marker")
    [[ "$backup_marker" == "$expected" ]] \
        || fail "backup database was not $expected"
    [[ -s "$backup_dir/secrets.keyring" ]] \
        || fail "backup secrets keyring was missing or empty"
    [[ "$(stat -c '%U:%G:%a' "$backup_dir")" == root:root:700 ]] \
        || fail "backup directory owner or mode was not root:root 0700"
    [[ "$(stat -c '%U:%G:%a' "$backup_dir/vaultlink")" == root:root:700 ]] \
        || fail "backup binary owner or mode was not root:root 0700"
    [[ "$(stat -c '%U:%G:%a' "$backup_dir/config.toml")" == root:root:600 ]] \
        || fail "backup configuration owner or mode was not root:root 0600"
    [[ "$(stat -c '%U:%G:%a' "$backup_dir/data.sqlite")" == root:root:600 ]] \
        || fail "backup database owner or mode was not root:root 0600"
    [[ "$(stat -c '%U:%G:%a' "$backup_dir/secrets.keyring")" == root:root:600 ]] \
        || fail "backup secrets keyring owner or mode was not root:root 0600"
}

assert_service_active() {
    grep -qx active "$MOCK_STATE_DIR/service.state" || fail "service was not active"
}

assert_service_inactive() {
    grep -qx inactive "$MOCK_STATE_DIR/service.state" || fail "service was not inactive"
}

assert_no_incomplete_backup() {
    if find /var/lib/vaultlink-backups -mindepth 1 -maxdepth 1 -type d -name '*.incomplete.*' -print -quit 2>/dev/null | grep -q .; then
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
    assert_config original
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

    backup_dir=$(find /var/lib/vaultlink-backups -mindepth 1 -maxdepth 1 -type d \
        ! -name '*.incomplete.*' -print -quit)
    [[ -n "$backup_dir" ]] || fail "$log_name did not keep its verified backup"
    assert_backup_unit "$backup_dir" original
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
    backup_dir=$("$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml")
    [[ -d "$backup_dir" ]] || fail "upgrade did not return a backup directory"
    assert_backup_unit "$backup_dir" original
    assert_binary candidate
    assert_config candidate
    assert_database original
    assert_service_active
    assert_no_incomplete_backup
    assert_health_requests 1
    echo "upgrade success case passed"
}

test_upgrade_rejects_mismatched_binary_configuration_pair_before_stop() {
    initialize_live original original
    make_candidate
    write_config "$TEST_ROOT/candidate.toml" original

    expect_failure upgrade-pair-mismatch \
        "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml"
    assert_binary original
    assert_config original
    assert_database original
    assert_service_active
    [[ "$(grep -c '^stop vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)" -eq 0 ]] \
        || fail "binary/configuration mismatch stopped the service"
    echo "upgrade binary/configuration pairing preflight passed"
}

test_upgrade_maintenance_lock_fails_before_stop() {
    initialize_live original original
    make_candidate
    install -d -o root -g root -m 0700 /run/vaultlink-locks
    install -o root -g root -m 0600 /dev/null \
        /run/vaultlink-locks/maintenance.lock
    exec 8>/run/vaultlink-locks/maintenance.lock
    flock -n 8
    expect_failure upgrade-maintenance-lock \
        "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml"
    flock -u 8
    exec 8>&-
    assert_binary original
    assert_config original
    assert_database original
    [[ "$(grep -c '^stop vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)" -eq 0 ]] \
        || fail "maintenance lock contention stopped the service"
    echo "upgrade and rollback shared maintenance lock passed"
}

test_upgrade_accepts_only_verified_inherited_lock() {
    initialize_live original original
    make_candidate
    install -d -o root -g root -m 0700 /run/vaultlink-locks
    install -o root -g root -m 0600 /dev/null \
        /run/vaultlink-locks/maintenance.lock
    exec 8>/run/vaultlink-locks/maintenance.lock
    flock -n 8
    VAULTLINK_MAINTENANCE_LOCK_FD=8 \
        "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml" >/dev/null
    assert_binary candidate
    assert_config candidate
    assert_database original
    assert_service_active
    if flock -n /run/vaultlink-locks/maintenance.lock -c true; then
        fail "upgrade helper released the inherited maintenance lock"
    fi
    flock -u 8
    exec 8>&-

    initialize_live original original
    make_candidate
    exec 8>"$TEST_ROOT/not-the-maintenance-lock"
    flock -n 8
    VAULTLINK_MAINTENANCE_LOCK_FD=8 expect_failure inherited-wrong-inode \
        "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml"
    flock -u 8
    exec 8>&-
    assert_binary original
    assert_config original
    assert_database original
    [[ "$(grep -c '^stop vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)" -eq 0 ]] \
        || fail "invalid inherited maintenance lock stopped the service"

    initialize_live original original
    make_candidate
    VAULTLINK_MAINTENANCE_LOCK_FD=9 expect_failure inherited-invalid-fd \
        "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml"
    [[ "$(grep -c '^stop vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)" -eq 0 ]] \
        || fail "invalid inherited maintenance FD stopped the service"
    echo "upgrade inherited maintenance-lock contract passed"
}

test_upgrade_rejects_semantic_downgrades_before_stop() {
    for candidate_version in 0.4.1 0.3.9; do
        initialize_live original original
        write_binary /opt/vaultlink/vaultlink original "$HEALTH_URL" - 0 0.4.2
        write_binary "$TEST_ROOT/candidate" candidate "$HEALTH_URL" - 0 "$candidate_version"
        write_config "$TEST_ROOT/candidate.toml" candidate
        log_name="upgrade-downgrade-${candidate_version//./}"

        expect_failure "$log_name" \
            "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml"
        grep -q "candidate version $candidate_version is older than installed version 0.4.2; use the rollback script" \
            "$TEST_ROOT/$log_name.log" \
            || fail "semantic downgrade to $candidate_version was not explained"
        assert_binary original
        assert_config original
        assert_database original
        assert_service_active
        [[ "$(grep -c '^stop vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)" -eq 0 ]] \
            || fail "semantic downgrade to $candidate_version stopped the service"
    done
    echo "upgrade semantic-downgrade gates passed"
}

test_semver_prerelease_build_and_validation_rules() {
    initialize_live original original
    write_binary /opt/vaultlink/vaultlink original "$HEALTH_URL" - 0 '1.0.0-alpha.1+old'
    write_binary "$TEST_ROOT/candidate" candidate "$HEALTH_URL" - 0 '1.0.0-alpha.2+new'
    write_config "$TEST_ROOT/candidate.toml" candidate
    "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml" >/dev/null
    assert_binary candidate
    assert_config candidate
    assert_service_active

    initialize_live original original
    write_binary /opt/vaultlink/vaultlink original "$HEALTH_URL" - 0 '1.0.0+old'
    write_binary "$TEST_ROOT/candidate" candidate "$HEALTH_URL" - 0 '1.0.0+new'
    write_config "$TEST_ROOT/candidate.toml" candidate
    "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml" >/dev/null
    assert_binary candidate
    assert_config candidate
    assert_service_active

    initialize_live original original
    write_binary /opt/vaultlink/vaultlink original "$HEALTH_URL" - 0 '1.0.0'
    write_binary "$TEST_ROOT/candidate" candidate "$HEALTH_URL" - 0 '1.0.0-rc.1+build.7'
    write_config "$TEST_ROOT/candidate.toml" candidate
    expect_failure upgrade-prerelease-downgrade \
        "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml"
    grep -q 'candidate version 1.0.0-rc.1+build.7 is older than installed version 1.0.0' \
        "$TEST_ROOT/upgrade-prerelease-downgrade.log" \
        || fail "SemVer prerelease downgrade was not rejected"
    [[ "$(grep -c '^stop vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)" -eq 0 ]] \
        || fail "SemVer prerelease downgrade stopped the service"

    invalid_index=0
    for invalid_version in '01.0.0' '1.0' '1.0.0-01' '1.0.0+'; do
        invalid_index=$((invalid_index + 1))
        initialize_live original original
        write_binary /opt/vaultlink/vaultlink original "$HEALTH_URL" - 0 '1.0.0'
        write_binary "$TEST_ROOT/candidate" candidate "$HEALTH_URL" - 0 "$invalid_version"
        write_config "$TEST_ROOT/candidate.toml" candidate
        log_name="upgrade-invalid-semver-$invalid_index"
        expect_failure "$log_name" \
            "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml"
        grep -q 'invalid semantic version:' "$TEST_ROOT/$log_name.log" \
            || fail "invalid semantic version $invalid_version was not explained"
        [[ "$(grep -c '^stop vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)" -eq 0 ]] \
            || fail "invalid semantic version $invalid_version stopped the service"
    done
    echo "SemVer prerelease, build metadata, and validation rules passed"
}

test_upgrade_backup_failure() {
    initialize_live original original
    make_candidate
    touch "$MOCK_STATE_DIR/fail-backup-once"
    expect_failure upgrade-backup-failure "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml"
    assert_binary original
    assert_config original
    assert_database original
    assert_service_active
    assert_no_incomplete_backup
    echo "upgrade backup-failure recovery passed"
}

test_upgrade_start_failure() {
    initialize_live original original
    make_candidate
    touch "$MOCK_STATE_DIR/fail-start-once"
    expect_failure upgrade-start-failure "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml"
    assert_binary original
    assert_config original
    assert_database original
    assert_service_active
    assert_no_incomplete_backup
    echo "upgrade start-failure rollback passed"
}

test_upgrade_integrity_failure() {
    initialize_live original original
    make_candidate
    touch "$MOCK_STATE_DIR/fail-live-integrity-once"
    expect_failure upgrade-integrity-failure "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml"
    assert_binary original
    assert_config original
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
    backup_dir=$(VAULTLINK_READINESS_ATTEMPTS=4 "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml")
    [[ -d "$backup_dir" ]] || fail "delayed upgrade did not return a backup directory"
    assert_binary candidate
    assert_config candidate
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
    tls_health_url=https://files.example.test/api/v2/health/ready
    tls_connect_to=files.example.test:443:127.0.0.1:443
    write_binary "$TEST_ROOT/candidate" candidate "$tls_health_url" "$tls_connect_to" 1
    write_config "$TEST_ROOT/candidate.toml" candidate

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
        "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml" >"$tls_stdout" 2>"$tls_log"; then
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
https://files.example.test/api/v2/health/ready
ARGS
)
    if [[ "$tls_curl_args" != "$expected_tls_curl_args" ]]; then
        printf 'expected standalone TLS curl arguments:\n%s\nactual arguments:\n%s\n' \
            "$expected_tls_curl_args" "$tls_curl_args" >&2
        fail "standalone TLS curl arguments were not exact"
    fi

    backup_dir=$(find /var/lib/vaultlink-backups -mindepth 1 -maxdepth 1 -type d \
        ! -name '*.incomplete.*' -print -quit)
    [[ -n "$backup_dir" ]] || fail "standalone TLS upgrade did not keep its verified backup"
    printf '%s\n' "$backup_dir" >"$TEST_ROOT/upgrade-standalone-tls.expected-stdout"
    cmp -s "$TEST_ROOT/upgrade-standalone-tls.expected-stdout" "$tls_stdout" \
        || fail "standalone TLS upgrade stdout contained more than the backup path"
    assert_binary candidate
    assert_config candidate
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
        VAULTLINK_READINESS_ATTEMPTS=2 "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml"
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
        VAULTLINK_READINESS_ATTEMPTS=2 "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml"
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
        VAULTLINK_READINESS_ATTEMPTS=2 "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml"
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
        "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml"
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
        VAULTLINK_READINESS_ATTEMPTS=1 "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml"
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
        "$UPGRADE" "$TEST_ROOT/candidate" "$TEST_ROOT/candidate.toml"

    [[ -f "$MOCK_STATE_DIR/health-mutation.done" ]] \
        || fail "recovery stop fixture did not mutate the live database"
    assert_health_requests 1
    assert_binary candidate
    assert_config candidate
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

    backup_dir=$(find /var/lib/vaultlink-backups -mindepth 1 -maxdepth 1 -type d \
        ! -name '*.incomplete.*' -print -quit)
    [[ -n "$backup_dir" ]] || fail "recovery stop failure did not keep its verified backup"
    assert_backup_unit "$backup_dir" original

    echo "upgrade recovery stop failure preserved candidate state for manual recovery"
}

prepare_rollback_case() {
    initialize_live original original
    source_backup=$(make_source_backup)
    prepare_package_rollback_target "$source_backup"
    write_binary /opt/vaultlink/vaultlink candidate
    write_config "$CONFIG_PATH" candidate
    "$REAL_SQLITE3" /var/lib/vaultlink/data.sqlite "UPDATE marker SET value='candidate'"
    printf '%s\n' inactive >"$MOCK_STATE_DIR/service.state"
    printf '%s\n' "$source_backup"
}

test_rollback_verify_only_preserves_active_service() {
    initialize_live original original
    source_backup=$(make_source_backup)
    prepare_package_rollback_target "$source_backup"

    output=$("$ROLLBACK" --verify-only "$source_backup")
    printf '%s\n' "$output" | grep -q 'backup verified for VaultLink 0.3.0:' \
        || fail "verify-only did not report the verified backup"
    printf '%s\n' "$output" | grep -q '^mock backup database authenticated$' \
        || fail "verify-only did not authenticate the copied database/keyring pair"
    assert_binary original
    assert_config original
    assert_database original
    assert_service_active
    [[ "$(grep -c '^stop vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)" -eq 0 ]] \
        || fail "verify-only stopped the active service"
    [[ -z "$(find /var/lib/vaultlink -maxdepth 1 -name '.backup-verify.*' -print -quit)" ]] \
        || fail "verify-only left its private database copy behind"
    echo "rollback verify-only preserved the active service"
}

test_rollback_verify_only_rejects_corrupt_database() {
    initialize_live original original
    source_backup=$(make_source_backup)
    prepare_package_rollback_target "$source_backup"
    printf '%s\n' 'not a SQLite database' >"$source_backup/data.sqlite"

    expect_failure rollback-verify-corrupt "$ROLLBACK" --verify-only "$source_backup"
    assert_binary original
    assert_config original
    assert_database original
    assert_service_active
    [[ "$(grep -c '^stop vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)" -eq 0 ]] \
        || fail "failed verify-only stopped the active service"
    echo "rollback verify-only rejected a corrupt database without service mutation"
}

test_rollback_success() {
    source_backup=$(prepare_rollback_case)
    output=$("$ROLLBACK" "$source_backup")
    printf '%s\n' "$output" | grep -q 'pre-rollback backup:' \
        || fail "rollback did not report its emergency backup"
    assert_binary original
    assert_config original
    assert_database original
    assert_service_active
    assert_no_incomplete_backup
    emergency_dir=${output##*pre-rollback backup: }
    [[ -d "$emergency_dir" ]] || fail "rollback emergency backup path was invalid"
    assert_backup_unit "$emergency_dir" candidate
    echo "rollback success case passed"
}

test_rollback_start_failure() {
    source_backup=$(prepare_rollback_case)
    touch "$MOCK_STATE_DIR/fail-start-once"
    expect_failure rollback-start-failure "$ROLLBACK" "$source_backup"
    assert_binary candidate
    assert_config candidate
    assert_database candidate
    assert_service_inactive
    assert_no_incomplete_backup
    echo "rollback start-failure recovery passed"
}

test_rollback_rejects_incomplete_backup_before_stop() {
    source_backup=$(prepare_rollback_case)
    rm -f "$source_backup/config.toml"
    expect_failure rollback-missing-config "$ROLLBACK" "$source_backup"
    assert_binary candidate
    assert_config candidate
    assert_database candidate
    assert_service_inactive
    [[ "$(grep -c '^stop vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)" -eq 0 ]] \
        || fail "incomplete rollback backup stopped the service"
    echo "rollback incomplete backup-unit preflight passed"
}

test_rollback_rejects_mismatched_pair_before_stop() {
    source_backup=$(prepare_rollback_case)
    write_config "$source_backup/config.toml" candidate
    expect_failure rollback-pair-mismatch "$ROLLBACK" "$source_backup"
    assert_binary candidate
    assert_config candidate
    assert_database candidate
    assert_service_inactive
    [[ "$(grep -c '^stop vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)" -eq 0 ]] \
        || fail "mismatched rollback pair stopped the service"
    echo "rollback binary/configuration pairing preflight passed"
}

test_rollback_rejects_unsafe_backup_inputs_before_stop() {
    source_backup=$(prepare_rollback_case)
    rm -f "$source_backup/config.toml"
    ln -s "$CONFIG_PATH" "$source_backup/config.toml"
    expect_failure rollback-symlink-source "$ROLLBACK" "$source_backup"
    assert_service_inactive
    [[ "$(grep -c '^stop vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)" -eq 0 ]] \
        || fail "symlinked rollback input stopped the service"

    source_backup=$(prepare_rollback_case)
    chmod 0755 "$source_backup"
    expect_failure rollback-writable-parent "$ROLLBACK" "$source_backup"
    assert_service_inactive
    [[ "$(grep -c '^stop vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)" -eq 0 ]] \
        || fail "writable rollback parent stopped the service"

    source_backup=$(prepare_rollback_case)
    backup_link=/var/lib/vaultlink-backups/source-backup-link
    ln -s "$source_backup" "$backup_link"
    expect_failure rollback-symlink-directory "$ROLLBACK" "$backup_link"
    assert_service_inactive
    [[ "$(grep -c '^stop vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)" -eq 0 ]] \
        || fail "symlinked rollback directory stopped the service"

    source_backup=$(prepare_rollback_case)
    install -o root -g root -m 0700 /bin/true "$source_backup/vaultlink"
    expect_failure rollback-wrong-package-candidate "$ROLLBACK" "$source_backup"
    assert_service_inactive
    [[ "$(grep -c '^stop vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)" -eq 0 ]] \
        || fail "wrong package rollback target stopped the service"
    echo "rollback root-only input and package-target guards passed"
}

test_rollback_rejects_semantic_roll_forward_before_stop() {
    initialize_live original original
    source_backup=$(make_source_backup)
    write_binary "$source_backup/vaultlink" original "$HEALTH_URL" - 0 '0.4.2'
    chmod 0700 "$source_backup/vaultlink"
    prepare_package_rollback_target "$source_backup"
    write_binary /opt/vaultlink/vaultlink candidate "$HEALTH_URL" - 0 '0.4.1'
    write_config "$CONFIG_PATH" candidate
    "$REAL_SQLITE3" /var/lib/vaultlink/data.sqlite "UPDATE marker SET value='candidate'"
    printf '%s\n' inactive >"$MOCK_STATE_DIR/service.state"

    expect_failure rollback-roll-forward "$ROLLBACK" "$source_backup"
    grep -q 'requested version 0.4.2 is newer than installed version 0.4.1; use the upgrade script' \
        "$TEST_ROOT/rollback-roll-forward.log" \
        || fail "semantic rollback roll-forward was not explained"
    assert_binary candidate
    assert_config candidate
    assert_database candidate
    assert_service_inactive
    [[ "$(grep -c '^stop vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)" -eq 0 ]] \
        || fail "semantic rollback roll-forward stopped the service"
    echo "rollback semantic roll-forward gate passed"
}

test_rollback_recovery_stop_failure_stays_fail_closed() {
    source_backup=$(prepare_rollback_case)
    touch "$MOCK_STATE_DIR/fail-start-once" "$MOCK_STATE_DIR/fail-second-stop-once"
    expect_failure rollback-recovery-stop-failure "$ROLLBACK" "$source_backup"
    assert_binary original
    assert_config original
    assert_database original
    assert_service_inactive
    grep -q 'CRITICAL: vaultlink.service could not be stopped; recover manually from ' \
        "$TEST_ROOT/rollback-recovery-stop-failure.log" \
        || fail "rollback recovery stop failure did not report manual recovery"
    [[ "$(grep -c '^start vaultlink.service$' "$MOCK_STATE_DIR/systemctl.log" || true)" -eq 1 ]] \
        || fail "rollback recovery stop failure attempted an unsafe restart"
    echo "rollback recovery stop failure remained fail closed"
}

create_service_account
create_mocks
seed_inherited_nonfixture_binary
export PATH="$MOCK_BIN:$PATH"
initialize_live original original
start_health_server

test_upgrade_success
test_upgrade_rejects_mismatched_binary_configuration_pair_before_stop
test_upgrade_maintenance_lock_fails_before_stop
test_upgrade_accepts_only_verified_inherited_lock
test_upgrade_rejects_semantic_downgrades_before_stop
test_semver_prerelease_build_and_validation_rules
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
test_rollback_verify_only_preserves_active_service
test_rollback_verify_only_rejects_corrupt_database
test_rollback_success
test_rollback_start_failure
test_rollback_rejects_incomplete_backup_before_stop
test_rollback_rejects_mismatched_pair_before_stop
test_rollback_rejects_unsafe_backup_inputs_before_stop
test_rollback_rejects_semantic_roll_forward_before_stop
test_rollback_recovery_stop_failure_stays_fail_closed

echo "VaultLink upgrade and rollback safety tests passed"
