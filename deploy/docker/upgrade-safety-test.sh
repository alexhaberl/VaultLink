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
REAL_SQLITE3="$(command -v sqlite3)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
UPGRADE="$REPO_ROOT/deploy/vaultlink-upgrade.sh"
ROLLBACK="$REPO_ROOT/deploy/vaultlink-rollback.sh"

export MOCK_STATE_DIR REAL_SQLITE3

fail() {
    echo "upgrade safety test failed: $*" >&2
    exit 1
}

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

if [ "${1:-}" = "--quiet" ] && [ "${2:-}" = "is-active" ]; then
    grep -qx active "$MOCK_STATE_DIR/service.state"
    exit $?
fi

case "${1:-}" in
    stop)
        printf '%s\n' inactive >"$MOCK_STATE_DIR/service.state"
        ;;
    start)
        if [ -f "$MOCK_STATE_DIR/fail-start-once" ]; then
            rm -f "$MOCK_STATE_DIR/fail-start-once"
            exit 1
        fi
        printf '%s\n' active >"$MOCK_STATE_DIR/service.state"
        ;;
    is-active)
        grep -qx active "$MOCK_STATE_DIR/service.state"
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
}

write_binary() {
    path=$1
    marker=$2
    printf '%s\n' '#!/bin/sh' "echo binary-marker:$marker" >"$path"
    chmod 0755 "$path"
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
    : >"$MOCK_STATE_DIR/systemctl.log"
    rm -f "$MOCK_STATE_DIR"/fail-*-once
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

expect_failure() {
    name=$1
    shift
    if "$@" >"$TEST_ROOT/$name.log" 2>&1; then
        fail "$name unexpectedly succeeded"
    fi
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

test_upgrade_success
test_upgrade_backup_failure
test_upgrade_start_failure
test_upgrade_integrity_failure
test_rollback_success
test_rollback_start_failure

echo "VaultLink upgrade and rollback safety tests passed"
