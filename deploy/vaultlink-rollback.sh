#!/bin/sh
set -eu

service=vaultlink.service
install_dir=/opt/vaultlink
live_binary="$install_dir/vaultlink"
staged_binary="$install_dir/.vaultlink.rollback.new"
data=/var/lib/vaultlink/data.sqlite
backup_root=/var/lib/vaultlink/backups

if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 1 ]; then
    echo "usage (as root): vaultlink-rollback.sh BACKUP_DIRECTORY" >&2
    exit 64
fi

backup_dir=$1
[ -x "$backup_dir/vaultlink" ] || { echo "backup binary missing" >&2; exit 1; }
[ -f "$backup_dir/data.sqlite" ] || { echo "database backup missing" >&2; exit 1; }
[ -x "$live_binary" ] || { echo "installed VaultLink binary is missing or not executable" >&2; exit 1; }
[ -f "$data" ] || { echo "live VaultLink database is missing" >&2; exit 1; }

for required_command in systemctl sqlite3 install mv rm grep sleep date chown chmod; do
    command -v "$required_command" >/dev/null || {
        echo "$required_command is required for a safe rollback" >&2
        exit 1
    }
done

sqlite3 "$backup_dir/data.sqlite" "PRAGMA integrity_check" | grep -qx ok

stamp=$(date -u +%Y%m%dT%H%M%SZ)
emergency_dir="$backup_root/rollback-pre-$stamp"
emergency_stage="$backup_root/.rollback-pre-$stamp.incomplete.$$"
staged_data="$backup_root/.data.sqlite.rollback.$stamp.$$.new"
[ ! -e "$emergency_dir" ] || { echo "pre-rollback backup already exists: $emergency_dir" >&2; exit 1; }

was_active=0
stop_attempted=0
emergency_valid=0
replacement_started=0

if systemctl --quiet is-active "$service"; then
    was_active=1
fi

restore_pre_rollback_state() {
    restore_failed=0

    install -o root -g root -m 0755 "$emergency_dir/vaultlink" "$live_binary" || restore_failed=1
    rm -f "$data-wal" "$data-shm" || restore_failed=1
    install -o vaultlink -g vaultlink -m 0600 "$emergency_dir/data.sqlite" "$data" || restore_failed=1

    return "$restore_failed"
}

on_failure() {
    status=$1
    trap - 0 1 2 15
    set +e

    rm -f "$staged_binary" "$staged_data"

    if [ "$replacement_started" -eq 1 ]; then
        echo "rollback failed; restoring pre-rollback state $emergency_dir" >&2
        systemctl stop "$service" >/dev/null 2>&1 || true
        if [ "$emergency_valid" -ne 1 ] || ! restore_pre_rollback_state; then
            echo "CRITICAL: automatic recovery failed; recover manually from $emergency_dir" >&2
        fi
    elif [ "$stop_attempted" -eq 1 ]; then
        echo "rollback failed before replacement; keeping the current installation" >&2
    fi

    if [ "$stop_attempted" -eq 1 ] && [ "$was_active" -eq 1 ]; then
        if ! systemctl start "$service"; then
            echo "CRITICAL: $service could not be restarted" >&2
        fi
    fi

    if [ -d "$emergency_stage" ]; then
        rm -rf "$emergency_stage"
    fi

    exit "$status"
}

wait_until_active() {
    attempts=0
    while [ "$attempts" -lt 10 ]; do
        if systemctl --quiet is-active "$service"; then
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 1
    done
    return 1
}

trap 'on_failure $?' 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

# Pre-stage the requested backup on the destination filesystems before downtime.
install -d -o root -g vaultlink -m 0750 "$backup_root"
install -o root -g root -m 0755 "$backup_dir/vaultlink" "$staged_binary"
install -o root -g vaultlink -m 0640 "$backup_dir/data.sqlite" "$staged_data"
sqlite3 "$staged_data" "PRAGMA integrity_check" | grep -qx ok

stop_attempted=1
systemctl stop "$service"

# Preserve the exact stopped state so a failed rollback can itself be rolled back.
install -d -o root -g vaultlink -m 0750 "$emergency_stage"
install -o root -g root -m 0755 "$live_binary" "$emergency_stage/vaultlink"
sqlite3 "$data" ".timeout 10000" ".backup '$emergency_stage/data.sqlite'"
chown root:vaultlink "$emergency_stage/data.sqlite"
chmod 0640 "$emergency_stage/data.sqlite"
sqlite3 "$emergency_stage/data.sqlite" "PRAGMA integrity_check" | grep -qx ok
mv "$emergency_stage" "$emergency_dir"
emergency_valid=1

chown vaultlink:vaultlink "$staged_data"
chmod 0600 "$staged_data"

# Set the state before the first mv so interruption at either replacement boundary recovers.
replacement_started=1
mv -f "$staged_binary" "$live_binary"
rm -f "$data-wal" "$data-shm"
mv -f "$staged_data" "$data"

systemctl start "$service"
wait_until_active
sqlite3 "$data" ".timeout 10000" "PRAGMA integrity_check" | grep -qx ok

trap - 0 1 2 15
echo "rollback completed; pre-rollback backup: $emergency_dir"
