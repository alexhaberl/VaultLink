#!/bin/sh
set -eu

service=vaultlink.service
install_dir=/opt/vaultlink
live_binary="$install_dir/vaultlink"
staged_binary="$install_dir/.vaultlink.new"
data=/var/lib/vaultlink/data.sqlite
backup_root=/var/lib/vaultlink/backups

if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 1 ]; then
    echo "usage (as root): vaultlink-upgrade.sh NEW_BINARY" >&2
    exit 64
fi

new_binary=$1
[ -x "$new_binary" ] || { echo "new binary is missing or not executable" >&2; exit 1; }
[ -x "$live_binary" ] || { echo "installed VaultLink binary is missing or not executable" >&2; exit 1; }
[ -f "$data" ] || { echo "VaultLink database is missing" >&2; exit 1; }

for required_command in systemctl sqlite3 install mv rm grep sleep date chown chmod; do
    command -v "$required_command" >/dev/null || {
        echo "$required_command is required for a safe upgrade" >&2
        exit 1
    }
done

stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup_dir="$backup_root/$stamp"
backup_stage="$backup_root/.$stamp.incomplete.$$"
[ ! -e "$backup_dir" ] || { echo "backup already exists: $backup_dir" >&2; exit 1; }

was_active=0
stop_attempted=0
backup_valid=0
candidate_activated=0

if systemctl --quiet is-active "$service"; then
    was_active=1
fi

restore_verified_backup() {
    restore_failed=0

    install -o root -g root -m 0755 "$backup_dir/vaultlink" "$live_binary" || restore_failed=1
    rm -f "$data-wal" "$data-shm" || restore_failed=1
    install -o vaultlink -g vaultlink -m 0600 "$backup_dir/data.sqlite" "$data" || restore_failed=1

    return "$restore_failed"
}

on_failure() {
    status=$1
    trap - 0 1 2 15
    set +e

    rm -f "$staged_binary"

    if [ "$candidate_activated" -eq 1 ]; then
        echo "upgrade failed; restoring verified backup $backup_dir" >&2
        systemctl stop "$service" >/dev/null 2>&1 || true
        if [ "$backup_valid" -ne 1 ] || ! restore_verified_backup; then
            echo "CRITICAL: automatic restore failed; recover manually from $backup_dir" >&2
        fi
    elif [ "$stop_attempted" -eq 1 ]; then
        echo "upgrade failed before activation; keeping the installed binary and database" >&2
    fi

    if [ "$stop_attempted" -eq 1 ] && [ "$was_active" -eq 1 ]; then
        if ! systemctl start "$service"; then
            echo "CRITICAL: $service could not be restarted" >&2
        fi
    fi

    if [ -n "$backup_stage" ] && [ -d "$backup_stage" ]; then
        rm -rf "$backup_stage"
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

# Stage all files that can be prepared safely before downtime.
install -d -o root -g vaultlink -m 0750 "$backup_root"
install -d -o root -g vaultlink -m 0750 "$backup_stage"
install -o root -g root -m 0755 "$live_binary" "$backup_stage/vaultlink"
install -o root -g root -m 0755 "$new_binary" "$staged_binary"

stop_attempted=1
systemctl stop "$service"

sqlite3 "$data" ".timeout 10000" ".backup '$backup_stage/data.sqlite'"
chown root:vaultlink "$backup_stage/data.sqlite"
chmod 0640 "$backup_stage/data.sqlite"
sqlite3 "$backup_stage/data.sqlite" "PRAGMA integrity_check" | grep -qx ok
mv "$backup_stage" "$backup_dir"
backup_stage=
backup_valid=1

# Set the state before mv so even interruption at the activation boundary restores safely.
candidate_activated=1
mv -f "$staged_binary" "$live_binary"

systemctl start "$service"
wait_until_active
sqlite3 "$data" ".timeout 10000" "PRAGMA integrity_check" | grep -qx ok

trap - 0 1 2 15
echo "$backup_dir"
