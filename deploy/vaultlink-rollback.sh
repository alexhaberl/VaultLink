#!/bin/sh
set -eu
umask 077

service=vaultlink.service
install_dir=/opt/vaultlink
live_binary="$install_dir/vaultlink"
staged_binary="$install_dir/.vaultlink.rollback.new"
restore_binary="$install_dir/.vaultlink.rollback.restore"
data=/var/lib/vaultlink/data.sqlite
data_dir=/var/lib/vaultlink
backup_root=/var/lib/vaultlink-backups
staged_data=
restore_data=
config_path=/etc/vaultlink/config.toml
staged_config=/etc/vaultlink/.config.toml.rollback.new
restore_config=/etc/vaultlink/.config.toml.rollback.restore
maintenance_lock=/run/lock/vaultlink-maintenance.lock
readiness_attempts=${VAULTLINK_READINESS_ATTEMPTS:-30}
readiness_timeout_seconds=${VAULTLINK_READINESS_TIMEOUT_SECONDS:-60}
readiness_interval_seconds=${VAULTLINK_READINESS_INTERVAL_SECONDS:-1}
readiness_connect_timeout_seconds=${VAULTLINK_READINESS_CONNECT_TIMEOUT_SECONDS:-2}
readiness_max_time_seconds=${VAULTLINK_READINESS_MAX_TIME_SECONDS:-3}

if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 1 ]; then
    echo "usage (as root): vaultlink-rollback.sh BACKUP_DIRECTORY" >&2
    exit 64
fi

backup_dir=$1
[ -x "$backup_dir/vaultlink" ] || { echo "backup binary missing" >&2; exit 1; }
[ -f "$backup_dir/config.toml" ] || { echo "configuration backup missing" >&2; exit 1; }
[ -f "$backup_dir/data.sqlite" ] || { echo "database backup missing" >&2; exit 1; }
[ -x "$live_binary" ] || { echo "installed VaultLink binary is missing or not executable" >&2; exit 1; }
[ -f "$config_path" ] || { echo "live VaultLink configuration is missing" >&2; exit 1; }
[ -f "$data" ] || { echo "live VaultLink database is missing" >&2; exit 1; }

for required_command in systemctl sqlite3 install mv mktemp rm grep sed sleep date chown chmod curl runuser timeout flock; do
    command -v "$required_command" >/dev/null || {
        echo "$required_command is required for a safe rollback" >&2
        exit 1
    }
done

exec 9>"$maintenance_lock"
if ! flock -n 9; then
    echo "another VaultLink upgrade or rollback is already running" >&2
    exit 1
fi

validate_bounded_integer() {
    name=$1
    value=$2
    minimum=$3
    maximum=$4
    case "$value" in
        ''|*[!0-9]*|??????????*)
            echo "$name must be an integer between $minimum and $maximum" >&2
            return 1
            ;;
    esac
    if [ "$value" -lt "$minimum" ] || [ "$value" -gt "$maximum" ]; then
        echo "$name must be an integer between $minimum and $maximum" >&2
        return 1
    fi
}

validate_bounded_integer VAULTLINK_READINESS_ATTEMPTS "$readiness_attempts" 1 120
validate_bounded_integer VAULTLINK_READINESS_TIMEOUT_SECONDS "$readiness_timeout_seconds" 1 300
validate_bounded_integer VAULTLINK_READINESS_INTERVAL_SECONDS "$readiness_interval_seconds" 0 30
validate_bounded_integer VAULTLINK_READINESS_CONNECT_TIMEOUT_SECONDS "$readiness_connect_timeout_seconds" 1 30
validate_bounded_integer VAULTLINK_READINESS_MAX_TIME_SECONDS "$readiness_max_time_seconds" 1 60

read_bounded_version() {
    version_binary=$1
    version_label=$2
    if ! bounded_version=$(
        timeout --kill-after=2 5 runuser -u vaultlink -- "$version_binary" --version
    ); then
        echo "$version_label does not provide a bounded --version response" >&2
        return 1
    fi
    case "$bounded_version" in
        ''|*[!0-9A-Za-z.+-]*)
            echo "$version_label returned an invalid version" >&2
            return 1
            ;;
    esac
    if [ "${#bounded_version}" -gt 128 ]; then
        echo "$version_label returned an invalid version" >&2
        return 1
    fi
    printf '%s\n' "$bounded_version"
}

derive_readiness_target() {
    target_binary=$1
    target_config=$2
    target_label=$3
    if ! bounded_target=$(
        timeout --kill-after=2 5 runuser -u vaultlink -- \
            "$target_binary" readiness-target --config "$target_config"
    ); then
        echo "$target_label could not derive the local readiness target" >&2
        return 1
    fi
    if [ "$(printf '%s\n' "$bounded_target" | sed -n '$=')" -ne 3 ]; then
        echo "$target_label returned an invalid local readiness target" >&2
        return 1
    fi
    target_url=$(printf '%s\n' "$bounded_target" | sed -n '1p')
    target_connect_to=$(printf '%s\n' "$bounded_target" | sed -n '2p')
    target_insecure=$(printf '%s\n' "$bounded_target" | sed -n '3p')
    [ "$target_connect_to" != "-" ] || target_connect_to=
    case "$target_url" in
        http://*)
            if [ "$target_insecure" != 0 ] || [ -n "$target_connect_to" ]; then
                echo "$target_label returned inconsistent local HTTP readiness settings" >&2
                return 1
            fi
            ;;
        https://*)
            if [ "$target_insecure" != 1 ] || [ -z "$target_connect_to" ]; then
                echo "$target_label returned inconsistent local HTTPS readiness settings" >&2
                return 1
            fi
            ;;
        *)
            echo "$target_label returned an invalid local readiness URL" >&2
            return 1
            ;;
    esac
    printf '%s\n%s\n%s\n' "$target_url" "${target_connect_to:--}" "$target_insecure"
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

probe_readiness() {
    expected_body=$1
    set -- \
        --disable \
        --silent \
        --show-error \
        --noproxy '*' \
        --proto '=http,https' \
        --connect-timeout "$readiness_connect_timeout_seconds" \
        --max-time "$readiness_request_max_time" \
        --max-filesize 4096 \
        --header 'Accept: application/json' \
        --output - \
        --write-out 'VAULTLINK_HTTP_STATUS:%{http_code}'
    if [ -n "$readiness_connect_to" ]; then
        set -- "$@" --connect-to "$readiness_connect_to"
    fi
    if [ "$readiness_insecure" -eq 1 ]; then
        # This gate tests the local application, not public certificate trust.
        set -- "$@" --insecure
    fi
    set -- "$@" -- "$readiness_url"

    response=
    if ! response=$(
        timeout --kill-after=1 "$readiness_request_max_time" \
            runuser -u vaultlink -- curl "$@" 2>/dev/null
    ); then
        readiness_last_result="transport failure"
        return 1
    fi
    case "$response" in
        *VAULTLINK_HTTP_STATUS:[0-9][0-9][0-9]) ;;
        *)
            readiness_last_result="malformed curl result"
            return 1
            ;;
    esac
    http_status=${response##*VAULTLINK_HTTP_STATUS:}
    response_body=${response%VAULTLINK_HTTP_STATUS:*}
    if [ "$http_status" != 200 ]; then
        readiness_last_result="HTTP $http_status"
        return 1
    fi
    if [ "$response_body" != "$expected_body" ]; then
        readiness_last_result="HTTP 200 with unexpected health JSON"
        return 1
    fi
    readiness_last_result="HTTP 200"
    return 0
}

wait_until_ready() {
    expected_body=$1
    label=$2
    attempts=0
    readiness_now=$(date +%s)
    readiness_deadline=$((readiness_now + readiness_timeout_seconds))
    readiness_last_result="no response"
    while [ "$attempts" -lt "$readiness_attempts" ]; do
        readiness_now=$(date +%s)
        readiness_remaining=$((readiness_deadline - readiness_now))
        if [ "$readiness_remaining" -le 0 ]; then
            break
        fi
        readiness_request_max_time=$readiness_max_time_seconds
        if [ "$readiness_request_max_time" -gt "$readiness_remaining" ]; then
            readiness_request_max_time=$readiness_remaining
        fi
        if probe_readiness "$expected_body"; then
            return 0
        fi
        attempts=$((attempts + 1))
        if [ "$attempts" -lt "$readiness_attempts" ]; then
            readiness_now=$(date +%s)
            readiness_remaining=$((readiness_deadline - readiness_now))
            if [ "$readiness_remaining" -le 0 ]; then
                break
            fi
            readiness_sleep_seconds=$readiness_interval_seconds
            if [ "$readiness_sleep_seconds" -gt "$readiness_remaining" ]; then
                readiness_sleep_seconds=$readiness_remaining
            fi
            sleep "$readiness_sleep_seconds"
        fi
    done
    echo "$label failed after $attempts attempts ($readiness_last_result)" >&2
    return 1
}

stamp=$(date -u +%Y%m%dT%H%M%SZ)
emergency_dir="$backup_root/rollback-pre-$stamp"
emergency_stage="$backup_root/.rollback-pre-$stamp.incomplete.$$"
[ ! -e "$emergency_dir" ] || { echo "pre-rollback backup already exists: $emergency_dir" >&2; exit 1; }

was_active=0
stop_attempted=0
emergency_valid=0
replacement_started=0
current_readiness_url=
current_readiness_connect_to=
current_readiness_insecure=0
current_health_body=
readiness_url=
readiness_connect_to=
readiness_insecure=0

if systemctl --quiet is-active "$service"; then
    was_active=1
fi

restore_pre_rollback_state() {
    restore_failed=0
    rm -f "$restore_binary" "$restore_config"
    if [ -n "$restore_data" ]; then
        rm -f "$restore_data"
    fi
    restore_data=$(mktemp "$data_dir/.data.sqlite.rollback.restore.XXXXXX") || return 1

    install -o root -g root -m 0755 "$emergency_dir/vaultlink" "$restore_binary" \
        || restore_failed=1
    install -o root -g vaultlink -m 0640 "$emergency_dir/config.toml" "$restore_config" \
        || restore_failed=1
    install -o vaultlink -g vaultlink -m 0600 "$emergency_dir/data.sqlite" "$restore_data" \
        || restore_failed=1
    if [ "$restore_failed" -eq 0 ]; then
        sqlite3 "$restore_data" "PRAGMA integrity_check" | grep -qx ok \
            || restore_failed=1
    fi
    if [ "$restore_failed" -ne 0 ]; then
        rm -f "$restore_binary" "$restore_config" "$restore_data"
        restore_data=
        return 1
    fi

    mv -f "$restore_binary" "$live_binary" || restore_failed=1
    mv -f "$restore_config" "$config_path" || restore_failed=1
    rm -f "$data-wal" "$data-shm" || restore_failed=1
    mv -f "$restore_data" "$data" || restore_failed=1
    rm -f "$restore_binary" "$restore_config" "$restore_data"
    restore_data=
    [ "$restore_failed" -eq 0 ]
}

on_failure() {
    status=$1
    trap - 0
    trap '' 1 2 15
    set +e
    restart_allowed=1

    rm -f "$staged_binary" "$staged_config" "$restore_binary" "$restore_config"
    if [ -n "$staged_data" ]; then
        rm -f "$staged_data"
        staged_data=
    fi
    if [ -n "$restore_data" ]; then
        rm -f "$restore_data"
        restore_data=
    fi

    if [ "$replacement_started" -eq 1 ]; then
        echo "rollback failed; restoring pre-rollback state $emergency_dir" >&2
        if ! systemctl stop "$service" >/dev/null 2>&1; then
            echo "CRITICAL: $service could not be stopped; recover manually from $emergency_dir" >&2
            restart_allowed=0
        elif [ "$emergency_valid" -ne 1 ] || ! restore_pre_rollback_state; then
            echo "CRITICAL: automatic recovery failed; recover manually from $emergency_dir" >&2
            restart_allowed=0
        fi
    elif [ "$stop_attempted" -eq 1 ]; then
        echo "rollback failed before replacement; keeping the current installation" >&2
    fi

    if [ "$stop_attempted" -eq 1 ] && [ "$was_active" -eq 1 ] && [ "$restart_allowed" -eq 1 ]; then
        readiness_url=$current_readiness_url
        readiness_connect_to=$current_readiness_connect_to
        readiness_insecure=$current_readiness_insecure
        if ! systemctl start "$service"; then
            echo "CRITICAL: $service could not be restarted" >&2
        elif ! wait_until_active; then
            echo "CRITICAL: restored $service did not become active" >&2
        elif ! wait_until_ready "$current_health_body" "restored service readiness"; then
            echo "CRITICAL: restored $service failed its local readiness check" >&2
        elif ! sqlite3 "$data" ".timeout 10000" "PRAGMA integrity_check" | grep -qx ok; then
            echo "CRITICAL: restored VaultLink database failed integrity verification" >&2
        fi
    fi

    if [ -d "$emergency_stage" ]; then
        rm -rf "$emergency_stage"
    fi

    exit "$status"
}

trap 'on_failure $?' 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

# Stage the complete requested rollback set on each destination filesystem.
install -d -o root -g root -m 0700 "$backup_root"
install -o root -g root -m 0755 "$backup_dir/vaultlink" "$staged_binary"
install -o root -g vaultlink -m 0640 "$backup_dir/config.toml" "$staged_config"
sqlite3 "$backup_dir/data.sqlite" "PRAGMA integrity_check" | grep -qx ok

# Validate both exact binary/configuration pairs before stopping the service.
requested_version=$(read_bounded_version "$staged_binary" "rollback binary")
requested_readiness_target=$(derive_readiness_target \
    "$staged_binary" "$staged_config" "rollback binary/configuration")
readiness_url=$(printf '%s\n' "$requested_readiness_target" | sed -n '1p')
readiness_connect_to=$(printf '%s\n' "$requested_readiness_target" | sed -n '2p')
[ "$readiness_connect_to" != "-" ] || readiness_connect_to=
readiness_insecure=$(printf '%s\n' "$requested_readiness_target" | sed -n '3p')
requested_health_body='{"ok":true,"version":"'"$requested_version"'"}'

current_version=$(read_bounded_version "$live_binary" "installed binary")
current_readiness_target=$(derive_readiness_target \
    "$live_binary" "$config_path" "installed binary/configuration")
current_readiness_url=$(printf '%s\n' "$current_readiness_target" | sed -n '1p')
current_readiness_connect_to=$(printf '%s\n' "$current_readiness_target" | sed -n '2p')
[ "$current_readiness_connect_to" != "-" ] || current_readiness_connect_to=
current_readiness_insecure=$(printf '%s\n' "$current_readiness_target" | sed -n '3p')
current_health_body='{"ok":true,"version":"'"$current_version"'"}'

stop_attempted=1
systemctl stop "$service"

# Preserve the exact stopped triple so a failed rollback can itself be rolled back.
install -d -o root -g root -m 0700 "$emergency_stage"
install -o root -g root -m 0700 "$live_binary" "$emergency_stage/vaultlink"
install -o root -g root -m 0600 "$config_path" "$emergency_stage/config.toml"
sqlite3 "$data" ".timeout 10000" ".backup '$emergency_stage/data.sqlite'"
chown root:root "$emergency_stage/data.sqlite"
chmod 0600 "$emergency_stage/data.sqlite"
sqlite3 "$emergency_stage/data.sqlite" "PRAGMA integrity_check" | grep -qx ok
mv "$emergency_stage" "$emergency_dir"
emergency_valid=1

staged_data=$(mktemp "$data_dir/.data.sqlite.rollback.new.XXXXXX")
install -o vaultlink -g vaultlink -m 0600 "$backup_dir/data.sqlite" "$staged_data"
sqlite3 "$staged_data" "PRAGMA integrity_check" | grep -qx ok

# Each rename is atomic on its destination filesystem. Handled failures restore
# the complete emergency triple before any restart is attempted.
replacement_started=1
mv -f "$staged_binary" "$live_binary"
mv -f "$staged_config" "$config_path"
rm -f "$data-wal" "$data-shm"
mv -f "$staged_data" "$data"

systemctl start "$service"
wait_until_active
wait_until_ready "$requested_health_body" "rollback readiness"
sqlite3 "$data" ".timeout 10000" "PRAGMA integrity_check" | grep -qx ok

trap - 0 1 2 15
echo "rollback completed; pre-rollback backup: $emergency_dir"
