#!/bin/sh
set -eu

service=vaultlink.service
install_dir=/opt/vaultlink
live_binary="$install_dir/vaultlink"
staged_binary="$install_dir/.vaultlink.new"
data=/var/lib/vaultlink/data.sqlite
backup_root=/var/lib/vaultlink/backups
config_path=/etc/vaultlink/config.toml
readiness_attempts=${VAULTLINK_READINESS_ATTEMPTS:-30}
readiness_timeout_seconds=${VAULTLINK_READINESS_TIMEOUT_SECONDS:-60}
readiness_interval_seconds=${VAULTLINK_READINESS_INTERVAL_SECONDS:-1}
readiness_connect_timeout_seconds=${VAULTLINK_READINESS_CONNECT_TIMEOUT_SECONDS:-2}
readiness_max_time_seconds=${VAULTLINK_READINESS_MAX_TIME_SECONDS:-3}

if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 1 ]; then
    echo "usage (as root): vaultlink-upgrade.sh NEW_BINARY" >&2
    exit 64
fi

new_binary=$1
[ -x "$new_binary" ] || { echo "new binary is missing or not executable" >&2; exit 1; }
[ -x "$live_binary" ] || { echo "installed VaultLink binary is missing or not executable" >&2; exit 1; }
[ -f "$data" ] || { echo "VaultLink database is missing" >&2; exit 1; }
[ -f "$config_path" ] || { echo "VaultLink configuration is missing: $config_path" >&2; exit 1; }

for required_command in systemctl sqlite3 install mv rm grep sed sleep date chown chmod curl runuser timeout; do
    command -v "$required_command" >/dev/null || {
        echo "$required_command is required for a safe upgrade" >&2
        exit 1
    }
done

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
    trap - 0
    trap '' 1 2 15
    set +e
    restart_allowed=1

    rm -f "$staged_binary"

    if [ "$candidate_activated" -eq 1 ]; then
        echo "upgrade failed; restoring verified backup $backup_dir" >&2
        if ! systemctl stop "$service" >/dev/null 2>&1; then
            echo "CRITICAL: $service could not be stopped; recover manually from $backup_dir" >&2
            restart_allowed=0
        elif [ "$backup_valid" -ne 1 ] || ! restore_verified_backup; then
            echo "CRITICAL: automatic restore failed; recover manually from $backup_dir" >&2
            restart_allowed=0
        fi
    elif [ "$stop_attempted" -eq 1 ]; then
        echo "upgrade failed before activation; keeping the installed binary and database" >&2
    fi

    if [ "$stop_attempted" -eq 1 ] && [ "$was_active" -eq 1 ] && [ "$restart_allowed" -eq 1 ]; then
        if ! systemctl start "$service"; then
            echo "CRITICAL: $service could not be restarted" >&2
        elif ! wait_until_active; then
            echo "CRITICAL: restored $service did not become active" >&2
        elif ! wait_until_ready "" "restored service readiness"; then
            echo "CRITICAL: restored $service failed its local readiness check" >&2
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

health_response_is_valid() {
    response_body=$1
    response_version=$(
        printf '%s\n' "$response_body" \
            | sed -n 's/^{"ok":true,"version":"\([0-9A-Za-z.+-][0-9A-Za-z.+-]*\)"}$/\1/p'
    )
    [ -n "$response_version" ] \
        && [ "$response_body" = '{"ok":true,"version":"'"$response_version"'"}' ]
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
    if [ -n "$expected_body" ]; then
        if [ "$response_body" != "$expected_body" ]; then
            readiness_last_result="HTTP 200 with unexpected health JSON"
            return 1
        fi
    elif ! health_response_is_valid "$response_body"; then
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

trap 'on_failure $?' 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

# Stage all files that can be prepared safely before downtime.
install -d -o root -g vaultlink -m 0750 "$backup_root"
install -d -o root -g vaultlink -m 0750 "$backup_stage"
install -o root -g root -m 0755 "$live_binary" "$backup_stage/vaultlink"
install -o root -g root -m 0755 "$new_binary" "$staged_binary"

# Inspect the immutable, root-owned staged copy with the same account as the service.
if ! candidate_version=$(
    timeout --kill-after=2 5 runuser -u vaultlink -- "$staged_binary" --version
); then
    echo "candidate does not provide a bounded --version response" >&2
    exit 1
fi
case "$candidate_version" in
    ''|*[!0-9A-Za-z.+-]*)
        echo "candidate returned an invalid version" >&2
        exit 1
        ;;
esac

if ! readiness_target=$(
    timeout --kill-after=2 5 runuser -u vaultlink -- \
        "$staged_binary" readiness-target --config "$config_path"
); then
    echo "candidate could not derive the local readiness target" >&2
    exit 1
fi
if [ "$(printf '%s\n' "$readiness_target" | sed -n '$=')" -ne 3 ]; then
    echo "candidate returned an invalid local readiness target" >&2
    exit 1
fi
readiness_url=$(printf '%s\n' "$readiness_target" | sed -n '1p')
readiness_connect_to=$(printf '%s\n' "$readiness_target" | sed -n '2p')
readiness_insecure=$(printf '%s\n' "$readiness_target" | sed -n '3p')
[ "$readiness_connect_to" != "-" ] || readiness_connect_to=
case "$readiness_url" in
    http://*)
        if [ "$readiness_insecure" != 0 ] || [ -n "$readiness_connect_to" ]; then
            echo "candidate returned inconsistent local HTTP readiness settings" >&2
            exit 1
        fi
        ;;
    https://*)
        if [ "$readiness_insecure" != 1 ] || [ -z "$readiness_connect_to" ]; then
            echo "candidate returned inconsistent local HTTPS readiness settings" >&2
            exit 1
        fi
        ;;
    *)
        echo "candidate returned an invalid local readiness URL" >&2
        exit 1
        ;;
esac
candidate_health_body='{"ok":true,"version":"'"$candidate_version"'"}'

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
wait_until_ready "$candidate_health_body" "candidate readiness"
sqlite3 "$data" ".timeout 10000" "PRAGMA integrity_check" | grep -qx ok

trap - 0 1 2 15
echo "$backup_dir"
