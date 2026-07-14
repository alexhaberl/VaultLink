#!/bin/sh
set -eu
umask 077

service=vaultlink.service
install_dir=/opt/vaultlink
live_binary="$install_dir/vaultlink"
staged_binary="$install_dir/.vaultlink.new"
restore_binary="$install_dir/.vaultlink.restore"
data=/var/lib/vaultlink/data.sqlite
data_dir=/var/lib/vaultlink
backup_root=/var/lib/vaultlink-backups
staged_data=
config_path=/etc/vaultlink/config.toml
staged_config=/etc/vaultlink/.config.toml.new
restore_config=/etc/vaultlink/.config.toml.restore
maintenance_lock=/run/lock/vaultlink-maintenance.lock
readiness_attempts=${VAULTLINK_READINESS_ATTEMPTS:-30}
readiness_timeout_seconds=${VAULTLINK_READINESS_TIMEOUT_SECONDS:-60}
readiness_interval_seconds=${VAULTLINK_READINESS_INTERVAL_SECONDS:-1}
readiness_connect_timeout_seconds=${VAULTLINK_READINESS_CONNECT_TIMEOUT_SECONDS:-2}
readiness_max_time_seconds=${VAULTLINK_READINESS_MAX_TIME_SECONDS:-3}

if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 2 ]; then
    echo "usage (as root): vaultlink-upgrade.sh NEW_BINARY NEW_CONFIG" >&2
    exit 64
fi

new_binary=$1
new_config=$2
[ -x "$new_binary" ] || { echo "new binary is missing or not executable" >&2; exit 1; }
[ -f "$new_config" ] || { echo "new configuration is missing" >&2; exit 1; }
[ -x "$live_binary" ] || { echo "installed VaultLink binary is missing or not executable" >&2; exit 1; }
[ -f "$data" ] || { echo "VaultLink database is missing" >&2; exit 1; }
[ -f "$config_path" ] || { echo "VaultLink configuration is missing: $config_path" >&2; exit 1; }

for required_command in systemctl sqlite3 install mv mktemp rm grep sed sleep date chown chmod curl runuser timeout flock od tr; do
    command -v "$required_command" >/dev/null || {
        echo "$required_command is required for a safe upgrade" >&2
        exit 1
    }
done
[ -r /dev/urandom ] || {
    echo "/dev/urandom is required for safe share-alias migration" >&2
    exit 1
}

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

stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup_dir="$backup_root/$stamp"
backup_stage="$backup_root/.$stamp.incomplete.$$"
[ ! -e "$backup_dir" ] || { echo "backup already exists: $backup_dir" >&2; exit 1; }

was_active=0
stop_attempted=0
backup_valid=0
candidate_activated=0
alias_rows=
alias_sql=
alias_mapping_temp=
alias_mapping_path=
alias_mapping_created=0
old_readiness_url=
old_readiness_connect_to=
old_readiness_insecure=0
old_health_body=
readiness_url=
readiness_connect_to=
readiness_insecure=0

if systemctl --quiet is-active "$service"; then
    was_active=1
fi

restore_verified_backup() {
    restore_failed=0
    rm -f "$restore_binary" "$restore_config"
    if [ -n "$staged_data" ]; then
        rm -f "$staged_data"
    fi
    staged_data=$(mktemp "$data_dir/.data.sqlite.restore.XXXXXX") || return 1

    install -o root -g root -m 0755 "$backup_dir/vaultlink" "$restore_binary" \
        || restore_failed=1
    install -o root -g vaultlink -m 0640 "$backup_dir/config.toml" "$restore_config" \
        || restore_failed=1
    install -o vaultlink -g vaultlink -m 0600 "$backup_dir/data.sqlite" "$staged_data" \
        || restore_failed=1
    if [ "$restore_failed" -eq 0 ]; then
        sqlite3 "$staged_data" "PRAGMA integrity_check" | grep -qx ok \
            || restore_failed=1
    fi
    if [ "$restore_failed" -ne 0 ]; then
        rm -f "$restore_binary" "$restore_config" "$staged_data"
        staged_data=
        return 1
    fi

    mv -f "$restore_binary" "$live_binary" || restore_failed=1
    mv -f "$restore_config" "$config_path" || restore_failed=1
    rm -f "$data-wal" "$data-shm" || restore_failed=1
    mv -f "$staged_data" "$data" || restore_failed=1
    rm -f "$restore_binary" "$restore_config" "$staged_data"
    staged_data=
    [ "$restore_failed" -eq 0 ]
}

migrate_short_share_aliases() {
    shares_table_exists=$(sqlite3 "$data" \
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='shares'")
    [ "$shares_table_exists" = 1 ] || return 0

    alias_rows="$backup_dir/.share-alias-migration.rows.$$"
    alias_sql="$backup_dir/.share-alias-migration.sql.$$"
    alias_mapping_temp="$backup_dir/.share-alias-migration.tsv.$$"
    alias_mapping_path="$backup_dir/share-alias-migration.tsv"
    tab=$(printf '\t')

    sqlite3 -batch -noheader -separator "$tab" "$data" \
        "SELECT id, alias FROM shares
         WHERE alias IS NOT NULL AND alias <> ''
           AND length(CAST(alias AS BLOB)) < 12
         ORDER BY id" >"$alias_rows"
    chown root:root "$alias_rows"
    chmod 0600 "$alias_rows"

    if [ ! -s "$alias_rows" ]; then
        rm -f "$alias_rows"
        alias_rows=
        return 0
    fi

    : >"$alias_sql"
    : >"$alias_mapping_temp"
    chown root:root "$alias_sql" "$alias_mapping_temp"
    chmod 0600 "$alias_sql" "$alias_mapping_temp"
    printf '%s\n' '.timeout 10000' '.bail on' 'BEGIN IMMEDIATE;' \
        'CREATE TEMP TABLE alias_migration_guard(changed INTEGER NOT NULL CHECK(changed = 1));' \
        >"$alias_sql"
    printf 'share_id\told_alias\tnew_alias\n' >"$alias_mapping_temp"

    while IFS="$tab" read -r alias_id old_alias; do
        case "$alias_id" in
            ''|*[!0-9]*)
                echo "share alias migration found an invalid database row id" >&2
                return 1
                ;;
        esac
        case "$old_alias" in
            ''|*[!A-Za-z0-9_-]*)
                echo "share alias migration found an invalid legacy alias" >&2
                return 1
                ;;
        esac
        if [ "${#old_alias}" -ge 12 ]; then
            echo "share alias migration found an inconsistent legacy alias" >&2
            return 1
        fi

        # Twenty hexadecimal characters add 80 bits from the kernel CSPRNG.
        # Keeping the old prefix makes the protected operator mapping auditable
        # while bringing every migrated value safely inside the 12..32 policy.
        suffix=$(LC_ALL=C od -An -N10 -tx1 /dev/urandom | tr -d ' \n')
        case "$suffix" in
            *[!0-9a-f]*)
                echo "secure share alias generation failed" >&2
                return 1
                ;;
        esac
        if [ "${#suffix}" -ne 20 ]; then
            echo "secure share alias generation failed" >&2
            return 1
        fi
        new_alias=$old_alias$suffix
        if [ "${#new_alias}" -lt 12 ] || [ "${#new_alias}" -gt 32 ]; then
            echo "generated share alias is outside the supported length" >&2
            return 1
        fi

        # Both aliases have been restricted to the URL-safe ASCII alphabet, so
        # embedding them as SQL literals cannot introduce quoting or SQL syntax.
        printf "UPDATE shares SET alias = '%s' WHERE id = %s AND alias = '%s';\n" \
            "$new_alias" "$alias_id" "$old_alias" >>"$alias_sql"
        printf '%s\n' 'INSERT INTO alias_migration_guard VALUES(changes());' \
            'DELETE FROM alias_migration_guard;' >>"$alias_sql"
        printf '%s\t%s\t%s\n' "$alias_id" "$old_alias" "$new_alias" \
            >>"$alias_mapping_temp"
    done <"$alias_rows"
    printf '%s\n' 'COMMIT;' >>"$alias_sql"

    if ! sqlite3 -batch "$data" <"$alias_sql"; then
        echo "share alias migration failed; refusing to activate the candidate" >&2
        return 1
    fi
    remaining_short_aliases=$(sqlite3 "$data" \
        "SELECT count(*) FROM shares
         WHERE alias IS NOT NULL AND alias <> ''
           AND length(CAST(alias AS BLOB)) < 12")
    if [ "$remaining_short_aliases" != 0 ]; then
        echo "share alias migration left legacy aliases behind" >&2
        return 1
    fi

    rm -f "$alias_rows" "$alias_sql"
    alias_rows=
    alias_sql=
    mv -f "$alias_mapping_temp" "$alias_mapping_path"
    alias_mapping_created=1
    alias_mapping_temp=
}

on_failure() {
    status=$1
    trap - 0
    trap '' 1 2 15
    set +e
    restart_allowed=1
    restore_completed=0

    rm -f "$staged_binary" "$staged_config" "$restore_binary" "$restore_config"
    if [ -n "$staged_data" ]; then
        rm -f "$staged_data"
        staged_data=
    fi
    if [ -n "$alias_rows" ]; then
        rm -f "$alias_rows"
    fi
    if [ -n "$alias_sql" ]; then
        rm -f "$alias_sql"
    fi
    if [ -n "$alias_mapping_temp" ]; then
        rm -f "$alias_mapping_temp"
    fi

    if [ "$candidate_activated" -eq 1 ]; then
        echo "upgrade failed; restoring verified backup $backup_dir" >&2
        if ! systemctl stop "$service" >/dev/null 2>&1; then
            echo "CRITICAL: $service could not be stopped; recover manually from $backup_dir" >&2
            restart_allowed=0
        elif [ "$backup_valid" -ne 1 ]; then
            echo "CRITICAL: automatic restore failed; recover manually from $backup_dir" >&2
            restart_allowed=0
        elif restore_verified_backup; then
            restore_completed=1
        else
            echo "CRITICAL: automatic restore failed; recover manually from $backup_dir" >&2
            restart_allowed=0
        fi
    elif [ "$stop_attempted" -eq 1 ]; then
        echo "upgrade failed before activation; keeping the installed binary, configuration, and database" >&2
    fi

    # A completed database restore makes a published migration map stale. Keep
    # it only when automatic restore failed and an operator may need it to
    # inspect or manually recover the possibly migrated live database.
    if [ "$restore_completed" -eq 1 ] && [ "$alias_mapping_created" -eq 1 ]; then
        rm -f "$alias_mapping_path"
    fi

    if [ "$stop_attempted" -eq 1 ] && [ "$was_active" -eq 1 ] && [ "$restart_allowed" -eq 1 ]; then
        readiness_url=$old_readiness_url
        readiness_connect_to=$old_readiness_connect_to
        readiness_insecure=$old_readiness_insecure
        if ! systemctl start "$service"; then
            echo "CRITICAL: $service could not be restarted" >&2
        elif ! wait_until_active; then
            echo "CRITICAL: restored $service did not become active" >&2
        elif ! wait_until_ready "$old_health_body" "restored service readiness"; then
            echo "CRITICAL: restored $service failed its local readiness check" >&2
        elif ! sqlite3 "$data" ".timeout 10000" "PRAGMA integrity_check" | grep -qx ok; then
            echo "CRITICAL: restored VaultLink database failed integrity verification" >&2
        fi
    fi

    if [ -n "$backup_stage" ] && [ -d "$backup_stage" ]; then
        rm -rf "$backup_stage"
    fi

    exit "$status"
}

trap 'on_failure $?' 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

# Stage immutable copies on their destination filesystems while the live service
# and its configuration remain untouched.
install -d -o root -g root -m 0700 "$backup_root"
install -d -o root -g root -m 0700 "$backup_stage"
install -o root -g root -m 0700 "$live_binary" "$backup_stage/vaultlink"
install -o root -g root -m 0600 "$config_path" "$backup_stage/config.toml"
install -o root -g root -m 0755 "$new_binary" "$staged_binary"
install -o root -g vaultlink -m 0640 "$new_config" "$staged_config"

# Validate both exact binary/configuration pairs as the service account before
# entering downtime.
old_version=$(read_bounded_version "$live_binary" "installed binary")
old_readiness_target=$(derive_readiness_target \
    "$live_binary" "$config_path" "installed binary/configuration")
old_readiness_url=$(printf '%s\n' "$old_readiness_target" | sed -n '1p')
old_readiness_connect_to=$(printf '%s\n' "$old_readiness_target" | sed -n '2p')
[ "$old_readiness_connect_to" != "-" ] || old_readiness_connect_to=
old_readiness_insecure=$(printf '%s\n' "$old_readiness_target" | sed -n '3p')
old_health_body='{"ok":true,"version":"'"$old_version"'"}'

candidate_version=$(read_bounded_version "$staged_binary" "candidate")
candidate_readiness_target=$(derive_readiness_target \
    "$staged_binary" "$staged_config" "candidate binary/configuration")
readiness_url=$(printf '%s\n' "$candidate_readiness_target" | sed -n '1p')
readiness_connect_to=$(printf '%s\n' "$candidate_readiness_target" | sed -n '2p')
[ "$readiness_connect_to" != "-" ] || readiness_connect_to=
readiness_insecure=$(printf '%s\n' "$candidate_readiness_target" | sed -n '3p')
candidate_health_body='{"ok":true,"version":"'"$candidate_version"'"}'

if [ "$old_version" = 0.4.0 ] && [ "$candidate_version" != 0.4.0 ] \
    && [ "$was_active" -eq 1 ]; then
    echo "an upgrade from 0.4.0 requires vaultlink.service to be stopped before the storage migration" >&2
    exit 1
fi

stop_attempted=1
systemctl stop "$service"

sqlite3 "$data" ".timeout 10000" ".backup '$backup_stage/data.sqlite'"
chown root:root "$backup_stage/data.sqlite"
chmod 0600 "$backup_stage/data.sqlite"
sqlite3 "$backup_stage/data.sqlite" "PRAGMA integrity_check" | grep -qx ok
mv "$backup_stage" "$backup_dir"
backup_stage=
backup_valid=1

# Each rename is atomic on its destination filesystem. The handled-failure trap
# restores the complete verified triple if any later step fails.
candidate_activated=1
migrate_short_share_aliases
mv -f "$staged_binary" "$live_binary"
mv -f "$staged_config" "$config_path"

systemctl start "$service"
wait_until_active
wait_until_ready "$candidate_health_body" "candidate readiness"
sqlite3 "$data" ".timeout 10000" "PRAGMA integrity_check" | grep -qx ok

trap - 0 1 2 15
echo "$backup_dir"
