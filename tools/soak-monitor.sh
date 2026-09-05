#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG

: "${SOAK_COMMIT_SHA:?set SOAK_COMMIT_SHA}"
: "${SOAK_BINARY_SHA256:?set SOAK_BINARY_SHA256}"
: "${SOAK_ORCHESTRATION_SHA256:?set SOAK_ORCHESTRATION_SHA256}"
: "${SOAK_EVIDENCE_DIR:?set SOAK_EVIDENCE_DIR}"
: "${SOAK_NAMESPACE:?set SOAK_NAMESPACE}"
: "${SOAK_START_EPOCH:?set SOAK_START_EPOCH}"
: "${SOAK_DEADLINE_EPOCH:?set SOAK_DEADLINE_EPOCH}"
: "${SOAK_ARCHITECTURE:?set SOAK_ARCHITECTURE}"
: "${SOAK_OS_ID:?set SOAK_OS_ID}"
: "${SOAK_OS_VERSION_ID:?set SOAK_OS_VERSION_ID}"
case "$SOAK_COMMIT_SHA" in
    *[!0-9a-f]*|'') echo "SOAK_COMMIT_SHA must be lowercase hexadecimal" >&2; exit 64 ;;
esac
[ "${#SOAK_COMMIT_SHA}" -eq 40 ] || { echo "SOAK_COMMIT_SHA must contain 40 characters" >&2; exit 64; }
case "$SOAK_BINARY_SHA256" in
    *[!0-9a-f]*|'') echo "SOAK_BINARY_SHA256 must be lowercase hexadecimal" >&2; exit 64 ;;
esac
[ "${#SOAK_BINARY_SHA256}" -eq 64 ] || { echo "SOAK_BINARY_SHA256 must contain 64 characters" >&2; exit 64; }
case "$SOAK_ORCHESTRATION_SHA256" in
    *[!0-9a-f]*|'') echo "SOAK_ORCHESTRATION_SHA256 must be lowercase hexadecimal" >&2; exit 64 ;;
esac
[ "${#SOAK_ORCHESTRATION_SHA256}" -eq 64 ] \
    || { echo "SOAK_ORCHESTRATION_SHA256 must contain 64 characters" >&2; exit 64; }
case "$SOAK_NAMESPACE" in *[!A-Za-z0-9._-]*|'') echo "SOAK_NAMESPACE contains unsafe characters" >&2; exit 64 ;; esac
namespace_tail=${SOAK_NAMESPACE#"$SOAK_COMMIT_SHA-"}
namespace_epoch=${namespace_tail%%-*}
namespace_random=${namespace_tail#*-}
case "$namespace_epoch" in *[!0-9]*|'') echo "SOAK_NAMESPACE epoch is invalid" >&2; exit 64 ;; esac
case "$namespace_random" in *[!0-9a-f]*|'') echo "SOAK_NAMESPACE random suffix is invalid" >&2; exit 64 ;; esac
if [ "${#namespace_random}" -ne 16 ] \
    || [ "$SOAK_NAMESPACE" != "$SOAK_COMMIT_SHA-$namespace_epoch-$namespace_random" ]; then
    echo "SOAK_NAMESPACE is not bound to the candidate commit" >&2
    exit 64
fi

duration=${SOAK_SECONDS:-259200}
interval=${SOAK_INTERVAL_SECONDS:-300}
load_interval=${SOAK_LOAD_INTERVAL_SECONDS:-21600}
database=${VAULTLINK_DATABASE:-/var/lib/vaultlink/data.sqlite}
config=${VAULTLINK_CONFIG:-/etc/vaultlink/config.toml}
health_url=${VAULTLINK_HEALTH_URL:-http://127.0.0.1:8080/api/v2/health/ready}
expected_version=${SOAK_EXPECTED_VERSION:-0.7.0}
load_script=${SOAK_LOAD_SCRIPT:-/usr/local/libexec/vaultlink/load-test.sh}
metrics="$SOAK_EVIDENCE_DIR/metrics.csv"
load_log="$SOAK_EVIDENCE_DIR/load.log"
journal_log="$SOAK_EVIDENCE_DIR/vaultlink-journal.log"
result="$SOAK_EVIDENCE_DIR/result.env"
load_failure="$SOAK_EVIDENCE_DIR/load.failed"

case "$duration:$interval:$load_interval" in
    *[!0-9:]*|:*|*::*) echo "soak durations must be decimal seconds" >&2; exit 64 ;;
esac
if [ "$duration" -le 0 ] || [ "$interval" -le 0 ] || [ "$load_interval" -le 0 ]; then
    echo "soak durations must be positive" >&2
    exit 64
fi
case "$SOAK_START_EPOCH:$SOAK_DEADLINE_EPOCH" in
    *[!0-9:]*|:*|*::*) echo "soak start and deadline must be decimal epochs" >&2; exit 64 ;;
esac
[ $((SOAK_DEADLINE_EPOCH - SOAK_START_EPOCH)) -eq "$duration" ] \
    || { echo "persisted soak deadline does not match its duration" >&2; exit 64; }
if [ "$SOAK_ARCHITECTURE" != amd64 ] || [ "$(uname -m)" != x86_64 ]; then
    echo "soak requires native amd64/x86_64" >&2
    exit 64
fi
if [ "$SOAK_OS_ID" != debian ] || [ "$SOAK_OS_VERSION_ID" != 13 ]; then
    echo "soak unit platform must be Debian 13" >&2
    exit 64
fi
actual_os_id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
actual_os_version_id=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')
if [ "$actual_os_id" != "$SOAK_OS_ID" ] || [ "$actual_os_version_id" != "$SOAK_OS_VERSION_ID" ]; then
    echo "soak host platform changed or is not Debian 13" >&2
    exit 64
fi

for command in nproc awk curl journalctl sha256sum sort sqlite3 systemctl; do
    command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 69; }
done
[ -x "$load_script" ] || { echo "soak load script is not executable" >&2; exit 69; }

install -d -m 2750 "$SOAK_EVIDENCE_DIR"
rm -f "$result" "$load_failure"
start_epoch=$SOAK_START_EPOCH
deadline=$SOAK_DEADLINE_EPOCH
result_state=failure
result_reason=monitor_failed
load_pid=
config_sha256=unavailable
expected_health_sha256=unavailable

finish() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$load_pid" ]; then
        kill "$load_pid" 2>/dev/null || true
        wait "$load_pid" 2>/dev/null || true
    fi
    end_epoch=$(date +%s)
    actual_duration=$((end_epoch - start_epoch))
    journalctl --quiet --unit=vaultlink.service --since="@$start_epoch" \
        --no-pager >"$journal_log" 2>&1 || true
    if [ "$status" -eq 0 ]; then
        result_state=success
        result_reason=passed
    fi
    tmp="$result.tmp.$$"
    printf '%s\n' \
        "state=$result_state" \
        "reason=$result_reason" \
        "commit_sha=$SOAK_COMMIT_SHA" \
        "namespace=$SOAK_NAMESPACE" \
        "binary_sha256=$SOAK_BINARY_SHA256" \
        "orchestration_sha256=$SOAK_ORCHESTRATION_SHA256" \
        "config_sha256=$config_sha256" \
        "health_sha256=$expected_health_sha256" \
        "architecture=$SOAK_ARCHITECTURE" \
        "os_id=$SOAK_OS_ID" \
        "os_version_id=$SOAK_OS_VERSION_ID" \
        "expected_version=$expected_version" \
        "start_epoch=$start_epoch" \
        "end_epoch=$end_epoch" \
        "duration_seconds=$actual_duration" \
        "load_interval_seconds=$load_interval" \
        >"$tmp"
    chmod 0640 "$tmp"
    mv -f "$tmp" "$result"
    exit "$status"
}
trap finish EXIT
trap 'result_reason=interrupted; exit 70' HUP INT TERM

fail() {
    result_reason=$1
    echo "soak gate failed: $1" >&2
    exit 1
}

pid=$(systemctl show -p MainPID --value vaultlink.service)
[ "$pid" -gt 0 ] || fail service_has_no_pid
initial_pid=$pid
restart_start=$(systemctl show -p NRestarts --value vaultlink.service)
actual_binary_sha256=$(sha256sum "/proc/$pid/exe" | awk '{print $1}')
[ "$actual_binary_sha256" = "$SOAK_BINARY_SHA256" ] || fail binary_hash_mismatch
config_sha256=$(sha256sum "$config" | awk '{print $1}')
expected_health_json="{\"ok\":true,\"version\":\"$expected_version\"}"
expected_health_sha256=$(printf '%s' "$expected_health_json" | sha256sum | awk '{print $1}')

printf 'epoch,timestamp,pid,rss_kib,restarts,health_sha256,config_sha256,integrity\n' >"$metrics"
printf 'commit=%s\nnamespace=%s\nbinary_sha256=%s\norchestration_sha256=%s\narchitecture=%s\nos_id=%s\nos_version_id=%s\nconfig_sha256=%s\nexpected_version=%s\nhealth_sha256=%s\n' \
    "$SOAK_COMMIT_SHA" "$SOAK_NAMESPACE" "$SOAK_BINARY_SHA256" \
    "$SOAK_ORCHESTRATION_SHA256" "$SOAK_ARCHITECTURE" "$SOAK_OS_ID" \
    "$SOAK_OS_VERSION_ID" "$config_sha256" \
    "$expected_version" "$expected_health_sha256" \
    >"$SOAK_EVIDENCE_DIR/candidate.env"

run_load_loop() {
    run=0
    while [ "$(date +%s)" -lt "$deadline" ]; do
        # Recheck at each six-hour run; collector/tag revalidate both snapshots.
        if ! [ "$(nproc)" -ge 8 ] \
            || ! [ "$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)" -ge 15728640 ]; then
            printf '%s\n' 'full load requires 8 vCPUs and at least 15 GiB MemTotal' >"$load_failure"
            return 1
        fi
        run=$((run + 1))
        run_dir="$SOAK_EVIDENCE_DIR/load-$run"
        mkdir -p "$run_dir"
        if ! LOAD_RUN_ID="$(printf '%03d' "$run")" \
            LOAD_TEST_EVIDENCE_DIR="$run_dir" \
            LOAD_PROFILE=full \
            DOWNLOAD_RANGE_BYTES=67108864 \
            DOWNLOAD_FIXTURE_BYTES=53687091200 \
            LOAD_P95_POLICY=strict \
            LOAD_CONNECT_TIMEOUT_SECONDS=5 \
            LOAD_METADATA_MAX_TIME_SECONDS=30 \
            LOAD_TRANSFER_MAX_TIME_SECONDS=300 \
            LOAD_ADMISSION_READY_TIMEOUT_SECONDS=10 \
            LOAD_ADMISSION_HOLDER_MAX_TIME_SECONDS=30 \
            LOAD_ADMISSION_PROBE_MAX_TIME_SECONDS=5 \
            LOAD_PROFILE_READY_TIMEOUT_SECONDS=10 \
            VAULTLINK_PROCESS_PID='' \
            VAULTLINK_PROCESS_UID='' \
            VAULTLINK_PROCESS_GID='' \
            VAULTLINK_EXPECTED_BINARY_PATH='' \
            VAULTLINK_EXPECTED_BINARY_SHA256='' \
            VAULTLINK_CONFIG="$config" \
            "$load_script" >>"$load_log" 2>&1; then
            printf 'load profile %s failed\n' "$run" >"$load_failure"
            return 1
        fi
        now=$(date +%s)
        remaining=$((deadline - now))
        [ "$remaining" -gt 0 ] || return 0
        sleep_for=$load_interval
        [ "$sleep_for" -le "$remaining" ] || sleep_for=$remaining
        sleep "$sleep_for"
    done
}
run_load_loop &
load_pid=$!

while [ "$(date +%s)" -lt "$deadline" ]; do
    [ ! -e "$load_failure" ] || fail load_profile_failed
    systemctl --quiet is-active vaultlink.service || fail service_inactive
    pid=$(systemctl show -p MainPID --value vaultlink.service)
    [ "$pid" -gt 0 ] || fail service_has_no_pid
    [ "$pid" = "$initial_pid" ] || fail service_pid_changed
    restarts=$(systemctl show -p NRestarts --value vaultlink.service)
    [ "$restarts" = "$restart_start" ] || fail unplanned_restart
    rss=$(awk '/VmRSS:/ { print $2 }' "/proc/$pid/status")
    [ -n "$rss" ] || fail rss_unavailable
    [ "$rss" -le 262144 ] || fail rss_exceeded_256_mib
    actual_binary_sha256=$(sha256sum "/proc/$pid/exe" | awk '{print $1}')
    [ "$actual_binary_sha256" = "$SOAK_BINARY_SHA256" ] || fail binary_hash_changed
    actual_config_sha256=$(sha256sum "$config" | awk '{print $1}')
    [ "$actual_config_sha256" = "$config_sha256" ] || fail config_hash_changed

    health_body="$SOAK_EVIDENCE_DIR/health.json.tmp"
    curl --fail --silent --show-error "$health_url" -o "$health_body" \
        || fail health_request_failed
    [ "$(cat "$health_body")" = "$expected_health_json" ] || fail health_json_mismatch
    health_sha256=$(sha256sum "$health_body" | awk '{print $1}')
    [ "$health_sha256" = "$expected_health_sha256" ] || fail health_hash_mismatch
    mv -f "$health_body" "$SOAK_EVIDENCE_DIR/health.json"

    integrity=$(sqlite3 "file:$database?mode=ro" \
        'PRAGMA query_only=ON; PRAGMA integrity_check;')
    [ "$integrity" = ok ] || fail sqlite_integrity_failed
    now=$(date +%s)
    printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$now" "$(date -u +%FT%TZ)" "$pid" "$rss" "$restarts" \
        "$health_sha256" "$actual_config_sha256" "$integrity" >>"$metrics"

    journal_tmp="$SOAK_EVIDENCE_DIR/vaultlink-journal.tmp"
    journalctl --quiet --unit=vaultlink.service --since="@$start_epoch" \
        --no-pager >"$journal_tmp" 2>&1 || fail journal_query_failed
    if grep -E -i -q \
        '(^|[[:space:]])(error|fatal)(:|[[:space:]])|panic(ked)?|database.*(corrupt|malformed|locked|i/o error)|sqlite.*(corrupt|malformed|locked|i/o error)|warn.*(database|sqlite|storage|cleanup)' \
        "$journal_tmp"; then
        mv -f "$journal_tmp" "$journal_log"
        fail journal_failure_pattern
    fi
    mv -f "$journal_tmp" "$journal_log"

    remaining=$((deadline - now))
    [ "$remaining" -gt 0 ] || break
    sleep_for=$interval
    [ "$sleep_for" -le "$remaining" ] || sleep_for=$remaining
    sleep "$sleep_for"
done

wait "$load_pid" || fail load_profile_failed
load_pid=
journalctl --quiet --unit=vaultlink.service --since="@$start_epoch" \
    --no-pager >"$journal_log" 2>&1 \
    || fail journal_query_failed
if grep -E -i -q \
    '(^|[[:space:]])(error|fatal)(:|[[:space:]])|panic(ked)?|database.*(corrupt|malformed|locked|i/o error)|sqlite.*(corrupt|malformed|locked|i/o error)|warn.*(database|sqlite|storage|cleanup)' \
    "$journal_log"; then
    fail journal_failure_pattern
fi

warm_start=$((start_epoch + 1800))
warm_end=$((start_epoch + 5400))
# Use a complete settled six-hour interval at the start of the final day, after
# allocator and application caches have seen multiple load profiles.
late_start=$((start_epoch + 172800))
late_end=$((start_epoch + 194400))
final_start=$((deadline - 3600))
median_rss() {
    from=$1
    to=$2
    awk -F, -v from="$from" -v to="$to" \
        'NR > 1 && $1 >= from && $1 <= to { print $4 }' "$metrics" \
        | sort -n \
        | awk '{ value[NR] = $1 } END {
            if (NR == 0) exit 1
            if (NR % 2) print value[(NR + 1) / 2]
            else print int((value[NR / 2] + value[NR / 2 + 1]) / 2)
        }'
}
warm_median=$(median_rss "$warm_start" "$warm_end") || fail warm_rss_window_missing
late_median=$(median_rss "$late_start" "$late_end") || fail late_rss_window_missing
final_median=$(median_rss "$final_start" "$deadline") || fail final_rss_window_missing
warm_allowance=$((warm_median * 15 / 100))
# A relative-only limit overreacts to bounded warmup on a small baseline.
[ "$warm_allowance" -ge 16384 ] || warm_allowance=16384
late_allowance=$((late_median * 5 / 100))
[ "$late_allowance" -ge 4096 ] || late_allowance=4096
warm_limit=$((warm_median + warm_allowance))
late_limit=$((late_median + late_allowance))
[ "$final_median" -le "$warm_limit" ] || fail rss_growth_exceeded_warm_allowance
[ "$final_median" -le "$late_limit" ] || fail rss_growth_exceeded_late_allowance
printf 'warm_rss_median_kib=%s\nlate_rss_median_kib=%s\nfinal_rss_median_kib=%s\nwarm_rss_growth_limit_kib=%s\nlate_rss_growth_limit_kib=%s\n' \
    "$warm_median" "$late_median" "$final_median" "$warm_limit" "$late_limit" \
    >>"$SOAK_EVIDENCE_DIR/candidate.env"

result_reason=passed
echo "72-hour soak gate passed; evidence: $SOAK_EVIDENCE_DIR"
