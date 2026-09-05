#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG

[ "$#" -eq 2 ] || {
    echo "usage: check-soak-evidence.sh COMMIT_SHA EVIDENCE_DIR" >&2
    exit 64
}
expected_commit=$1
evidence=$2
result="$evidence/result.env"
if [ ! -s "$result" ] || [ ! -s "$evidence/metrics.csv" ] \
    || [ ! -s "$evidence/SHA256SUMS" ] || [ ! -s "$evidence/health.json" ] \
    || [ ! -s "$evidence/candidate.env" ] || [ ! -f "$evidence/vaultlink-journal.log" ]; then
    echo "soak evidence is incomplete" >&2
    exit 1
fi

value() {
    key=$1
    values=$(sed -n "s/^${key}=//p" "$result")
    [ "$(printf '%s\n' "$values" | grep -c .)" -eq 1 ] \
        || { echo "soak result must define $key exactly once" >&2; exit 1; }
    printf '%s\n' "$values"
}

[ "$(value state)" = success ] || { echo "soak did not succeed" >&2; exit 1; }
[ "$(value reason)" = passed ] || { echo "soak success reason is invalid" >&2; exit 1; }
[ "$(value commit_sha)" = "$expected_commit" ] || { echo "soak commit mismatch" >&2; exit 1; }
[ "$(value architecture)" = amd64 ] || { echo "soak architecture must be amd64" >&2; exit 1; }
[ "$(value os_id)" = debian ] || { echo "soak OS must be Debian" >&2; exit 1; }
[ "$(value os_version_id)" = 13 ] || { echo "soak OS must be Debian 13" >&2; exit 1; }
[ "$(value expected_version)" = 0.7.0 ] || { echo "soak did not exercise VaultLink 0.7.0" >&2; exit 1; }
namespace=$(value namespace)
case "$namespace" in *[!A-Za-z0-9._-]*|'') echo "soak namespace is unsafe" >&2; exit 1 ;; esac
namespace_tail=${namespace#"$expected_commit-"}
namespace_epoch=${namespace_tail%%-*}
namespace_random=${namespace_tail#*-}
case "$namespace_epoch" in *[!0-9]*|'') echo "soak namespace epoch is invalid" >&2; exit 1 ;; esac
case "$namespace_random" in *[!0-9a-f]*|'') echo "soak namespace suffix is invalid" >&2; exit 1 ;; esac
if [ "${#namespace_random}" -ne 16 ] \
    || [ "$namespace" != "$expected_commit-$namespace_epoch-$namespace_random" ]; then
    echo "soak namespace is not bound to the candidate commit" >&2
    exit 1
fi
duration=$(value duration_seconds)
case "$duration" in *[!0-9]*|'') echo "invalid soak duration" >&2; exit 1 ;; esac
[ "$duration" -ge 259200 ] || { echo "soak duration is shorter than 72 hours" >&2; exit 1; }
start=$(value start_epoch)
end=$(value end_epoch)
case "$start:$end" in *[!0-9:]*|:*|*::*) echo "invalid soak start or end epoch" >&2; exit 1 ;; esac
[ $((end - start)) -eq "$duration" ] || { echo "soak timestamps and duration disagree" >&2; exit 1; }
unit_env="$evidence/unit.env"
[ -s "$unit_env" ] || { echo "soak evidence is missing unit.env" >&2; exit 1; }
unit_value() {
    key=$1
    values=$(sed -n "s/^${key}=//p" "$unit_env")
    [ "$(printf '%s\n' "$values" | grep -c .)" -eq 1 ] \
        || { echo "unit.env must define $key exactly once" >&2; exit 1; }
    printf '%s\n' "$values"
}
unit_start=$(unit_value SOAK_START_EPOCH)
unit_deadline=$(unit_value SOAK_DEADLINE_EPOCH)
case "$unit_start:$unit_deadline" in
    *[!0-9:]*|:*|*::*) echo "unit start or deadline epoch is invalid" >&2; exit 1 ;;
esac
[ "$unit_start" = "$start" ] \
    || { echo "result start does not match the persisted unit start" >&2; exit 1; }
[ $((unit_deadline - unit_start)) -eq 259200 ] \
    || { echo "persisted unit duration is not exactly 72 hours" >&2; exit 1; }
if [ "$end" -lt "$unit_deadline" ] || [ "$end" -gt $((unit_deadline + 900)) ]; then
    echo "soak completion is before its deadline or exceeds the 15-minute finalization grace" >&2
    exit 1
fi
binary_sha256=$(value binary_sha256)
case "$binary_sha256" in *[!0-9a-f]*|'') echo "invalid soak binary hash" >&2; exit 1 ;; esac
[ "${#binary_sha256}" -eq 64 ] || { echo "invalid soak binary hash" >&2; exit 1; }
orchestration_sha256=$(value orchestration_sha256)
case "$orchestration_sha256" in *[!0-9a-f]*|'') echo "invalid orchestration hash" >&2; exit 1 ;; esac
[ "${#orchestration_sha256}" -eq 64 ] || { echo "invalid orchestration hash" >&2; exit 1; }
approved_orchestration_sha256=$(
    for file in \
        deploy/vaultlink-soak-control.sh \
        deploy/vaultlink-soak-remote.sh \
        tools/soak-monitor.sh \
        tools/load-test.sh \
        tools/collect-soak-evidence.sh \
        deploy/vaultlink-soak@.service; do
        [ -f "$file" ] || { echo "approved orchestration file is missing: $file" >&2; exit 1; }
        sha256sum "$file" | awk '{print $1}'
    done | sha256sum | awk '{print $1}'
)
[ "$orchestration_sha256" = "$approved_orchestration_sha256" ] \
    || { echo "soak orchestration does not match the checked-out commit" >&2; exit 1; }
if ! grep -F -x -q "SOAK_COMMIT_SHA=$expected_commit" "$unit_env" \
    || ! grep -F -x -q "SOAK_BINARY_SHA256=$binary_sha256" "$unit_env" \
    || ! grep -F -x -q "SOAK_ORCHESTRATION_SHA256=$orchestration_sha256" "$unit_env" \
    || ! grep -F -x -q "SOAK_START_EPOCH=$start" "$unit_env" \
    || ! grep -F -x -q "SOAK_DEADLINE_EPOCH=$unit_deadline" "$unit_env" \
    || ! grep -F -x -q "SOAK_NAMESPACE=$namespace" "$unit_env" \
    || ! grep -F -x -q 'SOAK_ARCHITECTURE=amd64' "$unit_env" \
    || ! grep -F -x -q 'SOAK_OS_ID=debian' "$unit_env" \
    || ! grep -F -x -q 'SOAK_OS_VERSION_ID=13' "$unit_env" \
    || ! grep -F -x -q 'SOAK_SECONDS=259200' "$unit_env" \
    || ! grep -F -x -q 'SOAK_INTERVAL_SECONDS=300' "$unit_env" \
    || ! grep -F -x -q 'SOAK_LOAD_INTERVAL_SECONDS=21600' "$unit_env" \
    || ! grep -F -x -q 'SOAK_EXPECTED_VERSION=0.7.0' "$unit_env" \
    || ! grep -F -x -q 'architecture=amd64' "$evidence/candidate.env" \
    || ! grep -F -x -q 'os_id=debian' "$evidence/candidate.env" \
    || ! grep -F -x -q 'os_version_id=13' "$evidence/candidate.env"; then
    echo "unit evidence does not persist the approved orchestration time boundary" >&2
    exit 1
fi
[ "$(value load_interval_seconds)" = 21600 ] \
    || { echo "soak load interval is not six hours" >&2; exit 1; }
load_epochs=$(mktemp)
trap 'rm -f "$load_epochs"' EXIT HUP INT TERM

metric_samples=$(awk 'END { print NR - 1 }' "$evidence/metrics.csv")
[ "$metric_samples" -ge 850 ] || { echo "soak evidence has too few metric samples" >&2; exit 1; }
config_sha256=$(value config_sha256)
health_sha256=$(value health_sha256)
for hash in "$config_sha256" "$health_sha256"; do
    case "$hash" in *[!0-9a-f]*|'') echo "invalid soak config or health hash" >&2; exit 1 ;; esac
    [ "${#hash}" -eq 64 ] || { echo "invalid soak config or health hash" >&2; exit 1; }
done
for candidate_line in \
    "commit=$expected_commit" \
    "namespace=$namespace" \
    "binary_sha256=$binary_sha256" \
    "orchestration_sha256=$orchestration_sha256" \
    "config_sha256=$config_sha256" \
    'expected_version=0.7.0' \
    "health_sha256=$health_sha256"; do
    grep -F -x -q "$candidate_line" "$evidence/candidate.env" \
        || { echo "candidate evidence does not match the soak result" >&2; exit 1; }
done
awk -F, -v start="$start" -v end="$unit_deadline" \
    -v health="$health_sha256" -v config="$config_sha256" '
    NR == 1 {
        if ($0 != "epoch,timestamp,pid,rss_kib,restarts,health_sha256,config_sha256,integrity") exit 1
        next
    }
    $1 !~ /^[0-9]+$/ || $1 < start || $1 > end { exit 1 }
    NR == 2 {
        pid = $3
        restarts = $5
        if ($1 - start > 360) exit 1
    }
    NR > 2 && ($1 <= previous || $1 - previous > 360) { exit 1 }
    $3 != pid || $4 !~ /^[0-9]+$/ || $4 > 262144 || $5 != restarts \
        || $6 != health || $7 != config || $8 != "ok" { exit 1 }
    { previous = $1 }
    END { if (NR < 2 || end - previous > 360) exit 1 }
' "$evidence/metrics.csv" \
    || { echo "soak metrics violate PID, hash, restart, RSS, or integrity thresholds" >&2; exit 1; }
[ "$(cat "$evidence/health.json")" = '{"ok":true,"version":"0.7.0"}' ] \
    || { echo "soak health response is not exact" >&2; exit 1; }
[ "$(sha256sum "$evidence/health.json" | awk '{print $1}')" = "$health_sha256" ] \
    || { echo "soak health hash mismatch" >&2; exit 1; }
if grep -E -i -q \
    '(^|[[:space:]])(error|fatal)(:|[[:space:]])|panic(ked)?|database.*(corrupt|malformed|locked|i/o error)|sqlite.*(corrupt|malformed|locked|i/o error)|warn.*(database|sqlite|storage|cleanup)' \
    "$evidence/vaultlink-journal.log"; then
    echo "soak journal contains a failure pattern" >&2
    exit 1
fi

median_rss() {
    from=$1
    to=$2
    awk -F, -v from="$from" -v to="$to" \
        'NR > 1 && $1 >= from && $1 <= to { print $4 }' "$evidence/metrics.csv" \
        | sort -n \
        | awk '{ value[NR] = $1 } END {
            if (NR == 0) exit 1
            if (NR % 2) print value[(NR + 1) / 2]
            else print int((value[NR / 2] + value[NR / 2 + 1]) / 2)
        }'
}
warm_median=$(median_rss $((start + 1800)) $((start + 5400))) \
    || { echo "soak warm RSS window is incomplete" >&2; exit 1; }
# Recompute the same settled late window independently from monitor output.
late_median=$(median_rss $((start + 172800)) $((start + 194400))) \
    || { echo "soak late RSS window is incomplete" >&2; exit 1; }
final_median=$(median_rss $((unit_deadline - 3600)) "$unit_deadline") \
    || { echo "soak final RSS window is incomplete" >&2; exit 1; }
warm_allowance=$((warm_median * 15 / 100))
[ "$warm_allowance" -ge 16384 ] || warm_allowance=16384
late_allowance=$((late_median * 5 / 100))
[ "$late_allowance" -ge 4096 ] || late_allowance=4096
warm_limit=$((warm_median + warm_allowance))
late_limit=$((late_median + late_allowance))
[ "$final_median" -le "$warm_limit" ] \
    || { echo "recomputed RSS growth exceeds the warm allowance" >&2; exit 1; }
[ "$final_median" -le "$late_limit" ] \
    || { echo "recomputed RSS growth exceeds the late plateau allowance" >&2; exit 1; }
for rss_line in \
    "warm_rss_median_kib=$warm_median" \
    "late_rss_median_kib=$late_median" \
    "final_rss_median_kib=$final_median" \
    "warm_rss_growth_limit_kib=$warm_limit" \
    "late_rss_growth_limit_kib=$late_limit"; do
    grep -F -x -q "$rss_line" "$evidence/candidate.env" \
        || { echo "candidate RSS evidence does not match recomputed metrics" >&2; exit 1; }
done

load_runs=$(find "$evidence" -mindepth 2 -maxdepth 2 -path '*/load-*/result.env' -type f | wc -l)
[ "$load_runs" -ge 12 ] || { echo "soak evidence has too few successful load profiles" >&2; exit 1; }
evidence_field_value() {
    field_file=$1
    field_key=$2
    if [ ! -f "$field_file" ] || [ -L "$field_file" ]; then
        echo "load evidence field source is missing or unsafe" >&2
        exit 1
    fi
    field_values=$(sed -n "s/^${field_key}=//p" "$field_file")
    [ "$(printf '%s\n' "$field_values" | grep -c .)" -eq 1 ] \
        || { echo "load evidence must define $field_key exactly once" >&2; exit 1; }
    printf '%s\n' "$field_values"
}
for load_result in "$evidence"/load-*/result.env; do
    load_dir=${load_result%/result.env}
    load_command="$load_dir/load-command.env"
    profile_status="$load_dir/profile-status.env"
    if [ ! -s "$load_command" ] || [ -L "$load_command" ] \
        || [ ! -s "$profile_status" ] || [ -L "$profile_status" ] \
        || [ "$(evidence_field_value "$load_command" stage)" != complete ] \
        || [ "$(evidence_field_value "$load_command" exit_status)" != 0 ]; then
        echo "soak load evidence is missing a successful command or profile report" >&2
        exit 1
    fi
    load_value() {
        load_key=$1
        evidence_field_value "$load_result" "$load_key"
    }
    [ "$(load_value namespace)" = "$namespace" ] \
        || { echo "load namespace does not match the soak namespace" >&2; exit 1; }
    if [ "$(load_value identity_mode)" != trusted_proxy_xff ] \
        || [ "$(load_value concurrency_barrier)" != passed ] \
        || [ "$(load_value admission_same_identity_status)" != 503 ] \
        || [ "$(load_value admission_distinct_identity_status)" != 206 ]; then
        echo "load evidence did not prove trusted forwarded admission identities" >&2
        exit 1
    fi
    if [ "$(load_value supervision_mode)" != systemd ] \
        || [ "$(load_value metadata_p95_policy)" != strict ] \
        || [ "$(load_value metadata_p95_limit_seconds)" != 2.000 ] \
        || [ "$(load_value metadata_p95_within_limit)" != true ] \
        || [ "$(load_value metadata_p95_enforced)" != true ]; then
        echo "soak load evidence is not systemd-supervised with the strict p95 gate" >&2
        exit 1
    fi
    if [ "$(load_value load_profile)" != full ] \
        || [ "$(load_value metadata_clients)" != 100 ] \
        || [ "$(load_value metadata_requests)" != 2000 ] \
        || [ "$(load_value range_streams)" != 40 ] \
        || [ "$(load_value uploads)" != 10 ]; then
        echo "soak load result does not retain the full 100/40/10 workload" >&2
        exit 1
    fi
    if [ "$(load_value metadata_capacity_retry_limit_per_client)" != 3 ] \
        || [ "$(load_value metadata_capacity_retry_after_seconds)" != 1 ] \
        || [ "$(load_value metadata_capacity_response_limit_seconds)" != 1.100 ]; then
        echo "soak load result does not retain the bounded capacity retry contract" >&2
        exit 1
    fi
    metadata_capacity_retries=$(load_value metadata_capacity_retries)
    metadata_attempts=$(load_value metadata_attempts)
    case "$metadata_capacity_retries:$metadata_attempts" in
        *[!0-9:]*|:*|*::*|*:)
            echo "soak load result contains invalid metadata attempt counts" >&2
            exit 1
            ;;
    esac
    if [ "$metadata_capacity_retries" -gt 300 ] \
        || [ "$metadata_attempts" -ne $((2000 + metadata_capacity_retries)) ] \
        || [ "$(evidence_field_value "$profile_status" metadata_capacity_retries)" \
            != "$metadata_capacity_retries" ] \
        || [ "$(evidence_field_value "$profile_status" metadata_attempts)" \
            != "$metadata_attempts" ]; then
        echo "soak load metadata retry counts are inconsistent" >&2
        exit 1
    fi
    if [ "$(load_value range_share_count)" != 3 ] \
        || [ "$(load_value range_streams_per_share_max)" != 14 ] \
        || [ "$(load_value upload_share_count)" != 5 ] \
        || [ "$(load_value uploads_per_share)" != 2 ]; then
        echo "soak load result does not prove bounded per-share sharding" >&2
        exit 1
    fi
    for profile_line in \
        'load_profile=full' \
        'metadata_status=0' \
        'download_status=0' \
        'upload_status=0' \
        'rss_status=0' \
        'metadata_rows=2000' \
        'range_rows=40' \
        'upload_rows=10' \
        'supervision_mode=systemd' \
        'metadata_p95_policy=strict' \
        'metadata_p95_limit_seconds=2.000' \
        'metadata_p95_within_limit=true' \
        'metadata_p95_enforced=true'; do
        profile_key=${profile_line%%=*}
        profile_expected=${profile_line#*=}
        [ "$(evidence_field_value "$profile_status" "$profile_key")" = \
            "$profile_expected" ] \
            || { echo "soak load profile report violates $profile_line" >&2; exit 1; }
    done
    profile_rss_rows=$(evidence_field_value "$profile_status" rss_rows)
    case "$profile_rss_rows" in
        ''|*[!0-9]*|0) echo "soak load profile has no RSS samples" >&2; exit 1 ;;
    esac
    for phase in pre-load post-load; do
        snapshot="$load_dir/$phase.env"
        if [ ! -s "$snapshot" ] || [ -L "$snapshot" ]; then
            echo "load evidence is missing $phase report" >&2
            exit 1
        fi
        snapshot_cpu_count=$(evidence_field_value "$snapshot" host_cpu_count)
        snapshot_mem_total_kib=$(evidence_field_value "$snapshot" host_mem_total_kib)
        for resource_value in "$snapshot_cpu_count" "$snapshot_mem_total_kib"; do
            case "$resource_value" in
                ''|*[!0-9]*) echo "soak host resource evidence is invalid" >&2; exit 1 ;;
            esac
        done
        if ! [ "$snapshot_cpu_count" -ge 8 ] || ! [ "$snapshot_mem_total_kib" -ge 15728640 ]; then
            echo "full load qualification requires 8 available vCPUs and at least 15 GiB MemTotal" >&2
            exit 1
        fi
        [ "$(evidence_field_value "$snapshot" load_profile)" = full ] \
            || { echo "soak snapshot is not a full load profile" >&2; exit 1; }
        snapshot_epoch=$(evidence_field_value "$snapshot" epoch)
        snapshot_pid=$(evidence_field_value "$snapshot" pid)
        snapshot_starttime=$(evidence_field_value "$snapshot" process_starttime_ticks)
        snapshot_rss=$(evidence_field_value "$snapshot" rss_kib)
        snapshot_binary=$(evidence_field_value "$snapshot" binary_sha256)
        snapshot_health=$(evidence_field_value "$snapshot" health_sha256)
        snapshot_integrity=$(evidence_field_value "$snapshot" integrity)
        snapshot_supervision=$(evidence_field_value "$snapshot" supervision_mode)
        case "$snapshot_epoch:$snapshot_pid:$snapshot_starttime:$snapshot_rss" in
            *[!0-9:]*|:*|*::*|*:*:) echo "load $phase report contains invalid numeric state" >&2; exit 1 ;;
        esac
        if [ "$snapshot_rss" -gt 262144 ] \
            || [ "$snapshot_binary" != "$binary_sha256" ] \
            || [ "$snapshot_health" != "$health_sha256" ] \
            || [ "$snapshot_integrity" != ok ] \
            || [ "$snapshot_supervision" != systemd ]; then
            echo "load $phase report violates PID/hash/RSS/integrity state" >&2
            exit 1
        fi
        if [ "$phase" = pre-load ]; then
            pre_epoch=$snapshot_epoch
            pre_pid=$snapshot_pid
            pre_starttime=$snapshot_starttime
        else
            if [ "$snapshot_epoch" -lt "$pre_epoch" ] \
                || [ "$snapshot_pid" != "$pre_pid" ] \
                || [ "$snapshot_starttime" != "$pre_starttime" ]; then
                echo "load process identity changed or post-load predates pre-load" >&2
                exit 1
            fi
        fi
    done
    printf '%s\n' "$pre_epoch" >>"$load_epochs"
    reported_p95=$(load_value metadata_p95_seconds)
    printf '%s\n' "$reported_p95" | grep -E -x -q '[0-9]+([.][0-9]+)?' \
        || { echo "load metadata p95 is not numeric" >&2; exit 1; }
    calculated_p95=$(awk -F, '{ print $3 }' "$load_dir/metadata-load.csv" \
        | sort -n | awk 'NR == 1900 { print; exit }')
    if [ "$(wc -l <"$load_dir/metadata-load.csv")" -ne 2000 ] \
        || [ "$reported_p95" != "$calculated_p95" ] \
        || ! grep -F -x -q "metadata_observed_p95_seconds=$calculated_p95" \
            "$profile_status"; then
        echo "load metadata sample or p95 mismatch" >&2
        exit 1
    fi
    awk -F, '
        $1 !~ /^198\.18\.1\.[0-9]+$/ || $2 !~ /^2[0-9][0-9]$/ { exit 1 }
        { if (!seen[$1]++) clients++ }
        END {
            if (clients != 100) exit 1
            for (client = 1; client <= 100; client++)
                if (seen["198.18.1." client] != 20) exit 1
        }
    ' "$load_dir/metadata-load.csv" \
        || { echo "load metadata client identities or statuses are invalid" >&2; exit 1; }
    awk -v p95="$calculated_p95" 'BEGIN { exit !(p95 < 2.000) }' \
        || { echo "recomputed metadata p95 is not below 2 seconds" >&2; exit 1; }

    metadata_retry_file="$load_dir/metadata-capacity-retries.csv"
    if [ ! -f "$metadata_retry_file" ] || [ -L "$metadata_retry_file" ] \
        || [ "$(wc -l <"$metadata_retry_file")" -ne "$metadata_capacity_retries" ]; then
        echo "load metadata capacity retry evidence is missing or inconsistent" >&2
        exit 1
    fi
    awk -F, -v expected="$metadata_capacity_retries" '
        NF != 6 || $1 !~ /^198\.18\.1\.[0-9]+$/ \
            || $2 !~ /^([1-9]|1[0-9]|20)$/ \
            || $3 !~ /^[1-3]$/ || $4 != 503 \
            || $5 !~ /^[0-9]+([.][0-9]+)?$/ || $5 + 0 <= 0 \
            || $5 + 0 > 1.100 || $6 != 1 { exit 1 }
        {
            split($1, octets, ".")
            if (octets[4] < 1 || octets[4] > 100) exit 1
            if ($3 != ++retries[$1]) exit 1
        }
        END { if (NR != expected) exit 1 }
    ' "$metadata_retry_file" \
        || { echo "load metadata capacity retry evidence is invalid" >&2; exit 1; }

    range_bytes=$(load_value range_bytes)
    fixture_bytes=$(load_value fixture_bytes)
    range_hash=$(load_value range_sha256)
    if [ "$range_bytes" != 67108864 ] || [ "$fixture_bytes" != 53687091200 ]; then
        echo "full load requires 64-MiB ranges from the 50-GiB fixture" >&2
        exit 1
    fi
    case "$range_hash" in *[!0-9a-f]*|'') echo "load range hash is invalid" >&2; exit 1 ;; esac
    [ "${#range_hash}" -eq 64 ] || { echo "load range hash is invalid" >&2; exit 1; }
    range_end=$((range_bytes - 1))
    expected_range="bytes 0-$range_end/$fixture_bytes"
    [ "$(wc -l <"$load_dir/range-results.csv")" -eq 40 ] \
        || { echo "load range sample count mismatch" >&2; exit 1; }
    awk -F, -v bytes="$range_bytes" -v hash="$range_hash" -v expected="$expected_range" '
        NF != 9 || $1 !~ /^([0-9]|[1-3][0-9])$/ || seen[$1]++ { exit 1 }
        $2 != sprintf("198.18.2.%d", $1 + 1) || $3 != 206 || $4 != bytes || $5 != hash || $6 != expected { exit 1 }
        $7 !~ /^[0-9]+([.][0-9]+)?$/ || $7 + 0 < 0 \
            || $8 !~ /^[0-9]+([.][0-9]+)?$/ || $8 + 0 <= 0 \
            || $9 !~ /^[0-9]+([.][0-9]+)?$/ || $9 + 0 <= 0 { exit 1 }
        END { if (NR != 40) exit 1 }
    ' "$load_dir/range-results.csv" \
        || { echo "range status, length, hash, or Content-Range mismatch" >&2; exit 1; }
    calculated_range_p95=$(awk -F, '{print $7}' "$load_dir/range-results.csv" \
        | sort -n | awk 'NR == 38 {print; exit}')
    if [ "$(load_value range_ttfb_p95_seconds)" != "$calculated_range_p95" ] \
        || [ "$(evidence_field_value "$profile_status" range_ttfb_observed_p95_seconds)" != "$calculated_range_p95" ] \
        || ! awk -v value="$calculated_range_p95" 'BEGIN {exit !(value < 2.000)}'; then
        echo "recomputed range TTFB p95 is inconsistent or not below two seconds" >&2
        exit 1
    fi
    for range_report in "$load_result" "$profile_status"; do
        for range_field in range_ttfb_p95_limit_seconds=2.000 range_ttfb_p95_within_limit=true range_ttfb_p95_enforced=true; do
            [ "$(evidence_field_value "$range_report" "${range_field%%=*}")" = "${range_field#*=}" ] \
                || { echo "range report violates $range_field" >&2; exit 1; }
        done
    done

    upload_hash=$(load_value upload_sha256)
    case "$upload_hash" in *[!0-9a-f]*|'') echo "load upload hash is invalid" >&2; exit 1 ;; esac
    [ "${#upload_hash}" -eq 64 ] || { echo "load upload hash is invalid" >&2; exit 1; }
    [ "$(load_value upload_integrity)" = server_readback ] \
        || { echo "load upload integrity mode is not server readback" >&2; exit 1; }
    run_id=$(load_value run_id)
    [ "$(wc -l <"$load_dir/upload-results.csv")" -eq 10 ] \
        || { echo "load upload sample count mismatch" >&2; exit 1; }
    awk -F, -v hash="$upload_hash" -v soak_namespace="$namespace" -v run_id="$run_id" '
        NF != 8 || $1 !~ /^[0-9]$/ || seen[$1]++ { exit 1 }
        $2 != sprintf("198.18.3.%d", $1 + 1) || $3 != 303 || $4 != "created" \
            || $5 != hash || $6 != 200 || $7 != hash \
            || $8 != sprintf("load-%s-%s-%d.bin", soak_namespace, run_id, $1) { exit 1 }
        END { if (NR != 10) exit 1 }
    ' \
        "$load_dir/upload-results.csv" \
        || { echo "upload status or payload hash mismatch" >&2; exit 1; }

    [ -s "$load_dir/rss-samples.csv" ] \
        || { echo "load RSS samples are missing" >&2; exit 1; }
    reported_max_rss=$(load_value max_rss_kib)
    calculated_max_rss=$(awk -F, '
        NR == 1 {
            if ($0 != "epoch,pid,rss_kib") exit 1
            next
        }
        $1 !~ /^[0-9]+$/ || $2 !~ /^[0-9]+$/ || $3 !~ /^[0-9]+$/ { exit 1 }
        { if ($3 > maximum) maximum = $3; samples++ }
        END { if (samples == 0) exit 1; print maximum }
    ' "$load_dir/rss-samples.csv") \
        || { echo "load RSS samples are malformed" >&2; exit 1; }
    if [ "$reported_max_rss" != "$calculated_max_rss" ] \
        || [ "$calculated_max_rss" -gt 262144 ]; then
        echo "load RSS maximum is inconsistent or exceeds 256 MiB" >&2
        exit 1
    fi
done
sort -n -o "$load_epochs" "$load_epochs"
awk -v start="$start" -v end="$unit_deadline" -v interval=21600 '
    {
        epoch = $1
        if (epoch < start || epoch >= end) exit 1
        bucket = int((epoch - start) / interval)
        if (bucket < 0 || bucket > 11) exit 1
        seen[bucket] = 1
        if (NR > 1 && (epoch <= previous || epoch - previous > 25200)) exit 1
        previous = epoch
    }
    END {
        if (NR < 12) exit 1
        for (bucket = 0; bucket < 12; bucket++)
            if (!seen[bucket]) exit 1
    }
' "$load_epochs" \
    || { echo "load profiles do not cover all 12 six-hour soak buckets" >&2; exit 1; }
(
    cd "$evidence"
    sha256sum -c SHA256SUMS
)

printf 'binary_sha256=%s\n' "$binary_sha256"
echo "Exact-commit 72-hour soak evidence passed"
