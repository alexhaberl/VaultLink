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
[ "$(value expected_version)" = 0.5.0 ] || { echo "soak did not exercise VaultLink 0.5.0" >&2; exit 1; }
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
        tools/soak-monitor.sh \
        tools/load-test.sh \
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
    || ! grep -F -x -q 'SOAK_EXPECTED_VERSION=0.5.0' "$unit_env" \
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
    'expected_version=0.5.0' \
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
[ "$(cat "$evidence/health.json")" = '{"ok":true,"version":"0.5.0"}' ] \
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
final_median=$(median_rss $((unit_deadline - 3600)) "$unit_deadline") \
    || { echo "soak final RSS window is incomplete" >&2; exit 1; }
[ "$final_median" -le $((warm_median + (warm_median * 15 / 100))) ] \
    || { echo "recomputed RSS median growth exceeds 15 percent" >&2; exit 1; }

load_runs=$(find "$evidence" -mindepth 2 -maxdepth 2 -path '*/load-*/result.env' -type f | wc -l)
[ "$load_runs" -ge 12 ] || { echo "soak evidence has too few successful load profiles" >&2; exit 1; }
for load_result in "$evidence"/load-*/result.env; do
    load_dir=${load_result%/result.env}
    [ "$(sed -n 's/^namespace=//p' "$load_result")" = "$namespace" ] \
        || { echo "load namespace does not match the soak namespace" >&2; exit 1; }
    if [ "$(sed -n 's/^identity_mode=//p' "$load_result")" != trusted_proxy_xff ] \
        || [ "$(sed -n 's/^concurrency_barrier=//p' "$load_result")" != passed ] \
        || [ "$(sed -n 's/^admission_same_identity_status=//p' "$load_result")" != 503 ] \
        || [ "$(sed -n 's/^admission_distinct_identity_status=//p' "$load_result")" != 206 ]; then
        echo "load evidence did not prove trusted forwarded admission identities" >&2
        exit 1
    fi
    for phase in pre-load post-load; do
        snapshot="$load_dir/$phase.env"
        [ -s "$snapshot" ] || { echo "load evidence is missing $phase report" >&2; exit 1; }
        snapshot_epoch=$(sed -n 's/^epoch=//p' "$snapshot")
        snapshot_pid=$(sed -n 's/^pid=//p' "$snapshot")
        snapshot_rss=$(sed -n 's/^rss_kib=//p' "$snapshot")
        snapshot_binary=$(sed -n 's/^binary_sha256=//p' "$snapshot")
        snapshot_health=$(sed -n 's/^health_sha256=//p' "$snapshot")
        snapshot_integrity=$(sed -n 's/^integrity=//p' "$snapshot")
        case "$snapshot_epoch:$snapshot_pid:$snapshot_rss" in
            *[!0-9:]*|:*|*::*|*:*:) echo "load $phase report contains invalid numeric state" >&2; exit 1 ;;
        esac
        if [ "$snapshot_rss" -gt 262144 ] \
            || [ "$snapshot_binary" != "$binary_sha256" ] \
            || [ "$snapshot_health" != "$health_sha256" ] \
            || [ "$snapshot_integrity" != ok ]; then
            echo "load $phase report violates PID/hash/RSS/integrity state" >&2
            exit 1
        fi
        if [ "$phase" = pre-load ]; then
            pre_epoch=$snapshot_epoch
            pre_pid=$snapshot_pid
        else
            if [ "$snapshot_epoch" -lt "$pre_epoch" ] || [ "$snapshot_pid" != "$pre_pid" ]; then
                echo "load PID changed or post-load predates pre-load" >&2
                exit 1
            fi
        fi
    done
    printf '%s\n' "$pre_epoch" >>"$load_epochs"
    reported_p95=$(sed -n 's/^metadata_p95_seconds=//p' "$load_result")
    calculated_p95=$(awk -F, '{ print $3 }' "$load_dir/metadata-load.csv" \
        | sort -n | awk 'NR == 1900 { print; exit }')
    if [ "$(wc -l <"$load_dir/metadata-load.csv")" -ne 2000 ] \
        || [ "$reported_p95" != "$calculated_p95" ]; then
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
    awk -v p95="$calculated_p95" 'BEGIN { exit !(p95 < 0.750) }' \
        || { echo "recomputed metadata p95 exceeds 750 ms" >&2; exit 1; }

    range_bytes=$(sed -n 's/^range_bytes=//p' "$load_result")
    fixture_bytes=$(sed -n 's/^fixture_bytes=//p' "$load_result")
    range_hash=$(sed -n 's/^range_sha256=//p' "$load_result")
    case "$range_bytes:$fixture_bytes" in
        *[!0-9:]*|:*|*::*) echo "load evidence contains invalid range sizes" >&2; exit 1 ;;
    esac
    range_end=$((range_bytes - 1))
    expected_range="bytes 0-$range_end/$fixture_bytes"
    [ "$(wc -l <"$load_dir/range-results.csv")" -eq 40 ] \
        || { echo "load range sample count mismatch" >&2; exit 1; }
    awk -F, -v bytes="$range_bytes" -v hash="$range_hash" -v expected="$expected_range" '
        $2 != sprintf("198.18.2.%d", $1 + 1) || $3 != 206 || $4 != bytes || $5 != hash || $6 != expected { exit 1 }
    ' "$load_dir/range-results.csv" \
        || { echo "range status, length, hash, or Content-Range mismatch" >&2; exit 1; }

    upload_hash=$(sed -n 's/^upload_sha256=//p' "$load_result")
    case "$upload_hash" in *[!0-9a-f]*|'') echo "load upload hash is invalid" >&2; exit 1 ;; esac
    [ "${#upload_hash}" -eq 64 ] || { echo "load upload hash is invalid" >&2; exit 1; }
    [ "$(sed -n 's/^upload_integrity=//p' "$load_result")" = server_readback ] \
        || { echo "load upload integrity mode is not server readback" >&2; exit 1; }
    run_id=$(sed -n 's/^run_id=//p' "$load_result")
    [ "$(wc -l <"$load_dir/upload-results.csv")" -eq 10 ] \
        || { echo "load upload sample count mismatch" >&2; exit 1; }
    awk -F, -v hash="$upload_hash" -v soak_namespace="$namespace" -v run_id="$run_id" '
        $2 != sprintf("198.18.3.%d", $1 + 1) || $3 != 303 || $4 != "created" \
            || $5 != hash || $6 != 200 || $7 != hash \
            || $8 != sprintf("load-%s-%s-%d.bin", soak_namespace, run_id, $1) { exit 1 }
    ' \
        "$load_dir/upload-results.csv" \
        || { echo "upload status or payload hash mismatch" >&2; exit 1; }

    [ -s "$load_dir/rss-samples.csv" ] \
        || { echo "load RSS samples are missing" >&2; exit 1; }
    reported_max_rss=$(sed -n 's/^max_rss_kib=//p' "$load_result")
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
