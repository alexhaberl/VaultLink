#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG
umask 077

fail() {
    echo "soak evidence smoke failed: $*" >&2
    exit 1
}

refresh_evidence_manifest() {
    evidence=$1
    manifest_tmp="$work/SHA256SUMS.tmp"
    (
        cd "$evidence"
        find . -type f ! -name SHA256SUMS -print0 \
            | sort -z \
            | xargs -0 sha256sum >"$manifest_tmp"
        mv "$manifest_tmp" SHA256SUMS
    )
}

rewrite_rss_evidence() {
    evidence=$1
    warm=$2
    late=$3
    final=$4
    metrics_tmp="$work/metrics.csv.tmp"
    awk -F, -v OFS=, -v start="$start" -v end="$end" \
        -v warm="$warm" -v late="$late" -v final="$final" '
        NR == 1 { print; next }
        $1 >= start + 1800 && $1 <= start + 5400 { $4 = warm }
        $1 >= start + 172800 && $1 <= start + 194400 { $4 = late }
        $1 >= end - 3600 && $1 <= end { $4 = final }
        { print }
    ' "$evidence/metrics.csv" >"$metrics_tmp"
    mv "$metrics_tmp" "$evidence/metrics.csv"

    warm_allowance=$((warm * 15 / 100))
    [ "$warm_allowance" -ge 16384 ] || warm_allowance=16384
    late_allowance=$((late * 5 / 100))
    [ "$late_allowance" -ge 4096 ] || late_allowance=4096
    sed -i \
        '/^warm_rss_median_kib=/d;
         /^late_rss_median_kib=/d;
         /^final_rss_median_kib=/d;
         /^warm_rss_growth_limit_kib=/d;
         /^late_rss_growth_limit_kib=/d' \
        "$evidence/candidate.env"
    printf 'warm_rss_median_kib=%s\nlate_rss_median_kib=%s\nfinal_rss_median_kib=%s\nwarm_rss_growth_limit_kib=%s\nlate_rss_growth_limit_kib=%s\n' \
        "$warm" "$late" "$final" \
        "$((warm + warm_allowance))" "$((late + late_allowance))" \
        >>"$evidence/candidate.env"
    refresh_evidence_manifest "$evidence"
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
state="$work/state"
commit=0123456789abcdef0123456789abcdef01234567
active="$state/$commit"
destination="$work/collected"
mkdir -p "$active"
chmod 2750 "$state" "$active"
ln -s "$commit" "$state/active"

health='{"ok":true,"version":"0.6.0"}'
printf '%s' "$health" >"$active/health.json"
health_hash=$(printf '%s' "$health" | sha256sum | awk '{print $1}')
binary_hash=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
config_hash=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
namespace=${commit}-1000000-0123456789abcdef
orchestration_hash=$(
    for file in \
        deploy/vaultlink-soak-control.sh \
        deploy/vaultlink-soak-remote.sh \
        tools/soak-monitor.sh \
        tools/load-test.sh \
        tools/collect-soak-evidence.sh \
        deploy/vaultlink-soak@.service; do
        sha256sum "$file" | awk '{print $1}'
    done | sha256sum | awk '{print $1}'
)
start=1000000
end=1259200
printf '%s\n' \
    'state=success' \
    'reason=passed' \
    "commit_sha=$commit" \
    "namespace=$namespace" \
    "binary_sha256=$binary_hash" \
    "orchestration_sha256=$orchestration_hash" \
    "config_sha256=$config_hash" \
    "health_sha256=$health_hash" \
    'architecture=amd64' \
    'os_id=debian' \
    'os_version_id=13' \
    'expected_version=0.6.0' \
    "start_epoch=$start" \
    "end_epoch=$end" \
    'duration_seconds=259200' \
    'load_interval_seconds=21600' \
    >"$active/result.env"
printf '%s\n' \
    "SOAK_COMMIT_SHA=$commit" \
    "SOAK_BINARY_SHA256=$binary_hash" \
    "SOAK_ORCHESTRATION_SHA256=$orchestration_hash" \
    "SOAK_NAMESPACE=$namespace" \
    "SOAK_START_EPOCH=$start" \
    "SOAK_DEADLINE_EPOCH=$end" \
    'SOAK_ARCHITECTURE=amd64' \
    'SOAK_OS_ID=debian' \
    'SOAK_OS_VERSION_ID=13' \
    'SOAK_SECONDS=259200' \
    'SOAK_INTERVAL_SECONDS=300' \
    'SOAK_LOAD_INTERVAL_SECONDS=21600' \
    'SOAK_EXPECTED_VERSION=0.6.0' \
    >"$active/unit.env"
printf '%s\n' \
    "commit=$commit" \
    "namespace=$namespace" \
    "binary_sha256=$binary_hash" \
    "orchestration_sha256=$orchestration_hash" \
    'architecture=amd64' \
    'os_id=debian' \
    'os_version_id=13' \
    "config_sha256=$config_hash" \
    'expected_version=0.6.0' \
    "health_sha256=$health_hash" \
    >"$active/candidate.env"
printf '%s\n' 'VaultLink soak fixture started normally' >"$active/vaultlink-journal.log"

printf 'epoch,timestamp,pid,rss_kib,restarts,health_sha256,config_sha256,integrity\n' \
    >"$active/metrics.csv"
sample=0
while [ "$sample" -le 864 ]; do
    epoch=$((start + (sample * 300)))
    rss=35000
    [ "$epoch" -le $((start + 5400)) ] || rss=45000
    [ "$epoch" -lt $((start + 172800)) ] || rss=45228
    [ "$epoch" -le $((start + 194400)) ] || rss=45876
    [ "$epoch" -lt $((end - 3600)) ] || rss=46336
    printf '%s,synthetic,1234,%s,0,%s,%s,ok\n' \
        "$epoch" "$rss" "$health_hash" "$config_hash" \
        >>"$active/metrics.csv"
    sample=$((sample + 1))
done
printf '%s\n' \
    'warm_rss_median_kib=35000' \
    'late_rss_median_kib=45228' \
    'final_rss_median_kib=46336' \
    'warm_rss_growth_limit_kib=51384' \
    'late_rss_growth_limit_kib=49324' \
    >>"$active/candidate.env"

run=1
while [ "$run" -le 12 ]; do
    load="$active/load-$run"
    mkdir "$load"
    request=1
    while [ "$request" -le 2000 ]; do
        client=$((((request - 1) / 20) + 1))
        printf '198.18.1.%s,200,0.100000\n' "$client" >>"$load/metadata-load.csv"
        request=$((request + 1))
    done
    stream=0
    while [ "$stream" -lt 40 ]; do
        printf '%s,198.18.2.%s,206,64,%s,bytes 0-63/128\n' \
            "$stream" "$((stream + 1))" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
            >>"$load/range-results.csv"
        stream=$((stream + 1))
    done
    upload=0
    while [ "$upload" -lt 10 ]; do
        printf '%s,198.18.3.%s,303,created,%s,200,%s,load-%s-%s-%s.bin\n' \
            "$upload" "$((upload + 1))" \
            bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
            bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
            "$namespace" "$run" "$upload" \
            >>"$load/upload-results.csv"
        upload=$((upload + 1))
    done
    printf '%s\n' \
        "run_id=$run" \
        "namespace=$namespace" \
        'identity_mode=trusted_proxy_xff' \
        'concurrency_barrier=passed' \
        'admission_same_identity_status=503' \
        'admission_distinct_identity_status=206' \
        'supervision_mode=systemd' \
        'metadata_p95_policy=strict' \
        'metadata_p95_limit_seconds=2.000' \
        'metadata_p95_within_limit=true' \
        'metadata_p95_enforced=true' \
        'metadata_p95_seconds=0.100000' \
        'metadata_clients=100' \
        'metadata_requests=2000' \
        'range_streams=40' \
        'range_bytes=64' \
        'fixture_bytes=128' \
        'range_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
        'uploads=10' \
        'upload_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
        'upload_integrity=server_readback' \
        'max_rss_kib=101000' \
        >"$load/result.env"
    printf '%s\n' \
        'metadata_status=0' \
        'download_status=0' \
        'upload_status=0' \
        'rss_status=0' \
        'metadata_rows=2000' \
        'range_rows=40' \
        'upload_rows=10' \
        'rss_rows=2' \
        'metadata_observed_p95_seconds=0.100000' \
        'supervision_mode=systemd' \
        'metadata_p95_policy=strict' \
        'metadata_p95_limit_seconds=2.000' \
        'metadata_p95_within_limit=true' \
        'metadata_p95_enforced=true' \
        >"$load/profile-status.env"
    printf '%s\n' \
        'stage=complete' \
        'exit_status=0' \
        >"$load/load-command.env"
    load_epoch=$((start + ((run - 1) * 21600)))
    printf '%s\n' \
        'epoch,pid,rss_kib' \
        "$load_epoch,1234,100000" \
        "$((load_epoch + 1)),1234,101000" \
        >"$load/rss-samples.csv"
    printf '%s\n' \
        "epoch=$load_epoch" \
        'pid=1234' \
        'process_starttime_ticks=5000' \
        'rss_kib=100000' \
        "binary_sha256=$binary_hash" \
        "health_sha256=$health_hash" \
        'integrity=ok' \
        'supervision_mode=systemd' \
        >"$load/pre-load.env"
    printf '%s\n' \
        "epoch=$((load_epoch + 1))" \
        'pid=1234' \
        'process_starttime_ticks=5000' \
        'rss_kib=101000' \
        "binary_sha256=$binary_hash" \
        "health_sha256=$health_hash" \
        'integrity=ok' \
        'supervision_mode=systemd' \
        >"$load/post-load.env"
    run=$((run + 1))
done

outputs="$work/outputs"
SOAK_STATE_ROOT="$state" GITHUB_OUTPUT="$outputs" \
    sh tools/collect-soak-evidence.sh "$destination"
grep -F -x -q 'state=success' "$outputs" || fail "collector did not report success"
grep -F -x -q "commit_sha=$commit" "$outputs" || fail "collector changed the commit"
sh tools/check-soak-evidence.sh "$commit" "$destination" >/dev/null
[ "$(stat -c '%a' "$active")" = 2750 ] \
    || fail "synthetic evidence directory lost its setgid group-readable mode"

latency_evidence="$work/latency-evidence"
cp -R "$destination" "$latency_evidence"
sed -i 's/,0\.100000$/,1.999999/' "$latency_evidence/load-1/metadata-load.csv"
sed -i 's/^metadata_p95_seconds=0\.100000$/metadata_p95_seconds=1.999999/' \
    "$latency_evidence/load-1/result.env"
sed -i 's/^metadata_observed_p95_seconds=0\.100000$/metadata_observed_p95_seconds=1.999999/' \
    "$latency_evidence/load-1/profile-status.env"
refresh_evidence_manifest "$latency_evidence"
sh tools/check-soak-evidence.sh "$commit" "$latency_evidence" >/dev/null \
    || fail "evidence verifier rejected metadata p95 below 2 seconds"
sed -i 's/,1\.999999$/,2.000000/' "$latency_evidence/load-1/metadata-load.csv"
sed -i 's/^metadata_p95_seconds=1\.999999$/metadata_p95_seconds=2.000000/' \
    "$latency_evidence/load-1/result.env"
sed -i 's/^metadata_observed_p95_seconds=1\.999999$/metadata_observed_p95_seconds=2.000000/' \
    "$latency_evidence/load-1/profile-status.env"
refresh_evidence_manifest "$latency_evidence"
if sh tools/check-soak-evidence.sh "$commit" "$latency_evidence" >/dev/null 2>&1; then
    fail "evidence verifier accepted metadata p95 at the strict 2-second boundary"
fi

diagnostic_evidence="$work/diagnostic-evidence"
cp -R "$destination" "$diagnostic_evidence"
sed -i 's/^metadata_p95_policy=strict$/metadata_p95_policy=diagnostic/' \
    "$diagnostic_evidence/load-1/result.env" \
    "$diagnostic_evidence/load-1/profile-status.env"
sed -i 's/^metadata_p95_enforced=true$/metadata_p95_enforced=false/' \
    "$diagnostic_evidence/load-1/result.env" \
    "$diagnostic_evidence/load-1/profile-status.env"
refresh_evidence_manifest "$diagnostic_evidence"
if sh tools/check-soak-evidence.sh "$commit" "$diagnostic_evidence" >/dev/null 2>&1; then
    fail "evidence verifier accepted diagnostic p95 policy for the release soak"
fi

direct_evidence="$work/direct-evidence"
cp -R "$destination" "$direct_evidence"
sed -i 's/^supervision_mode=systemd$/supervision_mode=direct_pid/' \
    "$direct_evidence/load-1/result.env" \
    "$direct_evidence/load-1/profile-status.env" \
    "$direct_evidence/load-1/pre-load.env" \
    "$direct_evidence/load-1/post-load.env"
refresh_evidence_manifest "$direct_evidence"
if sh tools/check-soak-evidence.sh "$commit" "$direct_evidence" >/dev/null 2>&1; then
    fail "evidence verifier accepted direct-PID supervision for the release soak"
fi

warm_boundary_evidence="$work/warm-boundary-evidence"
cp -R "$destination" "$warm_boundary_evidence"
rewrite_rss_evidence "$warm_boundary_evidence" 35000 51384 51384
sh tools/check-soak-evidence.sh "$commit" "$warm_boundary_evidence" >/dev/null \
    || fail "evidence verifier rejected the exact 16-MiB warm-growth boundary"
rewrite_rss_evidence "$warm_boundary_evidence" 35000 51385 51385
if sh tools/check-soak-evidence.sh "$commit" "$warm_boundary_evidence" >/dev/null 2>&1; then
    fail "evidence verifier accepted warm RSS growth one KiB beyond its allowance"
fi

late_boundary_evidence="$work/late-boundary-evidence"
cp -R "$destination" "$late_boundary_evidence"
rewrite_rss_evidence "$late_boundary_evidence" 35000 45000 49096
sh tools/check-soak-evidence.sh "$commit" "$late_boundary_evidence" >/dev/null \
    || fail "evidence verifier rejected the exact 4-MiB late-growth boundary"
rewrite_rss_evidence "$late_boundary_evidence" 35000 45000 49097
if sh tools/check-soak-evidence.sh "$commit" "$late_boundary_evidence" >/dev/null 2>&1; then
    fail "evidence verifier accepted late RSS growth one KiB beyond its allowance"
fi

echo "Synthetic soak evidence collection and verification passed"
