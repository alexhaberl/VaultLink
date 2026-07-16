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

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
state="$work/state"
commit=0123456789abcdef0123456789abcdef01234567
active="$state/$commit"
destination="$work/collected"
mkdir -p "$active"
chmod 2750 "$state" "$active"
ln -s "$commit" "$state/active"

health='{"ok":true,"version":"0.5.0"}'
printf '%s' "$health" >"$active/health.json"
health_hash=$(printf '%s' "$health" | sha256sum | awk '{print $1}')
binary_hash=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
config_hash=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
namespace=${commit}-1000000-0123456789abcdef
orchestration_hash=$(
    for file in \
        deploy/vaultlink-soak-control.sh \
        tools/soak-monitor.sh \
        tools/load-test.sh \
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
    'expected_version=0.5.0' \
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
    'SOAK_EXPECTED_VERSION=0.5.0' \
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
    'expected_version=0.5.0' \
    "health_sha256=$health_hash" \
    >"$active/candidate.env"
printf '%s\n' 'VaultLink soak fixture started normally' >"$active/vaultlink-journal.log"

printf 'epoch,timestamp,pid,rss_kib,restarts,health_sha256,config_sha256,integrity\n' \
    >"$active/metrics.csv"
sample=0
while [ "$sample" -le 864 ]; do
    epoch=$((start + (sample * 300)))
    rss=100000
    [ "$epoch" -lt $((end - 3600)) ] || rss=110000
    printf '%s,synthetic,1234,%s,0,%s,%s,ok\n' \
        "$epoch" "$rss" "$health_hash" "$config_hash" \
        >>"$active/metrics.csv"
    sample=$((sample + 1))
done

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
    load_epoch=$((start + ((run - 1) * 21600)))
    printf '%s\n' \
        'epoch,pid,rss_kib' \
        "$load_epoch,1234,100000" \
        "$((load_epoch + 1)),1234,101000" \
        >"$load/rss-samples.csv"
    printf '%s\n' \
        "epoch=$load_epoch" \
        'pid=1234' \
        'rss_kib=100000' \
        "binary_sha256=$binary_hash" \
        "health_sha256=$health_hash" \
        'integrity=ok' \
        >"$load/pre-load.env"
    printf '%s\n' \
        "epoch=$((load_epoch + 1))" \
        'pid=1234' \
        'rss_kib=101000' \
        "binary_sha256=$binary_hash" \
        "health_sha256=$health_hash" \
        'integrity=ok' \
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

echo "Synthetic soak evidence collection and verification passed"
