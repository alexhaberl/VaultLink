#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG

: "${VAULTLINK_BASE_URL:?set VAULTLINK_BASE_URL}"
: "${DOWNLOAD_TOKEN:?set DOWNLOAD_TOKEN}"
: "${UPLOAD_TOKEN:?set UPLOAD_TOKEN}"
: "${UPLOAD_VERIFY_TOKEN:?set UPLOAD_VERIFY_TOKEN for the same upload directory}"
: "${SOAK_NAMESPACE:?set SOAK_NAMESPACE from vaultlink-soak-control}"
: "${VAULTLINK_CONFIG:?set VAULTLINK_CONFIG}"
command -v curl >/dev/null

case "$SOAK_NAMESPACE" in
    *[!A-Za-z0-9._-]*|'') echo "SOAK_NAMESPACE contains unsafe characters" >&2; exit 64 ;;
esac
[ "${#SOAK_NAMESPACE}" -le 128 ] || { echo "SOAK_NAMESPACE is too long" >&2; exit 64; }
case "$VAULTLINK_BASE_URL" in
    http://127.0.0.1:[0-9]*) ;;
    *) echo "VAULTLINK_BASE_URL must be the direct local HTTP listener" >&2; exit 64 ;;
esac
base_port=${VAULTLINK_BASE_URL#http://127.0.0.1:}
case "$base_port" in *[!0-9]*|'') echo "VAULTLINK_BASE_URL must contain only a loopback port" >&2; exit 64 ;; esac
[ "$base_port" -le 65535 ] || { echo "VAULTLINK_BASE_URL port is invalid" >&2; exit 64; }
[ -r "$VAULTLINK_CONFIG" ] || { echo "VaultLink config is not readable" >&2; exit 66; }

toml_value() {
    section=$1
    key=$2
    awk -v wanted_section="$section" -v wanted_key="$key" '
        /^[[:space:]]*\[/ {
            current = $0
            sub(/^[[:space:]]*\[/, "", current)
            sub(/\][[:space:]]*(#.*)?$/, "", current)
            next
        }
        current == wanted_section && $0 ~ "^[[:space:]]*" wanted_key "[[:space:]]*=" {
            value = $0
            sub("^[[:space:]]*" wanted_key "[[:space:]]*=[[:space:]]*", "", value)
            sub(/[[:space:]]*(#.*)?$/, "", value)
            print value
            exit
        }
    ' "$VAULTLINK_CONFIG"
}

[ "$(toml_value server mode)" = '"reverse_proxy"' ] \
    || { echo "soak requires reverse_proxy mode on the local listener" >&2; exit 77; }
[ "$(toml_value reverse_proxy enabled)" = true ] \
    || { echo "soak requires reverse_proxy.enabled=true" >&2; exit 77; }
[ "$(toml_value reverse_proxy trust_x_forwarded_headers)" = true ] \
    || { echo "soak requires trusted forwarded client identities" >&2; exit 77; }
trusted_proxies=$(toml_value reverse_proxy trusted_proxies)
case "$trusted_proxies" in
    *'"127.0.0.1"'*) ;;
    *) echo "soak local peer is not an explicit trusted proxy" >&2; exit 77 ;;
esac

soak_curl() {
    identity=$1
    shift
    curl --interface 127.0.0.1 --header "X-Forwarded-For: $identity" "$@"
}

work=$(mktemp -d)
admission_holders=""
stop_admission_holders() {
    for holder_pid in $admission_holders; do
        kill "$holder_pid" 2>/dev/null || true
    done
    for holder_pid in $admission_holders; do
        wait "$holder_pid" 2>/dev/null || true
    done
    admission_holders=""
}
cleanup() {
    stop_admission_holders
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM
# Generate one fresh, non-sparse payload per profile. Reusing it for the ten
# parallel uploads keeps generation bounded while detecting zero/sparse damage.
dd if=/dev/urandom of="$work/upload.bin" bs=1M count=64 status=none
run_id=${LOAD_RUN_ID:-manual}
case "$run_id" in *[!A-Za-z0-9._-]*) echo "LOAD_RUN_ID contains unsafe characters" >&2; exit 64 ;; esac
range_bytes=${DOWNLOAD_RANGE_BYTES:-67108864}
fixture_bytes=${DOWNLOAD_FIXTURE_BYTES:-53687091200}
case "$range_bytes:$fixture_bytes" in *[!0-9:]*|:*|*::*) echo "download sizes must be decimal bytes" >&2; exit 64 ;; esac
if [ "$range_bytes" -le 0 ] || [ "$range_bytes" -gt "$fixture_bytes" ]; then
    echo "invalid download range size" >&2
    exit 64
fi
range_end=$((range_bytes - 1))
expected_content_range="bytes 0-$range_end/$fixture_bytes"
truncate -s "$range_bytes" "$work/expected-zero-range.bin"
expected_range_hash=$(sha256sum "$work/expected-zero-range.bin" | awk '{print $1}')
rm "$work/expected-zero-range.bin"
upload_hash=$(sha256sum "$work/upload.bin" | awk '{print $1}')

verify_forwarded_admission_identity() {
    identity=198.18.255.1
    # Keep the server-side bodies open. The previous 1 MiB range fit into
    # loopback TCP buffers, so VaultLink could release all admission permits
    # before the rate-limited clients had drained their responses.
    admission_range_end=1073741823
    [ "$fixture_bytes" -gt "$admission_range_end" ] || {
        echo "download fixture must be at least 1 GiB for the admission test" >&2
        return 1
    }
    holder=0
    while [ "$holder" -lt 16 ]; do
        curl --interface 127.0.0.1 --header "X-Forwarded-For: $identity" \
            --silent --show-error --max-time 30 \
            --limit-rate 1024 --range "0-$admission_range_end" \
            --dump-header "$work/admission-$holder.headers" --output /dev/null \
            "$VAULTLINK_BASE_URL/v/$DOWNLOAD_TOKEN/download" &
        admission_holders="$admission_holders $!"
        holder=$((holder + 1))
    done
    sleep 2
    for header in "$work"/admission-*.headers; do
        grep -E -q '^HTTP/[0-9.]+ 206([[:space:]]|$)' "$header" || {
            stop_admission_holders
            echo "could not saturate the forwarded stream admission key" >&2
            return 1
        }
    done
    same_status=$(soak_curl "$identity" --silent --show-error --max-time 5 \
        --range 0-0 --output /dev/null --write-out '%{http_code}' \
        "$VAULTLINK_BASE_URL/v/$DOWNLOAD_TOKEN/download")
    distinct_status=$(soak_curl 198.18.255.2 --silent --show-error --max-time 5 \
        --range 0-0 --output /dev/null --write-out '%{http_code}' \
        "$VAULTLINK_BASE_URL/v/$DOWNLOAD_TOKEN/download")
    stop_admission_holders
    [ "$same_status" = 503 ] || {
        echo "same forwarded identity bypassed the per-client stream limit (HTTP $same_status; expected 503)" >&2
        return 1
    }
    [ "$distinct_status" = 206 ] || {
        echo "distinct forwarded identity did not receive an independent admission key (HTTP $distinct_status; expected 206)" >&2
        return 1
    }
}

verify_forwarded_admission_identity

pid=$(systemctl show -p MainPID --value vaultlink.service 2>/dev/null || true)
rss_before=0
if [ -z "$pid" ] || ! [ "$pid" -gt 0 ] 2>/dev/null \
    || ! systemctl --quiet is-active vaultlink.service; then
    echo "load profile requires an active systemd-managed VaultLink process" >&2
    exit 69
fi
rss_before=$(awk '/VmRSS:/ { print $2 * 1024 }' "/proc/$pid/status")

load_snapshot() {
    destination=$1
    if [ -z "$pid" ] || ! [ "$pid" -gt 0 ] 2>/dev/null; then
        echo "soak load evidence requires an active VaultLink PID" >&2
        return 1
    fi
    systemctl --quiet is-active vaultlink.service
    current_pid=$(systemctl show -p MainPID --value vaultlink.service)
    [ "$current_pid" = "$pid" ] || return 1
    rss_kib=$(awk '/VmRSS:/ { print $2 }' "/proc/$current_pid/status")
    binary_sha256=$(sha256sum "/proc/$current_pid/exe" | awk '{print $1}')
    health_body="$work/snapshot-health.json"
    curl --fail --silent --show-error \
        "${VAULTLINK_HEALTH_URL:-http://127.0.0.1:8080/api/v2/health/ready}" \
        -o "$health_body"
    expected_health="{\"ok\":true,\"version\":\"${SOAK_EXPECTED_VERSION:-0.5.0}\"}"
    [ "$(cat "$health_body")" = "$expected_health" ] || return 1
    health_sha256=$(sha256sum "$health_body" | awk '{print $1}')
    integrity=$(sqlite3 "file:${VAULTLINK_DATABASE:-/var/lib/vaultlink/data.sqlite}?mode=ro" \
        'PRAGMA query_only=ON; PRAGMA integrity_check;')
    [ "$integrity" = ok ] || return 1
    printf '%s\n' \
        "epoch=$(date +%s)" \
        "pid=$current_pid" \
        "rss_kib=$rss_kib" \
        "binary_sha256=$binary_sha256" \
        "health_sha256=$health_sha256" \
        "integrity=$integrity" \
        >"$destination"
}

if [ -n "${LOAD_TEST_EVIDENCE_DIR:-}" ]; then
    mkdir -p "$LOAD_TEST_EVIDENCE_DIR"
    load_snapshot "$LOAD_TEST_EVIDENCE_DIR/pre-load.env"
fi

wait_for_profile_go() {
    attempts=0
    while [ ! -e "$work/profile-go" ]; do
        attempts=$((attempts + 1))
        [ "$attempts" -le 200 ] || return 1
        sleep 0.05
    done
}

metadata_profile() {
    metadata_pids=""
    client=0
    while [ "$client" -lt 100 ]; do
        (
            identity="198.18.1.$((client + 1))"
            wait_for_profile_go
            request=0
            while [ "$request" -lt 20 ]; do
                soak_curl "$identity" --silent --show-error \
                    --connect-timeout 5 --max-time 30 -o /dev/null \
                    -w "$identity,%{http_code},%{time_total}\n" \
                    "$VAULTLINK_BASE_URL/v/$DOWNLOAD_TOKEN"
                request=$((request + 1))
            done
        ) >"$work/metadata-$client.csv" &
        metadata_pids="$metadata_pids $!"
        client=$((client + 1))
    done
    : >"$work/metadata-ready"
    trap 'kill $metadata_pids 2>/dev/null || true' HUP INT TERM
    metadata_failed=0
    for wait_pid in $metadata_pids; do
        wait "$wait_pid" || metadata_failed=1
    done
    [ "$metadata_failed" -eq 0 ] || return 1
    cat "$work"/metadata-*.csv >"$work/metadata.csv"
    [ "$(wc -l <"$work/metadata.csv")" -eq 2000 ] || return 1
    awk -F, '
        $1 !~ /^198\.18\.1\.[0-9]+$/ || $2 !~ /^2[0-9][0-9]$/ { exit 1 }
        { if (!seen[$1]++) clients++ }
        END {
            if (clients != 100) exit 1
            for (client = 1; client <= 100; client++)
                if (seen["198.18.1." client] != 20) exit 1
        }
    ' "$work/metadata.csv" || return 1
    p95=$(awk -F, '{ print $3 }' "$work/metadata.csv" \
        | sort -n | awk 'NR == 1900 { print; exit }')
    [ -n "$p95" ] || return 1
    awk -v p95="$p95" 'BEGIN { exit !(p95 < 0.750) }' || return 1
    printf '%s\n' "$p95" >"$work/metadata.p95"
}

download_profile() {
    download_pids=""
    download=0
    while [ "$download" -lt 40 ]; do
        (
            identity="198.18.2.$((download + 1))"
            wait_for_profile_go
            headers="$work/range-$download.headers"
            body="$work/range-$download.bin"
            status=$(soak_curl "$identity" --silent --show-error \
                --connect-timeout 5 --max-time 300 \
                --range "0-$range_end" \
                --dump-header "$headers" \
                --output "$body" \
                --write-out '%{http_code}' \
                "$VAULTLINK_BASE_URL/v/$DOWNLOAD_TOKEN/download")
            size=$(stat -c '%s' "$body")
            hash=$(sha256sum "$body" | awk '{print $1}')
            content_range=$(awk '
                tolower($1) == "content-range:" {
                    sub(/^[^:]*:[[:space:]]*/, "")
                    sub(/\r$/, "")
                    print
                    exit
                }
            ' "$headers")
            printf '%s,%s,%s,%s,%s,%s\n' \
                "$download" "$identity" "$status" "$size" "$hash" "$content_range"
            [ "$status" = 206 ]
            [ "$size" -eq "$range_bytes" ]
            [ "$hash" = "$expected_range_hash" ]
            [ "$content_range" = "$expected_content_range" ]
        ) >"$work/range-$download.result" &
        download_pids="$download_pids $!"
        download=$((download + 1))
    done
    : >"$work/download-ready"
    trap 'kill $download_pids 2>/dev/null || true' HUP INT TERM
    download_failed=0
    for wait_pid in $download_pids; do
        wait "$wait_pid" || download_failed=1
    done
    cat "$work"/range-*.result >"$work/ranges.csv"
    [ "$download_failed" -eq 0 ] || return 1
    [ "$(wc -l <"$work/ranges.csv")" -eq 40 ] || return 1
}

upload_profile() {
    upload_pids=""
    upload=0
    while [ "$upload" -lt 10 ]; do
        (
            identity="198.18.3.$((upload + 1))"
            wait_for_profile_go
            headers="$work/upload-$upload.headers"
            filename="load-$SOAK_NAMESPACE-$run_id-$upload.bin"
            status=$(soak_curl "$identity" --silent --show-error \
                --connect-timeout 5 --max-time 300 \
                --form "file=@$work/upload.bin;filename=$filename" \
                --dump-header "$headers" \
                --output /dev/null \
                --write-out '%{http_code}' \
                "$VAULTLINK_BASE_URL/v/$UPLOAD_TOKEN/upload")
            outcome=$(awk '
                tolower($1) == "x-vaultlink-upload-outcome:" {
                    sub(/^[^:]*:[[:space:]]*/, "")
                    sub(/\r$/, "")
                    print
                    exit
                }
            ' "$headers")
            [ "$status" = 303 ]
            [ "$outcome" = created ]
            verify_body="$work/upload-$upload.readback"
            verify_status=$(soak_curl "$identity" --silent --show-error \
                --connect-timeout 5 --max-time 300 \
                --output "$verify_body" --write-out '%{http_code}' \
                "$VAULTLINK_BASE_URL/v/$UPLOAD_VERIFY_TOKEN/download?path=$filename")
            server_hash=$(sha256sum "$verify_body" | awk '{print $1}')
            printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
                "$upload" "$identity" "$status" "$outcome" "$upload_hash" \
                "$verify_status" "$server_hash" "$filename"
            [ "$verify_status" = 200 ]
            [ "$server_hash" = "$upload_hash" ]
        ) >"$work/upload-$upload.result" &
        upload_pids="$upload_pids $!"
        upload=$((upload + 1))
    done
    : >"$work/upload-ready"
    trap 'kill $upload_pids 2>/dev/null || true' HUP INT TERM
    upload_failed=0
    for wait_pid in $upload_pids; do
        wait "$wait_pid" || upload_failed=1
    done
    cat "$work"/upload-*.result >"$work/uploads.csv"
    [ "$upload_failed" -eq 0 ] || return 1
    [ "$(wc -l <"$work/uploads.csv")" -eq 10 ] || return 1
}

rss_profile() {
    marker=$1
    shift
    printf 'epoch,pid,rss_kib\n' >"$work/rss-samples.csv"
    while [ -e "$marker" ]; do
        current_pid=$(systemctl show -p MainPID --value vaultlink.service 2>/dev/null || true)
        if [ "$current_pid" != "$pid" ] || [ ! -r "/proc/$pid/status" ]; then
            printf '%s\n' pid_changed >"$work/rss-failure"
            kill "$@" 2>/dev/null || true
            return 1
        fi
        rss_kib=$(awk '/VmRSS:/ { print $2 }' "/proc/$pid/status")
        case "$rss_kib" in *[!0-9]*|'')
            printf '%s\n' rss_unavailable >"$work/rss-failure"
            kill "$@" 2>/dev/null || true
            return 1
            ;;
        esac
        printf '%s,%s,%s\n' "$(date +%s)" "$pid" "$rss_kib" >>"$work/rss-samples.csv"
        if [ "$rss_kib" -gt 262144 ]; then
            printf '%s\n' rss_exceeded_256_mib >"$work/rss-failure"
            kill "$@" 2>/dev/null || true
            return 1
        fi
        sleep 1
    done
}

# All three pressure profiles overlap: 100 metadata clients, 40 validated
# range streams, and ten uploads are active in the same load window.
load_marker="$work/load-active"
: >"$load_marker"
metadata_profile &
metadata_pid=$!
download_profile &
download_pid=$!
upload_profile &
upload_pid=$!
rss_profile "$load_marker" "$metadata_pid" "$download_pid" "$upload_pid" &
rss_pid=$!
ready_attempts=0
while [ ! -e "$work/metadata-ready" ] \
    || [ ! -e "$work/download-ready" ] \
    || [ ! -e "$work/upload-ready" ]; do
    ready_attempts=$((ready_attempts + 1))
    if [ "$ready_attempts" -gt 200 ]; then
        kill "$metadata_pid" "$download_pid" "$upload_pid" 2>/dev/null || true
        rm -f "$load_marker"
        wait "$rss_pid" 2>/dev/null || true
        echo "load workers did not reach the concurrency barrier" >&2
        exit 1
    fi
    sleep 0.05
done
: >"$work/profile-go"
profile_failed=0
wait "$metadata_pid" || profile_failed=1
wait "$download_pid" || profile_failed=1
wait "$upload_pid" || profile_failed=1
rm -f "$load_marker"
wait "$rss_pid" || profile_failed=1
[ ! -e "$work/rss-failure" ] \
    || { echo "RSS load gate failed: $(cat "$work/rss-failure")" >&2; profile_failed=1; }
[ "$profile_failed" -eq 0 ] || { echo "parallel load profile failed" >&2; exit 1; }
p95=$(cat "$work/metadata.p95")
max_rss_kib=$(awk -F, 'NR > 1 { if ($3 > maximum) maximum = $3 } END {
    if (NR <= 1) exit 1
    print maximum
}' "$work/rss-samples.csv")
[ "$max_rss_kib" -le 262144 ] || { echo "absolute RSS gate exceeded" >&2; exit 1; }

if [ -n "${LOAD_TEST_EVIDENCE_DIR:-}" ]; then
    load_snapshot "$LOAD_TEST_EVIDENCE_DIR/post-load.env"
fi

if [ -n "$pid" ] && [ "$pid" -gt 0 ] 2>/dev/null; then
    rss_after=$(awk '/VmRSS:/ { print $2 * 1024 }' "/proc/$pid/status")
    added=$((rss_after - rss_before))
    [ "$added" -le 268435456 ] || { echo "RSS gate exceeded: $added bytes" >&2; exit 1; }
    echo "additional RSS: $added bytes"
fi

if [ -n "${LOAD_TEST_EVIDENCE_DIR:-}" ]; then
    install -m 0640 "$work/metadata.csv" "$LOAD_TEST_EVIDENCE_DIR/metadata-load.csv"
    install -m 0640 "$work/ranges.csv" "$LOAD_TEST_EVIDENCE_DIR/range-results.csv"
    install -m 0640 "$work/uploads.csv" "$LOAD_TEST_EVIDENCE_DIR/upload-results.csv"
    install -m 0640 "$work/rss-samples.csv" "$LOAD_TEST_EVIDENCE_DIR/rss-samples.csv"
    printf '%s\n' \
        "run_id=$run_id" \
        "namespace=$SOAK_NAMESPACE" \
        'identity_mode=trusted_proxy_xff' \
        'concurrency_barrier=passed' \
        "admission_same_identity_status=$same_status" \
        "admission_distinct_identity_status=$distinct_status" \
        "metadata_p95_seconds=$p95" \
        'metadata_clients=100' \
        'metadata_requests=2000' \
        'range_streams=40' \
        "range_bytes=$range_bytes" \
        "fixture_bytes=$fixture_bytes" \
        "range_sha256=$expected_range_hash" \
        'uploads=10' \
        "upload_sha256=$upload_hash" \
        'upload_integrity=server_readback' \
        "max_rss_kib=$max_rss_kib" \
        >"$LOAD_TEST_EVIDENCE_DIR/result.env"
fi

echo "Parallel load profile passed; metadata p95: $p95 seconds; max RSS: $max_rss_kib KiB."
