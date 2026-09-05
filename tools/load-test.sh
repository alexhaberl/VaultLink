#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG

: "${VAULTLINK_BASE_URL:?set VAULTLINK_BASE_URL}"
: "${DOWNLOAD_TOKEN:?set DOWNLOAD_TOKEN}"
: "${ADMISSION_DOWNLOAD_TOKEN:?set ADMISSION_DOWNLOAD_TOKEN for a second share of the download fixture}"
: "${RANGE_DOWNLOAD_TOKEN:?set RANGE_DOWNLOAD_TOKEN for a third share of the download fixture}"
: "${UPLOAD_TOKEN:?set UPLOAD_TOKEN}"
: "${UPLOAD_TOKEN_2:?set UPLOAD_TOKEN_2 for a second upload share}"
: "${UPLOAD_TOKEN_3:?set UPLOAD_TOKEN_3 for a third upload share}"
: "${UPLOAD_TOKEN_4:?set UPLOAD_TOKEN_4 for a fourth upload share}"
: "${UPLOAD_TOKEN_5:?set UPLOAD_TOKEN_5 for a fifth upload share}"
: "${UPLOAD_VERIFY_TOKEN:?set UPLOAD_VERIFY_TOKEN for the same upload directory}"
: "${SOAK_NAMESPACE:?set SOAK_NAMESPACE from vaultlink-soak-control}"
: "${VAULTLINK_CONFIG:?set VAULTLINK_CONFIG}"
command -v curl >/dev/null

validate_distinct_token_set() {
    token_set_name=$1
    shift
    for token_value in "$@"; do
        case "$token_value" in
            ''|*[!A-Za-z0-9._~-]*)
                echo "$token_set_name contains an invalid share token" >&2
                exit 64
                ;;
        esac
    done
    while [ "$#" -gt 1 ]; do
        token_value=$1
        shift
        for other_token_value in "$@"; do
            [ "$token_value" != "$other_token_value" ] || {
                echo "$token_set_name must contain distinct share tokens" >&2
                exit 64
            }
        done
    done
}

validate_distinct_token_set "download token set" \
    "$DOWNLOAD_TOKEN" "$ADMISSION_DOWNLOAD_TOKEN" "$RANGE_DOWNLOAD_TOKEN"
validate_distinct_token_set "upload token set" \
    "$UPLOAD_TOKEN" "$UPLOAD_TOKEN_2" "$UPLOAD_TOKEN_3" \
    "$UPLOAD_TOKEN_4" "$UPLOAD_TOKEN_5"

p95_limit=2.000
range_ttfb_p95_limit=2.000
metadata_capacity_retry_limit_per_client=3
metadata_capacity_retry_after_seconds=1
metadata_capacity_response_limit=1.100
p95_policy=${LOAD_P95_POLICY:-strict}
case "$p95_policy" in
    strict) p95_enforced=true ;;
    diagnostic) p95_enforced=false ;;
    *) echo "LOAD_P95_POLICY must be strict or diagnostic" >&2; exit 64 ;;
esac

validate_timeout() {
    timeout_name=$1
    timeout_value=$2
    timeout_max=$3
    case "$timeout_value" in
        *[!0-9]*|'')
            echo "$timeout_name must be a positive decimal integer" >&2
            exit 64
            ;;
    esac
    if [ "$timeout_value" -le 0 ] || [ "$timeout_value" -gt "$timeout_max" ]; then
        echo "$timeout_name is outside its allowed range" >&2
        exit 64
    fi
}

connect_timeout=${LOAD_CONNECT_TIMEOUT_SECONDS:-5}
metadata_max_time=${LOAD_METADATA_MAX_TIME_SECONDS:-30}
transfer_max_time=${LOAD_TRANSFER_MAX_TIME_SECONDS:-300}
profile_ready_timeout=${LOAD_PROFILE_READY_TIMEOUT_SECONDS:-10}
admission_ready_timeout=${LOAD_ADMISSION_READY_TIMEOUT_SECONDS:-10}
admission_holder_max_time=${LOAD_ADMISSION_HOLDER_MAX_TIME_SECONDS:-30}
admission_probe_max_time=${LOAD_ADMISSION_PROBE_MAX_TIME_SECONDS:-5}
validate_timeout LOAD_CONNECT_TIMEOUT_SECONDS "$connect_timeout" 300
validate_timeout LOAD_METADATA_MAX_TIME_SECONDS "$metadata_max_time" 3600
validate_timeout LOAD_TRANSFER_MAX_TIME_SECONDS "$transfer_max_time" 7200
validate_timeout LOAD_PROFILE_READY_TIMEOUT_SECONDS "$profile_ready_timeout" 900
validate_timeout LOAD_ADMISSION_READY_TIMEOUT_SECONDS "$admission_ready_timeout" 900
validate_timeout LOAD_ADMISSION_HOLDER_MAX_TIME_SECONDS "$admission_holder_max_time" 7200
validate_timeout LOAD_ADMISSION_PROBE_MAX_TIME_SECONDS "$admission_probe_max_time" 300
[ "$admission_holder_max_time" -gt "$admission_ready_timeout" ] || {
    echo "LOAD_ADMISSION_HOLDER_MAX_TIME_SECONDS must exceed the admission readiness timeout" >&2
    exit 64
}

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

supervision_mode=systemd
pid=
direct_process_uid=
direct_process_gid=
direct_binary_path=
direct_binary_sha256=
direct_process_starttime=
if [ -n "${VAULTLINK_PROCESS_PID:-}" ]; then
    supervision_mode=direct_pid
    pid=$VAULTLINK_PROCESS_PID
    : "${VAULTLINK_PROCESS_UID:?direct PID mode requires VAULTLINK_PROCESS_UID}"
    : "${VAULTLINK_PROCESS_GID:?direct PID mode requires VAULTLINK_PROCESS_GID}"
    : "${VAULTLINK_EXPECTED_BINARY_PATH:?direct PID mode requires VAULTLINK_EXPECTED_BINARY_PATH}"
    : "${VAULTLINK_EXPECTED_BINARY_SHA256:?direct PID mode requires VAULTLINK_EXPECTED_BINARY_SHA256}"
    direct_process_uid=$VAULTLINK_PROCESS_UID
    direct_process_gid=$VAULTLINK_PROCESS_GID
    direct_binary_path=$VAULTLINK_EXPECTED_BINARY_PATH
    direct_binary_sha256=$VAULTLINK_EXPECTED_BINARY_SHA256
    case "$pid" in *[!0-9]*|'') echo "direct PID must be a positive decimal integer" >&2; exit 64 ;; esac
    case "$direct_process_uid" in *[!0-9]*|'') echo "direct UID must be a positive decimal integer" >&2; exit 64 ;; esac
    case "$direct_process_gid" in *[!0-9]*|'') echo "direct GID must be a positive decimal integer" >&2; exit 64 ;; esac
    if [ "$pid" -le 1 ] || [ "$direct_process_uid" -le 0 ] \
        || [ "$direct_process_gid" -le 0 ]; then
        echo "direct PID mode received an invalid process identity" >&2
        exit 64
    fi
    case "$direct_binary_path" in
        /*) ;;
        *) echo "direct PID mode requires an absolute expected binary path" >&2; exit 64 ;;
    esac
    case "$direct_binary_sha256" in
        *[!0-9a-f]*|'')
            echo "direct PID mode requires a lowercase SHA-256 digest" >&2
            exit 64
            ;;
    esac
    [ "${#direct_binary_sha256}" -eq 64 ] || {
        echo "direct PID mode requires a 64-character SHA-256 digest" >&2
        exit 64
    }
    if [ ! -f "$direct_binary_path" ] || [ -L "$direct_binary_path" ] \
        || [ ! -x "$direct_binary_path" ]; then
        echo "direct PID mode expected binary is unsafe" >&2
        exit 66
    fi
    direct_identity_helper=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/check-direct-process-identity.sh
    if [ ! -f "$direct_identity_helper" ] || [ -L "$direct_identity_helper" ] \
        || [ ! -r "$direct_identity_helper" ]; then
        echo "direct PID identity helper is unavailable or unsafe" >&2
        exit 66
    fi
    command -v setpriv >/dev/null \
        || { echo "direct PID mode requires setpriv" >&2; exit 69; }
elif [ -n "${VAULTLINK_PROCESS_UID:-}${VAULTLINK_PROCESS_GID:-}${VAULTLINK_EXPECTED_BINARY_PATH:-}${VAULTLINK_EXPECTED_BINARY_SHA256:-}" ]; then
    echo "direct PID verification inputs require VAULTLINK_PROCESS_PID" >&2
    exit 64
fi

direct_pid_identity() {
    expected_starttime=$1
    setpriv --reuid="$direct_process_uid" --regid="$direct_process_gid" \
        --clear-groups --no-new-privs -- sh "$direct_identity_helper" \
        "$pid" "$direct_process_uid" "$direct_process_gid" \
        "$direct_binary_path" "$direct_binary_sha256" "$expected_starttime"
}

direct_pid_is_live() {
    kill -0 "$pid" 2>/dev/null || return 1
    [ -r "/proc/$pid/status" ] || return 1
    awk -v expected_uid="$direct_process_uid" \
        -v expected_gid="$direct_process_gid" '
        /^Uid:/ { uid_rows++; if ($2 != expected_uid) invalid = 1 }
        /^Gid:/ { gid_rows++; if ($2 != expected_gid) invalid = 1 }
        END { exit !(uid_rows == 1 && gid_rows == 1 && !invalid) }
    ' "/proc/$pid/status" || return 1
    observed_starttime=$(direct_pid_identity "$direct_process_starttime") \
        || return 1
    case "$observed_starttime" in *[!0-9]*|'') return 1 ;; esac
    if [ -n "$direct_process_starttime" ]; then
        [ "$observed_starttime" = "$direct_process_starttime" ] || return 1
    fi
}

load_current_pid() {
    if [ "$supervision_mode" = direct_pid ]; then
        direct_pid_is_live || return 1
        printf '%s\n' "$pid"
        return 0
    fi
    systemctl --quiet is-active vaultlink.service || return 1
    supervised_pid=$(systemctl show -p MainPID --value vaultlink.service 2>/dev/null || true)
    case "$supervised_pid" in *[!0-9]*|'') return 1 ;; esac
    [ "$supervised_pid" -gt 0 ] || return 1
    printf '%s\n' "$supervised_pid"
}

if [ "$supervision_mode" = direct_pid ]; then
    direct_process_starttime=$(direct_pid_identity '') || {
        echo "direct PID identity is unavailable" >&2
        exit 69
    }
    case "$direct_process_starttime" in
        *[!0-9]*|'') echo "direct PID start time is unavailable" >&2; exit 69 ;;
    esac
    direct_pid_is_live || {
        echo "direct PID mode requires the expected live VaultLink process" >&2
        exit 69
    }
    if [ "$(sha256sum "$direct_binary_path" | awk '{print $1}')" != \
        "$direct_binary_sha256" ]; then
        echo "direct PID mode binary integrity check failed" >&2
        exit 69
    fi
fi

soak_curl() {
    identity=$1
    shift
    curl --interface 127.0.0.1 --header "X-Forwarded-For: $identity" "$@"
}

work=$(mktemp -d)
load_stage=initialization
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
persist_load_evidence() {
    persist_status=$1
    [ -n "${LOAD_TEST_EVIDENCE_DIR:-}" ] || return 0
    mkdir -p "$LOAD_TEST_EVIDENCE_DIR" || return 1
    load_command_tmp="$LOAD_TEST_EVIDENCE_DIR/.load-command.env.$$"
    printf 'stage=%s\nexit_status=%s\n' "$load_stage" "$persist_status" \
        >"$load_command_tmp" || return 1
    chmod 0640 "$load_command_tmp" || return 1
    mv "$load_command_tmp" "$LOAD_TEST_EVIDENCE_DIR/load-command.env" || return 1
    [ "$persist_status" -ne 0 ] || return 0

    for partial_evidence in \
        'metadata.csv:metadata-load.partial.csv' \
        'metadata-capacity-retries.csv:metadata-capacity-retries.partial.csv' \
        'ranges.csv:range-results.partial.csv' \
        'uploads.csv:upload-results.partial.csv' \
        'rss-samples.csv:rss-samples.partial.csv' \
        'metadata.p95:metadata-p95.partial.txt' \
        'metadata.p95-within-limit:metadata-p95-within-limit.partial.txt' \
        'rss-failure:rss-failure.txt'; do
        partial_source=${partial_evidence%%:*}
        partial_destination=${partial_evidence#*:}
        if [ -f "$work/$partial_source" ] && [ ! -L "$work/$partial_source" ]; then
            install -m 0640 "$work/$partial_source" \
                "$LOAD_TEST_EVIDENCE_DIR/$partial_destination" || return 1
        fi
    done
}
cleanup() {
    load_exit_status=$?
    trap - EXIT HUP INT TERM
    set +e
    stop_admission_holders
    # Release the bounded but multi-gigabyte transient payloads before writing
    # small failure evidence. This also keeps diagnostics available if TMPDIR
    # itself reached its capacity during the parallel profile.
    rm -f "$work/upload.bin" "$work"/range-*.bin \
        "$work"/upload-*.readback "$work/snapshot-health.json"
    evidence_exit_status=0
    persist_load_evidence "$load_exit_status" || evidence_exit_status=$?
    rm -rf "$work"
    if [ "$load_exit_status" -eq 0 ] && [ "$evidence_exit_status" -ne 0 ]; then
        load_exit_status=$evidence_exit_status
    fi
    exit "$load_exit_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
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
        # Spread one client's 16 streams across two shares. A single share
        # would also exhaust max_streams_per_share=16 and make the distinct
        # client probe return a correct but ambiguous 503.
        if [ $((holder % 2)) -eq 0 ]; then
            holder_token=$DOWNLOAD_TOKEN
        else
            holder_token=$ADMISSION_DOWNLOAD_TOKEN
        fi
        curl --interface 127.0.0.1 --header "X-Forwarded-For: $identity" \
            --silent --show-error --max-time "$admission_holder_max_time" \
            --limit-rate 1024 --range "0-$admission_range_end" \
            --dump-header "$work/admission-$holder.headers" --output /dev/null \
            "$VAULTLINK_BASE_URL/v/$holder_token/download" &
        admission_holders="$admission_holders $!"
        holder=$((holder + 1))
    done
    admission_started=$(date +%s)
    while :; do
        ready_holders=0
        for header in "$work"/admission-*.headers; do
            if [ -f "$header" ] \
                && grep -E -q '^HTTP/[0-9.]+ 206([[:space:]]|$)' "$header"; then
                ready_holders=$((ready_holders + 1))
            fi
        done
        [ "$ready_holders" -eq 16 ] && break
        for holder_pid in $admission_holders; do
            kill -0 "$holder_pid" 2>/dev/null || {
                stop_admission_holders
                echo "an admission holder exited before saturation" >&2
                return 1
            }
        done
        admission_now=$(date +%s)
        if [ $((admission_now - admission_started)) -ge "$admission_ready_timeout" ]; then
            stop_admission_holders
            echo "could not saturate the forwarded stream admission key" >&2
            return 1
        fi
        sleep 1
    done
    for holder_pid in $admission_holders; do
        kill -0 "$holder_pid" 2>/dev/null || {
            stop_admission_holders
            echo "an admission holder exited before the admission probes" >&2
            return 1
        }
    done
    same_status=$(soak_curl "$identity" --silent --show-error \
        --max-time "$admission_probe_max_time" \
        --range 0-0 --output /dev/null --write-out '%{http_code}' \
        "$VAULTLINK_BASE_URL/v/$DOWNLOAD_TOKEN/download")
    distinct_status=$(soak_curl 198.18.255.2 --silent --show-error \
        --max-time "$admission_probe_max_time" \
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

load_stage=admission-identity
verify_forwarded_admission_identity

rss_before=0
current_pid=$(load_current_pid 2>/dev/null || true)
if [ -z "$current_pid" ]; then
    echo "load profile requires the expected active VaultLink process" >&2
    exit 69
fi
if [ -n "$pid" ] && [ "$current_pid" != "$pid" ]; then
    echo "load profile observed an unexpected VaultLink PID" >&2
    exit 69
fi
pid=$current_pid
rss_before=$(awk '/VmRSS:/ { print $2 * 1024 }' "/proc/$pid/status")

load_snapshot() {
    destination=$1
    if [ -z "$pid" ] || ! [ "$pid" -gt 0 ] 2>/dev/null; then
        echo "soak load evidence requires an active VaultLink PID" >&2
        return 1
    fi
    current_pid=$(load_current_pid)
    [ "$current_pid" = "$pid" ] || return 1
    process_starttime=$(sed 's/^[^)]*) //' "/proc/$current_pid/stat" \
        | awk '{ print $20; exit }')
    case "$process_starttime" in *[!0-9]*|'') return 1 ;; esac
    if [ "$supervision_mode" = direct_pid ]; then
        [ "$process_starttime" = "$direct_process_starttime" ] || return 1
    fi
    rss_kib=$(awk '/VmRSS:/ { print $2 }' "/proc/$current_pid/status")
    if [ "$supervision_mode" = direct_pid ]; then
        binary_sha256=$direct_binary_sha256
        [ "$(sha256sum "$direct_binary_path" | awk '{print $1}')" = \
            "$direct_binary_sha256" ] || return 1
    else
        binary_sha256=$(sha256sum "/proc/$current_pid/exe" | awk '{print $1}')
    fi
    health_body="$work/snapshot-health.json"
    curl --fail --silent --show-error \
        "${VAULTLINK_HEALTH_URL:-http://127.0.0.1:8080/api/v2/health/ready}" \
        -o "$health_body"
    expected_health="{\"ok\":true,\"version\":\"${SOAK_EXPECTED_VERSION:-0.7.0}\"}"
    [ "$(cat "$health_body")" = "$expected_health" ] || return 1
    health_sha256=$(sha256sum "$health_body" | awk '{print $1}')
    integrity=$(sqlite3 "file:${VAULTLINK_DATABASE:-/var/lib/vaultlink/data.sqlite}?mode=ro" \
        'PRAGMA query_only=ON; PRAGMA integrity_check;')
    [ "$integrity" = ok ] || return 1
    printf '%s\n' \
        "epoch=$(date +%s)" \
        "supervision_mode=$supervision_mode" \
        "pid=$current_pid" \
        "process_starttime_ticks=$process_starttime" \
        "rss_kib=$rss_kib" \
        "binary_sha256=$binary_sha256" \
        "health_sha256=$health_sha256" \
        "integrity=$integrity" \
        >"$destination"
}

load_stage=pre-load-snapshot
if [ -n "${LOAD_TEST_EVIDENCE_DIR:-}" ]; then
    mkdir -p "$LOAD_TEST_EVIDENCE_DIR"
    load_snapshot "$LOAD_TEST_EVIDENCE_DIR/pre-load.env"
fi

wait_for_profile_go() {
    attempts=0
    max_attempts=$((profile_ready_timeout * 20))
    while [ ! -e "$work/profile-go" ]; do
        attempts=$((attempts + 1))
        [ "$attempts" -le "$max_attempts" ] || return 1
        sleep 0.05
    done
}

metadata_profile() {
    metadata_pids=""
    client=0
    while [ "$client" -lt 100 ]; do
        (
            identity="198.18.1.$((client + 1))"
            capacity_evidence="$work/capacity-retry-client-$client.csv"
            headers="$work/metadata-$client.headers"
            : >"$capacity_evidence"
            wait_for_profile_go
            request=0
            capacity_retries=0
            while [ "$request" -lt 20 ]; do
                while :; do
                    metrics=$(soak_curl "$identity" --silent --show-error \
                        --connect-timeout "$connect_timeout" \
                        --max-time "$metadata_max_time" -o /dev/null \
                        --dump-header "$headers" \
                        -w '%{http_code},%{time_total}' \
                        "$VAULTLINK_BASE_URL/v/$DOWNLOAD_TOKEN")
                    status=${metrics%%,*}
                    duration=${metrics#*,}
                    case "$status" in
                        2??)
                            printf '%s,%s,%s\n' "$identity" "$status" "$duration"
                            break
                            ;;
                        503)
                            retry_after=$(awk '
                                { sub(/\r$/, "") }
                                tolower($1) == "retry-after:" {
                                    values++
                                    value = $2
                                    if (NF != 2) invalid = 1
                                }
                                END {
                                    if (values != 1 || invalid) exit 1
                                    print value
                                }
                            ' "$headers")
                            [ "$retry_after" = "$metadata_capacity_retry_after_seconds" ] \
                                || exit 1
                            awk -v value="$duration" \
                                -v limit="$metadata_capacity_response_limit" 'BEGIN {
                                    exit !(value ~ /^[0-9]+([.][0-9]+)?$/ \
                                        && value + 0 > 0 && value + 0 <= limit)
                                }' || exit 1
                            capacity_retries=$((capacity_retries + 1))
                            printf '%s,%s,%s,%s,%s,%s\n' \
                                "$identity" "$((request + 1))" "$capacity_retries" \
                                "$status" "$duration" "$retry_after" \
                                >>"$capacity_evidence"
                            [ "$capacity_retries" \
                                -le "$metadata_capacity_retry_limit_per_client" ] \
                                || exit 1
                            sleep "$retry_after"
                            ;;
                        *) exit 1 ;;
                    esac
                done
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
    # Aggregate every completed client result before returning a profile
    # failure so the EXIT evidence retains the available partial measurements.
    cat "$work"/metadata-*.csv >"$work/metadata.csv"
    cat "$work"/capacity-retry-client-*.csv >"$work/metadata-capacity-retries.csv"
    [ "$metadata_failed" -eq 0 ] || return 1
    [ "$(wc -l <"$work/metadata.csv")" -eq 2000 ] || return 1
    awk -F, '
        $1 !~ /^198\.18\.1\.[0-9]+$/ || $2 !~ /^2[0-9][0-9]$/ \
            || $3 !~ /^[0-9]+([.][0-9]+)?$/ || $3 + 0 <= 0 { exit 1 }
        { if (!seen[$1]++) clients++ }
        END {
            if (clients != 100) exit 1
            for (client = 1; client <= 100; client++)
                if (seen["198.18.1." client] != 20) exit 1
        }
    ' "$work/metadata.csv" || return 1
    awk -F, -v retry_limit="$metadata_capacity_retry_limit_per_client" \
        -v duration_limit="$metadata_capacity_response_limit" \
        -v retry_after="$metadata_capacity_retry_after_seconds" '
        NF != 6 || $1 !~ /^198\.18\.1\.[0-9]+$/ \
            || $2 !~ /^([1-9]|1[0-9]|20)$/ \
            || $3 !~ /^[1-9][0-9]*$/ || $3 > retry_limit || $4 != 503 \
            || $5 !~ /^[0-9]+([.][0-9]+)?$/ || $5 + 0 <= 0 \
            || $5 + 0 > duration_limit || $6 != retry_after { exit 1 }
        {
            split($1, octets, ".")
            if (octets[4] < 1 || octets[4] > 100) exit 1
            if ($3 != ++retries[$1]) exit 1
        }
    ' "$work/metadata-capacity-retries.csv" || return 1
    p95=$(awk -F, '{ print $3 }' "$work/metadata.csv" \
        | sort -n | awk 'NR == 1900 { print; exit }')
    [ -n "$p95" ] || return 1
    awk -v value="$p95" 'BEGIN {
        exit !(value ~ /^[0-9]+([.][0-9]+)?$/ && value + 0 > 0)
    }' || return 1
    printf '%s\n' "$p95" >"$work/metadata.p95"
    p95_within_limit=false
    if awk -v p95="$p95" -v limit="$p95_limit" \
        'BEGIN { exit !(p95 < limit) }'; then
        p95_within_limit=true
    fi
    printf '%s\n' "$p95_within_limit" >"$work/metadata.p95-within-limit"
}

download_profile() {
    download_pids=""
    download=0
    while [ "$download" -lt 40 ]; do
        (
            identity="198.18.2.$((download + 1))"
            case $((download % 3)) in
                0) download_token=$DOWNLOAD_TOKEN ;;
                1) download_token=$ADMISSION_DOWNLOAD_TOKEN ;;
                2) download_token=$RANGE_DOWNLOAD_TOKEN ;;
            esac
            wait_for_profile_go
            headers="$work/range-$download.headers"
            body="$work/range-$download.bin"
            metrics=$(soak_curl "$identity" --silent --show-error \
                --connect-timeout "$connect_timeout" \
                --max-time "$transfer_max_time" \
                --range "0-$range_end" \
                --dump-header "$headers" \
                --output "$body" \
                --write-out '%{http_code},%{time_starttransfer},%{speed_download},%{time_total}' \
                "$VAULTLINK_BASE_URL/v/$download_token/download")
            status=${metrics%%,*}
            remaining_metrics=${metrics#*,}
            time_starttransfer=${remaining_metrics%%,*}
            remaining_metrics=${remaining_metrics#*,}
            speed_download=${remaining_metrics%%,*}
            time_total=${remaining_metrics#*,}
            [ "$metrics" != "$remaining_metrics" ]
            case "$time_total" in *,*) exit 1 ;; esac
            awk -v ttfb="$time_starttransfer" -v speed="$speed_download" \
                -v duration="$time_total" 'BEGIN {
                    numeric = "^[0-9]+([.][0-9]+)?$"
                    numeric_values = ttfb ~ numeric && speed ~ numeric && duration ~ numeric
                    positive_values = ttfb + 0 >= 0 && speed + 0 > 0 && duration + 0 > 0
                    exit !(numeric_values && positive_values)
                }'
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
            # Keep the established first six columns byte-compatible for older
            # evidence readers; append performance measurements only.
            printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
                "$download" "$identity" "$status" "$size" "$hash" "$content_range" \
                "$time_starttransfer" "$speed_download" "$time_total"
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
    range_ttfb_p95=$(awk -F, '{ print $7 }' "$work/ranges.csv" \
        | sort -n | awk 'NR == 38 { print; exit }')
    range_throughput_median=$(awk -F, '{ print $8 }' "$work/ranges.csv" \
        | sort -n | awk 'NR == 20 { lower = $1 } NR == 21 { print (lower + $1) / 2; exit }')
    range_duration_p95=$(awk -F, '{ print $9 }' "$work/ranges.csv" \
        | sort -n | awk 'NR == 38 { print; exit }')
    [ -n "$range_ttfb_p95" ] && [ -n "$range_throughput_median" ] \
        && [ -n "$range_duration_p95" ] || return 1
    printf '%s\n' "$range_ttfb_p95" >"$work/range-ttfb.p95"
    printf '%s\n' "$range_throughput_median" >"$work/range-throughput.median"
    printf '%s\n' "$range_duration_p95" >"$work/range-duration.p95"
    range_ttfb_within_limit=false
    if awk -v p95="$range_ttfb_p95" -v limit="$range_ttfb_p95_limit" \
        'BEGIN { exit !(p95 < limit) }'; then
        range_ttfb_within_limit=true
    fi
    printf '%s\n' "$range_ttfb_within_limit" >"$work/range-ttfb.p95-within-limit"
}

upload_profile() {
    upload_pids=""
    upload=0
    while [ "$upload" -lt 10 ]; do
        (
            identity="198.18.3.$((upload + 1))"
            case $((upload % 5)) in
                0) upload_token=$UPLOAD_TOKEN ;;
                1) upload_token=$UPLOAD_TOKEN_2 ;;
                2) upload_token=$UPLOAD_TOKEN_3 ;;
                3) upload_token=$UPLOAD_TOKEN_4 ;;
                4) upload_token=$UPLOAD_TOKEN_5 ;;
            esac
            wait_for_profile_go
            headers="$work/upload-$upload.headers"
            filename="load-$SOAK_NAMESPACE-$run_id-$upload.bin"
            status=$(soak_curl "$identity" --silent --show-error \
                --connect-timeout "$connect_timeout" \
                --max-time "$transfer_max_time" \
                --form "file=@$work/upload.bin;filename=$filename" \
                --dump-header "$headers" \
                --output /dev/null \
                --write-out '%{http_code}' \
                "$VAULTLINK_BASE_URL/v/$upload_token/upload")
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
                --connect-timeout "$connect_timeout" \
                --max-time "$transfer_max_time" \
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
        current_pid=$(load_current_pid 2>/dev/null || true)
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
load_stage=parallel-profiles
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
ready_max_attempts=$((profile_ready_timeout * 20))
while [ ! -e "$work/metadata-ready" ] \
    || [ ! -e "$work/download-ready" ] \
    || [ ! -e "$work/upload-ready" ]; do
    ready_attempts=$((ready_attempts + 1))
    if [ "$ready_attempts" -gt "$ready_max_attempts" ]; then
        kill "$metadata_pid" "$download_pid" "$upload_pid" 2>/dev/null || true
        rm -f "$load_marker"
        wait "$rss_pid" 2>/dev/null || true
        echo "load workers did not reach the concurrency barrier" >&2
        exit 1
    fi
    sleep 0.05
done
: >"$work/profile-go"
metadata_status=0
download_status=0
upload_status=0
rss_status=0
wait "$metadata_pid" || metadata_status=$?
wait "$download_pid" || download_status=$?
wait "$upload_pid" || upload_status=$?
rm -f "$load_marker"
wait "$rss_pid" || rss_status=$?
profile_failed=0
for profile_status in \
    "$metadata_status" "$download_status" "$upload_status" "$rss_status"; do
    [ "$profile_status" -eq 0 ] || profile_failed=1
done
[ ! -e "$work/rss-failure" ] \
    || { echo "RSS load gate failed: $(cat "$work/rss-failure")" >&2; profile_failed=1; }
if [ -n "${LOAD_TEST_EVIDENCE_DIR:-}" ]; then
    metadata_rows=0
    range_rows=0
    upload_rows=0
    rss_rows=0
    metadata_capacity_retries=0
    [ ! -f "$work/metadata.csv" ] || metadata_rows=$(wc -l <"$work/metadata.csv")
    [ ! -f "$work/ranges.csv" ] || range_rows=$(wc -l <"$work/ranges.csv")
    [ ! -f "$work/uploads.csv" ] || upload_rows=$(wc -l <"$work/uploads.csv")
    [ ! -f "$work/rss-samples.csv" ] || rss_rows=$(wc -l <"$work/rss-samples.csv")
    [ ! -f "$work/metadata-capacity-retries.csv" ] \
        || metadata_capacity_retries=$(wc -l <"$work/metadata-capacity-retries.csv")
    metadata_attempts=$((metadata_rows + metadata_capacity_retries))
    observed_p95=unavailable
    observed_p95_within_limit=unavailable
    observed_range_ttfb_p95=unavailable
    observed_range_ttfb_within_limit=unavailable
    observed_range_throughput_median=unavailable
    observed_range_duration_p95=unavailable
    if [ -s "$work/metadata.csv" ]; then
        observed_p95=$(awk -F, '{ print $3 }' "$work/metadata.csv" \
            | sort -n | awk 'NR == 1900 { print; exit }')
        [ -n "$observed_p95" ] || observed_p95=unavailable
    fi
    if [ -s "$work/metadata.p95-within-limit" ]; then
        observed_p95_within_limit=$(cat "$work/metadata.p95-within-limit")
    fi
    if [ -s "$work/range-ttfb.p95" ]; then
        observed_range_ttfb_p95=$(cat "$work/range-ttfb.p95")
    fi
    if [ -s "$work/range-ttfb.p95-within-limit" ]; then
        observed_range_ttfb_within_limit=$(cat "$work/range-ttfb.p95-within-limit")
    fi
    if [ -s "$work/range-throughput.median" ]; then
        observed_range_throughput_median=$(cat "$work/range-throughput.median")
    fi
    if [ -s "$work/range-duration.p95" ]; then
        observed_range_duration_p95=$(cat "$work/range-duration.p95")
    fi
    profile_status_tmp="$LOAD_TEST_EVIDENCE_DIR/.profile-status.env.$$"
    printf '%s\n' \
        "supervision_mode=$supervision_mode" \
        "metadata_status=$metadata_status" \
        "download_status=$download_status" \
        "upload_status=$upload_status" \
        "rss_status=$rss_status" \
        "metadata_rows=$metadata_rows" \
        "metadata_attempts=$metadata_attempts" \
        "metadata_capacity_retries=$metadata_capacity_retries" \
        "range_rows=$range_rows" \
        "upload_rows=$upload_rows" \
        "rss_rows=$rss_rows" \
        "metadata_observed_p95_seconds=$observed_p95" \
        "metadata_p95_policy=$p95_policy" \
        "metadata_p95_limit_seconds=$p95_limit" \
        "metadata_p95_within_limit=$observed_p95_within_limit" \
        "metadata_p95_enforced=$p95_enforced" \
        "range_ttfb_observed_p95_seconds=$observed_range_ttfb_p95" \
        "range_ttfb_p95_limit_seconds=$range_ttfb_p95_limit" \
        "range_ttfb_p95_within_limit=$observed_range_ttfb_within_limit" \
        "range_ttfb_p95_enforced=$p95_enforced" \
        "range_throughput_median_bytes_per_second=$observed_range_throughput_median" \
        "range_duration_observed_p95_seconds=$observed_range_duration_p95" \
        >"$profile_status_tmp"
    chmod 0640 "$profile_status_tmp"
    mv "$profile_status_tmp" "$LOAD_TEST_EVIDENCE_DIR/profile-status.env"
fi
[ "$profile_failed" -eq 0 ] || { echo "parallel load profile failed" >&2; exit 1; }
p95=$(cat "$work/metadata.p95")
p95_within_limit=$(cat "$work/metadata.p95-within-limit")
range_ttfb_p95=$(cat "$work/range-ttfb.p95")
range_ttfb_within_limit=$(cat "$work/range-ttfb.p95-within-limit")
range_throughput_median=$(cat "$work/range-throughput.median")
range_duration_p95=$(cat "$work/range-duration.p95")
max_rss_kib=$(awk -F, 'NR > 1 { if ($3 > maximum) maximum = $3 } END {
    if (NR <= 1) exit 1
    print maximum
}' "$work/rss-samples.csv")
[ "$max_rss_kib" -le 262144 ] || { echo "absolute RSS gate exceeded" >&2; exit 1; }

load_stage=post-load-snapshot
if [ -n "${LOAD_TEST_EVIDENCE_DIR:-}" ]; then
    load_snapshot "$LOAD_TEST_EVIDENCE_DIR/post-load.env"
fi

if [ -n "$pid" ] && [ "$pid" -gt 0 ] 2>/dev/null; then
    rss_after=$(awk '/VmRSS:/ { print $2 * 1024 }' "/proc/$pid/status")
    added=$((rss_after - rss_before))
    [ "$added" -le 268435456 ] || { echo "RSS gate exceeded: $added bytes" >&2; exit 1; }
    echo "additional RSS: $added bytes"
fi

load_stage=evidence-finalization
if [ -n "${LOAD_TEST_EVIDENCE_DIR:-}" ]; then
    install -m 0640 "$work/metadata.csv" "$LOAD_TEST_EVIDENCE_DIR/metadata-load.csv"
    install -m 0640 "$work/metadata-capacity-retries.csv" \
        "$LOAD_TEST_EVIDENCE_DIR/metadata-capacity-retries.csv"
    install -m 0640 "$work/ranges.csv" "$LOAD_TEST_EVIDENCE_DIR/range-results.csv"
    install -m 0640 "$work/uploads.csv" "$LOAD_TEST_EVIDENCE_DIR/upload-results.csv"
    install -m 0640 "$work/rss-samples.csv" "$LOAD_TEST_EVIDENCE_DIR/rss-samples.csv"
    printf '%s\n' \
        "run_id=$run_id" \
        "namespace=$SOAK_NAMESPACE" \
        "supervision_mode=$supervision_mode" \
        'identity_mode=trusted_proxy_xff' \
        'concurrency_barrier=passed' \
        "admission_same_identity_status=$same_status" \
        "admission_distinct_identity_status=$distinct_status" \
        "metadata_p95_seconds=$p95" \
        "metadata_p95_policy=$p95_policy" \
        "metadata_p95_limit_seconds=$p95_limit" \
        "metadata_p95_within_limit=$p95_within_limit" \
        "metadata_p95_enforced=$p95_enforced" \
        "range_ttfb_p95_seconds=$range_ttfb_p95" \
        "range_ttfb_p95_limit_seconds=$range_ttfb_p95_limit" \
        "range_ttfb_p95_within_limit=$range_ttfb_within_limit" \
        "range_ttfb_p95_enforced=$p95_enforced" \
        "range_throughput_median_bytes_per_second=$range_throughput_median" \
        "range_duration_p95_seconds=$range_duration_p95" \
        'metadata_clients=100' \
        'metadata_requests=2000' \
        "metadata_attempts=$metadata_attempts" \
        "metadata_capacity_retries=$metadata_capacity_retries" \
        "metadata_capacity_retry_limit_per_client=$metadata_capacity_retry_limit_per_client" \
        "metadata_capacity_retry_after_seconds=$metadata_capacity_retry_after_seconds" \
        "metadata_capacity_response_limit_seconds=$metadata_capacity_response_limit" \
        'range_streams=40' \
        'range_share_count=3' \
        'range_streams_per_share_max=14' \
        "range_bytes=$range_bytes" \
        "fixture_bytes=$fixture_bytes" \
        "range_sha256=$expected_range_hash" \
        'uploads=10' \
        'upload_share_count=5' \
        'uploads_per_share=2' \
        "upload_sha256=$upload_hash" \
        'upload_integrity=server_readback' \
        "max_rss_kib=$max_rss_kib" \
        >"$LOAD_TEST_EVIDENCE_DIR/result.env"
fi

load_stage=performance-gate
if [ "$p95_enforced" = true ] && [ "$p95_within_limit" != true ]; then
    echo "metadata p95 gate failed: $p95 seconds is not below $p95_limit seconds" >&2
    exit 1
fi
if [ "$p95_enforced" = true ] && [ "$range_ttfb_within_limit" != true ]; then
    echo "range TTFB p95 gate failed: $range_ttfb_p95 seconds is not below $range_ttfb_p95_limit seconds" >&2
    exit 1
fi

echo "Parallel load profile passed; metadata p95: $p95 seconds; range TTFB p95: $range_ttfb_p95 seconds; range throughput median: $range_throughput_median bytes/s; range duration p95: $range_duration_p95 seconds; max RSS: $max_rss_kib KiB."
load_stage=complete
