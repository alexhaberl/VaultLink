#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG

state_root=${SOAK_STATE_ROOT:-/var/lib/vaultlink-soak}
destination=${1:-}
output_file=${GITHUB_OUTPUT:-/dev/stdout}

emit() {
    printf '%s=%s\n' "$1" "$2" >>"$output_file"
}

[ -d "$state_root" ] || { emit state idle; exit 0; }
state_root=$(realpath -e "$state_root")
[ -e "$state_root/active" ] || [ -L "$state_root/active" ] \
    || { emit state idle; exit 0; }
active=$(realpath -e "$state_root/active") || {
    echo "active soak state is a dangling link" >&2
    exit 1
}
case "$active" in "$state_root"/*) ;; *) echo "active soak escaped the state root" >&2; exit 1 ;; esac
commit=${active##*/}
case "$commit" in *[!0-9a-f]*|'') echo "active soak has an invalid commit" >&2; exit 1 ;; esac
[ "${#commit}" -eq 40 ] || { echo "active soak has an invalid commit" >&2; exit 1; }
emit commit_sha "$commit"

synthetic_reason=
if [ ! -s "$active/result.env" ]; then
    unit_env="$active/unit.env"
    [ -s "$unit_env" ] || { echo "active soak is missing unit.env" >&2; exit 1; }
    [ "$(stat -c '%u' "$unit_env")" -eq 0 ] \
        || { echo "unit.env is not root-owned" >&2; exit 1; }
    [ -z "$(find "$unit_env" -maxdepth 0 -perm /022 -print -quit)" ] \
        || { echo "unit.env is group- or world-writable" >&2; exit 1; }
    unit_value() {
        key=$1
        values=$(sed -n "s/^${key}=//p" "$unit_env")
        [ "$(printf '%s\n' "$values" | grep -c .)" -eq 1 ] \
            || { echo "unit.env must define $key exactly once" >&2; exit 1; }
        printf '%s\n' "$values"
    }
    unit_commit=$(unit_value SOAK_COMMIT_SHA)
    start_epoch=$(unit_value SOAK_START_EPOCH)
    deadline_epoch=$(unit_value SOAK_DEADLINE_EPOCH)
    binary_sha256=$(unit_value SOAK_BINARY_SHA256)
    orchestration_sha256=$(unit_value SOAK_ORCHESTRATION_SHA256)
    namespace=$(unit_value SOAK_NAMESPACE)
    evidence_dir=$(unit_value SOAK_EVIDENCE_DIR)
    architecture=$(unit_value SOAK_ARCHITECTURE)
    os_id=$(unit_value SOAK_OS_ID)
    os_version_id=$(unit_value SOAK_OS_VERSION_ID)
    [ "$unit_commit" = "$commit" ] || { echo "unit commit does not match active state" >&2; exit 1; }
    [ "$evidence_dir" = "$active" ] || { echo "unit evidence directory does not match active state" >&2; exit 1; }
    case "$start_epoch:$deadline_epoch" in
        *[!0-9:]*|:*|*::*) echo "unit start or deadline is invalid" >&2; exit 1 ;;
    esac
    [ "$deadline_epoch" -gt "$start_epoch" ] || { echo "unit deadline is invalid" >&2; exit 1; }
    [ $((deadline_epoch - start_epoch)) -eq 259200 ] \
        || { echo "unit duration is not exactly 72 hours" >&2; exit 1; }
    for hash in "$binary_sha256" "$orchestration_sha256"; do
        case "$hash" in *[!0-9a-f]*|'') echo "unit hash is invalid" >&2; exit 1 ;; esac
        [ "${#hash}" -eq 64 ] || { echo "unit hash is invalid" >&2; exit 1; }
    done
    case "$namespace" in *[!A-Za-z0-9._-]*|'') echo "unit namespace is invalid" >&2; exit 1 ;; esac
    if [ "$architecture" != amd64 ] || [ "$os_id" != debian ] || [ "$os_version_id" != 13 ]; then
        echo "unit platform is not Debian 13 amd64" >&2
        exit 1
    fi
    unit="vaultlink-soak@${commit}.service"
    load_state=$(systemctl show --property=LoadState --value "$unit" 2>/dev/null || true)
    if [ "$load_state" != loaded ]; then
        synthetic_reason=monitor_unit_unavailable
    elif systemctl --quiet is-failed "$unit"; then
        synthetic_reason=monitor_unit_failed
    elif ! systemctl --quiet is-active "$unit"; then
        synthetic_reason=monitor_unit_inactive
    elif [ "$(date +%s)" -gt $((deadline_epoch + 900)) ]; then
        synthetic_reason=monitor_deadline_exceeded
    else
        emit state pending
        exit 0
    fi
fi
[ -n "$destination" ] || { echo "collector destination is required for completed evidence" >&2; exit 64; }
[ ! -e "$destination" ] || { echo "collector destination must not already exist" >&2; exit 73; }
if find "$active" -mindepth 1 -type l -print -quit | grep -q .; then
    echo "soak evidence contains a symbolic link" >&2
    exit 1
fi
mkdir -p "$destination"
# The runner is intentionally not root. Preserve evidence bytes, modes and
# timestamps, but let the copied artifact be owned by the collecting account.
cp -a --no-preserve=ownership "$active/." "$destination/"
if [ ! -s "$destination/result.env" ]; then
    [ -n "$synthetic_reason" ] || { echo "soak result disappeared during collection" >&2; exit 1; }
    end_epoch=$(date +%s)
    duration_seconds=$((end_epoch - start_epoch))
    [ "$duration_seconds" -ge 0 ] || duration_seconds=0
    result_tmp="$destination/result.env.tmp.$$"
    printf '%s\n' \
        'state=failure' \
        "reason=$synthetic_reason" \
        "commit_sha=$commit" \
        "namespace=$namespace" \
        "binary_sha256=$binary_sha256" \
        "orchestration_sha256=$orchestration_sha256" \
        'config_sha256=unavailable' \
        'health_sha256=unavailable' \
        "architecture=$architecture" \
        "os_id=$os_id" \
        "os_version_id=$os_version_id" \
        'expected_version=0.6.0' \
        "start_epoch=$start_epoch" \
        "end_epoch=$end_epoch" \
        "duration_seconds=$duration_seconds" \
        'load_interval_seconds=21600' \
        "monitor_unit=$unit" \
        >"$result_tmp"
    chmod 0640 "$result_tmp"
    mv "$result_tmp" "$destination/result.env"
    printf '%s\n' \
        "state=failure" \
        "reason=$synthetic_reason" \
        "detected_epoch=$end_epoch" \
        "monitor_unit=$unit" \
        >"$destination/collector-failure.env"
fi
manifest_tmp=$(mktemp)
trap 'rm -f "$manifest_tmp"' EXIT HUP INT TERM
(
    cd "$destination"
    find . -type f ! -name SHA256SUMS -print0 \
        | sort -z \
        | xargs -0 sha256sum >"$manifest_tmp"
    mv "$manifest_tmp" SHA256SUMS
)
trap - EXIT HUP INT TERM
state=$(sed -n 's/^state=//p' "$destination/result.env")
[ "$state" = success ] || [ "$state" = failure ] \
    || { echo "completed soak result has an invalid state" >&2; exit 1; }
emit state "$state"
emit evidence_dir "$destination"
emit binary_sha256 "$(sed -n 's/^binary_sha256=//p' "$destination/result.env")"
emit duration_seconds "$(sed -n 's/^duration_seconds=//p' "$destination/result.env")"

echo "Collected soak evidence for $commit ($state)"
