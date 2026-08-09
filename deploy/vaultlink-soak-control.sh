#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG

state_root=${SOAK_STATE_ROOT:-/var/lib/vaultlink-soak}
runner_group=vaultlink-soak
unit_prefix=vaultlink-soak@

fail() {
    echo "soak control failed: $*" >&2
    exit 1
}

valid_commit() {
    value=$1
    [ "${#value}" -eq 40 ] || return 1
    case "$value" in *[!0-9a-f]*|'') return 1 ;; esac
}

valid_hash() {
    value=$1
    [ "${#value}" -eq 64 ] || return 1
    case "$value" in *[!0-9a-f]*|'') return 1 ;; esac
}

[ "$(id -u)" -eq 0 ] || { echo "soak control must run as root" >&2; exit 77; }
if [ "$#" -ne 4 ] || [ "$1" != start ]; then
    echo "usage: vaultlink-soak-control.sh start COMMIT_SHA BINARY_SHA256 ORCHESTRATION_SHA256" >&2
    exit 64
fi
commit=$2
expected_hash=$3
expected_orchestration_hash=$4
valid_commit "$commit" || { echo "invalid commit SHA" >&2; exit 64; }
valid_hash "$expected_hash" || { echo "invalid binary SHA-256" >&2; exit 64; }
valid_hash "$expected_orchestration_hash" || { echo "invalid orchestration SHA-256" >&2; exit 64; }
getent group "$runner_group" >/dev/null || fail "soak bridge group $runner_group does not exist"
[ "$(uname -m)" = x86_64 ] || fail "soak host must be x86_64"
[ -r /etc/os-release ] || fail "/etc/os-release is missing"
os_id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
os_version_id=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')
[ "$os_id" = debian ] || fail "soak host must run Debian"
[ "$os_version_id" = 13 ] || fail "soak host must run Debian 13"
[ -r /etc/vaultlink/soak.env ] || fail "/etc/vaultlink/soak.env is not provisioned"
[ "$(stat -c '%u' /etc/vaultlink/soak.env)" -eq 0 ] \
    || fail "soak.env must be owned by root"
[ -z "$(find /etc/vaultlink/soak.env -maxdepth 0 -perm /022 -print -quit)" ] \
    || fail "soak.env must not be group- or world-writable"

actual_orchestration_hash=$(
    for file in \
        /usr/local/sbin/vaultlink-soak-control \
        /usr/local/sbin/vaultlink-soak-remote \
        /usr/local/libexec/vaultlink/soak-monitor.sh \
        /usr/local/libexec/vaultlink/load-test.sh \
        /usr/local/libexec/vaultlink/collect-soak-evidence.sh \
        /etc/systemd/system/vaultlink-soak@.service; do
        [ -f "$file" ] || fail "installed orchestration file is missing: $file"
        [ "$(stat -c '%u' "$file")" -eq 0 ] \
            || fail "installed orchestration file is not root-owned: $file"
        [ -z "$(find "$file" -maxdepth 0 -perm /022 -print -quit)" ] \
            || fail "installed orchestration file is writable: $file"
        sha256sum "$file" | awk '{print $1}'
    done | sha256sum | awk '{print $1}'
)
[ "$actual_orchestration_hash" = "$expected_orchestration_hash" ] \
    || fail "installed monitor, load, unit, or control file differs from the approved commit"

systemctl --quiet is-active vaultlink.service || fail "vaultlink.service is not active"
pid=$(systemctl show -p MainPID --value vaultlink.service)
[ "$pid" -gt 0 ] || fail "vaultlink.service has no process"
actual_hash=$(sha256sum "/proc/$pid/exe" | awk '{print $1}')
[ "$actual_hash" = "$expected_hash" ] \
    || fail "running VaultLink binary does not match the approved hash"

install -d -o root -g "$runner_group" -m 2750 "$state_root"
if [ -e "$state_root/active" ] || [ -L "$state_root/active" ]; then
    active=$(realpath -e "$state_root/active" 2>/dev/null || true)
    if [ -n "$active" ] && [ -f "$active/result.env" ]; then
        fail "completed soak evidence is still active; archive it before a new run"
    fi
    fail "another soak is already active"
fi
evidence="$state_root/$commit"
[ ! -e "$evidence" ] || fail "state already exists for commit $commit"
install -d -o root -g "$runner_group" -m 2750 "$evidence"
start_epoch=$(date +%s)
deadline_epoch=$((start_epoch + 259200))
random_suffix=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
namespace="${commit}-${start_epoch}-${random_suffix}"
tmp="$evidence/unit.env.tmp.$$"
printf '%s\n' \
    "SOAK_COMMIT_SHA=$commit" \
    "SOAK_BINARY_SHA256=$expected_hash" \
    "SOAK_ORCHESTRATION_SHA256=$expected_orchestration_hash" \
    "SOAK_EVIDENCE_DIR=$evidence" \
    "SOAK_NAMESPACE=$namespace" \
    "SOAK_START_EPOCH=$start_epoch" \
    "SOAK_DEADLINE_EPOCH=$deadline_epoch" \
    'SOAK_ARCHITECTURE=amd64' \
    "SOAK_OS_ID=$os_id" \
    "SOAK_OS_VERSION_ID=$os_version_id" \
    'SOAK_SECONDS=259200' \
    'SOAK_INTERVAL_SECONDS=300' \
    'SOAK_LOAD_INTERVAL_SECONDS=21600' \
    'SOAK_EXPECTED_VERSION=0.5.0' \
    >"$tmp"
chmod 0640 "$tmp"
chown root:"$runner_group" "$tmp"
mv "$tmp" "$evidence/unit.env"
ln -s "$commit" "$state_root/active"

if ! systemctl start "${unit_prefix}${commit}.service"; then
    rm -f "$state_root/active"
    fail "systemd rejected the soak unit"
fi
echo "started 72-hour soak for $commit with binary $expected_hash and namespace $namespace"
