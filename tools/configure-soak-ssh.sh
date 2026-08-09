#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG
umask 077

fail() {
    echo "soak SSH configuration failed: $*" >&2
    exit 1
}

host=${SOAK_SSH_HOST:-}
port=${SOAK_SSH_PORT:-22}
user=${SOAK_SSH_USER:-}
private_key=${SOAK_SSH_PRIVATE_KEY:-}
host_keys=${SOAK_SSH_HOST_KEYS:-}
runner_temp=${RUNNER_TEMP:-}
output_file=${GITHUB_OUTPUT:-}

[ -n "$runner_temp" ] || fail "RUNNER_TEMP is missing"
[ -n "$output_file" ] || fail "GITHUB_OUTPUT is missing"
[ -n "$host" ] || fail "SOAK_SSH_HOST is missing"
[ -n "$user" ] || fail "SOAK_SSH_USER is missing"
[ -n "$private_key" ] || fail "SOAK_SSH_PRIVATE_KEY is missing"
[ -n "$host_keys" ] || fail "SOAK_SSH_HOST_KEYS is missing"

case "$host" in
    -*|*[!A-Za-z0-9.:-]*) fail "SOAK_SSH_HOST is invalid" ;;
esac
case "$user" in
    -*|*[!A-Za-z0-9._-]*) fail "SOAK_SSH_USER is invalid" ;;
esac
case "$port" in
    ''|*[!0-9]*) fail "SOAK_SSH_PORT is invalid" ;;
esac
if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    fail "SOAK_SSH_PORT is outside 1-65535"
fi

directory="$runner_temp/vaultlink-soak-ssh"
[ ! -e "$directory" ] || fail "SSH configuration directory already exists"
mkdir -m 0700 "$directory"
key="$directory/id"
known_hosts="$directory/known_hosts"
config="$directory/config"
printf '%s\n' "$private_key" >"$key"
printf '%s\n' "$host_keys" >"$known_hosts"
chmod 0600 "$key" "$known_hosts"
known_host_entries=$(grep -E -v '^[[:space:]]*(#|$)' "$known_hosts" || true)
if [ "$(printf '%s\n' "$known_host_entries" | grep -c . || true)" -ne 1 ]; then
    fail "SOAK_SSH_HOST_KEYS must contain exactly one trusted host key"
fi
ssh-keygen -y -f "$key" >/dev/null 2>&1 \
    || fail "SOAK_SSH_PRIVATE_KEY is not a readable private key"

lookup=$host
if [ "$port" -ne 22 ]; then
    lookup="[$host]:$port"
fi
ssh-keygen -F "$lookup" -f "$known_hosts" >/dev/null 2>&1 \
    || fail "SOAK_SSH_HOST_KEYS does not pin $lookup"

printf '%s\n' \
    'Host vaultlink-soak' \
    "    HostName $host" \
    "    Port $port" \
    "    User $user" \
    "    IdentityFile $key" \
    "    UserKnownHostsFile $known_hosts" \
    '    BatchMode yes' \
    '    IdentitiesOnly yes' \
    '    PasswordAuthentication no' \
    '    KbdInteractiveAuthentication no' \
    '    StrictHostKeyChecking yes' \
    '    ConnectTimeout 30' \
    '    ServerAliveInterval 15' \
    '    ServerAliveCountMax 2' \
    '    LogLevel ERROR' \
    >"$config"
chmod 0600 "$config"
printf 'config=%s\n' "$config" >>"$output_file"
