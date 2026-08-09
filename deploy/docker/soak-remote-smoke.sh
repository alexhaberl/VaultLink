#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG

fail() {
    echo "soak remote smoke failed: $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "the isolated smoke must run as root"
work=$(mktemp -d)
trap 'rm -rf "$work" /var/lib/vaultlink-soak /usr/local/sbin/vaultlink-soak-remote /usr/local/libexec/vaultlink/collect-soak-evidence.sh' EXIT HUP INT TERM
install -d -m 0755 /usr/local/sbin /usr/local/libexec/vaultlink
install -m 0755 deploy/vaultlink-soak-remote.sh /usr/local/sbin/vaultlink-soak-remote
install -m 0755 tools/collect-soak-evidence.sh /usr/local/libexec/vaultlink/collect-soak-evidence.sh

bundle="$work/idle.tar.gz"
SSH_CONNECTION='192.0.2.1 12345 192.0.2.2 22' \
SSH_ORIGINAL_COMMAND=collect \
    /usr/local/sbin/vaultlink-soak-remote >"$bundle"
mkdir "$work/idle"
tar -xzf "$bundle" -C "$work/idle"
[ "$(cat "$work/idle/collector.exit")" -eq 0 ] \
    || fail "idle collection returned an error"
grep -F -x -q 'state=idle' "$work/idle/collector.output" \
    || fail "idle collection did not preserve state"

if SSH_CONNECTION='192.0.2.1 12345 192.0.2.2 22' \
    SSH_ORIGINAL_COMMAND='collect extra' \
    /usr/local/sbin/vaultlink-soak-remote >/dev/null 2>&1; then
    fail "bridge accepted extra collect arguments"
fi
if SSH_ORIGINAL_COMMAND=collect \
    /usr/local/sbin/vaultlink-soak-remote >/dev/null 2>&1; then
    fail "bridge accepted a non-SSH invocation"
fi
if SSH_CONNECTION='192.0.2.1 12345 192.0.2.2 22' \
    SSH_ORIGINAL_COMMAND='start invalid invalid invalid' \
    /usr/local/sbin/vaultlink-soak-remote >/dev/null 2>&1; then
    fail "bridge accepted invalid start hashes"
fi

echo "Restricted soak SSH bridge smoke passed"
