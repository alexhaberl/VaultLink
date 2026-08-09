#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG
umask 077
set -f

state_root=/var/lib/vaultlink-soak
control=/usr/local/sbin/vaultlink-soak-control
collector=/usr/local/libexec/vaultlink/collect-soak-evidence.sh

fail() {
    echo "soak remote bridge failed: $*" >&2
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

[ -n "${SSH_CONNECTION:-}" ] || fail "the bridge is SSH-only"
original=${SSH_ORIGINAL_COMMAND:-}
old_ifs=$IFS
IFS=' '
# The forced command protocol is deliberately split into plain space-delimited
# tokens after pathname expansion has been disabled above.
# shellcheck disable=SC2086
set -- $original
IFS=$old_ifs
[ "$#" -gt 0 ] || fail "a bridge command is required"

case "$1" in
    start)
        [ "$#" -eq 4 ] || fail "start requires commit, binary, and orchestration hashes"
        valid_commit "$2" || fail "invalid commit SHA"
        valid_hash "$3" || fail "invalid binary SHA-256"
        valid_hash "$4" || fail "invalid orchestration SHA-256"
        exec sudo -- "$control" start "$2" "$3" "$4"
        ;;
    collect)
        [ "$#" -eq 1 ] || fail "collect takes no arguments"
        work=$(mktemp -d)
        trap 'rm -rf "$work"' EXIT HUP INT TERM
        output="$work/collector.output"
        log="$work/collector.log"
        evidence="$work/evidence"
        : >"$output"
        : >"$log"
        collector_exit=0
        GITHUB_OUTPUT="$output" SOAK_STATE_ROOT="$state_root" \
            "$collector" "$evidence" >"$log" 2>&1 || collector_exit=$?
        printf '%s\n' "$collector_exit" >"$work/collector.exit"
        set -- collector.exit collector.log collector.output
        if [ -d "$evidence" ]; then
            set -- "$@" evidence
        fi
        tar -czf - -C "$work" "$@"
        ;;
    *) fail "unsupported bridge command" ;;
esac
