#!/bin/sh
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
LANG=C
export PATH
export LC_ALL LANG

fail() {
    echo "direct process identity check failed: $*" >&2
    exit 1
}

[ "$#" -eq 6 ] || {
    echo "usage: $0 PID UID GID EXPECTED_PATH EXPECTED_SHA256 EXPECTED_STARTTIME" >&2
    exit 64
}

pid=$1
expected_uid=$2
expected_gid=$3
expected_path=$4
expected_sha256=$5
expected_starttime=$6

for numeric_value in "$pid" "$expected_uid" "$expected_gid"; do
    case "$numeric_value" in
        *[!0-9]*|'') fail "PID, UID, and GID must be decimal integers" ;;
    esac
done
if [ "$pid" -le 1 ] || [ "$expected_uid" -le 0 ] \
    || [ "$expected_gid" -le 0 ]; then
    fail "PID, UID, and GID must identify an unprivileged service process"
fi
case "$expected_path" in
    /*) ;;
    *) fail "expected executable path must be absolute" ;;
esac
case "$expected_sha256" in
    *[!0-9a-f]*|'') fail "expected executable digest must be lowercase SHA-256" ;;
esac
[ "${#expected_sha256}" -eq 64 ] \
    || fail "expected executable digest must contain 64 characters"
case "$expected_starttime" in
    *[!0-9]*) fail "expected process start time must be a decimal integer" ;;
esac

[ "$(id -u)" = "$expected_uid" ] \
    || fail "identity helper is not running with the expected UID"
[ "$(id -g)" = "$expected_gid" ] \
    || fail "identity helper is not running with the expected GID"
awk '
    /^Groups:/ { rows++; if (NF != 1) invalid = 1 }
    END { exit !(rows == 1 && !invalid) }
' /proc/self/status \
    || fail "identity helper retained supplementary groups"
awk '
    /^CapEff:/ {
        capability_rows++
        if (NF != 2 || $2 != "0000000000000000") invalid = 1
    }
    /^NoNewPrivs:/ {
        no_new_privileges_rows++
        if (NF != 2 || $2 != "1") invalid = 1
    }
    END {
        exit !(capability_rows == 1 && no_new_privileges_rows == 1 && !invalid)
    }
' /proc/self/status \
    || fail "identity helper retained privileges"

target_credentials_match() {
    awk -v expected_uid="$expected_uid" -v expected_gid="$expected_gid" '
        /^Uid:/ {
            uid_rows++
            if (NF != 5 || $2 != expected_uid || $3 != expected_uid \
                || $4 != expected_uid || $5 != expected_uid) invalid = 1
        }
        /^Gid:/ {
            gid_rows++
            if (NF != 5 || $2 != expected_gid || $3 != expected_gid \
                || $4 != expected_gid || $5 != expected_gid) invalid = 1
        }
        END { exit !(uid_rows == 1 && gid_rows == 1 && !invalid) }
    ' "/proc/$pid/status"
}

process_starttime() {
    sed 's/^.*) //' "/proc/$pid/stat" | awk '{ print $20; exit }'
}

kill -0 "$pid" 2>/dev/null || fail "target process is not live"
target_credentials_match || fail "target process UID/GID does not match"
starttime_before=$(process_starttime) \
    || fail "target process start time is unavailable"
case "$starttime_before" in
    *[!0-9]*|'') fail "target process start time is invalid" ;;
esac
if [ -n "$expected_starttime" ] \
    && [ "$starttime_before" != "$expected_starttime" ]; then
    fail "target PID was reused"
fi

observed_path=$(readlink "/proc/$pid/exe") \
    || fail "target executable path is unavailable"
[ "$observed_path" = "$expected_path" ] \
    || fail "target executable path does not match"
observed_sha256=$(sha256sum "/proc/$pid/exe" | awk '{ print $1; exit }') \
    || fail "target executable digest is unavailable"
[ "$observed_sha256" = "$expected_sha256" ] \
    || fail "target executable digest does not match"

target_credentials_match || fail "target process UID/GID changed during verification"
starttime_after=$(process_starttime) \
    || fail "target process start time disappeared during verification"
[ "$starttime_after" = "$starttime_before" ] \
    || fail "target process changed during verification"
[ "$(readlink "/proc/$pid/exe")" = "$expected_path" ] \
    || fail "target executable changed during verification"

printf '%s\n' "$starttime_after"
