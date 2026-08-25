#!/bin/sh
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CDPATH=
LC_ALL=C
LANG=C
export PATH CDPATH LC_ALL LANG

override=/etc/systemd/system.conf.d/90-vaultlink-tcg-device-timeout.conf
cleanup=/usr/local/bin/vaultlink-clear-tcg-device-timeout
directory_marker=/etc/systemd/system.conf.d/.vaultlink-tcg-created-directory
[ "$0" = "$cleanup" ] || exit 70
[ -f "$override" ] && [ ! -L "$override" ] || exit 70
expected='[Manager]
DefaultDeviceTimeoutSec=5min'
[ "$(cat "$override")" = "$expected" ] || exit 70
rm -f -- "$override"
if [ -e "$directory_marker" ] || [ -L "$directory_marker" ]; then
    [ -f "$directory_marker" ] && [ ! -L "$directory_marker" ] || exit 70
    [ "$(cat "$directory_marker")" = vaultlink-created ] || exit 70
    rm -f -- "$directory_marker"
    rmdir -- /etc/systemd/system.conf.d
fi
rm -f -- "$cleanup"
