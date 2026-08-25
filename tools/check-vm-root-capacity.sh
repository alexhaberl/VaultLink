#!/bin/sh
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CDPATH=
LC_ALL=C
LANG=C
export PATH CDPATH LC_ALL LANG

[ "$#" -eq 2 ] || {
    echo "usage: $0 MINIMUM_SIZE_BYTES MINIMUM_AVAILABLE_BYTES" >&2
    exit 64
}
minimum_size=$1
minimum_available=$2
case "$minimum_size" in ''|*[!0-9]*) exit 64 ;; esac
case "$minimum_available" in ''|*[!0-9]*) exit 64 ;; esac

root_size=$(findmnt -bno SIZE /)
root_size=$(printf '%s' "$root_size" | tr -d '[:space:]')
root_available=$(df -B1 --output=avail / | sed -n '2p')
root_available=$(printf '%s' "$root_available" | tr -d '[:space:]')
case "$root_size" in ''|*[!0-9]*) exit 70 ;; esac
case "$root_available" in ''|*[!0-9]*) exit 70 ;; esac
[ "$root_size" -ge "$minimum_size" ] || {
    echo "root filesystem is smaller than the reviewed minimum" >&2
    exit 70
}
[ "$root_available" -ge "$minimum_available" ] || {
    echo "root filesystem has less free space than the reviewed minimum" >&2
    exit 70
}

printf 'root_filesystem_size=%s\nroot_filesystem_available=%s\n' \
    "$root_size" "$root_available"
