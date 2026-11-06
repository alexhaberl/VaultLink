#!/bin/sh
# Restart APT after failed downloads; never enter its delayed-item retry loop.
# Debian apt 3.0.3 can exhaust host RAM with Acquire::Retries > 0:
# https://bugs.debian.org/1152704
set -eu
LC_ALL=C
export LC_ALL

case "${1:-}" in
    update) shift; set -- --error-on=any update "$@" ;;
    download) shift; set -- install --download-only "$@" ;;
    *)
        echo "usage: $0 {update|download} [apt-get arguments ...]" >&2
        exit 64
        ;;
esac

apt_attempt=1
apt_delay=5
while :; do
    printf 'APT download attempt %s/6 (internal retries disabled)\n' "$apt_attempt"
    if apt-get -o Acquire::Retries=0 \
        -o Acquire::https::Timeout=30 \
        -o Acquire::https::Pipeline-Depth=0 "$@"; then
        exit 0
    else
        apt_status=$?
    fi
    if [ "$apt_attempt" -ge 6 ]; then
        echo "APT downloads failed after $apt_attempt attempts" >&2
        exit "$apt_status"
    fi
    printf 'APT exited %s; restarting in %ss\n' "$apt_status" "$apt_delay" >&2
    sleep "$apt_delay"
    apt_attempt=$((apt_attempt + 1))
    apt_delay=$((apt_delay * 2))
    if [ "$apt_delay" -gt 30 ]; then
        apt_delay=30
    fi
done
