#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG

snapshot=${1:-deploy/docker/debian-snapshot.sources}
lock=${2:-deploy/docker/debian-packages.lock}
[ "$(id -u)" -eq 0 ] || {
    echo "pinned Debian package installation must run as root" >&2
    exit 77
}
if [ ! -s "$snapshot" ] || [ ! -s "$lock" ]; then
    echo "Debian snapshot or package lock is missing" >&2
    exit 66
fi

manifest_work=$(mktemp -d)
trap 'rm -rf "$manifest_work"' EXIT HUP INT TERM
installed_manifest() {
    dpkg-query -W -f='${db:Status-Abbrev} ${Package}=${Version}\n' \
        | awk '$1 == "ii" { print $2 }' \
        | sort -u
}
installed_manifest >"$manifest_work/before"
grep -E -v '^[[:space:]]*(#|$)' "$lock" | sort -u >"$manifest_work/locked"

# A digest-pinned base may still carry live mirrors in either legacy or deb822
# form. Remove every APT-readable source before installing the sole immutable
# snapshot definition.
rm -f /etc/apt/sources.list
find /etc/apt/sources.list.d -mindepth 1 -maxdepth 1 \
    \( -name '*.list' -o -name '*.sources' \) \
    -exec rm -f -- {} +
install -m 0644 "$snapshot" /etc/apt/sources.list.d/debian.sources
export DEBIAN_FRONTEND=noninteractive
apt-get update
grep -E -v '^[[:space:]]*(#|$)' "$lock" \
    | xargs apt-get install -y --no-install-recommends

failed=0
while IFS='=' read -r package expected; do
    case "$package" in ''|'#'*) continue ;; esac
    actual=$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null || true)
    if [ "$actual" != "$expected" ]; then
        echo "Debian package lock mismatch: $package expected $expected, got ${actual:-missing}" >&2
        failed=1
    fi
done <"$lock"
[ "$failed" -eq 0 ] || exit 1

installed_manifest >"$manifest_work/after"
comm -13 "$manifest_work/before" "$manifest_work/after" >"$manifest_work/changed"
comm -23 "$manifest_work/changed" "$manifest_work/locked" >"$manifest_work/unlocked"
if [ -s "$manifest_work/unlocked" ]; then
    echo "Debian packages added or changed outside the exact lock:" >&2
    sed 's/^/  /' "$manifest_work/unlocked" >&2
    exit 1
fi

[ ! -e /etc/apt/sources.list ] || {
    echo "legacy APT source list reappeared during installation" >&2
    exit 1
}
source_count=$(find /etc/apt/sources.list.d -mindepth 1 -maxdepth 1 \
    \( -name '*.list' -o -name '*.sources' \) -print | wc -l)
if [ "$source_count" -ne 1 ] \
    || ! cmp -s "$snapshot" /etc/apt/sources.list.d/debian.sources; then
    echo "immutable Debian snapshot is not the sole configured APT source" >&2
    exit 1
fi

rm -rf /var/lib/apt/lists/*
echo "Pinned Debian package set verified"
