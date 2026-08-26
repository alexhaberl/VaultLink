#!/bin/sh
# Compound guards intentionally use `A && B || fail` for fail-closed exits.
# shellcheck disable=SC2015
set -eu
PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CDPATH=
LC_ALL=C
LANG=C
export PATH CDPATH LC_ALL LANG

[ "$#" -eq 1 ] || {
    echo "usage: $0 TARGET_ID" >&2
    exit 64
}

target_id=$1
manifest_value() {
    python3 tools/package-targets.py get "$target_id" "$1"
}

read_os_release_field() {
    os_field=$1
    os_values=$(sed -n "s/^${os_field}=//p" /etc/os-release)
    [ "$(printf '%s\n' "$os_values" | grep -c .)" -eq 1 ] || return 1
    case "$os_values" in
        \"*\") os_values=${os_values#\"}; os_values=${os_values%\"} ;;
    esac
    case "$os_values" in ''|*[!A-Za-z0-9._+-]*) return 1 ;; esac
    printf '%s\n' "$os_values"
}

[ -r /etc/os-release ] || {
    echo "package builder OS identity is unavailable" >&2
    exit 77
}
expected_distribution=$(manifest_value distribution)
expected_distribution_version=$(manifest_value version)
[ "$(read_os_release_field ID)" = "$expected_distribution" ] || {
    echo "package builder is running in the wrong distribution" >&2
    exit 77
}
if [ "$expected_distribution" != arch ]; then
    [ "$(read_os_release_field VERSION_ID)" = "$expected_distribution_version" ] || {
        echo "package builder is running in the wrong distribution version" >&2
        exit 77
    }
else
    [ "$expected_distribution_version" = rolling ] || exit 77
fi

expected_uname=$(manifest_value uname)
expected_host=$(manifest_value rust_host)
expected_rust_version=$(sh tools/rust-toolchain-channel.sh) || {
    echo "repository-pinned Rust version is unavailable" >&2
    exit 77
}
# The smoke gate has no network. Select the exact native toolchain baked into
# the builder so rustup neither inherits caller state nor attempts a sync.
RUSTUP_TOOLCHAIN="${expected_rust_version}-${expected_host}"
export RUSTUP_TOOLCHAIN
[ "$(uname -m)" = "$expected_uname" ] || {
    echo "package builder is running on the wrong native architecture" >&2
    exit 77
}
[ "$(rustc -vV | sed -n 's/^host: //p')" = "$expected_host" ] || {
    echo "package builder Rust host does not match target" >&2
    exit 77
}
[ "$(rustc --version | awk '{print $2}')" = "$expected_rust_version" ] || {
    echo "package builder Rust version is not repository-pinned" >&2
    exit 77
}

marker=/usr/local/share/vaultlink-builder.env
packages=/usr/local/share/vaultlink-builder-packages.lock
[ -f "$marker" ] && [ -s "$packages" ] || {
    echo "package builder evidence is missing" >&2
    exit 77
}
[ "$(stat -c %u:%g:%a "$marker")" = 0:0:644 ] || {
    echo "package builder marker has unsafe ownership or mode" >&2
    exit 77
}
grep -F -x -q "target_id=$target_id" "$marker"
grep -F -x -q "distribution=$(manifest_value distribution)" "$marker"
grep -F -x -q "distribution_version=$(manifest_value version)" "$marker"
grep -F -x -q "architecture=$(manifest_value architecture)" "$marker"
grep -F -x -q "builder_base_image=$(manifest_value builder_base_image)" "$marker"
live_packages=$(mktemp "${TMPDIR:-/tmp}/vaultlink-builder-packages.XXXXXXXX")
trap 'rm -f "$live_packages"' EXIT HUP INT TERM
case "$expected_distribution" in
    debian | ubuntu)
        dpkg-query -W -f='${binary:Package}=${Version}\n' \
            | LC_ALL=C sort >"$live_packages"
        ;;
    fedora)
        rpm -qa --qf '%{NAME}=%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' \
            | LC_ALL=C sort >"$live_packages"
        ;;
    arch)
        pacman -Q | LC_ALL=C sort >"$live_packages"
        ;;
    *) exit 77 ;;
esac
cmp "$packages" "$live_packages" || {
    echo "package builder live package closure differs from its stored lock" >&2
    exit 77
}
rm -f "$live_packages"
trap - EXIT HUP INT TERM
expected_packages_sha256=$(manifest_value builder_packages_sha256)
[ "$(sha256sum "$packages" | awk '{print $1}')" = "$expected_packages_sha256" ] || {
    echo "package builder package closure differs from the reviewed lock" >&2
    exit 77
}
if [ "$(manifest_value distribution)" = arch ]; then
    grep -F -x -q "arch_snapshot_date=$(manifest_value snapshot_date)" "$marker"
fi

case "$(manifest_value package_format)" in
    deb)
        command -v dpkg-deb >/dev/null
        command -v lintian >/dev/null
        ;;
    rpm)
        command -v rpmbuild >/dev/null
        command -v rpmlint >/dev/null
        ;;
    pkg.tar.zst)
        command -v makepkg >/dev/null
        command -v namcap >/dev/null
        ;;
    *) exit 77 ;;
esac

for command in cargo-cyclonedx cargo-audit cmp gh minisign readelf shellcheck ssh stat; do
    command -v "$command" >/dev/null
done

echo "package builder $target_id: OK"
