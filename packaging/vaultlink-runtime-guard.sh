#!/bin/sh
# Compound guards intentionally use `A && B || fail` for fail-closed exits.
# shellcheck disable=SC2015
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
CDPATH=
LC_ALL=C
LANG=C
export PATH CDPATH LC_ALL LANG
umask 077

marker=/usr/share/vaultlink/install-method.env
candidate=/usr/lib/vaultlink/package/vaultlink
live_binary=/opt/vaultlink/vaultlink
version_file=/usr/lib/vaultlink/package/version
checksum_file=/usr/lib/vaultlink/package/vaultlink.sha256

fail() {
    echo "VaultLink runtime parity guard: $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "guard must run as root"
case "$#:${1:-}" in
    0:) guard_mode=full ;;
    1:--package-only) guard_mode=package-only ;;
    *) fail "usage: vaultlink-runtime-guard.sh [--package-only]" ;;
esac
for required_command in awk cat cmp dpkg-query grep id pacman rpm runuser sed \
    sha256sum stat timeout tr uname wc; do
    case "$required_command" in
        dpkg-query|pacman|rpm) ;;
        *) command -v "$required_command" >/dev/null || fail "$required_command is required" ;;
    esac
done

validate_root_file() {
    guard_file=$1
    expected_file_mode=$2
    [ -f "$guard_file" ] && [ ! -L "$guard_file" ] \
        || fail "$guard_file is missing, non-regular, or a symlink"
    [ "$(stat -c '%u:%g:%a' "$guard_file")" = "0:0:$expected_file_mode" ] \
        || fail "$guard_file must be root:root mode 0$expected_file_mode"
}

validate_root_file "$0" 755
validate_root_file "$marker" 644
validate_root_file "$candidate" 755
validate_root_file "$version_file" 644
validate_root_file "$checksum_file" 644
if [ "$guard_mode" = full ]; then
    [ -f "$live_binary" ] && [ ! -L "$live_binary" ] \
        || fail "active runtime is missing, non-regular, or a symlink"
    validate_root_file "$live_binary" 755
fi
[ "$(wc -l <"$marker" | tr -d '[:space:]')" = 5 ] \
    || fail "installation marker must contain exactly five lines"

read_exact_field() {
    field_file=$1
    field_name=$2
    field_value=$(sed -n "s/^${field_name}=//p" "$field_file")
    [ "$(printf '%s\n' "$field_value" | grep -c .)" -eq 1 ] \
        || fail "$field_file must define $field_name exactly once"
    case "$field_value" in
        \"*\") field_value=${field_value#\"}; field_value=${field_value%\"} ;;
    esac
    case "$field_value" in
        ''|*[!A-Za-z0-9._+-]*) fail "$field_file contains unsafe $field_name" ;;
    esac
    printf '%s\n' "$field_value"
}

package_format=$(read_exact_field "$marker" FORMAT)
os_id=$(read_exact_field "$marker" OS_ID)
os_version=$(read_exact_field "$marker" OS_VERSION)
package_arch=$(read_exact_field "$marker" ARCH)
package_name=$(read_exact_field "$marker" PACKAGE_NAME)
[ "$package_name" = vaultlink ] || fail "unexpected package name in marker"
expected_marker=$(printf 'FORMAT=%s\nOS_ID=%s\nOS_VERSION=%s\nARCH=%s\nPACKAGE_NAME=vaultlink' \
    "$package_format" "$os_id" "$os_version" "$package_arch")
[ "$(cat "$marker")" = "$expected_marker" ] \
    || fail "installation marker fields or ordering are not canonical"
actual_os_id=$(read_exact_field /etc/os-release ID)
[ "$actual_os_id" = "$os_id" ] || fail "installation marker OS does not match host"
if [ "$os_id" = arch ]; then
    [ "$os_version" = rolling ] || fail "Arch marker version must be rolling"
else
    actual_os_version=$(read_exact_field /etc/os-release VERSION_ID)
    [ "$actual_os_version" = "$os_version" ] \
        || fail "installation marker OS version does not match host"
fi
actual_machine=$(uname -m)
case "$package_arch:$actual_machine" in
    amd64:x86_64|arm64:aarch64|x86_64:x86_64|aarch64:aarch64) ;;
    *) fail "installation marker architecture does not match host" ;;
esac
case "$package_format:$os_id:$os_version:$package_arch" in
    deb:debian:13:amd64|deb:debian:13:arm64|\
    deb:ubuntu:24.04:amd64|deb:ubuntu:24.04:arm64|\
    deb:ubuntu:26.04:amd64|deb:ubuntu:26.04:arm64|\
    rpm:fedora:44:x86_64|rpm:fedora:44:aarch64|\
    pkg.tar.zst:arch:rolling:x86_64) ;;
    *) fail "unsupported package target tuple" ;;
esac

package_version=$(cat "$version_file")
[ "$(wc -l <"$version_file" | tr -d '[:space:]')" = 1 ] \
    || fail "package version metadata must contain exactly one line"
printf '%s\n' "$package_version" \
    | grep -E -q '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' \
    || fail "package version metadata is not strict stable SemVer"
case "$package_format:$os_id:$os_version" in
    deb:debian:13) expected_database_version=$package_version-1+deb13 ;;
    deb:ubuntu:24.04) expected_database_version=$package_version-1+ubuntu24.04 ;;
    deb:ubuntu:26.04) expected_database_version=$package_version-1+ubuntu26.04 ;;
    rpm:fedora:44) expected_database_version=$package_version-1.fc44 ;;
    pkg.tar.zst:arch:rolling) expected_database_version=$package_version-1 ;;
    *) fail "cannot derive native package version" ;;
esac
case "$package_format" in
    deb)
        command -v dpkg-query >/dev/null || fail "dpkg-query is required"
        [ "$(dpkg-query -W -f='${db:Status-Status}' vaultlink 2>/dev/null)" = installed ] \
            || fail "Debian package database does not report VaultLink installed"
        database_version=$(dpkg-query -W -f='${Version}' vaultlink 2>/dev/null)
        database_arch=$(dpkg-query -W -f='${Architecture}' vaultlink 2>/dev/null)
        ;;
    rpm)
        command -v rpm >/dev/null || fail "rpm is required"
        [ "$(rpm -q --qf '%{NAME}' vaultlink 2>/dev/null)" = vaultlink ] \
            || fail "RPM database does not report VaultLink installed"
        [ "$(rpm -q --qf '%{EPOCHNUM}' vaultlink 2>/dev/null)" = 0 ] \
            || fail "RPM database reports a forbidden nonzero epoch"
        database_version=$(rpm -q --qf '%{VERSION}-%{RELEASE}' vaultlink 2>/dev/null)
        database_arch=$(rpm -q --qf '%{ARCH}' vaultlink 2>/dev/null)
        ;;
    pkg.tar.zst)
        command -v pacman >/dev/null || fail "pacman is required"
        database_record=$(pacman -Q vaultlink 2>/dev/null) \
            || fail "Pacman database does not report VaultLink installed"
        [ "${database_record%% *}" = vaultlink ] || fail "unexpected Pacman package record"
        database_version=${database_record#* }
        database_arch_lines=$(pacman -Qi vaultlink 2>/dev/null \
            | sed -n 's/^Architecture[[:space:]]*:[[:space:]]*//p') \
            || fail "Pacman package metadata is unavailable"
        [ "$(printf '%s\n' "$database_arch_lines" \
            | awk 'NF { count++ } END { print count + 0 }')" -eq 1 ] \
            || fail "Pacman package metadata must report architecture exactly once"
        database_arch=$database_arch_lines
        ;;
esac
[ "$database_version" = "$expected_database_version" ] \
    || fail "native package database version diverges from candidate metadata"
[ "$database_arch" = "$package_arch" ] \
    || fail "native package database architecture diverges from marker"

checksum_line=$(cat "$checksum_file")
[ "$(wc -l <"$checksum_file" | tr -d '[:space:]')" = 1 ] \
    || fail "candidate checksum metadata must contain exactly one line"
candidate_sha256=$(sha256sum "$candidate" | awk '{ print $1 }')
[ "$checksum_line" = "$candidate_sha256  vaultlink" ] \
    || fail "candidate checksum metadata is not canonical"
(cd /usr/lib/vaultlink/package && sha256sum -c vaultlink.sha256 >/dev/null) \
    || fail "package candidate checksum does not match metadata"
candidate_version=$(timeout --kill-after=2 5 runuser -u vaultlink -- "$candidate" --version) \
    || fail "package candidate version probe failed"
[ "$candidate_version" = "$package_version" ] \
    || fail "candidate version diverges from package metadata"
if [ "$guard_mode" = full ]; then
    cmp -s "$candidate" "$live_binary" \
        || fail "active runtime differs from native package candidate"
    live_version=$(timeout --kill-after=2 5 runuser -u vaultlink -- "$live_binary" --version) \
        || fail "active runtime version probe failed"
    [ "$live_version" = "$package_version" ] \
        || fail "active runtime version diverges from package metadata"
fi
