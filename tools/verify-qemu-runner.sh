#!/bin/sh
# Verify the native QEMU harness against the commit-bound image inputs and
# complete Debian package closure. The selected container digest is enforced
# by the calling workflow; this script verifies the contents of that image.
# Compound guards intentionally use `A && B || fail` for fail-closed exits.
# shellcheck disable=SC2015
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CDPATH=
LC_ALL=C
LANG=C
export PATH CDPATH LC_ALL LANG
umask 077

fail() {
    echo "QEMU runner verification failed: $*" >&2
    exit 1
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: verify-qemu-runner.sh ARCHITECTURE [LOCK_DIRECTORY]" >&2
    exit 64
fi
architecture=$1
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
lock_directory=${2:-$repo_root/deploy/docker}

case "$architecture:$(uname -m)" in
    amd64:x86_64) qemu_command=qemu-system-x86_64 ;;
    arm64:aarch64) qemu_command=qemu-system-aarch64 ;;
    *) fail "container machine does not match requested architecture $architecture" ;;
esac

image_lock=$lock_directory/qemu-runner-image.lock
base_lock=$lock_directory/qemu-runner-base-image.lock
packages_lock=$lock_directory/qemu-runner-packages-$architecture.lock
for lock_file in "$image_lock" "$base_lock" "$packages_lock"; do
    [ -f "$lock_file" ] && [ ! -L "$lock_file" ] \
        || fail "missing or unsafe commit-bound lock: $lock_file"
done
[ "$(wc -l <"$image_lock" | tr -d '[:space:]')" -eq 1 ] \
    && [ "$(wc -l <"$base_lock" | tr -d '[:space:]')" -eq 1 ] \
    || fail "image and base locks must contain exactly one line"
image=$(cat "$image_lock")
base_image=$(cat "$base_lock")
printf '%s\n' "$image" \
    | grep -E -q '^ghcr\.io/alexhaberl/vaultlink-qemu-runner@sha256:[0-9a-f]{64}$' \
    || fail "QEMU runner image lock is not provisioned"
printf '%s\n' "$base_image" \
    | grep -E -q '^[a-z0-9.-]+(/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$' \
    || fail "QEMU runner base-image lock is not provisioned"
[ "$(sed -n '$=' "$packages_lock")" -ge 1 ] \
    && ! grep -F -x -q UNPROVISIONED "$packages_lock" \
    || fail "QEMU runner package closure is not provisioned"
LC_ALL=C sort -c -u "$packages_lock" \
    || fail "QEMU runner package closure is not sorted and unique"
awk '
    !/^[a-z0-9][a-z0-9+.-]*(:[a-z0-9][a-z0-9-]*)?=[A-Za-z0-9][A-Za-z0-9.+:~_-]*$/ {
        exit 1
    }
' "$packages_lock" || fail "QEMU runner package closure has an invalid record"

read_os_release_field() {
    field=$1
    values=$(sed -n "s/^${field}=//p" /etc/os-release)
    [ "$(printf '%s\n' "$values" | grep -c .)" -eq 1 ] || return 1
    case "$values" in \"*\") values=${values#\"}; values=${values%\"} ;; esac
    case "$values" in ''|*[!A-Za-z0-9._+-]*) return 1 ;; esac
    printf '%s\n' "$values"
}

[ -r /etc/os-release ] || fail "container OS identity is unavailable"
[ "$(read_os_release_field ID)" = ubuntu ] \
    && [ "$(read_os_release_field VERSION_ID)" = 24.04 ] \
    || fail "QEMU runner must use exactly Ubuntu 24.04"

marker=/usr/local/share/vaultlink-qemu-runner.env
embedded_packages=/usr/local/share/vaultlink-qemu-runner-packages.lock
[ -f "$marker" ] && [ ! -L "$marker" ] \
    && [ "$(stat -c '%u:%g:%a' "$marker")" = 0:0:644 ] \
    || fail "QEMU runner marker is missing or unsafe"
[ -f "$embedded_packages" ] && [ ! -L "$embedded_packages" ] \
    && [ "$(stat -c '%u:%g:%a' "$embedded_packages")" = 0:0:644 ] \
    || fail "embedded QEMU runner package closure is missing or unsafe"

work=$(mktemp -d "${TMPDIR:-/tmp}/vaultlink-qemu-runner.XXXXXXXX")
cleanup() {
    rm -rf -- "$work"
}
trap cleanup 0 1 2 15
printf 'base_image=%s\narchitecture=%s\n' "$base_image" "$architecture" \
    >"$work/expected.env"
cmp "$work/expected.env" "$marker" >/dev/null \
    || fail "QEMU runner marker differs from the commit-bound inputs"
cmp "$packages_lock" "$embedded_packages" >/dev/null \
    || fail "embedded QEMU runner package closure differs from the commit"
dpkg-query -W -f='${binary:Package}=${Version}\n' | LC_ALL=C sort \
    >"$work/live-packages.lock"
cmp "$packages_lock" "$work/live-packages.lock" >/dev/null \
    || fail "live QEMU runner package database differs from the commit"

for required_command in base64 cloud-localds cmp dpkg-query python3 qemu-img scp \
    sha256sum ssh stat "$qemu_command"; do
    command -v "$required_command" >/dev/null \
        || fail "required harness command is missing: $required_command"
done
if [ "$architecture" = arm64 ]; then
    command -v guestfish >/dev/null \
        || fail "arm64 QEMU runner is missing guestfish"
    guestfs_path=$(guestfish get-path)
    printf '%s' "$guestfs_path" | python3 -c \
        'import re,sys; value=sys.stdin.read(); sys.exit(0 if re.fullmatch(r"/usr/lib/[A-Za-z0-9._+-]+/guestfs", value) else 1)' \
        || fail "arm64 libguestfs path is unsafe"
    [ -d "$guestfs_path" ] && [ ! -L "$guestfs_path" ] \
        || fail "arm64 libguestfs path is missing or unsafe"
    supermin_directory=$guestfs_path/supermin.d
    [ -d "$supermin_directory" ] && [ ! -L "$supermin_directory" ] \
        || fail "arm64 Supermin input directory is missing or unsafe"
    selinux_fragment=$supermin_directory/packages-vaultlink-selinux
    [ -f "$selinux_fragment" ] && [ ! -L "$selinux_fragment" ] \
        && [ "$(stat -c '%u:%g:%a' "$selinux_fragment")" = 0:0:644 ] \
        || fail "arm64 Supermin SELinux package fragment is missing or unsafe"
    [ "$(wc -l <"$selinux_fragment" | tr -d '[:space:]')" -eq 1 ] \
        && grep -F -x -q policycoreutils "$selinux_fragment" \
        || fail "arm64 Supermin SELinux package fragment is invalid"
    [ "$(dpkg-query -W -f='${Status}' policycoreutils)" \
        = 'install ok installed' ] \
        || fail "arm64 QEMU runner is missing policycoreutils"
    LIBGUESTFS_BACKEND=direct
    LIBGUESTFS_BACKEND_SETTINGS=force_tcg
    LIBGUESTFS_CACHEDIR=$work/libguestfs-cache
    mkdir -m 0700 "$LIBGUESTFS_CACHEDIR"
    export LIBGUESTFS_BACKEND LIBGUESTFS_BACKEND_SETTINGS \
        LIBGUESTFS_CACHEDIR
    [ "$(guestfish get-backend)" = direct ] \
        || fail "arm64 libguestfs must use the direct backend"
    [ "$(guestfish get-backend-settings)" = force_tcg ] \
        || fail "arm64 libguestfs must be pinned to TCG"
    printf '%s\n' vaultlink-guestfish-probe >"$work/guestfish-probe.expected"
    guestfish \
        -N "$work/guestfish-probe.img=fs:ext4:64M" -m /dev/sda1 \
        >"$work/guestfish-probe.features" <<EOF
feature-available selinuxrelabel
upload $work/guestfish-probe.expected /vaultlink-probe
download /vaultlink-probe $work/guestfish-probe.actual
EOF
    [ "$(cat "$work/guestfish-probe.features")" = true ] \
        || fail "arm64 QEMU runner lacks guestfish SELinux relabel support"
    cmp "$work/guestfish-probe.expected" "$work/guestfish-probe.actual" \
        || fail "arm64 QEMU runner guestfish write/read probe failed"
    [ -r /usr/share/AAVMF/AAVMF_CODE.fd ] \
        || [ -r /usr/share/qemu-efi-aarch64/QEMU_EFI.fd ] \
        || fail "AArch64 UEFI firmware is missing"
fi

packages_sha256=$(sha256sum "$packages_lock" | awk '{print $1}')
trap - 0 1 2 15
rm -rf -- "$work"
printf 'qemu_runner_architecture=%s\nqemu_runner_packages_sha256=%s\n' \
    "$architecture" "$packages_sha256"
