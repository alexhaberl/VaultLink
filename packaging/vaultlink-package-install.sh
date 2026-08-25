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

fail() {
    echo "VaultLink Arch initial installer: $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run this installer as root"
[ "$#" -eq 1 ] || {
    echo "usage: vaultlink-package-install.sh ROOT_OWNED_PACKAGE.pkg.tar.zst" >&2
    exit 64
}
for required_command in awk basename bsdtar cat chmod cmp cp dirname du find flock grep \
    gzip install mktemp pacman readlink rm runuser sed sha256sum sort stat timeout tr uniq wc; do
    command -v "$required_command" >/dev/null \
        || fail "$required_command is required"
done

package_input=$1
validate_trusted_parent_chain() {
    trusted_path=$1
    trusted_parent=$(dirname -- "$trusted_path")
    while :; do
        [ -d "$trusted_parent" ] && [ ! -L "$trusted_parent" ] \
            || fail "path parent is not a regular directory: $trusted_parent"
        [ "$(stat -c '%u' "$trusted_parent")" = 0 ] \
            || fail "path parent must be owned by root: $trusted_parent"
        trusted_parent_mode=$(stat -c '%a' "$trusted_parent")
        case "$trusted_parent_mode" in
            [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
            *) fail "path parent has an unsupported mode: $trusted_parent" ;;
        esac
        if [ "$((0$trusted_parent_mode & 0022))" -ne 0 ]; then
            [ "$((0$trusted_parent_mode & 01000))" -ne 0 ] \
                || fail "path parent must not be group/world-writable unless root-owned sticky: $trusted_parent"
        fi
        [ "$trusted_parent" = / ] && break
        trusted_parent=$(dirname -- "$trusted_parent")
    done
}

[ -f "$0" ] && [ ! -L "$0" ] \
    || fail "installer itself must be a regular file, not a symlink"
[ "$(readlink -f -- "$0")" = "$0" ] \
    || fail "installer must be invoked through its canonical absolute path"
validate_trusted_parent_chain "$0"
[ "$(stat -c '%u:%g' "$0")" = 0:0 ] \
    || fail "installer itself must be owned by root:root"
installer_mode=$(stat -c '%a' "$0")
case "$installer_mode" in
    [0-7][0-7][0-7]) ;;
    *) fail "installer itself has an unsupported mode" ;;
esac
[ "$((0$installer_mode & 0100))" -ne 0 ] \
    || fail "installer itself must be executable by root"
[ "$((0$installer_mode & 0022))" -eq 0 ] \
    || fail "installer itself must not be group- or world-writable"
installer_identity=$(stat -c '%d:%i:%s' "$0")
installer_hash=$(sha256sum "$0" | awk '{ print $1 }')
[ -f "$package_input" ] && [ ! -L "$package_input" ] \
    || fail "package must be a regular file, not a symlink"
package_path=$(readlink -f -- "$package_input")
[ -n "$package_path" ] && [ -f "$package_path" ] && [ ! -L "$package_path" ] \
    || fail "package path could not be resolved safely"
validate_trusted_parent_chain "$package_path"
package_asset_name=$(basename "$package_path")
case "$package_asset_name" in
    vaultlink-[0-9]*.[0-9]*.[0-9]*-1-x86_64.pkg.tar.zst) ;;
    *) fail "unexpected Arch package asset name" ;;
esac
[ "$(stat -c '%u:%g' "$package_path")" = 0:0 ] \
    || fail "package must be owned by root:root"
package_mode=$(stat -c '%a' "$package_path")
case "$package_mode" in 400|440|444|600|640|644) ;; *) fail "package mode must not be executable or group/world-writable" ;; esac
package_size=$(stat -c '%s' "$package_path")
[ "$package_size" -ge 1024 ] && [ "$package_size" -le 1073741824 ] \
    || fail "package size is outside the 1KiB..1GiB safety bound"
package_source_identity=$(stat -c '%d:%i:%s' "$package_path")
package_source_hash=$(sha256sum "$package_path" | awk '{ print $1 }')

lock_directory=/run/vaultlink-locks
install_lock=$lock_directory/package-install.lock
update_lock=$lock_directory/update.lock
maintenance_lock=$lock_directory/maintenance.lock
prepare_lock_file() {
    prepared_lock_path=$1
    [ -d /run ] && [ ! -L /run ] \
        && [ "$(stat -Lc '%u:%g:%a' /run 2>/dev/null || true)" = 0:0:755 ] \
        || fail "/run must be a root-owned mode-0755 directory"
    if [ -e "$lock_directory" ] || [ -L "$lock_directory" ]; then
        [ -d "$lock_directory" ] && [ ! -L "$lock_directory" ] \
            && [ "$(stat -Lc '%u:%g:%a' "$lock_directory" 2>/dev/null || true)" = 0:0:700 ] \
            || fail "VaultLink lock directory is unsafe"
    else
        install -d -o root -g root -m 0700 "$lock_directory"
    fi
    if [ -e "$prepared_lock_path" ] || [ -L "$prepared_lock_path" ]; then
        [ -f "$prepared_lock_path" ] && [ ! -L "$prepared_lock_path" ] \
            && [ "$(stat -Lc '%u:%g:%a' "$prepared_lock_path" 2>/dev/null || true)" = 0:0:600 ] \
            || fail "VaultLink lock file is unsafe: $prepared_lock_path"
    else
        install -o root -g root -m 0600 /dev/null "$prepared_lock_path"
    fi
    [ -f "$prepared_lock_path" ] && [ ! -L "$prepared_lock_path" ] \
        && [ "$(stat -Lc '%u:%g:%a' "$prepared_lock_path" 2>/dev/null || true)" = 0:0:600 ] \
        || fail "VaultLink lock file is unsafe: $prepared_lock_path"
}
validate_open_lock() {
    opened_lock_fd=$1
    opened_lock_path=$2
    [ -f "$opened_lock_path" ] && [ ! -L "$opened_lock_path" ] \
        && [ "$(stat -Lc '%u:%g:%a' "$opened_lock_path" 2>/dev/null || true)" = 0:0:600 ] \
        && [ "$(stat -Lc '%d:%i' "/proc/self/fd/$opened_lock_fd" 2>/dev/null || true)" = \
            "$(stat -Lc '%d:%i' "$opened_lock_path" 2>/dev/null || true)" ] \
        || fail "VaultLink lock changed while it was opened: $opened_lock_path"
}
prepare_lock_file "$install_lock"
prepare_lock_file "$update_lock"
prepare_lock_file "$maintenance_lock"
exec 7>"$install_lock"
validate_open_lock 7 "$install_lock"
flock -n 7 || fail "another VaultLink package installation is running"
validate_open_lock 7 "$install_lock"
exec 9>"$update_lock"
validate_open_lock 9 "$update_lock"
flock -n 9 || fail "another VaultLink update operation is running"
validate_open_lock 9 "$update_lock"
exec 8>"$maintenance_lock"
validate_open_lock 8 "$maintenance_lock"
flock -n 8 || fail "another VaultLink upgrade or rollback is running"
validate_open_lock 8 "$maintenance_lock"
pacman -Q vaultlink >/dev/null 2>&1 \
    && fail "this wrapper is only for initial installation; use the signed updater for upgrades"

work=$(mktemp -d /var/tmp/vaultlink-arch-install.XXXXXXXX)
package_transaction_started=0
installation_complete=0
trusted_reinstall=0
marker_recovery=/var/lib/vaultlink-backups/install-method.env
marker_recovery_preexisting=0
if [ -e "$marker_recovery" ] || [ -L "$marker_recovery" ]; then
    marker_recovery_preexisting=1
fi
cleanup_live_armed=0
cleanup_update_armed=0
expected_cleanup_candidate=
expected_cleanup_update_config=
reinstall_update_state=unrecorded
reinstall_update_identity=
reinstall_update_hash=
cleanup_created_mutable_files() {
    if [ "$cleanup_live_armed" -eq 1 ] \
        && { [ -e /opt/vaultlink/vaultlink ] || [ -L /opt/vaultlink/vaultlink ]; }; then
        [ -f /opt/vaultlink/vaultlink ] && [ ! -L /opt/vaultlink/vaultlink ] \
            && [ "$(stat -c '%u:%g:%a' /opt/vaultlink/vaultlink)" = 0:0:755 ] \
            && cmp -s "$expected_cleanup_candidate" /opt/vaultlink/vaultlink \
            || return 1
        rm -f /opt/vaultlink/vaultlink || return 1
    fi
    if [ "$cleanup_update_armed" -eq 1 ] \
        && { [ -e /etc/vaultlink/update.conf ] || [ -L /etc/vaultlink/update.conf ]; }; then
        [ -f /etc/vaultlink/update.conf ] && [ ! -L /etc/vaultlink/update.conf ] \
            && [ "$(stat -c '%u:%g:%a' /etc/vaultlink/update.conf)" = 0:0:644 ] \
            && cmp -s "$expected_cleanup_update_config" /etc/vaultlink/update.conf \
            || return 1
        rm -f /etc/vaultlink/update.conf || return 1
    fi
    case "$reinstall_update_state" in
        present)
            [ -f /etc/vaultlink/update.conf ] && [ ! -L /etc/vaultlink/update.conf ] \
                && [ "$(stat -c '%d:%i:%u:%g:%a:%Y:%s' /etc/vaultlink/update.conf)" = \
                    "$reinstall_update_identity" ] \
                && [ "$(sha256sum /etc/vaultlink/update.conf | awk '{ print $1 }')" = \
                    "$reinstall_update_hash" ] \
                || return 1
            ;;
        absent)
            [ ! -e /etc/vaultlink/update.conf ] \
                && [ ! -L /etc/vaultlink/update.conf ] || return 1
            ;;
        unrecorded) ;;
        *) return 1 ;;
    esac
}
cleanup_attempt_marker_recovery() {
    [ "$trusted_reinstall" -eq 0 ] \
        && [ "$marker_recovery_preexisting" -eq 0 ] || return 0
    [ -e "$marker_recovery" ] || [ -L "$marker_recovery" ] || return 0

    # A fresh Arch post_install creates this persistent recovery copy before
    # it creates update.conf and the active binary. If that exact attempt is
    # rolled back by this wrapper, leaving its provenance behind would make a
    # retry look like a state-preserving reinstall. Delete it only after the
    # package and every attempt-owned mutable file are proven absent, and only
    # when the file is the exact canonical marker minted by this package.
    ! pacman -Q vaultlink >/dev/null 2>&1 \
        && [ ! -e /usr/share/vaultlink/install-method.env ] \
        && [ ! -L /usr/share/vaultlink/install-method.env ] \
        && [ ! -e /usr/lib/vaultlink/package/vaultlink ] \
        && [ ! -L /usr/lib/vaultlink/package/vaultlink ] \
        && [ ! -e /opt/vaultlink/vaultlink ] \
        && [ ! -L /opt/vaultlink/vaultlink ] \
        && [ ! -e /etc/vaultlink/update.conf ] \
        && [ ! -L /etc/vaultlink/update.conf ] \
        || return 1
    [ -f "$marker_recovery" ] && [ ! -L "$marker_recovery" ] \
        && [ "$(stat -c '%u:%g:%a' "$marker_recovery")" = 0:0:600 ] \
        && [ "$(wc -l <"$marker_recovery" | tr -d '[:space:]')" = 5 ] \
        || return 1
    expected_recovery_marker=$(printf 'FORMAT=pkg.tar.zst\nOS_ID=arch\nOS_VERSION=rolling\nARCH=x86_64\nPACKAGE_NAME=vaultlink')
    [ "$(cat "$marker_recovery")" = "$expected_recovery_marker" ] \
        || return 1
    rm -f "$marker_recovery"
}
cleanup() {
    cleanup_status=$?
    trap - 0
    trap '' 1 2 15
    cleanup_failed=0
    if [ "$cleanup_status" -ne 0 ] \
        && [ "$package_transaction_started" -eq 1 ] \
        && [ "$installation_complete" -eq 0 ] \
        && pacman -Q vaultlink >/dev/null 2>&1; then
        expected_marker=$(printf 'FORMAT=pkg.tar.zst\nOS_ID=arch\nOS_VERSION=rolling\nARCH=x86_64\nPACKAGE_NAME=vaultlink')
        if [ "$trusted_reinstall" -eq 0 ] \
            && [ -f /usr/share/vaultlink/install-method.env ] \
            && [ ! -L /usr/share/vaultlink/install-method.env ] \
            && [ "$(stat -c '%u:%g:%a' /usr/share/vaultlink/install-method.env)" = 0:0:644 ] \
            && [ "$(cat /usr/share/vaultlink/install-method.env)" = "$expected_marker" ]; then
            # This wrapper proved the marker absent before the first-install
            # transaction. If post_install minted it but later failed, revoke
            # only that attempt's provisional provenance so the signed
            # markerless cleanup path can remove the registered payload even
            # when sysusers had not completed yet.
            rm -f /usr/share/vaultlink/install-method.env
            cleanup_remove_argument=--recover-failed-install
        elif [ ! -e /usr/share/vaultlink/install-method.env ] \
            && [ ! -L /usr/share/vaultlink/install-method.env ]; then
            cleanup_remove_argument=--recover-failed-install
        elif [ -f /usr/share/vaultlink/install-method.env ] \
            && [ ! -L /usr/share/vaultlink/install-method.env ] \
            && [ "$(stat -c '%u:%g:%a' /usr/share/vaultlink/install-method.env)" = 0:0:644 ] \
            && [ "$(cat /usr/share/vaultlink/install-method.env)" = "$expected_marker" ]; then
            cleanup_remove_argument=
        else
            cleanup_failed=1
            cleanup_remove_argument=invalid
        fi
        if [ "$cleanup_remove_argument" != invalid ] \
            && [ -x /usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh ]; then
            if [ -n "$cleanup_remove_argument" ]; then
                /usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh \
                    "$cleanup_remove_argument" || cleanup_failed=1
            else
                /usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh \
                    || cleanup_failed=1
            fi
        else
            cleanup_failed=1
        fi
    fi
    if [ "$cleanup_status" -ne 0 ] && ! cleanup_created_mutable_files; then
        cleanup_failed=1
    fi
    if [ "$cleanup_status" -ne 0 ] && ! cleanup_attempt_marker_recovery; then
        cleanup_failed=1
    fi
    if [ "$cleanup_failed" -eq 0 ]; then
        rm -rf "$work"
    else
        echo "CRITICAL: rejected Arch install could not be restored to a retryable state" >&2
        echo "CRITICAL: verified package and cleanup references retained below $work" >&2
    fi
    exit "$cleanup_status"
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15
install -o root -g root -m 0600 "$package_path" "$work/package.pkg.tar.zst"
[ "$(stat -c '%d:%i:%s' "$package_path")" = "$package_source_identity" ] \
    && [ "$(sha256sum "$package_path" | awk '{ print $1 }')" = "$package_source_hash" ] \
    || fail "package source changed while it was staged"
[ "$(sha256sum "$work/package.pkg.tar.zst" | awk '{ print $1 }')" = "$package_source_hash" ] \
    || fail "staged package differs from the validated source"
package_path="$work/package.pkg.tar.zst"

bsdtar -tf "$package_path" >"$work/archive-files"
[ "$(wc -l <"$work/archive-files" | tr -d '[:space:]')" -le 128 ] \
    || fail "package contains too many entries"
awk '
    !/^[A-Za-z0-9._+\/-]+$/ || /^\// || /(^|\/)\.\.?(\/|$)/ { exit 1 }
' "$work/archive-files" || fail "package contains an unsafe path"
[ "$(sort "$work/archive-files" | uniq -d | wc -l | tr -d '[:space:]')" -eq 0 ] \
    || fail "package contains duplicate paths"
bsdtar -tvf "$package_path" | awk 'substr($0, 1, 1) !~ /^[-d]$/ { exit 1 }' \
    || fail "package contains a symlink, hardlink, or special file"

cat >"$work/expected-files" <<'EOF'
.BUILDINFO
.INSTALL
.MTREE
.PKGINFO
usr/
usr/bin/
usr/bin/vaultlink-update
usr/lib/
usr/lib/systemd/
usr/lib/systemd/system/
usr/lib/systemd/system/vaultlink-update.service
usr/lib/systemd/system/vaultlink-update.timer
usr/lib/systemd/system/vaultlink.service
usr/lib/sysusers.d/
usr/lib/sysusers.d/vaultlink.conf
usr/lib/tmpfiles.d/
usr/lib/tmpfiles.d/vaultlink.conf
usr/lib/vaultlink/
usr/lib/vaultlink/package/
usr/lib/vaultlink/package/PKGBUILD
usr/lib/vaultlink/package/builder-packages.lock
usr/lib/vaultlink/package/deploy/
usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh
usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh
usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh
usr/lib/vaultlink/package/deploy/vaultlink-rollback.sh
usr/lib/vaultlink/package/deploy/vaultlink-runtime-guard.sh
usr/lib/vaultlink/package/deploy/vaultlink-upgrade.sh
usr/lib/vaultlink/package/vaultlink
usr/lib/vaultlink/package/vaultlink.cdx.json
usr/lib/vaultlink/package/vaultlink.sha256
usr/lib/vaultlink/package/version
usr/share/
usr/share/doc/
usr/share/doc/vaultlink/
usr/share/doc/vaultlink/examples/
usr/share/doc/vaultlink/examples/config/
usr/share/doc/vaultlink/examples/config/development.toml
usr/share/doc/vaultlink/examples/config/production-reverse-proxy.toml
usr/share/doc/vaultlink/examples/config/production-standalone-letsencrypt.toml
usr/share/doc/vaultlink/examples/config/production-standalone-tls.toml
usr/share/doc/vaultlink/examples/deploy/
usr/share/doc/vaultlink/examples/deploy/Caddyfile
usr/share/doc/vaultlink/examples/deploy/mnt-storage.mount.example
usr/share/doc/vaultlink/examples/deploy/vaultlink-external-proxy-network.conf
usr/share/doc/vaultlink/examples/deploy/vaultlink-external-storage.conf
usr/share/doc/vaultlink/examples/deploy/vaultlink-standalone-capability.conf
usr/share/doc/vaultlink/examples/deploy/vaultlink-update.conf.example
usr/share/libalpm/
usr/share/libalpm/hooks/
usr/share/libalpm/hooks/vaultlink-remove.hook
usr/share/licenses/
usr/share/licenses/vaultlink/
usr/share/licenses/vaultlink/LICENSE
usr/share/vaultlink/
usr/share/vaultlink/minisign.pub
usr/share/vaultlink/update.conf.example
EOF
sort "$work/archive-files" >"$work/archive-files.sorted"
[ "$(sha256sum "$work/expected-files" | awk '{ print $1 }')" = \
    "$(sha256sum "$work/archive-files.sorted" | awk '{ print $1 }')" ] \
    || fail "package archive inventory differs from the reviewed allowlist"

metadata_root="$work/metadata-root"
install -d -o root -g root -m 0700 "$metadata_root"
bsdtar --no-same-owner -xpf "$package_path" -C "$metadata_root" \
    || fail "package could not be extracted for metadata verification"
[ -z "$(find "$metadata_root" -type l -o ! -type d ! -type f | sed -n '1p')" ] \
    || fail "extracted package contains a link or special file"

cp "$metadata_root/.PKGINFO" "$work/PKGINFO"
[ "$(sed -n 's/^pkgname = //p' "$work/PKGINFO")" = vaultlink ] \
    || fail "unexpected package name"
package_version=$(sed -n 's/^pkgver = \(.*\)-1$/\1/p' "$work/PKGINFO")
printf '%s\n' "$package_version" \
    | grep -E -q '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' \
    || fail "package version is not strict stable SemVer"
[ "$package_asset_name" = "vaultlink-$package_version-1-x86_64.pkg.tar.zst" ] \
    || fail "package asset name does not exactly match its metadata version"
[ "$(sed -n 's/^arch = //p' "$work/PKGINFO")" = x86_64 ] \
    || fail "package architecture is not x86_64"
[ "$(uname -m)" = x86_64 ] || fail "Arch package requires an x86_64 host"
arch_builddate=$(sed -n 's/^builddate = //p' "$work/PKGINFO")
case "$arch_builddate" in ''|*[!0-9]*) fail "invalid Arch build date" ;; esac
arch_package_size=$(du -sb "$metadata_root/usr" | awk '{ print $1 }')
actual_binary_hash=$(sha256sum \
    "$metadata_root/usr/lib/vaultlink/package/vaultlink" | awk '{ print $1 }')
packaged_pkgbuild="$metadata_root/usr/lib/vaultlink/package/PKGBUILD"
packaged_builder_lock="$metadata_root/usr/lib/vaultlink/package/builder-packages.lock"
[ -f "$packaged_pkgbuild" ] && [ ! -L "$packaged_pkgbuild" ] \
    && [ "$(stat -c '%u:%g:%a' "$packaged_pkgbuild")" = 0:0:644 ] \
    || fail "packaged Arch PKGBUILD is unsafe"
[ -f "$packaged_builder_lock" ] && [ ! -L "$packaged_builder_lock" ] \
    && [ "$(stat -c '%u:%g:%a' "$packaged_builder_lock")" = 0:0:644 ] \
    || fail "packaged Arch builder lock is unsafe"
awk 'NF != 2 || $1 !~ /^[A-Za-z0-9@._+-]+$/ \
        || $2 !~ /^[A-Za-z0-9@._+:-]+$/ { exit 1 }' \
    "$packaged_builder_lock" \
    || fail "Arch builder package lock contains unsafe records"
LC_ALL=C sort -c -u "$packaged_builder_lock" \
    || fail "Arch builder package lock must be sorted and unique"
arch_buildtool_package_version=$(awk '$1 == "pacman" { print $2 }' \
    "$packaged_builder_lock")
arch_fakeroot_package_version=$(awk '$1 == "fakeroot" { print $2 }' \
    "$packaged_builder_lock")
[ "$(printf '%s\n' "$arch_buildtool_package_version" | grep -c . || true)" -eq 1 ] \
    && [ "$(printf '%s\n' "$arch_fakeroot_package_version" | grep -c . || true)" -eq 1 ] \
    || fail "Arch builder lock must contain pacman and fakeroot exactly once"
arch_buildtool_version=${arch_buildtool_package_version#*:}
arch_buildtool_version=${arch_buildtool_version%-*}
arch_buildtool_version=${arch_buildtool_version%%.r[0-9]*}
arch_fakeroot_version=${arch_fakeroot_package_version#*:}
arch_fakeroot_version=${arch_fakeroot_version%-*}
cat >"$work/expected-PKGINFO" <<EOF
# Generated by makepkg $arch_buildtool_version
# using fakeroot version $arch_fakeroot_version
pkgname = vaultlink
pkgbase = vaultlink
xdata = pkgtype=pkg
pkgver = $package_version-1
pkgdesc = Secure file sharing for an existing Linux mountpoint
url = https://github.com/alexhaberl/VaultLink
builddate = $arch_builddate
packager = VaultLink maintainers <noreply@vaultlink.example>
size = $arch_package_size
arch = x86_64
license = MIT
depend = bash
depend = ca-certificates
depend = coreutils
depend = curl
depend = diffutils
depend = findutils
depend = gawk
depend = gcc-libs
depend = glibc
depend = grep
depend = gzip
depend = libarchive
depend = minisign
depend = sed
depend = sqlite
depend = systemd
depend = tar
depend = util-linux
depend = zstd
optdepend = cifs-utils: SMB 3.1.1 storage provisioning
EOF
cmp -s "$work/expected-PKGINFO" "$work/PKGINFO" \
    || fail "Arch .PKGINFO fields or values differ from the reviewed template"
sed -n 's/^depend = //p' "$work/PKGINFO" >"$work/dependencies"
cat >"$work/expected-dependencies" <<'EOF'
bash
ca-certificates
coreutils
curl
diffutils
findutils
gawk
gcc-libs
glibc
grep
gzip
libarchive
minisign
sed
sqlite
systemd
tar
util-linux
zstd
EOF
[ "$(sha256sum "$work/dependencies" | awk '{ print $1 }')" = \
    "$(sha256sum "$work/expected-dependencies" | awk '{ print $1 }')" ] \
    || fail "package dependencies differ from the reviewed allowlist"
[ "$(sed -n 's/^optdepend = //p' "$work/PKGINFO")" = \
    'cifs-utils: SMB 3.1.1 storage provisioning' ] \
    || fail "cifs-utils must be the sole optional dependency"

arch_pkgbuild_sha256=$(sha256sum "$packaged_pkgbuild" | awk '{ print $1 }')
cat >"$work/expected-BUILDINFO" <<EOF
format = 2
pkgname = vaultlink
pkgbase = vaultlink
pkgver = $package_version-1
pkgarch = x86_64
pkgbuild_sha256sum = $arch_pkgbuild_sha256
packager = VaultLink maintainers <noreply@vaultlink.example>
builddate = $arch_builddate
builddir = /build/vaultlink-package
startdir = /build/vaultlink-package
buildtool = makepkg
buildtoolver = $arch_buildtool_version
buildenv = !distcc
buildenv = color
buildenv = !ccache
buildenv = check
buildenv = !sign
options = strip
options = docs
options = !libtool
options = !staticlibs
options = emptydirs
options = zipman
options = purge
options = debug
options = lto
EOF
sed -n 's/^installed = //p' "$metadata_root/.BUILDINFO" \
    >"$work/actual-installed"
[ "$(wc -l <"$work/actual-installed" | tr -d '[:space:]')" = \
    "$(wc -l <"$packaged_builder_lock" | tr -d '[:space:]')" ] \
    || fail "Arch BUILDINFO installed closure count differs from builder lock"
: >"$work/expected-installed"
while read -r installed_name installed_version; do
    installed_matches=$(grep -F -x \
        -e "$installed_name-$installed_version-x86_64" \
        -e "$installed_name-$installed_version-any" \
        "$work/actual-installed" || true)
    [ "$(printf '%s\n' "$installed_matches" | grep -c . || true)" -eq 1 ] \
        || fail "Arch BUILDINFO does not bind the exact builder closure"
    printf '%s\n' "$installed_matches" >>"$work/expected-installed"
done <"$packaged_builder_lock"
cmp -s "$work/expected-installed" "$work/actual-installed" \
    || fail "Arch BUILDINFO installed closure is non-canonical"
sed 's/^/installed = /' "$work/expected-installed" >>"$work/expected-BUILDINFO"
cmp -s "$work/expected-BUILDINFO" "$metadata_root/.BUILDINFO" \
    || fail "Arch .BUILDINFO differs from the real pinned makepkg environment"

gzip -t "$metadata_root/.MTREE" || fail "Arch .MTREE is not valid gzip data"
gzip -dc "$metadata_root/.MTREE" >"$work/package.mtree"
gzip -n <"$work/package.mtree" >"$work/canonical.MTREE"
cmp -s "$work/canonical.MTREE" "$metadata_root/.MTREE" \
    || fail "Arch .MTREE compression is not canonical"
(
    cd "$metadata_root"
    bsdtar --format=mtree \
        --options='!all,use-set,type,uid,gid,mode,time,size,sha256,link' \
        --exclude .MTREE -cf - .
) >"$work/recomputed-package.mtree" \
    || fail "Arch .MTREE payload reconstruction failed"
[ "$(grep -c '^\. ' "$work/package.mtree" || true)" -eq 0 ] \
    || fail "Arch .MTREE must not contain an unowned package-root record"
sed '/^\. /d' "$work/package.mtree" >"$work/package-body.mtree"
sed '/^\. /d' "$work/recomputed-package.mtree" \
    >"$work/recomputed-package-body.mtree"
cmp -s "$work/package-body.mtree" "$work/recomputed-package-body.mtree" \
    || fail "Arch .MTREE does not match payload metadata and hashes"
bsdtar -tf "$metadata_root/.MTREE" \
    | sed -e 's|^\./||' -e 's|/$||' -e '/^$/d' -e '/^\.$/d' \
    | sort >"$work/mtree-files"
sed -e 's|/$||' -e '/^\.MTREE$/d' "$work/archive-files" | sort \
    >"$work/expected-mtree-files"
cmp -s "$work/expected-mtree-files" "$work/mtree-files" \
    || fail "Arch .MTREE inventory differs from the package archive"

: >"$work/missing-dependencies"
while IFS= read -r dependency; do
    if ! pacman -T "$dependency" >"$work/dependency-check" 2>&1; then
        cat "$work/dependency-check" >>"$work/missing-dependencies"
    fi
done <"$work/expected-dependencies"
if [ -s "$work/missing-dependencies" ]; then
    tr '\n' ' ' <"$work/missing-dependencies" >&2
    printf '\n' >&2
    fail "all package dependencies must already be installed; network resolution is forbidden"
fi

embedded_installer=usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh
bsdtar -xOf "$package_path" "$embedded_installer" >"$work/embedded-installer"
[ "$(stat -c '%d:%i:%s' "$0")" = "$installer_identity" ] \
    && [ "$(sha256sum "$0" | awk '{ print $1 }')" = "$installer_hash" ] \
    || fail "installer changed while it was running"
[ "$installer_hash" = \
    "$(sha256sum "$work/embedded-installer" | awk '{ print $1 }')" ] \
    || fail "installer does not belong to the selected signed package"
embedded_remover=usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh
bsdtar -xOf "$package_path" "$embedded_remover" >"$work/embedded-remover"
[ -s "$work/embedded-remover" ] \
    || fail "package lacks the signed failed-install recovery/removal wrapper"
bsdtar -xOf "$package_path" usr/share/libalpm/hooks/vaultlink-remove.hook \
    >"$work/vaultlink-remove.hook"
cat >"$work/expected-remove.hook" <<'EOF'
[Trigger]
Operation = Remove
Type = Package
Target = vaultlink

[Action]
Description = Verifying VaultLink is inactive before removal
When = PreTransaction
Exec = /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh preremove-preflight pkg.tar.zst arch rolling x86_64 vaultlink remove
AbortOnFail
EOF
cmp -s "$work/expected-remove.hook" "$work/vaultlink-remove.hook" \
    || fail "Arch removal hook differs from the reviewed policy"
bsdtar -xOf "$package_path" usr/lib/vaultlink/package/version >"$work/version"
[ "$(cat "$work/version")" = "$package_version" ] \
    || fail "package version metadata mismatch"
bsdtar -xOf "$package_path" usr/lib/vaultlink/package/vaultlink.sha256 \
    >"$work/vaultlink.sha256"
checksum_line=$(cat "$work/vaultlink.sha256")
[ "$(wc -l <"$work/vaultlink.sha256" | tr -d '[:space:]')" = 1 ] \
    || fail "candidate checksum metadata must contain exactly one line"
expected_binary_hash=${checksum_line%%  *}
[ "${#expected_binary_hash}" -eq 64 ] \
    || fail "candidate checksum must contain exactly 64 hexadecimal characters"
[ "$checksum_line" = "$actual_binary_hash  vaultlink" ] \
    || fail "candidate checksum metadata is not canonical"
[ "$actual_binary_hash" = "$expected_binary_hash" ] \
    || fail "candidate payload does not match its package checksum"
embedded_key_hash=$(
    bsdtar -xOf "$package_path" usr/share/vaultlink/minisign.pub \
        | sha256sum | awk '{ print $1 }'
)

lifecycle=usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh
bsdtar -xOf "$package_path" "$lifecycle" >"$work/vaultlink-package-lifecycle.sh"
chmod 0700 "$work/vaultlink-package-lifecycle.sh"
if [ -e /usr/share/vaultlink/install-method.env ] \
    || [ -L /usr/share/vaultlink/install-method.env ]; then
    initial_install_mode=reinstall
else
    initial_install_mode=fresh
fi
"$work/vaultlink-package-lifecycle.sh" \
    preinstall pkg.tar.zst arch rolling x86_64 vaultlink "$initial_install_mode"

[ ! -e /opt/vaultlink/vaultlink ] && [ ! -L /opt/vaultlink/vaultlink ] \
    || fail "package installation requires the active binary to be absent"
if [ -e /usr/share/vaultlink/install-method.env ] \
    || [ -L /usr/share/vaultlink/install-method.env ]; then
    # The lifecycle preflight has already validated the exact marker, host,
    # and retained service identity. Its presence distinguishes a supported
    # reinstall after removal from a markerless first installation.
    trusted_reinstall=1
fi
if [ -e /etc/vaultlink/update.conf ] || [ -L /etc/vaultlink/update.conf ]; then
    [ "$trusted_reinstall" -eq 1 ] \
        || fail "first installation requires update.conf to be absent"
    [ -f /etc/vaultlink/update.conf ] && [ ! -L /etc/vaultlink/update.conf ] \
        || fail "retained update.conf must be a regular file"
    reinstall_update_state=present
    reinstall_update_identity=$(stat -c '%d:%i:%u:%g:%a:%Y:%s' \
        /etc/vaultlink/update.conf)
    reinstall_update_hash=$(sha256sum /etc/vaultlink/update.conf | awk '{ print $1 }')
else
    reinstall_update_state=absent
fi
install -o root -g root -m 0600 \
    "$metadata_root/usr/lib/vaultlink/package/vaultlink" \
    "$work/expected-cleanup-candidate"
install -o root -g root -m 0600 \
    "$metadata_root/usr/share/vaultlink/update.conf.example" \
    "$work/expected-cleanup-update.conf"
expected_cleanup_candidate=$work/expected-cleanup-candidate
expected_cleanup_update_config=$work/expected-cleanup-update.conf
cleanup_live_armed=1
[ "$reinstall_update_state" = present ] || cleanup_update_armed=1

package_transaction_started=1
pacman -U --noconfirm -- "$package_path"
pacman -Q vaultlink | grep -F -x -q "vaultlink $package_version-1" \
    || fail "pacman did not register the exact installed version"
[ "$(stat -c '%u:%g:%a' /usr/lib/vaultlink/package/vaultlink)" = 0:0:755 ] \
    || fail "installed candidate ownership or mode is unsafe"
[ "$(stat -c '%u:%g:%a' /usr/share/vaultlink/minisign.pub)" = 0:0:644 ] \
    || fail "installed public key ownership or mode is unsafe"
[ "$(sha256sum /usr/share/vaultlink/minisign.pub | awk '{ print $1 }')" = \
    "$embedded_key_hash" ] \
    || fail "installed public key differs from the signed package payload"
(
    cd /usr/lib/vaultlink/package
    sha256sum -c vaultlink.sha256 >/dev/null
) || fail "installed candidate checksum is invalid"
[ -x /usr/bin/vaultlink-update ] && [ ! -L /usr/bin/vaultlink-update ] \
    || fail "Arch updater payload is not installed below /usr/bin"
[ -x /usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh ] \
    && [ ! -L /usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh ] \
    && cmp -s "$work/embedded-remover" \
        /usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh \
    || fail "installed removal wrapper differs from the signed package"
[ -x /usr/sbin/vaultlink-update ] \
    || fail "Arch merged-/usr alias does not expose the updater to its unit"
[ -x /opt/vaultlink/vaultlink ] && [ ! -L /opt/vaultlink/vaultlink ] \
    || fail "fresh package did not create the active copy"
[ "$(timeout --kill-after=2 5 runuser -u vaultlink -- /opt/vaultlink/vaultlink --version)" = "$package_version" ] \
    || fail "installed active copy reports the wrong version"
expected_marker=$(printf 'FORMAT=pkg.tar.zst\nOS_ID=arch\nOS_VERSION=rolling\nARCH=x86_64\nPACKAGE_NAME=vaultlink')
actual_marker=$(cat /usr/share/vaultlink/install-method.env)
[ "$actual_marker" = "$expected_marker" ] \
    || fail "installed package marker is invalid"
grep '^usr/' "$work/expected-files" | sed 's|^|/|' >"$work/expected-installed-files"
pacman -Qql vaultlink | sort >"$work/actual-installed-files"
[ "$(sha256sum "$work/expected-installed-files" | awk '{ print $1 }')" = \
    "$(sha256sum "$work/actual-installed-files" | awk '{ print $1 }')" ] \
    || fail "pacman package-owned inventory differs from the reviewed archive"
if command -v systemctl >/dev/null; then
    systemctl --quiet is-active vaultlink.service 2>/dev/null \
        && fail "initial package installation started VaultLink"
    systemctl --quiet is-active vaultlink-update.timer 2>/dev/null \
        && fail "initial package installation started the update timer"
fi
find /etc/systemd/system -type l \
    \( -name vaultlink.service -o -name vaultlink-update.timer \) -print \
    | grep -q . && fail "initial package installation enabled a VaultLink unit"
case "$reinstall_update_state" in
    present)
        [ -f /etc/vaultlink/update.conf ] && [ ! -L /etc/vaultlink/update.conf ] \
            && [ "$(stat -c '%d:%i:%u:%g:%a:%Y:%s' /etc/vaultlink/update.conf)" = \
                "$reinstall_update_identity" ] \
            && [ "$(sha256sum /etc/vaultlink/update.conf | awk '{ print $1 }')" = \
                "$reinstall_update_hash" ] \
            || fail "reinstallation changed retained update.conf"
        ;;
    absent)
        if [ "$trusted_reinstall" -eq 1 ]; then
            [ ! -e /etc/vaultlink/update.conf ] \
                && [ ! -L /etc/vaultlink/update.conf ] \
                || fail "reinstallation did not preserve absent update.conf"
        fi
        ;;
esac

installation_complete=1
trap - 0 1 2 15
rm -rf "$work"
echo "VaultLink $package_version Arch initial installation completed"
