#!/bin/sh
# Compound guards intentionally fail closed; mock functions are reached via
# the sourced lifecycle and traps rather than direct calls in this file.
# shellcheck disable=SC2015,SC2317
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CDPATH=
LC_ALL=C
LANG=C
export PATH CDPATH LC_ALL LANG
umask 077

fail() {
    echo "native package container smoke failed: $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "the package smoke must run as root"
[ -f /.dockerenv ] || fail "the destructive package smoke must run in a disposable Docker container"
[ "$#" -eq 3 ] || {
    echo "usage: package-container-smoke.sh TARGET_ID VERSION PACKAGE" >&2
    exit 64
}
target_id=$1
version=$2
package=$3
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
cd "$repo_root"
[ -f "$package" ] && [ ! -L "$package" ] && [ -s "$package" ] \
    || fail "package is missing, empty, or a symlink"

target_get() {
    python3 tools/package-targets.py get "$target_id" "$1" --allow-unprovisioned
}
os_id=$(target_get distribution)
os_version=$(target_get version)
package_format=$(target_get package_format)
package_arch=$(target_get package_arch)
if [ "$os_id" = arch ]; then
    [ "$os_version" = rolling ] || fail "unexpected Arch target version"
fi

marker=/usr/share/vaultlink/install-method.env
candidate=/usr/lib/vaultlink/package/vaultlink
live_binary=/opt/vaultlink/vaultlink
config=/etc/vaultlink/config.toml
update_config=/etc/vaultlink/update.conf
database=/var/lib/vaultlink/data.sqlite
keyring=/var/lib/vaultlink/secrets.keyring
backup_probe=/var/lib/vaultlink-backups/package-smoke/evidence
arch_initial_installer=
arch_unsafe_installer=
arch_package_stage=
arch_pacman_db_backup=
arch_pacman_binary_backup=
identity_backup_dir=
systemctl_backup=
systemd_run_dir_created=0
arch_abort_hook=
lock_attack_work=

cleanup() {
    if [ -n "$arch_initial_installer" ]; then
        rm -f "$arch_initial_installer"
    fi
    if [ -n "$arch_unsafe_installer" ]; then
        rm -f "$arch_unsafe_installer"
    fi
    if [ -n "$arch_package_stage" ] && [ -d "$arch_package_stage" ]; then
        rm -f "$arch_package_stage/$(basename "$package")"
        rmdir "$arch_package_stage" 2>/dev/null || :
    fi
    if [ -n "$arch_pacman_db_backup" ] \
        && [ -d "$arch_pacman_db_backup" ] \
        && rmdir /var/lib/pacman/local 2>/dev/null; then
        mv "$arch_pacman_db_backup" /var/lib/pacman/local
    fi
    if [ -n "$arch_pacman_binary_backup" ] \
        && [ -f "$arch_pacman_binary_backup" ]; then
        rm -f /usr/bin/pacman
        mv "$arch_pacman_binary_backup" /usr/bin/pacman
    fi
    if [ -n "$identity_backup_dir" ] && [ -d "$identity_backup_dir" ]; then
        for identity_file in passwd group shadow gshadow; do
            if [ -f "$identity_backup_dir/$identity_file" ]; then
                cp -p "$identity_backup_dir/$identity_file" "/etc/$identity_file"
            fi
        done
        rm -rf "$identity_backup_dir"
    fi
    if [ -n "$systemctl_backup" ] && [ -f "$systemctl_backup" ]; then
        rm -f /usr/bin/systemctl
        mv "$systemctl_backup" /usr/bin/systemctl
    fi
    if [ "$systemd_run_dir_created" -eq 1 ]; then
        rmdir /run/systemd/system 2>/dev/null || :
    fi
    if [ -n "$arch_abort_hook" ]; then
        rm -f "$arch_abort_hook"
    fi
    if [ -n "$lock_attack_work" ]; then
        case "$lock_attack_work" in
            /tmp/vaultlink-lock-attack.*) rm -rf -- "$lock_attack_work" ;;
        esac
    fi
}
trap cleanup 0 1 2 15

expected_marker() {
    printf 'FORMAT=%s\nOS_ID=%s\nOS_VERSION=%s\nARCH=%s\nPACKAGE_NAME=vaultlink\n' \
        "$package_format" "$os_id" "$os_version" "$package_arch"
}

assert_marker() {
    [ -f "$marker" ] && [ ! -L "$marker" ] || fail "installation marker is missing"
    [ "$(stat -c '%u:%g:%a' "$marker")" = 0:0:644 ] \
        || fail "installation marker ownership or mode is unsafe"
    actual=$(cat "$marker")
    expected=$(expected_marker)
    [ "$actual" = "$expected" ] || fail "installation marker content mismatch"
}

package_is_installed() {
    case "$package_format" in
        deb) dpkg-query -W -f='${db:Status-Status}' vaultlink 2>/dev/null | grep -F -x -q installed ;;
        rpm) rpm -q vaultlink >/dev/null 2>&1 ;;
        pkg.tar.zst) pacman -Q vaultlink >/dev/null 2>&1 ;;
    esac
}

package_install() {
    case "$package_format" in
        deb) dpkg -i "$package" ;;
        rpm) rpm -Uvh --replacepkgs "$package" ;;
        pkg.tar.zst) pacman -U --noconfirm "$package" ;;
    esac
}

package_initial_install() {
    if [ "$package_format" = pkg.tar.zst ]; then
        "$arch_initial_installer" "$package"
    else
        package_install
    fi
}

package_upgrade() {
    if [ "$package_format" = pkg.tar.zst ]; then
        /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh \
            preinstall pkg.tar.zst arch rolling x86_64 vaultlink upgrade
    fi
    package_install
}

package_remove() {
    case "$package_format" in
        deb) dpkg -r vaultlink ;;
        rpm) rpm -e vaultlink ;;
        pkg.tar.zst)
            /usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh
            ;;
    esac
}

case "$package_format" in
    deb)
        command -v dpkg >/dev/null || fail "dpkg is required"
        ;;
    rpm)
        command -v rpm >/dev/null || fail "rpm is required"
        ;;
    pkg.tar.zst)
        command -v pacman >/dev/null || fail "pacman is required"
        command -v bsdtar >/dev/null || fail "bsdtar is required"
        original_package=$package
        arch_package_stage=$(mktemp -d /var/tmp/vaultlink-package-smoke.XXXXXXXX)
        chmod 0700 "$arch_package_stage"
        install -o root -g root -m 0600 "$original_package" \
            "$arch_package_stage/$(basename "$original_package")"
        package="$arch_package_stage/$(basename "$original_package")"
        arch_initial_installer=$(mktemp /var/tmp/vaultlink-package-install.XXXXXXXX)
        bsdtar -xOf "$package" \
            usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh \
            >"$arch_initial_installer"
        chown root:root "$arch_initial_installer"
        chmod 0700 "$arch_initial_installer"
        for unsafe_mode in 0777 0722; do
            arch_unsafe_installer=$(mktemp /var/tmp/vaultlink-package-install-unsafe.XXXXXXXX)
            install -o root -g root -m "$unsafe_mode" \
                "$arch_initial_installer" "$arch_unsafe_installer"
            unsafe_log=$(mktemp "${TMPDIR:-/tmp}/vaultlink-installer-mode.XXXXXXXX")
            if "$arch_unsafe_installer" "$package" >"$unsafe_log" 2>&1; then
                fail "Arch installer accepted unsafe mode $unsafe_mode"
            fi
            grep -F -q 'must not be group- or world-writable' "$unsafe_log" \
                || { cat "$unsafe_log" >&2; fail "Arch installer mode rejection was not explicit"; }
            rm -f "$unsafe_log" "$arch_unsafe_installer"
            arch_unsafe_installer=
        done
        unsafe_parent=/var/tmp/vaultlink-untrusted-parent.$$
        install -d -o 65534 -g 65534 -m 0700 "$unsafe_parent"
        install -o root -g root -m 0600 "$package" "$unsafe_parent/$(basename "$package")"
        unsafe_log=$(mktemp "${TMPDIR:-/tmp}/vaultlink-installer-parent.XXXXXXXX")
        if "$arch_initial_installer" "$unsafe_parent/$(basename "$package")" \
            >"$unsafe_log" 2>&1; then
            fail "Arch installer accepted a package below an untrusted parent"
        fi
        grep -F -q 'path parent must be owned by root' "$unsafe_log" \
            || { cat "$unsafe_log" >&2; fail "Arch installer parent rejection was not explicit"; }
        rm -f "$unsafe_log" "$unsafe_parent/$(basename "$package")"
        rmdir "$unsafe_parent"
        ;;
    *) fail "unsupported package format: $package_format" ;;
esac
command -v sqlite3 >/dev/null || fail "sqlite3 is required"
for identity_command in getent id; do
    command -v "$identity_command" >/dev/null \
        || fail "$identity_command is required for the identity-negative smoke"
done
package_is_installed && fail "container is not clean: vaultlink is already installed"
[ ! -e "$marker" ] && [ ! -L "$marker" ] \
    || fail "container is not clean: installation marker exists"

# Predictable files below Debian's root:root mode-1777 /run/lock can be
# pre-created and replaced by their unprivileged owner. VaultLink therefore
# uses a private root-only directory directly below /run. Prove the original
# attack class, unsafe path shapes, post-flock inode binding, and the valid
# inherited-open-file contract before any package transaction starts.
lock_directory=/run/vaultlink-locks
lock_update=$lock_directory/update.lock
lock_maintenance=$lock_directory/maintenance.lock
lock_install=$lock_directory/package-install.lock
lifecycle_source=$repo_root/packaging/vaultlink-package-lifecycle.sh
run_lock_prepare_probe() {
    probe_lock_path=$1
    sh -eu -c '
        VAULTLINK_PACKAGE_LIFECYCLE_EMBEDDED=1
        export VAULTLINK_PACKAGE_LIFECYCLE_EMBEDDED
        . "$1"
        package_prepare_lock_file "$2"
    ' sh "$lifecycle_source" "$probe_lock_path"
}
[ ! -e "$lock_directory" ] && [ ! -L "$lock_directory" ] \
    || fail "container is not clean: VaultLink lock directory exists"
install -d -o root -g root -m 0700 "$lock_directory"
for lock_probe_file in "$lock_update" "$lock_maintenance" "$lock_install"; do
    install -o root -g root -m 0600 /dev/null "$lock_probe_file"
done
lock_update_identity=$(stat -Lc '%d:%i:%u:%g:%a' "$lock_update")
if runuser -u nobody -- sh -c \
    ': > /run/vaultlink-locks/attacker-precreated.lock' >/dev/null 2>&1; then
    fail "unprivileged user pre-created a file in the private lock directory"
fi
if runuser -u nobody -- rm -f "$lock_update" >/dev/null 2>&1; then
    fail "unprivileged user replaced a root-owned VaultLink lock"
fi
[ ! -e "$lock_directory/attacker-precreated.lock" ] \
    && [ "$(stat -Lc '%d:%i:%u:%g:%a' "$lock_update")" = \
        "$lock_update_identity" ] \
    || fail "unprivileged lock precreation/replacement changed protected state"

lock_attack_work=$(mktemp -d /tmp/vaultlink-lock-attack.XXXXXXXX)
chmod 0700 "$lock_attack_work"
for lock_probe_file in "$lock_update" "$lock_maintenance" "$lock_install"; do
    rm -f "$lock_probe_file"
done
rmdir "$lock_directory"
ln -s "$lock_attack_work" "$lock_directory"
lock_attack_log=$lock_attack_work/symlink-directory.log
if run_lock_prepare_probe "$lock_update" >"$lock_attack_log" 2>&1; then
    fail "lifecycle accepted a symlink lock directory"
fi
grep -F -q 'VaultLink lock directory is unsafe' "$lock_attack_log" \
    || { cat "$lock_attack_log" >&2; fail "symlink lock-directory rejection was not explicit"; }
rm -f "$lock_directory"
install -d -o root -g root -m 0755 "$lock_directory"
lock_attack_log=$lock_attack_work/unsafe-directory-mode.log
if run_lock_prepare_probe "$lock_update" >"$lock_attack_log" 2>&1; then
    fail "lifecycle accepted a non-private lock directory"
fi
grep -F -q 'VaultLink lock directory is unsafe' "$lock_attack_log" \
    || { cat "$lock_attack_log" >&2; fail "lock-directory mode rejection was not explicit"; }
chmod 0700 "$lock_directory"
install -o root -g root -m 0600 /dev/null "$lock_attack_work/symlink-target"
ln -s "$lock_attack_work/symlink-target" "$lock_update"
lock_attack_log=$lock_attack_work/symlink-file.log
if run_lock_prepare_probe "$lock_update" >"$lock_attack_log" 2>&1; then
    fail "lifecycle accepted a symlink lock file"
fi
grep -F -q 'VaultLink lock file is unsafe' "$lock_attack_log" \
    || { cat "$lock_attack_log" >&2; fail "symlink lock-file rejection was not explicit"; }
rm -f "$lock_update"
install -o root -g root -m 0666 /dev/null "$lock_update"
lock_attack_log=$lock_attack_work/unsafe-file-mode.log
if run_lock_prepare_probe "$lock_update" >"$lock_attack_log" 2>&1; then
    fail "lifecycle accepted a writable lock file"
fi
grep -F -q 'VaultLink lock file is unsafe' "$lock_attack_log" \
    || { cat "$lock_attack_log" >&2; fail "lock-file mode rejection was not explicit"; }
rm -f "$lock_update"
install -o root -g root -m 0600 /dev/null "$lock_update"
sh -eu -c '
    VAULTLINK_PACKAGE_LIFECYCLE_EMBEDDED=1
    export VAULTLINK_PACKAGE_LIFECYCLE_EMBEDDED
    . "$1"
    exec 6>"$2"
    flock -n 6
    mv "$2" "$3/original-update.lock"
    install -o root -g root -m 0600 /dev/null "$2"
    ! package_lock_is_inherited 6 "$2"
' sh "$lifecycle_source" "$lock_update" "$lock_attack_work" \
    || fail "inherited lock validation accepted an FD/path inode swap"
rm -f "$lock_update"
mv "$lock_attack_work/original-update.lock" "$lock_update"
sh -eu -c '
    VAULTLINK_PACKAGE_LIFECYCLE_EMBEDDED=1
    export VAULTLINK_PACKAGE_LIFECYCLE_EMBEDDED
    . "$1"
    exec 6>"$2"
    flock -n 6
    package_lock_is_inherited 6 "$2"
' sh "$lifecycle_source" "$lock_update" \
    || fail "valid inherited VaultLink lock descriptor was rejected"
rm -rf -- "$lock_attack_work"
lock_attack_work=

if [ "$package_format" = pkg.tar.zst ]; then
    # Exercise the supported installer's offline dependency preflight against
    # an intentionally empty local Pacman database. The signed package is
    # inspected, but pacman -U must never be reached or mutate the filesystem.
    [ -d /var/lib/pacman/local ] || fail "Pacman local database is unavailable"
    arch_pacman_db_backup=/var/lib/pacman/local.vaultlink-smoke.$$
    [ ! -e "$arch_pacman_db_backup" ] \
        || fail "Pacman smoke backup path already exists"
    mv /var/lib/pacman/local "$arch_pacman_db_backup"
    install -d -o root -g root -m 0755 /var/lib/pacman/local
    dependency_log=$(mktemp "${TMPDIR:-/tmp}/vaultlink-dependency-preflight.XXXXXXXX")
    if "$arch_initial_installer" "$package" >"$dependency_log" 2>&1; then
        fail "Arch initial installer skipped its offline dependency preflight"
    fi
    grep -F -q 'all package dependencies must already be installed; network resolution is forbidden' \
        "$dependency_log" \
        || { cat "$dependency_log" >&2; fail "Arch dependency rejection was not explicit"; }
    package_is_installed \
        && fail "Arch dependency preflight reached the package transaction"
    [ ! -e "$marker" ] && [ ! -L "$marker" ] \
        || fail "Arch dependency preflight created an installation marker"
    unexpected_pacman_state=$(find /var/lib/pacman/local -mindepth 1 \
        ! -name ALPM_DB_VERSION -print)
    [ -z "$unexpected_pacman_state" ] \
        || fail "Arch dependency preflight created package database entries"
    if [ -e /var/lib/pacman/local/ALPM_DB_VERSION ] \
        || [ -L /var/lib/pacman/local/ALPM_DB_VERSION ]; then
        [ -f /var/lib/pacman/local/ALPM_DB_VERSION ] \
            && [ ! -L /var/lib/pacman/local/ALPM_DB_VERSION ] \
            || fail "Pacman database format marker is unsafe"
        rm -f /var/lib/pacman/local/ALPM_DB_VERSION
    fi
    rmdir /var/lib/pacman/local \
        || fail "Arch dependency preflight mutated the empty Pacman database"
    mv "$arch_pacman_db_backup" /var/lib/pacman/local
    arch_pacman_db_backup=
    rm -f "$dependency_log"
fi

# systemd-sysusers deliberately preserves existing accounts. Exercise every
# security-relevant identity invariant before any package manager can unpack
# code or grant package provenance. The container is disposable, and the
# account databases are restored byte-for-byte between probes.
identity_backup_dir=$(mktemp -d /var/tmp/vaultlink-identity-db.XXXXXXXX)
for identity_file in passwd group shadow gshadow; do
    [ -f "/etc/$identity_file" ] || fail "/etc/$identity_file is unavailable"
    cp -p "/etc/$identity_file" "$identity_backup_dir/$identity_file"
done
case "$os_id" in
    debian|ubuntu|fedora) identity_nologin=/usr/sbin/nologin ;;
    arch) identity_nologin=/usr/bin/nologin ;;
    *) fail "unsupported identity target: $os_id" ;;
esac
[ -x "$identity_nologin" ] && [ ! -L "$identity_nologin" ] \
    || fail "expected distro nologin path is unavailable or unsafe"
identity_uid=699
while getent passwd "$identity_uid" >/dev/null 2>&1 \
    || getent group "$identity_uid" >/dev/null 2>&1; do
    identity_uid=$((identity_uid + 1))
    [ "$identity_uid" -lt 900 ] \
        || fail "no free system UID/GID is available for identity probes"
done
identity_extra_gid=$((identity_uid + 1))
while getent passwd "$identity_extra_gid" >/dev/null 2>&1 \
    || getent group "$identity_extra_gid" >/dev/null 2>&1; do
    identity_extra_gid=$((identity_extra_gid + 1))
    [ "$identity_extra_gid" -lt 950 ] \
        || fail "no free supplementary GID is available for identity probes"
done

identity_restore() {
    for identity_file in passwd group shadow gshadow; do
        cp -p "$identity_backup_dir/$identity_file" "/etc/$identity_file"
    done
}

identity_add_passwd() {
    identity_test_uid=$1
    identity_test_home=$2
    identity_test_shell=$3
    printf 'vaultlink:x:%s:%s:VaultLink service account:%s:%s\n' \
        "$identity_test_uid" "$identity_uid" "$identity_test_home" \
        "$identity_test_shell" >>/etc/passwd
}

identity_add_group() {
    printf 'vaultlink:x:%s:\n' "$identity_uid" >>/etc/group
}

identity_add_shadow() {
    identity_test_password=$1
    printf 'vaultlink:%s:1::::::\n' "$identity_test_password" >>/etc/shadow
}

assert_identity_rejected() {
    identity_label=$1
    identity_expected_error=$2
    identity_log=$(mktemp "${TMPDIR:-/tmp}/vaultlink-identity-negative.XXXXXXXX")
    if package_initial_install >"$identity_log" 2>&1; then
        fail "package installation accepted unsafe identity: $identity_label"
    fi
    grep -F -q "$identity_expected_error" "$identity_log" \
        || { cat "$identity_log" >&2; fail "identity rejection was not explicit: $identity_label"; }
    package_is_installed \
        && fail "identity preflight left the package installed: $identity_label"
    [ ! -e "$marker" ] && [ ! -L "$marker" ] \
        || fail "identity preflight created an installation marker: $identity_label"
    [ ! -e "$candidate" ] && [ ! -L "$candidate" ] \
        || fail "identity preflight unpacked the candidate: $identity_label"
    [ ! -e "$live_binary" ] && [ ! -L "$live_binary" ] \
        || fail "identity preflight activated runtime code: $identity_label"
    rm -f "$identity_log"
    identity_restore
}

identity_add_passwd 0 /var/lib/vaultlink "$identity_nologin"
identity_add_group
identity_add_shadow '!*'
assert_identity_rejected root-uid \
    'vaultlink must use a non-root system UID below 1000'

identity_add_passwd "$identity_uid" /tmp "$identity_nologin"
identity_add_group
identity_add_shadow '!*'
assert_identity_rejected wrong-home 'vaultlink home directory is unexpected'

identity_add_passwd "$identity_uid" /var/lib/vaultlink /bin/sh
identity_add_group
identity_add_shadow '!*'
assert_identity_rejected wrong-shell \
    'vaultlink login shell is unexpected for'

identity_add_passwd "$identity_uid" /var/lib/vaultlink "$identity_nologin"
identity_add_group
identity_add_shadow "\$6\$not-a-real-login-hash"
assert_identity_rejected active-password \
    'vaultlink shadow password is not locked'

identity_add_passwd "$identity_uid" /var/lib/vaultlink "$identity_nologin"
identity_add_group
printf 'vaultlink-extra:x:%s:vaultlink\n' "$identity_extra_gid" >>/etc/group
identity_add_shadow '!*'
assert_identity_rejected supplementary-group \
    'vaultlink must belong only to its exact primary group'

identity_add_passwd "$identity_uid" /var/lib/vaultlink "$identity_nologin"
assert_identity_rejected passwd-only 'vaultlink service identity is incomplete'

identity_add_group
assert_identity_rejected group-only 'vaultlink service identity is incomplete'

identity_add_shadow '!*'
assert_identity_rejected shadow-only 'vaultlink service identity is incomplete'

identity_restore

# A fresh package must reject every markerless package-owned application tree,
# not merely the old /opt runtime path. Prove the guard runs before unpacking
# by preserving a hostile version metadata file byte-for-byte.
install -d -o root -g root -m 0755 /usr/lib/vaultlink/package
printf '%s\n' 'markerless-package-owned-collision' \
    >/usr/lib/vaultlink/package/version
chown root:root /usr/lib/vaultlink/package/version
chmod 0644 /usr/lib/vaultlink/package/version
package_collision_hash=$(sha256sum /usr/lib/vaultlink/package/version | awk '{ print $1 }')
package_collision_log=$(mktemp "${TMPDIR:-/tmp}/vaultlink-package-collision.XXXXXXXX")
if package_initial_install >"$package_collision_log" 2>&1; then
    fail "package manager adopted markerless package-owned state"
fi
grep -F -q 'refusing to adopt markerless existing installation: /usr/lib/vaultlink' \
    "$package_collision_log" \
    || { cat "$package_collision_log" >&2; fail "package-owned collision rejection was not explicit"; }
package_is_installed \
    && fail "package-owned collision left the package installed"
[ ! -e "$marker" ] && [ ! -L "$marker" ] \
    || fail "package-owned collision created an installation marker"
[ "$(sha256sum /usr/lib/vaultlink/package/version | awk '{ print $1 }')" = \
    "$package_collision_hash" ] \
    || fail "package-owned collision was overwritten before rejection"
rm -f "$package_collision_log" /usr/lib/vaultlink/package/version
rmdir /usr/lib/vaultlink/package /usr/lib/vaultlink

# The package manager must execute the fail-closed preinstall check before it
# can adopt a markerless archive-style installation.
install -d -o root -g root -m 0755 /opt/vaultlink
install -o root -g root -m 0755 /bin/true "$live_binary"
negative_log=$(mktemp "${TMPDIR:-/tmp}/vaultlink-markerless.XXXXXXXX")
if [ "$package_format" = pkg.tar.zst ]; then
    legacy_hash=$(sha256sum "$live_binary" | awk '{ print $1 }')
    package_install >"$negative_log" 2>&1 || :
    package_is_installed \
        || fail "direct pacman test did not exercise Pacman's scriptlet semantics"
    [ ! -e "$marker" ] && [ ! -L "$marker" ] \
        || fail "direct pacman install granted provenance to markerless legacy state"
    [ "$(sha256sum "$live_binary" | awk '{ print $1 }')" = "$legacy_hash" ] \
        || fail "direct pacman install replaced markerless legacy active state"
    grep -F -q 'refusing to grant package provenance to markerless existing installation' \
        "$negative_log" \
        || { cat "$negative_log" >&2; fail "Arch post_install legacy guard was not exercised"; }
    # Recover through the signed, package-owned wrapper. It holds the install,
    # update, and maintenance locks, authorizes markerless cleanup only for
    # this explicit mode, and must preserve the rejected archive runtime.
    /usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh \
        --recover-failed-install >/dev/null
    package_is_installed && fail "rejected direct pacman package could not be removed"
    [ ! -e "$marker" ] && [ ! -L "$marker" ] \
        || fail "removal minted provenance for a rejected direct pacman install"
    [ "$(sha256sum "$live_binary" | awk '{ print $1 }')" = "$legacy_hash" ] \
        || fail "removal changed the pre-existing markerless active binary"
    : >"$negative_log"
fi
if package_initial_install >"$negative_log" 2>&1; then
    fail "package manager adopted a markerless active binary"
fi
grep -F -q 'refusing to adopt markerless existing installation' "$negative_log" \
    || { cat "$negative_log" >&2; fail "markerless rejection was not explicit"; }
package_is_installed && fail "failed markerless install left the package installed"
rm -f "$negative_log" "$live_binary"

if [ "$package_format" = pkg.tar.zst ]; then
    # Force the supported wrapper to fail only after Pacman's post_install has
    # created both update.conf and the active copy. Cleanup may remove exactly
    # those attempt-owned bytes, but no pre-existing state or user data.
    systemctl_backup=/usr/bin/systemctl.vaultlink-fresh-cleanup.$$
    mv /usr/bin/systemctl "$systemctl_backup"
    cat >/usr/bin/systemctl <<'EOF'
#!/bin/sh
case "$*" in
    '--quiet is-active vaultlink.service')
        counter=/run/vaultlink-fresh-cleanup-systemctl.count
        count=$(cat "$counter" 2>/dev/null || printf '%s\n' 0)
        count=$((count + 1))
        printf '%s\n' "$count" >"$counter"
        if [ "$count" -ge 2 ]; then
            kill -TERM "$PPID"
        fi
        exit 1
        ;;
    *) exit 1 ;;
esac
EOF
    chown root:root /usr/bin/systemctl
    chmod 0755 /usr/bin/systemctl
    fresh_cleanup_log=$(mktemp "${TMPDIR:-/tmp}/vaultlink-fresh-cleanup.XXXXXXXX")
    if package_initial_install >"$fresh_cleanup_log" 2>&1; then
        fail "Arch installer ignored a post-activation failure"
    else
        fresh_cleanup_status=$?
    fi
    [ "$fresh_cleanup_status" -eq 143 ] \
        || fail "Arch installer did not propagate SIGTERM as status 143"
    package_is_installed && fail "failed Arch first install remained registered"
    [ ! -e "$marker" ] && [ ! -L "$marker" ] \
        || fail "failed Arch first install retained provisional provenance"
    [ ! -e "$live_binary" ] && [ ! -L "$live_binary" ] \
        || fail "failed Arch first install retained its attempt-owned active copy"
    [ ! -e "$update_config" ] && [ ! -L "$update_config" ] \
        || fail "failed Arch first install retained its attempt-owned update.conf"
    [ ! -e /var/lib/vaultlink-backups/install-method.env ] \
        && [ ! -L /var/lib/vaultlink-backups/install-method.env ] \
        || fail "failed Arch first install retained attempt-owned recovery provenance"
    rm -f "$fresh_cleanup_log" /run/vaultlink-fresh-cleanup-systemctl.count \
        /usr/bin/systemctl
    mv "$systemctl_backup" /usr/bin/systemctl
    systemctl_backup=
fi

if [ "$package_format" = deb ]; then
    # Debian must recover across a reboot/power loss between unpack and
    # configure without relying on volatile /run handoff state.
    dpkg --unpack "$package" >/dev/null
    rm -f /run/vaultlink-locks/package-install.mode
    dpkg --configure vaultlink >/dev/null
else
    package_initial_install >/dev/null
fi
package_is_installed || fail "fresh package installation was not registered"
assert_marker
id vaultlink >/dev/null 2>&1 || fail "service identity was not provisioned"
[ -x "$candidate" ] && [ ! -L "$candidate" ] || fail "candidate was not installed safely"
[ -x "$live_binary" ] && [ ! -L "$live_binary" ] \
    || fail "fresh installation did not create the active copy"
[ "$(sha256sum "$candidate" | awk '{ print $1 }')" = \
    "$(sha256sum "$live_binary" | awk '{ print $1 }')" ] \
    || fail "fresh active copy differs from the candidate"
[ "$(timeout --kill-after=2 5 runuser -u vaultlink -- "$live_binary" --version)" = "$version" ] \
    || fail "fresh active copy reports the wrong version"
grep -F -x -q auto_install=false "$update_config" \
    || fail "fresh updater configuration must remain opt-in"
if command -v systemctl >/dev/null; then
    systemctl --quiet is-active vaultlink.service 2>/dev/null \
        && fail "fresh installation started VaultLink"
    systemctl --quiet is-active vaultlink-update.timer 2>/dev/null \
        && fail "fresh installation started the update timer"
fi
find /etc/systemd/system -type l \
    \( -name vaultlink.service -o -name vaultlink-update.timer \) -print \
    | grep -q . && fail "fresh installation enabled a VaultLink unit"

runtime_guard=/usr/lib/vaultlink/package/deploy/vaultlink-runtime-guard.sh
"$runtime_guard" || fail "runtime parity guard rejected a consistent installation"
runtime_guard_candidate_hash=$(sha256sum "$candidate" | awk '{ print $1 }')
install -o root -g root -m 0755 /bin/true "$live_binary"
runtime_guard_log=$(mktemp "${TMPDIR:-/tmp}/vaultlink-runtime-guard.XXXXXXXX")
if "$runtime_guard" >"$runtime_guard_log" 2>&1; then
    fail "runtime parity guard accepted a package/live mixed state"
fi
grep -F -q 'active runtime differs from native package candidate' "$runtime_guard_log" \
    || { cat "$runtime_guard_log" >&2; fail "runtime parity rejection was not explicit"; }
[ "$(sha256sum "$candidate" | awk '{ print $1 }')" = "$runtime_guard_candidate_hash" ] \
    || fail "runtime parity guard mutated the package candidate"
install -o root -g root -m 0755 "$candidate" "$live_binary"
rm -f "$runtime_guard_log"
"$runtime_guard" || fail "runtime parity guard rejected restored parity"
rm -f "$live_binary"
"$runtime_guard" --package-only \
    || fail "package-only runtime guard rejected a valid package with missing live binary"
if "$runtime_guard" >"$runtime_guard_log" 2>&1; then
    fail "full runtime guard accepted a missing live binary"
fi
grep -F -q 'active runtime' "$runtime_guard_log" \
    || { cat "$runtime_guard_log" >&2; fail "missing-live parity rejection was not explicit"; }
install -o root -g root -m 0755 "$candidate" "$live_binary"
rm -f "$runtime_guard_log"

# The updater may reinstall the verified old package after a failed new
# activation, when candidate/DB are still new but the upgrade helper has
# already restored the old live runtime. That narrow preinstall mismatch is
# authorized only by an explicit recovery environment plus both secure locks.
# DEB and Arch require the exact inherited descriptors; RPM closes unrelated
# descriptors around scriptlets, so its hook instead proves both lock paths
# remain securely contended. Environment alone must fail before mutation.
install -o root -g root -m 0755 /bin/true "$live_binary"
recovery_preflight_hash=$(sha256sum "$live_binary" | awk '{ print $1 }')
recovery_preflight_log=$(mktemp "${TMPDIR:-/tmp}/vaultlink-recovery-preflight.XXXXXXXX")
if VAULTLINK_PACKAGE_RECOVERY=1 \
    /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh \
        preinstall "$package_format" "$os_id" "$os_version" "$package_arch" \
        vaultlink upgrade >"$recovery_preflight_log" 2>&1; then
    fail "package recovery environment bypassed parity without inherited locks"
fi
case "$package_format" in
    rpm) recovery_lock_rejection='RPM package recovery requires both secure updater locks to be held' ;;
    *) recovery_lock_rejection='package recovery requires inherited locked update and maintenance descriptors' ;;
esac
grep -F -q "$recovery_lock_rejection" \
    "$recovery_preflight_log" \
    || { cat "$recovery_preflight_log" >&2; fail "unlocked package recovery rejection was not explicit"; }
[ "$(sha256sum "$live_binary" | awk '{ print $1 }')" = "$recovery_preflight_hash" ] \
    || fail "rejected package recovery preflight changed the active binary"
install -d -o root -g root -m 0700 /run/vaultlink-locks
for recovery_lock_path in \
    /run/vaultlink-locks/update.lock \
    /run/vaultlink-locks/maintenance.lock; do
    if [ ! -e "$recovery_lock_path" ] && [ ! -L "$recovery_lock_path" ]; then
        install -o root -g root -m 0600 /dev/null "$recovery_lock_path"
    fi
done
exec 9>/run/vaultlink-locks/update.lock
flock -n 9 || fail "could not acquire updater lock for recovery preflight probe"
exec 8>/run/vaultlink-locks/maintenance.lock
flock -n 8 || fail "could not acquire maintenance lock for recovery preflight probe"
VAULTLINK_PACKAGE_RECOVERY=1 \
    /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh \
        preinstall "$package_format" "$os_id" "$os_version" "$package_arch" \
        vaultlink upgrade \
    || fail "locked package recovery preflight rejected the bounded live/candidate mismatch"
exec 8>&-
exec 9>&-
[ "$(sha256sum "$live_binary" | awk '{ print $1 }')" = "$recovery_preflight_hash" ] \
    || fail "authorized package recovery preflight changed the active binary"
install -o root -g root -m 0755 "$candidate" "$live_binary"
rm -f "$recovery_preflight_log"

if [ "$package_format" = pkg.tar.zst ]; then
    arch_db_record=$(pacman -Q vaultlink)
    arch_db_version=${arch_db_record#* }
    arch_desc=/var/lib/pacman/local/vaultlink-$arch_db_version/desc
    [ -f "$arch_desc" ] && [ ! -L "$arch_desc" ] \
        || fail "Arch package database description is unavailable"
    arch_desc_backup=$(mktemp "${TMPDIR:-/tmp}/vaultlink-pacman-desc.XXXXXXXX")
    cp -p "$arch_desc" "$arch_desc_backup"
    awk 'previous == "%ARCH%" { print "any"; previous = ""; next }
         { print; previous = $0 }' "$arch_desc_backup" >"$arch_desc"
    if "$runtime_guard" >"$runtime_guard_log" 2>&1; then
        fail "runtime guard accepted an incompatible Pacman database architecture"
    fi
    grep -F -q 'native package database architecture diverges from marker' \
        "$runtime_guard_log" \
        || { cat "$runtime_guard_log" >&2; fail "Pacman architecture rejection was not explicit"; }
    cp -p "$arch_desc_backup" "$arch_desc"
    rm -f "$arch_desc_backup" "$runtime_guard_log"
    "$runtime_guard" || fail "runtime guard rejected restored Pacman architecture parity"
fi

if [ "$package_format" = deb ]; then
    # On upgrade, postinst receives the previously configured version from
    # dpkg itself. The candidate is configured after simulated volatile-state
    # loss while the transactional active copy remains untouched.
    deb_reboot_active_hash=$(sha256sum "$live_binary" | awk '{ print $1 }')
    deb_reboot_active_identity=$(stat -c '%d:%i:%u:%g:%a:%Y:%s' "$live_binary")
    dpkg --unpack "$package" >/dev/null
    rm -f /run/vaultlink-locks/package-install.mode
    dpkg --configure vaultlink >/dev/null
    [ "$(sha256sum "$live_binary" | awk '{ print $1 }')" = "$deb_reboot_active_hash" ] \
        || fail "Debian post-reboot upgrade configure changed the active binary"
    [ "$(stat -c '%d:%i:%u:%g:%a:%Y:%s' "$live_binary")" = \
        "$deb_reboot_active_identity" ] \
        || fail "Debian post-reboot upgrade configure replaced active runtime metadata"
fi

# A package removal must retain the active binary when stopping systemd fails
# and either unit is still active or its state cannot be established. Source
# the installed lifecycle in a subshell and inject deterministic systemctl
# responses without requiring systemd as PID 1 in this container gate.
active_hash_before_remove_probe=$(sha256sum "$live_binary" | awk '{ print $1 }')
if [ "$package_format" != pkg.tar.zst ]; then
    # DEB/RPM scriptlets must obtain both serialization locks before their
    # first systemd or active-runtime mutation. Exercise each independently
    # with a separate lock owner so inherited-open-file semantics cannot make
    # the contender appear successful.
    for removal_lock_probe in \
        update.lock:update \
        maintenance.lock:maintenance; do
        removal_lock_file=${removal_lock_probe%%:*}
        removal_lock_label=${removal_lock_probe#*:}
        removal_lock_dir=$(mktemp -d "${TMPDIR:-/tmp}/vaultlink-removal-lock.XXXXXXXX")
        (
            exec 6>"/run/vaultlink-locks/$removal_lock_file"
            flock 6
            : >"$removal_lock_dir/ready"
            while [ ! -e "$removal_lock_dir/release" ]; do
                sleep 0.05
            done
        ) &
        removal_lock_holder=$!
        removal_lock_wait=0
        while [ ! -e "$removal_lock_dir/ready" ]; do
            removal_lock_wait=$((removal_lock_wait + 1))
            [ "$removal_lock_wait" -lt 100 ] || break
            sleep 0.05
        done
        removal_lock_log=$removal_lock_dir/removal.log
        removal_systemctl_log=$removal_lock_dir/systemctl.log
        if [ "$removal_lock_label" = update ]; then
            # Prove even an absent recovery marker stays absent when the
            # first lock is contended.
            mv /var/lib/vaultlink-backups/install-method.env \
                "$removal_lock_dir/install-method.env.saved"
            removal_recovery_state=absent
        else
            removal_recovery_state=present
            removal_recovery_identity=$(stat -c '%d:%i:%u:%g:%a:%Y:%s' \
                /var/lib/vaultlink-backups/install-method.env)
            removal_recovery_hash=$(sha256sum \
                /var/lib/vaultlink-backups/install-method.env | awk '{ print $1 }')
        fi
        removal_lock_status=0
        (
            VAULTLINK_PACKAGE_LIFECYCLE_EMBEDDED=1
            export VAULTLINK_PACKAGE_LIFECYCLE_EMBEDDED
            # shellcheck disable=SC1091
            . /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh
            package_name=vaultlink
            export package_format os_id os_version package_arch package_name
            # shellcheck disable=SC2317,SC2329
            package_systemd_manager_present() { return 0; }
            # shellcheck disable=SC2317,SC2329
            systemctl() {
                : >"$removal_systemctl_log"
                return 1
            }
            package_preremove remove
        ) >"$removal_lock_log" 2>&1 || removal_lock_status=$?
        : >"$removal_lock_dir/release"
        wait "$removal_lock_holder"
        [ "$removal_lock_status" -ne 0 ] \
            || fail "$removal_lock_label lock contention did not abort removal"
        case "$removal_lock_label" in
            update) removal_lock_error='another VaultLink update operation is running' ;;
            maintenance) removal_lock_error='another VaultLink upgrade or rollback is running' ;;
        esac
        grep -F -q "$removal_lock_error" "$removal_lock_log" \
            || { cat "$removal_lock_log" >&2; fail "$removal_lock_label lock rejection was not explicit"; }
        [ ! -e "$removal_systemctl_log" ] \
            || fail "$removal_lock_label lock contention reached systemctl mutation"
        if [ "$removal_recovery_state" = absent ]; then
            [ ! -e /var/lib/vaultlink-backups/install-method.env ] \
                && [ ! -L /var/lib/vaultlink-backups/install-method.env ] \
                || fail "$removal_lock_label lock contention created recovery provenance"
            mv "$removal_lock_dir/install-method.env.saved" \
                /var/lib/vaultlink-backups/install-method.env
        else
            [ "$(stat -c '%d:%i:%u:%g:%a:%Y:%s' \
                /var/lib/vaultlink-backups/install-method.env)" = \
                "$removal_recovery_identity" ] \
                && [ "$(sha256sum /var/lib/vaultlink-backups/install-method.env \
                    | awk '{ print $1 }')" = "$removal_recovery_hash" ] \
                || fail "$removal_lock_label lock contention changed recovery provenance"
        fi
        [ "$(sha256sum "$live_binary" | awk '{ print $1 }')" = \
            "$active_hash_before_remove_probe" ] \
            || fail "$removal_lock_label lock contention changed the active binary"
        rm -rf "$removal_lock_dir"
    done
fi
for removal_probe_state in active unknown; do
    removal_probe_log=$(mktemp "${TMPDIR:-/tmp}/vaultlink-removal-negative.XXXXXXXX")
    if (
        if [ "$package_format" = pkg.tar.zst ]; then
            # This probe targets the post-lock systemd guard. Arch ordinarily
            # reaches it only through the signed remover, so reproduce that
            # wrapper's already-held exact lock descriptors in this isolated
            # sourced-lifecycle test.
            exec 9>/run/vaultlink-locks/update.lock
            flock -n 9
            exec 8>/run/vaultlink-locks/maintenance.lock
            flock -n 8
        fi
        VAULTLINK_PACKAGE_LIFECYCLE_EMBEDDED=1
        export VAULTLINK_PACKAGE_LIFECYCLE_EMBEDDED
        # The installed, already package-verified lifecycle is sourced here.
        # shellcheck disable=SC1091
        . /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh
        package_name=vaultlink
        export package_format os_id os_version package_arch package_name
        # Invoked indirectly by package_preremove from the sourced lifecycle.
        # shellcheck disable=SC2317,SC2329
        package_systemd_manager_present() {
            return 0
        }
        # Invoked indirectly by package_preremove from the sourced lifecycle.
        # shellcheck disable=SC2317,SC2329
        systemctl() {
            case "${1:-}" in
                disable) return 1 ;;
                is-active)
                    case "${2:-}" in
                        vaultlink-update.timer) printf '%s\n' inactive; return 3 ;;
                        vaultlink-update.service) printf '%s\n' inactive; return 3 ;;
                        vaultlink.service)
                            printf '%s\n' "$removal_probe_state"
                            [ "$removal_probe_state" = active ] && return 0
                            return 4
                            ;;
                    esac
                    ;;
            esac
            return 1
        }
        package_preremove remove
    ) >"$removal_probe_log" 2>&1; then
        fail "package removal accepted $removal_probe_state service state"
    fi
    grep -F -q 'cannot prove vaultlink.service inactive before removal' \
        "$removal_probe_log" \
        || { cat "$removal_probe_log" >&2; fail "unsafe removal rejection was not explicit"; }
    [ -f "$live_binary" ] && [ ! -L "$live_binary" ] \
        || fail "unsafe removal probe deleted the active binary"
    [ "$(sha256sum "$live_binary" | awk '{ print $1 }')" = \
        "$active_hash_before_remove_probe" ] \
        || fail "unsafe removal probe changed the active binary"
    rm -f "$removal_probe_log"
done

if [ "$package_format" = pkg.tar.zst ]; then
    # Pacman ignores .INSTALL function status, so the package also owns an
    # AbortOnFail libalpm PreTransaction hook. Prove with the real package
    # manager that direct pacman removal without the signed wrapper's inherited
    # locks aborts without querying or mutating systemd state.
    [ "$(readlink -f "$(command -v systemctl)")" = /usr/bin/systemctl ] \
        || fail "Arch removal probe requires physical /usr/bin/systemctl"
    [ -f /usr/bin/systemctl ] && [ ! -L /usr/bin/systemctl ] \
        || fail "Arch systemctl path is unsafe"
    systemctl_backup=/usr/bin/systemctl.vaultlink-smoke.$$
    [ ! -e "$systemctl_backup" ] && [ ! -L "$systemctl_backup" ] \
        || fail "Arch systemctl backup path already exists"
    mv /usr/bin/systemctl "$systemctl_backup"
    cat >/usr/bin/systemctl <<'EOF'
#!/bin/sh
case "${1:-}" in
    disable) : >/run/vaultlink-removal-mutated; exit 1 ;;
    is-active)
        case "${2:-}" in
            vaultlink-update.timer) printf '%s\n' inactive; exit 3 ;;
            vaultlink-update.service) printf '%s\n' inactive; exit 3 ;;
            vaultlink.service) printf '%s\n' active; exit 0 ;;
        esac
        ;;
    is-enabled)
        printf '%s\n' disabled
        exit 1
        ;;
esac
exit 1
EOF
    chown root:root /usr/bin/systemctl
    chmod 0755 /usr/bin/systemctl
    if [ ! -d /run/systemd/system ]; then
        install -d -o root -g root -m 0755 /run/systemd/system
        systemd_run_dir_created=1
    fi
    arch_candidate_hash=$(sha256sum "$candidate" | awk '{ print $1 }')
    arch_unit_hash=$(sha256sum /usr/lib/systemd/system/vaultlink.service | awk '{ print $1 }')
    arch_hook_hash=$(sha256sum /usr/share/libalpm/hooks/vaultlink-remove.hook | awk '{ print $1 }')
    arch_removal_log=$(mktemp "${TMPDIR:-/tmp}/vaultlink-arch-removal.XXXXXXXX")
    if pacman -R --noconfirm vaultlink >"$arch_removal_log" 2>&1; then
        fail "Arch removal transaction ignored its AbortOnFail safety hook"
    fi
    grep -F -q 'Arch removal requires the signed wrapper holding the update lock' \
        "$arch_removal_log" \
        || { cat "$arch_removal_log" >&2; fail "Arch removal hook rejection was not explicit"; }
    [ ! -e /run/vaultlink-removal-mutated ] \
        || fail "Arch removal preflight invoked a mutating systemctl action"
    package_is_installed \
        || fail "failed Arch removal changed the package database"
    [ "$(sha256sum "$candidate" | awk '{ print $1 }')" = "$arch_candidate_hash" ] \
        || fail "failed Arch removal changed the candidate"
    [ "$(sha256sum /usr/lib/systemd/system/vaultlink.service | awk '{ print $1 }')" = \
        "$arch_unit_hash" ] \
        || fail "failed Arch removal changed the service unit"
    [ "$(sha256sum /usr/share/libalpm/hooks/vaultlink-remove.hook | awk '{ print $1 }')" = \
        "$arch_hook_hash" ] \
        || fail "failed Arch removal changed its transaction hook"
    assert_marker
    [ "$(sha256sum "$live_binary" | awk '{ print $1 }')" = \
        "$active_hash_before_remove_probe" ] \
        || fail "failed Arch removal changed the active binary"
    rm -f "$arch_removal_log" /usr/bin/systemctl
    mv "$systemctl_backup" /usr/bin/systemctl
    systemctl_backup=
    if [ "$systemd_run_dir_created" -eq 1 ]; then
        rmdir /run/systemd/system
        systemd_run_dir_created=0
    fi

    # A later AbortOnFail transaction hook must leave VaultLink byte-for-byte
    # intact. This proves our earlier hook is a pure preflight and never stops
    # units or unlinks /opt before the package transaction is committed.
    arch_abort_hook=/usr/share/libalpm/hooks/zz-vaultlink-smoke-abort.hook
    cat >"$arch_abort_hook" <<'EOF'
[Trigger]
Operation = Remove
Type = Package
Target = vaultlink

[Action]
Description = Injecting a later VaultLink removal abort
When = PreTransaction
Exec = /bin/false
AbortOnFail
EOF
    chown root:root "$arch_abort_hook"
    chmod 0644 "$arch_abort_hook"
    arch_candidate_hash=$(sha256sum "$candidate" | awk '{ print $1 }')
    arch_unit_hash=$(sha256sum /usr/lib/systemd/system/vaultlink.service | awk '{ print $1 }')
    arch_hook_hash=$(sha256sum /usr/share/libalpm/hooks/vaultlink-remove.hook | awk '{ print $1 }')
    arch_live_hash=$(sha256sum "$live_binary" | awk '{ print $1 }')
    if package_remove >/dev/null 2>&1; then
        fail "later Arch AbortOnFail hook did not abort package removal"
    fi
    package_is_installed \
        || fail "later Arch hook abort changed the package database"
    [ "$(sha256sum "$candidate" | awk '{ print $1 }')" = "$arch_candidate_hash" ] \
        || fail "later Arch hook abort changed the candidate"
    [ "$(sha256sum /usr/lib/systemd/system/vaultlink.service | awk '{ print $1 }')" = \
        "$arch_unit_hash" ] \
        || fail "later Arch hook abort changed the service unit"
    [ "$(sha256sum /usr/share/libalpm/hooks/vaultlink-remove.hook | awk '{ print $1 }')" = \
        "$arch_hook_hash" ] \
        || fail "later Arch hook abort changed the removal hook"
    [ "$(sha256sum "$live_binary" | awk '{ print $1 }')" = "$arch_live_hash" ] \
        || fail "later Arch hook abort changed the active binary"
    assert_marker
    rm -f "$arch_abort_hook"
    arch_abort_hook=

    # Inject failures at both critical Pacman removal phases. If pre_remove
    # already unlinked /opt while the package DB and candidate remain exact,
    # the signed wrapper must restore live parity before restoring prior unit
    # state. If payload/DB parity is gone, it must remain terminally inactive
    # and must never attempt to start or enable a unit.
    install -d -o root -g root -m 0755 /run/systemd/system
    systemd_run_dir_created=1
    removal_mock_state=/run/vaultlink-remove-wrapper-smoke
    rm -rf "$removal_mock_state"
    install -d -o root -g root -m 0700 "$removal_mock_state"
    for removal_unit in vaultlink.service vaultlink-update.timer; do
        printf '%s\n' active >"$removal_mock_state/$removal_unit.active"
        printf '%s\n' enabled >"$removal_mock_state/$removal_unit.enabled"
    done
    printf '%s\n' inactive >"$removal_mock_state/vaultlink-update.service.active"
    : >"$removal_mock_state/systemctl.log"
    systemctl_backup=/usr/bin/systemctl.vaultlink-remove-recovery.$$
    mv /usr/bin/systemctl "$systemctl_backup"
    cat >/usr/bin/systemctl <<'EOF'
#!/bin/sh
set -eu
state=/run/vaultlink-remove-wrapper-smoke
command_name=$1
shift
printf '%s %s\n' "$command_name" "$*" >>"$state/systemctl.log"
case "$command_name" in
    is-active)
        unit=$1
        unit_state=$(cat "$state/$unit.active")
        printf '%s\n' "$unit_state"
        [ "$unit_state" = active ]
        ;;
    is-enabled)
        unit=$1
        unit_state=$(cat "$state/$unit.enabled")
        printf '%s\n' "$unit_state"
        [ "$unit_state" = enabled ]
        ;;
    disable)
        [ "${1:-}" != --now ] || shift
        for unit in "$@"; do
            printf '%s\n' disabled >"$state/$unit.enabled"
            printf '%s\n' inactive >"$state/$unit.active"
        done
        ;;
    stop)
        for unit in "$@"; do
            printf '%s\n' inactive >"$state/$unit.active"
        done
        ;;
    enable)
        for unit in "$@"; do
            printf '%s\n' enabled >"$state/$unit.enabled"
        done
        ;;
    start)
        for unit in "$@"; do
            [ "$unit" != vaultlink.service ] || [ -x /opt/vaultlink/vaultlink ]
            printf '%s\n' active >"$state/$unit.active"
        done
        ;;
    daemon-reload) ;;
    *) exit 64 ;;
esac
EOF
    chown root:root /usr/bin/systemctl
    chmod 0755 /usr/bin/systemctl

    arch_pacman_binary_backup=/usr/bin/pacman.vaultlink-remove-recovery.$$
    mv /usr/bin/pacman "$arch_pacman_binary_backup"
    export VAULTLINK_REAL_PACMAN=$arch_pacman_binary_backup
    cat >/usr/bin/pacman <<'EOF'
#!/bin/sh
set -eu
case "${1:-}" in
    -R)
        /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh \
            preremove pkg.tar.zst arch rolling x86_64 vaultlink remove
        case "${VAULTLINK_ARCH_REMOVE_TEST_PHASE:-}" in
            after-preremove) exit 77 ;;
            signal-after-preremove)
                kill -TERM "$PPID"
                exit 79
                ;;
            after-payload)
                rm -f /usr/lib/vaultlink/package/vaultlink \
                    /usr/lib/vaultlink/package/deploy/vaultlink-runtime-guard.sh
                : >/run/vaultlink-remove-wrapper-smoke/package-removed
                exit 78
                ;;
            *) exit 64 ;;
        esac
        ;;
    -Q|-Qi)
        if [ -e /run/vaultlink-remove-wrapper-smoke/package-removed ]; then
            exit 1
        fi
        exec "$VAULTLINK_REAL_PACMAN" "$@"
        ;;
    *) exec "$VAULTLINK_REAL_PACMAN" "$@" ;;
esac
EOF
    chown root:root /usr/bin/pacman
    chmod 0755 /usr/bin/pacman

    recovery_candidate_copy=$(mktemp "${TMPDIR:-/tmp}/vaultlink-remove-candidate.XXXXXXXX")
    recovery_guard_copy=$(mktemp "${TMPDIR:-/tmp}/vaultlink-remove-guard.XXXXXXXX")
    install -m 0600 "$candidate" "$recovery_candidate_copy"
    install -m 0600 "$runtime_guard" "$recovery_guard_copy"
    removal_wrapper=/usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh
    recovery_log=$(mktemp "${TMPDIR:-/tmp}/vaultlink-remove-recovery.XXXXXXXX")
    if VAULTLINK_ARCH_REMOVE_TEST_PHASE=after-preremove \
        "$removal_wrapper" >"$recovery_log" 2>&1; then
        fail "Arch removal wrapper hid a failure after pre_remove"
    fi
    package_is_installed || fail "pre_remove failure changed the real package database"
    cmp -s "$candidate" "$live_binary" \
        || fail "Arch removal recovery did not restore live/candidate parity"
    "$runtime_guard" || fail "Arch removal recovery did not restore full runtime parity"
    [ "$(cat "$removal_mock_state/vaultlink.service.active")" = active ] \
        && [ "$(cat "$removal_mock_state/vaultlink.service.enabled")" = enabled ] \
        && [ "$(cat "$removal_mock_state/vaultlink-update.timer.active")" = active ] \
        && [ "$(cat "$removal_mock_state/vaultlink-update.timer.enabled")" = enabled ] \
        || fail "Arch removal recovery did not restore prior unit state"

    : >"$removal_mock_state/systemctl.log"
    for removal_unit in vaultlink.service vaultlink-update.timer; do
        printf '%s\n' active >"$removal_mock_state/$removal_unit.active"
        printf '%s\n' enabled >"$removal_mock_state/$removal_unit.enabled"
    done
    printf '%s\n' inactive >"$removal_mock_state/vaultlink-update.service.active"
    if VAULTLINK_ARCH_REMOVE_TEST_PHASE=signal-after-preremove \
        "$removal_wrapper" >"$recovery_log" 2>&1; then
        fail "Arch removal wrapper ignored SIGTERM during Pacman"
    else
        removal_signal_status=$?
    fi
    [ "$removal_signal_status" -eq 143 ] \
        || fail "Arch removal wrapper did not propagate SIGTERM as status 143"
    cmp -s "$candidate" "$live_binary" \
        || fail "signalled Arch removal did not restore live/candidate parity"
    "$runtime_guard" || fail "signalled Arch removal did not restore runtime parity"

    : >"$removal_mock_state/systemctl.log"
    for removal_unit in vaultlink.service vaultlink-update.timer; do
        printf '%s\n' active >"$removal_mock_state/$removal_unit.active"
        printf '%s\n' enabled >"$removal_mock_state/$removal_unit.enabled"
    done
    printf '%s\n' inactive >"$removal_mock_state/vaultlink-update.service.active"
    if VAULTLINK_ARCH_REMOVE_TEST_PHASE=after-payload \
        "$removal_wrapper" >"$recovery_log" 2>&1; then
        fail "Arch removal wrapper hid a mixed payload failure"
    fi
    grep -F -q 'CRITICAL: Arch removal failed in a mixed state' "$recovery_log" \
        || { cat "$recovery_log" >&2; fail "mixed Arch removal failure was not terminal"; }
    for removal_unit in vaultlink.service vaultlink-update.timer vaultlink-update.service; do
        [ "$(cat "$removal_mock_state/$removal_unit.active")" = inactive ] \
            || fail "mixed Arch removal left $removal_unit active"
    done
    ! grep -E -q '^(start|enable) ' "$removal_mock_state/systemctl.log" \
        || fail "mixed Arch removal attempted to start or enable a unit"

    install -o root -g root -m 0755 "$recovery_candidate_copy" "$candidate"
    install -o root -g root -m 0755 "$recovery_guard_copy" "$runtime_guard"
    install -o root -g root -m 0755 "$candidate" "$live_binary"
    rm -f "$removal_mock_state/package-removed" "$recovery_log" \
        "$recovery_candidate_copy" "$recovery_guard_copy" /usr/bin/pacman
    mv "$arch_pacman_binary_backup" /usr/bin/pacman
    arch_pacman_binary_backup=
    rm -f /usr/bin/systemctl
    mv "$systemctl_backup" /usr/bin/systemctl
    systemctl_backup=
    rm -rf "$removal_mock_state"
    rmdir /run/systemd/system
    systemd_run_dir_created=0
    "$runtime_guard" || fail "Arch removal fault probes did not restore runtime parity"
fi

# A postinstall failure during any upgrade must preserve the pre-existing
# trusted host marker. A hostile updater-config symlink injects that failure
# after the package payload and marker have been examined.
marker_hash_before=$(sha256sum "$marker" | awk '{ print $1 }')
rm -f "$update_config"
ln -s /dev/null "$update_config"
package_upgrade >/dev/null 2>&1 || :
[ -f "$marker" ] && [ ! -L "$marker" ] \
    || fail "failed package upgrade removed the existing installation marker"
[ "$(sha256sum "$marker" | awk '{ print $1 }')" = "$marker_hash_before" ] \
    || fail "failed package upgrade changed the existing installation marker"
rm -f "$update_config"

# A same-package reinstall must leave an already consistent active runtime
# byte-for-byte and inode-for-inode untouched. The real two-version updater
# gate separately proves that a changed package candidate is not activated by
# package-manager scriptlets.
active_before=$(sha256sum "$live_binary" | awk '{ print $1 }')
active_identity_before=$(stat -c '%d:%i:%u:%g:%a:%Y:%s' "$live_binary")
rm -f "$update_config"
package_upgrade >/dev/null
active_after=$(sha256sum "$live_binary" | awk '{ print $1 }')
[ "$active_after" = "$active_before" ] \
    || fail "package reinstall modified the transactional active copy"
[ "$(stat -c '%d:%i:%u:%g:%a:%Y:%s' "$live_binary")" = \
    "$active_identity_before" ] \
    || fail "package reinstall replaced active runtime metadata"
[ ! -e "$update_config" ] && [ ! -L "$update_config" ] \
    || fail "package upgrade recreated an intentionally absent updater configuration"

printf '%s\n' 'package-smoke-config' >"$config"
chown root:vaultlink "$config"
chmod 0640 "$config"
printf '%s\n' 'auto_install=true' >"$update_config"
chown root:root "$update_config"
chmod 0644 "$update_config"
sqlite3 "$database" "CREATE TABLE package_smoke(value TEXT); INSERT INTO package_smoke VALUES('preserve');"
chown vaultlink:vaultlink "$database"
chmod 0600 "$database"
printf '%s\n' 'package-smoke-keyring' >"$keyring"
chown vaultlink:vaultlink "$keyring"
chmod 0600 "$keyring"
install -d -o root -g root -m 0700 "$(dirname "$backup_probe")"
printf '%s\n' 'package-smoke-backup' >"$backup_probe"
chown root:root "$backup_probe"
chmod 0600 "$backup_probe"

config_hash=$(sha256sum "$config" | awk '{ print $1 }')
update_hash=$(sha256sum "$update_config" | awk '{ print $1 }')
update_identity=$(stat -c '%d:%i:%u:%g:%a:%Y:%s' "$update_config")
database_hash=$(sha256sum "$database" | awk '{ print $1 }')
keyring_hash=$(sha256sum "$keyring" | awk '{ print $1 }')
backup_hash=$(sha256sum "$backup_probe" | awk '{ print $1 }')

package_remove >/dev/null
package_is_installed && fail "package removal did not update the package database"
[ ! -e "$candidate" ] || fail "package-owned candidate survived removal"
[ ! -e "$live_binary" ] || fail "active binary survived package removal"
[ ! -e /usr/lib/systemd/system/vaultlink.service ] \
    || fail "package-owned service unit survived removal"
assert_marker
id vaultlink >/dev/null 2>&1 || fail "service identity was deleted on removal"
[ "$(sha256sum "$config" | awk '{ print $1 }')" = "$config_hash" ] \
    || fail "configuration changed during removal"
[ "$(sha256sum "$update_config" | awk '{ print $1 }')" = "$update_hash" ] \
    || fail "updater configuration changed during removal"
[ "$(stat -c '%d:%i:%u:%g:%a:%Y:%s' "$update_config")" = "$update_identity" ] \
    || fail "updater configuration metadata changed during removal"
[ "$(sha256sum "$database" | awk '{ print $1 }')" = "$database_hash" ] \
    || fail "database changed during removal"
[ "$(sha256sum "$keyring" | awk '{ print $1 }')" = "$keyring_hash" ] \
    || fail "keyring changed during removal"
[ "$(sha256sum "$backup_probe" | awk '{ print $1 }')" = "$backup_hash" ] \
    || fail "backup changed during removal"
sqlite3 "$database" 'PRAGMA integrity_check' | grep -F -x -q ok \
    || fail "preserved database failed integrity verification"

if [ "$package_format" != pkg.tar.zst ]; then
    # DEB/RPM own the public marker, so a crash after payload removal but
    # before post-remove reconstruction can leave only the root-only recovery
    # copy. Stale recovery must never adopt newly introduced archive state;
    # the exact interrupted-remove shape remains reinstallable.
    rm -f "$marker"
    install -d -o root -g root -m 0755 /opt/vaultlink
    install -o root -g root -m 0755 /bin/true "$live_binary"
    interrupted_remove_log=$(mktemp "${TMPDIR:-/tmp}/vaultlink-marker-recovery.XXXXXXXX")
    interrupted_live_hash=$(sha256sum "$live_binary" | awk '{ print $1 }')
    if package_initial_install >"$interrupted_remove_log" 2>&1; then
        fail "stale marker recovery adopted markerless archive state"
    fi
    grep -F -q 'marker recovery rejected non-removal state' "$interrupted_remove_log" \
        || { cat "$interrupted_remove_log" >&2; fail "stale marker recovery rejection was not explicit"; }
    package_is_installed && fail "stale marker recovery mutated the package database"
    [ ! -e "$marker" ] && [ ! -L "$marker" ] \
        || fail "stale marker recovery recreated public provenance"
    [ "$(sha256sum "$live_binary" | awk '{ print $1 }')" = "$interrupted_live_hash" ] \
        || fail "stale marker recovery changed archive state"
    rm -f "$live_binary" "$interrupted_remove_log"
    rmdir /usr/share/vaultlink \
        || fail "interrupted-remove simulation retained package-owned state"
fi

package_initial_install >/dev/null
package_is_installed || fail "package reinstall was not registered"
assert_marker
[ "$(sha256sum "$candidate" | awk '{ print $1 }')" = \
    "$(sha256sum "$live_binary" | awk '{ print $1 }')" ] \
    || fail "reinstall did not atomically restore the candidate as active copy"
[ "$(sha256sum "$config" | awk '{ print $1 }')" = "$config_hash" ] \
    || fail "reinstall changed preserved configuration"
[ "$(sha256sum "$update_config" | awk '{ print $1 }')" = "$update_hash" ] \
    || fail "reinstall changed preserved updater configuration"
[ "$(stat -c '%d:%i:%u:%g:%a:%Y:%s' "$update_config")" = "$update_identity" ] \
    || fail "reinstall changed preserved updater configuration metadata"
[ "$(sha256sum "$database" | awk '{ print $1 }')" = "$database_hash" ] \
    || fail "reinstall changed preserved database"
[ "$(sha256sum "$keyring" | awk '{ print $1 }')" = "$keyring_hash" ] \
    || fail "reinstall changed preserved keyring"
[ "$(sha256sum "$backup_probe" | awk '{ print $1 }')" = "$backup_hash" ] \
    || fail "reinstall changed preserved backup"

if [ "$package_format" = pkg.tar.zst ]; then
    rm -f "$update_config"
    package_remove >/dev/null
    package_initial_install >/dev/null
    package_is_installed || fail "Arch absent-update.conf reinstall was not registered"
    [ ! -e "$update_config" ] && [ ! -L "$update_config" ] \
        || fail "Arch reinstall recreated intentionally absent update.conf"
    "$runtime_guard" || fail "Arch absent-update.conf reinstall broke runtime parity"
fi

echo "$(basename "$package"): package container lifecycle passed"
