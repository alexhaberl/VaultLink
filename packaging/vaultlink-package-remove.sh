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
    echo "VaultLink Arch removal wrapper: $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run this removal wrapper as root"
case "$#:${1:-}" in
    0:) removal_mode=normal ;;
    1:--recover-failed-install) removal_mode=failed-install ;;
    *)
        echo "usage: vaultlink-package-remove.sh [--recover-failed-install]" >&2
        exit 64
        ;;
esac
for required_command in awk flock install mv pacman readlink rm sha256sum stat systemctl; do
    command -v "$required_command" >/dev/null \
        || fail "$required_command is required"
done

[ -f "$0" ] && [ ! -L "$0" ] \
    || fail "removal wrapper itself must be a regular file, not a symlink"
[ "$(stat -c '%u:%g' "$0")" = 0:0 ] \
    || fail "removal wrapper itself must be owned by root:root"
wrapper_mode=$(stat -c '%a' "$0")
case "$wrapper_mode" in [0-7][0-7][0-7]) ;; *) fail "removal wrapper has an unsupported mode" ;; esac
[ "$((0$wrapper_mode & 0100))" -ne 0 ] \
    || fail "removal wrapper must be executable by root"
[ "$((0$wrapper_mode & 0022))" -eq 0 ] \
    || fail "removal wrapper must not be group- or world-writable"
[ "$(readlink -f -- "$0")" = /usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh ] \
    || fail "removal wrapper must run from its package-owned path"
pacman -Q vaultlink >/dev/null 2>&1 || fail "VaultLink is not installed"

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
            "$(stat -Lc '%d:%i' "$opened_lock_path" 2>/dev/null || true)" ]
}
prepare_lock_file "$install_lock"
prepare_lock_file "$update_lock"
prepare_lock_file "$maintenance_lock"
lock_is_inherited() {
    inherited_fd=$1
    inherited_path=$2
    validate_open_lock "$inherited_fd" "$inherited_path" || return 1
    inherited_fd_identity=$(stat -Lc '%d:%i' "/proc/self/fd/$inherited_fd" 2>/dev/null || true)
    inherited_path_identity=$(stat -Lc '%d:%i' "$inherited_path" 2>/dev/null || true)
    inherited_probe_status=0
    flock -n -E 75 "$inherited_path" true >/dev/null 2>&1 \
        || inherited_probe_status=$?
    [ -n "$inherited_fd_identity" ] \
        && [ "$inherited_fd_identity" = "$inherited_path_identity" ] \
        && [ "$inherited_probe_status" -eq 75 ] \
        && flock -n "$inherited_fd"
}
if ! lock_is_inherited 7 "$install_lock"; then
    exec 7>"$install_lock"
    validate_open_lock 7 "$install_lock" \
        || fail "VaultLink package-install lock changed while it was opened"
    flock -n 7 || fail "another VaultLink package installation is running"
    validate_open_lock 7 "$install_lock" \
        || fail "VaultLink package-install lock changed after locking"
fi
if ! lock_is_inherited 9 "$update_lock"; then
    exec 9>"$update_lock"
    validate_open_lock 9 "$update_lock" \
        || fail "VaultLink update lock changed while it was opened"
    flock -n 9 || fail "another VaultLink update operation is running"
    validate_open_lock 9 "$update_lock" \
        || fail "VaultLink update lock changed after locking"
fi
if ! lock_is_inherited 8 "$maintenance_lock"; then
    exec 8>"$maintenance_lock"
    validate_open_lock 8 "$maintenance_lock" \
        || fail "VaultLink maintenance lock changed while it was opened"
    flock -n 8 || fail "another VaultLink upgrade or rollback is running"
    validate_open_lock 8 "$maintenance_lock" \
        || fail "VaultLink maintenance lock changed after locking"
fi
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

if [ "$removal_mode" = failed-install ]; then
    [ ! -e /usr/share/vaultlink/install-method.env ] \
        && [ ! -L /usr/share/vaultlink/install-method.env ] \
        || fail "failed-install recovery is only valid without package provenance"
    recovery_live_hash=absent
    if [ -e /opt/vaultlink/vaultlink ] || [ -L /opt/vaultlink/vaultlink ]; then
        [ -f /opt/vaultlink/vaultlink ] && [ ! -L /opt/vaultlink/vaultlink ] \
            || fail "markerless active runtime is unsafe"
        recovery_live_hash=$(sha256sum /opt/vaultlink/vaultlink | awk '{ print $1 }')
    fi
    VAULTLINK_ARCH_FAILED_INSTALL_CLEANUP=1 \
        pacman -R --noconfirm vaultlink
    pacman -Q vaultlink >/dev/null 2>&1 \
        && fail "Pacman still reports the rejected package installed"
    [ ! -e /usr/lib/vaultlink/package/vaultlink ] \
        && [ ! -e /usr/share/libalpm/hooks/vaultlink-remove.hook ] \
        || fail "rejected package payload survived recovery removal"
    if [ "$recovery_live_hash" = absent ]; then
        [ ! -e /opt/vaultlink/vaultlink ] && [ ! -L /opt/vaultlink/vaultlink ] \
            || fail "failed-install recovery created an active runtime"
    else
        [ "$(sha256sum /opt/vaultlink/vaultlink | awk '{ print $1 }')" = \
            "$recovery_live_hash" ] \
            || fail "failed-install recovery changed the markerless active runtime"
    fi
    exit 0
fi

removal_mutated=0
removal_complete=0
systemd_manager_present=0
service_active=inactive
service_enabled=disabled
timer_active=inactive
timer_enabled=disabled
if [ -d /run/systemd/system ]; then
    systemd_manager_present=1
    service_active=$(systemctl is-active vaultlink.service 2>/dev/null || true)
    service_enabled=$(systemctl is-enabled vaultlink.service 2>/dev/null || true)
    timer_active=$(systemctl is-active vaultlink-update.timer 2>/dev/null || true)
    timer_enabled=$(systemctl is-enabled vaultlink-update.timer 2>/dev/null || true)
    update_active=$(systemctl is-active vaultlink-update.service 2>/dev/null || true)
    case "$service_active" in active|inactive) ;; *) fail "cannot establish VaultLink service state" ;; esac
    case "$service_enabled" in enabled|disabled) ;; *) fail "cannot establish VaultLink enablement state" ;; esac
    case "$timer_active" in active|inactive) ;; *) fail "cannot establish updater timer state" ;; esac
    case "$timer_enabled" in enabled|disabled) ;; *) fail "cannot establish updater timer enablement" ;; esac
    [ "$update_active" = inactive ] || fail "vaultlink-update.service is not inactive"
fi
restore_units() {
    removal_status=$?
    trap - 0
    trap '' 1 2 15
    if [ "$systemd_manager_present" -eq 1 ] \
        && [ "$removal_mutated" -eq 1 ] \
        && [ "$removal_complete" -eq 0 ]; then
        removal_recovery_failed=0
        systemctl disable --now vaultlink-update.timer vaultlink.service \
            >/dev/null 2>&1 || :
        systemctl stop vaultlink-update.service >/dev/null 2>&1 || :
        for recovery_unit in vaultlink-update.timer vaultlink-update.service vaultlink.service; do
            [ "$(systemctl is-active "$recovery_unit" 2>/dev/null || true)" = inactive ] \
                || removal_recovery_failed=1
        done
        for recovery_unit in vaultlink-update.timer vaultlink.service; do
            [ "$(systemctl is-enabled "$recovery_unit" 2>/dev/null || true)" = disabled ] \
                || removal_recovery_failed=1
        done

        runtime_guard=/usr/lib/vaultlink/package/deploy/vaultlink-runtime-guard.sh
        candidate=/usr/lib/vaultlink/package/vaultlink
        live_binary=/opt/vaultlink/vaultlink
        if [ "$removal_recovery_failed" -eq 0 ] \
            && pacman -Q vaultlink >/dev/null 2>&1 \
            && [ -x "$runtime_guard" ] && [ ! -L "$runtime_guard" ] \
            && [ "$(stat -c '%u:%g:%a' "$runtime_guard")" = 0:0:755 ] \
            && "$runtime_guard" --package-only >/dev/null 2>&1; then
            recovery_live_stage=/opt/vaultlink/.vaultlink.remove-recovery.$$
            rm -f "$recovery_live_stage"
            if install -o root -g root -m 0755 "$candidate" "$recovery_live_stage" \
                && mv -f "$recovery_live_stage" "$live_binary" \
                && "$runtime_guard" >/dev/null 2>&1 \
                && systemctl daemon-reload >/dev/null 2>&1; then
                :
            else
                rm -f "$recovery_live_stage"
                removal_recovery_failed=1
            fi
        else
            removal_recovery_failed=1
        fi

        if [ "$removal_recovery_failed" -eq 0 ]; then
            if [ "$service_enabled" = enabled ]; then
                systemctl enable vaultlink.service >/dev/null 2>&1 \
                    || removal_recovery_failed=1
            fi
            if [ "$timer_enabled" = enabled ]; then
                systemctl enable vaultlink-update.timer >/dev/null 2>&1 \
                    || removal_recovery_failed=1
            fi
            if [ "$service_active" = active ]; then
                systemctl start vaultlink.service >/dev/null 2>&1 \
                    || removal_recovery_failed=1
            fi
            if [ "$timer_active" = active ]; then
                systemctl start vaultlink-update.timer >/dev/null 2>&1 \
                    || removal_recovery_failed=1
            fi
        fi
        if [ "$removal_recovery_failed" -ne 0 ]; then
            systemctl disable --now vaultlink-update.timer vaultlink.service \
                >/dev/null 2>&1 || :
            systemctl stop vaultlink-update.service >/dev/null 2>&1 || :
            echo "CRITICAL: Arch removal failed in a mixed state; all VaultLink units remain inactive" >&2
        fi
    fi
    exit "$removal_status"
}
trap restore_units 0

if [ "$systemd_manager_present" -eq 1 ]; then
    removal_mutated=1
    systemctl disable --now vaultlink-update.timer vaultlink.service >/dev/null
    systemctl stop vaultlink-update.service >/dev/null
    for package_unit in vaultlink-update.timer vaultlink-update.service vaultlink.service; do
        package_unit_state=$(systemctl is-active "$package_unit" 2>/dev/null || true)
        [ "$package_unit_state" = inactive ] \
            || fail "$package_unit did not become inactive (state: ${package_unit_state:-unavailable})"
    done
    for package_unit in vaultlink-update.timer vaultlink.service; do
        package_unit_enabled=$(systemctl is-enabled "$package_unit" 2>/dev/null || true)
        [ "$package_unit_enabled" = disabled ] \
            || fail "$package_unit did not become disabled (state: ${package_unit_enabled:-unavailable})"
    done
fi

pacman -R --noconfirm vaultlink
pacman -Q vaultlink >/dev/null 2>&1 && fail "Pacman still reports VaultLink installed"
[ ! -e /usr/lib/vaultlink/package/vaultlink ] \
    && [ ! -e /opt/vaultlink/vaultlink ] \
    || fail "VaultLink package or active binary survived removal"
removal_complete=1
trap - 0 1 2 15
