#!/bin/sh
# Compound guards intentionally use `A && B || fail` for fail-closed exits.
# shellcheck disable=SC2015
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
LANG=C
export PATH LC_ALL LANG
umask 077

marker=/usr/share/vaultlink/install-method.env
marker_recovery=/var/lib/vaultlink-backups/install-method.env
candidate=/usr/lib/vaultlink/package/vaultlink
candidate_version_file=/usr/lib/vaultlink/package/version
live_binary=/opt/vaultlink/vaultlink
update_example=/usr/share/vaultlink/update.conf.example
update_config=/etc/vaultlink/update.conf
lock_directory=/run/vaultlink-locks
update_lock=$lock_directory/update.lock
maintenance_lock=$lock_directory/maintenance.lock
install_lock=$lock_directory/package-install.lock

package_fail() {
    echo "VaultLink package lifecycle: $*" >&2
    exit 1
}

package_require_root() {
    [ "$(id -u)" -eq 0 ] || package_fail "this operation must run as root"
}

package_validate_argument() {
    argument_name=$1
    argument_value=$2
    case "$argument_value" in
        ''|*[!A-Za-z0-9._+-]*)
            package_fail "$argument_name contains unsafe characters"
            ;;
    esac
}

package_expected_marker() {
    printf 'FORMAT=%s\nOS_ID=%s\nOS_VERSION=%s\nARCH=%s\nPACKAGE_NAME=%s\n' \
        "$package_format" "$os_id" "$os_version" "$package_arch" "$package_name"
}

package_validate_marker() {
    [ -f "$marker" ] && [ ! -L "$marker" ] \
        || package_fail "missing or unsafe installation marker: $marker"
    [ "$(stat -c '%u:%g:%a' "$marker")" = '0:0:644' ] \
        || package_fail "installation marker must be root:root mode 0644"
    [ "$(wc -l <"$marker" | tr -d '[:space:]')" = 5 ] \
        || package_fail "installation marker must contain exactly five lines"
    marker_actual=$(cat "$marker")
    marker_expected=$(package_expected_marker)
    [ "$marker_actual" = "$marker_expected" ] \
        || package_fail "installation marker does not match this package target"
}

package_validate_marker_recovery() {
    package_validate_regular_file "$marker_recovery" 600
    [ -d "${marker_recovery%/*}" ] && [ ! -L "${marker_recovery%/*}" ] \
        && [ "$(stat -c '%u:%g:%a' "${marker_recovery%/*}")" = 0:0:700 ] \
        || package_fail "marker recovery directory is unsafe"
    [ "$(wc -l <"$marker_recovery" | tr -d '[:space:]')" -eq 5 ] \
        || package_fail "marker recovery must contain exactly five lines"
    expected_recovery_marker=$(package_expected_marker)
    [ "$(cat "$marker_recovery")" = "$expected_recovery_marker" ] \
        || package_fail "marker recovery does not match this package target"
}

package_write_marker_recovery() {
    if [ -e "$marker_recovery" ] || [ -L "$marker_recovery" ]; then
        package_validate_marker_recovery
        return 0
    fi
    marker_recovery_directory=${marker_recovery%/*}
    if [ -e "$marker_recovery_directory" ] || [ -L "$marker_recovery_directory" ]; then
        [ -d "$marker_recovery_directory" ] && [ ! -L "$marker_recovery_directory" ] \
            && [ "$(stat -c '%u:%g:%a' "$marker_recovery_directory")" = 0:0:700 ] \
            || package_fail "marker recovery directory is unsafe"
    else
        install -d -o root -g root -m 0700 "$marker_recovery_directory"
    fi
    marker_recovery_stage="$marker_recovery_directory/.install-method.env.$$"
    package_expected_marker >"$marker_recovery_stage"
    chown root:root "$marker_recovery_stage"
    chmod 0600 "$marker_recovery_stage"
    mv -f "$marker_recovery_stage" "$marker_recovery"
    marker_recovery_stage=
    package_validate_marker_recovery
}

package_recover_marker_if_needed() {
    [ ! -e "$marker" ] && [ ! -L "$marker" ] || return 0
    [ -e "$marker_recovery" ] || [ -L "$marker_recovery" ] || return 0
    package_validate_marker_recovery
    # A persistent recovery marker proves only that a supported package once
    # existed. It must never bless archive files created after a normal
    # removal. Recovery is limited to the exact interrupted-remove shape:
    # package-owned and archive control/runtime paths are all absent, while
    # documented mutable configuration and state may remain.
    for interrupted_remove_path in \
        /opt/vaultlink/vaultlink \
        /usr/lib/vaultlink \
        /usr/share/vaultlink \
        /usr/share/doc/vaultlink \
        /usr/share/licenses/vaultlink \
        /usr/lib/systemd/system/vaultlink.service \
        /usr/lib/systemd/system/vaultlink-update.service \
        /usr/lib/systemd/system/vaultlink-update.timer \
        /usr/lib/sysusers.d/vaultlink.conf \
        /usr/lib/tmpfiles.d/vaultlink.conf \
        /usr/share/libalpm/hooks/vaultlink-remove.hook \
        /usr/bin/vaultlink-update \
        /usr/sbin/vaultlink-update \
        /usr/local/sbin/vaultlink-update \
        /etc/systemd/system/vaultlink.service \
        /etc/systemd/system/vaultlink-update.service \
        /etc/systemd/system/vaultlink-update.timer; do
        if [ -e "$interrupted_remove_path" ] || [ -L "$interrupted_remove_path" ]; then
            package_fail "marker recovery rejected non-removal state: $interrupted_remove_path"
        fi
    done
    install -d -o root -g root -m 0755 "${marker%/*}"
    recovered_marker_stage="${marker%/*}/.install-method.env.recover.$$"
    install -o root -g root -m 0644 "$marker_recovery" "$recovered_marker_stage"
    mv -f "$recovered_marker_stage" "$marker"
    recovered_marker_stage=
    package_validate_marker
}

package_read_os_field() {
    field=$1
    values=$(sed -n "s/^${field}=//p" /etc/os-release)
    [ "$(printf '%s\n' "$values" | grep -c .)" -eq 1 ] \
        || package_fail "/etc/os-release must define $field exactly once"
    case "$values" in
        \"*\") values=${values#\"}; values=${values%\"} ;;
    esac
    case "$values" in
        ''|*[!A-Za-z0-9._+-]*) package_fail "unsafe $field in /etc/os-release" ;;
    esac
    printf '%s\n' "$values"
}

package_validate_platform() {
    [ -r /etc/os-release ] || package_fail "/etc/os-release is unavailable"
    actual_os_id=$(package_read_os_field ID)
    [ "$actual_os_id" = "$os_id" ] \
        || package_fail "package is for $os_id, host is $actual_os_id"
    if [ "$os_id" != arch ]; then
        actual_os_version=$(package_read_os_field VERSION_ID)
        [ "$actual_os_version" = "$os_version" ] \
            || package_fail "package is for $os_id $os_version, host is $actual_os_version"
    else
        [ "$os_version" = rolling ] \
            || package_fail "Arch packages must carry the rolling host marker"
    fi

    actual_machine=$(uname -m)
    case "$package_arch:$actual_machine" in
        amd64:x86_64|arm64:aarch64|x86_64:x86_64|aarch64:aarch64) ;;
        *) package_fail "package architecture $package_arch does not match host $actual_machine" ;;
    esac
}

package_validate_regular_file() {
    file=$1
    expected_mode=$2
    [ -f "$file" ] && [ ! -L "$file" ] \
        || package_fail "missing or unsafe package file: $file"
    [ "$(stat -c '%u:%g:%a' "$file")" = "0:0:$expected_mode" ] \
        || package_fail "$file must be root:root mode $expected_mode"
}

package_read_identity_entry() {
    database=$1
    entry=$(getent "$database" vaultlink 2>/dev/null || true)
    entry_count=$(printf '%s\n' "$entry" | grep -c . || true)
    [ "$entry_count" -le 1 ] \
        || package_fail "service identity has duplicate $database entries"
    printf '%s\n' "$entry"
}

package_validate_service_identity() {
    command -v getent >/dev/null || package_fail "getent is required"
    command -v id >/dev/null || package_fail "id is required"

    passwd_entry=$(package_read_identity_entry passwd)
    group_entry=$(package_read_identity_entry group)
    shadow_entry=$(package_read_identity_entry shadow)
    [ -n "$passwd_entry" ] && [ -n "$group_entry" ] && [ -n "$shadow_entry" ] \
        || package_fail "vaultlink service identity is incomplete"

    IFS=: read -r identity_name identity_password identity_uid identity_gid \
        identity_gecos identity_home identity_shell identity_extra <<EOF
$passwd_entry
EOF
    [ "$identity_name" = vaultlink ] && [ "$identity_password" = x ] \
        && [ "$identity_gecos" = 'VaultLink service account' ] \
        && [ -z "$identity_extra" ] \
        || package_fail "vaultlink passwd entry is malformed"
    case "$identity_uid:$identity_gid" in
        *[!0-9:]*|:*|*:) package_fail "vaultlink UID or GID is not decimal" ;;
    esac
    [ "$identity_uid" -ge 1 ] && [ "$identity_uid" -lt 1000 ] \
        || package_fail "vaultlink must use a non-root system UID below 1000"
    [ "$identity_home" = /var/lib/vaultlink ] \
        || package_fail "vaultlink home directory is unexpected"
    case "$os_id:$identity_shell" in
        debian:/usr/sbin/nologin|ubuntu:/usr/sbin/nologin|\
        fedora:/usr/sbin/nologin|arch:/usr/bin/nologin) ;;
        *) package_fail "vaultlink login shell is unexpected for $os_id" ;;
    esac
    [ -x "$identity_shell" ] && [ ! -L "$identity_shell" ] \
        || package_fail "vaultlink nologin shell is unavailable or unsafe"

    IFS=: read -r service_group_name service_group_password service_group_gid \
        service_group_members service_group_extra <<EOF
$group_entry
EOF
    [ "$service_group_name" = vaultlink ] \
        && [ "$service_group_password" = x ] \
        && [ "$service_group_gid" = "$identity_gid" ] \
        && [ -z "$service_group_members" ] \
        && [ -z "$service_group_extra" ] \
        || package_fail "vaultlink group entry is not the exact sole primary group"

    [ "$(printf '%s\n' "$shadow_entry" | awk -F : '{ print NF }')" -eq 9 ] \
        || package_fail "vaultlink shadow entry must contain exactly nine fields"
    shadow_name=${shadow_entry%%:*}
    shadow_tail=${shadow_entry#*:}
    shadow_password=${shadow_tail%%:*}
    [ "$shadow_name" = vaultlink ] && [ -n "$shadow_password" ] \
        || package_fail "vaultlink shadow entry is malformed"
    case "$shadow_password" in
        !*|\**) ;;
        *) package_fail "vaultlink shadow password is not locked" ;;
    esac

    [ "$(id -u vaultlink)" = "$identity_uid" ] \
        && [ "$(id -g vaultlink)" = "$identity_gid" ] \
        && [ "$(id -gn vaultlink)" = vaultlink ] \
        && [ "$(id -Gn vaultlink)" = vaultlink ] \
        || package_fail "vaultlink must belong only to its exact primary group"
}

package_validate_service_identity_if_present() {
    passwd_entry=$(package_read_identity_entry passwd)
    group_entry=$(package_read_identity_entry group)
    shadow_entry=$(package_read_identity_entry shadow)
    if [ -n "$passwd_entry" ] || [ -n "$group_entry" ] \
        || [ -n "$shadow_entry" ]; then
        package_validate_service_identity
    fi
}

package_create_arch_marker() {
    [ "$package_format" = pkg.tar.zst ] || return 0
    if [ ! -e "$marker" ] && [ ! -L "$marker" ]; then
        # Pacman does not propagate .INSTALL hook failures as transaction
        # failures. Recheck every pre-existing state boundary that an archive
        # installation could have created before granting package provenance.
        for legacy_path in \
            /opt/vaultlink/vaultlink \
            /etc/vaultlink/config.toml \
            /etc/vaultlink/update.conf \
            /var/lib/vaultlink/data.sqlite \
            /var/lib/vaultlink/secrets.keyring \
            /usr/local/sbin/vaultlink-update \
            /etc/systemd/system/vaultlink.service; do
            if [ -e "$legacy_path" ] || [ -L "$legacy_path" ]; then
                package_fail "refusing to grant package provenance to markerless existing installation: $legacy_path"
            fi
        done
        install -d -o root -g root -m 0755 /usr/share/vaultlink
        arch_marker_stage=/usr/share/vaultlink/.install-method.env.$$
        package_expected_marker >"$arch_marker_stage"
        chown root:root "$arch_marker_stage"
        chmod 0644 "$arch_marker_stage"
        mv -f "$arch_marker_stage" "$marker"
        arch_marker_stage=
        arch_marker_created=1
    fi
}

package_reject_markerless_installation() {
    # These application-specific paths are either package-owned payload or
    # mutable archive-install state. Without a valid host marker none may be
    # adopted or overwritten, even when their contents happen to match.
    for markerless_path in \
        /opt/vaultlink/vaultlink \
        /etc/vaultlink/config.toml \
        /etc/vaultlink/update.conf \
        /var/lib/vaultlink/data.sqlite \
        /var/lib/vaultlink/secrets.keyring \
        /usr/lib/vaultlink \
        /usr/share/vaultlink \
        /usr/share/doc/vaultlink \
        /usr/share/licenses/vaultlink \
        /usr/lib/systemd/system/vaultlink.service \
        /usr/lib/systemd/system/vaultlink-update.service \
        /usr/lib/systemd/system/vaultlink-update.timer \
        /usr/lib/sysusers.d/vaultlink.conf \
        /usr/lib/tmpfiles.d/vaultlink.conf \
        /usr/share/libalpm/hooks/vaultlink-remove.hook \
        /usr/bin/vaultlink-update \
        /usr/sbin/vaultlink-update \
        /usr/local/sbin/vaultlink-update \
        /etc/systemd/system/vaultlink.service \
        /etc/systemd/system/vaultlink-update.service \
        /etc/systemd/system/vaultlink-update.timer; do
        if [ -e "$markerless_path" ] || [ -L "$markerless_path" ]; then
            package_fail "refusing to adopt markerless existing installation: $markerless_path"
        fi
    done
}

package_preinstall() {
    mode=$1
    case "$mode" in fresh|reinstall|upgrade) ;; *) package_fail "invalid preinstall mode" ;; esac
    package_validate_platform
    package_recover_marker_if_needed

    if [ -e "$marker" ] || [ -L "$marker" ]; then
        package_validate_marker
        package_validate_service_identity
        if [ "$mode" = upgrade ]; then
            package_validate_regular_file "$candidate" 755
            package_validate_regular_file "$live_binary" 755
            if [ "${VAULTLINK_PACKAGE_RECOVERY:-0}" = 1 ]; then
                if [ "$package_format" = rpm ]; then
                    # RPM deliberately closes unrelated descriptors before
                    # running scriptlets. The updater still holds both locks
                    # across the transaction, so RPM recovery proves the two
                    # exact root-owned lock files remain contended instead.
                    package_lock_path_is_secure_and_contended "$update_lock" \
                        && package_lock_path_is_secure_and_contended "$maintenance_lock" \
                        || package_fail "RPM package recovery requires both secure updater locks to be held"
                else
                    package_lock_is_inherited 9 "$update_lock" \
                        && package_lock_is_inherited 8 "$maintenance_lock" \
                        || package_fail "package recovery requires inherited locked update and maintenance descriptors"
                fi
            else
                cmp -s "$candidate" "$live_binary" \
                    || package_fail "package upgrade requires existing live/candidate parity"
            fi
        fi
        return 0
    fi
    [ "$mode" = fresh ] \
        || package_fail "an upgrade requires an existing valid installation marker"
    package_validate_service_identity_if_present
    package_reject_markerless_installation
}

package_write_update_default() {
    install_mode=$1
    if [ ! -e "$update_config" ] && [ ! -L "$update_config" ]; then
        [ "$install_mode" = fresh ] || return 0
        # Arch retains the unowned provenance marker across package removal.
        # A later reinstall is still a pacman `post_install`, but conscious
        # absence of update.conf must remain absence. Only the transaction
        # that minted the fresh marker may install the default.
        if [ "$package_format" = pkg.tar.zst ] \
            && [ "${arch_marker_created:-0}" -eq 0 ]; then
            return 0
        fi
        package_validate_regular_file "$update_example" 644
        install -d -o root -g vaultlink -m 0750 /etc/vaultlink
        install -o root -g root -m 0644 "$update_example" "$update_config"
    elif [ -L "$update_config" ] || [ ! -f "$update_config" ]; then
        package_fail "existing updater configuration is not a regular file"
    fi
}

package_postinstall_cleanup() {
    postinstall_status=$?
    trap - 0 1 2 15
    if [ -n "${arch_marker_stage:-}" ]; then
        rm -f "$arch_marker_stage"
    fi
    if [ -n "${live_stage:-}" ]; then
        rm -f "$live_stage"
    fi
    if [ -n "${marker_recovery_stage:-}" ]; then
        rm -f "$marker_recovery_stage"
    fi
    if [ -n "${recovered_marker_stage:-}" ]; then
        rm -f "$recovered_marker_stage"
    fi
    if [ "$postinstall_status" -ne 0 ] \
        && [ "${arch_marker_created:-0}" -eq 1 ]; then
        rm -f "$marker"
    fi
    exit "$postinstall_status"
}

package_postinstall() {
    mode=$1
    version=$2
    case "$mode" in fresh|reinstall|upgrade) ;; *) package_fail "invalid postinstall mode" ;; esac
    arch_marker_created=0
    arch_marker_stage=
    live_stage=
    marker_recovery_stage=
    recovered_marker_stage=
    # Only a marker minted by this exact fresh Arch postinstall is provisional.
    # Existing DEB, RPM, and Arch provenance survives later configuration
    # failures so a failed upgrade cannot erase the trusted rollback identity.
    trap package_postinstall_cleanup 0
    trap 'exit 129' 1
    trap 'exit 130' 2
    trap 'exit 143' 15
    package_validate_platform
    package_create_arch_marker
    package_validate_marker
    package_write_marker_recovery

    command -v systemd-tmpfiles >/dev/null \
        || package_fail "systemd-tmpfiles is required"
    if [ "$mode" = fresh ]; then
        command -v systemd-sysusers >/dev/null \
            || package_fail "systemd-sysusers is required"
        systemd-sysusers /usr/lib/sysusers.d/vaultlink.conf
        package_validate_service_identity
    else
        # The protected automatic-update unit deliberately cannot mutate
        # /etc/passwd. Upgrades must use the exact existing identity that was
        # validated before package mutation; sysusers is fresh-install only.
        package_validate_service_identity
    fi
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/vaultlink.conf

    package_validate_regular_file "$candidate" 755
    package_validate_regular_file "$candidate_version_file" 644
    package_validate_regular_file /usr/share/vaultlink/minisign.pub 644
    package_validate_regular_file /usr/lib/vaultlink/package/deploy/vaultlink-upgrade.sh 755
    package_validate_regular_file /usr/lib/vaultlink/package/deploy/vaultlink-rollback.sh 755
    package_validate_regular_file /usr/lib/vaultlink/package/deploy/vaultlink-runtime-guard.sh 755
    if [ "$package_format" = pkg.tar.zst ]; then
        package_validate_regular_file /usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh 755
    fi
    package_validate_regular_file /usr/sbin/vaultlink-update 755
    [ "$(cat "$candidate_version_file")" = "$version" ] \
        || package_fail "candidate version metadata does not match package version"

    for required_command in cmp timeout runuser install mv; do
        command -v "$required_command" >/dev/null \
            || package_fail "$required_command is required"
    done
    if ! candidate_version=$(timeout --kill-after=2 5 runuser -u vaultlink -- "$candidate" --version); then
        package_fail "candidate did not provide a bounded version response"
    fi
    [ "$candidate_version" = "$version" ] \
        || package_fail "candidate reports $candidate_version instead of $version"

    package_write_update_default "$mode"

    if [ "$mode" != upgrade ]; then
        if command -v systemctl >/dev/null \
            && systemctl --quiet is-active vaultlink.service 2>/dev/null; then
            package_fail "$mode installation found an unexpectedly active service"
        fi
        if [ ! -e "$live_binary" ] && [ ! -L "$live_binary" ]; then
            live_stage=/opt/vaultlink/.vaultlink.package-new.$$
            install -o root -g root -m 0755 "$candidate" "$live_stage"
            mv -f "$live_stage" "$live_binary"
            live_stage=
        else
            # `dpkg --configure` must be repeatable after a reboot between
            # unpack and configure, including a power loss immediately after
            # the atomic copy. Only the exact package candidate is accepted;
            # preinst remains the markerless legacy/adoption boundary.
            package_validate_regular_file "$live_binary" 755
            cmp -s "$candidate" "$live_binary" \
                || package_fail "$mode configure found a divergent active binary"
        fi
    else
        # A package upgrade stages only the candidate. The signed updater owns
        # transactional activation, readiness verification, and package-level
        # rollback; package-manager scriptlets must not alter /opt here.
        [ -x "$live_binary" ] && [ ! -L "$live_binary" ] \
            || package_fail "package upgrade requires the existing active binary"
    fi

    if command -v systemctl >/dev/null; then
        systemctl daemon-reload >/dev/null 2>&1 || :
    fi
    trap - 0 1 2 15
}

package_systemd_manager_present() {
    [ -d /run/systemd/system ]
}

package_validate_lock_directory() {
    [ -d /run ] && [ ! -L /run ] \
        && [ "$(stat -Lc '%u:%g:%a' /run 2>/dev/null || true)" = 0:0:755 ] \
        || return 1
    [ -d "$lock_directory" ] && [ ! -L "$lock_directory" ] \
        && [ "$(stat -Lc '%u:%g:%a' "$lock_directory" 2>/dev/null || true)" = 0:0:700 ]
}

package_prepare_lock_directory() {
    [ -d /run ] && [ ! -L /run ] \
        && [ "$(stat -Lc '%u:%g:%a' /run 2>/dev/null || true)" = 0:0:755 ] \
        || package_fail "/run must be a root-owned mode-0755 directory"
    if [ -e "$lock_directory" ] || [ -L "$lock_directory" ]; then
        package_validate_lock_directory \
            || package_fail "VaultLink lock directory is unsafe"
    else
        install -d -o root -g root -m 0700 "$lock_directory"
    fi
    package_validate_lock_directory \
        || package_fail "VaultLink lock directory is unsafe"
}

package_validate_lock_file() {
    package_validated_lock_path=$1
    package_validate_lock_directory \
        && [ -f "$package_validated_lock_path" ] \
        && [ ! -L "$package_validated_lock_path" ] \
        && [ "$(stat -Lc '%u:%g:%a' "$package_validated_lock_path" 2>/dev/null || true)" = 0:0:600 ]
}

package_prepare_lock_file() {
    package_prepared_lock_path=$1
    package_prepare_lock_directory
    if [ -e "$package_prepared_lock_path" ] || [ -L "$package_prepared_lock_path" ]; then
        package_validate_lock_file "$package_prepared_lock_path" \
            || package_fail "VaultLink lock file is unsafe: $package_prepared_lock_path"
    else
        install -o root -g root -m 0600 /dev/null "$package_prepared_lock_path"
    fi
    package_validate_lock_file "$package_prepared_lock_path" \
        || package_fail "VaultLink lock file is unsafe: $package_prepared_lock_path"
}

package_lock_is_inherited() {
    package_lock_fd=$1
    package_lock_path=$2
    package_validate_lock_file "$package_lock_path" || return 1
    package_lock_fd_identity=$(stat -Lc '%d:%i' "/proc/self/fd/$package_lock_fd" 2>/dev/null || true)
    package_lock_path_identity=$(stat -Lc '%d:%i' "$package_lock_path" 2>/dev/null || true)
    [ -n "$package_lock_fd_identity" ] \
        && [ "$package_lock_fd_identity" = "$package_lock_path_identity" ] \
        || return 1

    # Prove the inherited open-file description was already locked. Merely
    # calling `flock -n FD` is insufficient because it would acquire an
    # unlocked descriptor and turn an untrusted recovery request into an
    # authorized one. A separate descriptor must first observe contention;
    # the inherited descriptor itself must then be able to re-lock.
    package_lock_probe_status=0
    flock -n -E 75 "$package_lock_path" true >/dev/null 2>&1 \
        || package_lock_probe_status=$?
    [ "$package_lock_probe_status" -eq 75 ] \
        && flock -n "$package_lock_fd"
}

package_lock_path_is_secure_and_contended() {
    package_contended_lock_path=$1
    package_validate_lock_file "$package_contended_lock_path" || return 1
    package_contended_lock_identity_before=$(stat -Lc '%d:%i' "$package_contended_lock_path" 2>/dev/null || true)
    [ -n "$package_contended_lock_identity_before" ] || return 1
    package_contended_lock_status=0
    flock -n -E 75 "$package_contended_lock_path" true >/dev/null 2>&1 \
        || package_contended_lock_status=$?
    package_contended_lock_identity_after=$(stat -Lc '%d:%i' "$package_contended_lock_path" 2>/dev/null || true)
    [ "$package_contended_lock_status" -eq 75 ] \
        && [ "$package_contended_lock_identity_after" = "$package_contended_lock_identity_before" ]
}

package_require_inherited_removal_locks() {
    package_lock_is_inherited 9 "$update_lock" \
        || package_fail "Arch removal requires the signed wrapper holding the update lock"
    package_lock_is_inherited 8 "$maintenance_lock" \
        || package_fail "Arch removal requires the signed wrapper holding the maintenance lock"
}

package_failed_install_cleanup_authorized() {
    [ "$package_format" = pkg.tar.zst ] \
        && [ "${VAULTLINK_ARCH_FAILED_INSTALL_CLEANUP:-0}" = 1 ] \
        && [ ! -e "$marker" ] && [ ! -L "$marker" ] \
        && package_lock_is_inherited 7 "$install_lock" \
        && package_lock_is_inherited 9 "$update_lock" \
        && package_lock_is_inherited 8 "$maintenance_lock"
}

package_acquire_removal_locks() {
    package_prepare_lock_file "$update_lock"
    package_prepare_lock_file "$maintenance_lock"
    if ! package_lock_is_inherited 9 "$update_lock"; then
        exec 9>"$update_lock"
        package_validate_lock_file "$update_lock" \
            && [ "$(stat -Lc '%d:%i' /proc/self/fd/9 2>/dev/null || true)" = \
                "$(stat -Lc '%d:%i' "$update_lock" 2>/dev/null || true)" ] \
            || package_fail "VaultLink update lock changed while it was opened"
        flock -n 9 \
            || package_fail "another VaultLink update operation is running"
        package_validate_lock_file "$update_lock" \
            && [ "$(stat -Lc '%d:%i' /proc/self/fd/9 2>/dev/null || true)" = \
                "$(stat -Lc '%d:%i' "$update_lock" 2>/dev/null || true)" ] \
            || package_fail "VaultLink update lock changed after locking"
    fi
    if ! package_lock_is_inherited 8 "$maintenance_lock"; then
        exec 8>"$maintenance_lock"
        package_validate_lock_file "$maintenance_lock" \
            && [ "$(stat -Lc '%d:%i' /proc/self/fd/8 2>/dev/null || true)" = \
                "$(stat -Lc '%d:%i' "$maintenance_lock" 2>/dev/null || true)" ] \
            || package_fail "VaultLink maintenance lock changed while it was opened"
        flock -n 8 \
            || package_fail "another VaultLink upgrade or rollback is running"
        package_validate_lock_file "$maintenance_lock" \
            && [ "$(stat -Lc '%d:%i' /proc/self/fd/8 2>/dev/null || true)" = \
                "$(stat -Lc '%d:%i' "$maintenance_lock" 2>/dev/null || true)" ] \
            || package_fail "VaultLink maintenance lock changed after locking"
    fi
}

package_preremove_preflight() {
    mode=$1
    [ "$mode" = remove ] || package_fail "invalid removal-preflight mode"
    package_validate_platform
    if package_failed_install_cleanup_authorized; then
        # Pacman may register a package even though its post_install failed.
        # The signed install/removal wrappers hold all three exact locks while
        # this markerless cleanup removes only package-owned payload.
        return 0
    fi
    package_validate_marker
    package_validate_service_identity
    package_require_inherited_removal_locks

    # This path is used by Arch's AbortOnFail PreTransaction hook and must be
    # strictly read-only. The signed removal wrapper owns both serialization
    # locks and stops/disables the units before invoking Pacman, so a direct
    # `pacman -R` is rejected without creating a lock-check TOCTOU window.
    if command -v systemctl >/dev/null && package_systemd_manager_present; then
        for package_unit in vaultlink-update.timer vaultlink-update.service vaultlink.service; do
            package_unit_state=$(systemctl is-active "$package_unit" 2>/dev/null || true)
            [ "$package_unit_state" = inactive ] \
                || package_fail "$package_unit must already be inactive before package removal (state: ${package_unit_state:-unavailable})"
        done
        for package_unit in vaultlink-update.timer vaultlink.service; do
            package_unit_enabled=$(systemctl is-enabled "$package_unit" 2>/dev/null || true)
            [ "$package_unit_enabled" = disabled ] \
                || package_fail "$package_unit must already be disabled before package removal (state: ${package_unit_enabled:-unavailable})"
        done
    fi
}

package_preremove() {
    mode=$1
    [ "$mode" = remove ] || package_fail "invalid removal mode"
    package_validate_platform
    if package_failed_install_cleanup_authorized; then
        # Never unlink /opt in markerless cleanup: it may belong to the
        # rejected archive installation that caused post_install to fail.
        return 0
    fi
    package_validate_marker
    if [ "$package_format" = pkg.tar.zst ]; then
        package_require_inherited_removal_locks
    else
        # DEB/RPM scriptlets own their locks. Acquire both before the first
        # persistent, systemd, or /opt mutation so lock contention cannot
        # change recovery provenance or leave a stopped service behind while
        # the package transaction itself aborts.
        package_acquire_removal_locks
    fi
    package_validate_service_identity
    if [ "$package_format" != pkg.tar.zst ]; then
        # DEB/RPM own the public marker and remove it before their post-remove
        # scriptlet runs. Persist an exact root-only recovery copy first so a
        # reboot in that window remains safely reinstallable.
        package_write_marker_recovery
    fi
    if command -v systemctl >/dev/null && package_systemd_manager_present; then
        # A stop error is tolerable only when both units nevertheless report
        # the exact terminal inactive state. Never unlink the active binary
        # while a service is active, transitioning, failed, or unknowable.
        systemctl disable --now \
            vaultlink-update.timer vaultlink.service >/dev/null 2>&1 || :
        systemctl stop vaultlink-update.service >/dev/null 2>&1 || :
        for package_unit in vaultlink-update.timer vaultlink-update.service vaultlink.service; do
            package_unit_state=$(systemctl is-active "$package_unit" 2>/dev/null || true)
            [ "$package_unit_state" = inactive ] \
                || package_fail "cannot prove $package_unit inactive before removal (state: ${package_unit_state:-unavailable})"
        done
    fi
    if [ -e "$live_binary" ] || [ -L "$live_binary" ]; then
        [ ! -L "$live_binary" ] && [ -f "$live_binary" ] \
            || package_fail "refusing to remove unsafe active binary"
        rm -f "$live_binary"
    fi
}

package_postremove_cleanup() {
    postremove_status=$?
    trap - 0
    trap '' 1 2 15
    [ -z "${marker_stage:-}" ] || rm -f "$marker_stage"
    exit "$postremove_status"
}

package_postremove() {
    mode=$1
    [ "$mode" = remove ] || package_fail "invalid post-removal mode"

    # A rejected direct Arch pacman transaction has no valid marker. Pacman
    # may nevertheless register and later remove that package; never mint
    # provenance for the pre-existing archive installation in that path.
    if [ "$package_format" = pkg.tar.zst ] \
        && [ ! -e "$marker" ] && [ ! -L "$marker" ]; then
        if command -v systemctl >/dev/null; then
            systemctl daemon-reload >/dev/null 2>&1 || :
        fi
        return 0
    fi

    # Ordinary removal deliberately preserves configuration, database,
    # keyring, backups, service identity, and this provenance marker. The
    # marker allows a later package reinstall while still rejecting an old
    # markerless archive installation.
    install -d -o root -g root -m 0755 /usr/share/vaultlink
    marker_stage=/usr/share/vaultlink/.install-method.env.$$
    trap package_postremove_cleanup 0
    trap 'exit 129' 1
    trap 'exit 130' 2
    trap 'exit 143' 15
    package_expected_marker >"$marker_stage"
    chown root:root "$marker_stage"
    chmod 0644 "$marker_stage"
    mv -f "$marker_stage" "$marker"
    marker_stage=
    trap - 0 1 2 15
    package_write_marker_recovery

    if command -v systemctl >/dev/null; then
        systemctl daemon-reload >/dev/null 2>&1 || :
    fi
}

vaultlink_package_main() {
    package_require_root
    [ "$#" -ge 6 ] || package_fail "incomplete lifecycle arguments"
    operation=$1
    package_format=$2
    os_id=$3
    os_version=$4
    package_arch=$5
    package_name=$6
    shift 6

    for argument_pair in \
        "FORMAT:$package_format" \
        "OS_ID:$os_id" \
        "OS_VERSION:$os_version" \
        "ARCH:$package_arch" \
        "PACKAGE_NAME:$package_name"; do
        package_validate_argument "${argument_pair%%:*}" "${argument_pair#*:}"
    done
    [ "$package_name" = vaultlink ] || package_fail "unexpected package name"
    case "$package_format:$os_id:$os_version:$package_arch" in
        deb:debian:13:amd64|deb:debian:13:arm64|\
        deb:ubuntu:24.04:amd64|deb:ubuntu:24.04:arm64|\
        deb:ubuntu:26.04:amd64|deb:ubuntu:26.04:arm64|\
        rpm:fedora:44:x86_64|rpm:fedora:44:aarch64|\
        pkg.tar.zst:arch:rolling:x86_64) ;;
        *) package_fail "unsupported package target tuple" ;;
    esac

    case "$operation" in
        preinstall)
            [ "$#" -eq 1 ] || package_fail "preinstall expects MODE"
            package_preinstall "$1"
            ;;
        postinstall)
            [ "$#" -eq 2 ] || package_fail "postinstall expects MODE VERSION"
            package_validate_argument VERSION "$2"
            package_postinstall "$1" "$2"
            ;;
        preremove)
            [ "$#" -eq 1 ] || package_fail "preremove expects MODE"
            package_preremove "$1"
            ;;
        preremove-preflight)
            [ "$#" -eq 1 ] || package_fail "preremove-preflight expects MODE"
            package_preremove_preflight "$1"
            ;;
        postremove)
            [ "$#" -eq 1 ] || package_fail "postremove expects MODE"
            package_postremove "$1"
            ;;
        *) package_fail "unknown lifecycle operation: $operation" ;;
    esac
}

if [ "${VAULTLINK_PACKAGE_LIFECYCLE_EMBEDDED:-0}" != 1 ]; then
    vaultlink_package_main "$@"
fi
