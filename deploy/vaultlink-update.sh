#!/bin/sh
# Compound guards intentionally use `A && B || return/fail` to fail closed.
# shellcheck disable=SC2015
set -eu
umask 077
LC_ALL=C
LANG=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL LANG PATH
# Never inherit the maintainer-script recovery capability from the caller.
# The verified old-package branch sets it only inside a short-lived subshell
# after FD9 and FD8 are both already locked by this updater.
unset VAULTLINK_PACKAGE_RECOVERY

repository=alexhaberl/VaultLink
github_origin=https://github.com
latest_release_url="$github_origin/$repository/releases/latest"
package_name=vaultlink
live_binary=/opt/vaultlink/vaultlink
live_config=/etc/vaultlink/config.toml
data=/var/lib/vaultlink/data.sqlite
keyring=/var/lib/vaultlink/secrets.keyring
update_config=/etc/vaultlink/update.conf
public_key=/usr/share/vaultlink/minisign.pub
install_method=/usr/share/vaultlink/install-method.env
package_binary=/usr/lib/vaultlink/package/vaultlink
package_lifecycle=/usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh
package_installer=/usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh
package_remover=/usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh
runtime_guard=/usr/lib/vaultlink/package/deploy/vaultlink-runtime-guard.sh
package_remove_hook=/usr/share/libalpm/hooks/vaultlink-remove.hook
package_upgrade=/usr/lib/vaultlink/package/deploy/vaultlink-upgrade.sh
package_rollback=/usr/lib/vaultlink/package/deploy/vaultlink-rollback.sh
lock_directory=/run/vaultlink-locks
update_lock=$lock_directory/update.lock
maintenance_lock=$lock_directory/maintenance.lock
backup_root=/var/lib/vaultlink-backups
work_root=/var/lib/vaultlink-backups/update-evidence
package_limit=536870912
metadata_limit=1048576

work=
package_mutation_started=0
service_downtime_started=0
recovery_backup=
recovery_backup_valid=0
service_was_active=0
update_complete=0
old_package_file=
maintenance_lock_held=0
preserve_work=0
trusted_install_method=

fail() {
    echo "VaultLink update failed: $*" >&2
    exit 1
}

# Recompute DEB metadata with dpkg-gencontrol's reproducible Debian Policy
# 5.6.20 algorithm instead of filesystem-dependent allocated blocks.
debian_installed_size() {
    deb_size_root=$1
    deb_size_inventory=$2
    find "$deb_size_root" -printf '%y\t%s\t%D:%i\n' >"$deb_size_inventory" \
        || return 1
    awk -F '\t' '
        $1 == "f" || $1 == "l" {
            if (!seen[$3]++) total += int(($2 + 1023) / 1024)
            next
        }
        { total += 1 }
        END { print total + 0 }
    ' "$deb_size_inventory"
}

validate_lock_directory() {
    [ -d /run ] && [ ! -L /run ] \
        && [ "$(stat -Lc '%u:%g:%a' /run 2>/dev/null || true)" = 0:0:755 ] \
        && [ -d "$lock_directory" ] && [ ! -L "$lock_directory" ] \
        && [ "$(stat -Lc '%u:%g:%a' "$lock_directory" 2>/dev/null || true)" = 0:0:700 ]
}

prepare_lock_file() {
    prepared_lock_path=$1
    [ -d /run ] && [ ! -L /run ] \
        && [ "$(stat -Lc '%u:%g:%a' /run 2>/dev/null || true)" = 0:0:755 ] \
        || return 1
    if [ -e "$lock_directory" ] || [ -L "$lock_directory" ]; then
        validate_lock_directory || return 1
    else
        install -d -o root -g root -m 0700 "$lock_directory" || return 1
    fi
    if [ -e "$prepared_lock_path" ] || [ -L "$prepared_lock_path" ]; then
        [ -f "$prepared_lock_path" ] && [ ! -L "$prepared_lock_path" ] \
            && [ "$(stat -Lc '%u:%g:%a' "$prepared_lock_path" 2>/dev/null || true)" = 0:0:600 ] \
            || return 1
    else
        install -o root -g root -m 0600 /dev/null "$prepared_lock_path" || return 1
    fi
    validate_lock_directory \
        && [ -f "$prepared_lock_path" ] && [ ! -L "$prepared_lock_path" ] \
        && [ "$(stat -Lc '%u:%g:%a' "$prepared_lock_path" 2>/dev/null || true)" = 0:0:600 ]
}

validate_open_lock() {
    opened_lock_fd=$1
    opened_lock_path=$2
    validate_lock_directory \
        && [ -f "$opened_lock_path" ] && [ ! -L "$opened_lock_path" ] \
        && [ "$(stat -Lc '%u:%g:%a' "$opened_lock_path" 2>/dev/null || true)" = 0:0:600 ] \
        && [ "$(stat -Lc '%d:%i' "/proc/self/fd/$opened_lock_fd" 2>/dev/null || true)" = \
            "$(stat -Lc '%d:%i' "$opened_lock_path" 2>/dev/null || true)" ]
}

usage() {
    echo "usage (as root): vaultlink-update [check|install|auto]" >&2
    exit 64
}

[ "$(id -u)" -eq 0 ] || usage
[ "$#" -eq 1 ] || usage
action=$1
case "$action" in
    check|install|auto) ;;
    *) usage ;;
esac

for required_command in awk cat chmod chown cmp curl date du find flock grep id \
    getent install minisign mktemp mv rm runuser sed sha256sum sleep sort stat systemctl \
    tar timeout tr uname uniq wc sqlite3; do
    command -v "$required_command" >/dev/null \
        || fail "$required_command is required for signed package updates"
done

validate_root_file() {
    checked_file=$1
    checked_label=$2
    if [ ! -f "$checked_file" ] || [ -L "$checked_file" ]; then
        echo "$checked_label must be a regular file" >&2
        return 1
    fi
    [ "$(stat -c %u "$checked_file")" -eq 0 ] || {
        echo "$checked_label must be owned by root" >&2
        return 1
    }
    checked_mode=$(stat -c %a "$checked_file")
    case "$checked_mode" in
        ''|*[!0-7]*)
            echo "$checked_label has an invalid mode" >&2
            return 1
            ;;
    esac
    [ $((0$checked_mode & 0022)) -eq 0 ] || {
        echo "$checked_label must not be group- or world-writable" >&2
        return 1
    }
}

validate_candidate_checksum_root() {
    checksum_root=$1
    checksum_candidate="$checksum_root/usr/lib/vaultlink/package/vaultlink"
    checksum_metadata="$checksum_root/usr/lib/vaultlink/package/vaultlink.sha256"
    validate_root_file "$checksum_candidate" "package candidate" || return 1
    validate_root_file "$checksum_metadata" "package candidate checksum" || return 1
    [ "$(wc -l <"$checksum_metadata" | tr -d '[:space:]')" = 1 ] || return 1
    checksum_digest=$(sha256sum "$checksum_candidate" | awk '{ print $1 }') || return 1
    [ "$(cat "$checksum_metadata")" = "$checksum_digest  vaultlink" ] || return 1
    (cd "$checksum_root/usr/lib/vaultlink/package" \
        && sha256sum -c vaultlink.sha256 >/dev/null)
}

validate_service_file() {
    service_file=$1
    service_label=$2
    if [ ! -f "$service_file" ] || [ -L "$service_file" ]; then
        echo "$service_label must be a regular file" >&2
        return 1
    fi
    [ "$(stat -c '%u:%g' "$service_file")" = \
        "$(id -u vaultlink):$(id -g vaultlink)" ] || {
        echo "$service_label must be owned by vaultlink:vaultlink" >&2
        return 1
    }
    service_mode=$(stat -c %a "$service_file")
    case "$service_mode" in ''|*[!0-7]*) return 1 ;; esac
    [ $((0$service_mode & 0077)) -eq 0 ] || {
        echo "$service_label must not be accessible by group or world" >&2
        return 1
    }
}

read_auto_install() {
    if [ ! -e "$update_config" ]; then
        printf '%s\n' false
        return
    fi
    validate_root_file "$update_config" "update configuration" || return 1
    awk '
        /^[[:space:]]*($|#)/ { next }
        /^[[:space:]]*auto_install[[:space:]]*=[[:space:]]*(true|false)[[:space:]]*$/ {
            line = $0
            sub(/^[[:space:]]*auto_install[[:space:]]*=[[:space:]]*/, "", line)
            sub(/[[:space:]]*$/, "", line)
            value = line
            count++
            next
        }
        { invalid = 1 }
        END {
            if (invalid || count != 1)
                exit 1
            print value
        }
    ' "$update_config"
}

validate_stable_tag() {
    checked_tag=$1
    [ "${#checked_tag}" -le 64 ] || return 1
    awk -v tag="$checked_tag" '
        BEGIN {
            if (tag !~ /^v[0-9]+\.[0-9]+\.[0-9]+$/)
                exit 1
            sub(/^v/, "", tag)
            if (split(tag, parts, ".") != 3)
                exit 1
            for (i = 1; i <= 3; i++)
                if (length(parts[i]) > 1 && substr(parts[i], 1, 1) == "0")
                    exit 1
        }
    '
}

read_bounded_version() {
    version_binary=$1
    version_label=$2
    if ! bounded_version=$(
        timeout --kill-after=2 5 runuser -u vaultlink -- "$version_binary" --version
    ); then
        echo "$version_label does not provide a bounded --version response" >&2
        return 1
    fi
    case "$bounded_version" in
        ''|*[!0-9A-Za-z.+-]*)
            echo "$version_label returned an invalid version" >&2
            return 1
            ;;
    esac
    [ "${#bounded_version}" -le 128 ] || {
        echo "$version_label returned an invalid version" >&2
        return 1
    }
    printf '%s\n' "$bounded_version"
}

read_bounded_version_from_root_workspace() {
    workspace_binary=$1
    workspace_label=$2
    # Keep terminal evidence root-only while allowing the unprivileged account
    # to execute only this already-opened, signed candidate inode.
    exec 7<"$workspace_binary" || return 1
    if workspace_version=$(read_bounded_version /proc/self/fd/7 "$workspace_label"); then
        exec 7<&-
        printf '%s\n' "$workspace_version"
        return 0
    fi
    exec 7<&-
    return 1
}

# Print -1, 0 or 1 using SemVer precedence. Build metadata is ignored.
compare_semver() {
    left_version=$1
    right_version=$2
    LC_ALL=C awk -v left="$left_version" -v right="$right_version" '
        function invalid(version) {
            print "invalid semantic version: " version > "/dev/stderr"
            exit 2
        }
        function valid_ids(value, reject_zero, parts, count, i) {
            if (value == "") return 0
            count = split(value, parts, ".")
            for (i = 1; i <= count; i++) {
                if (parts[i] == "" || parts[i] !~ /^[0-9A-Za-z-]+$/) return 0
                if (reject_zero && parts[i] ~ /^[0-9]+$/ && length(parts[i]) > 1 \
                    && substr(parts[i], 1, 1) == "0") return 0
            }
            return 1
        }
        function normalize(version, core, pre, build, separator, parts, count, i) {
            separator = index(version, "+")
            if (separator) {
                build = substr(version, separator + 1)
                version = substr(version, 1, separator - 1)
                if (!valid_ids(build, 0) || index(build, "+")) invalid(version "+" build)
            }
            separator = index(version, "-")
            if (separator) {
                pre = substr(version, separator + 1)
                core = substr(version, 1, separator - 1)
                if (!valid_ids(pre, 1)) invalid(version)
            } else { pre = ""; core = version }
            count = split(core, parts, ".")
            if (count != 3) invalid(version)
            for (i = 1; i <= 3; i++)
                if (parts[i] !~ /^[0-9]+$/ \
                    || (length(parts[i]) > 1 && substr(parts[i], 1, 1) == "0")) invalid(version)
            return parts[1] "|" parts[2] "|" parts[3] "|" pre
        }
        function numcmp(a, b) {
            if (length(a) != length(b)) return length(a) < length(b) ? -1 : 1
            if (a == b) return 0
            return ("x" a) < ("x" b) ? -1 : 1
        }
        function precmp(a, b, ap, bp, ac, bc, count, i, order, an, bn) {
            if (a == "" || b == "") {
                if (a == b) return 0
                return a == "" ? 1 : -1
            }
            ac = split(a, ap, "."); bc = split(b, bp, ".")
            count = ac < bc ? ac : bc
            for (i = 1; i <= count; i++) {
                an = ap[i] ~ /^[0-9]+$/; bn = bp[i] ~ /^[0-9]+$/
                if (an && bn) order = numcmp(ap[i], bp[i])
                else if (an != bn) order = an ? -1 : 1
                else if (ap[i] == bp[i]) order = 0
                else order = ("x" ap[i]) < ("x" bp[i]) ? -1 : 1
                if (order != 0) return order
            }
            if (ac == bc) return 0
            return ac < bc ? -1 : 1
        }
        BEGIN {
            split(normalize(left), lp, "|"); split(normalize(right), rp, "|")
            for (i = 1; i <= 3; i++) {
                order = numcmp(lp[i], rp[i])
                if (order != 0) { print order; exit }
            }
            print precmp(lp[4], rp[4])
        }
    '
}

read_install_method() {
    validate_root_file "$install_method" "installation method marker" || return 1
    [ "$(stat -c '%u:%g:%a' "$install_method")" = 0:0:644 ] || {
        echo "installation method marker must be root:root mode 0644" >&2
        return 1
    }
    [ "$(wc -l <"$install_method" | tr -d '[:space:]')" -eq 5 ] || {
        echo "installation method marker must contain five newline-terminated fields" >&2
        return 1
    }
    awk '
        NR == 1 && $0 ~ /^FORMAT=(deb|rpm|pkg\.tar\.zst)$/ { next }
        NR == 2 && $0 ~ /^OS_ID=(debian|ubuntu|fedora|arch)$/ { next }
        NR == 3 && $0 ~ /^OS_VERSION=(13|24\.04|26\.04|44|rolling)$/ { next }
        NR == 4 && $0 ~ /^ARCH=(amd64|arm64|x86_64|aarch64)$/ { next }
        NR == 5 && $0 == "PACKAGE_NAME=vaultlink" { next }
        { exit 1 }
        END { if (NR != 5) exit 1 }
    ' "$install_method" || {
        echo "installation method marker is invalid" >&2
        return 1
    }
    marker_format=$(sed -n '1s/^FORMAT=//p' "$install_method")
    marker_os_id=$(sed -n '2s/^OS_ID=//p' "$install_method")
    marker_os_version=$(sed -n '3s/^OS_VERSION=//p' "$install_method")
    marker_arch=$(sed -n '4s/^ARCH=//p' "$install_method")
    marker_package_name=$(sed -n '5s/^PACKAGE_NAME=//p' "$install_method")
}

validate_persistent_install_method() {
    [ -n "$trusted_install_method" ] && [ -f "$trusted_install_method" ] \
        && [ ! -L "$trusted_install_method" ] || return 1
    [ "$(stat -c '%u:%g:%a' "$trusted_install_method")" = 0:0:600 ] || return 1
    validate_root_file "$install_method" "installation method marker" || return 1
    [ "$(stat -c '%u:%g:%a' "$install_method")" = 0:0:644 ] || return 1
    cmp -s "$install_method" "$trusted_install_method"
}

read_os_release_value() {
    os_key=$1
    os_values=$(sed -n "s/^$os_key=//p" /etc/os-release)
    [ "$(printf '%s\n' "$os_values" | grep -c .)" -eq 1 ] || return 1
    case "$os_values" in \"*\") os_values=${os_values#\"}; os_values=${os_values%\"} ;; esac
    case "$os_values" in ''|*[!A-Za-z0-9._+-]*) return 1 ;; esac
    printf '%s\n' "$os_values"
}

validate_host_binding() {
    [ "$marker_package_name" = "$package_name" ] || return 1
    actual_os_id=$(read_os_release_value ID) || return 1
    [ "$marker_os_id" = "$actual_os_id" ] || return 1
    case "$marker_os_id:$marker_os_version:$marker_format" in
        debian:13:deb|ubuntu:24.04:deb|ubuntu:26.04:deb|fedora:44:rpm)
            actual_os_version=$(read_os_release_value VERSION_ID) || return 1
            ;;
        arch:rolling:pkg.tar.zst) actual_os_version=rolling ;;
        *) return 1 ;;
    esac
    [ "$marker_os_version" = "$actual_os_version" ] || return 1
    actual_machine=$(uname -m)
    case "$marker_format:$marker_arch:$actual_machine" in
        deb:amd64:x86_64|deb:arm64:aarch64|rpm:x86_64:x86_64|rpm:aarch64:aarch64|pkg.tar.zst:x86_64:x86_64) ;;
        *) return 1 ;;
    esac
}

validate_service_identity() {
    case "$marker_os_id" in
        debian|ubuntu|fedora) expected_nologin=/usr/sbin/nologin ;;
        arch) expected_nologin=/usr/bin/nologin ;;
        *) return 1 ;;
    esac
    [ -f "$expected_nologin" ] && [ ! -L "$expected_nologin" ] \
        && [ -x "$expected_nologin" ] || return 1
    service_passwd=$(getent passwd vaultlink) || return 1
    service_ids=$(printf '%s\n' "$service_passwd" | awk -F: -v shell="$expected_nologin" '
        NR == 1 && NF == 7 && $1 == "vaultlink" && $2 == "x" \
            && $3 ~ /^[0-9]+$/ && ($3 + 0) >= 1 && ($3 + 0) <= 999 \
            && $4 ~ /^[0-9]+$/ && $5 == "VaultLink service account" \
            && $6 == "/var/lib/vaultlink" && $7 == shell {
                print $3; print $4; valid = 1; next
            }
        { invalid = 1 }
        END { if (NR != 1 || invalid || !valid) exit 1 }
    ') || return 1
    service_uid=$(printf '%s\n' "$service_ids" | sed -n '1p')
    service_gid=$(printf '%s\n' "$service_ids" | sed -n '2p')
    [ -n "$service_uid" ] && [ -n "$service_gid" ] || return 1

    service_group=$(getent group vaultlink) || return 1
    printf '%s\n' "$service_group" | awk -F: -v gid="$service_gid" '
        NR == 1 && NF == 4 && $1 == "vaultlink" && $2 == "x" \
            && $3 == gid && $4 == "" { valid = 1; next }
        { invalid = 1 }
        END { if (NR != 1 || invalid || !valid) exit 1 }
    ' || return 1

    service_shadow=$(getent shadow vaultlink) || return 1
    printf '%s\n' "$service_shadow" | awk -F: '
        NR == 1 && NF == 9 && $1 == "vaultlink" && $2 != "" \
            && ($2 ~ /^!/ || $2 ~ /^\*/) { valid = 1; next }
        { invalid = 1 }
        END { if (NR != 1 || invalid || !valid) exit 1 }
    ' || return 1

    [ "$(id -u vaultlink)" = "$service_uid" ] \
        && [ "$(id -g vaultlink)" = "$service_gid" ] \
        && [ "$(id -gn vaultlink)" = vaultlink ] \
        && [ "$(id -Gn vaultlink)" = vaultlink ]
}

asset_name_for_version() {
    asset_version=$1
    case "$marker_os_id:$marker_os_version:$marker_format" in
        debian:13:deb) printf 'vaultlink_%s-1+deb13_%s.deb\n' "$asset_version" "$marker_arch" ;;
        ubuntu:24.04:deb) printf 'vaultlink_%s-1+ubuntu24.04_%s.deb\n' "$asset_version" "$marker_arch" ;;
        ubuntu:26.04:deb) printf 'vaultlink_%s-1+ubuntu26.04_%s.deb\n' "$asset_version" "$marker_arch" ;;
        fedora:44:rpm) printf 'vaultlink-%s-1.fc44.%s.rpm\n' "$asset_version" "$marker_arch" ;;
        arch:rolling:pkg.tar.zst) printf 'vaultlink-%s-1-x86_64.pkg.tar.zst\n' "$asset_version" ;;
        *) return 1 ;;
    esac
}

expected_database_version() {
    database_upstream=$1
    case "$marker_os_id:$marker_os_version:$marker_format" in
        debian:13:deb) printf '%s-1+deb13\n' "$database_upstream" ;;
        ubuntu:24.04:deb) printf '%s-1+ubuntu24.04\n' "$database_upstream" ;;
        ubuntu:26.04:deb) printf '%s-1+ubuntu26.04\n' "$database_upstream" ;;
        fedora:44:rpm) printf '%s-1.fc44\n' "$database_upstream" ;;
        arch:rolling:pkg.tar.zst) printf '%s-1\n' "$database_upstream" ;;
        *) return 1 ;;
    esac
}

require_package_commands() {
    case "$marker_format" in
        deb)
            for command_name in dpkg dpkg-deb dpkg-query md5sum xargs; do command -v "$command_name" >/dev/null || return 1; done
            ;;
        rpm)
            for command_name in cpio rpm rpm2cpio; do command -v "$command_name" >/dev/null || return 1; done
            ;;
        pkg.tar.zst)
            for command_name in bsdtar gzip pacman; do command -v "$command_name" >/dev/null || return 1; done
            ;;
        *) return 1 ;;
    esac
}

validate_installed_package() {
    database_expected_upstream=$1
    database_expected_version=$(expected_database_version "$database_expected_upstream") || return 1
    case "$marker_format" in
        deb)
            [ "$(dpkg-query -W -f='${db:Status-Status}' "$package_name" 2>/dev/null)" = installed ] || return 1
            [ "$(dpkg-query -W -f='${Version}' "$package_name" 2>/dev/null)" = "$database_expected_version" ] || return 1
            [ "$(dpkg-query -W -f='${Architecture}' "$package_name" 2>/dev/null)" = "$marker_arch" ] || return 1
            dpkg-query -L "$package_name" 2>/dev/null | grep -F -x -q "$package_binary" || return 1
            ;;
        rpm)
            [ "$(rpm -q --qf '%{NAME}' "$package_name" 2>/dev/null)" = "$package_name" ] || return 1
            [ "$(rpm -q --qf '%{EPOCHNUM}' "$package_name" 2>/dev/null)" = 0 ] || return 1
            [ "$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$package_name" 2>/dev/null)" = "$database_expected_version" ] || return 1
            [ "$(rpm -q --qf '%{ARCH}' "$package_name" 2>/dev/null)" = "$marker_arch" ] || return 1
            [ "$(rpm -qf --qf '%{NAME}' "$package_binary" 2>/dev/null)" = "$package_name" ] || return 1
            ;;
        pkg.tar.zst)
            [ "$(pacman -Q "$package_name" 2>/dev/null)" = "$package_name $database_expected_version" ] || return 1
            installed_pacman_arch=$(pacman -Qi "$package_name" 2>/dev/null \
                | sed -n 's/^Architecture[[:space:]]*:[[:space:]]*//p') || return 1
            [ "$(printf '%s\n' "$installed_pacman_arch" \
                | awk 'NF { count++ } END { print count + 0 }')" -eq 1 ] || return 1
            [ "$installed_pacman_arch" = "$marker_arch" ] || return 1
            pacman -Qoq "$package_binary" 2>/dev/null | grep -F -x -q "$package_name" || return 1
            ;;
        *) return 1 ;;
    esac
}

validate_arch_remove_hook() {
    hook_file=$1
    validate_root_file "$hook_file" "Arch removal hook" || return 1
    [ "$(stat -c %a "$hook_file")" = 644 ] || return 1
    [ "$(wc -l <"$hook_file" | tr -d '[:space:]')" = 10 ] || return 1
    expected_hook=$(printf '%s\n' \
        '[Trigger]' \
        'Operation = Remove' \
        'Type = Package' \
        'Target = vaultlink' \
        '' \
        '[Action]' \
        'Description = Verifying VaultLink is inactive before removal' \
        'When = PreTransaction' \
        'Exec = /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh preremove-preflight pkg.tar.zst arch rolling x86_64 vaultlink remove' \
        'AbortOnFail')
    actual_hook=$(cat "$hook_file")
    [ "$actual_hook" = "$expected_hook" ]
}

validate_installed_payload() {
    installed_expected_version=$1
    installed_expected_root=$2
    validate_installed_package "$installed_expected_version" || return 1
    validate_service_identity || return 1
    validate_persistent_install_method || return 1
    for installed_file in "$package_binary" "$package_lifecycle" "$runtime_guard" "$package_upgrade" \
        "$package_rollback" "$public_key" /usr/lib/vaultlink/package/version \
        /usr/lib/vaultlink/package/vaultlink.sha256; do
        validate_root_file "$installed_file" "installed package payload" || return 1
        cmp -s "$installed_file" "$installed_expected_root$installed_file" || return 1
    done
    case "$marker_format" in
        pkg.tar.zst)
            validate_root_file "$package_installer" "installed Arch package installer" || return 1
            cmp -s "$package_installer" "$installed_expected_root$package_installer" || return 1
            [ "$(stat -c %a "$package_installer")" = 755 ] || return 1
            validate_root_file "$package_remover" "installed Arch package remover" || return 1
            cmp -s "$package_remover" "$installed_expected_root$package_remover" || return 1
            [ "$(stat -c %a "$package_remover")" = 755 ] || return 1
            validate_arch_remove_hook "$package_remove_hook" || return 1
            cmp -s "$package_remove_hook" \
                "$installed_expected_root$package_remove_hook" || return 1
            for installed_arch_metadata in \
                /usr/lib/vaultlink/package/PKGBUILD \
                /usr/lib/vaultlink/package/builder-packages.lock; do
                validate_root_file "$installed_arch_metadata" \
                    "installed Arch build provenance" || return 1
                [ "$(stat -c %a "$installed_arch_metadata")" = 644 ] || return 1
                cmp -s "$installed_arch_metadata" \
                    "$installed_expected_root$installed_arch_metadata" || return 1
            done
            [ ! -e "$installed_expected_root$install_method" ] \
                && [ ! -L "$installed_expected_root$install_method" ] || return 1
            installed_updater=/usr/bin/vaultlink-update
            ;;
        deb|rpm)
            validate_root_file "$installed_expected_root$install_method" \
                "package installation marker" || return 1
            [ "$(stat -c %a "$installed_expected_root$install_method")" = 644 ] || return 1
            cmp -s "$trusted_install_method" "$installed_expected_root$install_method" || return 1
            installed_updater=/usr/sbin/vaultlink-update
            ;;
        *) return 1 ;;
    esac
    validate_root_file "$installed_updater" "installed package updater" || return 1
    cmp -s "$installed_updater" "$installed_expected_root$installed_updater" || return 1
    [ -x "$package_binary" ] && [ -x "$package_lifecycle" ] \
        && [ -x "$package_upgrade" ] && [ -x "$package_rollback" ] \
        && [ -x "$installed_updater" ] || return 1
    [ "$(stat -c %a "$package_binary")" = 755 ] \
        && [ "$(stat -c %a "$package_lifecycle")" = 755 ] \
        && [ "$(stat -c %a "$package_upgrade")" = 755 ] \
        && [ "$(stat -c %a "$package_rollback")" = 755 ] \
        && [ "$(stat -c %a "$installed_updater")" = 755 ] \
        && [ "$(stat -c %a "$public_key")" = 644 ] \
        && [ "$(stat -c %a "$install_method")" = 644 ] || return 1
    cmp -s /usr/lib/vaultlink/package/version \
        "$installed_expected_root/usr/lib/vaultlink/package/version" || return 1
    cmp -s /usr/lib/vaultlink/package/vaultlink.sha256 \
        "$installed_expected_root/usr/lib/vaultlink/package/vaultlink.sha256" || return 1
    validate_candidate_checksum_root '' || return 1
    [ "$(read_bounded_version "$package_binary" "installed package candidate")" = \
        "$installed_expected_version" ] || return 1
}

curl_common() {
    curl --fail --silent --show-error --max-redirs 0 \
        --proto '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 180 --retry 3 --retry-delay 2 \
        --retry-max-time 45 --user-agent 'VaultLink signed package updater' "$@"
}

fetch_latest_tag() {
    redirect_response=$(curl_common --max-filesize "$metadata_limit" --output /dev/null \
        --write-out '%{http_code}\n%{redirect_url}' "$latest_release_url") || return 1
    [ "$(printf '%s\n' "$redirect_response" | sed -n '$=')" -eq 2 ] || return 1
    redirect_status=$(printf '%s\n' "$redirect_response" | sed -n '1p')
    effective_url=$(printf '%s\n' "$redirect_response" | sed -n '2p')
    case "$redirect_status" in 301|302|303|307|308) ;; *) return 1 ;; esac
    release_prefix="$github_origin/$repository/releases/tag/"
    case "$effective_url" in
        "$release_prefix"*) fetched_tag=${effective_url#"$release_prefix"} ;;
        *) return 1 ;;
    esac
    validate_stable_tag "$fetched_tag" || return 1
    printf '%s\n' "$fetched_tag"
}

validate_release_asset_redirect() {
    redirect_url=$1
    [ "${#redirect_url}" -le 8192 ] || return 1
    [ "$(printf '%s\n' "$redirect_url" | sed -n '$=')" -eq 1 ] || return 1
    case "$redirect_url" in
        https://release-assets.githubusercontent.com/github-production-release-asset/*)
            redirect_relative=${redirect_url#https://release-assets.githubusercontent.com/github-production-release-asset/}
            case "$redirect_relative" in
                ''|/*|*'//'*) return 1 ;;
            esac
            case "/$redirect_relative/" in *'/../'*|*'/./'*) return 1 ;; esac
            case "$redirect_url" in *'#'*) return 1 ;; esac
            ;;
        *) return 1 ;;
    esac
}

download_asset() {
    download_tag=$1
    download_name=$2
    download_limit=$3
    download_destination=$4
    download_url="$github_origin/$repository/releases/download/$download_tag/$download_name"
    asset_redirect_response=$(curl_common --max-filesize "$metadata_limit" \
        --output /dev/null --write-out '%{http_code}\n%{redirect_url}' \
        "$download_url") || return 1
    [ "$(printf '%s\n' "$asset_redirect_response" | sed -n '$=')" -eq 2 ] || return 1
    asset_redirect_status=$(printf '%s\n' "$asset_redirect_response" | sed -n '1p')
    asset_redirect=$(printf '%s\n' "$asset_redirect_response" | sed -n '2p')
    case "$asset_redirect_status" in 301|302|303|307|308) ;; *) return 1 ;; esac
    validate_release_asset_redirect "$asset_redirect" || return 1
    asset_response=$(curl_common --max-filesize "$download_limit" \
        --output "$download_destination" --write-out '%{http_code}\n%{url_effective}' \
        "$asset_redirect") || return 1
    [ "$(printf '%s\n' "$asset_response" | sed -n '$=')" -eq 2 ] || return 1
    [ "$(printf '%s\n' "$asset_response" | sed -n '1p')" = 200 ] || return 1
    [ "$(printf '%s\n' "$asset_response" | sed -n '2p')" = "$asset_redirect" ] || return 1
    [ -s "$download_destination" ] || return 1
    [ "$(stat -c %s "$download_destination")" -le "$download_limit" ] || return 1
}

verify_release_package() {
    verify_version=$1
    verify_directory=$2
    verify_asset=$(asset_name_for_version "$verify_version") || return 1
    verify_tag=v$verify_version
    verify_package="$verify_directory/$verify_asset"
    verify_signature="$verify_package.minisig"
    verify_checksums="$verify_directory/SHA256SUMS"
    verify_checksums_signature="$verify_checksums.minisig"
    install -d -o root -g root -m 0700 "$verify_directory"
    download_asset "$verify_tag" "$verify_asset" "$package_limit" "$verify_package" || return 1
    download_asset "$verify_tag" "$verify_asset.minisig" "$metadata_limit" "$verify_signature" || return 1
    download_asset "$verify_tag" SHA256SUMS "$metadata_limit" "$verify_checksums" || return 1
    download_asset "$verify_tag" SHA256SUMS.minisig "$metadata_limit" "$verify_checksums_signature" || return 1
    minisign -V -q -p "$public_key" -m "$verify_package" -x "$verify_signature" || return 1
    minisign -V -q -p "$public_key" -m "$verify_checksums" -x "$verify_checksums_signature" || return 1
    expected_sha256=$(awk -v expected_file="$verify_asset" '
        $2 == expected_file && length($1) == 64 && $1 !~ /[^0-9a-f]/ {
            checksum = $1; matches++
        }
        END { if (matches != 1) exit 1; print checksum }
    ' "$verify_checksums") || return 1
    actual_sha256=$(sha256sum "$verify_package" | awk '{print $1}')
    [ "$actual_sha256" = "$expected_sha256" ] || return 1
    printf '%s\n' "$verify_package"
}

validate_embedded_lifecycle() {
    lifecycle_script=$1
    lifecycle_payload=$2
    lifecycle_scratch=$3
    lifecycle_sha256=$(sha256sum "$lifecycle_payload" | awk '{print $1}')
    [ "$(grep -F -c '# BEGIN VAULTLINK PACKAGE LIFECYCLE' "$lifecycle_script" || true)" -eq 1 ] || return 1
    [ "$(grep -F -c '# END VAULTLINK PACKAGE LIFECYCLE' "$lifecycle_script" || true)" -eq 1 ] || return 1
    [ "$(grep -F -c "# VAULTLINK_PACKAGE_LIFECYCLE_SHA256=$lifecycle_sha256" \
        "$lifecycle_script" || true)" -eq 1 ] || return 1
    sed '1{/^#!\/bin\/sh$/d;}' "$lifecycle_payload" >"$lifecycle_scratch.expected"
    awk '
        $0 == "# BEGIN VAULTLINK PACKAGE LIFECYCLE" { copy = 1; next }
        $0 == "# END VAULTLINK PACKAGE LIFECYCLE" { copy = 0; exit }
        copy { print }
    ' "$lifecycle_script" >"$lifecycle_scratch.actual"
    cmp -s "$lifecycle_scratch.expected" "$lifecycle_scratch.actual" || return 1
    lifecycle_source_lines=$(wc -l <"$lifecycle_payload" | tr -d '[:space:]')
    lifecycle_script_lines=$(wc -l <"$lifecycle_script" | tr -d '[:space:]')
    [ "$lifecycle_script_lines" -le $((lifecycle_source_lines + 40)) ] || return 1
}

write_expected_embedded_lifecycle() {
    expected_script=$1
    expected_lifecycle=$2
    expected_lifecycle_sha256=$(sha256sum "$expected_lifecycle" | awk '{print $1}')
    {
        printf '%s\n' '#!/bin/sh' 'VAULTLINK_PACKAGE_LIFECYCLE_EMBEDDED=1'
        printf '# VAULTLINK_PACKAGE_LIFECYCLE_SHA256=%s\n' "$expected_lifecycle_sha256"
        printf '%s\n' '# BEGIN VAULTLINK PACKAGE LIFECYCLE'
        sed '1{/^#!\/bin\/sh$/d;}' "$expected_lifecycle"
        printf '%s\n' '# END VAULTLINK PACKAGE LIFECYCLE'
    } >"$expected_script"
}

validate_deb_scriptlets() {
    deb_control_root=$1
    deb_lifecycle=$2
    deb_version=$3

    write_expected_embedded_lifecycle "$deb_control_root/expected-preinst" "$deb_lifecycle"
    cat >>"$deb_control_root/expected-preinst" <<EOF
case "\${1:-}" in
    install)
        if [ -e /usr/share/vaultlink/install-method.env ] \
            || [ -L /usr/share/vaultlink/install-method.env ]; then
            lifecycle_mode=reinstall
        else
            lifecycle_mode=fresh
        fi
        ;;
    upgrade) lifecycle_mode=upgrade ;;
    abort-upgrade) exit 0 ;;
    *) package_fail "unsupported Debian preinst operation: \${1:-missing}" ;;
esac
vaultlink_package_main preinstall "$marker_format" "$marker_os_id" "$marker_os_version" "$marker_arch" vaultlink "\$lifecycle_mode"
EOF
    cmp -s "$deb_control_root/expected-preinst" "$deb_control_root/preinst" || return 1

    cat >"$deb_control_root/expected-postinst" <<EOF
#!/bin/sh
set -eu
case "\${1:-}" in
    configure) ;;
    abort-upgrade|abort-remove|abort-deconfigure) exit 0 ;;
    *) echo "unsupported Debian postinst operation: \${1:-missing}" >&2; exit 1 ;;
esac
case "\$#" in
    1|2) ;;
    *) echo "invalid Debian configure version arguments" >&2; exit 1 ;;
esac
case "\${2:-}" in
    '') lifecycle_mode=fresh ;;
    ?*)
        if [ -e /opt/vaultlink/vaultlink ] \
            || [ -L /opt/vaultlink/vaultlink ]; then
            lifecycle_mode=upgrade
        else
            lifecycle_mode=reinstall
        fi
        ;;
esac
/usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh postinstall "$marker_format" "$marker_os_id" "$marker_os_version" "$marker_arch" vaultlink "\$lifecycle_mode" "$deb_version"
EOF
    cmp -s "$deb_control_root/expected-postinst" "$deb_control_root/postinst" || return 1

    cat >"$deb_control_root/expected-prerm" <<EOF
#!/bin/sh
set -eu
case "\${1:-}" in
    remove|deconfigure)
        exec /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh preremove "$marker_format" "$marker_os_id" "$marker_os_version" "$marker_arch" vaultlink remove
        ;;
    upgrade|failed-upgrade) exit 0 ;;
    *) echo "unsupported Debian prerm operation: \${1:-missing}" >&2; exit 1 ;;
esac
EOF
    cmp -s "$deb_control_root/expected-prerm" "$deb_control_root/prerm" || return 1

    write_expected_embedded_lifecycle "$deb_control_root/expected-postrm" "$deb_lifecycle"
    cat >>"$deb_control_root/expected-postrm" <<EOF
case "\${1:-}" in
    remove|purge|disappear)
        vaultlink_package_main postremove "$marker_format" "$marker_os_id" "$marker_os_version" "$marker_arch" vaultlink remove
        ;;
    upgrade|failed-upgrade) exit 0 ;;
    abort-install|abort-upgrade) exit 0 ;;
    *) package_fail "unsupported Debian postrm operation: \${1:-missing}" ;;
esac
EOF
    cmp -s "$deb_control_root/expected-postrm" "$deb_control_root/postrm"
}

validate_rpm_scriptlets() {
    rpm_metadata_root=$1
    rpm_lifecycle=$2
    rpm_version=$3

    write_expected_embedded_lifecycle "$rpm_metadata_root.expected-rpm-prein" "$rpm_lifecycle"
    cat >>"$rpm_metadata_root.expected-rpm-prein" <<EOF
if [ "\${1:-1}" -gt 1 ]; then lifecycle_mode=upgrade; elif [ -e /var/lib/vaultlink-backups/install-method.env ] || [ -L /var/lib/vaultlink-backups/install-method.env ]; then lifecycle_mode=reinstall; else lifecycle_mode=fresh; fi
vaultlink_package_main preinstall "$marker_format" "$marker_os_id" "$marker_os_version" "$marker_arch" vaultlink "\$lifecycle_mode"
EOF
    cmp -s "$rpm_metadata_root.expected-rpm-prein" "$rpm_metadata_root.rpm-prein" || {
        echo "RPM pre-install scriptlet differs from the reviewed policy" >&2
        return 1
    }

    cat >"$rpm_metadata_root.expected-rpm-postin" <<EOF
#!/bin/sh
set -eu
if [ "\${1:-1}" -gt 1 ]; then lifecycle_mode=upgrade; elif [ -e /var/lib/vaultlink-backups/install-method.env ] || [ -L /var/lib/vaultlink-backups/install-method.env ]; then lifecycle_mode=reinstall; else lifecycle_mode=fresh; fi
exec /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh postinstall "$marker_format" "$marker_os_id" "$marker_os_version" "$marker_arch" vaultlink "\$lifecycle_mode" "$rpm_version"
EOF
    cmp -s "$rpm_metadata_root.expected-rpm-postin" "$rpm_metadata_root.rpm-postin" || {
        echo "RPM post-install scriptlet differs from the reviewed policy" >&2
        return 1
    }

    cat >"$rpm_metadata_root.expected-rpm-preun" <<EOF
#!/bin/sh
set -eu
if [ "\${1:-0}" -ne 0 ]; then exit 0; fi; lifecycle_mode=remove
exec /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh preremove "$marker_format" "$marker_os_id" "$marker_os_version" "$marker_arch" vaultlink "\$lifecycle_mode"
EOF
    cmp -s "$rpm_metadata_root.expected-rpm-preun" "$rpm_metadata_root.rpm-preun" || {
        echo "RPM pre-uninstall scriptlet differs from the reviewed policy" >&2
        return 1
    }

    write_expected_embedded_lifecycle "$rpm_metadata_root.expected-rpm-postun" "$rpm_lifecycle"
    cat >>"$rpm_metadata_root.expected-rpm-postun" <<EOF
if [ "\${1:-0}" -ne 0 ]; then exit 0; fi; lifecycle_mode=remove
vaultlink_package_main postremove "$marker_format" "$marker_os_id" "$marker_os_version" "$marker_arch" vaultlink "\$lifecycle_mode"
EOF
    cmp -s "$rpm_metadata_root.expected-rpm-postun" "$rpm_metadata_root.rpm-postun" || {
        echo "RPM post-uninstall scriptlet differs from the reviewed policy" >&2
        return 1
    }
}

validate_arch_install_script() {
    arch_script=$1
    arch_lifecycle=$2
    arch_version=$3
    arch_expected=$4
    write_expected_embedded_lifecycle "$arch_expected" "$arch_lifecycle"
    cat >>"$arch_expected" <<EOF
pre_install() {
    if [ -e /usr/share/vaultlink/install-method.env ] || [ -L /usr/share/vaultlink/install-method.env ]; then
        lifecycle_mode=reinstall
    else
        lifecycle_mode=fresh
    fi
    vaultlink_package_main preinstall "$marker_format" "$marker_os_id" "$marker_os_version" "$marker_arch" vaultlink "\$lifecycle_mode"
}
post_install() {
    if [ -e /usr/share/vaultlink/install-method.env ] || [ -L /usr/share/vaultlink/install-method.env ]; then
        lifecycle_mode=reinstall
    else
        lifecycle_mode=fresh
    fi
    vaultlink_package_main postinstall "$marker_format" "$marker_os_id" "$marker_os_version" "$marker_arch" vaultlink "\$lifecycle_mode" "$arch_version"
}
pre_upgrade() {
    vaultlink_package_main preinstall "$marker_format" "$marker_os_id" "$marker_os_version" "$marker_arch" vaultlink upgrade
}
post_upgrade() {
    vaultlink_package_main postinstall "$marker_format" "$marker_os_id" "$marker_os_version" "$marker_arch" vaultlink upgrade "$arch_version"
}
pre_remove() {
    vaultlink_package_main preremove "$marker_format" "$marker_os_id" "$marker_os_version" "$marker_arch" vaultlink remove
}
post_remove() {
    vaultlink_package_main postremove "$marker_format" "$marker_os_id" "$marker_os_version" "$marker_arch" vaultlink remove
}
EOF
    cmp -s "$arch_expected" "$arch_script"
}

validate_package_metadata() {
    metadata_file=$1
    metadata_version=$2
    metadata_root=$3
    metadata_lifecycle="$metadata_root/usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh"
    [ -f "$metadata_lifecycle" ] && [ ! -L "$metadata_lifecycle" ] || return 1
    case "$marker_format" in
        deb)
            deb_dependencies=$(dpkg-deb -f "$metadata_file" Depends) || return 1
            printf '%s\n' "$deb_dependencies" | awk '
                !/^[a-z0-9][a-z0-9+.-]*(, [a-z0-9][a-z0-9+.-]*)*$/ { exit 1 }
                { count = split($0, dependency, ", ") }
                END {
                    if (NR != 1 || count < 1 || count > 64) exit 1
                    for (i = 1; i <= count; i++) print dependency[i]
                }
            ' >"$metadata_root.deb-depends" || return 1
            [ "$(wc -l <"$metadata_root.deb-depends" | tr -d '[:space:]')" = \
                "$(sort -u "$metadata_root.deb-depends" | wc -l | tr -d '[:space:]')" ] \
                || return 1
            cat >"$metadata_root.baseline-deb-depends" <<'EOF'
ca-certificates
curl
libc6
libgcc-s1
mawk
minisign
sqlite3
systemd
EOF
            while IFS= read -r baseline_dependency; do
                grep -F -x -q "$baseline_dependency" "$metadata_root.deb-depends" || return 1
            done <"$metadata_root.baseline-deb-depends"
            [ "$(dpkg-deb -f "$metadata_file" Suggests)" = cifs-utils ] || return 1
            [ -z "$(dpkg-deb -f "$metadata_file" Recommends 2>/dev/null || true)" ] || return 1
            for forbidden_deb_field in Pre-Depends Conflicts Breaks Replaces Provides \
                Enhances; do
                [ -z "$(dpkg-deb -f "$metadata_file" "$forbidden_deb_field" 2>/dev/null || true)" ] \
                    || return 1
            done
            # dpkg-deb synthesizes `no` when the Essential field is absent.
            # The later byte-exact control allowlist still rejects an explicit
            # Essential field, including an explicit `Essential: no`.
            [ "$(dpkg-deb -f "$metadata_file" Essential)" = no ] || return 1
            [ "$(dpkg-deb -f "$metadata_file" Section)" = net ] || return 1
            [ "$(dpkg-deb -f "$metadata_file" Priority)" = optional ] || return 1
            control_root="$metadata_root.control"
            install -d -o root -g root -m 0700 "$control_root"
            dpkg-deb -e "$metadata_file" "$control_root" || return 1
            unexpected_control=$(find "$control_root" ! -type d ! -type f -print -quit)
            [ -z "$unexpected_control" ] || return 1
            (cd "$control_root" && find . -type f -printf '%P\n' | sort) \
                >"$metadata_root.control-files"
            printf '%s\n' control md5sums postinst postrm preinst prerm \
                >"$metadata_root.expected-control-files"
            cmp -s "$metadata_root.expected-control-files" "$metadata_root.control-files" || return 1
            [ "$(stat -c '%a' "$control_root/control")" = 644 ] || return 1
            [ "$(stat -c '%a' "$control_root/md5sums")" = 644 ] || return 1
            for control_script in preinst postinst prerm postrm; do
                [ -x "$control_root/$control_script" ] \
                    && [ "$(stat -c '%a' "$control_root/$control_script")" = 755 ] \
                    || return 1
            done
            metadata_deb_version=$(expected_database_version "$metadata_version") || return 1
            metadata_installed_size=$(debian_installed_size "$metadata_root" \
                "$metadata_root.deb-installed-size.inventory") \
                || return 1
            cat >"$metadata_root.expected-deb-control" <<EOF
Package: vaultlink
Version: $metadata_deb_version
Architecture: $marker_arch
Maintainer: VaultLink maintainers <alexhaberl@users.noreply.github.com>
Installed-Size: $metadata_installed_size
Depends: $deb_dependencies
Suggests: cifs-utils
Section: net
Priority: optional
Homepage: https://github.com/alexhaberl/VaultLink
Description: secure file sharing for an existing Linux mountpoint
 VaultLink provides hardened self-hosted file sharing with explicit setup,
 signed updates, transactional activation, and verified rollback.
EOF
            cmp -s "$metadata_root.expected-deb-control" "$control_root/control" \
                || return 1
            (cd "$metadata_root" \
                && find usr -type f -print0 | sort -z | xargs -0 md5sum) \
                >"$metadata_root.expected-md5sums" || return 1
            cmp -s "$metadata_root.expected-md5sums" "$control_root/md5sums" \
                || return 1
            validate_embedded_lifecycle "$control_root/preinst" "$metadata_lifecycle" \
                "$metadata_root.deb-preinst" || return 1
            validate_embedded_lifecycle "$control_root/postrm" "$metadata_lifecycle" \
                "$metadata_root.deb-postrm" || return 1
            validate_deb_scriptlets "$control_root" "$metadata_lifecycle" \
                "$metadata_version" || return 1
            grep -F -q 'refusing to adopt markerless existing installation' "$metadata_lifecycle" || return 1
            grep -F -q 'package upgrade stages only the candidate' "$metadata_lifecycle" || return 1
            ;;
        rpm)
            rpm -qp --requires "$metadata_file" >"$metadata_root.rpm-requires.raw" \
                || return 1
            awk '$0 !~ /^rpmlib\(/ { print }' "$metadata_root.rpm-requires.raw" \
                >"$metadata_root.rpm-requires" || return 1
            awk '
                /^\/[A-Za-z0-9._+\/-]+$/ {
                    if ($0 ~ /\/\// || $0 ~ /(^|\/)\.\.?(\/|$)/) exit 1
                    next
                }
                /^[A-Za-z0-9][A-Za-z0-9._+\/-]*$/ { next }
                { exit 1 }
            ' "$metadata_root.rpm-requires" || return 1
            sort -u "$metadata_root.rpm-requires" >"$metadata_root.rpm-requires.sorted"
            rpm_dependency_count=$(wc -l <"$metadata_root.rpm-requires.sorted" \
                | tr -d '[:space:]')
            [ "$rpm_dependency_count" -ge 1 ] && [ "$rpm_dependency_count" -le 64 ] \
                || return 1
            # RPM records /bin/sh once per scriptlet class. The exact
            # REQUIRENAME/FLAGS/VERSION tuple allowlist below is authoritative;
            # the user-facing --requires list is intentionally de-duplicated.
            mv -f "$metadata_root.rpm-requires.sorted" "$metadata_root.rpm-requires"
            cat >"$metadata_root.baseline-rpm-requires" <<'EOF'
/bin/sh
bash
ca-certificates
coreutils
cpio
curl
diffutils
findutils
gawk
glibc
grep
gzip
libgcc
minisign
rpm
sed
sqlite
systemd
tar
util-linux
EOF
            while IFS= read -r baseline_dependency; do
                grep -F -x -q "$baseline_dependency" "$metadata_root.rpm-requires" || return 1
            done <"$metadata_root.baseline-rpm-requires"
            rpm -qp --qf '[%{REQUIRENAME}\t%{REQUIREFLAGS}\t%{REQUIREVERSION}\n]' \
                "$metadata_file" | sort >"$metadata_root.rpm-require-tuples" || return 1
            printf '%s\t%s\t\n' \
                /bin/sh 768 /bin/sh 1280 /bin/sh 2304 /bin/sh 4352 \
                >"$metadata_root.expected-rpm-require-tuples.unsorted"
            cat >>"$metadata_root.expected-rpm-require-tuples.unsorted" <<'EOF'
rpmlib(CompressedFileNames)	16777226	3.0.4-1
rpmlib(FileDigests)	16777226	4.6.0-1
rpmlib(PayloadFilesHavePrefix)	16777226	4.0-1
rpmlib(PayloadIsZstd)	16777226	5.4.18-1
EOF
            while IFS= read -r rpm_regular_dependency; do
                [ "$rpm_regular_dependency" = /bin/sh ] && continue
                printf '%s\t0\t\n' "$rpm_regular_dependency" \
                    >>"$metadata_root.expected-rpm-require-tuples.unsorted" || return 1
            done <"$metadata_root.rpm-requires"
            sort "$metadata_root.expected-rpm-require-tuples.unsorted" \
                >"$metadata_root.expected-rpm-require-tuples" || return 1
            cmp -s "$metadata_root.expected-rpm-require-tuples" \
                "$metadata_root.rpm-require-tuples" || return 1
            [ "$(rpm -qp --recommends "$metadata_file")" = cifs-utils ] || return 1
            [ -z "$(rpm -qp --suggests "$metadata_file")" ] || return 1
            [ -z "$(rpm -qp --enhances "$metadata_file")" ] || return 1
            [ -z "$(rpm -qp --supplements "$metadata_file")" ] || return 1
            [ "$(rpm -qp --qf '%{LICENSE}' "$metadata_file")" = MIT ] || return 1
            [ "$(rpm -qp --qf '%{EPOCHNUM}' "$metadata_file")" = 0 ] || return 1
            case "$marker_arch" in
                x86_64) metadata_rpm_provide_arch=x86-64 ;;
                aarch64) metadata_rpm_provide_arch=aarch-64 ;;
                *) return 1 ;;
            esac
            rpm -qp --provides "$metadata_file" | sort \
                >"$metadata_root.rpm-provides" || return 1
            cat >"$metadata_root.expected-rpm-provides" <<EOF
vaultlink = $metadata_version-1.fc44
vaultlink($metadata_rpm_provide_arch) = $metadata_version-1.fc44
EOF
            cmp -s "$metadata_root.expected-rpm-provides" \
                "$metadata_root.rpm-provides" || return 1
            rpm -qp --qf '[%{PROVIDENAME}\t%{PROVIDEFLAGS}\t%{PROVIDEVERSION}\n]' \
                "$metadata_file" | sort >"$metadata_root.rpm-provide-tuples" || return 1
            cat >"$metadata_root.expected-rpm-provide-tuples" <<EOF
vaultlink	8	$metadata_version-1.fc44
vaultlink($metadata_rpm_provide_arch)	8	$metadata_version-1.fc44
EOF
            cmp -s "$metadata_root.expected-rpm-provide-tuples" \
                "$metadata_root.rpm-provide-tuples" || return 1
            [ "$(rpm -qp --qf '%{FILEDIGESTALGO}' "$metadata_file")" = 8 ] || return 1
            [ "$(rpm -qp --qf '%{PAYLOADFORMAT}|%{PAYLOADCOMPRESSOR}|%{PAYLOADFLAGS}' \
                "$metadata_file")" = 'cpio|zstd|19' ] || return 1
            case "$(rpm -qp --qf '%{SYSUSERS}' "$metadata_file")" in
                ''|'(none)') ;;
                *) return 1 ;;
            esac
            rpm -qp --qf '%{PREIN}' "$metadata_file" >"$metadata_root.rpm-prein" || return 1
            rpm -qp --qf '%{POSTIN}' "$metadata_file" >"$metadata_root.rpm-postin" || return 1
            rpm -qp --qf '%{PREUN}' "$metadata_file" >"$metadata_root.rpm-preun" || return 1
            rpm -qp --qf '%{POSTUN}' "$metadata_file" >"$metadata_root.rpm-postun" || return 1
            validate_embedded_lifecycle "$metadata_root.rpm-prein" "$metadata_lifecycle" \
                "$metadata_root.rpm-prein-check" || return 1
            validate_embedded_lifecycle "$metadata_root.rpm-postun" "$metadata_lifecycle" \
                "$metadata_root.rpm-postun-check" || return 1
            validate_rpm_scriptlets "$metadata_root" "$metadata_lifecycle" \
                "$metadata_version" || return 1
            for rpm_program_tag in PREINPROG POSTINPROG PREUNPROG POSTUNPROG; do
                [ "$(rpm -qp --qf "%{$rpm_program_tag}" "$metadata_file")" = /bin/sh ] \
                    || return 1
            done
            for rpm_flags_tag in PREINFLAGS POSTINFLAGS PREUNFLAGS POSTUNFLAGS; do
                rpm_flags_value=$(rpm -qp --qf "%{$rpm_flags_tag}" "$metadata_file") \
                    || return 1
                case "$rpm_flags_value" in ''|'(none)') ;; *) return 1 ;; esac
            done
            for forbidden_rpm_tag in \
                PRETRANS PRETRANSFLAGS PRETRANSPROG \
                POSTTRANS POSTTRANSFLAGS POSTTRANSPROG \
                PREUNTRANS PREUNTRANSFLAGS PREUNTRANSPROG \
                POSTUNTRANS POSTUNTRANSFLAGS POSTUNTRANSPROG \
                VERIFYSCRIPT VERIFYSCRIPTFLAGS VERIFYSCRIPTPROG \
                TRIGGERCONDS TRIGGERFLAGS TRIGGERINDEX TRIGGERNAME \
                TRIGGERSCRIPTFLAGS TRIGGERSCRIPTPROG TRIGGERSCRIPTS \
                TRIGGERTYPE TRIGGERVERSION \
                FILETRIGGERCONDS FILETRIGGERFLAGS FILETRIGGERINDEX FILETRIGGERNAME \
                FILETRIGGERPRIORITIES FILETRIGGERSCRIPTFLAGS FILETRIGGERSCRIPTPROG \
                FILETRIGGERSCRIPTS FILETRIGGERTYPE FILETRIGGERVERSION \
                TRANSFILETRIGGERCONDS TRANSFILETRIGGERFLAGS TRANSFILETRIGGERINDEX \
                TRANSFILETRIGGERNAME TRANSFILETRIGGERPRIORITIES \
                TRANSFILETRIGGERSCRIPTFLAGS TRANSFILETRIGGERSCRIPTPROG \
                TRANSFILETRIGGERSCRIPTS TRANSFILETRIGGERTYPE \
                TRANSFILETRIGGERVERSION \
                ORDERFLAGS ORDERNAME ORDERVERSION \
                POLICIES POLICYFLAGS POLICYNAMES POLICYTYPES POLICYTYPESINDEXES; do
                forbidden_rpm_value=$(rpm -qp --qf "%{$forbidden_rpm_tag}" \
                    "$metadata_file") || return 1
                case "$forbidden_rpm_value" in ''|'(none)') ;; *) return 1 ;; esac
            done
            [ -z "$(rpm -qp --conflicts "$metadata_file")" ] || return 1
            [ -z "$(rpm -qp --obsoletes "$metadata_file")" ] || return 1
            rpm -qp --qf '[%{FILENAMES}\t%{FILECAPS}\n]' "$metadata_file" \
                >"$metadata_root.rpm-filecaps" || return 1
            if awk -F '\t' 'NF > 1 && $2 != "" && $2 != "(none)" { found = 1 } \
                END { exit !found }' "$metadata_root.rpm-filecaps"; then
                return 1
            fi
            rpm -qp --qf '[%{FILENAMES}\t%{FILEFLAGS}\t%{FILEVERIFYFLAGS}\n]' \
                "$metadata_file" >"$metadata_root.rpm-file-policy" || return 1
            awk -F '\t' '
                BEGIN { expected_docs = 0 }
                {
                    expected_flags = 0
                    if ($1 ~ /^\/usr\/share\/doc\/vaultlink\/examples\/config\/(development|production-reverse-proxy|production-standalone-letsencrypt|production-standalone-tls)\.toml$/ \
                        || $1 ~ /^\/usr\/share\/doc\/vaultlink\/examples\/deploy\/(Caddyfile|mnt-storage\.mount\.example|vaultlink-external-proxy-network\.conf|vaultlink-external-storage\.conf|vaultlink-standalone-capability\.conf|vaultlink-update\.conf\.example)$/) {
                        expected_flags = 2
                        expected_docs++
                    }
                    if ($2 != expected_flags || $3 != 4294967295) exit 1
                }
                END { if (expected_docs != 10) exit 1 }
            ' "$metadata_root.rpm-file-policy" || return 1
            grep -F -q 'refusing to adopt markerless existing installation' "$metadata_lifecycle" || return 1
            grep -F -q 'package upgrade stages only the candidate' "$metadata_lifecycle" || return 1
            ;;
        pkg.tar.zst)
            for arch_metadata in .PKGINFO .INSTALL .BUILDINFO .MTREE; do
                [ -f "$metadata_root/$arch_metadata" ] && [ ! -L "$metadata_root/$arch_metadata" ] \
                    || return 1
            done
            [ "$(sed -n 's/^pkgname = //p' "$metadata_root/.PKGINFO")" = "$package_name" ] || return 1
            [ "$(sed -n 's/^pkgver = //p' "$metadata_root/.PKGINFO")" = "$metadata_version-1" ] || return 1
            [ "$(sed -n 's/^arch = //p' "$metadata_root/.PKGINFO")" = "$marker_arch" ] || return 1
            metadata_arch_builddate=$(sed -n 's/^builddate = //p' "$metadata_root/.PKGINFO")
            case "$metadata_arch_builddate" in ''|*[!0-9]*) return 1 ;; esac
            metadata_arch_size=$(du -sb "$metadata_root/usr" | awk '{ print $1 }') || return 1
            metadata_pkgbuild="$metadata_root/usr/lib/vaultlink/package/PKGBUILD"
            metadata_builder_lock="$metadata_root/usr/lib/vaultlink/package/builder-packages.lock"
            [ -f "$metadata_pkgbuild" ] && [ ! -L "$metadata_pkgbuild" ] \
                && [ -f "$metadata_builder_lock" ] && [ ! -L "$metadata_builder_lock" ] \
                || return 1
            awk 'NF != 2 || $1 !~ /^[A-Za-z0-9@._+-]+$/ \
                    || $2 !~ /^[A-Za-z0-9@._+:-]+$/ { exit 1 }' \
                "$metadata_builder_lock" || return 1
            LC_ALL=C sort -c -u "$metadata_builder_lock" || return 1
            metadata_pacman_package_version=$(awk '$1 == "pacman" { print $2 }' \
                "$metadata_builder_lock")
            metadata_fakeroot_package_version=$(awk '$1 == "fakeroot" { print $2 }' \
                "$metadata_builder_lock")
            [ "$(printf '%s\n' "$metadata_pacman_package_version" | grep -c . || true)" -eq 1 ] \
                && [ "$(printf '%s\n' "$metadata_fakeroot_package_version" | grep -c . || true)" -eq 1 ] \
                || return 1
            metadata_makepkg_version=${metadata_pacman_package_version#*:}
            metadata_makepkg_version=${metadata_makepkg_version%-*}
            metadata_makepkg_version=${metadata_makepkg_version%%.r[0-9]*}
            metadata_fakeroot_version=${metadata_fakeroot_package_version#*:}
            metadata_fakeroot_version=${metadata_fakeroot_version%-*}
            metadata_arch_dependency_lines=$(sed -n 's/^depend = /depend = /p' \
                "$metadata_root/.PKGINFO") || return 1
            cat >"$metadata_root.expected-PKGINFO" <<EOF
# Generated by makepkg $metadata_makepkg_version
# using fakeroot version $metadata_fakeroot_version
pkgname = vaultlink
pkgbase = vaultlink
xdata = pkgtype=pkg
pkgver = $metadata_version-1
pkgdesc = Secure file sharing for an existing Linux mountpoint
url = https://github.com/alexhaberl/VaultLink
builddate = $metadata_arch_builddate
packager = VaultLink maintainers <noreply@vaultlink.example>
size = $metadata_arch_size
arch = $marker_arch
license = MIT
$metadata_arch_dependency_lines
optdepend = cifs-utils: SMB 3.1.1 storage provisioning
EOF
            cmp -s "$metadata_root.expected-PKGINFO" "$metadata_root/.PKGINFO" || return 1
            metadata_pkgbuild_sha256=$(sha256sum "$metadata_pkgbuild" \
                | awk '{ print $1 }') || return 1
            cat >"$metadata_root.expected-BUILDINFO" <<EOF
format = 2
pkgname = vaultlink
pkgbase = vaultlink
pkgver = $metadata_version-1
pkgarch = $marker_arch
pkgbuild_sha256sum = $metadata_pkgbuild_sha256
packager = VaultLink maintainers <noreply@vaultlink.example>
builddate = $metadata_arch_builddate
builddir = /build/vaultlink-package
startdir = /build/vaultlink-package
buildtool = makepkg
buildtoolver = $metadata_makepkg_version
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
                >"$metadata_root.actual-installed" || return 1
            [ "$(wc -l <"$metadata_root.actual-installed" | tr -d '[:space:]')" = \
                "$(wc -l <"$metadata_builder_lock" | tr -d '[:space:]')" ] \
                || return 1
            : >"$metadata_root.expected-installed"
            while read -r metadata_installed_name metadata_installed_version; do
                metadata_installed_matches=$(grep -F -x \
                    -e "$metadata_installed_name-$metadata_installed_version-$marker_arch" \
                    -e "$metadata_installed_name-$metadata_installed_version-any" \
                    "$metadata_root.actual-installed" || true)
                [ "$(printf '%s\n' "$metadata_installed_matches" | grep -c . || true)" -eq 1 ] \
                    || return 1
                printf '%s\n' "$metadata_installed_matches" \
                    >>"$metadata_root.expected-installed"
            done <"$metadata_builder_lock"
            cmp -s "$metadata_root.expected-installed" \
                "$metadata_root.actual-installed" || return 1
            sed 's/^/installed = /' "$metadata_root.expected-installed" \
                >>"$metadata_root.expected-BUILDINFO"
            cmp -s "$metadata_root.expected-BUILDINFO" \
                "$metadata_root/.BUILDINFO" || return 1
            gzip -t "$metadata_root/.MTREE" || return 1
            gzip -dc "$metadata_root/.MTREE" >"$metadata_root.package.mtree" || return 1
            gzip -n <"$metadata_root.package.mtree" \
                >"$metadata_root.canonical.MTREE" || return 1
            cmp -s "$metadata_root.canonical.MTREE" "$metadata_root/.MTREE" || return 1
            (
                cd "$metadata_root"
                bsdtar --format=mtree \
                    --options='!all,use-set,type,uid,gid,mode,time,size,sha256,link' \
                    --exclude .MTREE -cf - .
            ) >"$metadata_root.recomputed-package.mtree" || return 1
            [ "$(grep -c '^\. ' "$metadata_root.package.mtree" || true)" -eq 0 ] \
                || return 1
            sed '/^\. /d' "$metadata_root.package.mtree" \
                >"$metadata_root.package-body.mtree" || return 1
            sed '/^\. /d' "$metadata_root.recomputed-package.mtree" \
                >"$metadata_root.recomputed-package-body.mtree" || return 1
            cmp -s "$metadata_root.package-body.mtree" \
                "$metadata_root.recomputed-package-body.mtree" || return 1
            bsdtar -tf "$metadata_root/.MTREE" \
                | sed -e 's|^\./||' -e 's|/$||' -e '/^$/d' -e '/^\.$/d' \
                | sort >"$metadata_root.mtree-files" || return 1
            (cd "$metadata_root" && find . -mindepth 1 ! -name .MTREE -print \
                | sed -e 's|^\./||' -e 's|/$||' | sort) \
                >"$metadata_root.expected-mtree-files" || return 1
            cmp -s "$metadata_root.expected-mtree-files" \
                "$metadata_root.mtree-files" || return 1
            sed -n 's/^depend = //p' "$metadata_root/.PKGINFO" >"$metadata_root.arch-depends"
            awk '/^[a-z0-9][a-z0-9@._+-]*$/ { next } { exit 1 }' \
                "$metadata_root.arch-depends" || return 1
            arch_dependency_count=$(wc -l <"$metadata_root.arch-depends" | tr -d '[:space:]')
            [ "$arch_dependency_count" -ge 1 ] && [ "$arch_dependency_count" -le 64 ] \
                || return 1
            [ "$arch_dependency_count" = \
                "$(sort -u "$metadata_root.arch-depends" | wc -l | tr -d '[:space:]')" ] \
                || return 1
            cat >"$metadata_root.baseline-arch-depends" <<'EOF'
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
            while IFS= read -r baseline_dependency; do
                grep -F -x -q "$baseline_dependency" "$metadata_root.arch-depends" || return 1
            done <"$metadata_root.baseline-arch-depends"
            [ "$(sed -n 's/^optdepend = //p' "$metadata_root/.PKGINFO")" = \
                'cifs-utils: SMB 3.1.1 storage provisioning' ] || return 1
            validate_embedded_lifecycle "$metadata_root/.INSTALL" "$metadata_lifecycle" \
                "$metadata_root.arch-install" || return 1
            validate_arch_install_script "$metadata_root/.INSTALL" "$metadata_lifecycle" \
                "$metadata_version" "$metadata_root.expected-arch-install" || return 1
            for arch_hook in pre_install post_install pre_upgrade post_upgrade pre_remove post_remove; do
                [ "$(grep -E -c "^${arch_hook}\\(\\) \\{" "$metadata_root/.INSTALL" || true)" -eq 1 ] \
                    || return 1
            done
            grep -F -q 'refusing to adopt markerless existing installation' "$metadata_lifecycle" || return 1
            grep -F -q 'package upgrade stages only the candidate' "$metadata_lifecycle" || return 1
            ;;
        *) return 1 ;;
    esac
}

extract_and_validate_package() {
    extract_file=$1
    extract_version=$2
    extract_root=$3
    expected_full_version=$(expected_database_version "$extract_version") || return 1
    install -d -o root -g root -m 0755 "$extract_root"
    payload_paths="$extract_root.paths"
    payload_types="$extract_root.types"
    case "$marker_format" in
        deb)
            [ "$(dpkg-deb -f "$extract_file" Package)" = "$package_name" ] || return 1
            [ "$(dpkg-deb -f "$extract_file" Version)" = "$expected_full_version" ] || return 1
            [ "$(dpkg-deb -f "$extract_file" Architecture)" = "$marker_arch" ] || return 1
            dpkg-deb --fsys-tarfile "$extract_file" >"$extract_root.data.tar" || return 1
            tar -tf "$extract_root.data.tar" >"$payload_paths" || return 1
            tar -tvf "$extract_root.data.tar" | awk '{ print substr($1, 1, 1) }' \
                >"$payload_types" || return 1
            ;;
        rpm)
            [ "$(rpm -qp --qf '%{NAME}' "$extract_file")" = "$package_name" ] || return 1
            [ "$(rpm -qp --qf '%{EPOCHNUM}' "$extract_file")" = 0 ] || return 1
            [ "$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$extract_file")" = "$expected_full_version" ] || return 1
            [ "$(rpm -qp --qf '%{ARCH}' "$extract_file")" = "$marker_arch" ] || return 1
            rpm -qpl "$extract_file" >"$payload_paths" || return 1
            rpm -qp --qf '[%{FILEMODES:perms}\n]' "$extract_file" \
                | awk '{ print substr($0, 1, 1) }' >"$payload_types" || return 1
            ;;
        pkg.tar.zst)
            bsdtar -tf "$extract_file" >"$payload_paths" || return 1
            bsdtar -tvf "$extract_file" | awk '{ print substr($1, 1, 1) }' \
                >"$payload_types" || return 1
            ;;
        *) return 1 ;;
    esac

    # Reject unsafe paths, links, hardlinks and special files before extraction.
    [ "$(wc -l <"$payload_paths" | tr -d '[:space:]')" = \
        "$(wc -l <"$payload_types" | tr -d '[:space:]')" ] || return 1
    awk '$0 != "-" && $0 != "d" { exit 1 }' "$payload_types" || return 1
    awk -v format="$marker_format" '
        NR == FNR { archive_type[FNR] = $0; next }
        $0 == "." || $0 == "./" {
            root_count++
            if (archive_type[FNR] != "d") invalid = 1
        }
        END {
            if (invalid) exit 1
            if (format == "deb" && root_count != 1) exit 1
            if (format != "deb" && root_count != 0) exit 1
        }
    ' "$payload_types" "$payload_paths" || return 1
    awk -v format="$marker_format" '
        {
            path = $0
            if (format == "rpm") {
                if (path !~ /^\/usr\//) exit 1
                sub(/^\//, "", path)
            } else {
                if (path == "." || path == "./") next
                sub(/^\.\//, "", path)
            }
            if (path == "" || path ~ /[^A-Za-z0-9._@+\/-]/ \
                || path ~ /^\// || path ~ /\/\// \
                || path == ".." || path ~ /^\.\.\// || path ~ /\/\.\.($|\/)/ \
                || path ~ /^\.\// || path ~ /\/\.($|\/)/)
                exit 1
            if (path !~ /^usr\// \
                && !(format == "pkg.tar.zst" \
                    && path ~ /^\.(PKGINFO|INSTALL|BUILDINFO|MTREE)$/))
                exit 1
            print path
        }
    ' "$payload_paths" >"$extract_root.normalized-paths" || return 1
    payload_entry_count=$(wc -l <"$extract_root.normalized-paths" | tr -d '[:space:]')
    [ "$payload_entry_count" -le 128 ] || return 1
    duplicate_payload=$(sort "$extract_root.normalized-paths" | uniq -d | sed -n '1p')
    [ -z "$duplicate_payload" ] || return 1

    case "$marker_format" in
        deb)
            (ulimit -f 1048576; dpkg-deb -x "$extract_file" "$extract_root") || return 1
            ;;
        rpm)
            rpm2cpio "$extract_file" >"$extract_root/package.cpio" || return 1
            (umask 022; ulimit -f 1048576; cd "$extract_root" \
                && cpio --quiet -idm --no-absolute-filenames <package.cpio) || return 1
            rm -f "$extract_root/package.cpio"
            ;;
        pkg.tar.zst)
            (umask 022; ulimit -f 1048576; \
                bsdtar --no-same-owner -xpf "$extract_file" -C "$extract_root") || return 1
            ;;
    esac
    unexpected_link=$(find "$extract_root" -type l -print -quit)
    [ -z "$unexpected_link" ] || return 1
    unexpected_special=$(find "$extract_root" ! -type d ! -type f -print -quit)
    [ -z "$unexpected_special" ] || return 1
    unexpected_hardlink=$(find "$extract_root" -type f -links +1 -print -quit)
    [ -z "$unexpected_hardlink" ] || return 1
    [ "$(du -sk "$extract_root" | awk '{print $1}')" -le 1048576 ] || return 1
    [ ! -e "$extract_root/etc" ] || return 1

    validate_package_metadata "$extract_file" "$extract_version" "$extract_root" || return 1
    cat >"$extract_root.expected-files.unsorted" <<'EOF'
usr/lib/systemd/system/vaultlink-update.service
usr/lib/systemd/system/vaultlink-update.timer
usr/lib/systemd/system/vaultlink.service
usr/lib/sysusers.d/vaultlink.conf
usr/lib/tmpfiles.d/vaultlink.conf
usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh
usr/lib/vaultlink/package/deploy/vaultlink-runtime-guard.sh
usr/lib/vaultlink/package/deploy/vaultlink-rollback.sh
usr/lib/vaultlink/package/deploy/vaultlink-upgrade.sh
usr/lib/vaultlink/package/vaultlink
usr/lib/vaultlink/package/vaultlink.cdx.json
usr/lib/vaultlink/package/vaultlink.sha256
usr/lib/vaultlink/package/version
usr/share/doc/vaultlink/examples/config/development.toml
usr/share/doc/vaultlink/examples/config/production-reverse-proxy.toml
usr/share/doc/vaultlink/examples/config/production-standalone-letsencrypt.toml
usr/share/doc/vaultlink/examples/config/production-standalone-tls.toml
usr/share/doc/vaultlink/examples/deploy/Caddyfile
usr/share/doc/vaultlink/examples/deploy/mnt-storage.mount.example
usr/share/doc/vaultlink/examples/deploy/vaultlink-external-proxy-network.conf
usr/share/doc/vaultlink/examples/deploy/vaultlink-external-storage.conf
usr/share/doc/vaultlink/examples/deploy/vaultlink-standalone-capability.conf
usr/share/doc/vaultlink/examples/deploy/vaultlink-update.conf.example
usr/share/licenses/vaultlink/LICENSE
usr/share/vaultlink/install-method.env
usr/share/vaultlink/minisign.pub
usr/share/vaultlink/update.conf.example
EOF
    case "$marker_format" in
        deb)
            printf '%s\n' usr/sbin/vaultlink-update \
                usr/share/doc/vaultlink/changelog.Debian.gz \
                usr/share/doc/vaultlink/copyright \
                >>"$extract_root.expected-files.unsorted"
            ;;
        rpm)
            printf '%s\n' usr/sbin/vaultlink-update \
                >>"$extract_root.expected-files.unsorted"
            ;;
        pkg.tar.zst)
            sed -i '/^usr\/share\/vaultlink\/install-method.env$/d' \
                "$extract_root.expected-files.unsorted"
            printf '%s\n' usr/bin/vaultlink-update \
                usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh \
                usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh \
                usr/lib/vaultlink/package/PKGBUILD \
                usr/lib/vaultlink/package/builder-packages.lock \
                usr/share/libalpm/hooks/vaultlink-remove.hook \
                >>"$extract_root.expected-files.unsorted"
            ;;
        *) return 1 ;;
    esac
    sort "$extract_root.expected-files.unsorted" >"$extract_root.expected-files"
    (cd "$extract_root" && find usr -type f -print | sort) >"$extract_root.actual-files"
    cmp -s "$extract_root.expected-files" "$extract_root.actual-files" || return 1
    cat >"$extract_root.expected-directories" <<'EOF'
usr
usr/lib
usr/lib/systemd
usr/lib/systemd/system
usr/lib/sysusers.d
usr/lib/tmpfiles.d
usr/lib/vaultlink
usr/lib/vaultlink/package
usr/lib/vaultlink/package/deploy
usr/sbin
usr/share
usr/share/doc
usr/share/doc/vaultlink
usr/share/doc/vaultlink/examples
usr/share/doc/vaultlink/examples/config
usr/share/doc/vaultlink/examples/deploy
usr/share/licenses
usr/share/licenses/vaultlink
usr/share/vaultlink
EOF
    if [ "$marker_format" = pkg.tar.zst ]; then
        sed -i 's|^usr/sbin$|usr/bin|' "$extract_root.expected-directories"
        printf '%s\n' usr/share/libalpm usr/share/libalpm/hooks \
            >>"$extract_root.expected-directories"
    fi
    sort "$extract_root.expected-directories" >"$extract_root.expected-directories.sorted"
    mv -f "$extract_root.expected-directories.sorted" "$extract_root.expected-directories"
    (cd "$extract_root" && find usr -type d -print | sort) \
        >"$extract_root.actual-directories"
    cmp -s "$extract_root.expected-directories" "$extract_root.actual-directories" \
        || return 1
    while IFS= read -r payload_directory; do
        [ "$(stat -c '%u:%g:%a' "$extract_root/$payload_directory")" = 0:0:755 ] \
            || return 1
    done <"$extract_root.actual-directories"
    extracted_binary="$extract_root${package_binary}"
    extracted_upgrade="$extract_root${package_upgrade}"
    extracted_rollback="$extract_root${package_rollback}"
    extracted_runtime_guard="$extract_root${runtime_guard}"
    extracted_key="$extract_root${public_key}"
    extracted_marker="$extract_root${install_method}"
    extracted_lifecycle="$extract_root${package_lifecycle}"
    for extracted_regular in "$extracted_binary" "$extracted_lifecycle" "$extracted_runtime_guard" \
        "$extracted_upgrade" "$extracted_rollback" "$extracted_key"; do
        [ -f "$extracted_regular" ] && [ ! -L "$extracted_regular" ] || return 1
        validate_root_file "$extracted_regular" "critical package payload" || return 1
    done
    [ -x "$extracted_binary" ] && [ -x "$extracted_lifecycle" ] && [ -x "$extracted_runtime_guard" ] \
        && [ -x "$extracted_upgrade" ] && [ -x "$extracted_rollback" ] || return 1
    case "$marker_format" in
        pkg.tar.zst)
            [ ! -e "$extracted_marker" ] && [ ! -L "$extracted_marker" ] || return 1
            extracted_installer="$extract_root${package_installer}"
            validate_root_file "$extracted_installer" "Arch package installer" || return 1
            [ "$(stat -c %a "$extracted_installer")" = 755 ] || return 1
            extracted_remover="$extract_root${package_remover}"
            validate_root_file "$extracted_remover" "Arch package remover" || return 1
            [ "$(stat -c %a "$extracted_remover")" = 755 ] || return 1
            extracted_remove_hook="$extract_root${package_remove_hook}"
            validate_arch_remove_hook "$extracted_remove_hook" || return 1
            ;;
        deb|rpm)
            validate_root_file "$extracted_marker" "package installation marker" || return 1
            [ "$(stat -c %a "$extracted_marker")" = 644 ] || return 1
            cmp -s "$trusted_install_method" "$extracted_marker" || return 1
            ;;
        *) return 1 ;;
    esac
    cmp -s "$public_key" "$extracted_key" || return 1
    [ "$(cat "$extract_root/usr/lib/vaultlink/package/version")" = "$extract_version" ] || return 1
    validate_candidate_checksum_root "$extract_root" || return 1
    while IFS= read -r payload_file; do
        case "$payload_file" in
            usr/lib/vaultlink/package/vaultlink|\
            usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh|\
            usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh|\
            usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh|\
            usr/lib/vaultlink/package/deploy/vaultlink-runtime-guard.sh|\
            usr/lib/vaultlink/package/deploy/vaultlink-rollback.sh|\
            usr/lib/vaultlink/package/deploy/vaultlink-upgrade.sh|\
            usr/sbin/vaultlink-update|usr/bin/vaultlink-update) expected_mode=755 ;;
            *) expected_mode=644 ;;
        esac
        [ "$(stat -c '%u:%g:%a' "$extract_root/$payload_file")" = "0:0:$expected_mode" ] \
            || return 1
    done <"$extract_root.actual-files"
    [ "$(read_bounded_version_from_root_workspace "$extracted_binary" \
        "package candidate")" = "$extract_version" ] || return 1
}

package_dry_run() {
    dry_file=$1
    dry_is_old=$2
    dry_extract_root=$3
    case "$marker_format" in
        deb)
            while IFS= read -r deb_dependency; do
                [ -n "$deb_dependency" ] || return 1
                [ "$(dpkg-query -W -f='${db:Status-Status}' \
                    "$deb_dependency" 2>/dev/null)" = installed ] || return 1
            done <"$dry_extract_root.deb-depends"
            dpkg --simulate --install "$dry_file" >/dev/null
            ;;
        rpm)
            if [ "$dry_is_old" = 1 ]; then
                rpm --nocontexts --test --upgrade --oldpackage --replacepkgs "$dry_file" >/dev/null
            else
                rpm --nocontexts --test --upgrade --replacepkgs "$dry_file" >/dev/null
            fi
            ;;
        pkg.tar.zst)
            set --
            while IFS= read -r arch_dependency; do
                [ -n "$arch_dependency" ] || return 1
                set -- "$@" "$arch_dependency"
            done <"$dry_extract_root.arch-depends"
            [ "$#" -ge 1 ] && [ "$#" -le 64 ] || return 1
            missing_dependencies=$(pacman -T -- "$@") || return 1
            [ -z "$missing_dependencies" ] || return 1
            pacman --upgrade --noconfirm --needed --print -- "$dry_file" >/dev/null
            ;;
        *) return 1 ;;
    esac
}

package_install_native() {
    case "$marker_format" in
        deb) dpkg --install "$install_file" >/dev/null ;;
        rpm)
            # Fedora's RPM SELinux plugin assigns a scriptlet execution
            # context that requires a domain transition. The kernel rejects
            # that transition under NoNewPrivileges even though SELinux stays
            # Enforcing. The updater has already verified the signed package,
            # its exact scriptlets, metadata, payload paths, and dependencies;
            # suppress only RPM's transaction context plugin so the reviewed
            # scriptlets execute in the existing updater domain without
            # weakening the systemd no-new-privileges boundary.
            if [ "$install_is_old" = 1 ]; then
                rpm --nocontexts --upgrade --oldpackage --replacepkgs "$install_file" >/dev/null
            else
                rpm --nocontexts --upgrade --replacepkgs "$install_file" >/dev/null
            fi
            ;;
        pkg.tar.zst) pacman --upgrade --noconfirm "$install_file" >/dev/null ;;
        *) return 1 ;;
    esac
}

package_install() {
    install_file=$1
    install_is_old=$2
    if [ "$install_is_old" = 1 ]; then
        # Recovery is the sole state in which package DB/candidate may report
        # the failed new package while /opt has already been restored to the
        # verified old runtime. Maintainer scripts accept that narrow mismatch
        # only when this updater passes both already-held lock descriptors.
        (
            VAULTLINK_PACKAGE_RECOVERY=1
            export VAULTLINK_PACKAGE_RECOVERY
            package_install_native
        )
    else
        (
            unset VAULTLINK_PACKAGE_RECOVERY
            package_install_native
        )
    fi
}

record_file_identity() {
    identity_file=$1
    identity_output=$2
    [ -f "$identity_file" ] && [ ! -L "$identity_file" ] || return 1
    stat -c '%d:%i:%u:%g:%a:%y' "$identity_file" >"$identity_output"
}

validate_file_unchanged_from_backup() {
    unchanged_file=$1
    unchanged_copy=$2
    unchanged_metadata=$3
    [ -f "$unchanged_file" ] && [ ! -L "$unchanged_file" ] || return 1
    cmp -s "$unchanged_file" "$unchanged_copy" || return 1
    current_identity=$(stat -c '%d:%i:%u:%g:%a:%y' "$unchanged_file") || return 1
    [ "$current_identity" = "$(cat "$unchanged_metadata")" ]
}

create_recovery_backup() {
    recovery_stamp=$(date -u +%Y%m%dT%H%M%SZ)
    recovery_stage="$backup_root/.package-update-$recovery_stamp-$$.incomplete"
    recovery_backup="$backup_root/package-update-$recovery_stamp-$$"
    [ ! -e "$recovery_stage" ] && [ ! -e "$recovery_backup" ] || return 1
    if systemctl --quiet is-active vaultlink.service; then
        service_was_active=1
    elif [ "$action" = auto ]; then
        echo "automatic installation stopped because vaultlink.service became inactive" >&2
        return 1
    fi
    # From this point until a completed update, the exit trap owns restoration
    # of the exact original service state. Set this before the stop so a signal
    # cannot strand a previously active service in the stopped state.
    service_downtime_started=1
    systemctl stop vaultlink.service || return 1
    ! systemctl --quiet is-active vaultlink.service || return 1
    validate_installed_payload "$installed_version" "$old_extract_root" || return 1
    cmp -s "$live_binary" "$old_extract_root$package_binary" || return 1
    install -d -o root -g root -m 0700 "$backup_root" "$recovery_stage" || return 1
    record_file_identity "$live_config" "$recovery_stage/config.metadata" || return 1
    install -o root -g root -m 0700 "$live_binary" "$recovery_stage/vaultlink" || return 1
    install -o root -g root -m 0600 "$live_config" "$recovery_stage/config.toml" || return 1
    install -o root -g root -m 0600 "$keyring" "$recovery_stage/secrets.keyring" || return 1
    validate_persistent_install_method || return 1
    install -o root -g root -m 0600 "$trusted_install_method" \
        "$recovery_stage/install-method.env" || return 1
    sqlite3 "$data" ".timeout 10000" ".backup '$recovery_stage/data.sqlite'" || return 1
    chown root:root "$recovery_stage/data.sqlite"
    chmod 0600 "$recovery_stage/data.sqlite"
    sqlite3 "$recovery_stage/data.sqlite" 'PRAGMA integrity_check' | grep -q -x ok || return 1
    [ -s "$recovery_stage/secrets.keyring" ] || return 1
    if [ -e "$update_config" ]; then
        validate_root_file "$update_config" "update configuration" || return 1
        record_file_identity "$update_config" "$recovery_stage/update-config.metadata" \
            || return 1
        install -o root -g root -m "$(stat -c %a "$update_config")" \
            "$update_config" "$recovery_stage/update.conf" || return 1
        printf '%s\n' present >"$recovery_stage/update-config.state"
    else
        printf '%s\n' absent >"$recovery_stage/update-config.state"
    fi
    (
        cd "$recovery_stage"
        sha256sum vaultlink config.toml config.metadata data.sqlite secrets.keyring \
            install-method.env update-config.state >SHA256SUMS
        if [ -f update.conf ]; then
            sha256sum update.conf update-config.metadata >>SHA256SUMS
        fi
    ) || return 1
    validate_file_unchanged_from_backup "$live_config" \
        "$recovery_stage/config.toml" "$recovery_stage/config.metadata" || return 1
    if [ -f "$recovery_stage/update.conf" ]; then
        validate_file_unchanged_from_backup "$update_config" \
            "$recovery_stage/update.conf" "$recovery_stage/update-config.metadata" \
            || return 1
    else
        [ ! -e "$update_config" ] && [ ! -L "$update_config" ] || return 1
    fi
    mv "$recovery_stage" "$recovery_backup" || return 1
    recovery_backup_valid=1
}

validate_recovery_backup() {
    [ "$recovery_backup_valid" -eq 1 ] && [ -d "$recovery_backup" ] \
        && [ ! -L "$recovery_backup" ] || return 1
    [ "$(stat -c '%u:%g:%a' "$recovery_backup")" = 0:0:700 ] || return 1
    (cd "$recovery_backup" && sha256sum -c SHA256SUMS >/dev/null)
}

restore_install_method_backup() {
    validate_recovery_backup || return 1
    validate_root_file "$recovery_backup/install-method.env" \
        "recovery installation marker" || return 1
    cmp -s "$recovery_backup/install-method.env" "$trusted_install_method" || return 1
    marker_directory=${install_method%/*}
    [ -d "$marker_directory" ] && [ ! -L "$marker_directory" ] || return 1
    [ "$(stat -c %u "$marker_directory")" -eq 0 ] || return 1
    marker_directory_mode=$(stat -c %a "$marker_directory")
    [ $((0$marker_directory_mode & 0022)) -eq 0 ] || return 1
    marker_restore="$marker_directory/.install-method.env.package-restore"
    rm -f "$marker_restore"
    install -o root -g root -m 0644 "$recovery_backup/install-method.env" \
        "$marker_restore" || return 1
    mv -f "$marker_restore" "$install_method" || return 1
    validate_persistent_install_method
}

restore_runtime_backup() {
    validate_recovery_backup || return 1
    restore_binary=/opt/vaultlink/.vaultlink.package-restore
    restore_data=/var/lib/vaultlink/.data.sqlite.package-restore
    restore_keyring=/var/lib/vaultlink/.secrets.keyring.package-restore
    rm -f "$restore_binary" "$restore_data" "$restore_keyring"
    install -o root -g root -m 0755 "$recovery_backup/vaultlink" "$restore_binary" || return 1
    install -o vaultlink -g vaultlink -m 0600 "$recovery_backup/data.sqlite" "$restore_data" || return 1
    install -o vaultlink -g vaultlink -m 0600 "$recovery_backup/secrets.keyring" "$restore_keyring" || return 1
    sqlite3 "$restore_data" 'PRAGMA integrity_check' | grep -q -x ok || return 1
    validate_file_unchanged_from_backup "$live_config" \
        "$recovery_backup/config.toml" "$recovery_backup/config.metadata" || return 1
    mv -f "$restore_binary" "$live_binary" || return 1
    rm -f "$data-wal" "$data-shm"
    mv -f "$restore_data" "$data" || return 1
    mv -f "$restore_keyring" "$keyring" || return 1
    case "$(cat "$recovery_backup/update-config.state")" in
        present)
            validate_file_unchanged_from_backup "$update_config" \
                "$recovery_backup/update.conf" \
                "$recovery_backup/update-config.metadata" || return 1
            ;;
        absent)
            [ ! -e "$update_config" ] && [ ! -L "$update_config" ] || return 1
            ;;
        *) return 1 ;;
    esac
}

wait_for_service() {
    wait_expected_version=$1
    wait_attempt=0
    while [ "$wait_attempt" -lt 30 ]; do
        if systemctl --quiet is-active vaultlink.service; then break; fi
        wait_attempt=$((wait_attempt + 1)); sleep 1
    done
    systemctl --quiet is-active vaultlink.service || return 1
    wait_target=$(timeout --kill-after=2 5 runuser -u vaultlink -- \
        "$live_binary" readiness-target --config "$live_config") || return 1
    [ "$(printf '%s\n' "$wait_target" | sed -n '$=')" -eq 3 ] || return 1
    wait_url=$(printf '%s\n' "$wait_target" | sed -n '1p')
    wait_connect=$(printf '%s\n' "$wait_target" | sed -n '2p')
    wait_insecure=$(printf '%s\n' "$wait_target" | sed -n '3p')
    case "$wait_url" in
        http://*) [ "$wait_connect:$wait_insecure" = -:0 ] || return 1 ;;
        https://*) [ "$wait_connect" != - ] && [ "$wait_insecure" = 1 ] || return 1 ;;
        *) return 1 ;;
    esac
    set -- --disable --silent --show-error --noproxy '*' --proto '=http,https' \
        --connect-timeout 2 --max-time 3 --max-filesize 4096 \
        --header 'Accept: application/json' --output -
    [ "$wait_connect" = - ] || set -- "$@" --connect-to "$wait_connect"
    [ "$wait_insecure" = 0 ] || set -- "$@" --insecure
    wait_attempt=0
    wait_expected_body='{"ok":true,"version":"'"$wait_expected_version"'"}'
    while [ "$wait_attempt" -lt 30 ]; do
        if wait_body=$(timeout --kill-after=1 4 runuser -u vaultlink -- curl "$@" -- "$wait_url" 2>/dev/null) \
            && [ "$wait_body" = "$wait_expected_body" ]; then return 0; fi
        wait_attempt=$((wait_attempt + 1)); sleep 1
    done
    return 1
}

force_service_inactive() {
    # A terminal recovery failure must never leave a potentially mixed
    # package/runtime state serving requests. Stopping may itself report an
    # error, so verify the exact postcondition independently.
    systemctl stop vaultlink.service >/dev/null 2>&1 || :
    inactive_state=$(systemctl is-active vaultlink.service 2>/dev/null || true)
    [ "$inactive_state" = inactive ]
}

recover_previous_installation() {
    set +e
    recovery_failed=0
    recovery_stopped=0
    recovery_lock_ready=$maintenance_lock_held
    if [ "$maintenance_lock_held" -eq 0 ]; then
        if prepare_lock_file "$maintenance_lock"; then
            exec 8>"$maintenance_lock"
        else
            recovery_failed=1
        fi
        if [ "$recovery_failed" -eq 0 ] \
            && validate_open_lock 8 "$maintenance_lock" \
            && flock -n 8 \
            && validate_open_lock 8 "$maintenance_lock"; then
            maintenance_lock_held=1
            recovery_lock_ready=1
        else
            recovery_failed=1
        fi
    fi
    if [ "$recovery_lock_ready" -eq 1 ] \
        && systemctl stop vaultlink.service >/dev/null 2>&1; then
        recovery_stopped=1
    else
        recovery_failed=1
    fi
    if [ "$recovery_stopped" -eq 1 ]; then
        restore_install_method_backup || recovery_failed=1
        if package_install "$old_package_file" 1; then
            systemctl daemon-reload || recovery_failed=1
        else
            recovery_failed=1
        fi
        restore_runtime_backup || recovery_failed=1
        validate_installed_payload "$installed_version" "$old_extract_root" || recovery_failed=1
        cmp -s "$live_binary" "$old_extract_root$package_binary" || recovery_failed=1
        restored_version=$(read_bounded_version "$live_binary" "restored binary") || recovery_failed=1
        [ "${restored_version:-}" = "$installed_version" ] || recovery_failed=1
        sqlite3 "$data" 'PRAGMA integrity_check' | grep -q -x ok || recovery_failed=1
        if [ "$service_was_active" -eq 1 ]; then
            # Do not restart until package-manager, payload, live-binary, and
            # database parity have all been restored. If start/readiness then
            # fails, force the service back to the exact inactive state.
            if [ "$recovery_failed" -eq 0 ]; then
                systemctl start vaultlink.service || recovery_failed=1
                wait_for_service "$installed_version" || recovery_failed=1
            fi
        else
            force_service_inactive || recovery_failed=1
        fi
    fi
    if [ "$recovery_failed" -ne 0 ]; then
        force_service_inactive || recovery_failed=1
    fi
    [ "$recovery_failed" -eq 0 ]
}

restore_pre_mutation_service_state() {
    set +e
    pre_mutation_restore_failed=0
    validate_installed_payload "$installed_version" "$old_extract_root" \
        || pre_mutation_restore_failed=1
    cmp -s "$live_binary" "$old_extract_root$package_binary" \
        || pre_mutation_restore_failed=1
    sqlite3 "$data" 'PRAGMA integrity_check' | grep -q -x ok \
        || pre_mutation_restore_failed=1
    if [ "$service_was_active" -eq 1 ]; then
        if [ "$pre_mutation_restore_failed" -eq 0 ]; then
            systemctl start vaultlink.service || pre_mutation_restore_failed=1
            wait_for_service "$installed_version" || pre_mutation_restore_failed=1
        fi
    else
        force_service_inactive || pre_mutation_restore_failed=1
    fi
    if [ "$pre_mutation_restore_failed" -ne 0 ]; then
        force_service_inactive || pre_mutation_restore_failed=1
    fi
    if [ "$pre_mutation_restore_failed" -eq 0 ]; then
        if [ -n "${recovery_stage:-}" ] && [ -d "$recovery_stage" ] \
            && [ ! -L "$recovery_stage" ]; then
            case "$recovery_stage" in
                "$backup_root"/.package-update-*.incomplete) rm -rf -- "$recovery_stage" ;;
                *) pre_mutation_restore_failed=1 ;;
            esac
        fi
        service_downtime_started=0
    fi
    [ "$pre_mutation_restore_failed" -eq 0 ]
}

on_exit() {
    exit_status=$?
    trap - 0
    # Recovery may reinstall a verified package, restore SQLite state, and
    # wait for readiness. A second termination signal must not interrupt that
    # bounded fail-closed recovery and strand a mixed package/runtime state.
    trap '' 1 2 15
    if [ "$exit_status" -ne 0 ] && [ "$package_mutation_started" -eq 1 ] \
        && [ "$update_complete" -eq 0 ]; then
        echo "VaultLink package update failed; restoring the verified previous package and runtime" >&2
        if recover_previous_installation; then
            echo "VaultLink previous package and runtime were restored" >&2
        else
            preserve_work=1
            if [ -n "$work" ] && [ -d "$work" ]; then
                find "$work" -type d -exec chmod 0700 {} +
                find "$work" -type f -exec chmod 0600 {} +
            fi
            echo "CRITICAL: package/runtime recovery parity failed; recover manually from $recovery_backup" >&2
            echo "CRITICAL: verified old package and signed evidence preserved at $work" >&2
        fi
    elif [ "$exit_status" -ne 0 ] && [ "$service_downtime_started" -eq 1 ] \
        && [ "$update_complete" -eq 0 ]; then
        echo "VaultLink update preparation was interrupted; restoring the original service state" >&2
        if restore_pre_mutation_service_state; then
            echo "VaultLink original service state was restored without changing the package database" >&2
        else
            preserve_work=1
            if [ -n "$work" ] && [ -d "$work" ]; then
                find "$work" -type d -exec chmod 0700 {} +
                find "$work" -type f -exec chmod 0600 {} +
            fi
            echo "CRITICAL: pre-mutation service-state restoration failed; package database was not changed" >&2
            echo "CRITICAL: verified old package and signed evidence preserved at $work" >&2
            if [ -n "${recovery_stage:-}" ]; then
                echo "CRITICAL: incomplete recovery material may remain at $recovery_stage" >&2
            fi
        fi
    fi
    if [ "$preserve_work" -eq 0 ] && [ -n "$work" ] && [ -d "$work" ]; then
        rm -rf -- "$work"
    fi
    exit "$exit_status"
}
trap on_exit 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

validate_root_file "$live_binary" "installed VaultLink binary" || fail "installed binary is unsafe"
validate_root_file "$live_config" "installed VaultLink configuration" || fail "installed configuration is unsafe"
validate_root_file "$public_key" "VaultLink release public key" || fail "release public key is unsafe"
[ "$(stat -c %a "$public_key")" = 644 ] || fail "release public key must have mode 0644"
[ -x "$live_binary" ] || fail "installed VaultLink binary is not executable"
read_install_method || fail "a strict package installation marker is required; archive installations cannot be updated"
validate_host_binding || fail "installation marker does not match the exact host distribution and architecture"
validate_service_identity || fail "the VaultLink service identity is missing, unlocked, or inconsistent"
validate_service_file "$data" "VaultLink database" || fail "installed database is unsafe"
validate_service_file "$keyring" "VaultLink secrets keyring" || fail "installed secrets keyring is unsafe"
require_package_commands || fail "native package tooling for $marker_format is unavailable"
installed_version=$(read_bounded_version "$live_binary" "installed binary") || fail "installed version is invalid"
validate_stable_tag "v$installed_version" || fail "installed version is not a stable SemVer version"
validate_installed_package "$installed_version" \
    || fail "package database, marker, architecture, and live binary are not a consistent installation"
current_updater=/usr/sbin/vaultlink-update
current_arch_installer=
current_arch_remover=
if [ "$marker_format" = pkg.tar.zst ]; then
    current_updater=/usr/bin/vaultlink-update
    current_arch_installer=$package_installer
    current_arch_remover=$package_remover
fi
for current_payload in "$package_binary" "$package_lifecycle" "$runtime_guard" "$package_upgrade" \
    "$package_rollback" "$current_updater" ${current_arch_installer:+"$current_arch_installer"} \
    ${current_arch_remover:+"$current_arch_remover"} \
    ${current_arch_installer:+"$package_remove_hook"} \
    ${current_arch_installer:+"/usr/lib/vaultlink/package/PKGBUILD"} \
    ${current_arch_installer:+"/usr/lib/vaultlink/package/builder-packages.lock"} \
    /usr/lib/vaultlink/package/version /usr/lib/vaultlink/package/vaultlink.sha256; do
    validate_root_file "$current_payload" "installed package payload" \
        || fail "installed package payload is unsafe"
done
[ -x "$package_binary" ] && [ -x "$package_lifecycle" ] && [ -x "$runtime_guard" ] && [ -x "$package_upgrade" ] \
    && [ -x "$package_rollback" ] && [ -x "$current_updater" ] \
    || fail "installed package executables have unsafe modes"
[ "$(stat -c %a "$package_binary")" = 755 ] \
    && [ "$(stat -c %a "$package_lifecycle")" = 755 ] \
    && [ "$(stat -c %a "$runtime_guard")" = 755 ] \
    && [ "$(stat -c %a "$package_upgrade")" = 755 ] \
    && [ "$(stat -c %a "$package_rollback")" = 755 ] \
    && [ "$(stat -c %a "$current_updater")" = 755 ] \
    || fail "installed package executables must have mode 0755"
if [ -n "$current_arch_installer" ]; then
    [ -x "$current_arch_installer" ] \
        && [ "$(stat -c %a "$current_arch_installer")" = 755 ] \
        || fail "installed Arch package installer must be root-owned mode 0755"
    [ -x "$current_arch_remover" ] \
        && [ "$(stat -c %a "$current_arch_remover")" = 755 ] \
        || fail "installed Arch package remover must be root-owned mode 0755"
    validate_arch_remove_hook "$package_remove_hook" \
        || fail "installed Arch removal hook is unsafe or unexpected"
    [ "$(stat -c %a /usr/lib/vaultlink/package/PKGBUILD)" = 644 ] \
        && [ "$(stat -c %a /usr/lib/vaultlink/package/builder-packages.lock)" = 644 ] \
        || fail "installed Arch build provenance must have mode 0644"
fi
[ "$(cat /usr/lib/vaultlink/package/version)" = "$installed_version" ] \
    || fail "installed package version metadata diverges from the package database"
validate_candidate_checksum_root '' \
    || fail "installed package candidate checksum is invalid"
[ "$(read_bounded_version "$package_binary" "installed package candidate")" = "$installed_version" ] \
    || fail "installed package candidate diverges from the package database"
cmp -s "$live_binary" "$package_binary" \
    || fail "live binary diverges from the installed package candidate"

prepare_lock_file "$update_lock" \
    || fail "VaultLink update lock path is unsafe"
prepare_lock_file "$maintenance_lock" \
    || fail "VaultLink maintenance lock path is unsafe"
exec 9>"$update_lock"
validate_open_lock 9 "$update_lock" \
    || fail "VaultLink update lock changed while it was opened"
flock -n 9 || fail "another VaultLink update check is already running"
validate_open_lock 9 "$update_lock" \
    || fail "VaultLink update lock changed while it was acquired"

latest_tag=$(fetch_latest_tag) || fail "the latest stable GitHub release could not be resolved safely"
latest_version=${latest_tag#v}
version_order=$(compare_semver "$latest_version" "$installed_version") \
    || fail "installed or release version is not valid SemVer"
printf 'installed_version=%s\n' "$installed_version"
printf 'latest_version=%s\n' "$latest_version"
if [ "$version_order" -le 0 ]; then
    printf 'update_available=false\n'
    exit 0
fi
printf 'update_available=true\n'
[ "$action" != check ] || exit 0

if [ "$action" = auto ]; then
    auto_install_value=$(read_auto_install) || fail "update configuration is invalid"
    if [ "$auto_install_value" != true ]; then
        printf 'auto_install=false\n'
        exit 0
    fi
    systemctl --quiet is-active vaultlink.service \
        || fail "automatic installation requires an active vaultlink.service"
fi

for protected_directory in "$backup_root" "$work_root"; do
    if [ -e "$protected_directory" ] || [ -L "$protected_directory" ]; then
        [ -d "$protected_directory" ] && [ ! -L "$protected_directory" ] \
            || fail "protected update workspace path is unsafe: $protected_directory"
    fi
done
install -d -o root -g root -m 0700 "$backup_root" "$work_root" \
    || fail "could not create the protected update workspace"
for protected_directory in "$backup_root" "$work_root"; do
    [ "$(stat -c '%u:%g:%a' "$protected_directory")" = 0:0:700 ] \
        || fail "protected update workspace must be root:root mode 0700"
done
work=$(mktemp -d "$work_root/vaultlink-update.XXXXXXXX") \
    || fail "could not create the protected update directory"
trusted_install_method="$work/host-install-method.env"
install -o root -g root -m 0600 "$install_method" "$trusted_install_method" \
    || fail "could not preserve the installation binding for the transaction"
validate_persistent_install_method \
    || fail "installation binding changed while preparing the transaction"
old_package_file=$(verify_release_package "$installed_version" "$work/old-release") \
    || fail "installed release package or its signed evidence could not be verified"
new_package_file=$(verify_release_package "$latest_version" "$work/new-release") \
    || fail "new release package or its signed evidence could not be verified"
old_extract_root="$work/old-package"
new_extract_root="$work/new-package"
extract_and_validate_package "$old_package_file" "$installed_version" "$old_extract_root" \
    || fail "installed release package payload is invalid"
extract_and_validate_package "$new_package_file" "$latest_version" "$new_extract_root" \
    || fail "new release package payload is invalid"
validate_installed_payload "$installed_version" "$old_extract_root" \
    || fail "installed package payload differs from its verified release package"
candidate_binary="$new_extract_root${package_binary}"
candidate_upgrade="$new_extract_root${package_upgrade}"

package_dry_run "$new_package_file" 0 "$new_extract_root" \
    || fail "new package dependencies are unavailable; update the host packages manually"
package_dry_run "$old_package_file" 1 "$old_extract_root" \
    || fail "the verified rollback package cannot be reinstalled offline"

exec 8>"$maintenance_lock"
validate_open_lock 8 "$maintenance_lock" \
    || fail "VaultLink maintenance lock changed while it was opened"
flock -n 8 || fail "another VaultLink upgrade or rollback is already running"
validate_open_lock 8 "$maintenance_lock" \
    || fail "VaultLink maintenance lock changed while it was acquired"
maintenance_lock_held=1
validate_installed_payload "$installed_version" "$old_extract_root" \
    || fail "installed package state changed before the maintenance window"
cmp -s "$live_binary" "$old_extract_root$package_binary" \
    || fail "live runtime changed before the maintenance window"
create_recovery_backup || fail "could not create the pre-update runtime recovery unit"
validate_persistent_install_method \
    || fail "installation binding changed before native package installation"
package_mutation_started=1
package_install "$new_package_file" 0 || fail "native package installation failed"
systemctl daemon-reload \
    || fail "systemd could not reload the newly installed package units"
validate_installed_payload "$latest_version" "$new_extract_root" \
    || fail "new package database state or installed candidate is inconsistent"
cmp -s "$public_key" "$new_extract_root${public_key}" \
    || fail "installed package changed the pinned release public key"
validate_persistent_install_method \
    || fail "installed package changed the persistent installation binding"

# The normal upgrade helper owns migration, activation, readiness, integrity,
# and its own automatic runtime restore. Transfer the already locked open file
# description on FD 8; the helper validates its inode and lock before use. This
# keeps package installation and runtime activation in one critical section.
validate_installed_payload "$latest_version" "$new_extract_root" \
    || fail "package state changed before the maintenance-lock handoff"
cmp -s "$live_binary" "$recovery_backup/vaultlink" \
    || fail "live runtime changed before the maintenance-lock handoff"
backup_directory=$(VAULTLINK_MAINTENANCE_LOCK_FD=8 \
    "$candidate_upgrade" "$candidate_binary" "$live_config") \
    || fail "verified package activation or migration failed"
case "$backup_directory" in
    "$backup_root"/*)
        case "${backup_directory#"$backup_root"/}" in
            ''|*[!A-Za-z0-9._-]*) fail "upgrade helper returned an unsafe backup path" ;;
        esac
        ;;
    *) fail "upgrade helper returned an unsafe backup path" ;;
esac
[ -d "$backup_directory" ] && [ ! -L "$backup_directory" ] \
    && [ "$(stat -c '%u:%g:%a' "$backup_directory")" = 0:0:700 ] \
    || fail "upgrade helper did not retain a protected backup directory"

[ "$(read_bounded_version "$live_binary" "updated binary")" = "$latest_version" ] \
    || fail "live binary does not match the package database version"
validate_installed_payload "$latest_version" "$new_extract_root" \
    || fail "updated package database, payload, and installation binding diverged"
[ "$(read_bounded_version "$package_binary" "installed package candidate")" = "$latest_version" ] \
    || fail "installed package candidate does not match the package database version"
cmp -s "$package_binary" "$candidate_binary" \
    || fail "installed package candidate differs from the verified release payload"
cmp -s "$live_binary" "$candidate_binary" \
    || fail "live binary differs from the verified package candidate"
sqlite3 "$data" 'PRAGMA integrity_check' | grep -q -x ok \
    || fail "updated database failed integrity verification"
wait_for_service "$latest_version" || fail "updated service failed readiness verification"
if [ "$service_was_active" -eq 0 ]; then
    systemctl stop vaultlink.service || fail "could not preserve the deliberately stopped service state"
    systemctl --quiet is-active vaultlink.service \
        && fail "manual package update unexpectedly left the service active"
fi
validate_file_unchanged_from_backup "$live_config" \
    "$recovery_backup/config.toml" "$recovery_backup/config.metadata" \
    || fail "package update changed configuration bytes or filesystem identity"
if [ -f "$recovery_backup/update.conf" ]; then
    validate_file_unchanged_from_backup "$update_config" \
        "$recovery_backup/update.conf" "$recovery_backup/update-config.metadata" \
        || fail "package update changed update.conf bytes or filesystem identity"
else
    [ ! -e "$update_config" ] && [ ! -L "$update_config" ] \
        || fail "package installation created an update configuration"
fi

update_complete=1
printf 'backup_directory=%s\n' "$backup_directory"
printf 'recovery_directory=%s\n' "$recovery_backup"
printf 'update_installed=true\n'
