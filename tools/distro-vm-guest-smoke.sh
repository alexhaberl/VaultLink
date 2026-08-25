#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG

[ "$(id -u)" -eq 0 ] || exit 77
[ "$#" -eq 8 ] || {
    echo "usage: $0 TARGET_ID DISTRO DISTRO_VERSION FORMAT PACKAGE_ARCH VERSION PACKAGE VM_PACKAGES_SHA256" >&2
    exit 64
}
target_id=$1
distribution=$2
distribution_version=$3
package_format=$4
package_arch=$5
version=$6
package=$7
vm_packages_sha256=$8
[ -f "$package" ] || exit 66
package_copy=/var/tmp/$(basename "$package")
install -o root -g root -m 0600 "$package" "$package_copy"
package=$package_copy
arch_initial_installer=
fedora_audit_marker=
fedora_audit_start_line=

# shellcheck disable=SC1091
. /etc/os-release
[ "$ID" = "$distribution" ] || {
    echo "unexpected guest distribution: $ID" >&2
    exit 77
}
if [ "$distribution" != arch ]; then
    [ "$VERSION_ID" = "$distribution_version" ] || {
        echo "unexpected guest version: $VERSION_ID" >&2
        exit 77
    }
fi
[ "$(cat /usr/local/share/vaultlink-vm-target)" = "$target_id" ]
[ "$(sha256sum /usr/local/share/vaultlink-vm-packages.lock | awk '{print $1}')" = "$vm_packages_sha256" ]

# Prove that the immutable guest still has the complete package closure that
# was measured while its image was provisioned.  Hashing only the stored lock
# would not bind that evidence to the live package database.
live_vm_packages=$(mktemp)
trap 'rm -f "$live_vm_packages"' EXIT HUP INT TERM
case "$distribution" in
    debian | ubuntu)
        dpkg-query -W -f='${binary:Package}=${Version}\n' \
            | LC_ALL=C sort >"$live_vm_packages"
        ;;
    fedora)
        rpm -qa --qf '%{NAME}=%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' \
            | LC_ALL=C sort >"$live_vm_packages"
        ;;
    arch)
        pacman -Q | LC_ALL=C sort >"$live_vm_packages"
        ;;
    *) exit 65 ;;
esac
cmp /usr/local/share/vaultlink-vm-packages.lock "$live_vm_packages"
rm -f "$live_vm_packages"
trap - EXIT HUP INT TERM
[ "$(findmnt -n -o FSTYPE --target /mnt)" = ext4 ]
[ "$(findmnt -n -o SOURCE --target /mnt)" = /dev/vdb ]

install_package() {
    case "$package_format" in
        deb) dpkg --install "$package" ;;
        rpm) rpm --upgrade --replacepkgs "$package" ;;
        pkg.tar.zst) pacman -U --noconfirm "$package" ;;
        *) exit 65 ;;
    esac
}
initial_install_package() {
    if [ "$package_format" = pkg.tar.zst ]; then
        "$arch_initial_installer" "$package"
    else
        install_package
    fi
}
upgrade_package() {
    if [ "$package_format" = pkg.tar.zst ]; then
        /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh \
            preinstall pkg.tar.zst arch rolling x86_64 vaultlink upgrade
    fi
    install_package
}
remove_package() {
    case "$package_format" in
        deb) dpkg --remove vaultlink ;;
        rpm) rpm --erase vaultlink ;;
        pkg.tar.zst)
            /usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh
            ;;
        *) exit 65 ;;
    esac
}
query_package() {
    case "$package_format" in
        deb) dpkg-query -W -f='${Version}\n' vaultlink ;;
        rpm) rpm -q --qf '%{VERSION}-%{RELEASE}\n' vaultlink ;;
        pkg.tar.zst) pacman -Q vaultlink | awk '{print $2}' ;;
        *) exit 65 ;;
    esac
}

if [ "$package_format" = pkg.tar.zst ]; then
    arch_initial_installer=/var/tmp/vaultlink-package-install.sh
    bsdtar -xOf "$package" \
        usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh \
        >"$arch_initial_installer"
    chown root:root "$arch_initial_installer"
    chmod 0700 "$arch_initial_installer"
fi

if [ "$distribution" = fedora ]; then
    [ "$(getenforce)" = Enforcing ]
    [ "$(systemctl is-active auditd.service)" = active ]
    audit_log=/var/log/audit/audit.log
    [ -f "$audit_log" ] && [ ! -L "$audit_log" ] && [ -s "$audit_log" ]
    fedora_audit_marker="VAULTLINK_FULL_GATE_START_${target_id}_$$"
    auditctl -m "$fedora_audit_marker"
    audit_attempt=0
    while ! grep -F -q "$fedora_audit_marker" "$audit_log"; do
        audit_attempt=$((audit_attempt + 1))
        [ "$audit_attempt" -lt 30 ] || exit 70
        sleep 1
    done
    fedora_audit_start_line=$(grep -n -F "$fedora_audit_marker" "$audit_log" \
        | tail -n 1 | cut -d: -f1)
    case "$fedora_audit_start_line" in ''|*[!0-9]*) exit 70 ;; esac
fi

verify_install() {
    installed=$(query_package)
    case "$installed" in "$version"-1*) ;; *) echo "unexpected package version: $installed" >&2; exit 77 ;; esac
    marker=/usr/share/vaultlink/install-method.env
    [ "$(stat -c %u:%g:%a "$marker")" = 0:0:644 ]
    grep -F -x -q "FORMAT=$package_format" "$marker"
    grep -F -x -q "OS_ID=$distribution" "$marker"
    grep -F -x -q "OS_VERSION=$distribution_version" "$marker"
    grep -F -x -q "ARCH=$package_arch" "$marker"
    grep -F -x -q 'PACKAGE_NAME=vaultlink' "$marker"
    [ -x /usr/lib/vaultlink/package/vaultlink ]
    [ -x /usr/lib/vaultlink/package/deploy/vaultlink-upgrade.sh ]
    [ -x /usr/lib/vaultlink/package/deploy/vaultlink-rollback.sh ]
    [ -x /usr/sbin/vaultlink-update ]
    if systemctl --quiet is-enabled vaultlink.service; then
        echo "fresh package unexpectedly enabled vaultlink.service" >&2
        exit 77
    fi
    if systemctl --quiet is-enabled vaultlink-update.timer; then
        echo "fresh package unexpectedly enabled vaultlink-update.timer" >&2
        exit 77
    fi
    if systemctl --quiet is-active vaultlink.service; then
        echo "fresh package unexpectedly started vaultlink.service" >&2
        exit 77
    fi
    runuser -u vaultlink -- /usr/lib/vaultlink/package/vaultlink --version \
        | grep -F -q "$version"
}

initial_install_package
systemctl daemon-reload
verify_install
upgrade_package
verify_install

sh /tmp/distro-vm-runtime-smoke.sh "$target_id" /tmp/vaultlink-vm-evidence

# Exercise the real systemd sandbox and distribution package hooks without
# network access. The temporary drop-in replaces only ExecStart and performs a
# same-package reinstall from a protected local copy; all other unit hardening
# remains exactly as shipped.
unit_probe_dir=/var/lib/vaultlink-backups/unit-package-probe
unit_dropin=/etc/systemd/system/vaultlink-update.service.d/90-package-gate.conf
install -d -o root -g root -m 0700 "$unit_probe_dir"
unit_probe_package="$unit_probe_dir/$(basename "$package")"
install -o root -g root -m 0600 "$package" "$unit_probe_package"
case "$package_format" in
    deb) unit_probe_command="/usr/bin/dpkg --install $unit_probe_package" ;;
    rpm) unit_probe_command="/usr/bin/rpm --upgrade --replacepkgs $unit_probe_package" ;;
    pkg.tar.zst) unit_probe_command="/usr/bin/pacman -U --noconfirm $unit_probe_package" ;;
    *) exit 65 ;;
esac
install -d -o root -g root -m 0755 "$(dirname "$unit_dropin")"
cat >"$unit_dropin" <<EOF
[Service]
ExecStart=
ExecStart=$unit_probe_command
EOF
chown root:root "$unit_dropin"
chmod 0644 "$unit_dropin"
systemctl daemon-reload
if ! systemctl start vaultlink-update.service; then
    journalctl -u vaultlink-update.service --no-pager \
        > /tmp/vaultlink-vm-evidence/update-unit-package-manager.journal
    exit 77
fi
systemctl show vaultlink-update.service --no-pager \
    -p ActiveState -p Result -p ExecMainStatus \
    > /tmp/vaultlink-vm-evidence/update-unit-package-manager.env
grep -F -x -q 'ActiveState=inactive' \
    /tmp/vaultlink-vm-evidence/update-unit-package-manager.env
grep -F -x -q 'Result=success' \
    /tmp/vaultlink-vm-evidence/update-unit-package-manager.env
grep -F -x -q 'ExecMainStatus=0' \
    /tmp/vaultlink-vm-evidence/update-unit-package-manager.env
journalctl -u vaultlink-update.service --no-pager \
    > /tmp/vaultlink-vm-evidence/update-unit-package-manager.journal
rm -f "$unit_dropin"
rm -rf "$unit_probe_dir"
systemctl daemon-reload

install -d -m 0750 /etc/vaultlink /var/lib/vaultlink /var/lib/vaultlink-backups
printf preserved >/etc/vaultlink/vm-smoke-preserve
printf preserved >/var/lib/vaultlink/vm-smoke-preserve
printf preserved >/var/lib/vaultlink-backups/vm-smoke-preserve
remove_package
for path in \
    /etc/vaultlink/vm-smoke-preserve \
    /var/lib/vaultlink/vm-smoke-preserve \
    /var/lib/vaultlink-backups/vm-smoke-preserve; do
    grep -F -x -q preserved "$path"
done
test -s /var/lib/vaultlink/data.sqlite
test -s /var/lib/vaultlink/secrets.keyring
[ "$(sqlite3 /var/lib/vaultlink/data.sqlite 'PRAGMA integrity_check;')" = ok ]
printf 'ok\n' >/tmp/vaultlink-vm-evidence/post-remove-sqlite-integrity.txt
id vaultlink >/dev/null

initial_install_package
systemctl daemon-reload
verify_install
[ "$(sqlite3 /var/lib/vaultlink/data.sqlite 'PRAGMA integrity_check;')" = ok ]
printf 'ok\n' >/tmp/vaultlink-vm-evidence/post-reinstall-sqlite-integrity.txt
candidate_sha256=$(sha256sum /usr/lib/vaultlink/package/vaultlink | awk '{print $1}')
active_sha256=$(sha256sum /opt/vaultlink/vaultlink | awk '{print $1}')
[ "$candidate_sha256" = "$active_sha256" ]
service_enabled=$(systemctl is-enabled vaultlink.service 2>/dev/null || true)
timer_enabled=$(systemctl is-enabled vaultlink-update.timer 2>/dev/null || true)
service_active=$(systemctl is-active vaultlink.service 2>/dev/null || true)
if [ "$distribution" = fedora ]; then
    evidence=/tmp/vaultlink-vm-evidence
    [ "$(getenforce)" = Enforcing ]
    [ "$(systemctl is-active auditd.service)" = active ]
    auditctl -s >"$evidence/audit-status-full-gate-after.txt"
    grep -E -q '^enabled[[:space:]]+1$' "$evidence/audit-status-full-gate-after.txt"
    sed -n "${fedora_audit_start_line},\$p" "$audit_log" \
        >"$evidence/audit-window-full-gate.log"
    grep -F -q "$fedora_audit_marker" "$evidence/audit-window-full-gate.log"
    journalctl -k -b --no-pager >"$evidence/kernel-audit-full-gate.journal"
    if grep -E 'type=(AVC|USER_AVC|SELINUX_ERR|USER_SELINUX_ERR)' \
        "$evidence/audit-window-full-gate.log" \
        | grep -E -i 'vaultlink|/opt/vaultlink|/var/lib/vaultlink|/mnt/storage'; then
        echo "SELinux recorded a VaultLink-related AVC denial during the full package gate" >&2
        exit 77
    fi
    if grep -E -i 'avc:[[:space:]]+denied' "$evidence/kernel-audit-full-gate.journal" \
        | grep -E -i 'vaultlink|/opt/vaultlink|/var/lib/vaultlink|/mnt/storage'; then
        echo "kernel journal recorded a VaultLink-related AVC denial during the full package gate" >&2
        exit 77
    fi
    printf 'selinux=Enforcing\nvaultlink_avc_denials=0\nwindow=full-package-gate\n' \
        >"$evidence/selinux-full-gate.env"
fi
printf 'target=%s\npackage_version=%s\npackage_sha256=%s\nbinary_sha256=%s\n' \
    "$target_id" "$(query_package)" \
    "$(sha256sum "$package" | awk '{print $1}')" \
    "$candidate_sha256"
printf 'active_binary_sha256=%s\nservice_enabled=%s\nupdate_timer_enabled=%s\nservice_active=%s\n' \
    "$active_sha256" "$service_enabled" "$timer_enabled" "$service_active"
