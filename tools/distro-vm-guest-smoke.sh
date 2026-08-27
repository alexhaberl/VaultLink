#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG

[ "$(id -u)" -eq 0 ] || exit 77
[ "$#" -eq 9 ] || {
    echo "usage: $0 TARGET_ID DISTRO DISTRO_VERSION FORMAT PACKAGE_ARCH VERSION PACKAGE VM_PACKAGES_SHA256 ACCELERATION" >&2
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
acceleration=$9
case "$acceleration" in kvm|tcg) ;; *) exit 64 ;; esac
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
/bin/sh /tmp/check-vm-root-capacity.sh 6979321856 1073741824
storage_source=$(findmnt -n -o SOURCE --mountpoint /mnt 2>/dev/null || true)
case "$storage_source" in
    /dev/*) storage_source=$(readlink -f -- "$storage_source" || true) ;;
esac
storage_fstype=$(findmnt -n -o FSTYPE --mountpoint /mnt 2>/dev/null || true)
storage_device_fstype=$(blkid -s TYPE -o value /dev/vdb 2>/dev/null || true)
storage_label=$(blkid -s LABEL -o value /dev/vdb 2>/dev/null || true)
printf 'storage_source=%s\nstorage_filesystem=%s\nstorage_device_filesystem=%s\nstorage_label=%s\n' \
    "$storage_source" "$storage_fstype" "$storage_device_fstype" "$storage_label"
if [ "$storage_source" != /dev/vdb ] \
    || [ "$storage_fstype" != ext4 ] \
    || [ "$storage_device_fstype" != ext4 ] \
    || [ "$storage_label" != vaultlink-data ]; then
    {
        echo "expected /dev/vdb mounted as ext4 on /mnt with label vaultlink-data"
        lsblk -o NAME,PATH,TYPE,FSTYPE,LABEL,MOUNTPOINTS || true
        findmnt --raw -o SOURCE,TARGET,FSTYPE,OPTIONS || true
        blkid || true
        sed -n '1,200p' /etc/fstab || true
        cloud-init status --long || true
    } >&2
    exit 70
fi
if [ "$distribution" = arch ]; then
    [ -L /etc/systemd/system/systemd-time-wait-sync.service ]
    [ "$(readlink /etc/systemd/system/systemd-time-wait-sync.service)" = /dev/null ]
    systemctl is-enabled systemd-time-wait-sync.service | grep -F -x -q masked
    [ "$(systemctl show -p LoadState --value systemd-time-wait-sync.service)" = masked ]
    [ "$(systemctl show -p ActiveState --value systemd-time-wait-sync.service)" = inactive ]
    if systemctl --quiet is-failed systemd-time-wait-sync.service; then
        exit 70
    fi
    if systemctl is-enabled systemd-timesyncd.service 2>/dev/null \
        | grep -F -x -q masked; then
        exit 70
    fi
fi

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

sh /tmp/distro-vm-runtime-smoke.sh \
    "$target_id" /tmp/vaultlink-vm-evidence "$acceleration"

# Exercise the real systemd sandbox and first prove that its bounded ambient
# transaction capabilities do not survive the runuser boundary. The candidate
# still runs as the exact service identity with no permitted, effective, or
# ambient capabilities and with no-new-privileges set.
unit_probe_dir=/var/lib/vaultlink-backups/unit-package-probe
unit_dropin=/etc/systemd/system/vaultlink-update.service.d/90-package-gate.conf
unit_credential_probe=/usr/local/sbin/vaultlink-update-credential-probe
unit_credential_state=/var/lib/vaultlink/update-unit-credential.env
unit_package_probe=/usr/local/sbin/vaultlink-update-package-probe
unit_package_probe_state=/var/lib/vaultlink/update-unit-package-manager-launcher.env
install -d -o root -g root -m 0700 "$unit_probe_dir"
cat >"$unit_credential_probe" <<'EOF'
#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG
umask 077

output=/var/lib/vaultlink/update-unit-credential.env
[ ! -e "$output" ] && [ ! -L "$output" ] || exit 77
service_uid=$(id -u vaultlink)
service_gid=$(id -g vaultlink)
[ "$(id -u)" = "$service_uid" ]
[ "$(id -g)" = "$service_gid" ]
[ "$(id -G)" = "$service_gid" ]
status_field() {
    field=$1
    values=$(sed -n "s/^${field}:[[:space:]]*//p" /proc/self/status)
    [ "$(printf '%s\n' "$values" | grep -c .)" -eq 1 ] || exit 77
    printf '%s\n' "$values" | awk '{$1=$1; print}'
}
status_uid=$(status_field Uid)
status_gid=$(status_field Gid)
cap_inheritable=$(status_field CapInh)
cap_permitted=$(status_field CapPrm)
cap_effective=$(status_field CapEff)
cap_bounding=$(status_field CapBnd)
cap_ambient=$(status_field CapAmb)
no_new_privileges=$(status_field NoNewPrivs)
[ "$status_uid" = "$service_uid $service_uid $service_uid $service_uid" ]
[ "$status_gid" = "$service_gid $service_gid $service_gid $service_gid" ]
[ "$cap_inheritable" = 00000000000000cf ]
[ "$cap_permitted" = 0000000000000000 ]
[ "$cap_effective" = 0000000000000000 ]
[ "$cap_bounding" = 00000000000000cf ]
[ "$cap_ambient" = 0000000000000000 ]
[ "$no_new_privileges" = 1 ]
printf 'uid=%s\ngid=%s\ncap_inheritable=%s\ncap_permitted=%s\ncap_effective=%s\ncap_bounding=%s\ncap_ambient=%s\nno_new_privileges=%s\n' \
    "$service_uid" "$service_gid" "$cap_inheritable" "$cap_permitted" \
    "$cap_effective" "$cap_bounding" "$cap_ambient" \
    "$no_new_privileges" >"$output"
EOF
chown root:root "$unit_credential_probe"
chmod 0755 "$unit_credential_probe"
install -d -o root -g root -m 0755 "$(dirname "$unit_dropin")"
cat >"$unit_dropin" <<EOF
[Service]
ExecStart=
ExecStart=/usr/sbin/runuser -u vaultlink -- $unit_credential_probe
EOF
chown root:root "$unit_dropin"
chmod 0644 "$unit_dropin"
systemctl daemon-reload
systemctl show vaultlink-update.service --no-pager \
    -p NoNewPrivileges -p CapabilityBoundingSet -p AmbientCapabilities \
    -p SecureBits \
    > /tmp/vaultlink-vm-evidence/update-unit-sandbox.env
grep -F -x -q 'NoNewPrivileges=yes' \
    /tmp/vaultlink-vm-evidence/update-unit-sandbox.env
grep -F -x -q \
    'CapabilityBoundingSet=cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_setgid cap_setuid' \
    /tmp/vaultlink-vm-evidence/update-unit-sandbox.env
grep -F -x -q \
    'AmbientCapabilities=cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_setgid cap_setuid' \
    /tmp/vaultlink-vm-evidence/update-unit-sandbox.env
grep -F -x -q 'SecureBits=0' \
    /tmp/vaultlink-vm-evidence/update-unit-sandbox.env
if ! systemctl start vaultlink-update.service; then
    journalctl -u vaultlink-update.service --no-pager \
        > /tmp/vaultlink-vm-evidence/update-unit-credential.journal
    exit 77
fi
install -o root -g root -m 0644 "$unit_credential_state" \
    /tmp/vaultlink-vm-evidence/update-unit-credential.env
grep -F -x -q 'cap_permitted=0000000000000000' \
    /tmp/vaultlink-vm-evidence/update-unit-credential.env
grep -F -x -q 'cap_effective=0000000000000000' \
    /tmp/vaultlink-vm-evidence/update-unit-credential.env
grep -F -x -q 'cap_ambient=0000000000000000' \
    /tmp/vaultlink-vm-evidence/update-unit-credential.env
grep -F -x -q 'no_new_privileges=1' \
    /tmp/vaultlink-vm-evidence/update-unit-credential.env
rm -f "$unit_credential_state" "$unit_credential_probe"

# Replace only ExecStart again and perform a same-package reinstall from a
# protected local copy. Start through a root-owned generic launcher just as the
# real unit starts vaultlink-update before it spawns the package manager. A
# direct ExecStart=/usr/bin/rpm would instead test init_t's RPM transition under
# no-new-privileges, which is not the production execution path on Fedora.
# All shipped sandboxing remains in force and the native package manager plus
# its distro scriptlets must complete without network.
unit_probe_package="$unit_probe_dir/$(basename "$package")"
install -o root -g root -m 0600 "$package" "$unit_probe_package"
case "$package_format" in
    deb) unit_probe_command="/usr/bin/dpkg --install $unit_probe_package" ;;
    rpm) unit_probe_command="/usr/bin/rpm --nocontexts --upgrade --replacepkgs $unit_probe_package" ;;
    pkg.tar.zst) unit_probe_command="/usr/bin/pacman -U --noconfirm $unit_probe_package" ;;
    *) exit 65 ;;
esac
cat >"$unit_package_probe" <<EOF
#!/bin/sh
set -eu
launcher_context=unavailable
if [ -r /proc/self/attr/current ]; then
    launcher_context=\$(tr -d '\\000' </proc/self/attr/current)
fi
launcher_no_new_privileges=\$(awk '/^NoNewPrivs:/ { print \$2 }' /proc/self/status)
[ "\$launcher_no_new_privileges" = 1 ]
printf 'selinux_context=%s\nno_new_privileges=%s\n' \
    "\$launcher_context" "\$launcher_no_new_privileges" \
    >"$unit_package_probe_state"
exec $unit_probe_command
EOF
chown root:root "$unit_package_probe"
chmod 0755 "$unit_package_probe"
cat >"$unit_dropin" <<EOF
[Service]
ExecStart=
ExecStart=$unit_package_probe
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
install -o root -g root -m 0644 "$unit_package_probe_state" \
    /tmp/vaultlink-vm-evidence/update-unit-package-manager-launcher.env
grep -F -x -q 'no_new_privileges=1' \
    /tmp/vaultlink-vm-evidence/update-unit-package-manager-launcher.env
case "$target_id" in
    fedora44-*)
        grep -E -x -q \
            'selinux_context=[^:]+:[^:]+:unconfined_service_t:.*' \
            /tmp/vaultlink-vm-evidence/update-unit-package-manager-launcher.env
        ;;
esac
journalctl -u vaultlink-update.service --no-pager \
    > /tmp/vaultlink-vm-evidence/update-unit-package-manager.journal
rm -f "$unit_dropin" "$unit_package_probe" "$unit_package_probe_state"
rm -rf "$unit_probe_dir"
systemctl daemon-reload

install -d -m 0750 /etc/vaultlink /var/lib/vaultlink
[ "$(stat -c '%u:%g:%a' /var/lib/vaultlink-backups)" = 0:0:700 ]
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
