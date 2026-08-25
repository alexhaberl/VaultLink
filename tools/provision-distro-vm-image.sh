#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG

[ "$#" -eq 4 ] || {
    echo "usage: $0 TARGET_ID SOURCE_QCOW2 OUTPUT_QCOW2 ARCH_SNAPSHOT_DATE" >&2
    exit 64
}

target_id=$1
source_image=$2
output_image=$3
arch_snapshot_date=$4
case "$target_id" in *[!a-z0-9-]*|'') exit 64 ;; esac
[ -f "$source_image" ] && [ ! -L "$source_image" ] \
    && [ ! -e "$output_image" ] && [ ! -L "$output_image" ] || exit 66
source_image=$(cd -- "$(dirname -- "$source_image")" && pwd)/$(basename -- "$source_image")
output_image=$(cd -- "$(dirname -- "$output_image")" && pwd)/$(basename -- "$output_image")

distribution=$(python3 tools/package-targets.py get "$target_id" distribution --allow-unprovisioned)
distribution_version=$(python3 tools/package-targets.py get "$target_id" version --allow-unprovisioned)
architecture=$(python3 tools/package-targets.py get "$target_id" architecture --allow-unprovisioned)
work=$(mktemp -d)
qemu_pid=
cleanup() {
    if [ -n "$qemu_pid" ]; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

case "$distribution" in
    debian | ubuntu)
        [ "$arch_snapshot_date" = UNPROVISIONED ] || exit 64
        cat >"$work/install-packages.sh" <<EOF
#!/bin/sh
set -eu
expected_id='$distribution'
expected_version='$distribution_version'
. /etc/os-release
[ "\${ID:-}" = "\$expected_id" ] \
    && [ "\${VERSION_ID:-}" = "\$expected_version" ] || {
    echo "guest OS identity does not match \$expected_id \$expected_version" >&2
    exit 77
}
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    bash ca-certificates coreutils cpio curl diffutils dpkg findutils grep gzip \
    mawk minisign openssh-server python3 rpm2cpio sed sqlite3 sudo systemd \
    tar util-linux zstd
EOF
        ;;
    fedora)
        [ "$arch_snapshot_date" = UNPROVISIONED ] || exit 64
        cat >"$work/install-packages.sh" <<EOF
#!/bin/sh
set -eu
expected_id='$distribution'
expected_version='$distribution_version'
. /etc/os-release
[ "\${ID:-}" = "\$expected_id" ] \
    && [ "\${VERSION_ID:-}" = "\$expected_version" ] || {
    echo "guest OS identity does not match \$expected_id \$expected_version" >&2
    exit 77
}
dnf --assumeyes --setopt=install_weak_deps=False install \
    audit bash ca-certificates coreutils cpio curl diffutils findutils gawk \
    glibc grep gzip libgcc minisign openssh-server policycoreutils python3 \
    rpm2cpio sed sqlite sudo systemd tar util-linux zstd
systemctl enable auditd.service
EOF
        ;;
    arch)
        case "$arch_snapshot_date" in 20??-??-??) ;; *) exit 64 ;; esac
        python3 - "$arch_snapshot_date" <<'PY'
import datetime
import sys
value = sys.argv[1]
if datetime.date.fromisoformat(value).isoformat() != value:
    raise SystemExit(64)
PY
        arch_snapshot_path=$(printf '%s\n' "$arch_snapshot_date" | tr '-' '/')
        cat >"$work/install-packages.sh" <<EOF
#!/bin/sh
set -eu
. /etc/os-release
[ "\${ID:-}" = arch ] || {
    echo "guest OS identity is not Arch Linux" >&2
    exit 77
}
cat >/etc/pacman.d/mirrorlist <<'MIRROR'
Server = https://archive.archlinux.org/repos/$arch_snapshot_path/\$repo/os/\$arch
MIRROR
# A release snapshot is an exact upper and lower bound.  The second -u lets
# pacman downgrade packages from a newer upstream cloud image to that date.
pacman -Syyuu --noconfirm --needed \\
    bash ca-certificates coreutils curl diffutils findutils gawk gcc-libs \\
    glibc grep gzip libarchive minisign openssh python sed sqlite sudo \\
    systemd tar util-linux zstd
EOF
        ;;
    *) exit 65 ;;
esac
chmod 0755 "$work/install-packages.sh"
package_script_b64=$(base64 -w0 "$work/install-packages.sh")

cat >"$work/meta-data" <<EOF
instance-id: vaultlink-image-$target_id
local-hostname: vaultlink-$target_id
EOF
cat >"$work/user-data" <<EOF
#cloud-config
package_update: false
package_upgrade: false
write_files:
  - path: /usr/local/share/vaultlink-vm-target
    owner: root:root
    permissions: '0644'
    content: '$target_id'
  - path: /usr/local/sbin/vaultlink-provision-packages
    owner: root:root
    permissions: '0700'
    encoding: b64
    content: '$package_script_b64'
runcmd:
  - [ sh, -c, "set -eu; /usr/local/sbin/vaultlink-provision-packages; if command -v dpkg-query >/dev/null; then dpkg-query -W -f='\${binary:Package}=\${Version}\\n' | LC_ALL=C sort >/usr/local/share/vaultlink-vm-packages.lock; elif command -v rpm >/dev/null; then rpm -qa --qf '%{NAME}=%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n' | LC_ALL=C sort >/usr/local/share/vaultlink-vm-packages.lock; else pacman -Q | LC_ALL=C sort >/usr/local/share/vaultlink-vm-packages.lock; fi; chmod 0644 /usr/local/share/vaultlink-vm-packages.lock; hash=\$(sha256sum /usr/local/share/vaultlink-vm-packages.lock | awk '{print \$1}'); lock=\$(base64 -w0 /usr/local/share/vaultlink-vm-packages.lock); echo \$hash >/usr/local/share/vaultlink-vm-packages.sha256; echo VAULTLINK_VM_PACKAGES_SHA256_$target_id=\$hash | tee /dev/console; echo VAULTLINK_VM_PACKAGES_LOCK_$target_id=\$lock | tee /dev/console; echo VAULTLINK_VM_PROVISIONED_$target_id | tee /dev/console" ]
  - [ sync ]
power_state:
  delay: now
  mode: poweroff
  message: VaultLink VM provisioning complete
  timeout: 120
  condition: true
EOF

cloud-localds "$work/seed.img" "$work/user-data" "$work/meta-data"
qemu-img info --output=json "$source_image" | grep -F -q '"format": "qcow2"'
qemu-img check "$source_image"
qemu-img create -q -f qcow2 -F qcow2 -b "$source_image" "$work/overlay.qcow2"

case "$architecture" in
    amd64)
        qemu='qemu-system-x86_64'
        machine_args='-machine q35'
        firmware_args=
        ;;
    arm64)
        qemu='qemu-system-aarch64'
        machine_args='-machine virt'
        firmware=/usr/share/AAVMF/AAVMF_CODE.fd
        [ -r "$firmware" ] || firmware=/usr/share/qemu-efi-aarch64/QEMU_EFI.fd
        [ -r "$firmware" ] || {
            echo "AArch64 UEFI firmware is missing" >&2
            exit 69
        }
        firmware_args="-bios $firmware"
        ;;
    *) exit 65 ;;
esac

acceleration=tcg
acceleration_args='-accel tcg,thread=multi -cpu max'
if [ "$architecture" = amd64 ] \
    && [ -c /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ] \
    && "$qemu" -accel help 2>/dev/null | grep -F -x -q 'kvm'; then
    acceleration=kvm
    acceleration_args='-accel kvm -cpu host'
fi

# Word splitting is intentional only for the fixed QEMU arguments.
# shellcheck disable=SC2086
$qemu $machine_args $firmware_args $acceleration_args \
    -smp 4 -m 6144 -nographic -no-reboot \
    -drive "if=virtio,file=$work/overlay.qcow2,format=qcow2,cache=unsafe" \
    -drive "if=virtio,file=$work/seed.img,format=raw,readonly=on" \
    -nic user,model=virtio-net-pci \
    >"$work/serial.log" 2>&1 &
qemu_pid=$!

deadline=$(( $(date +%s) + 2700 ))
while kill -0 "$qemu_pid" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
        tail -n 200 "$work/serial.log" >&2 || true
        echo "VM provisioning timed out" >&2
        exit 70
    fi
    sleep 5
done
set +e
wait "$qemu_pid"
qemu_status=$?
set -e
qemu_pid=
[ "$qemu_status" -eq 0 ] || {
    tail -n 200 "$work/serial.log" >&2 || true
    echo "VM provisioning QEMU exited with status $qemu_status" >&2
    exit 70
}
grep -F -q "VAULTLINK_VM_PROVISIONED_$target_id" "$work/serial.log" || {
    tail -n 200 "$work/serial.log" >&2 || true
    echo "guest did not report successful provisioning" >&2
    exit 70
}
packages_sha256=$(sed -n \
    "s/^.*VAULTLINK_VM_PACKAGES_SHA256_$target_id=\([0-9a-f][0-9a-f]*\).*$/\1/p" \
    "$work/serial.log" | tail -n 1)
case "$packages_sha256" in
    [0-9a-f][0-9a-f]*) ;;
    *) echo "guest package closure hash is missing" >&2; exit 70 ;;
esac
[ "${#packages_sha256}" -eq 64 ] || exit 70
packages_lock_b64=$(sed -n \
    "s/^.*VAULTLINK_VM_PACKAGES_LOCK_$target_id=\([A-Za-z0-9+\/=][A-Za-z0-9+\/=]*\).*$/\1/p" \
    "$work/serial.log" | tail -n 1)
[ -n "$packages_lock_b64" ] || {
    echo "guest package closure evidence is missing" >&2
    exit 70
}
printf '%s' "$packages_lock_b64" | base64 -d >"$output_image.packages.lock"
LC_ALL=C sort -c "$output_image.packages.lock"
[ "$(sha256sum "$output_image.packages.lock" | awk '{print $1}')" = "$packages_sha256" ] \
    || { echo "guest package closure evidence hash mismatch" >&2; exit 70; }

qemu-img convert -q -O qcow2 -o compat=1.1,lazy_refcounts=off \
    "$work/overlay.qcow2" "$output_image"
qemu-img check "$output_image"

# Cold-boot the converted image without a NIC. This verifies that the image
# itself (not just the provisioning overlay/session) has the exact target OS
# identity, reviewed marker, and complete package closure.
case "$distribution" in
    debian | ubuntu | fedora)
        cat >"$work/verify-os.sh" <<EOF
#!/bin/sh
set -eu
. /etc/os-release
[ "\${ID:-}" = '$distribution' ]
[ "\${VERSION_ID:-}" = '$distribution_version' ]
EOF
        ;;
    arch)
        cat >"$work/verify-os.sh" <<'EOF'
#!/bin/sh
set -eu
. /etc/os-release
[ "${ID:-}" = arch ]
EOF
        ;;
    *) exit 65 ;;
esac
chmod 0700 "$work/verify-os.sh"
verify_os_b64=$(base64 -w0 "$work/verify-os.sh")
cat >"$work/verify-meta-data" <<EOF
instance-id: vaultlink-image-verify-$target_id
local-hostname: vaultlink-verify-$target_id
EOF
cat >"$work/verify-user-data" <<EOF
#cloud-config
network:
  config: disabled
write_files:
  - path: /usr/local/sbin/vaultlink-verify-os
    owner: root:root
    permissions: '0700'
    encoding: b64
    content: '$verify_os_b64'
runcmd:
  - [ sh, -c, "set -eu; /usr/local/sbin/vaultlink-verify-os; test \"\$(cat /usr/local/share/vaultlink-vm-target)\" = \"$target_id\"; test \"\$(sha256sum /usr/local/share/vaultlink-vm-packages.lock | awk '{print \$1}')\" = \"$packages_sha256\"; LC_ALL=C sort -c /usr/local/share/vaultlink-vm-packages.lock; if command -v dpkg-query >/dev/null; then dpkg-query -W -f='\${binary:Package}=\${Version}\\n' | LC_ALL=C sort >/run/vaultlink-vm-packages.live; elif command -v rpm >/dev/null; then rpm -qa --qf '%{NAME}=%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n' | LC_ALL=C sort >/run/vaultlink-vm-packages.live; else pacman -Q | LC_ALL=C sort >/run/vaultlink-vm-packages.live; fi; cmp /usr/local/share/vaultlink-vm-packages.lock /run/vaultlink-vm-packages.live; rm -f /run/vaultlink-vm-packages.live; echo VAULTLINK_VM_COLD_BOOT_VERIFIED_$target_id | tee /dev/console" ]
  - [ sync ]
power_state:
  delay: now
  mode: poweroff
  message: VaultLink VM verification complete
  timeout: 120
  condition: true
EOF
cloud-localds "$work/verify-seed.img" \
    "$work/verify-user-data" "$work/verify-meta-data"
qemu-img create -q -f qcow2 -F qcow2 -b "$output_image" \
    "$work/verify-overlay.qcow2"
# shellcheck disable=SC2086
$qemu $machine_args $firmware_args $acceleration_args \
    -smp 4 -m 6144 -nographic -no-reboot \
    -drive "if=virtio,file=$work/verify-overlay.qcow2,format=qcow2,cache=unsafe" \
    -drive "if=virtio,file=$work/verify-seed.img,format=raw,readonly=on" \
    -nic none >"$work/verify-serial.log" 2>&1 &
qemu_pid=$!
deadline=$(( $(date +%s) + 1200 ))
while kill -0 "$qemu_pid" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
        tail -n 200 "$work/verify-serial.log" >&2 || true
        echo "cold-boot VM verification timed out" >&2
        exit 70
    fi
    sleep 5
done
set +e
wait "$qemu_pid"
qemu_status=$?
set -e
qemu_pid=
[ "$qemu_status" -eq 0 ] || {
    tail -n 200 "$work/verify-serial.log" >&2 || true
    echo "cold-boot QEMU exited with status $qemu_status" >&2
    exit 70
}
grep -F -q "VAULTLINK_VM_COLD_BOOT_VERIFIED_$target_id" \
    "$work/verify-serial.log" || {
        tail -n 200 "$work/verify-serial.log" >&2 || true
        echo "converted guest failed cold-boot verification" >&2
        exit 70
    }

chmod 0644 "$output_image"
printf '%s\n' "$packages_sha256" >"$output_image.packages.sha256"
printf '%s\n' "$acceleration" >"$output_image.acceleration"
printf '%s\n' true >"$output_image.cold-boot-verified"
chmod 0644 "$output_image.packages.lock" "$output_image.packages.sha256" \
    "$output_image.acceleration" "$output_image.cold-boot-verified"
echo "provisioned distro VM $target_id"
