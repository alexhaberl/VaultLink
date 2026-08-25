#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG

[ "$#" -eq 4 ] || {
    echo "usage: $0 TARGET_ID PACKAGE QCOW2 EVIDENCE_DIRECTORY" >&2
    exit 64
}
target_id=$1
package=$2
source_image=$3
evidence=$4
[ -f "$package" ] && [ ! -L "$package" ] \
    && [ -f "$source_image" ] && [ ! -L "$source_image" ] \
    && [ ! -e "$evidence" ] && [ ! -L "$evidence" ] || exit 66
package=$(cd -- "$(dirname -- "$package")" && pwd)/$(basename -- "$package")
source_image=$(cd -- "$(dirname -- "$source_image")" && pwd)/$(basename -- "$source_image")
evidence=$(cd -- "$(dirname -- "$evidence")" && pwd)/$(basename -- "$evidence")

field() {
    python3 tools/package-targets.py get "$target_id" "$1"
}
distribution=$(field distribution)
distribution_version=$(field version)
architecture=$(field architecture)
package_format=$(field package_format)
package_arch=$(field package_arch)
vm_packages_sha256=$(field vm_packages_sha256)
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
expected_asset=$(python3 tools/package-targets.py asset "$target_id" "$version")
[ "$(basename "$package")" = "$expected_asset" ] || exit 77
ssh_timeout=1200
tcg_timeout_override=false
tcg_cleanup_command=:
if [ "$target_id" = fedora44-arm64 ]; then
    [ "$architecture" = arm64 ] || exit 77
    ssh_timeout=3600
    tcg_timeout_override=true
    tcg_cleanup_command=/usr/local/bin/vaultlink-clear-tcg-device-timeout
fi

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
install -d -m 0755 "$evidence"

ssh-keygen -q -t ed25519 -N '' -f "$work/client-key"
ssh-keygen -q -t ed25519 -N '' -f "$work/host-key"
client_public=$(cat "$work/client-key.pub")
host_private=$(base64 -w0 "$work/host-key")
host_public=$(base64 -w0 "$work/host-key.pub")
cat >"$work/meta-data" <<EOF
instance-id: vaultlink-test-$target_id-$version
local-hostname: vaultlink-$target_id
EOF
cat >"$work/user-data" <<EOF
#cloud-config
users:
  - name: vaultlink-ci
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/sh
    ssh_authorized_keys:
      - $client_public
ssh_pwauth: false
disable_root: true
fs_setup:
  - label: vaultlink-storage
    filesystem: ext4
    device: /dev/vdb
    overwrite: false
mounts:
  - [ 'LABEL=vaultlink-storage', '/mnt', 'ext4', 'defaults,nofail', '0', '2' ]
write_files:
  - path: /etc/ssh/ssh_host_ed25519_key
    owner: root:root
    permissions: '0600'
    encoding: b64
    content: $host_private
  - path: /etc/ssh/ssh_host_ed25519_key.pub
    owner: root:root
    permissions: '0644'
    encoding: b64
    content: $host_public
runcmd:
  - [ sh, -c, "set -eu; $tcg_cleanup_command" ]
  - [ sh, -c, "systemctl restart sshd.service || systemctl restart ssh.service" ]
  - [ sh, -c, "echo VAULTLINK_VM_READY | tee /dev/console" ]
EOF
cloud-localds "$work/seed.img" "$work/user-data" "$work/meta-data"
qemu-img check "$source_image"
qemu-img info --output=json "$source_image" | python3 -c \
    'import json,sys; d=json.load(sys.stdin); s=d.get("virtual-size"); sys.exit(0) if d.get("format") == "qcow2" and type(s) is int and s == 8589934592 else sys.exit(70)'
qemu-img create -q -f qcow2 -F qcow2 -b "$source_image" "$work/overlay.qcow2"
qemu-img create -q -f raw "$work/storage.raw" 20G

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
        [ -r "$firmware" ] || exit 69
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
if [ "$tcg_timeout_override" = true ]; then
    [ "$acceleration" = tcg ] || exit 77
    sh tools/manage-tcg-device-timeout.sh inject "$work/overlay.qcow2"
fi

# KVM is an optional acceleration only. restrict=on blocks guest egress while
# retaining the explicit host-to-guest SSH forwarding channel. Network boot is
# unsupported, so the VirtIO NIC must not depend on a packaged PXE option ROM.
# shellcheck disable=SC2086
$qemu $machine_args $firmware_args $acceleration_args \
    -smp 4 -m 6144 -nographic -no-reboot \
    -drive "if=virtio,file=$work/overlay.qcow2,format=qcow2,cache=unsafe" \
    -drive "if=virtio,file=$work/storage.raw,format=raw,cache=unsafe" \
    -drive "if=virtio,file=$work/seed.img,format=raw,readonly=on" \
    -netdev user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:2222-:22 \
    -device virtio-net-pci,netdev=net0,romfile= \
    >"$evidence/serial.log" 2>&1 &
qemu_pid=$!

printf '[127.0.0.1]:2222 %s\n' "$(cat "$work/host-key.pub")" >"$work/known_hosts"
run_ssh() {
    ssh -i "$work/client-key" \
        -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
        -o "UserKnownHostsFile=$work/known_hosts" -o ConnectTimeout=5 \
        -p 2222 "$@"
}
run_scp() {
    scp -i "$work/client-key" \
        -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
        -o "UserKnownHostsFile=$work/known_hosts" -o ConnectTimeout=5 \
        -P 2222 "$@"
}
deadline=$(( $(date +%s) + ssh_timeout ))
while :; do
    if run_ssh vaultlink-ci@127.0.0.1 true 2>/dev/null \
        && grep -F -q VAULTLINK_VM_READY "$evidence/serial.log"; then
        break
    fi
    kill -0 "$qemu_pid" 2>/dev/null || {
        tail -n 200 "$evidence/serial.log" >&2 || true
        exit 70
    }
    [ "$(date +%s)" -lt "$deadline" ] || exit 70
    sleep 5
done
if [ "$target_id" = archlinux-amd64 ]; then
    host_epoch=$(date +%s)
    guest_epoch=$(run_ssh vaultlink-ci@127.0.0.1 date +%s)
    case "$guest_epoch" in ''|*[!0-9]*) exit 70 ;; esac
    clock_delta=$(( host_epoch - guest_epoch ))
    [ "$clock_delta" -ge 0 ] || clock_delta=$(( -clock_delta ))
    [ "$clock_delta" -le 300 ] || exit 70
    printf 'clock_source=qemu-rtc\nhost_guest_delta_seconds=%s\n' \
        "$clock_delta" >"$evidence/clock.env"
fi

run_scp \
    "$package" \
    tools/distro-vm-guest-smoke.sh \
    tools/distro-vm-runtime-smoke.sh \
    tools/check-vm-root-capacity.sh \
    deploy/docker/api-smoke.sh \
    tools/load-test.sh \
    vaultlink-ci@127.0.0.1:/tmp/
remote_package=/tmp/$(basename "$package")
# All expanded arguments are manifest-constrained and intentionally become
# distinct remote argv entries.
# shellcheck disable=SC2029
run_ssh vaultlink-ci@127.0.0.1 \
    sudo /bin/sh /tmp/distro-vm-guest-smoke.sh \
    "$target_id" "$distribution" "$distribution_version" "$package_format" \
    "$package_arch" "$version" "$remote_package" "$vm_packages_sha256" \
    >"$evidence/package.env"
run_scp -r vaultlink-ci@127.0.0.1:/tmp/vaultlink-vm-evidence \
    "$evidence/runtime"
run_ssh vaultlink-ci@127.0.0.1 \
    'uname -a; cat /etc/os-release; systemctl show vaultlink.service --no-pager || true; journalctl -u vaultlink.service --no-pager || true' \
    >"$evidence/guest-system.txt"
if ! run_ssh vaultlink-ci@127.0.0.1 \
    'sudo find /var/lib/vaultlink -type f -name "*.sqlite*" -exec sqlite3 {} "PRAGMA integrity_check;" \;' \
    >"$evidence/sqlite-integrity.txt" 2>"$evidence/sqlite-integrity.stderr"; then
    cat "$evidence/sqlite-integrity.stderr" >&2
    exit 1
fi
[ ! -s "$evidence/sqlite-integrity.stderr" ]
awk 'NF != 1 || $0 != "ok" { exit 1 } END { if (NR < 1) exit 1 }' \
    "$evidence/sqlite-integrity.txt"
[ "$(cat "$evidence/runtime/post-remove-sqlite-integrity.txt")" = ok ]
[ "$(cat "$evidence/runtime/post-reinstall-sqlite-integrity.txt")" = ok ]
printf 'network=restricted-user-mode\nacceleration=%s\ntarget=%s\n' "$acceleration" "$target_id" \
    >"$evidence/harness.env"
sha256sum "$package" "$source_image" >"$evidence/host-inputs.sha256"
grep -F -q "target=$target_id" "$evidence/package.env"
candidate_hash=$(sed -n 's/^binary_sha256=//p' "$evidence/package.env")
active_hash=$(sed -n 's/^active_binary_sha256=//p' "$evidence/package.env")
[ -n "$candidate_hash" ] && [ "$candidate_hash" = "$active_hash" ]
grep -F -x -q 'service_enabled=disabled' "$evidence/package.env"
grep -F -x -q 'update_timer_enabled=disabled' "$evidence/package.env"
grep -F -x -q 'service_active=inactive' "$evidence/package.env"
grep -F -q 'network=restricted-user-mode' "$evidence/harness.env"
grep -F -x -q 'readiness=ok' "$evidence/runtime/runtime.env"
grep -F -x -q 'upgrade=ok' "$evidence/runtime/runtime.env"
grep -F -x -q 'migration=ok' "$evidence/runtime/runtime.env"
grep -F -x -q 'rollback=ok' "$evidence/runtime/runtime.env"
grep -F -x -q 'metadata_clients=100' "$evidence/runtime/load/result.env"
grep -F -x -q 'upload_integrity=server_readback' "$evidence/runtime/load/result.env"

run_ssh vaultlink-ci@127.0.0.1 sudo poweroff || true
set +e
wait "$qemu_pid"
qemu_status=$?
set -e
qemu_pid=
[ "$qemu_status" -eq 0 ] || {
    tail -n 2000 "$evidence/serial.log" >&2 || true
    echo "full-system QEMU exited with status $qemu_status" >&2
    exit 70
}
if [ "$tcg_timeout_override" = true ]; then
    sh tools/manage-tcg-device-timeout.sh assert-clean "$work/overlay.qcow2"
fi
echo "full-system distro VM test $target_id: OK"
