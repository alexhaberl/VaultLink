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
acceleration_policy=${ACCELERATION_POLICY:-force-tcg}
case "$acceleration_policy" in force-tcg|auto) ;; *) exit 64 ;; esac
[ -f "$package" ] && [ ! -L "$package" ] \
    && [ -f "$source_image" ] && [ ! -L "$source_image" ] \
    && [ ! -e "$evidence" ] && [ ! -L "$evidence" ] || exit 66
package=$(cd -- "$(dirname -- "$package")" && pwd)/$(basename -- "$package")
source_image=$(cd -- "$(dirname -- "$source_image")" && pwd)/$(basename -- "$source_image")
evidence=$(cd -- "$(dirname -- "$evidence")" && pwd)/$(basename -- "$evidence")

field() {
    python3 tools/package-targets.py get "$target_id" "$1"
}
evidence_value() {
    evidence_file=$1
    evidence_key=$2
    [ -f "$evidence_file" ] && [ ! -L "$evidence_file" ] || exit 77
    awk -F= -v key="$evidence_key" '
        $1 == key {
            matches++
            value = substr($0, length(key) + 2)
        }
        END {
            if (matches != 1) exit 77
            print value
        }
    ' "$evidence_file"
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
host_private=$(sed 's/^/    /' "$work/host-key")
host_public=$(sed 's/^/    /' "$work/host-key.pub")
cat >"$work/guest-bootstrap.sh" <<'EOF'
#!/bin/sh
set -eu

mount_failure() {
    reason=$1
    {
        printf 'VAULTLINK_VM_MOUNT_FAILED reason=%s\n' "$reason"
        printf '%s\n' '--- lsblk ---'
        lsblk -o NAME,PATH,TYPE,FSTYPE,LABEL,MOUNTPOINTS || true
        printf '%s\n' '--- findmnt ---'
        findmnt --raw -o SOURCE,TARGET,FSTYPE,OPTIONS || true
        printf '%s\n' '--- blkid ---'
        blkid || true
        printf '%s\n' '--- /etc/fstab ---'
        sed -n '1,200p' /etc/fstab || true
        printf '%s\n' '--- cloud-init ---'
        cloud-init status --long || true
    } | tee /dev/console >&2
    exit 70
}

[ "$#" -eq 1 ] || mount_failure invalid_arguments
cleanup_command=$1
case "$cleanup_command" in
    :) ;;
    /usr/local/bin/vaultlink-clear-tcg-device-timeout)
        "$cleanup_command" || mount_failure tcg_cleanup_failed
        ;;
    *) mount_failure invalid_cleanup_command ;;
esac

if ! systemctl restart sshd.service && ! systemctl restart ssh.service; then
    mount_failure ssh_restart_failed
fi
[ -b /dev/vdb ] || mount_failure device_missing
storage_source=$(findmnt -n -o SOURCE --mountpoint /mnt 2>/dev/null) \
    || mount_failure not_mounted
storage_source=$(readlink -f -- "$storage_source") \
    || mount_failure invalid_source
storage_fstype=$(findmnt -n -o FSTYPE --mountpoint /mnt 2>/dev/null) \
    || mount_failure missing_mount_fstype
storage_device_fstype=$(blkid -s TYPE -o value /dev/vdb 2>/dev/null || true)
storage_label=$(blkid -s LABEL -o value /dev/vdb 2>/dev/null || true)
[ "$storage_source" = /dev/vdb ] || mount_failure wrong_source
[ "$storage_fstype" = ext4 ] || mount_failure wrong_mount_fstype
[ "$storage_device_fstype" = ext4 ] || mount_failure wrong_device_fstype
[ "$storage_label" = vaultlink-data ] || mount_failure wrong_label

echo VAULTLINK_VM_STORAGE_READY | tee /dev/console
echo VAULTLINK_VM_READY | tee /dev/console
EOF
guest_bootstrap=$(sed 's/^/      /' "$work/guest-bootstrap.sh")
cat >"$work/meta-data" <<EOF
instance-id: vaultlink-test-$target_id-$version
local-hostname: vaultlink-$target_id
EOF
cat >"$work/user-data" <<EOF
#cloud-config
ssh_deletekeys: true
ssh_keys:
  ed25519_private: |
$host_private
  ed25519_public: |
$host_public
users:
  - name: vaultlink-ci
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/sh
    ssh_authorized_keys:
      - $client_public
ssh_pwauth: false
disable_root: true
write_files:
  - path: /usr/local/sbin/vaultlink-vm-bootstrap
    owner: root:root
    permissions: '0700'
    content: |
$guest_bootstrap
fs_setup:
  - label: vaultlink-data
    filesystem: ext4
    device: /dev/vdb
    overwrite: false
mounts:
  - [ 'LABEL=vaultlink-data', '/mnt', 'ext4', 'defaults,nofail', '0', '2' ]
runcmd:
  - [ /usr/local/sbin/vaultlink-vm-bootstrap, '$tcg_cleanup_command' ]
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

acceleration=$(ACCELERATION_POLICY="$acceleration_policy" \
    sh tools/select-qemu-acceleration.sh \
    "$architecture" "$qemu" "$evidence/acceleration-selection.env")
case "$acceleration" in
    tcg) acceleration_args='-accel tcg,thread=multi -cpu max' ;;
    kvm) acceleration_args='-accel kvm -cpu host' ;;
    *) exit 77 ;;
esac
[ "$acceleration_policy" != force-tcg ] || [ "$acceleration" = tcg ]
# Persist the harness-selected acceleration before the VM starts so every
# terminal boot/runtime failure still has runner-independent context. QEMU is
# authoritative for functional behavior only; its p95 is always diagnostic.
printf '%s\n' \
    'network=restricted-user-mode' \
    "acceleration_policy=$acceleration_policy" \
    "acceleration=$acceleration" \
    "target=$target_id" \
    "architecture=$architecture" \
    'metadata_p95_policy=diagnostic' \
    'metadata_p95_limit_seconds=2.000' \
    'metadata_p95_enforced=false' \
    >"$evidence/harness.env"
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
        -o HostKeyAlgorithms=ssh-ed25519 \
        -o "UserKnownHostsFile=$work/known_hosts" -o ConnectTimeout=5 \
        -p 2222 "$@"
}
run_scp() {
    scp -i "$work/client-key" \
        -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
        -o HostKeyAlgorithms=ssh-ed25519 \
        -o "UserKnownHostsFile=$work/known_hosts" -o ConnectTimeout=5 \
        -P 2222 "$@"
}
ssh_readiness_error="$work/ssh-readiness.stderr"
capture_readiness_diagnostic() {
    install -m 0644 "$ssh_readiness_error" \
        "$evidence/ssh-readiness-last.stderr"
    ssh_status=0
    run_ssh -vv vaultlink-ci@127.0.0.1 true \
        >/dev/null 2>"$evidence/ssh-readiness-diagnostic.stderr" \
        || ssh_status=$?
    ready_marker_present=false
    if grep -F -q VAULTLINK_VM_READY "$evidence/serial.log"; then
        ready_marker_present=true
    fi
    storage_ready_marker_present=false
    if grep -F -q VAULTLINK_VM_STORAGE_READY "$evidence/serial.log"; then
        storage_ready_marker_present=true
    fi
    qemu_alive=false
    if kill -0 "$qemu_pid" 2>/dev/null; then
        qemu_alive=true
    fi
    printf 'ssh_status=%s\nstorage_ready_marker_present=%s\nready_marker_present=%s\nqemu_alive=%s\n' \
        "$ssh_status" "$storage_ready_marker_present" \
        "$ready_marker_present" "$qemu_alive" \
        >"$evidence/ssh-readiness.env"
    if [ "$ssh_status" -eq 0 ] \
        && [ "$storage_ready_marker_present" = true ] \
        && [ "$ready_marker_present" = true ] \
        && [ "$qemu_alive" = true ]; then
        return 0
    fi
    echo "$1" >&2
    if [ -s "$evidence/ssh-readiness-last.stderr" ]; then
        echo "last SSH readiness probe:" >&2
        cat "$evidence/ssh-readiness-last.stderr" >&2 || true
    fi
    echo "SSH readiness diagnostic:" >&2
    cat "$evidence/ssh-readiness-diagnostic.stderr" >&2 || true
    echo "last 200 serial log lines:" >&2
    tail -n 200 "$evidence/serial.log" >&2 || true
    return 1
}
deadline=$(( $(date +%s) + ssh_timeout ))
while :; do
    if run_ssh vaultlink-ci@127.0.0.1 true 2>"$ssh_readiness_error" \
        && grep -F -q VAULTLINK_VM_STORAGE_READY "$evidence/serial.log" \
        && grep -F -q VAULTLINK_VM_READY "$evidence/serial.log"; then
        break
    fi
    if grep -F -q 'VAULTLINK_VM_MOUNT_FAILED ' "$evidence/serial.log"; then
        capture_readiness_diagnostic \
            "guest reported a terminal storage-mount failure" || true
        exit 70
    fi
    kill -0 "$qemu_pid" 2>/dev/null || {
        capture_readiness_diagnostic \
            "full-system QEMU exited before SSH readiness" || true
        exit 70
    }
    [ "$(date +%s)" -lt "$deadline" ] || {
        if capture_readiness_diagnostic \
            "SSH readiness timed out after ${ssh_timeout}s for $target_id"; then
            break
        fi
        exit 70
    }
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
guest_smoke_status=0
run_ssh vaultlink-ci@127.0.0.1 \
    sudo /bin/sh /tmp/distro-vm-guest-smoke.sh \
    "$target_id" "$distribution" "$distribution_version" "$package_format" \
    "$package_arch" "$version" "$remote_package" "$vm_packages_sha256" \
    "$acceleration" \
    >"$evidence/package.env" 2>"$evidence/guest-smoke.stderr" \
    || guest_smoke_status=$?
runtime_evidence_status=0
run_scp -r vaultlink-ci@127.0.0.1:/tmp/vaultlink-vm-evidence \
    "$evidence/runtime" 2>"$evidence/runtime-evidence-scp.stderr" \
    || runtime_evidence_status=$?
guest_system_status=0
run_ssh vaultlink-ci@127.0.0.1 \
    'uname -a; cat /etc/os-release; sudo systemctl show vaultlink.service --no-pager || true; sudo journalctl -u vaultlink.service --no-pager || true' \
    >"$evidence/guest-system.txt" 2>"$evidence/guest-system.stderr" \
    || guest_system_status=$?
sqlite_status=0
run_ssh vaultlink-ci@127.0.0.1 \
    'sudo sqlite3 /var/lib/vaultlink/data.sqlite "PRAGMA integrity_check;"' \
    >"$evidence/sqlite-integrity.txt" 2>"$evidence/sqlite-integrity.stderr" \
    || sqlite_status=$?
printf 'guest_smoke_status=%s\nruntime_evidence_status=%s\nguest_system_status=%s\nsqlite_status=%s\n' \
    "$guest_smoke_status" "$runtime_evidence_status" "$guest_system_status" \
    "$sqlite_status" >"$evidence/guest-commands.env"
if [ "$guest_smoke_status" -ne 0 ]; then
    cat "$evidence/guest-smoke.stderr" >&2 || true
    cat "$evidence/runtime-evidence-scp.stderr" >&2 || true
    cat "$evidence/guest-system.stderr" >&2 || true
    cat "$evidence/sqlite-integrity.stderr" >&2 || true
    tail -n 200 "$evidence/serial.log" >&2 || true
    exit "$guest_smoke_status"
fi
if [ "$runtime_evidence_status" -ne 0 ]; then
    cat "$evidence/runtime-evidence-scp.stderr" >&2 || true
    exit "$runtime_evidence_status"
fi
if [ "$guest_system_status" -ne 0 ]; then
    cat "$evidence/guest-system.stderr" >&2 || true
    exit "$guest_system_status"
fi
if [ "$sqlite_status" -ne 0 ]; then
    cat "$evidence/sqlite-integrity.stderr" >&2
    exit 1
fi
[ ! -s "$evidence/sqlite-integrity.stderr" ]
awk 'NF != 1 || $0 != "ok" { exit 1 } END { if (NR < 1) exit 1 }' \
    "$evidence/sqlite-integrity.txt"
[ "$(cat "$evidence/runtime/post-remove-sqlite-integrity.txt")" = ok ]
[ "$(cat "$evidence/runtime/post-reinstall-sqlite-integrity.txt")" = ok ]
sha256sum "$package" "$source_image" >"$evidence/host-inputs.sha256"
grep -F -q "target=$target_id" "$evidence/package.env"
candidate_hash=$(sed -n 's/^binary_sha256=//p' "$evidence/package.env")
active_hash=$(sed -n 's/^active_binary_sha256=//p' "$evidence/package.env")
[ -n "$candidate_hash" ] && [ "$candidate_hash" = "$active_hash" ]
grep -F -x -q 'service_enabled=disabled' "$evidence/package.env"
grep -F -x -q 'update_timer_enabled=disabled' "$evidence/package.env"
grep -F -x -q 'service_active=inactive' "$evidence/package.env"
grep -F -x -q 'stage=complete' "$evidence/runtime/runtime-command.env"
grep -F -x -q 'exit_status=0' "$evidence/runtime/runtime-command.env"
[ ! -e "$evidence/runtime/cookies.txt" ]
load_evidence=$evidence/runtime/load
grep -F -x -q 'stage=complete' "$load_evidence/load-command.env"
grep -F -x -q 'exit_status=0' "$load_evidence/load-command.env"
for load_profile in metadata download upload rss; do
    grep -F -x -q "${load_profile}_status=0" \
        "$load_evidence/profile-status.env"
done
grep -F -x -q 'metadata_rows=2000' "$load_evidence/profile-status.env"
grep -F -x -q 'range_rows=40' "$load_evidence/profile-status.env"
grep -F -x -q 'upload_rows=10' "$load_evidence/profile-status.env"
load_rss_rows=$(sed -n 's/^rss_rows=//p' "$load_evidence/profile-status.env")
case "$load_rss_rows" in ''|*[!0-9]*|0) exit 77 ;; esac
load_observed_p95=$(evidence_value \
    "$load_evidence/profile-status.env" metadata_observed_p95_seconds)
load_result_p95=$(evidence_value \
    "$load_evidence/result.env" metadata_p95_seconds)
[ "$load_result_p95" = "$load_observed_p95" ]
expected_p95_within_limit=$(awk -v value="$load_result_p95" 'BEGIN {
    if (value !~ /^[0-9]+([.][0-9]+)?$/ || !(value > 0)) exit 77
    print (value < 2.000) ? "true" : "false"
}')
for p95_evidence in \
    "$load_evidence/profile-status.env" \
    "$load_evidence/result.env"; do
    [ "$(evidence_value "$p95_evidence" supervision_mode)" = systemd ]
    [ "$(evidence_value "$p95_evidence" metadata_p95_policy)" = diagnostic ]
    [ "$(evidence_value "$p95_evidence" metadata_p95_limit_seconds)" = 2.000 ]
    [ "$(evidence_value "$p95_evidence" metadata_p95_enforced)" = false ]
    [ "$(evidence_value "$p95_evidence" metadata_p95_within_limit)" \
        = "$expected_p95_within_limit" ]
done
if find "$load_evidence" -type f -name '*.partial.*' -print | grep -q .; then
    exit 77
fi
grep -F -q 'network=restricted-user-mode' "$evidence/harness.env"
grep -F -x -q "acceleration_policy=$acceleration_policy" "$evidence/harness.env"
grep -F -x -q "acceleration=$acceleration" "$evidence/harness.env"
grep -F -x -q "target=$target_id" "$evidence/harness.env"
grep -F -x -q "architecture=$architecture" "$evidence/harness.env"
grep -F -x -q 'metadata_p95_policy=diagnostic' "$evidence/harness.env"
grep -F -x -q 'metadata_p95_limit_seconds=2.000' "$evidence/harness.env"
grep -F -x -q 'metadata_p95_enforced=false' "$evidence/harness.env"
grep -F -x -q 'readiness=ok' "$evidence/runtime/runtime.env"
grep -F -x -q "acceleration=$acceleration" "$evidence/runtime/runtime.env"
grep -F -x -q 'upgrade=ok' "$evidence/runtime/runtime.env"
grep -F -x -q 'migration=ok' "$evidence/runtime/runtime.env"
grep -F -x -q 'rollback=ok' "$evidence/runtime/runtime.env"
runtime_guard_wait=$evidence/runtime/runtime-guard-wait.env
[ "$(evidence_value "$runtime_guard_wait" timeout_seconds)" = 240 ]
[ "$(evidence_value "$runtime_guard_wait" settled)" = true ]
runtime_guard_elapsed=$(evidence_value "$runtime_guard_wait" elapsed_seconds)
runtime_guard_polls=$(evidence_value "$runtime_guard_wait" polls)
case "$runtime_guard_elapsed" in ''|*[!0-9]*) exit 77 ;; esac
case "$runtime_guard_polls" in ''|*[!0-9]*|0) exit 77 ;; esac
[ "$runtime_guard_elapsed" -le 240 ]
grep -E -q '^ActiveState=(failed|inactive)$' \
    "$evidence/runtime/runtime-guard-start-limit.env"
grep -E -q '^ActiveState=(failed|inactive)$' \
    "$evidence/runtime/runtime-guard-stability.env"
if [ "$package_format" = deb ]; then
    package_quiescence=$evidence/runtime/package-manager-quiescence.env
    [ "$(evidence_value "$package_quiescence" policy)" \
        = runtime-mask-and-drain ]
    [ "$(evidence_value "$package_quiescence" package_database)" \
        = available ]
    [ "$(evidence_value "$package_quiescence" lock_files_removed)" = false ]
    quiescence_wait=$(evidence_value "$package_quiescence" wait_seconds)
    case "$quiescence_wait" in ''|*[!0-9]*) exit 77 ;; esac
    [ "$quiescence_wait" -le 900 ]
fi
grep -F -x -q 'metadata_clients=100' "$evidence/runtime/load/result.env"
grep -F -x -q 'metadata_requests=2000' "$evidence/runtime/load/result.env"
grep -F -x -q 'metadata_capacity_retry_limit_per_client=3' \
    "$evidence/runtime/load/result.env"
grep -F -x -q 'metadata_capacity_retry_after_seconds=1' \
    "$evidence/runtime/load/result.env"
grep -F -x -q 'metadata_capacity_response_limit_seconds=1.100' \
    "$evidence/runtime/load/result.env"
grep -F -x -q 'range_streams=40' "$evidence/runtime/load/result.env"
grep -F -x -q 'uploads=10' "$evidence/runtime/load/result.env"
grep -F -x -q 'upload_integrity=server_readback' "$evidence/runtime/load/result.env"
metadata_capacity_retries=$(evidence_value \
    "$evidence/runtime/load/result.env" metadata_capacity_retries)
metadata_attempts=$(evidence_value \
    "$evidence/runtime/load/result.env" metadata_attempts)
case "$metadata_capacity_retries:$metadata_attempts" in
    *[!0-9:]*|:*|*::*|*:) exit 77 ;;
esac
[ "$metadata_capacity_retries" -le 300 ]
[ "$metadata_attempts" -eq $((2000 + metadata_capacity_retries)) ]
[ "$(evidence_value "$evidence/runtime/load/profile-status.env" \
    metadata_capacity_retries)" = "$metadata_capacity_retries" ]
[ "$(evidence_value "$evidence/runtime/load/profile-status.env" \
    metadata_attempts)" = "$metadata_attempts" ]
metadata_retry_file=$evidence/runtime/load/metadata-capacity-retries.csv
[ -f "$metadata_retry_file" ]
[ ! -L "$metadata_retry_file" ]
[ "$(wc -l <"$metadata_retry_file")" -eq "$metadata_capacity_retries" ]
awk -F, -v expected="$metadata_capacity_retries" '
    NF != 6 || $1 !~ /^198\.18\.1\.[0-9]+$/ \
        || $2 !~ /^([1-9]|1[0-9]|20)$/ \
        || $3 !~ /^[1-3]$/ || $4 != 503 \
        || $5 !~ /^[0-9]+([.][0-9]+)?$/ || $5 + 0 <= 0 \
        || $5 + 0 > 1.100 || $6 != 1 { exit 1 }
    {
        split($1, octets, ".")
        if (octets[4] < 1 || octets[4] > 100) exit 1
        if ($3 != ++retries[$1]) exit 1
    }
    END { if (NR != expected) exit 1 }
' "$metadata_retry_file"

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
