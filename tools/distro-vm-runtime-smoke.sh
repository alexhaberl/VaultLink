#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG
umask 077

[ "$(id -u)" -eq 0 ] || exit 77
[ "$#" -eq 3 ] || {
    echo "usage: $0 TARGET_ID EVIDENCE_DIRECTORY ACCELERATION" >&2
    exit 64
}
target_id=$1
evidence=$2
acceleration=$3
case "$target_id" in *[!a-z0-9-]*|'') exit 64 ;; esac
case "$evidence" in /*) ;; *) exit 64 ;; esac
case "$acceleration" in kvm|tcg) ;; *) exit 64 ;; esac

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

rm -rf "$evidence"
install -d -m 0755 "$evidence"
runtime_stage=initialization
runtime_config_work=
finalize_runtime_evidence() {
    runtime_status=$?
    trap - EXIT
    if [ -n "$runtime_config_work" ]; then
        rm -f "$runtime_config_work" || true
    fi
    if [ -d "$evidence" ] && [ ! -L "$evidence" ]; then
        rm -f "$evidence/cookies.txt" || true
        if [ "$runtime_status" -ne 0 ]; then
            systemctl show vaultlink.service --no-pager \
                >"$evidence/runtime-failure-systemd.env" 2>&1 || true
            journalctl -u vaultlink.service --no-pager -n 500 \
                >"$evidence/runtime-failure.journal" 2>&1 || true
        fi
        printf 'stage=%s\nexit_status=%s\n' "$runtime_stage" "$runtime_status" \
            >"$evidence/runtime-command.env" 2>/dev/null || true
        find "$evidence" -type d -exec chmod 0755 {} + 2>/dev/null || true
        find "$evidence" -type f -exec chmod 0644 {} + 2>/dev/null || true
    fi
    exit "$runtime_status"
}
trap finalize_runtime_evidence EXIT
api_work=/tmp/vaultlink-package-api-smoke
rm -rf "$api_work"
fedora_audit_marker=
fedora_audit_start_line=

runtime_stage=fedora-audit-precondition
if [ "$target_id" = fedora44-amd64 ] || [ "$target_id" = fedora44-arm64 ]; then
    [ "$(getenforce)" = Enforcing ]
    [ "$(systemctl is-active auditd.service)" = active ]
    auditctl -s >"$evidence/audit-status-before.txt"
    grep -E -q '^enabled[[:space:]]+1$' "$evidence/audit-status-before.txt"
    audit_log=/var/log/audit/audit.log
    [ -f "$audit_log" ] && [ ! -L "$audit_log" ] && [ -s "$audit_log" ]
    [ "$(stat -c %u "$audit_log")" -eq 0 ]
    fedora_audit_marker="VAULTLINK_GATE_START_${target_id}_$$"
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

runtime_stage=api-smoke
runuser -u vaultlink -- env \
    VAULTLINK_BIN=/opt/vaultlink/vaultlink \
    VAULTLINK_SMOKE_DIR="$api_work" \
    bash /tmp/api-smoke.sh >"$evidence/api-smoke.log" 2>&1

test -s "$api_work/config.toml"
test -s "$api_work/data/data.sqlite"
test -s "$api_work/data/secrets.keyring"
runtime_mount_base=/mnt/storage
runtime_root=$runtime_mount_base/shared
runtime_internal=$runtime_mount_base/.vaultlink-internal
install -d -o vaultlink -g vaultlink -m 0750 \
    "$runtime_mount_base" "$runtime_root" /var/lib/vaultlink
cp -a "$api_work/root/." "$runtime_root/"
cp -a "$api_work/data/." /var/lib/vaultlink/
install -d -o vaultlink -g vaultlink -m 0700 "$runtime_internal"
if [ -d "$api_work/root/.vaultlink-internal" ]; then
    cp -a "$api_work/root/.vaultlink-internal/." "$runtime_internal/"
fi
rm -rf "$runtime_root/.vaultlink-internal"
chown -R vaultlink:vaultlink \
    "$runtime_mount_base" /var/lib/vaultlink
chmod 0750 \
    "$runtime_mount_base" "$runtime_root" /var/lib/vaultlink
chmod 0700 "$runtime_internal"

runtime_stage=production-config
runtime_config_work=$(mktemp)
sed \
    -e 's/^mode = "development"$/mode = "reverse_proxy"/' \
    -e 's|^public_base_url = "http://localhost:18081"$|public_base_url = "https://files.example.test"|' \
    -e 's/^production_mode = false$/production_mode = true/' \
    -e 's/^secure_cookie = false$/secure_cookie = true/' \
    -e 's/^require_mount = false$/require_mount = true/' \
    -e "s|^internal_directory = \"$api_work/root/.vaultlink-internal\"$|internal_directory = \"$runtime_internal\"|" \
    -e "s|$api_work/root|$runtime_root|g" \
    -e "s|$api_work/data|/var/lib/vaultlink|g" \
    "$api_work/config.toml" >"$runtime_config_work"
awk '
    function finish_storage() {
        if (storage_filesystem == 0) {
            print "expected_filesystem_type = \"ext4\""
            storage_filesystem = 1
        }
        if (storage_source == 0) {
            print "expected_mount_source = \"/dev/vdb\""
            storage_source = 1
        }
    }
    skipping_proxies {
        if ($0 == "]") skipping_proxies = 0
        next
    }
    /^\[[^]]+\]$/ {
        if (section == "[storage]") finish_storage()
        section = $0
        print
        next
    }
    section == "[storage]" && /^expected_filesystem_type = / {
        print "expected_filesystem_type = \"ext4\""
        storage_filesystem++
        next
    }
    section == "[storage]" && /^expected_mount_source = / {
        print "expected_mount_source = \"/dev/vdb\""
        storage_source++
        next
    }
    section == "[reverse_proxy]" && $0 == "enabled = false" {
        print "enabled = true"
        rewritten_enabled++
        next
    }
    section == "[reverse_proxy]" && /^trusted_proxies = / {
        print "trusted_proxies = [\"127.0.0.1\"]"
        rewritten_proxies++
        if ($0 == "trusted_proxies = [") skipping_proxies = 1
        next
    }
    section == "[reverse_proxy]" && $0 == "trust_x_forwarded_headers = false" {
        print "trust_x_forwarded_headers = true"
        rewritten_forwarded++
        next
    }
    { print }
    END {
        if (section == "[storage]") finish_storage()
        if (skipping_proxies || rewritten_enabled != 1 \
            || rewritten_proxies != 1 || rewritten_forwarded != 1 \
            || storage_filesystem != 1 || storage_source != 1) exit 1
    }
' "$runtime_config_work" >"$evidence/config.toml"
rm -f "$runtime_config_work"
runtime_config_work=
grep -F -x -q 'mode = "reverse_proxy"' "$evidence/config.toml"
if ! awk '
    /^\[[^]]+\]$/ { section = $0; next }
    section == "[reverse_proxy]" && /^enabled[[:space:]]*=/ {
        enabled++
        enabled_ok += ($0 == "enabled = true")
    }
    section == "[reverse_proxy]" && /^trusted_proxies[[:space:]]*=/ {
        proxies++
        proxies_ok += ($0 == "trusted_proxies = [\"127.0.0.1\"]")
    }
    section == "[reverse_proxy]" && /^trust_x_forwarded_headers[[:space:]]*=/ {
        forwarded++
        forwarded_ok += ($0 == "trust_x_forwarded_headers = true")
    }
    section == "[tls]" && /^enabled[[:space:]]*=/ {
        tls++
        tls_ok += ($0 == "enabled = false")
    }
    END {
        exit !(enabled == 1 && enabled_ok == 1 \
            && proxies == 1 && proxies_ok == 1 \
            && forwarded == 1 && forwarded_ok == 1 \
            && tls == 1 && tls_ok == 1)
    }
' "$evidence/config.toml"; then
    echo "runtime smoke produced unsafe reverse-proxy configuration" >&2
    exit 77
fi
grep -F -x -q 'require_mount = true' "$evidence/config.toml"
grep -F -x -q 'expected_filesystem_type = "ext4"' "$evidence/config.toml"
grep -F -x -q 'root_mount_path = "/mnt/storage/shared"' "$evidence/config.toml"
grep -F -x -q 'internal_directory = "/mnt/storage/.vaultlink-internal"' "$evidence/config.toml"
[ "$(findmnt -n -o FSTYPE --target "$runtime_root")" = ext4 ]
[ "$(findmnt -n -o SOURCE --target "$runtime_root")" = /dev/vdb ]
install -o root -g vaultlink -m 0640 "$evidence/config.toml" /etc/vaultlink/config.toml

runtime_stage=service-start
systemd-analyze verify \
    /usr/lib/systemd/system/vaultlink.service \
    /usr/lib/systemd/system/vaultlink-update.service \
    /usr/lib/systemd/system/vaultlink-update.timer \
    >"$evidence/systemd-analyze.txt" 2>&1
systemctl start vaultlink.service
for attempt in $(seq 1 120); do
    if curl --fail --silent --show-error \
        http://127.0.0.1:18081/api/v2/health/ready \
        >"$evidence/readiness.json" 2>"$evidence/readiness-last.stderr"; then
        break
    fi
    [ "$attempt" -lt 120 ] || exit 70
    sleep 1
done
grep -F -q '"ok":true' "$evidence/readiness.json"

runtime_stage=authenticated-load
cookie="$evidence/cookies.txt"
password='VaultLink api smoke password 123!'
totp_secret=$(grep -Eo '[A-Z2-7]{32}' "$api_work/setup-response.html" | head -n 1)
totp_epoch=$(date +%s)
case "$totp_epoch" in ''|*[!0-9]*) exit 70 ;; esac
# The preceding API smoke authenticates with this same administrator. Wait for
# a new TOTP counter so this second login tests replay protection without
# racing the 30-second boundary used by the first login.
totp_wait_seconds=$((31 - totp_epoch % 30))
sleep "$totp_wait_seconds"
totp_code=$(python3 - "$totp_secret" <<'PY'
import base64, hashlib, hmac, struct, sys, time
secret = sys.argv[1]
secret += "=" * ((8 - len(secret) % 8) % 8)
key = base64.b32decode(secret)
counter = int(time.time() // 30)
digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
offset = digest[-1] & 15
print(f"{(struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff) % 1000000:06d}")
PY
)
login=$(curl --fail --silent --show-error -c "$cookie" \
    -H 'content-type: application/json' -X POST \
    http://127.0.0.1:18081/api/v2/session/login \
    -d "{\"username\":\"admin\",\"password\":\"$password\"}")
csrf=$(printf '%s' "$login" | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf_token"])')
mfa=$(curl --fail --silent --show-error -b "$cookie" -c "$cookie" \
    -H 'content-type: application/json' -H "x-csrf-token: $csrf" -X POST \
    http://127.0.0.1:18081/api/v2/session/mfa -d "{\"code\":\"$totp_code\"}")
csrf=$(printf '%s' "$mfa" | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf_token"])')

install -d -o vaultlink -g vaultlink -m 0750 \
    "$runtime_root/vaultlink-load" "$runtime_root/vaultlink-load/uploads"
runuser -u vaultlink -- truncate -s 50G "$runtime_root/vaultlink-load/sparse-50GiB.bin"
create_share() {
    path=$1
    permission=$2
    curl --fail --silent --show-error -b "$cookie" \
        -H 'content-type: application/json' -H "x-csrf-token: $csrf" -X POST \
        http://127.0.0.1:18081/api/v2/shares \
        -d "{\"path\":\"$path\",\"permission\":\"$permission\",\"overwrite_allowed\":false}" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])'
}
download_token=$(create_share vaultlink-load/sparse-50GiB.bin download_only)
upload_token=$(create_share vaultlink-load/uploads upload_only)
verify_token=$(create_share vaultlink-load/uploads download_upload)

load_tmp="$runtime_mount_base/.distro-vm-load-work"
[ ! -e "$load_tmp" ] && [ ! -L "$load_tmp" ] || exit 77
install -d -o root -g root -m 0700 "$load_tmp"
# QEMU remains authoritative for every functional, integrity and resource
# assertion, but its performance varies with the acceleration exposed by the
# managed runner. TCG therefore receives longer request deadlines without
# reducing the 100/40/10 workload. The p95 is measured in both modes and is
# intentionally diagnostic; the same-architecture native package gate owns
# the release-blocking <2-second assertion.
load_connect_timeout_seconds=5
load_metadata_max_time_seconds=30
load_transfer_max_time_seconds=300
load_admission_ready_timeout_seconds=10
load_admission_holder_max_time_seconds=30
load_admission_probe_max_time_seconds=5
load_profile_ready_timeout_seconds=10
if [ "$acceleration" = tcg ]; then
    load_connect_timeout_seconds=60
    load_metadata_max_time_seconds=300
    load_transfer_max_time_seconds=1800
    load_admission_ready_timeout_seconds=600
    load_admission_holder_max_time_seconds=1800
    load_admission_probe_max_time_seconds=120
    load_profile_ready_timeout_seconds=600
fi
VAULTLINK_BASE_URL=http://127.0.0.1:18081 \
VAULTLINK_HEALTH_URL=http://127.0.0.1:18081/api/v2/health/ready \
DOWNLOAD_TOKEN=$download_token \
UPLOAD_TOKEN=$upload_token \
UPLOAD_VERIFY_TOKEN=$verify_token \
SOAK_NAMESPACE="package-$target_id" \
LOAD_RUN_ID=full-system \
VAULTLINK_CONFIG=/etc/vaultlink/config.toml \
LOAD_TEST_EVIDENCE_DIR="$evidence/load" \
LOAD_P95_POLICY=diagnostic \
LOAD_CONNECT_TIMEOUT_SECONDS="$load_connect_timeout_seconds" \
LOAD_METADATA_MAX_TIME_SECONDS="$load_metadata_max_time_seconds" \
LOAD_TRANSFER_MAX_TIME_SECONDS="$load_transfer_max_time_seconds" \
LOAD_ADMISSION_READY_TIMEOUT_SECONDS="$load_admission_ready_timeout_seconds" \
LOAD_ADMISSION_HOLDER_MAX_TIME_SECONDS="$load_admission_holder_max_time_seconds" \
LOAD_ADMISSION_PROBE_MAX_TIME_SECONDS="$load_admission_probe_max_time_seconds" \
LOAD_PROFILE_READY_TIMEOUT_SECONDS="$load_profile_ready_timeout_seconds" \
VAULTLINK_PROCESS_PID='' \
VAULTLINK_PROCESS_UID='' \
VAULTLINK_PROCESS_GID='' \
VAULTLINK_EXPECTED_BINARY_PATH='' \
VAULTLINK_EXPECTED_BINARY_SHA256='' \
TMPDIR="$load_tmp" \
sh /tmp/load-test.sh >"$evidence/load.log" 2>&1
rmdir "$load_tmp"
grep -F -x -q 'integrity=ok' "$evidence/load/post-load.env"
p95=$(evidence_value "$evidence/load/result.env" metadata_p95_seconds)
observed_p95=$(evidence_value \
    "$evidence/load/profile-status.env" metadata_observed_p95_seconds)
[ "$p95" = "$observed_p95" ]
expected_p95_within_limit=$(awk -v value="$p95" 'BEGIN {
    if (value !~ /^[0-9]+([.][0-9]+)?$/ || !(value > 0)) exit 77
    print (value < 2.000) ? "true" : "false"
}')
for p95_evidence in \
    "$evidence/load/profile-status.env" \
    "$evidence/load/result.env"; do
    [ "$(evidence_value "$p95_evidence" supervision_mode)" = systemd ]
    [ "$(evidence_value "$p95_evidence" metadata_p95_policy)" = diagnostic ]
    [ "$(evidence_value "$p95_evidence" metadata_p95_limit_seconds)" = 2.000 ]
    [ "$(evidence_value "$p95_evidence" metadata_p95_enforced)" = false ]
    [ "$(evidence_value "$p95_evidence" metadata_p95_within_limit)" \
        = "$expected_p95_within_limit" ]
done

runtime_stage=upgrade-migration-rollback
database=/var/lib/vaultlink/data.sqlite
# Downgrade the live database metadata to the valid schema-5 shape while the
# idle service still owns its connection. The immediately following upgrade
# stops the service before copying it, then the packaged binary must perform
# the real 5->6 migration during readiness startup.
sqlite3 "$database" <<'SQL'
BEGIN IMMEDIATE;
INSERT INTO audit(occurred_at,actor,action,object_id,detail,priority)
VALUES('2026-08-25T00:00:00Z','vm-gate','upload','migration-probe','preserve',0);
DELETE FROM vaultlink_schema_migrations WHERE target_version=6;
UPDATE vaultlink_schema
SET fingerprint='vaultlink-schema-5-audit-priority-2026-07-19'
WHERE singleton=1;
PRAGMA user_version=5;
COMMIT;
SQL
[ "$(sqlite3 "$database" 'PRAGMA user_version;')" = 5 ]

backup=$(/usr/lib/vaultlink/package/deploy/vaultlink-upgrade.sh \
    /usr/lib/vaultlink/package/vaultlink /etc/vaultlink/config.toml)
[ -d "$backup" ]
printf '%s\n' "$backup" >"$evidence/upgrade-backup.txt"
[ "$(sqlite3 "$backup/data.sqlite" 'PRAGMA user_version;')" = 5 ]
[ "$(sqlite3 "$database" 'PRAGMA user_version;')" = 6 ]
[ "$(sqlite3 "$database" \
    "SELECT priority FROM audit WHERE object_id='migration-probe';")" = 100 ]
systemctl stop vaultlink.service
[ "$(systemctl is-active vaultlink.service 2>/dev/null || true)" = inactive ]
/usr/lib/vaultlink/package/deploy/vaultlink-rollback.sh "$backup" \
    >"$evidence/rollback.txt"
systemctl --quiet is-active vaultlink.service
curl --fail --silent --show-error \
    http://127.0.0.1:18081/api/v2/health/ready >"$evidence/post-rollback-readiness.json"
[ "$(sqlite3 "$database" 'PRAGMA user_version;')" = 6 ]
[ "$(sqlite3 "$database" \
    "SELECT priority FROM audit WHERE object_id='migration-probe';")" = 100 ]
[ "$(sqlite3 "$database" 'PRAGMA integrity_check;')" = ok ]

runtime_stage=runtime-integrity-guard
# A power-loss mixed state must fail before the binary executes and must not
# cause an unbounded Restart=on-failure loop.
systemctl stop vaultlink.service
rm -f /var/lib/vaultlink/runtime-guard-bypass
printf '%s\n' '#!/bin/sh' \
    ': > /var/lib/vaultlink/runtime-guard-bypass' \
    'exec /usr/lib/vaultlink/package/vaultlink "$@"' \
    >/opt/vaultlink/vaultlink
chown root:root /opt/vaultlink/vaultlink
chmod 0755 /opt/vaultlink/vaultlink
# The preceding clean stop leaves no failed state to reset. Avoid a separate
# reset-failed here: a disabled, inactive unit may be garbage-collected between
# the stop and reset calls even though its unit file remains installed.
if systemctl start vaultlink.service \
    >"$evidence/runtime-guard-start.stdout" \
    2>"$evidence/runtime-guard-start.stderr"; then
    echo "runtime parity guard accepted a divergent live binary" >&2
    exit 77
fi
sleep 31
systemctl show vaultlink.service --no-pager \
    -p ActiveState -p SubState -p Result -p NRestarts \
    -p StartLimitBurst -p StartLimitIntervalUSec \
    >"$evidence/runtime-guard-start-limit.env"
guard_active_state=$(sed -n 's/^ActiveState=//p' \
    "$evidence/runtime-guard-start-limit.env")
case "$guard_active_state" in failed|inactive) ;; *) exit 77 ;; esac
grep -F -x -q 'StartLimitBurst=3' "$evidence/runtime-guard-start-limit.env"
guard_restarts_before=$(sed -n 's/^NRestarts=//p' \
    "$evidence/runtime-guard-start-limit.env")
case "$guard_restarts_before" in ''|*[!0-9]*) exit 77 ;; esac
[ "$guard_restarts_before" -le 3 ]
[ ! -e /var/lib/vaultlink/runtime-guard-bypass ]
sleep 6
guard_restarts_after=$(systemctl show vaultlink.service -p NRestarts --value)
[ "$guard_restarts_after" = "$guard_restarts_before" ]
install -o root -g root -m 0755 /usr/lib/vaultlink/package/vaultlink \
    /opt/vaultlink/vaultlink
systemctl reset-failed vaultlink.service
systemctl start vaultlink.service
systemctl --quiet is-active vaultlink.service
printf 'database_integrity=ok\nreadiness=ok\nupgrade=ok\nmigration=ok\nrollback=ok\nacceleration=%s\n' \
    "$acceleration" >"$evidence/runtime.env"
systemctl show vaultlink.service \
    -p ActiveState -p SubState -p NRestarts -p MemoryCurrent \
    >"$evidence/systemd.env"
grep -F -x -q 'ActiveState=active' "$evidence/systemd.env"
grep -F -x -q 'SubState=running' "$evidence/systemd.env"
grep -F -x -q 'NRestarts=0' "$evidence/systemd.env"
journalctl -u vaultlink.service --no-pager >"$evidence/vaultlink.journal"

if [ "$target_id" = fedora44-amd64 ] || [ "$target_id" = fedora44-arm64 ]; then
    [ "$(getenforce)" = Enforcing ]
    [ "$(systemctl is-active auditd.service)" = active ]
    auditctl -s >"$evidence/audit-status-after.txt"
    grep -E -q '^enabled[[:space:]]+1$' "$evidence/audit-status-after.txt"
    sed -n "${fedora_audit_start_line},\$p" /var/log/audit/audit.log \
        >"$evidence/audit-window.log"
    grep -F -q "$fedora_audit_marker" "$evidence/audit-window.log"
    journalctl -k -b --no-pager >"$evidence/kernel-audit.journal"
    if grep -E 'type=(AVC|USER_AVC|SELINUX_ERR|USER_SELINUX_ERR)' \
        "$evidence/audit-window.log" \
        | grep -E -i 'vaultlink|/opt/vaultlink|/var/lib/vaultlink|/mnt/storage'; then
        echo "SELinux recorded a VaultLink-related AVC denial" >&2
        exit 77
    fi
    if grep -E -i 'avc:[[:space:]]+denied' "$evidence/kernel-audit.journal" \
        | grep -E -i 'vaultlink|/opt/vaultlink|/var/lib/vaultlink|/mnt/storage'; then
        echo "kernel journal recorded a VaultLink-related AVC denial" >&2
        exit 77
    fi
    printf 'selinux=Enforcing\nvaultlink_avc_denials=0\n' >"$evidence/selinux.env"
fi

runtime_stage=complete
echo "package runtime smoke $target_id: OK"
