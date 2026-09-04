#!/bin/sh
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CDPATH=
LC_ALL=C
LANG=C
export PATH CDPATH LC_ALL LANG
umask 077

fail() {
    echo "native package load smoke failed: $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "the native load smoke must run as root"
[ "$#" -eq 5 ] || {
    echo "usage: $0 TARGET_ID VERSION PACKAGE API_WORK EVIDENCE_DIRECTORY" >&2
    exit 64
}
target_id=$1
version=$2
package=$3
api_work=$4
evidence=$5
case "$target_id" in *[!a-z0-9-]*|'') exit 64 ;; esac
printf '%s\n' "$version" \
    | grep -E -q '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' \
    || { echo "VERSION must be strict stable SemVer" >&2; exit 64; }
[ "$api_work" = /tmp/vaultlink-offline-package-api ] \
    || fail "unexpected API fixture path"
[ "$evidence" = "/work/offline-smoke/$target_id/native-load" ] \
    || fail "unexpected native-load evidence path"
if [ ! -f "$package" ] || [ -L "$package" ]; then
    fail "package input is unsafe"
fi
package=$(readlink -f -- "$package")
case "$package" in
    "/work/offline-smoke/$target_id/"*) ;;
    *) fail "package input is outside the target artifact directory" ;;
esac
if [ ! -d "$api_work" ] || [ -L "$api_work" ]; then
    fail "API smoke fixture is unavailable"
fi

for command_name in awk cmp curl date df find findmnt grep install kill nproc \
    python3 readlink sed seq setpriv sha256sum sleep sort sqlite3 stat taskset \
    truncate; do
    command -v "$command_name" >/dev/null \
        || fail "required command is unavailable: $command_name"
done

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
[ "$repo_root" = /work ] || fail "native package gate must run from /work"
process_identity_helper=$repo_root/tools/check-direct-process-identity.sh
if [ ! -f "$process_identity_helper" ] || [ -L "$process_identity_helper" ] \
    || [ ! -r "$process_identity_helper" ]; then
    fail "direct process identity helper is unavailable or unsafe"
fi
storage_qualification_helper=$repo_root/tools/qualify-native-load-storage.py
if [ ! -f "$storage_qualification_helper" ] \
    || [ -L "$storage_qualification_helper" ] \
    || [ ! -r "$storage_qualification_helper" ]; then
    fail "storage qualification helper is unavailable or unsafe"
fi
cd "$repo_root"
python3 tools/package-targets.py validate >/dev/null
target_get() {
    python3 tools/package-targets.py get "$target_id" "$1"
}
package_format=$(target_get package_format)
package_arch=$(target_get package_arch)
target_distribution=$(target_get distribution)
target_distribution_version=$(target_get version)

if [ -L "$evidence" ]; then
    fail "native-load evidence path must not be a symlink"
fi
case "$evidence" in /work/offline-smoke/*/native-load) ;; *) exit 64 ;; esac
rm -rf -- "$evidence"
install -d -m 0755 "$evidence"

native_stage=initialization
service_pid=
runtime_base=
load_tmp=
load_client_workspace=
load_log=
password=
totp_secret=
totp_code=
csrf=
download_token=
admission_download_token=
range_download_token=
upload_token=
upload_token_2=
upload_token_3=
upload_token_4=
upload_token_5=
verify_token=

write_redacted_tail() {
    source_log=$1
    destination_log=$2
    maximum_lines=$3
    if [ ! -f "$source_log" ] || [ -L "$source_log" ]; then
        return 0
    fi
    NATIVE_REDACT_PASSWORD=$password \
    NATIVE_REDACT_TOTP_SECRET=$totp_secret \
    NATIVE_REDACT_TOTP_CODE=$totp_code \
    NATIVE_REDACT_CSRF=$csrf \
    NATIVE_REDACT_DOWNLOAD_TOKEN=$download_token \
    NATIVE_REDACT_ADMISSION_DOWNLOAD_TOKEN=$admission_download_token \
    NATIVE_REDACT_RANGE_DOWNLOAD_TOKEN=$range_download_token \
    NATIVE_REDACT_UPLOAD_TOKEN=$upload_token \
    NATIVE_REDACT_UPLOAD_TOKEN_2=$upload_token_2 \
    NATIVE_REDACT_UPLOAD_TOKEN_3=$upload_token_3 \
    NATIVE_REDACT_UPLOAD_TOKEN_4=$upload_token_4 \
    NATIVE_REDACT_UPLOAD_TOKEN_5=$upload_token_5 \
    NATIVE_REDACT_VERIFY_TOKEN=$verify_token \
    python3 - "$source_log" "$destination_log" "$maximum_lines" <<'PY'
from collections import deque
import os
import re
import sys

source, destination, maximum_lines = sys.argv[1:]
with open(source, "r", encoding="utf-8", errors="replace") as handle:
    text = "".join(deque(handle, maxlen=int(maximum_lines)))

secret_names = (
    "NATIVE_REDACT_PASSWORD",
    "NATIVE_REDACT_TOTP_SECRET",
    "NATIVE_REDACT_TOTP_CODE",
    "NATIVE_REDACT_CSRF",
    "NATIVE_REDACT_DOWNLOAD_TOKEN",
    "NATIVE_REDACT_ADMISSION_DOWNLOAD_TOKEN",
    "NATIVE_REDACT_RANGE_DOWNLOAD_TOKEN",
    "NATIVE_REDACT_UPLOAD_TOKEN",
    "NATIVE_REDACT_UPLOAD_TOKEN_2",
    "NATIVE_REDACT_UPLOAD_TOKEN_3",
    "NATIVE_REDACT_UPLOAD_TOKEN_4",
    "NATIVE_REDACT_UPLOAD_TOKEN_5",
    "NATIVE_REDACT_VERIFY_TOKEN",
)
known_secrets = sorted(
    {os.environ.get(name, "") for name in secret_names} - {""},
    key=len,
    reverse=True,
)
for secret in known_secrets:
    text = text.replace(secret, "[REDACTED]")

redactions = (
    (r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+", r"\1[REDACTED]"),
    (r"(?i)((?:set-)?cookie\s*:\s*)[^\r\n]+", r"\1[REDACTED]"),
    (r"(?i)(x-csrf-token\s*:\s*)[^\s,;]+", r"\1[REDACTED]"),
    (r"(?i)([#?&](?:token|preview_token|csrf_token)=)[^&#\s]+", r"\1[REDACTED]"),
    (r"(?i)(/(?:api/v2/public/)?shares/)[A-Za-z0-9._~-]+", r"\1[REDACTED]"),
    (r"(?i)(/v/)[A-Za-z0-9._~-]+", r"\1[REDACTED]"),
    (r"(?i)(\"?(?:password|secret|totp|token|csrf)[A-Za-z0-9_.-]*\"?\s*[:=]\s*)\"?[^\s,;}\"]+\"?", r"\1[REDACTED]"),
    (r"(?i)otpauth://[^\s]+", "otpauth://[REDACTED]"),
    (r"\b[A-Z2-7]{32}\b", "[REDACTED]"),
)
for pattern, replacement in redactions:
    text = re.sub(pattern, replacement, text)

with open(destination, "w", encoding="utf-8", newline="\n") as handle:
    handle.write(text)
PY
}

cleanup() {
    native_status=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ "$native_status" -ne 0 ]; then
        service_alive=false
        if [ -n "$service_pid" ] && kill -0 "$service_pid" 2>/dev/null; then
            service_alive=true
        fi
        printf '%s\n' \
            "stage=$native_stage" \
            "exit_status=$native_status" \
            "service_pid=${service_pid:-unavailable}" \
            "service_alive_before_cleanup=$service_alive" \
            >"$evidence/failure-status.env" 2>/dev/null || true
    fi
    if [ -n "$service_pid" ] && kill -0 "$service_pid" 2>/dev/null; then
        kill "$service_pid" 2>/dev/null || true
        wait "$service_pid" 2>/dev/null || true
    fi
    if [ -n "$load_tmp" ]; then
        case "$load_tmp" in
            /mnt/load-client/tmp) rm -rf -- "$load_tmp" ;;
        esac
    fi
    if [ -n "$runtime_base" ]; then
        case "$runtime_base" in
            /mnt/storage/vaultlink-native-load-*)
                if [ "$native_status" -ne 0 ]; then
                    write_redacted_tail "$runtime_base/service.log" \
                        "$evidence/failure-service.log" 200 || true
                    write_redacted_tail "$load_log" \
                        "$evidence/failure-load.log" 200 || true
                fi
                rm -rf -- "$runtime_base"
                ;;
        esac
    fi
    if [ -n "$load_client_workspace" ]; then
        case "$load_client_workspace" in
            /mnt/load-client/work) rm -rf -- "$load_client_workspace" ;;
        esac
    fi
    printf 'stage=%s\nexit_status=%s\n' "$native_stage" "$native_status" \
        >"$evidence/native-load-command.env" 2>/dev/null || true
    find "$evidence" -type d -exec chmod 0755 {} + 2>/dev/null || true
    find "$evidence" -type f -exec chmod 0644 {} + 2>/dev/null || true
    exit "$native_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

native_stage=resource_isolation
container_cpu_set=0-3
service_cpu_set=0-1
load_client_cpu_set=2-3
host_nproc=${VAULTLINK_NATIVE_HOST_NPROC:-}
host_mem_total_kib=${VAULTLINK_NATIVE_HOST_MEM_TOTAL_KIB:-}
docker_nproc=${VAULTLINK_NATIVE_DOCKER_NPROC:-}
requested_container_cpu_set=${VAULTLINK_NATIVE_CONTAINER_CPUSET:-}
case "$host_nproc:$host_mem_total_kib:$docker_nproc" in
    *[!0-9:]*|:*|*::*|*:) fail "runner resource qualification is invalid" ;;
esac
[ "$host_nproc" -ge 4 ] \
    || fail "native load runner has fewer than four CPUs"
[ "$host_mem_total_kib" -ge 8388608 ] \
    || fail "native load runner has less than 8 GiB memory"
[ "$docker_nproc" -ge 4 ] \
    || fail "Docker reports fewer than four CPUs"
[ "$requested_container_cpu_set" = "$container_cpu_set" ] \
    || fail "requested container CPU set must be exactly $container_cpu_set"
container_nproc=$(nproc)
case "$container_nproc" in *[!0-9]*|'') fail "container CPU count is invalid" ;; esac
[ "$container_nproc" -eq 4 ] \
    || fail "native load container must expose exactly four CPUs"
container_effective_cpu_set=$(sed -n \
    's/^Cpus_allowed_list:[[:space:]]*//p' /proc/self/status)
[ "$container_effective_cpu_set" = "$container_cpu_set" ] \
    || fail "native load container CPU set must be exactly $container_cpu_set"
taskset --cpu-list "$service_cpu_set" true \
    || fail "service CPU set is unavailable"
load_client_probe_cpu_set=$(taskset --cpu-list "$load_client_cpu_set" sh -c \
    "sed -n 's/^Cpus_allowed_list:[[:space:]]*//p' /proc/self/status")
[ "$load_client_probe_cpu_set" = "$load_client_cpu_set" ] \
    || fail "load-generator CPU set is unavailable"

load_client_mount=/mnt/load-client
if [ ! -d "$load_client_mount" ] || [ -L "$load_client_mount" ]; then
    fail "dedicated load-client tmpfs is unavailable or unsafe"
fi
[ "$(stat -c '%u:%g:%a' "$load_client_mount")" = 0:0:700 ] \
    || fail "load-client tmpfs must be root:root mode 0700"
[ -z "$(find "$load_client_mount" -mindepth 1 -maxdepth 1 -print -quit)" ] \
    || fail "load-client tmpfs must be empty before the profile"
load_client_mount_target=$(findmnt -n -o TARGET --target "$load_client_mount")
[ "$load_client_mount_target" = "$load_client_mount" ] \
    || fail "load-client path is not a dedicated mount"
load_client_mount_fstype=$(findmnt -n -o FSTYPE --target "$load_client_mount")
[ "$load_client_mount_fstype" = tmpfs ] \
    || fail "load-client mount must use tmpfs"
load_client_mount_source=$(findmnt -n -o SOURCE --target "$load_client_mount")
[ "$load_client_mount_source" = tmpfs ] \
    || fail "load-client tmpfs source is unexpected"
load_client_mount_options=$(findmnt -n -o OPTIONS --target "$load_client_mount")
case "$load_client_mount_options" in *[!A-Za-z0-9,._%:=+-]*)
    fail "load-client tmpfs options are unsafe"
    ;;
esac
for required_mount_option in rw nosuid nodev noexec; do
    case ",$load_client_mount_options," in
        *",$required_mount_option,"*) ;;
        *) fail "load-client tmpfs lacks $required_mount_option" ;;
    esac
done
load_client_capacity=$(df -B1 --output=size,avail "$load_client_mount" \
    | awk 'NR == 2 { print $1 ":" $2; exit }')
load_client_capacity_bytes=${load_client_capacity%%:*}
load_client_available_bytes=${load_client_capacity#*:}
case "$load_client_capacity_bytes:$load_client_available_bytes" in
    *[!0-9:]*|:*|*::*) fail "load-client tmpfs capacity is invalid" ;;
esac
[ "$load_client_capacity_bytes" -ge 4294967296 ] \
    || fail "load-client tmpfs is smaller than 4 GiB"
[ "$load_client_available_bytes" -ge 4294967296 ] \
    || fail "load-client tmpfs does not have 4 GiB available"
load_client_workspace=$load_client_mount/work
install -d -o root -g root -m 0700 "$load_client_workspace"
load_log=$load_client_workspace/load.log

expected_package_version=
case "$target_id:$package_format" in
    debian13-*:deb) expected_package_version="$version-1+deb13" ;;
    ubuntu2404-*:deb) expected_package_version="$version-1+ubuntu24.04" ;;
    ubuntu2604-*:deb) expected_package_version="$version-1+ubuntu26.04" ;;
    fedora44-*:rpm) expected_package_version="$version-1.fc44" ;;
    archlinux-amd64:pkg.tar.zst) expected_package_version="$version-1" ;;
    *) fail "unexpected package target/format binding" ;;
esac

package_database_snapshot() {
    snapshot_destination=$1
    case "$package_format" in
        deb)
            database_status=$(dpkg-query -W -f='${db:Status-Status}' vaultlink 2>/dev/null)
            database_version=$(dpkg-query -W -f='${Version}' vaultlink 2>/dev/null)
            database_arch=$(dpkg-query -W -f='${Architecture}' vaultlink 2>/dev/null)
            [ "$database_status" = installed ] || return 1
            ;;
        rpm)
            rpm -q vaultlink >/dev/null 2>&1 || return 1
            database_status=installed
            database_version=$(rpm -q --qf '%{VERSION}-%{RELEASE}' vaultlink)
            database_arch=$(rpm -q --qf '%{ARCH}' vaultlink)
            ;;
        pkg.tar.zst)
            database_status=installed
            database_version=$(pacman -Q vaultlink | awk '{ print $2 }')
            database_arch=$(pacman -Qi vaultlink 2>/dev/null \
                | sed -n 's/^Architecture[[:space:]]*:[[:space:]]*//p')
            [ "$(printf '%s\n' "$database_arch" | awk 'NF { count++ } END { print count + 0 }')" -eq 1 ] \
                || return 1
            ;;
        *) return 1 ;;
    esac
    [ "$database_version" = "$expected_package_version" ] || return 1
    [ "$database_arch" = "$package_arch" ] || return 1
    printf '%s\n' \
        "package_database_status=$database_status" \
        "package_database_format=$package_format" \
        "package_database_version=$database_version" \
        "package_database_arch=$database_arch" \
        >"$snapshot_destination"
}

native_stage=package_integrity
marker=/usr/share/vaultlink/install-method.env
candidate=/usr/lib/vaultlink/package/vaultlink
live_binary=/opt/vaultlink/vaultlink
if [ ! -f "$marker" ] || [ -L "$marker" ]; then
    fail "package marker is unsafe"
fi
[ "$(stat -c '%u:%g:%a' "$marker")" = 0:0:644 ] \
    || fail "package marker must be root:root mode 0644"
[ "$(wc -l <"$marker" | tr -d '[:space:]')" -eq 5 ] \
    || fail "package marker has an unexpected shape"
grep -F -x -q "FORMAT=$package_format" "$marker" \
    || fail "package marker format differs from the target"
grep -F -x -q "OS_ID=$target_distribution" "$marker" \
    || fail "package marker distribution differs from the target"
grep -F -x -q "OS_VERSION=$target_distribution_version" "$marker" \
    || fail "package marker distribution version differs from the target"
grep -F -x -q "ARCH=$package_arch" "$marker" \
    || fail "package marker architecture differs from the target"
grep -F -x -q 'PACKAGE_NAME=vaultlink' "$marker" \
    || fail "package marker name differs from VaultLink"
if [ ! -f "$candidate" ] || [ -L "$candidate" ] || [ ! -x "$candidate" ]; then
    fail "installed package candidate is unsafe"
fi
if [ ! -f "$live_binary" ] || [ -L "$live_binary" ] || [ ! -x "$live_binary" ]; then
    fail "active package binary is unsafe"
fi
[ "$(stat -c '%u:%g:%a' "$candidate")" = 0:0:755 ] \
    || fail "installed package candidate must be root:root mode 0755"
[ "$(stat -c '%u:%g:%a' "$live_binary")" = 0:0:755 ] \
    || fail "active package binary must be root:root mode 0755"
[ "$(cat /usr/lib/vaultlink/package/version)" = "$version" ] \
    || fail "installed package version metadata differs"
(cd /usr/lib/vaultlink/package && sha256sum -c vaultlink.sha256 >/dev/null) \
    || fail "installed package candidate checksum is invalid"
cmp -s "$candidate" "$live_binary" \
    || fail "active binary differs from the exact installed package candidate"
[ "$("$live_binary" --version)" = "$version" ] \
    || fail "active package binary reports the wrong version"
candidate_sha256=$(sha256sum "$candidate" | awk '{ print $1 }')
live_sha256=$(sha256sum "$live_binary" | awk '{ print $1 }')
package_sha256=$(sha256sum "$package" | awk '{ print $1 }')
package_database_snapshot "$evidence/package-database-before.env" \
    || fail "package database does not match the target"

native_stage=storage_qualification
if [ ! -d /mnt/storage ] || [ -L /mnt/storage ]; then
    fail "isolated native-load volume is unavailable"
fi
[ -z "$(find /mnt/storage -mindepth 1 -maxdepth 1 -print -quit)" ] \
    || fail "isolated native-load volume is not empty"
python3 "$storage_qualification_helper" \
    /mnt/storage "$evidence/storage-qualification.env" \
    || fail "native-load storage does not satisfy the SQLite WAL qualification"
grep -F -x -q 'qualification=pass' "$evidence/storage-qualification.env" \
    || fail "native-load storage qualification evidence is incomplete"
[ -z "$(find /mnt/storage -mindepth 1 -maxdepth 1 -print -quit)" ] \
    || fail "storage qualification did not leave the native-load volume empty"

native_stage=runtime_fixture
runtime_base="/mnt/storage/vaultlink-native-load-$target_id"
install -d -o root -g vaultlink -m 0750 "$runtime_base"
chown root:vaultlink "$runtime_base"
chmod 0750 "$runtime_base"
runtime_root=$runtime_base/shared
runtime_data=$runtime_base/data
runtime_internal=$runtime_base/.vaultlink-internal
install -d -o vaultlink -g vaultlink -m 0750 "$runtime_root" "$runtime_data"
install -d -o vaultlink -g vaultlink -m 0700 "$runtime_internal"
cp -a "$api_work/root/." "$runtime_root/"
cp -a "$api_work/data/." "$runtime_data/"
if [ -d "$api_work/root/.vaultlink-internal" ]; then
    cp -a "$api_work/root/.vaultlink-internal/." "$runtime_internal/"
fi
rm -rf -- "$runtime_root/.vaultlink-internal"
chown -R vaultlink:vaultlink "$runtime_root" "$runtime_data" "$runtime_internal"
chmod 0750 "$runtime_root" "$runtime_data"
chmod 0700 "$runtime_internal"

mount_fstype=$(findmnt -n -o FSTYPE --target "$runtime_root")
case "$mount_fstype" in ext2|ext3|ext4|xfs|btrfs|f2fs|bcachefs|zfs) ;; *)
    fail "isolated native-load volume does not provide an audited local filesystem ($mount_fstype)"
    ;;
esac
mount_source=$(findmnt -n -o SOURCE --target "$runtime_root")
mount_source=${mount_source%%[*}
case "$mount_source" in
    ''|*[!A-Za-z0-9./:_+-]*) fail "native-load mount source is unsafe" ;;
esac
[ "$(findmnt -n -o FSTYPE --target "$runtime_data")" = "$mount_fstype" ] \
    || fail "runtime data and payload are not on the same audited local filesystem"

runtime_config=$runtime_base/config.toml
awk -v root="$runtime_root" -v data="$runtime_data" \
    -v internal="$runtime_internal" -v fstype="$mount_fstype" \
    -v source="$mount_source" '
    function finish_storage() {
        if (!storage_fstype) {
            print "expected_filesystem_type = \"" fstype "\""
            storage_fstype = 1
        }
        if (!storage_source) {
            print "expected_mount_source = \"" source "\""
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
    section == "[server]" && /^mode[[:space:]]*=/ {
        print "mode = \"reverse_proxy\""; server_mode++; next
    }
    section == "[server]" && /^public_base_url[[:space:]]*=/ {
        print "public_base_url = \"https://files.example.test\""; public_url++; next
    }
    section == "[server]" && /^production_mode[[:space:]]*=/ {
        print "production_mode = true"; production++; next
    }
    section == "[storage]" && /^root_mount_path[[:space:]]*=/ {
        print "root_mount_path = \"" root "\""; storage_root++; next
    }
    section == "[storage]" && /^data_directory[[:space:]]*=/ {
        print "data_directory = \"" data "\""; storage_data++; next
    }
    section == "[storage]" && /^internal_directory[[:space:]]*=/ {
        print "internal_directory = \"" internal "\""; storage_internal++; next
    }
    section == "[storage]" && /^require_mount[[:space:]]*=/ {
        print "require_mount = true"; storage_mount++; next
    }
    section == "[storage]" && /^expected_filesystem_type[[:space:]]*=/ {
        print "expected_filesystem_type = \"" fstype "\""; storage_fstype++; next
    }
    section == "[storage]" && /^expected_mount_source[[:space:]]*=/ {
        print "expected_mount_source = \"" source "\""; storage_source++; next
    }
    section == "[security]" && /^secure_cookie[[:space:]]*=/ {
        print "secure_cookie = true"; secure_cookie++; next
    }
    section == "[reverse_proxy]" && /^enabled[[:space:]]*=/ {
        print "enabled = true"; proxy_enabled++; next
    }
    section == "[reverse_proxy]" && /^trusted_proxies[[:space:]]*=/ {
        print "trusted_proxies = [\"127.0.0.1\"]"; trusted_proxies++
        if ($0 ~ /\[[[:space:]]*$/) skipping_proxies = 1
        next
    }
    section == "[reverse_proxy]" && /^trust_x_forwarded_headers[[:space:]]*=/ {
        print "trust_x_forwarded_headers = true"; forwarded++; next
    }
    { print }
    END {
        if (section == "[storage]") finish_storage()
        if (skipping_proxies || server_mode != 1 || public_url != 1 \
            || production != 1 || storage_root != 1 || storage_data != 1 \
            || storage_internal != 1 || storage_mount != 1 \
            || storage_fstype != 1 || storage_source != 1 \
            || secure_cookie != 1 || proxy_enabled != 1 \
            || trusted_proxies != 1 || forwarded != 1) exit 1
    }
' "$api_work/config.toml" >"$runtime_config" \
    || fail "could not create the native reverse-proxy runtime configuration"
chown root:vaultlink "$runtime_config"
chmod 0640 "$runtime_config"
printf '%s\n' \
    'server_mode=reverse_proxy' \
    'production_mode=true' \
    'secure_cookie=true' \
    'reverse_proxy_enabled=true' \
    'trusted_proxy=127.0.0.1' \
    'require_mount=true' \
    "storage_filesystem=$mount_fstype" \
    >"$evidence/runtime-policy.env"

native_stage=service_start
vaultlink_uid=$(id -u vaultlink)
vaultlink_gid=$(id -g vaultlink)
case "$vaultlink_uid" in *[!0-9]*|'') fail "unsafe service UID" ;; esac
case "$vaultlink_gid" in *[!0-9]*|'') fail "unsafe service GID" ;; esac
if [ "$vaultlink_uid" -le 0 ] || [ "$vaultlink_gid" -le 0 ]; then
    fail "service identity must be unprivileged"
fi
verify_service_identity() {
    expected_starttime=$1
    setpriv --reuid="$vaultlink_uid" --regid="$vaultlink_gid" \
        --clear-groups --no-new-privs -- sh "$process_identity_helper" \
        "$service_pid" "$vaultlink_uid" "$vaultlink_gid" "$live_binary" \
        "$live_sha256" "$expected_starttime"
}
taskset --cpu-list "$service_cpu_set" \
    setpriv --reuid="$vaultlink_uid" --regid="$vaultlink_gid" --init-groups -- \
    "$live_binary" --config "$runtime_config" \
    >"$runtime_base/service.log" 2>&1 &
service_pid=$!
service_starttime=$(sed 's/^.*) //' "/proc/$service_pid/stat" \
    | awk '{ print $20; exit }')
case "$service_starttime" in *[!0-9]*|'') fail "service start time is unavailable" ;; esac
for attempt in $(seq 1 120); do
    kill -0 "$service_pid" 2>/dev/null || fail "package service exited during readiness"
    if curl --fail --silent --show-error \
        http://127.0.0.1:18081/api/v2/health/ready \
        >"$runtime_base/readiness.json" 2>/dev/null; then
        break
    fi
    [ "$attempt" -lt 120 ] || fail "package service did not become ready"
    sleep 0.25
done
expected_health="{\"ok\":true,\"version\":\"$version\"}"
[ "$(cat "$runtime_base/readiness.json")" = "$expected_health" ] \
    || fail "package service readiness response is unexpected"
install -m 0644 "$runtime_base/readiness.json" "$evidence/readiness.json"
readiness_sha256=$(sha256sum "$evidence/readiness.json" | awk '{ print $1 }')
[ "$(verify_service_identity "$service_starttime")" = "$service_starttime" ] \
    || fail "service PID does not execute the exact active package payload"
service_effective_cpu_set=$(sed -n \
    's/^Cpus_allowed_list:[[:space:]]*//p' "/proc/$service_pid/status")
[ "$service_effective_cpu_set" = "$service_cpu_set" ] \
    || fail "package service is not isolated to CPUs $service_cpu_set"
printf '%s\n' \
    "host_nproc=$host_nproc" \
    "host_mem_total_kib=$host_mem_total_kib" \
    "docker_nproc=$docker_nproc" \
    "requested_container_cpu_set=$requested_container_cpu_set" \
    "container_nproc=$container_nproc" \
    "container_cpu_set=$container_effective_cpu_set" \
    "service_cpu_set=$service_effective_cpu_set" \
    "load_generator_cpu_set=$load_client_probe_cpu_set" \
    "load_client_mount_target=$load_client_mount_target" \
    "load_client_mount_source=$load_client_mount_source" \
    "load_client_mount_fstype=$load_client_mount_fstype" \
    "load_client_mount_options=$load_client_mount_options" \
    "load_client_capacity_bytes=$load_client_capacity_bytes" \
    "load_client_available_bytes=$load_client_available_bytes" \
    'load_client_initial_state=empty' \
    'load_client_owner=0:0' \
    'load_client_mode=700' \
    'load_client_tmpdir=/mnt/load-client/tmp' \
    'load_client_cookie_path=/mnt/load-client/work/cookies.txt' \
    'server_storage_parent=/mnt/storage' \
    >"$evidence/resource-isolation.env"

native_stage=authenticated_load_setup
cookie=$load_client_workspace/cookies.txt
password='VaultLink api smoke password 123!'
totp_secret=$(grep -Eo '[A-Z2-7]{32}' "$api_work/setup-response.html" | head -n 1)
[ -n "$totp_secret" ] || fail "API fixture TOTP secret is unavailable"
totp_epoch=$(date +%s)
case "$totp_epoch" in *[!0-9]*|'') fail "clock is unavailable" ;; esac
sleep $((31 - totp_epoch % 30))
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
csrf=$(printf '%s' "$login" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf_token"])')
mfa=$(curl --fail --silent --show-error -b "$cookie" -c "$cookie" \
    -H 'content-type: application/json' -H "x-csrf-token: $csrf" -X POST \
    http://127.0.0.1:18081/api/v2/session/mfa -d "{\"code\":\"$totp_code\"}")
csrf=$(printf '%s' "$mfa" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf_token"])')

install -d -o vaultlink -g vaultlink -m 0750 \
    "$runtime_root/vaultlink-load" "$runtime_root/vaultlink-load/uploads"
setpriv --reuid="$vaultlink_uid" --regid="$vaultlink_gid" --init-groups -- \
    truncate -s 50G "$runtime_root/vaultlink-load/sparse-50GiB.bin"
create_share() {
    share_path=$1
    share_permission=$2
    curl --fail --silent --show-error -b "$cookie" \
        -H 'content-type: application/json' -H "x-csrf-token: $csrf" -X POST \
        http://127.0.0.1:18081/api/v2/shares \
        -d "{\"path\":\"$share_path\",\"permission\":\"$share_permission\",\"overwrite_allowed\":false}" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])'
}
download_token=$(create_share vaultlink-load/sparse-50GiB.bin download_only)
admission_download_token=$(create_share vaultlink-load/sparse-50GiB.bin download_only)
range_download_token=$(create_share vaultlink-load/sparse-50GiB.bin download_only)
upload_token=$(create_share vaultlink-load/uploads upload_only)
upload_token_2=$(create_share vaultlink-load/uploads upload_only)
upload_token_3=$(create_share vaultlink-load/uploads upload_only)
upload_token_4=$(create_share vaultlink-load/uploads upload_only)
upload_token_5=$(create_share vaultlink-load/uploads upload_only)
verify_token=$(create_share vaultlink-load/uploads download_upload)
for secret_value in \
    "$download_token" "$admission_download_token" "$range_download_token" \
    "$upload_token" "$upload_token_2" "$upload_token_3" "$upload_token_4" \
    "$upload_token_5" "$verify_token"; do
    [ -n "$secret_value" ] || fail "load share creation returned an empty token"
done

native_stage=authoritative_load
load_tmp=$load_client_mount/tmp
install -d -o root -g root -m 0700 "$load_tmp"
load_status=0
VAULTLINK_BASE_URL=http://127.0.0.1:18081 \
VAULTLINK_HEALTH_URL=http://127.0.0.1:18081/api/v2/health/ready \
DOWNLOAD_TOKEN=$download_token \
ADMISSION_DOWNLOAD_TOKEN=$admission_download_token \
RANGE_DOWNLOAD_TOKEN=$range_download_token \
UPLOAD_TOKEN=$upload_token \
UPLOAD_TOKEN_2=$upload_token_2 \
UPLOAD_TOKEN_3=$upload_token_3 \
UPLOAD_TOKEN_4=$upload_token_4 \
UPLOAD_TOKEN_5=$upload_token_5 \
UPLOAD_VERIFY_TOKEN=$verify_token \
SOAK_NAMESPACE="package-native-$target_id" \
LOAD_RUN_ID=native-package \
LOAD_P95_POLICY=strict \
LOAD_CONNECT_TIMEOUT_SECONDS=5 \
LOAD_METADATA_MAX_TIME_SECONDS=30 \
LOAD_TRANSFER_MAX_TIME_SECONDS=300 \
LOAD_PROFILE_READY_TIMEOUT_SECONDS=10 \
LOAD_ADMISSION_READY_TIMEOUT_SECONDS=10 \
LOAD_ADMISSION_HOLDER_MAX_TIME_SECONDS=30 \
LOAD_ADMISSION_PROBE_MAX_TIME_SECONDS=5 \
VAULTLINK_CONFIG="$runtime_config" \
VAULTLINK_DATABASE="$runtime_data/data.sqlite" \
SOAK_EXPECTED_VERSION="$version" \
VAULTLINK_PROCESS_PID="$service_pid" \
VAULTLINK_PROCESS_UID="$vaultlink_uid" \
VAULTLINK_PROCESS_GID="$vaultlink_gid" \
VAULTLINK_EXPECTED_BINARY_PATH="$live_binary" \
VAULTLINK_EXPECTED_BINARY_SHA256="$live_sha256" \
LOAD_TEST_EVIDENCE_DIR="$evidence/load" \
TMPDIR="$load_tmp" \
taskset --cpu-list "$load_client_cpu_set" sh tools/load-test.sh \
    >"$load_log" 2>&1 || load_status=$?
[ "$load_status" -eq 0 ] \
    || fail "authoritative 100/40/10 native load profile failed (status $load_status)"
rmdir "$load_tmp"

native_stage=evidence_verification
assert_field() {
    assert_file=$1
    assert_key=$2
    assert_value=$3
    [ "$(grep -F -x -c "$assert_key=$assert_value" "$assert_file" || true)" -eq 1 ] \
        || fail "$assert_file does not contain exact $assert_key evidence"
}
unique_field_value() {
    field_file=$1
    field_key=$2
    [ "$(grep -c "^${field_key}=" "$field_file" || true)" -eq 1 ] \
        || fail "$field_file must contain $field_key exactly once"
    sed -n "s/^${field_key}=//p" "$field_file"
}
result=$evidence/load/result.env
profile=$evidence/load/profile-status.env
pre_load=$evidence/load/pre-load.env
post_load=$evidence/load/post-load.env
load_command=$evidence/load/load-command.env
for evidence_file in "$result" "$profile" "$pre_load" "$post_load" "$load_command"; do
    if [ ! -s "$evidence_file" ] || [ -L "$evidence_file" ]; then
        fail "required native load evidence is missing"
    fi
done
assert_field "$load_command" stage complete
assert_field "$load_command" exit_status 0
assert_field "$result" supervision_mode direct_pid
assert_field "$result" metadata_p95_policy strict
assert_field "$result" metadata_p95_limit_seconds 2.000
assert_field "$result" metadata_p95_within_limit true
assert_field "$result" metadata_p95_enforced true
assert_field "$result" metadata_clients 100
assert_field "$result" metadata_requests 2000
assert_field "$result" range_streams 40
assert_field "$result" range_share_count 3
assert_field "$result" range_streams_per_share_max 14
assert_field "$result" uploads 10
assert_field "$result" upload_share_count 5
assert_field "$result" uploads_per_share 2
assert_field "$result" upload_integrity server_readback
assert_field "$profile" metadata_status 0
assert_field "$profile" download_status 0
assert_field "$profile" upload_status 0
assert_field "$profile" rss_status 0
assert_field "$profile" metadata_rows 2000
assert_field "$profile" range_rows 40
assert_field "$profile" upload_rows 10
assert_field "$profile" supervision_mode direct_pid
assert_field "$profile" metadata_p95_policy strict
assert_field "$profile" metadata_p95_limit_seconds 2.000
assert_field "$profile" metadata_p95_within_limit true
assert_field "$profile" metadata_p95_enforced true
rss_rows=$(unique_field_value "$profile" rss_rows)
case "$rss_rows" in *[!0-9]*|'') fail "native RSS row count is invalid" ;; esac
[ "$rss_rows" -gt 1 ] || fail "native RSS evidence contains no samples"
assert_field "$pre_load" supervision_mode direct_pid
assert_field "$post_load" supervision_mode direct_pid
assert_field "$pre_load" integrity ok
assert_field "$post_load" integrity ok
assert_field "$pre_load" pid "$service_pid"
assert_field "$post_load" pid "$service_pid"
assert_field "$pre_load" process_starttime_ticks "$service_starttime"
assert_field "$post_load" process_starttime_ticks "$service_starttime"
assert_field "$pre_load" binary_sha256 "$live_sha256"
assert_field "$post_load" binary_sha256 "$live_sha256"
assert_field "$pre_load" health_sha256 "$readiness_sha256"
assert_field "$post_load" health_sha256 "$readiness_sha256"
p95=$(unique_field_value "$result" metadata_p95_seconds)
awk -v value="$p95" 'BEGIN {
    exit !(value ~ /^[0-9]+([.][0-9]+)?$/ && value + 0 > 0 && value < 2.000)
}' || fail "native p95 is not a positive value below 2.000 seconds"
metadata_file=$evidence/load/metadata-load.csv
if [ ! -s "$metadata_file" ] || [ -L "$metadata_file" ]; then
    fail "native metadata evidence is missing"
fi
awk -F, '
    $1 !~ /^198\.18\.1\.[0-9]+$/ || $2 !~ /^2[0-9][0-9]$/ \
        || $3 !~ /^[0-9]+([.][0-9]+)?$/ || $3 + 0 <= 0 { exit 1 }
    {
        split($1, octets, ".")
        if (octets[4] < 1 || octets[4] > 100) exit 1
        seen[$1]++
    }
    END {
        if (NR != 2000) exit 1
        for (client = 1; client <= 100; client++)
            if (seen["198.18.1." client] != 20) exit 1
    }
' "$metadata_file" || fail "native metadata evidence is incomplete or invalid"
recomputed_p95=$(awk -F, '{ print $3 }' "$metadata_file" \
    | sort -n | awk 'NR == 1900 { print; exit }')
[ "$recomputed_p95" = "$p95" ] \
    || fail "native metadata p95 differs from the independently recomputed value"
[ "$(unique_field_value "$profile" metadata_observed_p95_seconds)" = "$p95" ] \
    || fail "native profile/result p95 evidence differs"
max_rss_kib=$(unique_field_value "$result" max_rss_kib)
case "$max_rss_kib" in *[!0-9]*|'') fail "native RSS evidence is invalid" ;; esac
[ "$max_rss_kib" -le 262144 ] || fail "native RSS exceeded 256 MiB"
rss_file=$evidence/load/rss-samples.csv
recomputed_max_rss=$(awk -F, -v expected_pid="$service_pid" '
    NR == 1 {
        if ($0 != "epoch,pid,rss_kib") exit 1
        next
    }
    $1 !~ /^[0-9]+$/ || $2 != expected_pid || $3 !~ /^[0-9]+$/ \
        || $3 > 262144 { exit 1 }
    { if ($3 > maximum) maximum = $3; rows++ }
    END {
        if (rows < 1) exit 1
        print maximum
    }
' "$rss_file") || fail "native RSS samples are incomplete or invalid"
[ "$recomputed_max_rss" = "$max_rss_kib" ] \
    || fail "native RSS maximum differs from the independently recomputed value"
range_sha256=$(unique_field_value "$result" range_sha256)
upload_sha256=$(unique_field_value "$result" upload_sha256)
assert_field "$result" range_bytes 67108864
assert_field "$result" fixture_bytes 53687091200
expected_content_range='bytes 0-67108863/53687091200'
awk -F, -v expected_hash="$range_sha256" \
    -v expected_content_range="$expected_content_range" '
    NF != 9 || $1 !~ /^[0-9]+$/ || $1 < 0 || $1 >= 40 \
        || $2 != "198.18.2." ($1 + 1) || $3 != 206 || $4 != 67108864 \
        || $5 != expected_hash || $6 != expected_content_range || seen[$1]++ { exit 1 }
    END {
        if (NR != 40) exit 1
        for (stream = 0; stream < 40; stream++) if (seen[stream] != 1) exit 1
    }
' "$evidence/load/range-results.csv" \
    || fail "native range evidence is incomplete or corrupt"
awk -F, -v expected_hash="$upload_sha256" -v target="$target_id" '
    NF != 8 || $1 !~ /^[0-9]+$/ || $1 < 0 || $1 >= 10 \
        || $2 != "198.18.3." ($1 + 1) || $3 != 303 || $4 != "created" \
        || $5 != expected_hash || $6 != 200 || $7 != expected_hash \
        || $8 != "load-package-native-" target "-native-package-" $1 ".bin" \
        || seen[$1]++ { exit 1 }
    END {
        if (NR != 10) exit 1
        for (upload = 0; upload < 10; upload++) if (seen[upload] != 1) exit 1
    }
' "$evidence/load/upload-results.csv" \
    || fail "native upload/readback evidence is incomplete or corrupt"
[ "$(sqlite3 "$runtime_data/data.sqlite" 'PRAGMA integrity_check;')" = ok ] \
    || fail "native load database integrity check failed"
kill -0 "$service_pid" 2>/dev/null || fail "package service exited during native load"
[ "$(verify_service_identity "$service_starttime")" = "$service_starttime" ] \
    || fail "package service identity or payload changed during native load"
[ "$(sed -n 's/^Cpus_allowed_list:[[:space:]]*//p' \
    "/proc/$service_pid/status")" = "$service_cpu_set" ] \
    || fail "package service CPU isolation changed during native load"
if [ "$(sha256sum "$candidate" | awk '{ print $1 }')" != "$candidate_sha256" ] \
    || [ "$(sha256sum "$live_binary" | awk '{ print $1 }')" != "$live_sha256" ]; then
    fail "installed package payload changed during native load"
fi
package_database_snapshot "$evidence/package-database-after.env" \
    || fail "package database changed during native load"
cmp -s "$evidence/package-database-before.env" \
    "$evidence/package-database-after.env" \
    || fail "package database state changed during native load"

printf '%s\n' \
    "target=$target_id" \
    "version=$version" \
    'execution=native_same_arch' \
    'network=none' \
    "package_sha256=$package_sha256" \
    "candidate_sha256=$candidate_sha256" \
    "active_binary_sha256=$live_sha256" \
    "service_uid=$vaultlink_uid" \
    "container_cpu_set=$container_effective_cpu_set" \
    "service_cpu_set=$service_effective_cpu_set" \
    "load_generator_cpu_set=$load_client_probe_cpu_set" \
    "load_client_mount_fstype=$load_client_mount_fstype" \
    "load_client_capacity_bytes=$load_client_capacity_bytes" \
    "service_starttime_ticks=$service_starttime" \
    "metadata_p95_seconds=$p95" \
    'metadata_p95_policy=strict' \
    'metadata_p95_limit_seconds=2.000' \
    'metadata_p95_within_limit=true' \
    'metadata_p95_enforced=true' \
    'supervision_mode=direct_pid' \
    'load_profile=100_metadata_40_ranges_10_uploads' \
    'package_database_parity=ok' \
    'payload_integrity=ok' \
    'readiness=ok' \
    "readiness_sha256=$readiness_sha256" \
    'sqlite_integrity=ok' \
    >"$evidence/native-package-load.env"

native_stage=complete
echo "native package load $target_id: OK (p95 $p95 seconds)"
