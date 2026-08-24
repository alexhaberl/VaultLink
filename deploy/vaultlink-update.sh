#!/bin/sh
set -eu
umask 077
LC_ALL=C
LANG=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL LANG
export PATH

repository=alexhaberl/VaultLink
github_origin=https://github.com
latest_release_url="$github_origin/$repository/releases/latest"
live_binary=/opt/vaultlink/vaultlink
live_config=/etc/vaultlink/config.toml
update_config=/etc/vaultlink/update.conf
public_key=/usr/share/vaultlink/minisign.pub
update_lock=/run/lock/vaultlink-update.lock
work_root=/var/tmp
archive_limit=536870912
metadata_limit=1048576

fail() {
    echo "VaultLink update failed: $*" >&2
    exit 1
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

for required_command in awk cmp curl dpkg find flock grep id install minisign \
    mktemp rm runuser sed sha256sum sort stat systemctl tar timeout tr uname uniq; do
    command -v "$required_command" >/dev/null \
        || fail "$required_command is required for signed updates"
done

validate_root_file() {
    checked_file=$1
    checked_label=$2
    if [ ! -f "$checked_file" ] || [ -L "$checked_file" ]; then
        fail "$checked_label must be a regular file"
    fi
    [ "$(stat -c %u "$checked_file")" -eq 0 ] \
        || fail "$checked_label must be owned by root"
    checked_mode=$(stat -c %a "$checked_file")
    case "$checked_mode" in
        ''|*[!0-7]*) fail "$checked_label has an invalid mode" ;;
    esac
    [ $((0$checked_mode & 0022)) -eq 0 ] \
        || fail "$checked_label must not be group- or world-writable"
}

read_auto_install() {
    if [ ! -e "$update_config" ]; then
        printf '%s\n' false
        return
    fi
    validate_root_file "$update_config" "update configuration"
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
    ' "$update_config" || fail "update configuration is invalid"
}

validate_stable_tag() {
    checked_tag=$1
    [ "${#checked_tag}" -le 64 ] || return 1
    awk -v tag="$checked_tag" '
        BEGIN {
            if (tag !~ /^v[0-9]+\.[0-9]+\.[0-9]+$/)
                exit 1
            sub(/^v/, "", tag)
            count = split(tag, parts, ".")
            if (count != 3)
                exit 1
            for (i = 1; i <= 3; i++) {
                if (length(parts[i]) > 1 && substr(parts[i], 1, 1) == "0")
                    exit 1
            }
        }
    '
}

read_bounded_version() {
    version_binary=$1
    version_label=$2
    if ! bounded_version=$(
        timeout --kill-after=2 5 runuser -u vaultlink -- \
            "$version_binary" --version
    ); then
        fail "$version_label does not provide a bounded --version response"
    fi
    case "$bounded_version" in
        ''|*[!0-9A-Za-z.+-]*) fail "$version_label returned an invalid version" ;;
    esac
    [ "${#bounded_version}" -le 128 ] \
        || fail "$version_label returned an invalid version"
    printf '%s\n' "$bounded_version"
}

# Keep SemVer precedence identical to the standalone upgrade and rollback
# scripts. Build metadata is ignored and pre-release identifiers retain their
# specified ordering.
compare_semver() {
    left_version=$1
    right_version=$2
    LC_ALL=C awk -v left="$left_version" -v right="$right_version" '
        function invalid(version) {
            print "invalid semantic version: " version > "/dev/stderr"
            exit 2
        }
        function identifiers_are_valid(value, reject_numeric_leading_zero, parts, count, i) {
            if (value == "")
                return 0
            count = split(value, parts, ".")
            for (i = 1; i <= count; i++) {
                if (parts[i] == "" || parts[i] !~ /^[0-9A-Za-z-]+$/)
                    return 0
                if (reject_numeric_leading_zero && parts[i] ~ /^[0-9]+$/ \
                    && length(parts[i]) > 1 && substr(parts[i], 1, 1) == "0")
                    return 0
            }
            return 1
        }
        function normalize(version, core, prerelease, build, separator, parts, count, i) {
            separator = index(version, "+")
            if (separator) {
                build = substr(version, separator + 1)
                version = substr(version, 1, separator - 1)
                if (!identifiers_are_valid(build, 0) || index(build, "+"))
                    invalid(version "+" build)
            }
            separator = index(version, "-")
            if (separator) {
                prerelease = substr(version, separator + 1)
                core = substr(version, 1, separator - 1)
                if (!identifiers_are_valid(prerelease, 1))
                    invalid(version)
            } else {
                prerelease = ""
                core = version
            }
            count = split(core, parts, ".")
            if (count != 3)
                invalid(version)
            for (i = 1; i <= 3; i++) {
                if (parts[i] !~ /^[0-9]+$/ \
                    || (length(parts[i]) > 1 && substr(parts[i], 1, 1) == "0"))
                    invalid(version)
            }
            return parts[1] "|" parts[2] "|" parts[3] "|" prerelease
        }
        function numeric_compare(left_number, right_number) {
            if (length(left_number) != length(right_number))
                return length(left_number) < length(right_number) ? -1 : 1
            if (left_number == right_number)
                return 0
            return ("x" left_number) < ("x" right_number) ? -1 : 1
        }
        function prerelease_compare(left_prerelease, right_prerelease, left_parts, right_parts, left_count, right_count, count, i, order, left_numeric, right_numeric) {
            if (left_prerelease == "" || right_prerelease == "") {
                if (left_prerelease == right_prerelease)
                    return 0
                return left_prerelease == "" ? 1 : -1
            }
            left_count = split(left_prerelease, left_parts, ".")
            right_count = split(right_prerelease, right_parts, ".")
            count = left_count < right_count ? left_count : right_count
            for (i = 1; i <= count; i++) {
                left_numeric = left_parts[i] ~ /^[0-9]+$/
                right_numeric = right_parts[i] ~ /^[0-9]+$/
                if (left_numeric && right_numeric) {
                    order = numeric_compare(left_parts[i], right_parts[i])
                } else if (left_numeric != right_numeric) {
                    order = left_numeric ? -1 : 1
                } else if (left_parts[i] == right_parts[i]) {
                    order = 0
                } else {
                    order = ("x" left_parts[i]) < ("x" right_parts[i]) ? -1 : 1
                }
                if (order != 0)
                    return order
            }
            if (left_count == right_count)
                return 0
            return left_count < right_count ? -1 : 1
        }
        BEGIN {
            split(normalize(left), left_parts, "|")
            split(normalize(right), right_parts, "|")
            for (i = 1; i <= 3; i++) {
                order = numeric_compare(left_parts[i], right_parts[i])
                if (order != 0) {
                    print order
                    exit
                }
            }
            print prerelease_compare(left_parts[4], right_parts[4])
        }
    '
}

curl_common() {
    curl \
        --fail \
        --silent \
        --show-error \
        --location \
        --max-redirs 5 \
        --proto '=https' \
        --proto-redir '=https' \
        --tlsv1.2 \
        --connect-timeout 10 \
        --max-time 180 \
        --retry 3 \
        --retry-delay 2 \
        --retry-max-time 45 \
        --user-agent 'VaultLink signed release updater' \
        "$@"
}

fetch_latest_tag() {
    if ! effective_url=$(
        curl_common \
            --max-filesize "$metadata_limit" \
            --output /dev/null \
            --write-out '%{url_effective}' \
            "$latest_release_url"
    ); then
        fail "the latest GitHub release could not be resolved"
    fi
    release_prefix="$github_origin/$repository/releases/tag/"
    case "$effective_url" in
        "$release_prefix"*) latest_tag=${effective_url#"$release_prefix"} ;;
        *) fail "GitHub redirected the latest release outside the expected repository" ;;
    esac
    validate_stable_tag "$latest_tag" \
        || fail "the latest GitHub release tag is not a stable SemVer tag"
    printf '%s\n' "$latest_tag"
}

download_asset() {
    asset_name=$1
    asset_limit=$2
    asset_destination=$3
    asset_url="$github_origin/$repository/releases/download/$latest_tag/$asset_name"
    curl_common \
        --max-filesize "$asset_limit" \
        --output "$asset_destination" \
        "$asset_url" \
        || fail "could not download signed release asset $asset_name"
    [ -s "$asset_destination" ] \
        || fail "downloaded release asset $asset_name is empty"
    asset_size=$(stat -c %s "$asset_destination")
    [ "$asset_size" -le "$asset_limit" ] \
        || fail "downloaded release asset $asset_name exceeds its size limit"
}

validate_root_file "$live_binary" "installed VaultLink binary"
validate_root_file "$live_config" "installed VaultLink configuration"
validate_root_file "$public_key" "VaultLink release public key"
[ -x "$live_binary" ] || fail "installed VaultLink binary is not executable"
id vaultlink >/dev/null 2>&1 || fail "the vaultlink service account is missing"

os_id=$(sed -n 's/^ID=//p' /etc/os-release | sed -n '1p' | tr -d '"')
os_version=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | sed -n '1p' | tr -d '"')
if [ "$os_id" != debian ] || [ "$os_version" != 13 ]; then
    fail "signed automatic updates support Debian 13 only"
fi

architecture=$(dpkg --print-architecture)
machine=$(uname -m)
case "$architecture:$machine" in
    amd64:x86_64|arm64:aarch64) ;;
    *) fail "unsupported or inconsistent host architecture $architecture/$machine" ;;
esac

install -d -o root -g root -m 0755 /run/lock
exec 9>"$update_lock"
flock -n 9 || fail "another VaultLink update check is already running"

installed_version=$(read_bounded_version "$live_binary" "installed binary")
latest_tag=$(fetch_latest_tag)
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

if [ "$action" = check ]; then
    exit 0
fi
if [ "$action" = auto ]; then
    auto_install_value=$(read_auto_install) \
        || fail "automatic update policy could not be read safely"
    if [ "$auto_install_value" != true ]; then
        printf 'auto_install=false\n'
        exit 0
    fi
    systemctl --quiet is-active vaultlink.service \
        || fail "automatic installation requires an active vaultlink.service"
fi

work=$(mktemp -d "$work_root/vaultlink-update.XXXXXXXX") \
    || fail "could not create the protected update directory"
cleanup() {
    rm -rf -- "$work"
}
trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

archive="VaultLink-$latest_version-debian13-$architecture.tar.gz"
archive_signature="$archive.minisig"
checksums="SHA256SUMS-$architecture"
checksums_signature="$checksums.minisig"
download_asset "$archive" "$archive_limit" "$work/$archive"
download_asset "$archive_signature" "$metadata_limit" "$work/$archive_signature"
download_asset "$checksums" "$metadata_limit" "$work/$checksums"
download_asset "$checksums_signature" "$metadata_limit" "$work/$checksums_signature"

minisign -V -q -p "$public_key" \
    -m "$work/$archive" -x "$work/$archive_signature" \
    || fail "release archive signature verification failed"
minisign -V -q -p "$public_key" \
    -m "$work/$checksums" -x "$work/$checksums_signature" \
    || fail "release checksum signature verification failed"

expected_archive_sha256=$(
    awk -v expected_file="$archive" '
        $2 == expected_file && $1 ~ /^[0-9a-f]{64}$/ {
            checksum = $1
            matches++
        }
        END {
            if (matches != 1)
                exit 1
            print checksum
        }
    ' "$work/$checksums"
) || fail "signed checksum manifest does not identify the release archive exactly once"
actual_archive_sha256=$(sha256sum "$work/$archive" | awk '{print $1}')
[ "$actual_archive_sha256" = "$expected_archive_sha256" ] \
    || fail "release archive checksum verification failed"

release_root="VaultLink-$latest_version-debian13-$architecture"
tar -tzf "$work/$archive" >"$work/archive.list" \
    || fail "release archive could not be listed"
[ -s "$work/archive.list" ] || fail "release archive is empty"
tar -tvzf "$work/$archive" >"$work/archive.verbose" \
    || fail "release archive metadata could not be listed"
awk '
    NF < 6 { exit 1 }
    substr($1, 1, 1) != "-" && substr($1, 1, 1) != "d" { exit 1 }
    $3 !~ /^[0-9]+$/ { exit 1 }
    {
        entries++
        total += $3
        if ($3 > 536870912 || entries > 10000 || total > 1073741824)
            exit 1
    }
' "$work/archive.verbose" \
    || fail "release archive contains unsafe types, sizes, or entry counts"
duplicate_entry=$(sort "$work/archive.list" | uniq -d | sed -n '1p')
[ -z "$duplicate_entry" ] || fail "release archive contains a duplicate path"
while IFS= read -r archive_entry; do
    case "$archive_entry" in
        "$release_root"|"$release_root/"*) ;;
        *) fail "release archive contains an entry outside its versioned root" ;;
    esac
    case "$archive_entry" in
        /*|*//*|..|../*|*/..|*/../*|.|./*|*/.|*/./*) fail "release archive contains an unsafe path" ;;
        *[!A-Za-z0-9._/@+~-]*) fail "release archive contains an unsafe path character" ;;
    esac
done <"$work/archive.list"

install -d -o root -g root -m 0700 "$work/extracted"
tar --no-same-owner --no-same-permissions \
    -xzf "$work/$archive" -C "$work/extracted" \
    || fail "release archive extraction failed"
extracted_root="$work/extracted/$release_root"
if [ ! -d "$extracted_root" ] || [ -L "$extracted_root" ]; then
    fail "release archive root is invalid"
fi
unexpected_type=$(find "$extracted_root" ! -type d ! -type f -print -quit)
[ -z "$unexpected_type" ] \
    || fail "release archive contains a link or special file"
unexpected_hardlink=$(find "$extracted_root" -type f -links +1 -print -quit)
[ -z "$unexpected_hardlink" ] \
    || fail "release archive contains a hard-linked file"

candidate_binary="$extracted_root/bin/vaultlink"
candidate_upgrade="$extracted_root/deploy/vaultlink-upgrade.sh"
candidate_public_key="$extracted_root/minisign.pub"
if [ ! -f "$candidate_binary" ] || [ -L "$candidate_binary" ] \
    || [ ! -x "$candidate_binary" ]; then
    fail "release archive does not contain an executable VaultLink binary"
fi
if [ ! -f "$candidate_upgrade" ] || [ -L "$candidate_upgrade" ] \
    || [ ! -x "$candidate_upgrade" ]; then
    fail "release archive does not contain an executable upgrade helper"
fi
if [ ! -f "$candidate_public_key" ] || [ -L "$candidate_public_key" ]; then
    fail "release archive does not contain the release public key"
fi
validate_root_file "$candidate_binary" "candidate VaultLink binary"
validate_root_file "$candidate_upgrade" "candidate upgrade helper"
validate_root_file "$candidate_public_key" "candidate release public key"
cmp -s "$public_key" "$candidate_public_key" \
    || fail "release archive attempts to replace the pinned release public key"

# The candidate is root-owned and immutable to the service account. Open only
# directory traversal plus binary read/execute so the same unprivileged version
# preflight used by manual upgrades can run; signatures, manifests, and helpers
# remain inside the otherwise root-only workspace.
chmod 0711 "$work" "$work/extracted" "$extracted_root" "$extracted_root/bin"
chmod 0755 "$candidate_binary"
candidate_version=$(read_bounded_version "$candidate_binary" "candidate binary")
[ "$candidate_version" = "$latest_version" ] \
    || fail "candidate binary version does not match the signed release tag"

# The helper is covered by the verified archive signature and may contain the
# migration orchestration required by the candidate. It still performs its own
# complete backup, preflight, readiness, integrity, and automatic restore.
backup_directory=$("$candidate_upgrade" "$candidate_binary" "$live_config") \
    || fail "the verified upgrade helper rejected or rolled back the update"
printf 'backup_directory=%s\n' "$backup_directory"
printf 'update_installed=true\n'
