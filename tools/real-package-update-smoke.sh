#!/bin/sh
# Exercise the production updater with real native package transactions. Only
# GitHub transport and systemd supervision are adapted inside the disposable
# container; dpkg/rpm/pacman is always delegated to the real distro binary.
# Compound assertions intentionally use A && B || fail as fail-closed guards.
# shellcheck disable=SC2015
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CDPATH=
LC_ALL=C
LANG=C
export PATH CDPATH LC_ALL LANG
umask 077

fail() {
    echo "real package update smoke failed: $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "the real package update smoke must run as root"
[ -f /.dockerenv ] \
    || fail "refusing destructive package transactions outside a disposable Docker container"
[ "$#" -eq 5 ] || {
    echo "usage: $0 TARGET_ID OLD_VERSION OLD_PACKAGE NEW_VERSION NEW_PACKAGE" >&2
    exit 64
}

target_id=$1
old_version=$2
old_package=$3
new_version=$4
new_package=$5
case "$target_id" in ''|*[!a-z0-9-]*) fail "unsafe target ID" ;; esac
for release_version in "$old_version" "$new_version"; do
    printf '%s\n' "$release_version" \
        | grep -E -q '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' \
        || fail "versions must be strict stable MAJOR.MINOR.PATCH values"
done
awk -v old="$old_version" -v new="$new_version" '
    BEGIN {
        split(old, left, "."); split(new, right, ".")
        for (i = 1; i <= 3; i++) {
            if ((left[i] + 0) < (right[i] + 0)) exit 0
            if ((left[i] + 0) > (right[i] + 0)) exit 1
        }
        exit 1
    }
' || fail "NEW_VERSION must be newer than OLD_VERSION"

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
cd "$repo_root"

absolute_regular_file() {
    input_file=$1
    [ -f "$input_file" ] && [ ! -L "$input_file" ] && [ -s "$input_file" ] \
        || return 1
    input_directory=$(cd -- "$(dirname -- "$input_file")" && pwd) || return 1
    printf '%s/%s\n' "$input_directory" "$(basename -- "$input_file")"
}

old_package=$(absolute_regular_file "$old_package") \
    || fail "OLD_PACKAGE must be a non-empty regular file"
new_package=$(absolute_regular_file "$new_package") \
    || fail "NEW_PACKAGE must be a non-empty regular file"

for required_command in awk bash cat chmod chown cmp cp curl date du find flock \
    getent grep gzip install kill minisign mktemp mv python3 readlink rm runuser \
    sed sha256sum sleep sort sqlite3 stat systemctl tail tar timeout touch uname; do
    command -v "$required_command" >/dev/null \
        || fail "$required_command is required for the real update smoke"
done
[ -f release/package-targets.json ] && [ -f tools/package-targets.py ] \
    || fail "package target manifest tooling is unavailable"
python3 tools/package-targets.py validate --allow-unprovisioned >/dev/null

target_get() {
    python3 tools/package-targets.py get "$target_id" "$1" --allow-unprovisioned
}

os_id=$(target_get distribution)
os_version=$(target_get version)
package_format=$(target_get package_format)
package_arch=$(target_get package_arch)
expected_uname=$(target_get uname)
[ "$(uname -m)" = "$expected_uname" ] \
    || fail "$target_id must run natively on $expected_uname"
if [ "$os_id" = arch ]; then
    os_version=rolling
fi

old_asset=$(python3 tools/package-targets.py asset \
    "$target_id" "$old_version" --allow-unprovisioned)
new_asset=$(python3 tools/package-targets.py asset \
    "$target_id" "$new_version" --allow-unprovisioned)
[ "$(basename -- "$old_package")" = "$old_asset" ] \
    || fail "OLD_PACKAGE asset name does not match the target manifest"
[ "$(basename -- "$new_package")" = "$new_asset" ] \
    || fail "NEW_PACKAGE asset name does not match the target manifest"

case "$package_format" in
    deb)
        for required_command in ar dpkg dpkg-deb dpkg-query xz; do
            command -v "$required_command" >/dev/null \
                || fail "$required_command is required for a DEB transaction"
        done
        native_manager=dpkg
        ;;
    rpm)
        for required_command in cpio rpm rpm2cpio rpmbuild; do
            command -v "$required_command" >/dev/null \
                || fail "$required_command is required for an RPM transaction"
        done
        native_manager=rpm
        ;;
    pkg.tar.zst)
        for required_command in bsdtar pacman zstd; do
            command -v "$required_command" >/dev/null \
                || fail "$required_command is required for an Arch transaction"
        done
        native_manager=pacman
        ;;
    *) fail "unsupported package format: $package_format" ;;
esac
for required_command in curl minisign python3 runuser sqlite3 systemctl; do
    command -v "$required_command" >/dev/null \
        || fail "$required_command is required for the real update smoke"
done

package_is_installed() {
    case "$package_format" in
        deb) [ "$(dpkg-query -W -f='${db:Status-Status}' vaultlink 2>/dev/null || true)" = installed ] ;;
        rpm) rpm -q vaultlink >/dev/null 2>&1 ;;
        pkg.tar.zst) pacman -Q vaultlink >/dev/null 2>&1 ;;
    esac
}

package_is_installed && fail "the disposable container already has VaultLink installed"
for identity_database in passwd group shadow; do
    ! getent "$identity_database" vaultlink >/dev/null 2>&1 \
        || fail "the disposable container already has a vaultlink $identity_database entry"
done
for clean_path in \
    /opt/vaultlink/vaultlink \
    /etc/vaultlink/config.toml \
    /var/lib/vaultlink/data.sqlite \
    /var/lib/vaultlink/secrets.keyring \
    /usr/lib/vaultlink/package \
    /usr/share/vaultlink/install-method.env; do
    [ ! -e "$clean_path" ] && [ ! -L "$clean_path" ] \
        || fail "the disposable container is not clean: $clean_path"
done

work=$(mktemp -d /var/tmp/vaultlink-real-package-update.XXXXXXXX)
chown root:root "$work"
chmod 0700 "$work"
api_work=/tmp/vaultlink-real-package-update-api.$$
curl_runtime=/var/tmp/vaultlink-real-package-update-curl.$$
real_curl_path=$curl_runtime/curl
service_state=$work/service-state
real_manager_directory=$work/real-manager
install -d -o root -g root -m 0700 \
    "$service_state" "$real_manager_directory"

stop_fixture_service() {
    pid_file=$service_state/pid
    if [ -f "$pid_file" ]; then
        fixture_pid=$(cat "$pid_file" 2>/dev/null || true)
        case "$fixture_pid" in ''|*[!0-9]*) ;;
            *)
                kill "$fixture_pid" 2>/dev/null || :
                fixture_wait=0
                while kill -0 "$fixture_pid" 2>/dev/null \
                    && [ "$fixture_wait" -lt 50 ]; do
                    sleep 0.1
                    fixture_wait=$((fixture_wait + 1))
                done
                kill -9 "$fixture_pid" 2>/dev/null || :
                ;;
        esac
        rm -f "$pid_file"
    fi
}

restore_overlay() {
    overlay_name=$1
    overlay_record=$work/overlay-$overlay_name.path
    overlay_original=$work/overlay-$overlay_name.original
    [ -f "$overlay_record" ] || return 0
    overlay_target=$(cat "$overlay_record")
    case "$overlay_target" in /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*) ;;
        *) return 1 ;;
    esac
    rm -f -- "$overlay_target"
    if [ -e "$overlay_original" ] || [ -L "$overlay_original" ]; then
        mv -- "$overlay_original" "$overlay_target"
    fi
}

cleanup() {
    cleanup_status=$?
    trap - 0 1 2 15
    trap '' 1 2 15
    stop_fixture_service
    restore_overlay "$native_manager" || :
    restore_overlay systemctl || :
    restore_overlay curl || :
    case "$api_work" in /tmp/vaultlink-real-package-update-api.*) rm -rf -- "$api_work" ;; esac
    case "$curl_runtime" in
        /var/tmp/vaultlink-real-package-update-curl.*) rm -rf -- "$curl_runtime" ;;
    esac
    case "$work" in /var/tmp/vaultlink-real-package-update.*) rm -rf -- "$work" ;; esac
    exit "$cleanup_status"
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

case "$curl_runtime" in /var/tmp/vaultlink-real-package-update-curl.*) ;;
    *) fail "unsafe curl runtime fixture path" ;;
esac
[ ! -e "$curl_runtime" ] && [ ! -L "$curl_runtime" ] \
    || fail "curl runtime fixture path already exists"
install -d -o root -g root -m 0755 "$curl_runtime"

expected_database_version() {
    database_semver=$1
    case "$package_format:$os_id:$os_version" in
        deb:debian:13) printf '%s-1+deb13\n' "$database_semver" ;;
        deb:ubuntu:24.04) printf '%s-1+ubuntu24.04\n' "$database_semver" ;;
        deb:ubuntu:26.04) printf '%s-1+ubuntu26.04\n' "$database_semver" ;;
        rpm:fedora:44) printf '%s-1.fc44\n' "$database_semver" ;;
        pkg.tar.zst:arch:rolling) printf '%s-1\n' "$database_semver" ;;
        *) return 1 ;;
    esac
}

validate_input_metadata() {
    metadata_version=$1
    metadata_package=$2
    metadata_expected=$(expected_database_version "$metadata_version") || return 1
    case "$package_format" in
        deb)
            [ "$(dpkg-deb -f "$metadata_package" Package)" = vaultlink ] \
                && [ "$(dpkg-deb -f "$metadata_package" Version)" = "$metadata_expected" ] \
                && [ "$(dpkg-deb -f "$metadata_package" Architecture)" = "$package_arch" ]
            ;;
        rpm)
            [ "$(rpm -qp --qf '%{NAME}' "$metadata_package")" = vaultlink ] \
                && [ "$(rpm -qp --qf '%{EPOCHNUM}' "$metadata_package")" = 0 ] \
                && [ "$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$metadata_package")" = "$metadata_expected" ] \
                && [ "$(rpm -qp --qf '%{ARCH}' "$metadata_package")" = "$package_arch" ]
            ;;
        pkg.tar.zst)
            metadata_pkginfo=$work/input-$metadata_version.PKGINFO
            bsdtar -xOf "$metadata_package" .PKGINFO >"$metadata_pkginfo"
            [ "$(sed -n 's/^pkgname = //p' "$metadata_pkginfo")" = vaultlink ] \
                && [ "$(sed -n 's/^pkgver = //p' "$metadata_pkginfo")" = "$metadata_expected" ] \
                && [ "$(sed -n 's/^arch = //p' "$metadata_pkginfo")" = "$package_arch" ]
            ;;
    esac
}

extract_member() {
    source_package=$1
    package_member=$2
    member_output=$3
    rm -f "$member_output"
    case "$package_format" in
        deb)
            member_tar=$work/member-$(basename -- "$member_output").tar
            dpkg-deb --fsys-tarfile "$source_package" >"$member_tar"
            if ! tar -xOf "$member_tar" "./$package_member" \
                >"$member_output" 2>/dev/null; then
                tar -xOf "$member_tar" "$package_member" >"$member_output"
            fi
            ;;
        rpm)
            member_cpio=$work/member-$(basename -- "$member_output").cpio
            rpm2cpio "$source_package" >"$member_cpio"
            cpio --quiet -i --to-stdout "./$package_member" \
                <"$member_cpio" >"$member_output"
            ;;
        pkg.tar.zst)
            if ! bsdtar -xOf "$source_package" "$package_member" \
                >"$member_output" 2>/dev/null; then
                bsdtar -xOf "$source_package" "./$package_member" >"$member_output"
            fi
            ;;
    esac
    [ -s "$member_output" ] || fail "package member is empty: $package_member"
}

validate_input_metadata "$old_version" "$old_package" \
    || fail "OLD_PACKAGE metadata does not match its declared target/version"
validate_input_metadata "$new_version" "$new_package" \
    || fail "NEW_PACKAGE metadata does not match its declared target/version"

input_old=$work/input-old
input_new=$work/input-new
install -d -o root -g root -m 0700 "$input_old" "$input_new"
extract_member "$old_package" usr/lib/vaultlink/package/vaultlink "$input_old/vaultlink"
extract_member "$old_package" usr/lib/vaultlink/package/vaultlink.cdx.json "$input_old/vaultlink.cdx.json"
extract_member "$new_package" usr/lib/vaultlink/package/vaultlink "$input_new/vaultlink"
extract_member "$new_package" usr/lib/vaultlink/package/vaultlink.cdx.json "$input_new/vaultlink.cdx.json"
chmod 0755 "$input_old/vaultlink" "$input_new/vaultlink"
[ "$(timeout --kill-after=2 5 "$input_old/vaultlink" --version)" = "$old_version" ] \
    || fail "OLD_PACKAGE payload binary reports the wrong version"
[ "$(timeout --kill-after=2 5 "$input_new/vaultlink" --version)" = "$new_version" ] \
    || fail "NEW_PACKAGE payload binary reports the wrong version"

fixture_repo=$work/repo
install -d -o root -g root -m 0700 "$fixture_repo"
for source_entry in config deploy packaging release tools; do
    cp -a "$repo_root/$source_entry" "$fixture_repo/"
done
cp -a "$repo_root/LICENSE" "$fixture_repo/LICENSE"

minisign -G -W -p "$work/minisign.pub" -s "$work/minisign.key" >/dev/null
install -o root -g root -m 0644 "$work/minisign.pub" \
    "$fixture_repo/release/minisign.pub"

source_date_epoch=$(date +%s)
normal_old=$work/packages-old
normal_new=$work/packages-new
missing_new=$work/packages-new-missing
install -d -o root -g root -m 0700 "$normal_old" "$normal_new" "$missing_new"
SOURCE_DATE_EPOCH=$source_date_epoch sh "$fixture_repo/tools/build-native-package.sh" \
    "$target_id" "$old_version" "$input_old/vaultlink" \
    "$input_old/vaultlink.cdx.json" "$normal_old" >/dev/null
SOURCE_DATE_EPOCH=$source_date_epoch sh "$fixture_repo/tools/build-native-package.sh" \
    "$target_id" "$new_version" "$input_new/vaultlink" \
    "$input_new/vaultlink.cdx.json" "$normal_new" >/dev/null

missing_dependency=vaultlink-real-update-missing-dependency
case "$package_format" in
    deb) ! dpkg-query -W "$missing_dependency" >/dev/null 2>&1 ;;
    rpm) ! rpm -q "$missing_dependency" >/dev/null 2>&1 ;;
    pkg.tar.zst) ! pacman -Q "$missing_dependency" >/dev/null 2>&1 ;;
esac || fail "the additive dependency fixture is unexpectedly installed"
case "$package_format" in
    deb)
        for dependency_script in \
            "$fixture_repo/tools/build-native-package.sh" \
            "$fixture_repo/tools/verify-native-package.sh"; do
            sed -i \
                "s/^Depends: ca-certificates, curl, libc6, libgcc-s1, mawk, minisign, sqlite3, systemd$/&, $missing_dependency/" \
                "$dependency_script"
            grep -F -q "systemd, $missing_dependency" "$dependency_script" \
                || fail "could not inject the DEB missing-dependency fixture"
        done
        sed -i \
            "s/ca-certificates, curl, libc6, libgcc-s1, mawk, minisign, sqlite3, systemd'/ca-certificates, curl, libc6, libgcc-s1, mawk, minisign, sqlite3, systemd, $missing_dependency'/" \
            "$fixture_repo/tools/verify-native-package.sh"
        [ "$(grep -F -c "systemd, $missing_dependency" \
            "$fixture_repo/tools/verify-native-package.sh")" -eq 2 ] \
            || fail "could not inject the DEB verifier dependency allowlist fixture"
        ;;
    rpm)
        sed -i \
            "s/^Requires: bash, ca-certificates, coreutils, cpio, curl, diffutils, findutils, gawk, glibc, grep, gzip, libgcc, minisign, rpm, sed, sqlite, systemd, tar, util-linux$/&, $missing_dependency/" \
            "$fixture_repo/tools/build-native-package.sh"
        sed -i "/^util-linux$/a $missing_dependency" \
            "$fixture_repo/tools/verify-native-package.sh"
        grep -F -q "util-linux, $missing_dependency" \
            "$fixture_repo/tools/build-native-package.sh" \
            || fail "could not inject the RPM missing-dependency fixture"
        [ "$(grep -F -x -c "$missing_dependency" \
            "$fixture_repo/tools/verify-native-package.sh")" -eq 2 ] \
            || fail "could not inject the RPM verifier fixture"
        ;;
    pkg.tar.zst)
        sed -i "/^  'zstd'$/a\\  '$missing_dependency'" \
            "$fixture_repo/packaging/arch/PKGBUILD"
        sed -i "/^depend = zstd$/a depend = $missing_dependency" \
            "$fixture_repo/tools/verify-native-package.sh"
        sed -i "/^zstd$/a $missing_dependency" \
            "$fixture_repo/tools/verify-native-package.sh"
        sed -i 's/makepkg --noconfirm/makepkg --nodeps --noconfirm/' \
            "$fixture_repo/tools/build-native-package.sh"
        grep -F -x -q "  '$missing_dependency'" \
            "$fixture_repo/packaging/arch/PKGBUILD" \
            || fail "could not inject the Arch PKGBUILD dependency fixture"
        [ "$(grep -F -c "depend = $missing_dependency" \
            "$fixture_repo/tools/verify-native-package.sh")" -eq 1 ] \
            || fail "could not inject the Arch missing-dependency fixture"
        ;;
esac
SOURCE_DATE_EPOCH=$source_date_epoch sh "$fixture_repo/tools/build-native-package.sh" \
    "$target_id" "$new_version" "$input_new/vaultlink" \
    "$input_new/vaultlink.cdx.json" "$missing_new" >/dev/null

archive_fixture_empty=
archive_fixture_parent=
archive_fixture_duplicate_root=
make_deb_archive_fixture() {
    fixture_kind=$1
    fixture_source=$2
    fixture_output=$3
    fixture_directory=$work/deb-archive-$fixture_kind
    install -d -o root -g root -m 0700 "$fixture_directory"
    (
        cd "$fixture_directory"
        ar x "$fixture_source"
        [ "$(ar t "$fixture_source")" = "$(printf '%s\n' \
            debian-binary control.tar.xz data.tar.xz)" ] \
            || fail "unexpected DEB ar member inventory"
        xz -dc data.tar.xz >data.tar
        python3 - data.tar data.fixture.tar "$fixture_kind" <<'PY'
import sys

source, destination, variant = sys.argv[1:]
block = 512
payload = bytearray(open(source, "rb").read())
if not payload or len(payload) % block:
    raise SystemExit("invalid source tar size")

entries = []
offset = 0
end_offset = None
while offset + block <= len(payload):
    header = bytes(payload[offset:offset + block])
    if header == b"\0" * block:
        end_offset = offset
        break
    raw_size = header[124:136]
    if raw_size and raw_size[0] & 0x80:
        raise SystemExit("base-256 tar sizes are outside this fixture")
    size_text = raw_size.split(b"\0", 1)[0].strip(b" ") or b"0"
    size = int(size_text, 8)
    name = header[0:100].split(b"\0", 1)[0]
    prefix = header[345:500].split(b"\0", 1)[0]
    if prefix:
        name = prefix + b"/" + name
    entries.append((offset, name, size, header))
    offset += block + ((size + block - 1) // block) * block

if end_offset is None:
    raise SystemExit("source tar has no end marker")
roots = [entry for entry in entries if entry[1] in (b".", b"./")]
if len(roots) != 1 or roots[0][2] != 0:
    raise SystemExit("source tar must contain exactly one empty root directory entry")
root_offset, _, _, root_header = roots[0]

def renamed_root(name):
    encoded = name.encode("ascii")
    if len(encoded) > 99:
        raise SystemExit("fixture name is too long")
    header = bytearray(root_header)
    header[0:100] = b"\0" * 100
    header[345:500] = b"\0" * 155
    header[0:len(encoded)] = encoded
    header[148:156] = b" " * 8
    checksum = sum(header)
    checksum_field = ("%06o\0 " % checksum).encode("ascii")
    if len(checksum_field) != 8:
        raise SystemExit("fixture checksum overflow")
    header[148:156] = checksum_field
    return header

if variant == "empty":
    payload[root_offset:root_offset + block] = renamed_root("")
elif variant == "parent":
    payload[root_offset:root_offset + block] = renamed_root("../")
elif variant == "duplicate-root":
    payload[end_offset:end_offset] = root_header
else:
    raise SystemExit("unknown archive fixture")

with open(destination, "wb") as output:
    output.write(payload)
PY
        xz --threads=1 -9 --check=crc64 -c data.fixture.tar >data.tar.xz.new
        mv -f data.tar.xz.new data.tar.xz
        ar cr "$fixture_output.stage" debian-binary control.tar.xz data.tar.xz
    )
    install -o root -g root -m 0600 "$fixture_output.stage" "$fixture_output"
    rm -f -- "$fixture_output.stage"
    [ "$(dpkg-deb -f "$fixture_output" Package)" = vaultlink ] \
        || fail "malformed DEB fixture lost its control metadata"
}

if [ "$package_format" = deb ]; then
    archive_fixture_empty=$work/new-empty.deb
    archive_fixture_parent=$work/new-parent.deb
    archive_fixture_duplicate_root=$work/new-duplicate-root.deb
    make_deb_archive_fixture empty "$normal_new/$new_asset" \
        "$archive_fixture_empty"
    make_deb_archive_fixture parent "$normal_new/$new_asset" \
        "$archive_fixture_parent"
    make_deb_archive_fixture duplicate-root "$normal_new/$new_asset" \
        "$archive_fixture_duplicate_root"
fi

fixture_assets=$work/assets
install -d -o root -g root -m 0700 "$fixture_assets"
publish_release() {
    publish_version=$1
    publish_package=$2
    publish_asset=$(python3 "$repo_root/tools/package-targets.py" asset \
        "$target_id" "$publish_version" --allow-unprovisioned)
    publish_directory=$fixture_assets/v$publish_version
    rm -rf -- "$publish_directory"
    install -d -o root -g root -m 0700 "$publish_directory"
    install -o root -g root -m 0600 "$publish_package" \
        "$publish_directory/$publish_asset"
    minisign -S -q -s "$work/minisign.key" \
        -m "$publish_directory/$publish_asset" \
        -x "$publish_directory/$publish_asset.minisig"
    (
        cd "$publish_directory"
        sha256sum "$publish_asset" >SHA256SUMS
    )
    minisign -S -q -s "$work/minisign.key" \
        -m "$publish_directory/SHA256SUMS" \
        -x "$publish_directory/SHA256SUMS.minisig"
}
publish_release "$old_version" "$normal_old/$old_asset"
publish_release "$new_version" "$missing_new/$new_asset"

write_curl_wrapper() {
    wrapper_file=$work/curl.wrapper
    cat >"$wrapper_file" <<'EOF'
#!/bin/sh
set -eu
fixture_assets=@ASSETS@
latest_version=@LATEST@
real_curl=@REAL@
fixture_url=
for fixture_argument do
    case "$fixture_argument" in
        https://github.com/alexhaberl/VaultLink/releases/latest|\
        https://github.com/alexhaberl/VaultLink/releases/download/*|\
        https://release-assets.githubusercontent.com/github-production-release-asset/vaultlink-real-update/*)
            fixture_url=$fixture_argument
            ;;
    esac
done
[ -n "$fixture_url" ] || exec "$real_curl" "$@"
output=
write_out=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --max-redirs|--proto|--proto-redir|--connect-timeout|--max-time|--retry|--retry-delay|--retry-max-time|--user-agent|--max-filesize|--output|--write-out|--noproxy|--header|--connect-to)
            [ "$#" -ge 2 ] || exit 64
            case "$1" in --output) output=$2 ;; --write-out) write_out=$2 ;; esac
            shift 2
            ;;
        --fail|--silent|--show-error|--location|--tlsv1.2|--disable|--insecure)
            shift
            ;;
        --) shift ;;
        --*) exit 64 ;;
        *) shift ;;
    esac
done
case "$fixture_url" in
    https://github.com/alexhaberl/VaultLink/releases/latest)
        [ "$output" = /dev/null ]
        [ "$write_out" = '%{http_code}\n%{redirect_url}' ]
        printf '302\nhttps://github.com/alexhaberl/VaultLink/releases/tag/v%s' "$latest_version"
        ;;
    https://github.com/alexhaberl/VaultLink/releases/download/*)
        [ "$output" = /dev/null ]
        [ "$write_out" = '%{http_code}\n%{redirect_url}' ]
        relative=${fixture_url#https://github.com/alexhaberl/VaultLink/releases/download/}
        printf '302\nhttps://release-assets.githubusercontent.com/github-production-release-asset/vaultlink-real-update/%s' "$relative"
        ;;
    https://release-assets.githubusercontent.com/github-production-release-asset/vaultlink-real-update/*)
        [ -n "$output" ] && [ "$output" != /dev/null ]
        [ "$write_out" = '%{http_code}\n%{url_effective}' ]
        relative=${fixture_url#https://release-assets.githubusercontent.com/github-production-release-asset/vaultlink-real-update/}
        case "$relative" in ''|/*|*..*|*//*|*[!A-Za-z0-9._+/-]*) exit 64 ;; esac
        cp "$fixture_assets/$relative" "$output"
        printf '200\n%s' "$fixture_url"
        ;;
esac
EOF
    sed -i \
        -e "s|@ASSETS@|$fixture_assets|g" \
        -e "s|@LATEST@|$new_version|g" \
        -e "s|@REAL@|$real_curl_path|g" \
        "$wrapper_file"
    chmod 0755 "$wrapper_file"
}

write_systemctl_wrapper() {
    wrapper_file=$work/systemctl.wrapper
    cat >"$wrapper_file" <<'EOF'
#!/bin/sh
set -eu
state=@STATE@
new_version=@NEW_VERSION@
quiet=0
if [ "${1:-}" = --quiet ]; then quiet=1; shift; fi
command_name=${1:-}
if [ "$#" -gt 0 ]; then shift; fi
active() {
    [ -f "$state/pid" ] || return 1
    pid=$(cat "$state/pid" 2>/dev/null || true)
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    kill -0 "$pid" 2>/dev/null
}
stop_service() {
    if active; then
        pid=$(cat "$state/pid")
        kill "$pid" 2>/dev/null || :
        count=0
        while kill -0 "$pid" 2>/dev/null && [ "$count" -lt 50 ]; do
            sleep 0.1
            count=$((count + 1))
        done
        kill -9 "$pid" 2>/dev/null || :
    fi
    rm -f "$state/pid"
}
case "$command_name" in
    is-active)
        unit=${1:-}
        if [ "$unit" = vaultlink.service ] && active; then
            [ "$quiet" -eq 1 ] || printf '%s\n' active
            exit 0
        fi
        [ "$quiet" -eq 1 ] || printf '%s\n' inactive
        exit 3
        ;;
    is-enabled)
        [ "$quiet" -eq 1 ] || printf '%s\n' disabled
        exit 1
        ;;
    stop)
        for unit do
            [ "$unit" != vaultlink.service ] || stop_service
        done
        ;;
    start)
        [ "$#" -eq 1 ] && [ "$1" = vaultlink.service ] || exit 1
        active && exit 0
        active_version=$(/opt/vaultlink/vaultlink --version)
        printf 'start %s\n' "$active_version" >>"$state/start.log"
        if [ -f "$state/fail-new-start" ] && [ "$active_version" = "$new_version" ]; then
            printf 'injected activation failure for %s\n' "$active_version" >>"$state/start.log"
            exit 1
        fi
        (
            exec 8>&- 9>&-
            exec runuser -u vaultlink -- /opt/vaultlink/vaultlink \
                --config /etc/vaultlink/config.toml
        ) >>"$state/service.log" 2>&1 &
        service_pid=$!
        printf '%s\n' "$service_pid" >"$state/pid"
        sleep 0.2
        kill -0 "$service_pid" 2>/dev/null || {
            rm -f "$state/pid"
            exit 1
        }
        ;;
    disable)
        if [ "${1:-}" = --now ]; then shift; fi
        for unit do
            [ "$unit" != vaultlink.service ] || stop_service
        done
        ;;
    enable|daemon-reload|reset-failed) ;;
    *)
        printf 'unsupported systemctl fixture call: %s %s\n' \
            "$command_name" "$*" >>"$state/systemctl-unexpected.log"
        exit 1
        ;;
esac
EOF
    sed -i \
        -e "s|@STATE@|$service_state|g" \
        -e "s|@NEW_VERSION@|$new_version|g" \
        "$wrapper_file"
    chmod 0755 "$wrapper_file"
}

write_manager_wrapper() {
    wrapper_file=$work/$native_manager.wrapper
    cat >"$wrapper_file" <<'EOF'
#!/bin/sh
set -eu
real_manager=@REAL@
manager_name=@MANAGER@
audit_log=@AUDIT@
mutation=0
dry_run=0
case "$manager_name:${1:-}" in
    dpkg:--install|pacman:--upgrade) mutation=1 ;;
esac
for manager_argument do
    case "$manager_name:$manager_argument" in
        rpm:--upgrade) mutation=1 ;;
        *:--test|*:--print|*:--dry-run) dry_run=1 ;;
    esac
done
if [ "$mutation" -eq 1 ] && [ "$dry_run" -eq 0 ]; then
    printf 'MUTATE %s' "$manager_name" >>"$audit_log"
else
    printf 'QUERY %s' "$manager_name" >>"$audit_log"
fi
printf ' %s' "$@" >>"$audit_log"
printf '\n' >>"$audit_log"
exec "$real_manager" "$@"
EOF
    sed -i \
        -e "s|@REAL@|$real_manager_directory/$native_manager|g" \
        -e "s|@MANAGER@|$native_manager|g" \
        -e "s|@AUDIT@|$work/package-manager.log|g" \
        "$wrapper_file"
    chmod 0755 "$wrapper_file"
}

overlay_command() {
    overlay_name=$1
    overlay_wrapper=$2
    overlay_path=$(PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v "$overlay_name") \
        || fail "$overlay_name is unavailable in the updater PATH"
    case "$overlay_path" in /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*) ;;
        *) fail "unsafe $overlay_name command path: $overlay_path" ;;
    esac
    overlay_canonical=$(readlink -f -- "$overlay_path")
    [ -f "$overlay_canonical" ] && [ -x "$overlay_canonical" ] \
        || fail "$overlay_name does not resolve to an executable regular file"
    cp -p -- "$overlay_canonical" "$work/real-$overlay_name"
    chmod 0700 "$work/real-$overlay_name"
    if [ "$overlay_name" = "$native_manager" ]; then
        install -o root -g root -m 0700 "$work/real-$overlay_name" \
            "$real_manager_directory/$native_manager"
    fi
    if [ "$overlay_name" = curl ]; then
        install -o root -g root -m 0755 "$work/real-curl" "$real_curl_path"
    fi
    printf '%s\n' "$overlay_path" >"$work/overlay-$overlay_name.path"
    mv -- "$overlay_path" "$work/overlay-$overlay_name.original"
    install -o root -g root -m 0755 "$overlay_wrapper" "$overlay_path"
}

write_curl_wrapper
write_systemctl_wrapper
write_manager_wrapper
overlay_command systemctl "$work/systemctl.wrapper"
overlay_command "$native_manager" "$work/$native_manager.wrapper"
: >"$work/package-manager.log"
install -d -o root -g root -m 0755 /run/systemd/system

install_initial_package() {
    initial_package=$normal_old/$old_asset
    case "$package_format" in
        deb) dpkg --install "$initial_package" >/dev/null ;;
        rpm) rpm --upgrade --replacepkgs "$initial_package" >/dev/null ;;
        pkg.tar.zst)
            initial_installer=$work/vaultlink-package-install.sh
            bsdtar -xOf "$initial_package" \
                usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh \
                >"$initial_installer"
            chown root:root "$initial_installer"
            chmod 0700 "$initial_installer"
            "$initial_installer" "$initial_package" >/dev/null
            ;;
    esac
}
install_initial_package
package_is_installed || fail "the real old-package installation was not registered"
installed_updater=/usr/sbin/vaultlink-update
[ "$package_format" != pkg.tar.zst ] || installed_updater=/usr/bin/vaultlink-update
cmp -s "$repo_root/deploy/vaultlink-update.sh" "$installed_updater" \
    || fail "installed updater differs from deploy/vaultlink-update.sh"

if ! runuser -u vaultlink -- env \
    VAULTLINK_BIN=/opt/vaultlink/vaultlink \
    VAULTLINK_SMOKE_DIR="$api_work" \
    VAULTLINK_SMOKE_PRESERVE_SERVICE_TOKEN=1 \
    bash "$repo_root/deploy/docker/api-smoke.sh" \
    >"$work/api-smoke.stdout" 2>"$work/api-smoke.stderr"; then
    tail -n 100 "$work/api-smoke.stderr" >&2
    fail "the installed old package failed the real API smoke"
fi
preserved_service_token_file=$api_work/preserved-service-token.secret
preserved_service_token_id_file=$api_work/preserved-service-token.id
for preserved_file in "$preserved_service_token_file" \
    "$preserved_service_token_id_file"; do
    [ -f "$preserved_file" ] && [ ! -L "$preserved_file" ] \
        && [ "$(stat -c '%a' "$preserved_file")" = 600 ] \
        || fail "API smoke did not leave a private service-token preservation fixture"
done
IFS= read -r preserved_service_token <"$preserved_service_token_file"
IFS= read -r preserved_service_token_id <"$preserved_service_token_id_file"
printf '%s' "$preserved_service_token" \
    | grep -E -q '^vlk_st_v1_[A-Za-z0-9_-]{43}$' \
    || fail "service-token preservation fixture has an invalid format"
case "$preserved_service_token_id" in
    ''|*[!0-9]*) fail "service-token preservation fixture has an invalid ID" ;;
esac
preserved_service_token_hash="$(
    sqlite3 "$api_work/data/data.sqlite" \
        "SELECT token_hash FROM service_tokens WHERE id=$preserved_service_token_id;"
)"
printf '%s' "$preserved_service_token_hash" | grep -E -q '^[0-9a-f]{64}$' \
    || fail "service-token preservation fixture has an invalid stored hash"
install -d -o root -g vaultlink -m 0750 /etc/vaultlink
install -d -o vaultlink -g vaultlink -m 0750 /var/lib/vaultlink
sed "s|$api_work/data|/var/lib/vaultlink|g" "$api_work/config.toml" \
    >"$work/config.toml"
grep -F -q 'data_directory = "/var/lib/vaultlink"' "$work/config.toml" \
    || fail "could not bind the API fixture to the package database path"
install -o root -g vaultlink -m 0640 "$work/config.toml" \
    /etc/vaultlink/config.toml
install -o vaultlink -g vaultlink -m 0600 "$api_work/data/data.sqlite" \
    /var/lib/vaultlink/data.sqlite
install -o vaultlink -g vaultlink -m 0600 "$api_work/data/secrets.keyring" \
    /var/lib/vaultlink/secrets.keyring

overlay_command curl "$work/curl.wrapper"
systemctl start vaultlink.service
readiness_attempt=0
until curl --fail --silent --show-error \
    http://127.0.0.1:18081/api/v2/health/ready >/dev/null 2>&1; do
    readiness_attempt=$((readiness_attempt + 1))
    [ "$readiness_attempt" -lt 100 ] || {
        "$real_curl_path" --verbose --max-time 3 \
            http://127.0.0.1:18081/api/v2/health/ready >&2 || :
        [ ! -s "$service_state/service.log" ] || tail -n 100 "$service_state/service.log" >&2
        fail "the real old binary did not become ready"
    }
    sleep 0.2
done

native_database_version() {
    case "$package_format" in
        deb) dpkg-query -W -f='${Version}' vaultlink ;;
        rpm) rpm -q --qf '%{VERSION}-%{RELEASE}' vaultlink ;;
        pkg.tar.zst) pacman -Q vaultlink | awk '{ print $2 }' ;;
    esac
}

assert_service_token_preserved() {
    expected_version=$1
    actual_hash="$(
        sqlite3 /var/lib/vaultlink/data.sqlite \
            "SELECT token_hash FROM service_tokens WHERE id=$preserved_service_token_id;"
    )"
    [ "$actual_hash" = "$preserved_service_token_hash" ] \
        || fail "service-token hash changed or disappeared at $expected_version parity"
    token_status="$(
        curl --silent --show-error \
            --output "$work/service-token-parity.json" \
            --write-out '%{http_code}' \
            --header "Authorization: Bearer $preserved_service_token" \
            http://127.0.0.1:18081/api/v2/monitoring/summary
    )"
    [ "$token_status" = 200 ] \
        || fail "service token was not authorized at $expected_version parity"
    grep -F -q "\"version\":\"$expected_version\"" \
        "$work/service-token-parity.json" \
        || fail "service-token parity response reported the wrong version"
    ! grep -aFq -- "$preserved_service_token" "$work/service-token-parity.json" \
        || fail "service-token parity response echoed the credential"
    ! grep -aiFq -- 'authorization:' "$work/service-token-parity.json" \
        || fail "service-token parity response echoed the Authorization header"
}

assert_parity() {
    parity_version=$1
    [ "$(native_database_version)" = "$(expected_database_version "$parity_version")" ] \
        || fail "native package database does not report $parity_version"
    [ "$(timeout --kill-after=2 5 /usr/lib/vaultlink/package/vaultlink --version)" = \
        "$parity_version" ] || fail "candidate does not report $parity_version"
    [ "$(timeout --kill-after=2 5 /opt/vaultlink/vaultlink --version)" = \
        "$parity_version" ] || fail "live binary does not report $parity_version"
    cmp -s /usr/lib/vaultlink/package/vaultlink /opt/vaultlink/vaultlink \
        || fail "candidate/live bytes differ for $parity_version"
    /usr/lib/vaultlink/package/deploy/vaultlink-runtime-guard.sh \
        || fail "runtime guard rejected $parity_version parity"
    systemctl --quiet is-active vaultlink.service \
        || fail "service is not active at $parity_version parity"
    [ "$(sqlite3 /var/lib/vaultlink/data.sqlite 'PRAGMA integrity_check;')" = ok ] \
        || fail "SQLite integrity failed at $parity_version parity"
    assert_service_token_preserved "$parity_version"
}

config_hash=$(sha256sum /etc/vaultlink/config.toml | awk '{ print $1 }')
config_identity=$(stat -c '%d:%i:%u:%g:%a:%y' /etc/vaultlink/config.toml)
update_hash=$(sha256sum /etc/vaultlink/update.conf | awk '{ print $1 }')
update_identity=$(stat -c '%d:%i:%u:%g:%a:%y' /etc/vaultlink/update.conf)
assert_mutable_bytes_unchanged() {
    [ "$(sha256sum /etc/vaultlink/config.toml | awk '{ print $1 }')" = \
        "$config_hash" ] \
        && [ "$(sha256sum /etc/vaultlink/update.conf | awk '{ print $1 }')" = \
            "$update_hash" ] || fail "config.toml or update.conf bytes changed"
}
assert_mutables_unchanged() {
    assert_mutable_bytes_unchanged
    [ "$(stat -c '%d:%i:%u:%g:%a:%y' /etc/vaultlink/config.toml)" = \
            "$config_identity" ] || fail "config.toml changed bytes or identity"
    [ "$(stat -c '%d:%i:%u:%g:%a:%y' /etc/vaultlink/update.conf)" = \
            "$update_identity" ] || fail "update.conf changed bytes or identity"
}
assert_parity "$old_version"

run_production_updater() {
    sh "$repo_root/deploy/vaultlink-update.sh" install
}

archive_parser_result=not-applicable
assert_archive_fixture_rejected() {
    archive_label=$1
    archive_package=$2
    publish_release "$new_version" "$archive_package"
    : >"$work/package-manager.log"
    if run_production_updater >"$work/archive-$archive_label.stdout" \
        2>"$work/archive-$archive_label.stderr"; then
        fail "the updater accepted the $archive_label DEB archive fixture"
    fi
    if ! grep -F -q 'new release package payload is invalid' \
        "$work/archive-$archive_label.stderr"; then
        tail -n 100 "$work/archive-$archive_label.stderr" >&2
        fail "the $archive_label DEB archive fixture failed at an unrelated guard"
    fi
    ! grep -q '^MUTATE ' "$work/package-manager.log" \
        || fail "the $archive_label DEB archive fixture reached package mutation"
    assert_parity "$old_version"
    assert_mutables_unchanged
}

if [ "$package_format" = deb ]; then
    # The normal old package above already proved that the legitimate single
    # `./` tar root is accepted. These signed variants must all be rejected by
    # the production updater before its real dpkg transaction begins.
    assert_archive_fixture_rejected empty-path "$archive_fixture_empty"
    assert_archive_fixture_rejected parent-traversal "$archive_fixture_parent"
    assert_archive_fixture_rejected duplicate-root "$archive_fixture_duplicate_root"
    archive_parser_result=ok
fi

# A signed package with a genuine additional native dependency must fail before
# the real package manager receives any mutating invocation.
publish_release "$new_version" "$missing_new/$new_asset"
: >"$work/package-manager.log"
before_db=$(native_database_version)
before_candidate=$(sha256sum /usr/lib/vaultlink/package/vaultlink | awk '{ print $1 }')
before_live=$(sha256sum /opt/vaultlink/vaultlink | awk '{ print $1 }')
if run_production_updater >"$work/missing.stdout" 2>"$work/missing.stderr"; then
    fail "the updater accepted a missing real package dependency"
fi
if ! grep -F -q 'new package dependencies are unavailable' \
    "$work/missing.stderr"; then
    tail -n 100 "$work/missing.stderr" >&2
    fail "missing-dependency rejection was not explicit"
fi
! grep -q '^MUTATE ' "$work/package-manager.log" \
    || fail "missing-dependency preflight reached a real package mutation"
[ "$(native_database_version)" = "$before_db" ] \
    && [ "$(sha256sum /usr/lib/vaultlink/package/vaultlink | awk '{ print $1 }')" = \
        "$before_candidate" ] \
    && [ "$(sha256sum /opt/vaultlink/vaultlink | awk '{ print $1 }')" = \
        "$before_live" ] || fail "missing-dependency preflight changed package/runtime state"
assert_parity "$old_version"
assert_mutables_unchanged

# Replace only the local signed fixture and prove the successful real package
# transaction plus package database/candidate/live parity.
publish_release "$new_version" "$normal_new/$new_asset"
: >"$work/package-manager.log"
if ! run_production_updater >"$work/success.stdout" \
    2>"$work/success.stderr"; then
    tail -n 100 "$work/success.stderr" >&2
    [ ! -s "$service_state/service.log" ] \
        || tail -n 100 "$service_state/service.log" >&2
    printf 'package-manager log:\n' >&2
    tail -n 100 "$work/package-manager.log" >&2 || :
    fail "the production updater rejected the valid package fixture"
fi
grep -F -x -q 'update_installed=true' "$work/success.stdout" \
    || fail "the production updater did not report success"
[ "$(grep -c '^MUTATE ' "$work/package-manager.log")" -eq 1 ] \
    && grep '^MUTATE ' "$work/package-manager.log" | grep -F -q "$new_asset" \
    || fail "success did not execute exactly one real new-package transaction"
if [ "$package_format" = rpm ]; then
    [ "$(grep -c '^MUTATE rpm --nocontexts --upgrade ' \
        "$work/package-manager.log")" -eq 1 ] \
        || fail "successful RPM update did not retain the reviewed --nocontexts transaction mode"
fi
assert_parity "$new_version"
assert_mutables_unchanged
success_backup=$(sed -n 's/^backup_directory=//p' "$work/success.stdout")
case "$success_backup" in /var/lib/vaultlink-backups/*) ;;
    *) fail "successful update did not report a protected rollback backup" ;;
esac
[ -d "$success_backup" ] && [ ! -L "$success_backup" ] \
    && [ "$(stat -c '%u:%g:%a' "$success_backup")" = 0:0:700 ] \
    || fail "successful update rollback backup is unsafe"

# Return to the old package-bound state using a real native downgrade followed
# by the packaged rollback helper and its frozen old-version runtime backup.
systemctl stop vaultlink.service
case "$package_format" in
    deb) dpkg --install "$normal_old/$old_asset" >/dev/null ;;
    rpm) rpm --upgrade --oldpackage --replacepkgs "$normal_old/$old_asset" >/dev/null ;;
    pkg.tar.zst) pacman --upgrade --noconfirm "$normal_old/$old_asset" >/dev/null ;;
esac
/usr/lib/vaultlink/package/deploy/vaultlink-rollback.sh "$success_backup" >/dev/null
assert_parity "$old_version"
assert_mutable_bytes_unchanged
# The explicit standalone rollback atomically replaces its four requested
# backup sources, including config.toml. Rebaseline filesystem identity only
# after proving that the reset restored the exact original mutable bytes.
config_identity=$(stat -c '%d:%i:%u:%g:%a:%y' /etc/vaultlink/config.toml)
update_identity=$(stat -c '%d:%i:%u:%g:%a:%y' /etc/vaultlink/update.conf)
assert_mutables_unchanged

# Fail the new runtime's start after the real new package is installed. The
# updater must reinstall the authenticated old package with the real manager,
# restore the old runtime unit, and finish in exact old-version parity.
: >"$work/package-manager.log"
: >"$service_state/fail-new-start"
if run_production_updater >"$work/activation.stdout" \
    2>"$work/activation.stderr"; then
    fail "the updater ignored the injected activation failure"
fi
rm -f "$service_state/fail-new-start"
if ! grep -F -q 'verified package activation or migration failed' \
    "$work/activation.stderr"; then
    tail -n 100 "$work/activation.stderr" >&2
    fail "activation failure was not reported by the production updater"
fi
if grep -F -q 'CRITICAL:' "$work/activation.stderr"; then
    tail -n 100 "$work/activation.stderr" >&2
    fail "activation recovery became terminal"
fi
[ "$(grep -c '^MUTATE ' "$work/package-manager.log")" -eq 2 ] \
    || fail "activation recovery did not execute exactly new+old real transactions"
if [ "$package_format" = rpm ]; then
    [ "$(grep -c '^MUTATE rpm --nocontexts --upgrade ' \
        "$work/package-manager.log")" -eq 2 ] \
        || fail "RPM activation recovery did not retain the reviewed --nocontexts transaction mode"
fi
first_mutation=$(grep '^MUTATE ' "$work/package-manager.log" | sed -n '1p')
second_mutation=$(grep '^MUTATE ' "$work/package-manager.log" | sed -n '2p')
printf '%s\n' "$first_mutation" | grep -F -q "$new_asset" \
    || fail "activation test did not install the real new package first"
printf '%s\n' "$second_mutation" | grep -F -q "$old_asset" \
    || fail "activation recovery did not reinstall the real old package"
assert_parity "$old_version"
assert_mutables_unchanged

printf 'target=%s\nold_version=%s\nnew_version=%s\n' \
    "$target_id" "$old_version" "$new_version"
printf 'native_package_manager=%s\ntransport_fixture=local-trusted-url-adapter\n' \
    "$native_manager"
printf 'archive_parser_negative_fixtures=%s\n' "$archive_parser_result"
printf 'missing_dependency_zero_mutation=ok\nsuccess_parity=ok\nactivation_old_package_reinstall=ok\n'
