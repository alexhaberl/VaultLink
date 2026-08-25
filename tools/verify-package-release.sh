#!/bin/sh
# Compound guards intentionally use `A && B || fail` for fail-closed exits.
# shellcheck disable=SC2015
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
LANG=C
export PATH LC_ALL LANG
umask 077

fail() {
    echo "package release verification failed: $*" >&2
    exit 1
}

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: verify-package-release.sh RELEASE_DIR VERSION [--signed]" >&2
    exit 64
fi
release_dir=$1
version=$2
signed=0
if [ "$#" -eq 3 ]; then
    [ "$3" = --signed ] || fail "unknown verification option: $3"
    signed=1
fi

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
cd "$repo_root"
for command_name in awk bsdtar cat cmp cpio diff dpkg-deb find grep id install \
    minisign python3 rm rpm rpm2cpio sha256sum sort stat tar tr wc; do
    command -v "$command_name" >/dev/null || fail "$command_name is required"
done
python3 tools/package-targets.py validate >/dev/null
sh tools/check-minisign-public-key.sh release/minisign.pub >/dev/null
[ -d "$release_dir" ] && [ ! -L "$release_dir" ] || fail "release directory is unsafe"
release_dir=$(cd -- "$release_dir" && pwd)

work=$(mktemp -d "${TMPDIR:-/tmp}/vaultlink-release-verify.XXXXXXXX")
cleanup() {
    rm -rf -- "$work"
}
trap cleanup 0 1 2 15

targets="$work/targets.tsv"
python3 tools/package-release-bundle.py targets "$version" >"$targets"
[ "$(wc -l <"$targets" | tr -d '[:space:]')" -eq 9 ] \
    || fail "target manifest did not resolve exactly nine packages"

bundle_name="vaultlink-$version-sbom-bundle.json"
expected_files="$work/expected-files"
: >"$expected_files"
while IFS="$(printf '\t')" read -r _target_id asset_name _package_format; do
    printf '%s\n' "$asset_name" >>"$expected_files"
    if [ "$signed" -eq 1 ]; then printf '%s.minisig\n' "$asset_name" >>"$expected_files"; fi
done <"$targets"
printf '%s\nSHA256SUMS\n' "$bundle_name" >>"$expected_files"
if [ "$signed" -eq 1 ]; then printf '%s\n' SHA256SUMS.minisig >>"$expected_files"; fi
sort -o "$expected_files" "$expected_files"
find "$release_dir" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' \
    | LC_ALL=C sort >"$work/actual-files"
diff -u "$expected_files" "$work/actual-files" \
    || fail "release directory has a missing or extra asset"
if find "$release_dir" -mindepth 1 -maxdepth 1 ! -type f -print | grep -q .; then
    fail "release directory contains a link, directory, or special file"
fi
expected_count=11
if [ "$signed" -eq 1 ]; then expected_count=21; fi
[ "$(wc -l <"$work/actual-files" | tr -d '[:space:]')" -eq "$expected_count" ] \
    || fail "release asset count is not $expected_count"
while IFS= read -r release_file; do
    mode=$(stat -c %a "$release_dir/$release_file")
    [ $((0$mode & 0022)) -eq 0 ] \
        || fail "release asset is group- or world-writable: $release_file"
    if [ "$(id -u)" -eq 0 ]; then
        [ "$(stat -c %u:%g "$release_dir/$release_file")" = 0:0 ] \
            || fail "release asset is not root-owned: $release_file"
    fi
done <"$work/actual-files"

expected_checksums="$work/SHA256SUMS.expected"
: >"$expected_checksums"
while IFS="$(printf '\t')" read -r _target_id asset_name _package_format; do
    (cd "$release_dir" && sha256sum "$asset_name") >>"$expected_checksums"
done <"$targets"
(cd "$release_dir" && sha256sum "$bundle_name") >>"$expected_checksums"
cmp "$expected_checksums" "$release_dir/SHA256SUMS" >/dev/null \
    || fail "global SHA256SUMS is not exact, complete, and ordered"
if [ "$signed" -eq 1 ]; then
    minisign -V -q -p release/minisign.pub -m "$release_dir/SHA256SUMS" \
        -x "$release_dir/SHA256SUMS.minisig" \
        || fail "global checksum signature is invalid"
fi

python3 tools/package-release-bundle.py verify "$version" "$release_dir" \
    "$release_dir/$bundle_name" --materialize "$work/sboms"

extract_reference() {
    reference_format=$1
    reference_package=$2
    reference_root=$3
    install -d -m 0700 "$reference_root"
    case "$reference_format" in
        deb)
            dpkg-deb --fsys-tarfile "$reference_package" >"$reference_root/data.tar"
            tar -xOf "$reference_root/data.tar" ./usr/lib/vaultlink/package/vaultlink \
                >"$reference_root/vaultlink"
            ;;
        rpm)
            rpm2cpio "$reference_package" >"$reference_root/payload.cpio"
            cpio --quiet -i --to-stdout ./usr/lib/vaultlink/package/vaultlink \
                <"$reference_root/payload.cpio" >"$reference_root/vaultlink"
            ;;
        pkg.tar.zst)
            bsdtar -xOf "$reference_package" usr/lib/vaultlink/package/vaultlink \
                >"$reference_root/vaultlink"
            ;;
        *) fail "unsupported target package format: $reference_format" ;;
    esac
    [ -s "$reference_root/vaultlink" ] || fail "package payload is missing"
    chmod 0755 "$reference_root/vaultlink"
    rm -f "$reference_root/data.tar" "$reference_root/payload.cpio"
}

while IFS="$(printf '\t')" read -r target_id asset_name package_format; do
    package="$release_dir/$asset_name"
    if [ "$signed" -eq 1 ]; then
        minisign -V -q -p release/minisign.pub -m "$package" \
            -x "$package.minisig" \
            || fail "direct package signature is invalid: $asset_name"
    fi
    reference="$work/reference-$target_id"
    extract_reference "$package_format" "$package" "$reference"
    sbom="$work/sboms/$target_id.cdx.json"
    sh tools/verify-native-package.sh "$target_id" "$version" "$package" \
        "$reference/vaultlink" "$sbom" --no-exec
    expected_payload=$(cat "$work/sboms/$target_id.payload.sha256")
    actual_payload=$(sha256sum "$reference/vaultlink" | awk '{print $1}')
    [ "$actual_payload" = "$expected_payload" ] \
        || fail "package payload differs from the SBOM bundle: $target_id"
done <"$targets"

trap - 0 1 2 15
rm -rf -- "$work"
printf 'release_version=%s\nasset_count=%s\nsigned=%s\n' \
    "$version" "$expected_count" "$signed"
