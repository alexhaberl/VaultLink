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
    echo "package release assembly failed: $*" >&2
    exit 1
}

[ "$#" -eq 3 ] || {
    echo "usage: assemble-package-release.sh INPUT_DIR OUTPUT_DIR VERSION" >&2
    exit 64
}

input_dir=$1
output_dir=$2
version=$3
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
cd "$repo_root"

for command_name in awk bsdtar cmp cpio diff dpkg-deb find grep install mv \
    python3 rm rpm rpm2cpio sha256sum sort stat tar tr wc; do
    command -v "$command_name" >/dev/null || fail "$command_name is required"
done
python3 tools/package-targets.py validate >/dev/null

[ -d "$input_dir" ] && [ ! -L "$input_dir" ] || fail "input directory is unsafe"
input_dir=$(cd -- "$input_dir" && pwd)
case "$output_dir" in /*) ;; *) output_dir="$repo_root/$output_dir" ;; esac
output_parent=$(dirname -- "$output_dir")
install -d -m 0755 "$output_parent"
output_parent=$(cd -- "$output_parent" && pwd)
output_dir="$output_parent/$(basename -- "$output_dir")"
[ ! -e "$output_dir" ] && [ ! -L "$output_dir" ] \
    || fail "refusing to overwrite output directory"

work=$(mktemp -d "${TMPDIR:-/tmp}/vaultlink-release-assembly.XXXXXXXX")
stage="$output_parent/.vaultlink-release.$$.incomplete"
cleanup() {
    rm -rf -- "$work" "$stage"
}
trap cleanup 0 1 2 15
[ ! -e "$stage" ] || fail "staging path already exists"
install -d -m 0700 "$stage"

targets="$work/targets.tsv"
python3 tools/package-release-bundle.py targets "$version" >"$targets"
[ "$(wc -l <"$targets" | tr -d '[:space:]')" -eq 9 ] \
    || fail "target manifest did not resolve exactly nine packages"

expected_inputs="$work/expected-inputs"
: >"$expected_inputs"
while IFS="$(printf '\t')" read -r target_id asset_name package_format; do
    [ -n "$target_id" ] && [ -n "$asset_name" ] && [ -n "$package_format" ] \
        || fail "invalid target record"
    printf '%s\n%s\n' "$asset_name" "$target_id.cdx.json" >>"$expected_inputs"
done <"$targets"
sort -o "$expected_inputs" "$expected_inputs"
find "$input_dir" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' \
    | LC_ALL=C sort >"$work/actual-inputs"
diff -u "$expected_inputs" "$work/actual-inputs" \
    || fail "input directory must contain exactly nine packages and nine target SBOMs"
if find "$input_dir" -mindepth 1 -maxdepth 1 ! -type f -print | grep -q .; then
    fail "input directory contains a link, directory, or special file"
fi

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
            tar -xOf "$reference_root/data.tar" ./usr/lib/vaultlink/package/vaultlink.cdx.json \
                >"$reference_root/vaultlink.cdx.json"
            ;;
        rpm)
            rpm2cpio "$reference_package" >"$reference_root/payload.cpio"
            cpio --quiet -i --to-stdout ./usr/lib/vaultlink/package/vaultlink \
                <"$reference_root/payload.cpio" >"$reference_root/vaultlink"
            cpio --quiet -i --to-stdout ./usr/lib/vaultlink/package/vaultlink.cdx.json \
                <"$reference_root/payload.cpio" >"$reference_root/vaultlink.cdx.json"
            ;;
        pkg.tar.zst)
            bsdtar -xOf "$reference_package" usr/lib/vaultlink/package/vaultlink \
                >"$reference_root/vaultlink"
            bsdtar -xOf "$reference_package" usr/lib/vaultlink/package/vaultlink.cdx.json \
                >"$reference_root/vaultlink.cdx.json"
            ;;
        *) fail "unsupported target package format: $reference_format" ;;
    esac
    [ -s "$reference_root/vaultlink" ] && [ -s "$reference_root/vaultlink.cdx.json" ] \
        || fail "package reference payload is incomplete"
    chmod 0755 "$reference_root/vaultlink"
    chmod 0644 "$reference_root/vaultlink.cdx.json"
    rm -f "$reference_root/data.tar" "$reference_root/payload.cpio"
}

payload_records="$work/payloads.tsv"
: >"$payload_records"
while IFS="$(printf '\t')" read -r target_id asset_name package_format; do
    package="$input_dir/$asset_name"
    sbom="$input_dir/$target_id.cdx.json"
    [ -f "$package" ] && [ ! -L "$package" ] && [ "$(stat -c %a "$package")" = 644 ] \
        || fail "package input must be a regular mode-0644 file: $asset_name"
    [ -f "$sbom" ] && [ ! -L "$sbom" ] && [ "$(stat -c %a "$sbom")" = 644 ] \
        || fail "SBOM input must be a regular mode-0644 file: $target_id"
    reference="$work/reference-$target_id"
    extract_reference "$package_format" "$package" "$reference"
    cmp "$sbom" "$reference/vaultlink.cdx.json" >/dev/null \
        || fail "package and target artifact carry different SBOMs: $target_id"
    sh tools/verify-native-package.sh "$target_id" "$version" "$package" \
        "$reference/vaultlink" "$sbom" --no-exec
    payload_sha256=$(sha256sum "$reference/vaultlink" | awk '{print $1}')
    printf '%s\t%s\n' "$target_id" "$payload_sha256" >>"$payload_records"
    install -o root -g root -m 0644 "$package" "$stage/$asset_name"
done <"$targets"

bundle_name="vaultlink-$version-sbom-bundle.json"
python3 tools/package-release-bundle.py build "$version" "$input_dir" \
    "$payload_records" "$stage/$bundle_name"
chmod 0644 "$stage/$bundle_name"

checksums="$stage/SHA256SUMS"
: >"$checksums"
while IFS="$(printf '\t')" read -r _target_id asset_name _package_format; do
    (cd "$stage" && sha256sum "$asset_name") >>"$checksums"
done <"$targets"
(cd "$stage" && sha256sum "$bundle_name") >>"$checksums"
chmod 0644 "$checksums"

mv "$stage" "$output_dir"
trap - 0 1 2 15
rm -rf -- "$work"
printf 'unsigned_release_dir=%s\nunsigned_asset_count=11\n' "$output_dir"
