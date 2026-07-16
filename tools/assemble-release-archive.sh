#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG

[ "$#" -eq 5 ] || {
    echo "usage: assemble-release-archive.sh BINARY SBOM OUTPUT_DIR VERSION ARCH" >&2
    exit 64
}
binary_source=$1
sbom_source=$2
dist=$3
version=$4
arch=$5
if [ ! -x "$binary_source" ] || [ ! -s "$sbom_source" ]; then
    echo "release binary or SBOM is missing" >&2
    exit 66
fi
case "$version:$arch" in *[!A-Za-z0-9._:+~-]*) echo "unsafe release version or architecture" >&2; exit 64 ;; esac
[ ! -e "$dist" ] || { echo "release output directory already exists: $dist" >&2; exit 73; }

root="VaultLink-${version}-debian13-${arch}"
archive="${root}.tar.gz"
standalone="vaultlink-${version}-debian13-${arch}"
sbom_name="vaultlink-${version}-debian13-${arch}.cdx.json"
checksums="SHA256SUMS-${arch}"
install -d "$dist/$root/bin" "$dist/$root/config" "$dist/$root/deploy" \
    "$dist/$root/docs" "$dist/$root/tools"
install -m 0755 "$binary_source" "$dist/$root/bin/vaultlink"
install -m 0755 "$binary_source" "$dist/$standalone"
install -m 0644 README.md CHANGELOG.md SECURITY.md LICENSE rust-toolchain.toml "$dist/$root/"
cp config/*.toml "$dist/$root/config/"
cp -R deploy/. "$dist/$root/deploy/"
cp -R docs/. "$dist/$root/docs/"
install -m 0755 \
    tools/check-soak-evidence.sh \
    tools/collect-soak-evidence.sh \
    tools/load-test.sh \
    tools/soak-monitor.sh \
    "$dist/$root/tools/"
if [ -s release/minisign.pub ]; then
    cp release/minisign.pub "$dist/$root/"
fi
install -m 0644 "$sbom_source" "$dist/$root/vaultlink.cdx.json"
install -m 0644 "$sbom_source" "$dist/$sbom_name"
tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
    -C "$dist" -cf "$dist/$root.tar" "$root"
gzip -n -9 "$dist/$root.tar"
(
    cd "$dist"
    sha256sum "$archive" "$standalone" "$sbom_name" >"$checksums"
    sha256sum -c "$checksums"
)

echo "$dist/$archive"
