#!/bin/sh
set -eu

: "${RELEASE_BUILDER_IMAGE:?VAULTLINK_RELEASE_BUILDER_IMAGE must be a digest-pinned repository variable}"
locked_image=$(sed -n '1p' deploy/docker/release-builder-image.lock)
[ "$(wc -l <deploy/docker/release-builder-image.lock)" -eq 1 ] \
    || { echo "release builder image lock must contain exactly one line" >&2; exit 1; }
[ "$locked_image" != UNPROVISIONED ] || {
    echo "release builder lock is UNPROVISIONED" >&2
    exit 1
}
case "$locked_image" in
    ghcr.io/alexhaberl/vaultlink-release-builder@sha256:*) ;;
    *) echo "release builder must be a digest-pinned ghcr.io image" >&2; exit 1 ;;
esac
if [ "$RELEASE_BUILDER_IMAGE" != "$locked_image" ]; then
    echo "release builder variable does not equal the checked-in image lock" >&2
    exit 1
fi
digest=${RELEASE_BUILDER_IMAGE##*@sha256:}
case "$digest" in *[!0-9a-f]*|'') echo "release builder digest is invalid" >&2; exit 1 ;; esac
[ "${#digest}" -eq 64 ] || { echo "release builder digest must have 64 hex characters" >&2; exit 1; }

failed=0
while IFS='=' read -r package expected; do
    case "$package" in ''|'#'*) continue ;; esac
    actual=$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null || true)
    if [ "$actual" != "$expected" ]; then
        echo "release builder package mismatch: $package expected $expected, got ${actual:-missing}" >&2
        failed=1
    fi
done <deploy/docker/debian-packages.lock
[ "$failed" -eq 0 ] || exit 1

[ ! -e /etc/apt/sources.list ] || { echo "release builder contains a legacy APT source" >&2; exit 1; }
source_count=$(find /etc/apt/sources.list.d -mindepth 1 -maxdepth 1 \
    \( -name '*.list' -o -name '*.sources' \) -print | wc -l)
if [ "$source_count" -ne 1 ] \
    || ! cmp -s deploy/docker/debian-snapshot.sources /etc/apt/sources.list.d/debian.sources; then
    echo "release builder does not contain the sole approved Debian snapshot" >&2
    exit 1
fi

cargo cyclonedx --version | grep -F -q '0.5.9'
cargo audit --version | grep -F -q '0.22.2'
test "$(rustc --version | awk '{print $2}')" = "$(sh tools/rust-toolchain-channel.sh)"
echo "Digest-pinned release builder verified: $RELEASE_BUILDER_IMAGE"
