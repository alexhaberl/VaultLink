#!/bin/sh
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
LANG=C
export PATH LC_ALL LANG

: "${ASSET:?ASSET is required}"
: "${VERSION:?VERSION is required}"
case "$ASSET" in
    *[!A-Za-z0-9._+-]*|'') echo "unsafe Arch package asset name" >&2; exit 64 ;;
esac
case "$VERSION" in
    *[!0-9.]*|'') echo "unsafe VaultLink version" >&2; exit 64 ;;
esac

cd /work
pacman -Syu --noconfirm --needed \
    ca-certificates coreutils curl libarchive minisign sqlite systemd \
    tar util-linux zstd
minisign -V -q -p release/minisign.pub \
    -m arch-release/SHA256SUMS \
    -x arch-release/SHA256SUMS.minisig
checksum=$(awk -v asset="$ASSET" '
    NF == 2 && $2 == asset && $1 ~ /^[0-9a-f]{64}$/ { print }
' arch-release/SHA256SUMS)
test "$(printf '%s\n' "$checksum" | grep -c .)" -eq 1
(cd arch-release && printf '%s\n' "$checksum" | sha256sum -c -)
minisign -V -q -p release/minisign.pub \
    -m "arch-release/$ASSET" \
    -x "arch-release/$ASSET.minisig"
install -o root -g root -m 0600 \
    "arch-release/$ASSET" "/var/tmp/$ASSET"
bsdtar -xOf "/var/tmp/$ASSET" \
    usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh \
    >/var/tmp/vaultlink-package-install.sh
chown root:root /var/tmp/vaultlink-package-install.sh
chmod 0700 /var/tmp/vaultlink-package-install.sh
/var/tmp/vaultlink-package-install.sh "/var/tmp/$ASSET"
test "$(/opt/vaultlink/vaultlink --version)" = "$VERSION"
test "$(wc -l </usr/share/vaultlink/install-method.env)" -eq 5
if systemctl --quiet is-enabled vaultlink.service; then
    echo "vaultlink.service was enabled by initial installation" >&2
    exit 1
fi
if systemctl --quiet is-enabled vaultlink-update.timer; then
    echo "vaultlink-update.timer was enabled by initial installation" >&2
    exit 1
fi
