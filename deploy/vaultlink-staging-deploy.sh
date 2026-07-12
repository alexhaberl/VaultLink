#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 2 ]; then
    echo "usage (as root): vaultlink-staging-deploy.sh RELEASE_ARCHIVE NEW_CONFIG" >&2
    exit 64
fi

archive=$1
new_config=$2
[ -s "$archive" ] || { echo "release archive missing" >&2; exit 1; }
[ -f "$new_config" ] || { echo "candidate configuration missing" >&2; exit 1; }
case "$(uname -m)" in
    x86_64)
        release_arch=amd64
        ;;
    aarch64|arm64)
        release_arch=arm64
        ;;
    *)
        echo "unsupported Linux architecture: $(uname -m)" >&2
        exit 1
        ;;
esac
candidate=$(mktemp -d /root/vaultlink-candidate.XXXXXX)
trap 'rm -rf "$candidate"' EXIT
tar -xzf "$archive" -C "$candidate"
root=$(find "$candidate" -mindepth 1 -maxdepth 1 -type d -name "VaultLink-*-debian13-$release_arch" -print)
[ -n "$root" ] || { echo "release root for $release_arch missing" >&2; exit 1; }
[ "$(printf '%s\n' "$root" | wc -l)" -eq 1 ] || { echo "multiple release roots found" >&2; exit 1; }

if [ -s /root/vaultlink.service ]; then
    install -o root -g root -m 0644 /root/vaultlink.service /etc/systemd/system/vaultlink.service
else
    install -o root -g root -m 0644 "$root/deploy/vaultlink.service" /etc/systemd/system/vaultlink.service
fi
if [ -s /root/vaultlink-upgrade.sh ]; then
    install -o root -g root -m 0755 /root/vaultlink-upgrade.sh /usr/local/sbin/vaultlink-upgrade
else
    install -o root -g root -m 0755 "$root/deploy/vaultlink-upgrade.sh" /usr/local/sbin/vaultlink-upgrade
fi
install -o root -g root -m 0755 "$root/deploy/vaultlink-rollback.sh" /usr/local/sbin/vaultlink-rollback
systemctl daemon-reload
/usr/local/sbin/vaultlink-upgrade "$root/bin/vaultlink" "$new_config"
