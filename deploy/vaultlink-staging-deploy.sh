#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 1 ]; then
    echo "usage (as root): vaultlink-staging-deploy.sh RELEASE_ARCHIVE" >&2
    exit 64
fi

archive=$1
[ -s "$archive" ] || { echo "release archive missing" >&2; exit 1; }
candidate=$(mktemp -d /root/vaultlink-candidate.XXXXXX)
trap 'rm -rf "$candidate"' EXIT
tar -xzf "$archive" -C "$candidate"
root=$(find "$candidate" -mindepth 1 -maxdepth 1 -type d -name 'VaultLink-*-debian13-amd64' -print -quit)
[ -n "$root" ] || { echo "release root missing" >&2; exit 1; }

cp -a /etc/vaultlink/config.toml "/etc/vaultlink/config.toml.pre-$(date -u +%Y%m%dT%H%M%SZ)"
sed -i -e '/^redirect_http_to_https[[:space:]]*=/d' -e '/^audit_log_path[[:space:]]*=/d' /etc/vaultlink/config.toml
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
/usr/local/sbin/vaultlink-upgrade "$root/bin/vaultlink"
