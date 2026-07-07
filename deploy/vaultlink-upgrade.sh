#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 1 ]; then
    echo "usage (as root): vaultlink-upgrade.sh NEW_BINARY" >&2
    exit 64
fi

new_binary=$1
install_dir=/opt/vaultlink
data=/var/lib/vaultlink/data.sqlite
stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup_dir="/var/lib/vaultlink/backups/$stamp"

[ -x "$new_binary" ] || { echo "new binary is missing or not executable" >&2; exit 1; }
command -v sqlite3 >/dev/null || { echo "sqlite3 is required for an online-safe backup" >&2; exit 1; }

systemctl stop vaultlink.service
install -d -o root -g vaultlink -m 0750 "$backup_dir"
if [ -f "$install_dir/vaultlink" ]; then
    install -o root -g root -m 0755 "$install_dir/vaultlink" "$backup_dir/vaultlink"
fi
if [ -f "$data" ]; then
    sqlite3 "$data" ".timeout 10000" ".backup '$backup_dir/data.sqlite'"
    chown root:vaultlink "$backup_dir/data.sqlite"
    chmod 0640 "$backup_dir/data.sqlite"
    sqlite3 "$backup_dir/data.sqlite" "PRAGMA integrity_check" | grep -qx ok
fi
install -o root -g root -m 0755 "$new_binary" "$install_dir/.vaultlink.new"
mv -f "$install_dir/.vaultlink.new" "$install_dir/vaultlink"

if ! systemctl start vaultlink.service; then
    echo "upgrade failed; restoring $backup_dir" >&2
    [ ! -f "$backup_dir/vaultlink" ] || install -o root -g root -m 0755 "$backup_dir/vaultlink" "$install_dir/vaultlink"
    [ ! -f "$backup_dir/data.sqlite" ] || install -o vaultlink -g vaultlink -m 0600 "$backup_dir/data.sqlite" "$data"
    systemctl start vaultlink.service || true
    exit 1
fi

echo "$backup_dir"
