#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 1 ]; then
    echo "usage (as root): vaultlink-rollback.sh BACKUP_DIRECTORY" >&2
    exit 64
fi

backup_dir=$1
[ -x "$backup_dir/vaultlink" ] || { echo "backup binary missing" >&2; exit 1; }
[ -f "$backup_dir/data.sqlite" ] || { echo "database backup missing" >&2; exit 1; }
sqlite3 "$backup_dir/data.sqlite" "PRAGMA integrity_check" | grep -qx ok

systemctl stop vaultlink.service
install -o root -g root -m 0755 "$backup_dir/vaultlink" /opt/vaultlink/vaultlink
install -o vaultlink -g vaultlink -m 0600 "$backup_dir/data.sqlite" /var/lib/vaultlink/data.sqlite
rm -f /var/lib/vaultlink/data.sqlite-wal /var/lib/vaultlink/data.sqlite-shm
systemctl start vaultlink.service
systemctl --quiet is-active vaultlink.service
