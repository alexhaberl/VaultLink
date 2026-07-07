#!/bin/sh
set -eu

mount_root=${1:-/mnt/storage}
install -d -o vaultlink -g vaultlink -m 0750 "$mount_root/vaultlink-load/uploads"
truncate -s 50G "$mount_root/vaultlink-load/sparse-50GiB.bin"
chown vaultlink:vaultlink "$mount_root/vaultlink-load/sparse-50GiB.bin"
chmod 0640 "$mount_root/vaultlink-load/sparse-50GiB.bin"
echo "Create a download share for vaultlink-load/sparse-50GiB.bin and an upload share for vaultlink-load/uploads."
