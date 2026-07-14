#!/bin/sh
set -eu

# Optional argument: the configured VaultLink storage.root_mount_path.
storage_root=${1:-/mnt/storage/shared}
case "$storage_root" in
    /*) ;;
    *) echo "storage root must be an absolute path" >&2; exit 64 ;;
esac
[ "$storage_root" != / ] || {
    echo "storage root must not be the filesystem root" >&2
    exit 64
}
[ -d "$storage_root" ] || {
    echo "storage root must already exist" >&2
    exit 66
}

storage_root=$(realpath -e -- "$storage_root") || {
    echo "storage root could not be resolved" >&2
    exit 66
}
[ "$storage_root" != / ] || {
    echo "storage root must not resolve to the filesystem root" >&2
    exit 64
}

fixture_root="$storage_root/vaultlink-load"
if [ -e "$fixture_root" ] || [ -L "$fixture_root" ]; then
    echo "load fixture already exists" >&2
    exit 73
fi

# Build below an unpredictable, newly-created directory and publish it with one
# rename. This prevents a pre-positioned vaultlink-load symlink from redirecting
# privileged truncate/chown operations outside the configured SecureRoot.
fixture_temp=$(mktemp -d "$storage_root/.vaultlink-load.XXXXXXXXXX") || exit 73
published=false
cleanup() {
    if [ "$published" != true ]; then
        rm -rf -- "$fixture_temp"
    fi
}
trap cleanup EXIT HUP INT TERM

# mktemp deliberately creates the staging root as the invoking account with
# mode 0700. The atomic rename preserves that metadata, so normalize the root
# itself before publishing it for the unprivileged VaultLink service.
chown vaultlink:vaultlink "$fixture_temp"
chmod 0750 "$fixture_temp"
install -d -o vaultlink -g vaultlink -m 0750 "$fixture_temp/uploads"
truncate -s 50G "$fixture_temp/sparse-50GiB.bin"
chown vaultlink:vaultlink "$fixture_temp/sparse-50GiB.bin"
chmod 0640 "$fixture_temp/sparse-50GiB.bin"
if [ -e "$fixture_root" ] || [ -L "$fixture_root" ]; then
    echo "load fixture appeared while it was being prepared" >&2
    exit 73
fi
mv -T -- "$fixture_temp" "$fixture_root"
published=true
trap - EXIT HUP INT TERM
echo "Create a download share for vaultlink-load/sparse-50GiB.bin and an upload share for vaultlink-load/uploads."
