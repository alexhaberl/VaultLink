#!/bin/sh
set -eu

# This helper may be started by root, but every path mutation below the
# service-owned storage root must run as the VaultLink account. Keep command
# resolution independent from a caller-controlled environment in both phases.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV

usage_error() {
    echo "storage root must be an absolute path other than /" >&2
    exit 64
}

resolve_storage_root() {
    candidate=$1
    case "$candidate" in
        /*) ;;
        *) usage_error ;;
    esac
    [ "$candidate" != / ] || usage_error
    [ -d "$candidate" ] || {
        echo "storage root must already exist" >&2
        exit 66
    }

    resolved=$(/usr/bin/realpath -e -- "$candidate") || {
        echo "storage root could not be resolved" >&2
        exit 66
    }
    [ "$resolved" != / ] || usage_error
    printf '%s\n' "$resolved"
}

vaultlink_uid=$(/usr/bin/id -u vaultlink 2>/dev/null) || {
    echo "vaultlink account does not exist" >&2
    exit 67
}
caller_uid=$(/usr/bin/id -u)

if [ "$caller_uid" -eq 0 ]; then
    [ "$#" -eq 1 ] || usage_error
    storage_root=$(resolve_storage_root "$1")
    [ "$(/usr/bin/stat -c '%u' -- "$storage_root")" = "$vaultlink_uid" ] || {
        echo "storage root must be owned by the vaultlink service UID" >&2
        exit 77
    }

    script_path=$(/usr/bin/realpath -e -- "$0") || {
        echo "helper script could not be resolved" >&2
        exit 66
    }
    if [ ! -f "$script_path" ] \
        || [ "$(/usr/bin/stat -c '%u' -- "$script_path")" -ne 0 ] \
        || [ -n "$(/usr/bin/find "$script_path" -maxdepth 0 -perm /022 -print -quit)" ]; then
        echo "helper script must be a root-owned, non-writable regular file" >&2
        exit 77
    fi

    # No caller-controlled variable crosses the privilege boundary. Root does
    # not mutate any path under storage_root; runuser immediately re-executes
    # the canonical helper as the service account.
    exec /usr/bin/env -i \
        PATH=/usr/sbin:/usr/bin:/sbin:/bin \
        /usr/sbin/runuser -u vaultlink -- \
        /bin/sh "$script_path" --vaultlink-phase "$storage_root"
fi

[ "$caller_uid" -eq "$vaultlink_uid" ] || {
    echo "load fixture preparation requires root or the vaultlink account" >&2
    exit 77
}
if [ "$#" -ne 2 ] || [ "$1" != --vaultlink-phase ]; then
    echo "the vaultlink phase must be entered through the root validator" >&2
    exit 77
fi

storage_root=$(resolve_storage_root "$2")
[ "$(/usr/bin/stat -c '%u' -- "$storage_root")" = "$vaultlink_uid" ] || {
    echo "storage root ownership changed before fixture preparation" >&2
    exit 77
}

umask 027
fixture_root="$storage_root/vaultlink-load"
if [ -e "$fixture_root" ] || [ -L "$fixture_root" ]; then
    echo "load fixture already exists" >&2
    exit 73
fi

fixture_temp=$(/usr/bin/mktemp -d "$storage_root/.vaultlink-load.XXXXXXXXXX") || exit 73
published=false
cleanup() {
    if [ "$published" != true ]; then
        /usr/bin/rm -rf -- "$fixture_temp"
    fi
}
trap cleanup EXIT
trap 'exit 70' HUP INT TERM

/usr/bin/chmod 0750 "$fixture_temp"
/usr/bin/mkdir -m 0750 "$fixture_temp/uploads"
# Create the pathname separately from sizing it. Besides making the intended
# mode explicit through this phase's umask, this gives the adversarial smoke a
# deterministic boundary at which it can replace the pathname before
# `truncate`. Both operations still run as the unprivileged service account.
/usr/bin/touch "$fixture_temp/sparse-50GiB.bin"
/usr/bin/truncate -s 50G "$fixture_temp/sparse-50GiB.bin"
/usr/bin/chmod 0640 "$fixture_temp/sparse-50GiB.bin"

# GNU mv -n deliberately reports success on a collision. Verify that the
# staging name disappeared so a concurrently-created target is never mistaken
# for our published fixture.
/usr/bin/mv -T -n -- "$fixture_temp" "$fixture_root"
if [ -e "$fixture_temp" ] || [ -L "$fixture_temp" ]; then
    echo "load fixture appeared while it was being prepared" >&2
    exit 73
fi

published=true
trap - EXIT HUP INT TERM
echo "Create a download share for vaultlink-load/sparse-50GiB.bin and an upload share for vaultlink-load/uploads."
