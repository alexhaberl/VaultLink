#!/bin/sh
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CDPATH=
LC_ALL=C
LANG=C
LIBGUESTFS_BACKEND=direct
LIBGUESTFS_BACKEND_SETTINGS=force_tcg
export PATH CDPATH LC_ALL LANG LIBGUESTFS_BACKEND \
    LIBGUESTFS_BACKEND_SETTINGS
umask 077

[ "$#" -eq 2 ] || {
    echo "usage: $0 inject|assert-clean QCOW2" >&2
    exit 64
}
action=$1
image=$2
case "$action" in inject|assert-clean) ;; *) exit 64 ;; esac
[ -f "$image" ] && [ ! -L "$image" ] || exit 66
image=$(cd -- "$(dirname -- "$image")" && pwd)/$(basename -- "$image")

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
cleanup_source=$script_dir/clear-tcg-device-timeout.sh
[ -f "$cleanup_source" ] && [ ! -L "$cleanup_source" ] || exit 66
[ "$(guestfish get-backend)" = direct ] || exit 70
[ "$(guestfish get-backend-settings)" = force_tcg ] || exit 70
override=/etc/systemd/system.conf.d/90-vaultlink-tcg-device-timeout.conf
cleanup=/usr/local/bin/vaultlink-clear-tcg-device-timeout
directory_marker=/etc/systemd/system.conf.d/.vaultlink-tcg-created-directory
selinux_policy=/etc/selinux/targeted/contexts/files/file_contexts
state_file=$image.vaultlink-tcg-state
work=$(mktemp -d)
cleanup_work() {
    status=$?
    trap - EXIT HUP INT TERM
    rm -rf -- "$work"
    exit "$status"
}
trap cleanup_work EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

cat >"$work/override.conf" <<'EOF'
[Manager]
DefaultDeviceTimeoutSec=5min
EOF
printf '%s\n' vaultlink-created >"$work/directory-marker"

inspect_paths() {
    guestfish --ro --format=qcow2 -a "$image" -i <<EOF
is-symlink /etc
is-dir /etc
is-symlink /etc/systemd
is-dir /etc/systemd
is-symlink /etc/systemd/system.conf.d
is-dir /etc/systemd/system.conf.d
is-symlink /usr
is-dir /usr
is-symlink /usr/local
is-dir /usr/local
is-symlink /usr/local/bin
is-dir /usr/local/bin
exists $override
is-symlink $override
exists $cleanup
is-symlink $cleanup
exists $directory_marker
is-symlink $directory_marker
exists $selinux_policy
is-symlink $selinux_policy
feature-available selinuxrelabel
EOF
}

inspect_paths >"$work/state"
cat >"$work/state-labels" <<'EOF'
etc_symlink
etc_directory
etc_systemd_symlink
etc_systemd_directory
etc_systemd_system_conf_d_symlink
etc_systemd_system_conf_d_directory
usr_symlink
usr_directory
usr_local_symlink
usr_local_directory
usr_local_bin_symlink
usr_local_bin_directory
timeout_override_exists
timeout_override_symlink
cleanup_helper_exists
cleanup_helper_symlink
directory_marker_exists
directory_marker_symlink
selinux_policy_exists
selinux_policy_symlink
selinuxrelabel_available
EOF
state_lines=$(wc -l <"$work/state" | tr -d '[:space:]')
state_boolean_lines=$(grep -E -c '^(true|false)$' "$work/state" || true)
if [ "$state_lines" -ne 21 ] || [ "$state_boolean_lines" -ne 21 ]; then
    state_sha256=$(sha256sum "$work/state" | awk '{print $1}')
    printf 'invalid Fedora systemd timeout path state: lines=%s boolean_lines=%s sha256=%s\n' \
        "$state_lines" "$state_boolean_lines" "$state_sha256" >&2
    exit 70
fi
report_unexpected_state() {
    state_sha256=$(sha256sum "$work/state" | awk '{print $1}')
    printf 'unexpected Fedora systemd timeout path state: sha256=%s\n' \
        "$state_sha256" >&2
    awk '
        NR == FNR { labels[NR] = $0; next }
        { print labels[FNR] "=" $0 }
    ' "$work/state-labels" "$work/state" >&2
}
cat >"$work/clean-missing-directory" <<'EOF'
false
true
false
true
false
false
false
true
false
true
false
true
false
false
false
false
false
false
true
false
true
EOF
cat >"$work/clean-existing-directory" <<'EOF'
false
true
false
true
false
true
false
true
false
true
false
true
false
false
false
false
false
false
true
false
true
EOF

if [ "$action" = inject ]; then
    [ ! -e "$state_file" ] && [ ! -L "$state_file" ] || exit 70
    marker_upload=
    marker_download=
    marker_relabel=
    marker_label_check=
    directory_relabel=
    directory_label_check="getxattr /etc/systemd/system.conf.d security.selinux"
    if cmp -s "$work/clean-missing-directory" "$work/state"; then
        printf '%s\n' absent >"$state_file"
        marker_upload="upload $work/directory-marker $directory_marker"
        marker_download="download $directory_marker $work/directory-marker.readback"
        marker_relabel="selinux-relabel $selinux_policy $directory_marker force:true"
        marker_label_check="getxattr $directory_marker security.selinux"
        directory_relabel="selinux-relabel $selinux_policy /etc/systemd/system.conf.d force:true"
    elif cmp -s "$work/clean-existing-directory" "$work/state"; then
        printf '%s\n' present >"$state_file"
    else
        report_unexpected_state
        exit 70
    fi
    chmod 0600 "$state_file"
    guestfish --rw --format=qcow2 -a "$image" -i <<EOF
mkdir-p /etc/systemd/system.conf.d
$marker_upload
$directory_relabel
upload $work/override.conf $override
chmod 0644 $override
upload $cleanup_source $cleanup
chmod 0700 $cleanup
selinux-relabel $selinux_policy $override force:true
selinux-relabel $selinux_policy $cleanup force:true
$marker_relabel
$directory_label_check
getxattr $override security.selinux
getxattr $cleanup security.selinux
$marker_label_check
download $override $work/override.readback
download $cleanup $work/cleanup.readback
$marker_download
EOF
    cmp "$work/override.conf" "$work/override.readback"
    cmp "$cleanup_source" "$work/cleanup.readback"
    if [ -n "$marker_download" ]; then
        cmp "$work/directory-marker" "$work/directory-marker.readback"
    fi
else
    [ -f "$state_file" ] && [ ! -L "$state_file" ] || exit 70
    case "$(cat "$state_file")" in
        absent) expected_state=$work/clean-missing-directory ;;
        present) expected_state=$work/clean-existing-directory ;;
        *) exit 70 ;;
    esac
    if ! cmp -s "$expected_state" "$work/state"; then
        report_unexpected_state
        exit 70
    fi
    rm -f -- "$state_file"
fi
