#!/bin/sh
# Compound guards intentionally use `A && B || fail` for fail-closed exits.
# shellcheck disable=SC2015
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CDPATH=
LC_ALL=C
LANG=C
export PATH CDPATH LC_ALL LANG

fail() {
    echo "native package lint failed: $*" >&2
    exit 1
}

[ "$#" -eq 2 ] || {
    echo "usage: lint-native-package.sh TARGET_ID PACKAGE" >&2
    exit 64
}
target_id=$1
package=$2
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
cd "$repo_root"
[ -f "$package" ] && [ ! -L "$package" ] && [ -s "$package" ] \
    || fail "package is missing, empty, or a symlink"
package_format=$(python3 tools/package-targets.py get \
    "$target_id" package_format --allow-unprovisioned)

case "$package_format" in
    deb)
        command -v lintian >/dev/null || fail "lintian is required for DEB targets"
        lintian --fail-on error "$package"
        ;;
    rpm)
        command -v rpmlint >/dev/null || fail "rpmlint is required for RPM targets"
        [ -f packaging/rpmlintrc ] && [ ! -L packaging/rpmlintrc ] \
            || fail "the reviewed rpmlint policy is unavailable"
        rpmlint -r packaging/rpmlintrc "$package"
        ;;
    pkg.tar.zst)
        command -v namcap >/dev/null || fail "namcap is required for Arch targets"
        namcap_log=$(mktemp "${TMPDIR:-/tmp}/vaultlink-namcap.XXXXXXXX")
        trap 'rm -f "$namcap_log"' 0 1 2 15
        if ! namcap "$package" >"$namcap_log" 2>&1; then
            cat "$namcap_log" >&2
            fail "namcap execution failed"
        fi
        cat "$namcap_log"
        if grep -E -q '(^|[[:space:]])E:[[:space:]]' "$namcap_log"; then
            fail "namcap reported a package error"
        fi
        # Namcap warnings remain visible for review, while every E: finding is
        # fail-closed because namcap itself intentionally exits zero for them.
        rm -f "$namcap_log"
        trap - 0 1 2 15
        ;;
    *) fail "unsupported package format: $package_format" ;;
esac

echo "$(basename "$package"): native package lint passed"
