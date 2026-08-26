#!/bin/sh
# Compound guards intentionally use `A && B || fail` for fail-closed exits.
# shellcheck disable=SC2015
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CDPATH=
LC_ALL=C
LANG=C
export PATH CDPATH LC_ALL LANG
umask 077

fail() {
    echo "native package verification failed: $*" >&2
    exit 1
}

# Keep this independent verifier aligned with dpkg-gencontrol's reproducible
# Debian Policy 5.6.20 Installed-Size algorithm.
debian_installed_size() {
    deb_size_root=$1
    deb_size_inventory=$2
    find "$deb_size_root" -printf '%y\t%s\t%D:%i\n' >"$deb_size_inventory" \
        || return 1
    awk -F '\t' '
        $1 == "f" || $1 == "l" {
            if (!seen[$3]++) total += int(($2 + 1023) / 1024)
            next
        }
        { total += 1 }
        END { print total + 0 }
    ' "$deb_size_inventory"
}

files_are_equal() {
    [ "$(sha256sum "$1" | awk '{ print $1 }')" = \
        "$(sha256sum "$2" | awk '{ print $1 }')" ]
}

no_exec=0
case "$#" in
    5) ;;
    6)
        [ "$6" = --no-exec ] || {
            echo "usage: verify-native-package.sh TARGET_ID VERSION PACKAGE BINARY SBOM [--no-exec]" >&2
            exit 64
        }
        no_exec=1
        ;;
    *)
        echo "usage: verify-native-package.sh TARGET_ID VERSION PACKAGE BINARY SBOM [--no-exec]" >&2
        exit 64
        ;;
esac
target_id=$1
version=$2
package=$3
binary_source=$4
sbom_source=$5
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
cd "$repo_root"

[ -f "$package" ] && [ ! -L "$package" ] && [ -s "$package" ] \
    || fail "package is missing, empty, or a symlink"
[ -f "$binary_source" ] && [ ! -L "$binary_source" ] \
    || fail "reference binary is unavailable"
[ -f "$sbom_source" ] && [ ! -L "$sbom_source" ] \
    || fail "reference SBOM is unavailable"
python3 tools/package-targets.py validate --allow-unprovisioned >/dev/null

target_get() {
    python3 tools/package-targets.py get "$target_id" "$1" --allow-unprovisioned
}

os_id=$(target_get distribution)
os_version=$(target_get version)
package_format=$(target_get package_format)
package_arch=$(target_get package_arch)
expected_uname=$(target_get uname)
builder_packages_sha256=$(target_get builder_packages_sha256)
asset_name=$(python3 tools/package-targets.py asset "$target_id" "$version" --allow-unprovisioned)
[ "$(basename "$package")" = "$asset_name" ] \
    || fail "package asset name does not match the target manifest"
if [ "$no_exec" -eq 0 ]; then
    [ "$(uname -m)" = "$expected_uname" ] \
        || fail "package verification must run on native $expected_uname"
fi
if [ "$os_id" = arch ]; then
    [ "$os_version" = rolling ] || fail "unexpected Arch manifest target"
    os_version=rolling
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/vaultlink-package-verify.XXXXXXXX")
cleanup() {
    rm -rf "$work"
}
trap cleanup 0 1 2 15
root="$work/root"
install -d "$root"
package_source=$package
package_source_identity=$(stat -c '%d:%i:%s' "$package_source")
package_input_sha256=$(sha256sum "$package_source" | awk '{ print $1 }')
install -m 0600 "$package_source" "$work/package.input"
[ "$(stat -c '%d:%i:%s' "$package_source")" = "$package_source_identity" ] \
    && [ "$(sha256sum "$package_source" | awk '{ print $1 }')" = \
        "$package_input_sha256" ] \
    || fail "package source changed while it was frozen"
[ "$(sha256sum "$work/package.input" | awk '{ print $1 }')" = \
    "$package_input_sha256" ] \
    || fail "frozen package differs from its validated source"
package=$work/package.input
lifecycle_sha256=$(sha256sum packaging/vaultlink-package-lifecycle.sh | awk '{ print $1 }')
sed '1{/^#!\/bin\/sh$/d;}' packaging/vaultlink-package-lifecycle.sh \
    >"$work/expected-lifecycle-body"

verify_embedded_lifecycle() {
    script=$1
    begin_count=$(grep -F -c '# BEGIN VAULTLINK PACKAGE LIFECYCLE' "$script" || true)
    end_count=$(grep -F -c '# END VAULTLINK PACKAGE LIFECYCLE' "$script" || true)
    [ "$begin_count:$end_count" = 1:1 ] \
        || fail "$script must embed exactly one bounded lifecycle copy"
    [ "$(grep -F -c "# VAULTLINK_PACKAGE_LIFECYCLE_SHA256=$lifecycle_sha256" "$script" || true)" -eq 1 ] \
        || fail "$script embeds an unexpected lifecycle revision"
    awk '
        $0 == "# BEGIN VAULTLINK PACKAGE LIFECYCLE" { copy = 1; next }
        $0 == "# END VAULTLINK PACKAGE LIFECYCLE" { copy = 0; exit }
        copy { print }
    ' "$script" >"$work/actual-lifecycle-body"
    files_are_equal "$work/expected-lifecycle-body" "$work/actual-lifecycle-body" \
        || fail "$script lifecycle body differs from the reviewed source"
}

verify_installed_lifecycle_wrapper() {
    script=$1
    operation=$2
    [ "$(grep -F -c '# BEGIN VAULTLINK PACKAGE LIFECYCLE' "$script" || true)" -eq 0 ] \
        || fail "$script unnecessarily embeds the lifecycle helper"
    [ "$(grep -F -c "/usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh $operation" "$script" || true)" -eq 1 ] \
        || fail "$script must invoke the installed $operation helper exactly once"
    [ "$(wc -l <"$script" | tr -d '[:space:]')" -le 32 ] \
        || fail "$script exceeds the bounded installed-helper wrapper size"
}

append_expected_lifecycle_source() {
    destination=$1
    {
        printf '%s\n' 'VAULTLINK_PACKAGE_LIFECYCLE_EMBEDDED=1'
        printf '%s\n' "# VAULTLINK_PACKAGE_LIFECYCLE_SHA256=$lifecycle_sha256"
        printf '%s\n' '# BEGIN VAULTLINK PACKAGE LIFECYCLE'
        sed '1{/^#!\/bin\/sh$/d;}' packaging/vaultlink-package-lifecycle.sh
        printf '%s\n' '# END VAULTLINK PACKAGE LIFECYCLE'
    } >>"$destination"
}

render_expected_deb_scripts() {
    expected_control=$1
    install -d "$expected_control"

    expected_preinst="$expected_control/preinst"
    printf '%s\n' '#!/bin/sh' >"$expected_preinst"
    append_expected_lifecycle_source "$expected_preinst"
    cat >>"$expected_preinst" <<EOF
case "\${1:-}" in
    install)
        if [ -e /usr/share/vaultlink/install-method.env ] \
            || [ -L /usr/share/vaultlink/install-method.env ]; then
            lifecycle_mode=reinstall
        else
            lifecycle_mode=fresh
        fi
        ;;
    upgrade) lifecycle_mode=upgrade ;;
    abort-upgrade) exit 0 ;;
    *) package_fail "unsupported Debian preinst operation: \${1:-missing}" ;;
esac
vaultlink_package_main preinstall "$package_format" "$os_id" "$os_version" "$package_arch" vaultlink "\$lifecycle_mode"
EOF

    expected_postinst="$expected_control/postinst"
    printf '%s\n' '#!/bin/sh' 'set -eu' >"$expected_postinst"
    cat >>"$expected_postinst" <<EOF
case "\${1:-}" in
    configure) ;;
    abort-upgrade|abort-remove|abort-deconfigure) exit 0 ;;
    *) echo "unsupported Debian postinst operation: \${1:-missing}" >&2; exit 1 ;;
esac
case "\$#" in
    1|2) ;;
    *) echo "invalid Debian configure version arguments" >&2; exit 1 ;;
esac
case "\${2:-}" in
    '') lifecycle_mode=fresh ;;
    ?*)
        if [ -e /opt/vaultlink/vaultlink ] \
            || [ -L /opt/vaultlink/vaultlink ]; then
            lifecycle_mode=upgrade
        else
            lifecycle_mode=reinstall
        fi
        ;;
esac
/usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh postinstall "$package_format" "$os_id" "$os_version" "$package_arch" vaultlink "\$lifecycle_mode" "$version"
EOF

    expected_prerm="$expected_control/prerm"
    printf '%s\n' '#!/bin/sh' 'set -eu' >"$expected_prerm"
    cat >>"$expected_prerm" <<EOF
case "\${1:-}" in
    remove|deconfigure)
        exec /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh preremove "$package_format" "$os_id" "$os_version" "$package_arch" vaultlink remove
        ;;
    upgrade|failed-upgrade) exit 0 ;;
    *) echo "unsupported Debian prerm operation: \${1:-missing}" >&2; exit 1 ;;
esac
EOF

    expected_postrm="$expected_control/postrm"
    printf '%s\n' '#!/bin/sh' >"$expected_postrm"
    append_expected_lifecycle_source "$expected_postrm"
    cat >>"$expected_postrm" <<EOF
case "\${1:-}" in
    remove|purge|disappear)
        vaultlink_package_main postremove "$package_format" "$os_id" "$os_version" "$package_arch" vaultlink remove
        ;;
    upgrade|failed-upgrade) exit 0 ;;
    abort-install|abort-upgrade) exit 0 ;;
    *) package_fail "unsupported Debian postrm operation: \${1:-missing}" ;;
esac
EOF
}

render_expected_deb_control() {
    expected_control_file=$1
    expected_deb_version=$2
    expected_installed_size=$3
    cat >"$expected_control_file" <<EOF
Package: vaultlink
Version: $expected_deb_version
Architecture: $package_arch
Maintainer: VaultLink maintainers <alexhaberl@users.noreply.github.com>
Installed-Size: $expected_installed_size
Depends: ca-certificates, curl, libc6, libgcc-s1, mawk, minisign, sqlite3, systemd
Suggests: cifs-utils
Section: net
Priority: optional
Homepage: https://github.com/alexhaberl/VaultLink
Description: secure file sharing for an existing Linux mountpoint
 VaultLink provides hardened self-hosted file sharing with explicit setup,
 signed updates, transactional activation, and verified rollback.
EOF
}

render_expected_rpm_scripts() {
    expected_rpm=$1
    install -d "$expected_rpm"
    # These are the literal positional-parameter expressions stored in RPM.
    # shellcheck disable=SC2016
    rpm_install_mode='if [ "${1:-1}" -gt 1 ]; then lifecycle_mode=upgrade; elif [ -e /var/lib/vaultlink-backups/install-method.env ] || [ -L /var/lib/vaultlink-backups/install-method.env ]; then lifecycle_mode=reinstall; else lifecycle_mode=fresh; fi'
    # shellcheck disable=SC2016
    rpm_remove_mode='if [ "${1:-0}" -ne 0 ]; then exit 0; fi; lifecycle_mode=remove'

    printf '%s\n' '#!/bin/sh' >"$expected_rpm/prein"
    append_expected_lifecycle_source "$expected_rpm/prein"
    printf '%s\n' "$rpm_install_mode" \
        "vaultlink_package_main preinstall \"$package_format\" \"$os_id\" \"$os_version\" \"$package_arch\" vaultlink \"\$lifecycle_mode\"" \
        >>"$expected_rpm/prein"

    printf '%s\n' '#!/bin/sh' 'set -eu' \
        "$rpm_install_mode" \
        "exec /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh postinstall \"$package_format\" \"$os_id\" \"$os_version\" \"$package_arch\" vaultlink \"\$lifecycle_mode\" \"$version\"" \
        >"$expected_rpm/postin"

    printf '%s\n' '#!/bin/sh' 'set -eu' \
        "$rpm_remove_mode" \
        "exec /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh preremove \"$package_format\" \"$os_id\" \"$os_version\" \"$package_arch\" vaultlink \"\$lifecycle_mode\"" \
        >"$expected_rpm/preun"

    printf '%s\n' '#!/bin/sh' >"$expected_rpm/postun"
    append_expected_lifecycle_source "$expected_rpm/postun"
    printf '%s\n' "$rpm_remove_mode" \
        "vaultlink_package_main postremove \"$package_format\" \"$os_id\" \"$os_version\" \"$package_arch\" vaultlink \"\$lifecycle_mode\"" \
        >>"$expected_rpm/postun"
}

render_expected_arch_install() {
    expected_install=$1
    printf '%s\n' '#!/bin/sh' >"$expected_install"
    append_expected_lifecycle_source "$expected_install"
    cat >>"$expected_install" <<EOF
pre_install() {
    if [ -e /usr/share/vaultlink/install-method.env ] || [ -L /usr/share/vaultlink/install-method.env ]; then
        lifecycle_mode=reinstall
    else
        lifecycle_mode=fresh
    fi
    vaultlink_package_main preinstall "$package_format" "$os_id" "$os_version" "$package_arch" vaultlink "\$lifecycle_mode"
}
post_install() {
    if [ -e /usr/share/vaultlink/install-method.env ] || [ -L /usr/share/vaultlink/install-method.env ]; then
        lifecycle_mode=reinstall
    else
        lifecycle_mode=fresh
    fi
    vaultlink_package_main postinstall "$package_format" "$os_id" "$os_version" "$package_arch" vaultlink "\$lifecycle_mode" "$version"
}
pre_upgrade() {
    vaultlink_package_main preinstall "$package_format" "$os_id" "$os_version" "$package_arch" vaultlink upgrade
}
post_upgrade() {
    vaultlink_package_main postinstall "$package_format" "$os_id" "$os_version" "$package_arch" vaultlink upgrade "$version"
}
pre_remove() {
    vaultlink_package_main preremove "$package_format" "$os_id" "$os_version" "$package_arch" vaultlink remove
}
post_remove() {
    vaultlink_package_main postremove "$package_format" "$os_id" "$os_version" "$package_arch" vaultlink remove
}
EOF
}

render_expected_arch_pkginfo() {
    expected_pkginfo=$1
    expected_builddate=$2
    expected_package_size=$3
    expected_makepkg_version=$4
    expected_fakeroot_version=$5
    cat >"$expected_pkginfo" <<EOF
# Generated by makepkg $expected_makepkg_version
# using fakeroot version $expected_fakeroot_version
pkgname = vaultlink
pkgbase = vaultlink
xdata = pkgtype=pkg
pkgver = $version-1
pkgdesc = Secure file sharing for an existing Linux mountpoint
url = https://github.com/alexhaberl/VaultLink
builddate = $expected_builddate
packager = VaultLink maintainers <noreply@vaultlink.example>
size = $expected_package_size
arch = $package_arch
license = MIT
depend = bash
depend = ca-certificates
depend = coreutils
depend = curl
depend = diffutils
depend = findutils
depend = gawk
depend = gcc-libs
depend = glibc
depend = grep
depend = gzip
depend = libarchive
depend = minisign
depend = sed
depend = sqlite
depend = systemd
depend = tar
depend = util-linux
depend = zstd
optdepend = cifs-utils: SMB 3.1.1 storage provisioning
EOF
}

render_expected_arch_buildinfo() {
    expected_buildinfo=$1
    expected_builddate=$2
    expected_pkgbuild_sha256=$3
    expected_buildtool_version=$4
    cat >"$expected_buildinfo" <<EOF
format = 2
pkgname = vaultlink
pkgbase = vaultlink
pkgver = $version-1
pkgarch = $package_arch
pkgbuild_sha256sum = $expected_pkgbuild_sha256
packager = VaultLink maintainers <noreply@vaultlink.example>
builddate = $expected_builddate
builddir = /build/vaultlink-package
startdir = /build/vaultlink-package
buildtool = makepkg
buildtoolver = $expected_buildtool_version
buildenv = !distcc
buildenv = color
buildenv = !ccache
buildenv = check
buildenv = !sign
options = strip
options = docs
options = !libtool
options = !staticlibs
options = emptydirs
options = zipman
options = purge
options = debug
options = lto
EOF
}

append_validated_arch_installed_closure() {
    closure_buildinfo=$1
    closure_builder_lock=$2
    closure_destination=$3
    awk '
        NF != 2 || $1 !~ /^[A-Za-z0-9@._+-]+$/ \
            || $2 !~ /^[A-Za-z0-9@._+:-]+$/ { exit 1 }
    ' "$closure_builder_lock" \
        || fail "Arch builder package lock contains unsafe records"
    LC_ALL=C sort -c -u "$closure_builder_lock" \
        || fail "Arch builder package lock must be sorted and unique"
    sed -n 's/^installed = //p' "$closure_buildinfo" \
        >"$work/actual-arch-installed"
    [ "$(wc -l <"$work/actual-arch-installed" | tr -d '[:space:]')" = \
        "$(wc -l <"$closure_builder_lock" | tr -d '[:space:]')" ] \
        || fail "Arch BUILDINFO installed closure count differs from builder lock"
    : >"$work/expected-arch-installed"
    while read -r closure_name closure_version; do
        closure_matches=$(grep -F -x \
            -e "$closure_name-$closure_version-$package_arch" \
            -e "$closure_name-$closure_version-any" \
            "$work/actual-arch-installed" || true)
        [ "$(printf '%s\n' "$closure_matches" | grep -c . || true)" -eq 1 ] \
            || fail "Arch BUILDINFO does not exactly bind $closure_name from the builder lock"
        printf '%s\n' "$closure_matches" >>"$work/expected-arch-installed"
    done <"$closure_builder_lock"
    files_are_equal "$work/expected-arch-installed" "$work/actual-arch-installed" \
        || fail "Arch BUILDINFO installed closure order or values are non-canonical"
    sed 's/^/installed = /' "$work/expected-arch-installed" \
        >>"$closure_destination"
}

verify_arch_mtree() {
    mtree_root=$1
    command -v gzip >/dev/null || fail "gzip is required for Arch MTREE verification"
    gzip -t "$mtree_root/.MTREE" \
        || fail "Arch .MTREE is not valid gzip data"
    gzip -dc "$mtree_root/.MTREE" >"$work/actual-package.mtree"
    # makepkg delegates .MTREE compression to gzip's pinned default level.
    gzip -n <"$work/actual-package.mtree" >"$work/canonical.MTREE"
    files_are_equal "$work/canonical.MTREE" "$mtree_root/.MTREE" \
        || fail "Arch .MTREE compression is not canonical"
    (
        cd "$mtree_root"
        bsdtar --format=mtree \
            --options='!all,use-set,type,uid,gid,mode,time,size,sha256,link' \
            --exclude .MTREE -cf - .
    ) >"$work/recomputed-package.mtree" \
        || fail "Arch .MTREE payload reconstruction failed"
    [ "$(grep -c '^\. ' "$work/actual-package.mtree" || true)" -eq 0 ] \
        || fail "Arch .MTREE must not contain an unowned package-root record"
    # Extraction deliberately retains the private verifier directory's mode
    # and time. makepkg omits that unowned root from .MTREE, so compare every
    # package-owned child against a fresh semantic reconstruction.
    sed '/^\. /d' "$work/actual-package.mtree" >"$work/actual-package-body.mtree"
    sed '/^\. /d' "$work/recomputed-package.mtree" \
        >"$work/recomputed-package-body.mtree"
    files_are_equal "$work/actual-package-body.mtree" \
        "$work/recomputed-package-body.mtree" \
        || fail "Arch .MTREE does not match package payload metadata and hashes"
    bsdtar -tf "$mtree_root/.MTREE" \
        | sed -e 's|^\./||' -e 's|/$||' -e '/^$/d' -e '/^\.$/d' \
        | sort >"$work/mtree-files"
    (cd "$mtree_root" && find . -mindepth 1 ! -name .MTREE -print \
        | sed 's|^\./||' | sort) >"$work/expected-mtree-files"
    files_are_equal "$work/expected-mtree-files" "$work/mtree-files" \
        || fail "Arch .MTREE inventory differs from the package archive"
}

rpm_tag_must_be_empty() {
    rpm_tag=$1
    rpm_tag_value=$(rpm -qp --queryformat "%{$rpm_tag}" "$package")
    case "$rpm_tag_value" in ''|'(none)') ;; *) fail "RPM contains forbidden $rpm_tag metadata" ;; esac
}

prepare_expected_payload_inventory() {
    cat >"$work/expected-files" <<'EOF'
usr/lib/systemd/system/vaultlink-update.service
usr/lib/systemd/system/vaultlink-update.timer
usr/lib/systemd/system/vaultlink.service
usr/lib/sysusers.d/vaultlink.conf
usr/lib/tmpfiles.d/vaultlink.conf
usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh
usr/lib/vaultlink/package/deploy/vaultlink-runtime-guard.sh
usr/lib/vaultlink/package/deploy/vaultlink-rollback.sh
usr/lib/vaultlink/package/deploy/vaultlink-upgrade.sh
usr/lib/vaultlink/package/vaultlink
usr/lib/vaultlink/package/vaultlink.cdx.json
usr/lib/vaultlink/package/vaultlink.sha256
usr/lib/vaultlink/package/version
usr/sbin/vaultlink-update
usr/share/doc/vaultlink/examples/config/development.toml
usr/share/doc/vaultlink/examples/config/production-reverse-proxy.toml
usr/share/doc/vaultlink/examples/config/production-standalone-letsencrypt.toml
usr/share/doc/vaultlink/examples/config/production-standalone-tls.toml
usr/share/doc/vaultlink/examples/deploy/Caddyfile
usr/share/doc/vaultlink/examples/deploy/mnt-storage.mount.example
usr/share/doc/vaultlink/examples/deploy/vaultlink-external-proxy-network.conf
usr/share/doc/vaultlink/examples/deploy/vaultlink-external-storage.conf
usr/share/doc/vaultlink/examples/deploy/vaultlink-standalone-capability.conf
usr/share/doc/vaultlink/examples/deploy/vaultlink-update.conf.example
usr/share/licenses/vaultlink/LICENSE
usr/share/vaultlink/install-method.env
usr/share/vaultlink/minisign.pub
usr/share/vaultlink/update.conf.example
EOF
    if [ "$package_format" = deb ]; then
        printf '%s\n' \
            'usr/share/doc/vaultlink/changelog.Debian.gz' \
            'usr/share/doc/vaultlink/copyright' \
            >>"$work/expected-files"
    fi
    if [ "$package_format" = pkg.tar.zst ]; then
        sed -i 's|^usr/sbin/vaultlink-update$|usr/bin/vaultlink-update|' "$work/expected-files"
        sed -i '/^usr\/share\/vaultlink\/install-method.env$/d' "$work/expected-files"
        printf '%s\n' \
            'usr/lib/vaultlink/package/PKGBUILD' \
            'usr/lib/vaultlink/package/builder-packages.lock' \
            'usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh' \
            'usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh' \
            'usr/share/libalpm/hooks/vaultlink-remove.hook' \
            >>"$work/expected-files"
    fi
    sort -o "$work/expected-files" "$work/expected-files"

    cat >"$work/expected-directories" <<'EOF'
usr
usr/lib
usr/lib/systemd
usr/lib/systemd/system
usr/lib/sysusers.d
usr/lib/tmpfiles.d
usr/lib/vaultlink
usr/lib/vaultlink/package
usr/lib/vaultlink/package/deploy
usr/sbin
usr/share
usr/share/doc
usr/share/doc/vaultlink
usr/share/doc/vaultlink/examples
usr/share/doc/vaultlink/examples/config
usr/share/doc/vaultlink/examples/deploy
usr/share/licenses
usr/share/licenses/vaultlink
usr/share/vaultlink
EOF
    if [ "$package_format" = pkg.tar.zst ]; then
        sed -i 's|^usr/sbin$|usr/bin|' "$work/expected-directories"
        printf '%s\n' 'usr/share/libalpm' 'usr/share/libalpm/hooks' \
            >>"$work/expected-directories"
    fi
    sort -o "$work/expected-directories" "$work/expected-directories"
}

validate_archive_inventory() {
    archive_paths=$1
    archive_types=$2
    expected_members=$3
    [ "$(wc -l <"$archive_paths" | tr -d '[:space:]')" = \
        "$(wc -l <"$archive_types" | tr -d '[:space:]')" ] \
        || fail "package archive listing/type counts differ"
    awk '$0 != "-" && $0 != "d" { exit 1 }' "$archive_types" \
        || fail "package archive contains a link or special file"
    awk -v format="$package_format" '
        NR == FNR { archive_type[FNR] = $0; next }
        $0 == "." || $0 == "./" {
            root_count++
            if (archive_type[FNR] != "d") invalid = 1
        }
        END {
            if (invalid) exit 1
            if (format == "deb" && root_count != 1) exit 1
            if (format != "deb" && root_count != 0) exit 1
        }
    ' "$archive_types" "$archive_paths" \
        || fail "package archive has an invalid root-directory record"
    awk '
        {
            path = $0
            sub(/^\.\//, "", path)
            sub(/\/$/, "", path)
            if (path == "" || path == ".") next
            if (path ~ /^\// || path ~ /[^A-Za-z0-9._@+\/-]/ \
                || path ~ /\/\// || path == ".." || path ~ /^\.\.\// \
                || path ~ /\/\.\.($|\/)/ || path ~ /^\.\// || path ~ /\/\.($|\/)/)
                exit 1
            print path
        }
    ' "$archive_paths" >"$work/archive-members.normalized" \
        || fail "package archive contains an unsafe path"
    [ -z "$(sort "$work/archive-members.normalized" | uniq -d | sed -n '1p')" ] \
        || fail "package archive contains duplicate paths"
    sort "$work/archive-members.normalized" >"$work/archive-members.sorted"
    files_are_equal "$expected_members" "$work/archive-members.sorted" \
        || fail "package archive inventory differs from the reviewed allowlist"
}

validate_payload_member_allowlist() {
    payload_members=$1
    comm -23 "$payload_members" "$work/expected-payload-members" \
        >"$work/unexpected-payload-members"
    [ ! -s "$work/unexpected-payload-members" ] \
        || fail "package archive contains a path outside the reviewed payload allowlist"
    comm -23 "$work/expected-files" "$payload_members" \
        >"$work/missing-payload-files"
    [ ! -s "$work/missing-payload-files" ] \
        || fail "package archive omits a required payload file"
}

prepare_expected_payload_inventory
cat "$work/expected-files" "$work/expected-directories" \
    | sort >"$work/expected-payload-members"

case "$package_format" in
    deb)
        command -v dpkg-deb >/dev/null || fail "dpkg-deb is required"
        command -v md5sum >/dev/null || fail "md5sum is required"
        command -v tar >/dev/null || fail "tar is required"
        command -v xargs >/dev/null || fail "xargs is required"
        [ "$(dpkg-deb -f "$package" Package)" = vaultlink ] \
            || fail "unexpected Debian package name"
        [ "$(dpkg-deb -f "$package" Architecture)" = "$package_arch" ] \
            || fail "unexpected Debian package architecture"
        deb_version="${version}-1"
        case "$os_id:$os_version" in
            debian:13) deb_version="${deb_version}+deb13" ;;
            ubuntu:24.04) deb_version="${deb_version}+ubuntu24.04" ;;
            ubuntu:26.04) deb_version="${deb_version}+ubuntu26.04" ;;
            *) fail "unexpected DEB target" ;;
        esac
        [ "$(dpkg-deb -f "$package" Version)" = "$deb_version" ] \
            || fail "unexpected Debian package version"
        [ "$(dpkg-deb -f "$package" Depends)" = \
            'ca-certificates, curl, libc6, libgcc-s1, mawk, minisign, sqlite3, systemd' ] \
            || fail "Debian runtime dependencies differ from the target allowlist"
        [ "$(dpkg-deb -f "$package" Suggests)" = cifs-utils ] \
            || fail "cifs-utils must be the sole optional Debian dependency"
        [ -z "$(dpkg-deb -f "$package" Recommends 2>/dev/null || true)" ] \
            || fail "Debian package has unexpected recommendations"
        [ "$(dpkg-deb -f "$package" Section)" = net ] \
            && [ "$(dpkg-deb -f "$package" Priority)" = optional ] \
            || fail "unexpected Debian section or priority"
        dpkg-deb --fsys-tarfile "$package" >"$work/deb-data.tar"
        tar -tf "$work/deb-data.tar" >"$work/archive-paths"
        tar -tvf "$work/deb-data.tar" | awk '{ print substr($1, 1, 1) }' \
            >"$work/archive-types"
        validate_archive_inventory "$work/archive-paths" "$work/archive-types" \
            "$work/expected-payload-members"
        dpkg-deb --ctrl-tarfile "$package" >"$work/deb-control.tar"
        tar -tf "$work/deb-control.tar" >"$work/archive-paths"
        tar -tvf "$work/deb-control.tar" | awk '{ print substr($1, 1, 1) }' \
            >"$work/archive-types"
        cat >"$work/expected-control-archive-members" <<'EOF'
control
md5sums
postinst
postrm
preinst
prerm
EOF
        validate_archive_inventory "$work/archive-paths" "$work/archive-types" \
            "$work/expected-control-archive-members"
        [ "$(sha256sum "$package" | awk '{ print $1 }')" = "$package_input_sha256" ] \
            || fail "package changed while it was being validated"
        dpkg-deb -x "$package" "$root"
        dpkg-deb -e "$package" "$work/control"
        find "$work/control" -mindepth 1 -maxdepth 1 -printf '%f\n' \
            | sort >"$work/control-members"
        cat >"$work/expected-control-members" <<'EOF'
control
md5sums
postinst
postrm
preinst
prerm
EOF
        files_are_equal "$work/expected-control-members" "$work/control-members" \
            || fail "Debian control archive contains unexpected or missing members"
        [ -z "$(find "$work/control" -mindepth 1 ! -type f -print -quit)" ] \
            || fail "Debian control archive members must be regular files"
        for control_metadata in control md5sums; do
            [ "$(stat -c '%a' "$work/control/$control_metadata")" = 644 ] \
                || fail "Debian control member $control_metadata must be mode 0644"
        done
        for script in preinst postinst prerm postrm; do
            [ -x "$work/control/$script" ] \
                || fail "Debian maintainer script $script is missing"
            [ "$(stat -c '%a' "$work/control/$script")" = 755 ] \
                || fail "Debian maintainer script $script must be mode 0755"
        done
        installed_size=$(debian_installed_size "$root" \
            "$work/deb-installed-size.inventory") \
            || fail "failed to calculate Debian Installed-Size"
        render_expected_deb_control "$work/expected-deb-control" \
            "$deb_version" "$installed_size"
        files_are_equal "$work/expected-deb-control" "$work/control/control" \
            || fail "Debian control fields or values differ from the reviewed template"
        (
            cd "$root"
            find usr -type f -print0 | sort -z | xargs -0 md5sum
        ) >"$work/expected-md5sums"
        files_are_equal "$work/expected-md5sums" "$work/control/md5sums" \
            || fail "Debian md5sums is not the canonical checksum inventory"
        render_expected_deb_scripts "$work/expected-control"
        for script in preinst postinst prerm postrm; do
            files_are_equal "$work/expected-control/$script" "$work/control/$script" \
                || fail "Debian maintainer script $script differs from the reviewed template"
        done
        grep -F -q 'refusing to adopt markerless existing installation' "$work/control/preinst" \
            || fail "Debian preinst lacks the markerless-install guard"
        verify_embedded_lifecycle "$work/control/preinst"
        verify_installed_lifecycle_wrapper "$work/control/postinst" postinstall
        verify_installed_lifecycle_wrapper "$work/control/prerm" preremove
        verify_embedded_lifecycle "$work/control/postrm"
        ;;
    rpm)
        command -v rpm >/dev/null || fail "rpm is required"
        command -v rpm2cpio >/dev/null || fail "rpm2cpio is required"
        command -v cpio >/dev/null || fail "cpio is required"
        [ "$(rpm -qp --queryformat '%{NAME}' "$package")" = vaultlink ] \
            || fail "unexpected RPM package name"
        [ "$(rpm -qp --queryformat '%{ARCH}' "$package")" = "$package_arch" ] \
            || fail "unexpected RPM architecture"
        [ "$(rpm -qp --queryformat '%{VERSION}-%{RELEASE}' "$package")" = "$version-1.fc44" ] \
            || fail "unexpected RPM version"
        [ "$(rpm -qp --queryformat '%{EPOCHNUM}' "$package")" = 0 ] \
            || fail "RPM epoch must be exactly zero"
        rpm -qp --requires "$package" | grep -v '^rpmlib(' | sort -u >"$work/rpm-requires"
        cat >"$work/expected-rpm-requires" <<'EOF'
/bin/sh
bash
ca-certificates
coreutils
cpio
curl
diffutils
findutils
gawk
glibc
grep
gzip
libgcc
minisign
rpm
sed
sqlite
systemd
tar
util-linux
EOF
        files_are_equal "$work/expected-rpm-requires" "$work/rpm-requires" \
            || fail "RPM runtime dependencies differ from the target allowlist"
        rpm -qp --queryformat '[%{REQUIRENAME}\t%{REQUIREFLAGS}\t%{REQUIREVERSION}\n]' \
            "$package" | sort >"$work/rpm-require-tuples"
        printf '%s\t%s\t\n' \
            /bin/sh 768 /bin/sh 1280 /bin/sh 2304 /bin/sh 4352 \
            >"$work/expected-rpm-require-tuples.unsorted"
        while IFS= read -r expected_rpm_dependency; do
            [ "$expected_rpm_dependency" = /bin/sh ] && continue
            printf '%s\t0\t\n' "$expected_rpm_dependency" \
                >>"$work/expected-rpm-require-tuples.unsorted"
        done <"$work/expected-rpm-requires"
        cat >>"$work/expected-rpm-require-tuples.unsorted" <<'EOF'
rpmlib(CompressedFileNames)	16777226	3.0.4-1
rpmlib(FileDigests)	16777226	4.6.0-1
rpmlib(PayloadFilesHavePrefix)	16777226	4.0-1
rpmlib(PayloadIsZstd)	16777226	5.4.18-1
EOF
        sort "$work/expected-rpm-require-tuples.unsorted" \
            >"$work/expected-rpm-require-tuples"
        files_are_equal "$work/expected-rpm-require-tuples" "$work/rpm-require-tuples" \
            || fail "RPM require name/flags/version tuples differ from the reviewed allowlist"
        [ "$(rpm -qp --recommends "$package")" = cifs-utils ] \
            || fail "cifs-utils must be the sole RPM recommendation"
        [ -z "$(rpm -qp --suggests "$package")" ] \
            || fail "RPM package has unexpected suggestions"
        [ -z "$(rpm -qp --enhances "$package")" ] \
            || fail "RPM package has unexpected enhances metadata"
        [ -z "$(rpm -qp --supplements "$package")" ] \
            || fail "RPM package has unexpected supplements metadata"
        [ -z "$(rpm -qp --conflicts "$package")" ] \
            || fail "RPM package has unexpected conflicts metadata"
        [ -z "$(rpm -qp --obsoletes "$package")" ] \
            || fail "RPM package has unexpected obsoletes metadata"
        case "$package_arch" in
            x86_64) rpm_provide_arch=x86-64 ;;
            aarch64) rpm_provide_arch=aarch-64 ;;
            *) fail "unsupported RPM provide architecture mapping: $package_arch" ;;
        esac
        rpm -qp --provides "$package" | sort >"$work/rpm-provides"
        cat >"$work/expected-rpm-provides" <<EOF
vaultlink = $version-1.fc44
vaultlink($rpm_provide_arch) = $version-1.fc44
EOF
        files_are_equal "$work/expected-rpm-provides" "$work/rpm-provides" \
            || fail "RPM provides metadata differs from the reviewed allowlist"
        rpm -qp --queryformat '[%{PROVIDENAME}\t%{PROVIDEFLAGS}\t%{PROVIDEVERSION}\n]' \
            "$package" | sort >"$work/rpm-provide-tuples"
        cat >"$work/expected-rpm-provide-tuples" <<EOF
vaultlink	8	$version-1.fc44
vaultlink($rpm_provide_arch)	8	$version-1.fc44
EOF
        files_are_equal "$work/expected-rpm-provide-tuples" "$work/rpm-provide-tuples" \
            || fail "RPM provide tuples differ from the reviewed allowlist"
        [ "$(rpm -qp --queryformat '%{LICENSE}' "$package")" = MIT ] \
            || fail "unexpected RPM license metadata"
        [ "$(rpm -qp --queryformat '%{FILEDIGESTALGO}' "$package")" = 8 ] \
            || fail "RPM file digest algorithm must be SHA-256"
        [ "$(rpm -qp --queryformat '%{PAYLOADFORMAT}|%{PAYLOADCOMPRESSOR}|%{PAYLOADFLAGS}' \
            "$package")" = 'cpio|zstd|19' ] \
            || fail "RPM payload format/compression differs from the reviewed policy"
        case "$(rpm -qp --queryformat '%{SYSUSERS}' "$package")" in
            ''|'(none)') ;;
            *) fail "RPM package has unexpected sysusers header metadata" ;;
        esac
        rpm -qp --queryformat '[%{FILENAMES}\n]' "$package" \
            | awk '
                $0 !~ /^\/usr(\/|$)/ { exit 1 }
                { sub(/^\//, ""); print }
            ' | sort >"$work/rpm-header-members" \
            || fail "RPM header contains an unsafe payload path"
        [ -z "$(uniq -d "$work/rpm-header-members" | sed -n '1p')" ] \
            || fail "RPM header contains duplicate payload paths"
        validate_payload_member_allowlist "$work/rpm-header-members"
        rpm2cpio "$package" >"$work/payload.cpio"
        cpio -it --quiet <"$work/payload.cpio" >"$work/archive-paths"
        cpio -itv --quiet <"$work/payload.cpio" \
            | awk '{ print substr($1, 1, 1) }' >"$work/archive-types"
        validate_archive_inventory "$work/archive-paths" "$work/archive-types" \
            "$work/rpm-header-members"
        [ "$(sha256sum "$package" | awk '{ print $1 }')" = "$package_input_sha256" ] \
            || fail "package changed while it was being validated"
        # RPM omits common parent directories from its owned inventory. Use
        # the platform's standard 0755 creation mask for those extraction-only
        # parents; explicitly packaged application directories retain their
        # archive metadata.
        (cd "$root" && umask 022 && cpio -idm --quiet <"$work/payload.cpio")
        rpm -qp --queryformat '%{PREIN}' "$package" >"$work/rpm-prein"
        rpm -qp --queryformat '%{POSTIN}' "$package" >"$work/rpm-postin"
        rpm -qp --queryformat '%{PREUN}' "$package" >"$work/rpm-preun"
        rpm -qp --queryformat '%{POSTUN}' "$package" >"$work/rpm-postun"
        render_expected_rpm_scripts "$work/expected-rpm"
        for script in prein postin preun postun; do
            files_are_equal "$work/expected-rpm/$script" "$work/rpm-$script" \
                || fail "RPM $script scriptlet differs from the reviewed template"
        done
        for scriptlet_class in PREIN POSTIN PREUN POSTUN; do
            [ "$(rpm -qp --queryformat "%{${scriptlet_class}PROG}" "$package")" = /bin/sh ] \
                || fail "RPM $scriptlet_class must use exactly /bin/sh"
            rpm_flags=$(rpm -qp --queryformat "%{${scriptlet_class}FLAGS}" "$package")
            case "$rpm_flags" in ''|'(none)') ;; *) fail "RPM $scriptlet_class has unexpected flags" ;; esac
        done
        for forbidden_tag in \
            PRETRANS PRETRANSFLAGS PRETRANSPROG \
            POSTTRANS POSTTRANSFLAGS POSTTRANSPROG \
            PREUNTRANS PREUNTRANSFLAGS PREUNTRANSPROG \
            POSTUNTRANS POSTUNTRANSFLAGS POSTUNTRANSPROG \
            VERIFYSCRIPT VERIFYSCRIPTFLAGS VERIFYSCRIPTPROG \
            TRIGGERCONDS TRIGGERFLAGS TRIGGERINDEX TRIGGERNAME \
            TRIGGERSCRIPTFLAGS TRIGGERSCRIPTPROG TRIGGERSCRIPTS \
            TRIGGERTYPE TRIGGERVERSION \
            FILETRIGGERCONDS FILETRIGGERFLAGS FILETRIGGERINDEX FILETRIGGERNAME \
            FILETRIGGERPRIORITIES FILETRIGGERSCRIPTFLAGS FILETRIGGERSCRIPTPROG \
            FILETRIGGERSCRIPTS FILETRIGGERTYPE FILETRIGGERVERSION \
            TRANSFILETRIGGERCONDS TRANSFILETRIGGERFLAGS TRANSFILETRIGGERINDEX \
            TRANSFILETRIGGERNAME TRANSFILETRIGGERPRIORITIES \
            TRANSFILETRIGGERSCRIPTFLAGS TRANSFILETRIGGERSCRIPTPROG \
            TRANSFILETRIGGERSCRIPTS TRANSFILETRIGGERTYPE TRANSFILETRIGGERVERSION \
            ORDERFLAGS ORDERNAME ORDERVERSION \
            POLICIES POLICYFLAGS POLICYNAMES POLICYTYPES POLICYTYPESINDEXES; do
            rpm_tag_must_be_empty "$forbidden_tag"
        done
        rpm -qp --queryformat '[%{FILENAMES}\t%{FILECAPS}\n]' "$package" \
            >"$work/rpm-filecaps"
        if awk -F '\t' 'NF > 1 && $2 != "" && $2 != "(none)" { found = 1 } END { exit !found }' \
            "$work/rpm-filecaps"; then
            fail "RPM payload contains forbidden file capabilities"
        fi
        rpm -qp --queryformat '[%{FILENAMES}\t%{FILEFLAGS}\t%{FILEVERIFYFLAGS}\n]' \
            "$package" >"$work/rpm-file-policy"
        awk -F '\t' '
            BEGIN { expected_docs = 0 }
            {
                expected_flags = 0
                if ($1 ~ /^\/usr\/share\/doc\/vaultlink\/examples\/config\/(development|production-reverse-proxy|production-standalone-letsencrypt|production-standalone-tls)\.toml$/ \
                    || $1 ~ /^\/usr\/share\/doc\/vaultlink\/examples\/deploy\/(Caddyfile|mnt-storage\.mount\.example|vaultlink-external-proxy-network\.conf|vaultlink-external-storage\.conf|vaultlink-standalone-capability\.conf|vaultlink-update\.conf\.example)$/) {
                    expected_flags = 2
                    expected_docs++
                }
                if ($2 != expected_flags || $3 != 4294967295) exit 1
            }
            END { if (expected_docs != 10) exit 1 }
        ' "$work/rpm-file-policy" \
            || fail "RPM file flags or verification flags differ from the reviewed allowlist"
        grep -F -q 'refusing to adopt markerless existing installation' "$work/rpm-prein" \
            || fail "RPM preinstall lacks the markerless-install guard"
        verify_embedded_lifecycle "$work/rpm-prein"
        verify_installed_lifecycle_wrapper "$work/rpm-postin" postinstall
        verify_installed_lifecycle_wrapper "$work/rpm-preun" preremove
        verify_embedded_lifecycle "$work/rpm-postun"
        ;;
    pkg.tar.zst)
        command -v bsdtar >/dev/null || fail "bsdtar is required"
        bsdtar -tf "$package" >"$work/archive-paths"
        bsdtar -tvf "$package" | awk '{ print substr($1, 1, 1) }' \
            >"$work/archive-types"
        {
            cat "$work/expected-payload-members"
            printf '%s\n' .BUILDINFO .INSTALL .MTREE .PKGINFO
        } | sort >"$work/expected-arch-archive-members"
        validate_archive_inventory "$work/archive-paths" "$work/archive-types" \
            "$work/expected-arch-archive-members"
        [ "$(sha256sum "$package" | awk '{ print $1 }')" = "$package_input_sha256" ] \
            || fail "package changed while it was being validated"
        bsdtar -xf "$package" -C "$root"
        [ -f "$root/.PKGINFO" ] && [ -f "$root/.INSTALL" ] \
            && [ -f "$root/.BUILDINFO" ] && [ -f "$root/.MTREE" ] \
            || fail "Arch package metadata is incomplete"
        for arch_metadata in .PKGINFO .INSTALL .BUILDINFO .MTREE; do
            [ ! -L "$root/$arch_metadata" ] \
                && [ "$(stat -c '%a' "$root/$arch_metadata")" = 644 ] \
                || fail "Arch $arch_metadata must be a regular mode-0644 file"
        done
        [ "$(sed -n 's/^pkgname = //p' "$root/.PKGINFO")" = vaultlink ] \
            || fail "unexpected Arch package name"
        [ "$(sed -n 's/^pkgver = //p' "$root/.PKGINFO")" = "$version-1" ] \
            || fail "unexpected Arch package version"
        [ "$(sed -n 's/^arch = //p' "$root/.PKGINFO")" = "$package_arch" ] \
            || fail "unexpected Arch package architecture"
        arch_builddate=$(sed -n 's/^builddate = //p' "$root/.PKGINFO")
        case "$arch_builddate" in ''|*[!0-9]*) fail "invalid Arch build date" ;; esac
        [ "$(printf '%s\n' "$arch_builddate" | wc -l | tr -d '[:space:]')" = 1 ] \
            || fail "Arch build date must occur exactly once"
        arch_package_size=$(du -sb "$root/usr" | awk '{ print $1 }')
        packaged_pkgbuild="$root/usr/lib/vaultlink/package/PKGBUILD"
        packaged_builder_lock="$root/usr/lib/vaultlink/package/builder-packages.lock"
        files_are_equal packaging/arch/PKGBUILD "$packaged_pkgbuild" \
            || fail "packaged Arch PKGBUILD differs from the reviewed source"
        case "$builder_packages_sha256" in
            UNPROVISIONED)
                if [ "$no_exec" -eq 0 ] \
                    && [ -f /usr/local/share/vaultlink-builder-packages.lock ]; then
                    files_are_equal /usr/local/share/vaultlink-builder-packages.lock \
                        "$packaged_builder_lock" \
                        || fail "packaged Arch builder lock differs from the native builder"
                fi
                ;;
            *[!0-9a-f]*|'') fail "invalid Arch builder-package hash in target manifest" ;;
            *)
                [ "$(sha256sum "$packaged_builder_lock" | awk '{ print $1 }')" = \
                    "$builder_packages_sha256" ] \
                    || fail "packaged Arch builder lock differs from the target manifest"
                ;;
        esac
        arch_buildtool_package_version=$(awk '$1 == "pacman" { print $2 }' \
            "$packaged_builder_lock")
        arch_fakeroot_package_version=$(awk '$1 == "fakeroot" { print $2 }' \
            "$packaged_builder_lock")
        [ "$(printf '%s\n' "$arch_buildtool_package_version" | grep -c . || true)" -eq 1 ] \
            && [ "$(printf '%s\n' "$arch_fakeroot_package_version" | grep -c . || true)" -eq 1 ] \
            || fail "Arch builder lock must contain pacman and fakeroot exactly once"
        arch_buildtool_version=${arch_buildtool_package_version#*:}
        arch_buildtool_version=${arch_buildtool_version%-*}
        arch_buildtool_version=${arch_buildtool_version%%.r[0-9]*}
        arch_fakeroot_version=${arch_fakeroot_package_version#*:}
        arch_fakeroot_version=${arch_fakeroot_version%-*}
        render_expected_arch_pkginfo "$work/expected-arch-pkginfo" \
            "$arch_builddate" "$arch_package_size" \
            "$arch_buildtool_version" "$arch_fakeroot_version"
        files_are_equal "$work/expected-arch-pkginfo" "$root/.PKGINFO" \
            || fail "Arch .PKGINFO fields or values differ from the reviewed template"
        arch_pkgbuild_sha256=$(sha256sum "$packaged_pkgbuild" | awk '{ print $1 }')
        render_expected_arch_buildinfo "$work/expected-arch-buildinfo" \
            "$arch_builddate" "$arch_pkgbuild_sha256" "$arch_buildtool_version"
        append_validated_arch_installed_closure "$root/.BUILDINFO" \
            "$packaged_builder_lock" "$work/expected-arch-buildinfo"
        files_are_equal "$work/expected-arch-buildinfo" "$root/.BUILDINFO" \
            || fail "Arch .BUILDINFO differs from the real pinned makepkg environment"
        verify_arch_mtree "$root"
        sed -n 's/^depend = //p' "$root/.PKGINFO" >"$work/arch-depends"
cat >"$work/expected-arch-depends" <<'EOF'
bash
ca-certificates
coreutils
curl
diffutils
findutils
gawk
gcc-libs
glibc
grep
gzip
libarchive
minisign
sed
sqlite
systemd
tar
util-linux
zstd
EOF
        files_are_equal "$work/expected-arch-depends" "$work/arch-depends" \
            || fail "Arch runtime dependencies differ from the target allowlist"
        [ "$(sed -n 's/^optdepend = //p' "$root/.PKGINFO")" = \
            'cifs-utils: SMB 3.1.1 storage provisioning' ] \
            || fail "cifs-utils must be the sole optional Arch dependency"
        render_expected_arch_install "$work/expected-arch-install"
        files_are_equal "$work/expected-arch-install" "$root/.INSTALL" \
            || fail "Arch .INSTALL differs from the reviewed template"
        grep -F -q 'refusing to adopt markerless existing installation' "$root/.INSTALL" \
            || fail "Arch pre_install lacks the markerless-install guard"
        grep -F -q 'package upgrade stages only the candidate' "$root/.INSTALL" \
            || fail "Arch post_upgrade lacks the staged-upgrade invariant"
        verify_embedded_lifecycle "$root/.INSTALL"
        for arch_hook in pre_install post_install pre_upgrade post_upgrade pre_remove post_remove; do
            [ "$(grep -E -c "^${arch_hook}\\(\\) \\{" "$root/.INSTALL" || true)" -eq 1 ] \
                || fail "Arch install metadata must define $arch_hook exactly once"
        done
        rm -f "$root/.PKGINFO" "$root/.INSTALL" "$root/.BUILDINFO" "$root/.MTREE"
        ;;
    *) fail "unsupported package format: $package_format" ;;
esac

[ "$(sha256sum "$package" | awk '{ print $1 }')" = "$package_input_sha256" ] \
    || fail "package changed while it was being extracted"

find "$root" -type l -print >"$work/symlinks"
[ ! -s "$work/symlinks" ] || fail "package payload must not contain symlinks"
find "$root" ! -type d ! -type f -print >"$work/special-files"
[ ! -s "$work/special-files" ] || fail "package payload contains special files"

(
    cd "$root"
    find usr -type f -print | sort
) >"$work/actual-files"
files_are_equal "$work/expected-files" "$work/actual-files" \
    || fail "package file allowlist mismatch"

(
    cd "$root"
    find usr -type d -print | sort
) >"$work/actual-directories"
files_are_equal "$work/expected-directories" "$work/actual-directories" \
    || fail "package directory allowlist mismatch"

while IFS= read -r packaged_directory; do
    [ "$(stat -c '%a' "$root/$packaged_directory")" = 755 ] \
        || fail "$packaged_directory must be mode 0755"
    if [ "$(id -u)" -eq 0 ]; then
        [ "$(stat -c '%u:%g' "$root/$packaged_directory")" = 0:0 ] \
            || fail "$packaged_directory must be owned by root:root"
    fi
done <"$work/actual-directories"

packaged_updater=usr/sbin/vaultlink-update
[ "$package_format" != pkg.tar.zst ] || packaged_updater=usr/bin/vaultlink-update
arch_installer=
arch_remover=
[ "$package_format" != pkg.tar.zst ] \
    || arch_installer=usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh
[ "$package_format" != pkg.tar.zst ] \
    || arch_remover=usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh
for executable in \
    usr/lib/vaultlink/package/vaultlink \
    usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh \
    usr/lib/vaultlink/package/deploy/vaultlink-runtime-guard.sh \
    usr/lib/vaultlink/package/deploy/vaultlink-rollback.sh \
    usr/lib/vaultlink/package/deploy/vaultlink-upgrade.sh \
    "$packaged_updater"; do
    [ "$(stat -c '%a' "$root/$executable")" = 755 ] \
        || fail "$executable must be mode 0755"
done
if [ -n "$arch_installer" ]; then
    [ "$(stat -c '%a' "$root/$arch_installer")" = 755 ] \
        || fail "$arch_installer must be mode 0755"
fi
if [ -n "$arch_remover" ]; then
    [ "$(stat -c '%a' "$root/$arch_remover")" = 755 ] \
        || fail "$arch_remover must be mode 0755"
fi
while IFS= read -r packaged_file; do
    case "$packaged_file" in
        usr/lib/vaultlink/package/vaultlink|\
        usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh|\
        usr/lib/vaultlink/package/deploy/vaultlink-rollback.sh|\
        usr/lib/vaultlink/package/deploy/vaultlink-runtime-guard.sh|\
        usr/lib/vaultlink/package/deploy/vaultlink-upgrade.sh|\
        usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh|\
        usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh|\
        usr/sbin/vaultlink-update|usr/bin/vaultlink-update) continue ;;
    esac
    [ "$(stat -c '%a' "$root/$packaged_file")" = 644 ] \
        || fail "$packaged_file must be mode 0644"
done <"$work/actual-files"

if [ "$(id -u)" -eq 0 ]; then
    while IFS= read -r packaged_file; do
        [ "$(stat -c '%u:%g' "$root/$packaged_file")" = 0:0 ] \
            || fail "$packaged_file must be owned by root:root"
    done <"$work/actual-files"
fi

if [ "$package_format" != pkg.tar.zst ]; then
    expected_marker=$(printf 'FORMAT=%s\nOS_ID=%s\nOS_VERSION=%s\nARCH=%s\nPACKAGE_NAME=vaultlink' \
        "$package_format" "$os_id" "$os_version" "$package_arch")
    actual_marker=$(cat "$root/usr/share/vaultlink/install-method.env")
    [ "$actual_marker" = "$expected_marker" ] \
        || fail "installation marker content is not exact"
    [ "$(wc -l <"$root/usr/share/vaultlink/install-method.env" | tr -d '[:space:]')" = 5 ] \
        || fail "installation marker must contain five newline-terminated fields"
fi

files_are_equal "$binary_source" "$root/usr/lib/vaultlink/package/vaultlink" \
    || fail "package candidate differs from the supplied binary"
sh tools/check-native-package-elf.sh \
    "$target_id" "$root/usr/lib/vaultlink/package/vaultlink" >/dev/null
files_are_equal "$sbom_source" "$root/usr/lib/vaultlink/package/vaultlink.cdx.json" \
    || fail "packaged SBOM differs from the supplied SBOM"
files_are_equal release/minisign.pub "$root/usr/share/vaultlink/minisign.pub" \
    || fail "packaged Minisign key differs from the pinned release key"

compare_repo_asset() {
    source_file=$1
    packaged_file=$2
    files_are_equal "$source_file" "$root/$packaged_file" \
        || fail "$packaged_file differs from reviewed source $source_file"
}
compare_repo_asset deploy/vaultlink.service usr/lib/systemd/system/vaultlink.service
compare_repo_asset deploy/vaultlink-update.service usr/lib/systemd/system/vaultlink-update.service
compare_repo_asset deploy/vaultlink-update.timer usr/lib/systemd/system/vaultlink-update.timer
compare_repo_asset packaging/vaultlink.sysusers usr/lib/sysusers.d/vaultlink.conf
if [ "$package_format" = pkg.tar.zst ]; then
    compare_repo_asset packaging/vaultlink-remove.hook \
        usr/share/libalpm/hooks/vaultlink-remove.hook
    compare_repo_asset packaging/vaultlink-package-remove.sh \
        usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh
fi
compare_repo_asset packaging/vaultlink.tmpfiles usr/lib/tmpfiles.d/vaultlink.conf
compare_repo_asset packaging/vaultlink-package-lifecycle.sh \
    usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh
compare_repo_asset packaging/vaultlink-runtime-guard.sh \
    usr/lib/vaultlink/package/deploy/vaultlink-runtime-guard.sh
if [ "$package_format" = pkg.tar.zst ]; then
    compare_repo_asset packaging/vaultlink-package-install.sh \
        usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh
fi
compare_repo_asset deploy/vaultlink-upgrade.sh \
    usr/lib/vaultlink/package/deploy/vaultlink-upgrade.sh
compare_repo_asset deploy/vaultlink-rollback.sh \
    usr/lib/vaultlink/package/deploy/vaultlink-rollback.sh
compare_repo_asset deploy/vaultlink-update.sh "$packaged_updater"
compare_repo_asset deploy/vaultlink-update.conf.example usr/share/vaultlink/update.conf.example
compare_repo_asset LICENSE usr/share/licenses/vaultlink/LICENSE
if [ "$package_format" = deb ]; then
    compare_repo_asset LICENSE usr/share/doc/vaultlink/copyright
    package_version="${version}-1"
    case "$os_id:$os_version" in
        debian:13) package_version="${package_version}+deb13" ;;
        ubuntu:24.04) package_version="${package_version}+ubuntu24.04" ;;
        ubuntu:26.04) package_version="${package_version}+ubuntu26.04" ;;
        *) fail "unexpected DEB target" ;;
    esac
    changelog_epoch=$(stat -c '%Y' "$root/usr/share/doc/vaultlink/changelog.Debian.gz")
    changelog_date=$(date -u -d "@$changelog_epoch" '+%a, %d %b %Y %H:%M:%S +0000')
    cat >"$work/expected-changelog.Debian" <<EOF
vaultlink ($package_version) stable; urgency=medium

  * Release the native VaultLink $version package.

 -- VaultLink maintainers <alexhaberl@users.noreply.github.com>  $changelog_date
EOF
    gzip -dc "$root/usr/share/doc/vaultlink/changelog.Debian.gz" \
        >"$work/actual-changelog.Debian"
    files_are_equal "$work/expected-changelog.Debian" "$work/actual-changelog.Debian" \
        || fail "Debian changelog differs from deterministic package metadata"
fi
for example in config/*.toml; do
    compare_repo_asset "$example" "usr/share/doc/vaultlink/examples/config/$(basename "$example")"
done
for example in \
    deploy/Caddyfile \
    deploy/mnt-storage.mount.example \
    deploy/vaultlink-external-proxy-network.conf \
    deploy/vaultlink-external-storage.conf \
    deploy/vaultlink-standalone-capability.conf \
    deploy/vaultlink-update.conf.example; do
    compare_repo_asset "$example" "usr/share/doc/vaultlink/examples/deploy/$(basename "$example")"
done
[ "$(cat "$root/usr/lib/vaultlink/package/version")" = "$version" ] \
    || fail "packaged candidate version metadata is incorrect"
candidate_sha256=$(sha256sum "$root/usr/lib/vaultlink/package/vaultlink" \
    | awk '{ print $1 }')
printf '%s  vaultlink\n' "$candidate_sha256" >"$work/expected-vaultlink.sha256"
files_are_equal "$work/expected-vaultlink.sha256" \
    "$root/usr/lib/vaultlink/package/vaultlink.sha256" \
    || fail "packaged candidate checksum metadata is not canonical"
(
    cd "$root/usr/lib/vaultlink/package"
    sha256sum -c vaultlink.sha256 >/dev/null
) || fail "packaged candidate checksum is invalid"
if [ "$no_exec" -eq 0 ]; then
    [ "$(timeout --kill-after=2 5 "$root/usr/lib/vaultlink/package/vaultlink" --version)" = "$version" ] \
        || fail "packaged candidate reports the wrong version"
fi

[ ! -e "$root/etc" ] \
    || fail "native package must not ship production configuration or state under /etc"
grep -F -x -q 'auto_install=false' \
    "$root/usr/share/doc/vaultlink/examples/deploy/vaultlink-update.conf.example" \
    || fail "packaged updater example must remain opt-in"
grep -F -x -q 'ExecStart=/opt/vaultlink/vaultlink --config /etc/vaultlink/config.toml' \
    "$root/usr/lib/systemd/system/vaultlink.service" \
    || fail "packaged service must execute only the transactional active copy"
grep -F -x -q 'ExecStart=/usr/sbin/vaultlink-update auto' \
    "$root/usr/lib/systemd/system/vaultlink-update.service" \
    || fail "packaged updater unit must use the native-package updater path"

echo "$asset_name: package payload verified"
