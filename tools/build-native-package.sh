#!/bin/sh
# Compound guards intentionally use `A && B || fail` for fail-closed exits.
# shellcheck disable=SC2015
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CDPATH=
LC_ALL=C
LANG=C
export PATH CDPATH LC_ALL LANG
umask 022

fail() {
    echo "native package build failed: $*" >&2
    exit 1
}

# Match dpkg-gencontrol and Debian Policy 5.6.20: round each regular file and
# symlink separately, assign 1 KiB to other objects, and count hardlinks once.
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

[ "$#" -eq 5 ] || {
    echo "usage: build-native-package.sh TARGET_ID VERSION BINARY SBOM OUTPUT_DIR" >&2
    exit 64
}

target_id=$1
version=$2
binary_source=$3
sbom_source=$4
output_dir=$5
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
cd "$repo_root"

case "$target_id" in ''|*[!a-z0-9-]*) fail "unsafe target ID" ;; esac
if ! printf '%s\n' "$version" | grep -E -q '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
    fail "version must be strict stable MAJOR.MINOR.PATCH"
fi
[ -f "$binary_source" ] && [ ! -L "$binary_source" ] && [ -x "$binary_source" ] \
    || fail "binary must be an executable regular file"
[ -f "$sbom_source" ] && [ ! -L "$sbom_source" ] && [ -s "$sbom_source" ] \
    || fail "SBOM must be a non-empty regular file"
[ -f release/package-targets.json ] && [ -f tools/package-targets.py ] \
    || fail "package target manifest tooling is unavailable"
command -v python3 >/dev/null || fail "python3 is required to query the target manifest"
python3 tools/package-targets.py validate --allow-unprovisioned >/dev/null

target_get() {
    python3 tools/package-targets.py get "$target_id" "$1" --allow-unprovisioned
}

os_id=$(target_get distribution)
os_version=$(target_get version)
expected_uname=$(target_get uname)
package_format=$(target_get package_format)
package_arch=$(target_get package_arch)
asset_name=$(python3 tools/package-targets.py asset "$target_id" "$version" --allow-unprovisioned)
if [ "$os_id" = arch ]; then
    [ "$os_version" = rolling ] || fail "unexpected Arch target version marker"
    # The dated build snapshot remains locked in the target manifest. The host
    # marker describes Arch's runtime release model, which has no VERSION_ID.
    os_version=rolling
fi
[ "$(uname -m)" = "$expected_uname" ] \
    || fail "$target_id must be built natively on $expected_uname, not $(uname -m)"
sh tools/check-native-package-elf.sh "$target_id" "$binary_source" >/dev/null

binary_version=$(
    timeout --kill-after=2 5 "$binary_source" --version
) || fail "binary did not provide a bounded version response"
[ "$binary_version" = "$version" ] \
    || fail "binary reports $binary_version instead of $version"

case "${SOURCE_DATE_EPOCH:-0}" in ''|*[!0-9]*) fail "SOURCE_DATE_EPOCH must be an integer" ;; esac
source_date_epoch=${SOURCE_DATE_EPOCH:-0}
export SOURCE_DATE_EPOCH="$source_date_epoch"

install -d "$output_dir"
output_dir=$(cd -- "$output_dir" && pwd)
final_package="$output_dir/$asset_name"
[ ! -e "$final_package" ] || fail "refusing to overwrite $final_package"

work=$(mktemp -d "${TMPDIR:-/tmp}/vaultlink-package.XXXXXXXX")
arch_fixed_build=
cleanup() {
    if [ -n "$arch_fixed_build" ]; then
        case "$arch_fixed_build" in
            /build/vaultlink-package) rm -rf -- "$arch_fixed_build" ;;
            *) echo "refusing to remove unsafe Arch build path: $arch_fixed_build" >&2 ;;
        esac
    fi
    rm -rf "$work"
}
trap cleanup 0 1 2 15
payload="$work/payload"

install -d \
    "$payload/usr/lib/vaultlink/package/deploy" \
    "$payload/usr/lib/systemd/system" \
    "$payload/usr/lib/sysusers.d" \
    "$payload/usr/lib/tmpfiles.d" \
    "$payload/usr/share/vaultlink" \
    "$payload/usr/share/doc/vaultlink/examples/config" \
    "$payload/usr/share/doc/vaultlink/examples/deploy" \
    "$payload/usr/share/licenses/vaultlink"

install -m 0755 "$binary_source" "$payload/usr/lib/vaultlink/package/vaultlink"
install -m 0644 "$sbom_source" "$payload/usr/lib/vaultlink/package/vaultlink.cdx.json"
install -m 0755 \
    deploy/vaultlink-upgrade.sh \
    deploy/vaultlink-rollback.sh \
    packaging/vaultlink-package-lifecycle.sh \
    packaging/vaultlink-runtime-guard.sh \
    "$payload/usr/lib/vaultlink/package/deploy/"
if [ "$package_format" = pkg.tar.zst ]; then
    install -m 0755 packaging/vaultlink-package-install.sh \
        "$payload/usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh"
    install -m 0755 packaging/vaultlink-package-remove.sh \
        "$payload/usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh"
    install -d "$payload/usr/share/libalpm/hooks"
    install -m 0644 packaging/vaultlink-remove.hook \
        "$payload/usr/share/libalpm/hooks/vaultlink-remove.hook"
    [ -f /usr/local/share/vaultlink-builder-packages.lock ] \
        && [ ! -L /usr/local/share/vaultlink-builder-packages.lock ] \
        && [ -s /usr/local/share/vaultlink-builder-packages.lock ] \
        || fail "Arch builder package lock is unavailable"
    install -m 0644 packaging/arch/PKGBUILD \
        "$payload/usr/lib/vaultlink/package/PKGBUILD"
    install -m 0644 /usr/local/share/vaultlink-builder-packages.lock \
        "$payload/usr/lib/vaultlink/package/builder-packages.lock"
fi
if [ "$package_format" = pkg.tar.zst ]; then
    # Arch's filesystem package owns /usr/sbin as a symlink to bin. Installing
    # the real file below /usr/bin keeps /usr/sbin/vaultlink-update resolvable
    # without conflicting with that merged-/usr boundary.
    install -d "$payload/usr/bin"
    install -m 0755 deploy/vaultlink-update.sh "$payload/usr/bin/vaultlink-update"
else
    install -d "$payload/usr/sbin"
    install -m 0755 deploy/vaultlink-update.sh "$payload/usr/sbin/vaultlink-update"
fi
install -m 0644 \
    deploy/vaultlink.service \
    deploy/vaultlink-update.service \
    deploy/vaultlink-update.timer \
    "$payload/usr/lib/systemd/system/"
install -m 0644 packaging/vaultlink.sysusers "$payload/usr/lib/sysusers.d/vaultlink.conf"
install -m 0644 packaging/vaultlink.tmpfiles "$payload/usr/lib/tmpfiles.d/vaultlink.conf"
install -m 0644 release/minisign.pub "$payload/usr/share/vaultlink/minisign.pub"
install -m 0644 deploy/vaultlink-update.conf.example \
    "$payload/usr/share/vaultlink/update.conf.example"
install -m 0644 LICENSE "$payload/usr/share/licenses/vaultlink/LICENSE"

for example in config/*.toml; do
    install -m 0644 "$example" "$payload/usr/share/doc/vaultlink/examples/config/"
done
for example in \
    deploy/Caddyfile \
    deploy/mnt-storage.mount.example \
    deploy/vaultlink-external-proxy-network.conf \
    deploy/vaultlink-external-storage.conf \
    deploy/vaultlink-standalone-capability.conf \
    deploy/vaultlink-update.conf.example; do
    install -m 0644 "$example" "$payload/usr/share/doc/vaultlink/examples/deploy/"
done

printf '%s\n' "$version" >"$payload/usr/lib/vaultlink/package/version"
binary_sha256=$(sha256sum "$binary_source" | awk '{ print $1 }')
printf '%s  vaultlink\n' "$binary_sha256" \
    >"$payload/usr/lib/vaultlink/package/vaultlink.sha256"
if [ "$package_format" != pkg.tar.zst ]; then
    printf 'FORMAT=%s\nOS_ID=%s\nOS_VERSION=%s\nARCH=%s\nPACKAGE_NAME=vaultlink\n' \
        "$package_format" "$os_id" "$os_version" "$package_arch" \
        >"$payload/usr/share/vaultlink/install-method.env"
fi

# Package contents, including directories, receive a single deterministic time.
find "$payload" -exec touch -h -d "@$source_date_epoch" {} +

append_lifecycle_source() {
    destination=$1
    {
        printf '%s\n' 'VAULTLINK_PACKAGE_LIFECYCLE_EMBEDDED=1'
        printf '%s\n' "# VAULTLINK_PACKAGE_LIFECYCLE_SHA256=$(sha256sum packaging/vaultlink-package-lifecycle.sh | awk '{ print $1 }')"
        printf '%s\n' '# BEGIN VAULTLINK PACKAGE LIFECYCLE'
        sed '1{/^#!\/bin\/sh$/d;}' packaging/vaultlink-package-lifecycle.sh
        printf '%s\n' '# END VAULTLINK PACKAGE LIFECYCLE'
    } >>"$destination"
}

write_deb_scripts() {
    control_dir=$1

    preinst="$control_dir/preinst"
    printf '%s\n' '#!/bin/sh' >"$preinst"
    append_lifecycle_source "$preinst"
    cat >>"$preinst" <<EOF
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

    postinst="$control_dir/postinst"
    printf '%s\n' '#!/bin/sh' 'set -eu' >"$postinst"
    cat >>"$postinst" <<EOF
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

    prerm="$control_dir/prerm"
    printf '%s\n' '#!/bin/sh' 'set -eu' >"$prerm"
    cat >>"$prerm" <<EOF
case "\${1:-}" in
    remove|deconfigure)
        exec /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh preremove "$package_format" "$os_id" "$os_version" "$package_arch" vaultlink remove
        ;;
    upgrade|failed-upgrade) exit 0 ;;
    *) echo "unsupported Debian prerm operation: \${1:-missing}" >&2; exit 1 ;;
esac
EOF

    postrm="$control_dir/postrm"
    printf '%s\n' '#!/bin/sh' >"$postrm"
    append_lifecycle_source "$postrm"
    cat >>"$postrm" <<EOF
case "\${1:-}" in
    remove|purge|disappear)
        vaultlink_package_main postremove "$package_format" "$os_id" "$os_version" "$package_arch" vaultlink remove
        ;;
    upgrade|failed-upgrade) exit 0 ;;
    abort-install|abort-upgrade) exit 0 ;;
    *) package_fail "unsupported Debian postrm operation: \${1:-missing}" ;;
esac
EOF
    chmod 0755 "$preinst" "$postinst" "$prerm" "$postrm"
}

build_deb() {
    command -v dpkg-deb >/dev/null || fail "dpkg-deb is required for DEB targets"
    debroot="$work/debroot"
    cp -a "$payload" "$debroot"
    package_version="${version}-1"
    case "$os_id:$os_version" in
        debian:13) package_version="${package_version}+deb13" ;;
        ubuntu:24.04) package_version="${package_version}+ubuntu24.04" ;;
        ubuntu:26.04) package_version="${package_version}+ubuntu26.04" ;;
        *) fail "unexpected DEB target" ;;
    esac
    install -m 0644 LICENSE "$debroot/usr/share/doc/vaultlink/copyright"
    changelog_date=$(date -u -d "@$source_date_epoch" '+%a, %d %b %Y %H:%M:%S +0000')
    cat >"$work/changelog.Debian" <<EOF
vaultlink ($package_version) stable; urgency=medium

  * Release the native VaultLink $version package.

 -- VaultLink maintainers <alexhaberl@users.noreply.github.com>  $changelog_date
EOF
    gzip -n -9 <"$work/changelog.Debian" \
        >"$debroot/usr/share/doc/vaultlink/changelog.Debian.gz"
    chmod 0644 \
        "$debroot/usr/share/doc/vaultlink/copyright" \
        "$debroot/usr/share/doc/vaultlink/changelog.Debian.gz"
    installed_size=$(debian_installed_size "$debroot" \
        "$work/deb-installed-size.inventory") \
        || fail "failed to calculate Debian Installed-Size"
    install -d -m 0755 "$debroot/DEBIAN"
    cat >"$debroot/DEBIAN/control" <<EOF
Package: vaultlink
Version: $package_version
Architecture: $package_arch
Maintainer: VaultLink maintainers <alexhaberl@users.noreply.github.com>
Installed-Size: $installed_size
Depends: ca-certificates, curl, libc6, libgcc-s1, mawk, minisign, sqlite3, systemd
Suggests: cifs-utils
Section: net
Priority: optional
Homepage: https://github.com/alexhaberl/VaultLink
Description: secure file sharing for an existing Linux mountpoint
 VaultLink provides hardened self-hosted file sharing with explicit setup,
 signed updates, transactional activation, and verified rollback.
EOF
    write_deb_scripts "$debroot/DEBIAN"
    (
        cd "$debroot"
        find usr -type f -print0 | sort -z | xargs -0 md5sum >DEBIAN/md5sums
    )
    chmod 0644 "$debroot/DEBIAN/control" "$debroot/DEBIAN/md5sums"
    find "$debroot" -exec touch -h -d "@$source_date_epoch" {} +
    package_stage="$work/$asset_name"
    DPKG_DEB_COMPRESSOR_TYPE=xz DPKG_DEB_COMPRESSOR_LEVEL=9 \
        dpkg-deb --build --root-owner-group --uniform-compression --threads-max=1 \
        "$debroot" "$package_stage" >/dev/null
    install -m 0644 "$package_stage" "$final_package"
}

write_rpm_embedded_wrapper() {
    output=$1
    operation=$2
    mode_expression=$3
    printf '%s\n' '#!/bin/sh' >"$output"
    append_lifecycle_source "$output"
    cat >>"$output" <<EOF
$mode_expression
vaultlink_package_main $operation "$package_format" "$os_id" "$os_version" "$package_arch" vaultlink "\$lifecycle_mode"${4:-}
EOF
    chmod 0755 "$output"
}

write_rpm_installed_wrapper() {
    output=$1
    operation=$2
    mode_expression=$3
    printf '%s\n' '#!/bin/sh' 'set -eu' >"$output"
    cat >>"$output" <<EOF
$mode_expression
exec /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh $operation "$package_format" "$os_id" "$os_version" "$package_arch" vaultlink "\$lifecycle_mode"${4:-}
EOF
    chmod 0755 "$output"
}

build_rpm() {
    command -v rpmbuild >/dev/null || fail "rpmbuild is required for RPM targets"
    rpmroot="$work/rpmbuild"
    install -d "$rpmroot/BUILD" "$rpmroot/BUILDROOT" "$rpmroot/RPMS" \
        "$rpmroot/SOURCES" "$rpmroot/SPECS" "$rpmroot/SRPMS"
    tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
        -C "$payload" -cf "$rpmroot/SOURCES/vaultlink-payload.tar" .

    # These are literal scriptlet bodies; their positional parameter expands
    # only when RPM invokes the installed scriptlet.
    # shellcheck disable=SC2016
    rpm_install_mode='if [ "${1:-1}" -gt 1 ]; then lifecycle_mode=upgrade; elif [ -e /var/lib/vaultlink-backups/install-method.env ] || [ -L /var/lib/vaultlink-backups/install-method.env ]; then lifecycle_mode=reinstall; else lifecycle_mode=fresh; fi'
    # shellcheck disable=SC2016
    rpm_remove_mode='if [ "${1:-0}" -ne 0 ]; then exit 0; fi; lifecycle_mode=remove'
    write_rpm_embedded_wrapper "$rpmroot/SOURCES/pre.sh" preinstall "$rpm_install_mode"
    write_rpm_installed_wrapper "$rpmroot/SOURCES/post.sh" postinstall "$rpm_install_mode" \
        " \"$version\""
    write_rpm_installed_wrapper "$rpmroot/SOURCES/preun.sh" preremove "$rpm_remove_mode"
    write_rpm_embedded_wrapper "$rpmroot/SOURCES/postun.sh" postremove "$rpm_remove_mode"
    # RPM expands macros even in scriptlet bodies loaded with -f. Escape every
    # literal percent once so the installed scriptlets remain byte-exact shell.
    for rpm_script in pre.sh post.sh preun.sh postun.sh; do
        sed 's/%/%%/g' "$rpmroot/SOURCES/$rpm_script" \
            >"$rpmroot/SOURCES/.$rpm_script.escaped"
        mv -f "$rpmroot/SOURCES/.$rpm_script.escaped" "$rpmroot/SOURCES/$rpm_script"
        chmod 0755 "$rpmroot/SOURCES/$rpm_script"
    done

    spec="$rpmroot/SPECS/vaultlink.spec"
    cat >"$spec" <<EOF
Name: vaultlink
%global debug_package %{nil}
%global __os_install_post %{nil}
Version: $version
Release: 1.fc44
Summary: Secure file sharing for an existing Linux mountpoint
License: MIT
URL: https://github.com/alexhaberl/VaultLink
Source0: vaultlink-payload.tar
Source1: pre.sh
Source2: post.sh
Source3: preun.sh
Source4: postun.sh
BuildArch: $package_arch
AutoReqProv: no
Requires: bash, ca-certificates, coreutils, cpio, curl, diffutils, findutils, gawk, glibc, grep, gzip, libgcc, minisign, rpm, sed, sqlite, systemd, tar, util-linux
Recommends: cifs-utils

%description
VaultLink provides hardened self-hosted file sharing with explicit setup,
signed updates, transactional activation, and verified rollback.

%prep
%setup -q -c -T

%build

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
tar -xf %{SOURCE0} -C %{buildroot}

%pre -p /bin/sh -f %{SOURCE1}
%post -p /bin/sh -f %{SOURCE2}
%preun -p /bin/sh -f %{SOURCE3}
%postun -p /bin/sh -f %{SOURCE4}

%files
%defattr(-,root,root,-)
/usr/lib/vaultlink
/usr/lib/systemd/system/vaultlink.service
/usr/lib/systemd/system/vaultlink-update.service
/usr/lib/systemd/system/vaultlink-update.timer
/usr/lib/sysusers.d/vaultlink.conf
/usr/lib/tmpfiles.d/vaultlink.conf
/usr/sbin/vaultlink-update
/usr/share/vaultlink
/usr/share/doc/vaultlink
/usr/share/licenses/vaultlink

%changelog
* Thu Jan 01 2026 VaultLink maintainers <noreply@vaultlink.example> - $version-1
- Native VaultLink package
EOF
    find "$rpmroot" -exec touch -h -d "@$source_date_epoch" {} +
    rpmbuild -bb "$spec" \
        --define "_topdir $rpmroot" \
        --define "_buildhost vaultlink.invalid" \
        --define "_build_id_links none" \
        --define "_source_date_epoch $source_date_epoch" \
        --define "use_source_date_epoch_as_buildtime 1" \
        --define "clamp_mtime_to_source_date_epoch 1" \
        --define "_binary_filedigest_algorithm 8" \
        --define "_binary_payload w19.zstdio" >/dev/null
    rpm_results=$(find "$rpmroot/RPMS" -type f -name '*.rpm' -print)
    [ "$(printf '%s\n' "$rpm_results" | grep -c .)" -eq 1 ] \
        || fail "rpmbuild did not produce exactly one binary RPM"
    [ "$(basename "$rpm_results")" = "$asset_name" ] \
        || fail "rpmbuild produced unexpected asset $(basename "$rpm_results")"
    install -m 0644 "$rpm_results" "$final_package"
}

write_arch_install() {
    destination=$1
    printf '%s\n' '#!/bin/sh' >"$destination"
    append_lifecycle_source "$destination"
    cat >>"$destination" <<EOF
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
    chmod 0644 "$destination"
}

build_arch_package() {
    for arch_build_command in bsdtar env getent makepkg runuser; do
        command -v "$arch_build_command" >/dev/null \
            || fail "$arch_build_command is required for Arch targets"
    done
    [ -f /.dockerenv ] \
        || fail "Arch packages must be assembled inside the pinned builder container"
    if [ -e /build ] || [ -L /build ]; then
        [ -d /build ] && [ ! -L /build ] \
            && [ "$(stat -c '%u:%g:%a' /build 2>/dev/null || true)" = 0:0:755 ] \
            || fail "/build is not a safe fixed build root"
    else
        install -d -o root -g root -m 0755 /build
    fi
    arch_build_path=/build/vaultlink-package
    [ ! -e "$arch_build_path" ] && [ ! -L "$arch_build_path" ] \
        || fail "fixed Arch build directory already exists"
    arch_builder_uid=$(id -u nobody)
    arch_builder_gid=$(id -g nobody)
    case "$arch_builder_uid" in ''|*[!0-9]*) fail "Arch builder UID is unavailable" ;; esac
    case "$arch_builder_gid" in ''|*[!0-9]*) fail "Arch builder GID is unavailable" ;; esac
    [ "$arch_builder_uid" -ne 0 ] && [ "$arch_builder_gid" -ne 0 ] \
        || fail "Arch builder identity must be unprivileged"
    install -d -o "$arch_builder_uid" -g "$arch_builder_gid" -m 0700 \
        "$arch_build_path" "$arch_build_path/home"
    arch_fixed_build=$arch_build_path
    cp -a "$payload" "$arch_fixed_build/payload"
    chown -R root:root "$arch_fixed_build/payload"
    install -o root -g root -m 0644 packaging/arch/PKGBUILD \
        "$arch_fixed_build/PKGBUILD"
    write_arch_install "$arch_fixed_build/vaultlink.install"
    chown root:root "$arch_fixed_build/vaultlink.install"
    chmod 0644 "$arch_fixed_build/vaultlink.install"
    find "$arch_fixed_build/payload" -exec touch -h -d "@$source_date_epoch" {} +
    (
        cd "$arch_fixed_build"
        runuser -u nobody -- env \
            HOME="$arch_fixed_build/home" \
            PACKAGER='VaultLink maintainers <noreply@vaultlink.example>' \
            SOURCE_DATE_EPOCH="$source_date_epoch" \
            VAULTLINK_PACKAGE_ARCH="$package_arch" \
            VAULTLINK_PACKAGE_VERSION="$version" \
            makepkg --noconfirm --cleanbuild --force >/dev/null
    )
    arch_result="$arch_fixed_build/$asset_name"
    [ -f "$arch_result" ] && [ ! -L "$arch_result" ] \
        || fail "makepkg did not produce the expected Arch package"
    install -m 0644 "$arch_result" "$final_package"
}

case "$package_format" in
    deb) build_deb ;;
    rpm) build_rpm ;;
    pkg.tar.zst) build_arch_package ;;
    *) fail "unsupported package format from manifest: $package_format" ;;
esac

sh tools/verify-native-package.sh \
    "$target_id" "$version" "$final_package" "$binary_source" "$sbom_source"
touch -h -d "@$source_date_epoch" "$final_package"
sha256sum "$final_package"
