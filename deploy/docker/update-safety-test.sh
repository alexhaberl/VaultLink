#!/bin/sh
# Test assertions intentionally use `A && B || fail/exit` as fail-closed guards.
# shellcheck disable=SC2015
set -eu
umask 077

[ "$(id -u)" -eq 0 ] || {
    echo "update safety tests must run as root in a disposable container" >&2
    exit 1
}

test_root=/tmp/vaultlink-package-update-safety
assets=$test_root/assets
records=$test_root/records
mock_dir=/usr/sbin
updater=/work/deploy/vaultlink-update.sh
arch_nologin=/usr/bin/nologin

fail() {
    echo "package update safety test failed: $*" >&2
    exit 1
}

cleanup() {
    for mock_command in curl systemctl uname id getent dpkg dpkg-query dpkg-deb rpm \
        rpm2cpio cpio pacman bsdtar; do
        rm -f "$mock_dir/$mock_command"
        if [ -e "$test_root/original-$mock_command" ]; then
            mv -f "$test_root/original-$mock_command" "$mock_dir/$mock_command"
        fi
    done
    if [ -e "$test_root/os-release.original" ] || [ -L "$test_root/os-release.original" ]; then
        rm -f /etc/os-release
        cp -a "$test_root/os-release.original" /etc/os-release
    fi
    rm -f "$arch_nologin"
    if [ -e "$test_root/arch-nologin.original" ] \
        || [ -L "$test_root/arch-nologin.original" ]; then
        mv -f "$test_root/arch-nologin.original" "$arch_nologin"
    fi
    rm -rf "$test_root" /usr/lib/vaultlink/package
    rm -f /etc/vaultlink/update.conf /etc/vaultlink/config.toml
    rm -f /usr/share/vaultlink/minisign.pub /usr/share/vaultlink/install-method.env
    rm -f /opt/vaultlink/vaultlink /var/lib/vaultlink/data.sqlite \
        /var/lib/vaultlink/data.sqlite-wal /var/lib/vaultlink/data.sqlite-shm \
        /var/lib/vaultlink/secrets.keyring
    rm -rf /var/lib/vaultlink-backups/package-update-*-* \
        /var/lib/vaultlink-backups/helper-update-safety \
        /var/lib/vaultlink-backups/update-evidence
}
trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

expect_failure() {
    failure_name=$1
    shift
    if "$@" >"$test_root/$failure_name.stdout" 2>"$test_root/$failure_name.stderr"; then
        fail "$failure_name unexpectedly succeeded"
    fi
}

preserve_mock_target() {
    preserve_name=$1
    if [ -e "$mock_dir/$preserve_name" ] || [ -L "$mock_dir/$preserve_name" ]; then
        mv "$mock_dir/$preserve_name" "$test_root/original-$preserve_name"
    fi
}

rm -rf "$test_root"
install -d -m 0700 "$test_root" "$assets" "$records"
cp -a /etc/os-release "$test_root/os-release.original"
if [ -e "$arch_nologin" ] || [ -L "$arch_nologin" ]; then
    mv "$arch_nologin" "$test_root/arch-nologin.original"
fi
install -m 0755 /usr/sbin/nologin "$arch_nologin"
for mock_command in curl systemctl uname id getent dpkg dpkg-query dpkg-deb rpm \
    rpm2cpio cpio pacman bsdtar; do
    preserve_mock_target "$mock_command"
done

minisign -G -W -p "$test_root/minisign.pub" -s "$test_root/minisign.key" >/dev/null
minisign -G -W -p "$test_root/other-minisign.pub" \
    -s "$test_root/other-minisign.key" >/dev/null

# All GitHub and readiness traffic is served from protected local fixtures.
cat >"$mock_dir/curl" <<'EOF'
#!/bin/sh
set -eu
output=
write_out=
url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --max-redirs|--proto|--proto-redir|--connect-timeout|--max-time|--retry|--retry-delay|--retry-max-time|--user-agent|--max-filesize|--output|--write-out|--noproxy|--header|--connect-to)
            [ "$#" -ge 2 ] || exit 64
            case "$1" in
                --output) output=$2 ;;
                --write-out) write_out=$2 ;;
            esac
            shift 2
            ;;
        --fail|--silent|--show-error|--location|--tlsv1.2|--disable|--insecure)
            shift
            ;;
        --)
            shift
            [ "$#" -eq 1 ] || exit 64
            url=$1
            shift
            ;;
        --*) exit 64 ;;
        *)
            [ -z "$url" ] || exit 64
            url=$1
            shift
            ;;
    esac
done
[ -n "$url" ] || exit 64
case "$url" in
    https://github.com/alexhaberl/VaultLink/releases/latest)
        [ "$output" = /dev/null ] || exit 64
        [ "$write_out" = '%{http_code}\n%{redirect_url}' ] || exit 64
        printf '302\n%s' "${VAULTLINK_UPDATE_TEST_EFFECTIVE_URL:-https://github.com/alexhaberl/VaultLink/releases/tag/v${VAULTLINK_UPDATE_TEST_LATEST:-0.6.1}}"
        ;;
    https://github.com/alexhaberl/VaultLink/releases/download/*)
        [ "$output" = /dev/null ] || exit 64
        [ "$write_out" = '%{http_code}\n%{redirect_url}' ] || exit 64
        relative=${url#https://github.com/alexhaberl/VaultLink/releases/download/}
        tag=${relative%%/*}
        asset=${relative#*/}
        [ "$tag/$asset" != "${VAULTLINK_UPDATE_TEST_FAIL_ASSET:-}" ] || exit 22
        printf '302\n%s' "${VAULTLINK_UPDATE_TEST_ASSET_REDIRECT:-https://release-assets.githubusercontent.com/github-production-release-asset/vaultlink-test/$tag/$asset?fixture=1}"
        ;;
    https://release-assets.githubusercontent.com/github-production-release-asset/vaultlink-test/*)
        [ -n "$output" ] && [ "$output" != /dev/null ] || exit 64
        [ "$write_out" = '%{http_code}\n%{url_effective}' ] || exit 64
        relative=${url#https://release-assets.githubusercontent.com/github-production-release-asset/vaultlink-test/}
        relative=${relative%%\?*}
        tag=${relative%%/*}
        asset=${relative#*/}
        cp "$VAULTLINK_UPDATE_TEST_ASSETS/$tag/$asset" "$output"
        printf '200\n%s' "$url"
        ;;
    http://127.0.0.1:18081/health)
        version=$(/opt/vaultlink/vaultlink --version)
        printf '{"ok":true,"version":"%s"}' "$version"
        ;;
    *) exit 22 ;;
esac
EOF
chmod 0755 "$mock_dir/curl"

cat >"$mock_dir/systemctl" <<'EOF'
#!/bin/sh
set -eu
state=$VAULTLINK_UPDATE_TEST_ROOT/service-active
case "$*" in
    '--quiet is-active vaultlink.service')
        if [ "${VAULTLINK_UPDATE_TEST_STOP_BEFORE_TRANSACTION:-0}" = 1 ]; then
            active_checks=$VAULTLINK_UPDATE_TEST_ROOT/service-active-checks
            checks=0
            [ ! -f "$active_checks" ] || checks=$(cat "$active_checks")
            checks=$((checks + 1))
            printf '%s\n' "$checks" >"$active_checks"
            if [ "$checks" -ge 2 ]; then
                rm -f "$state"
                exit 1
            fi
        fi
        if [ "${VAULTLINK_UPDATE_TEST_SWAP_LIVE_AFTER_ACTIVE_CHECK:-0}" = 1 ] \
            && [ -e "$state" ]; then
            swap_marker=$VAULTLINK_UPDATE_TEST_ROOT/live-swap-fired
            if [ ! -e "$swap_marker" ]; then
                printf '%s\n' '# same-version payload not present in the signed package' \
                    >>/opt/vaultlink/vaultlink
                : >"$swap_marker"
            fi
        fi
        [ -e "$state" ]
        ;;
    'is-active vaultlink.service')
        if [ -e "$state" ]; then
            printf '%s\n' active
            exit 0
        fi
        printf '%s\n' inactive
        exit 3
        ;;
    'stop vaultlink.service')
        rm -f "$state"
        case "${VAULTLINK_UPDATE_TEST_SIGNAL_ON_STOP:-}" in
            '') ;;
            HUP|INT|TERM)
                signal_marker=$VAULTLINK_UPDATE_TEST_ROOT/signal-on-stop-fired
                if [ ! -e "$signal_marker" ]; then
                    : >"$signal_marker"
                    kill -s "$VAULTLINK_UPDATE_TEST_SIGNAL_ON_STOP" "$PPID"
                fi
                ;;
            *) exit 64 ;;
        esac
        ;;
    'start vaultlink.service') : >"$state" ;;
    'daemon-reload')
        package_version=$(sed -n '2p' "$VAULTLINK_UPDATE_TEST_ROOT/package-db")
        printf '%s\n' "$package_version" \
            >>"$VAULTLINK_UPDATE_TEST_ROOT/daemon-reloads"
        [ "$package_version" != "${VAULTLINK_UPDATE_TEST_DAEMON_RELOAD_FAIL_VERSION:-}" ] \
            || exit 73
        ;;
    *) exit 64 ;;
esac
EOF
chmod 0755 "$mock_dir/systemctl"

cat >"$mock_dir/uname" <<'EOF'
#!/bin/sh
set -eu
[ "$#" -eq 1 ] && [ "$1" = -m ] || exit 64
printf '%s\n' "$VAULTLINK_UPDATE_TEST_MACHINE"
EOF
chmod 0755 "$mock_dir/uname"

cat >"$mock_dir/id" <<'EOF'
#!/bin/sh
set -eu
identity_uid=997
[ "${VAULTLINK_UPDATE_TEST_IDENTITY_FAULT:-}" != root-uid ] || identity_uid=0
case "$*" in
    -u) printf '%s\n' 0 ;;
    '-u vaultlink') printf '%s\n' "$identity_uid" ;;
    '-g vaultlink') printf '%s\n' 997 ;;
    '-gn vaultlink') printf '%s\n' vaultlink ;;
    '-Gn vaultlink')
        if [ "${VAULTLINK_UPDATE_TEST_IDENTITY_FAULT:-}" = supplementary-group ]; then
            printf '%s\n' 'vaultlink wheel'
        else
            printf '%s\n' vaultlink
        fi
        ;;
    vaultlink) printf 'uid=%s(vaultlink) gid=997(vaultlink) groups=997(vaultlink)\n' "$identity_uid" ;;
    *) exec /usr/bin/id "$@" ;;
esac
EOF
chmod 0755 "$mock_dir/id"

cat >"$mock_dir/getent" <<'EOF'
#!/bin/sh
set -eu
[ "$#" -eq 2 ] && [ "$2" = vaultlink ] || exit 64
case "$1" in
    passwd)
        home=/var/lib/vaultlink
        [ "${VAULTLINK_UPDATE_TEST_IDENTITY_FAULT:-}" != wrong-home ] || home=/nonexistent
        identity_uid=997
        [ "${VAULTLINK_UPDATE_TEST_IDENTITY_FAULT:-}" != root-uid ] || identity_uid=0
        case "$VAULTLINK_UPDATE_TEST_OS_ID" in
            debian|ubuntu|fedora) shell=/usr/sbin/nologin ;;
            arch) shell=/usr/bin/nologin ;;
            *) exit 64 ;;
        esac
        [ "${VAULTLINK_UPDATE_TEST_IDENTITY_FAULT:-}" != wrong-shell ] || shell=/bin/false
        printf 'vaultlink:x:%s:997:VaultLink service account:%s:%s\n' \
            "$identity_uid" "$home" "$shell"
        ;;
    group) printf '%s\n' 'vaultlink:x:997:' ;;
    shadow)
        if [ "${VAULTLINK_UPDATE_TEST_IDENTITY_FAULT:-}" = unlocked-shadow ]; then
            printf '%s\n' 'vaultlink:$6$not-locked:::::::'
        else
            printf '%s\n' 'vaultlink:!*:::::::'
        fi
        ;;
    *) exit 64 ;;
esac
EOF
chmod 0755 "$mock_dir/getent"

# Test packages are deterministic tar payloads carrying an internal metadata
# fixture. These adapters expose exactly the native-manager interfaces used by
# the production updater; actual DEB/RPM/Arch format and lint gates run in the
# distribution package jobs.
cat >"$test_root/read-meta.sh" <<'EOF'
#!/bin/sh
set -eu
file=$1
field=$2
tar -xOzf "$file" .vaultlink-test-meta | sed -n "s/^$field=//p"
EOF
chmod 0755 "$test_root/read-meta.sh"

cat >"$test_root/write-scriptlet.sh" <<'EOF'
#!/bin/sh
set -eu
package=$1
kind=$2
read_meta=$VAULTLINK_UPDATE_TEST_ROOT/read-meta.sh
upstream=$($read_meta "$package" UPSTREAM)
format=$VAULTLINK_UPDATE_TEST_FORMAT
os_id=$VAULTLINK_UPDATE_TEST_OS_ID
os_version=$VAULTLINK_UPDATE_TEST_OS_VERSION
arch=$VAULTLINK_UPDATE_TEST_ARCH
lifecycle=$VAULTLINK_UPDATE_TEST_ROOT/scriptlet-lifecycle.$$
trap 'rm -f "$lifecycle"' 0 1 2 15
tar -xOzf "$package" usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh \
    >"$lifecycle"
write_embedded() {
    printf '%s\n' '#!/bin/sh' 'VAULTLINK_PACKAGE_LIFECYCLE_EMBEDDED=1'
    printf '# VAULTLINK_PACKAGE_LIFECYCLE_SHA256=%s\n' "$(sha256sum "$lifecycle" | awk '{print $1}')"
    printf '%s\n' '# BEGIN VAULTLINK PACKAGE LIFECYCLE'
    sed '1{/^#!\/bin\/sh$/d;}' "$lifecycle"
    printf '%s\n' '# END VAULTLINK PACKAGE LIFECYCLE'
}
case "$kind" in
    preinst)
        write_embedded
        cat <<EOS
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
vaultlink_package_main preinstall "$format" "$os_id" "$os_version" "$arch" vaultlink "\$lifecycle_mode"
EOS
        ;;
    postinst)
        cat <<EOS
#!/bin/sh
set -eu
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
/usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh postinstall "$format" "$os_id" "$os_version" "$arch" vaultlink "\$lifecycle_mode" "$upstream"
EOS
        ;;
    prerm)
        cat <<EOS
#!/bin/sh
set -eu
case "\${1:-}" in
    remove|deconfigure)
        exec /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh preremove "$format" "$os_id" "$os_version" "$arch" vaultlink remove
        ;;
    upgrade|failed-upgrade) exit 0 ;;
    *) echo "unsupported Debian prerm operation: \${1:-missing}" >&2; exit 1 ;;
esac
EOS
        ;;
    postrm)
        write_embedded
        cat <<EOS
case "\${1:-}" in
    remove|purge|disappear)
        vaultlink_package_main postremove "$format" "$os_id" "$os_version" "$arch" vaultlink remove
        ;;
    upgrade|failed-upgrade) exit 0 ;;
    abort-install|abort-upgrade) exit 0 ;;
    *) package_fail "unsupported Debian postrm operation: \${1:-missing}" ;;
esac
EOS
        ;;
    rpm-prein)
        write_embedded
        printf '%s\n' \
            'if [ "${1:-1}" -gt 1 ]; then lifecycle_mode=upgrade; elif [ -e /var/lib/vaultlink-backups/install-method.env ] || [ -L /var/lib/vaultlink-backups/install-method.env ]; then lifecycle_mode=reinstall; else lifecycle_mode=fresh; fi' \
            "vaultlink_package_main preinstall \"$format\" \"$os_id\" \"$os_version\" \"$arch\" vaultlink \"\$lifecycle_mode\""
        ;;
    rpm-postin)
        printf '%s\n' '#!/bin/sh' 'set -eu' \
            'if [ "${1:-1}" -gt 1 ]; then lifecycle_mode=upgrade; elif [ -e /var/lib/vaultlink-backups/install-method.env ] || [ -L /var/lib/vaultlink-backups/install-method.env ]; then lifecycle_mode=reinstall; else lifecycle_mode=fresh; fi' \
            "exec /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh postinstall \"$format\" \"$os_id\" \"$os_version\" \"$arch\" vaultlink \"\$lifecycle_mode\" \"$upstream\""
        ;;
    rpm-preun)
        printf '%s\n' '#!/bin/sh' 'set -eu' \
            'if [ "${1:-0}" -ne 0 ]; then exit 0; fi; lifecycle_mode=remove' \
            "exec /usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh preremove \"$format\" \"$os_id\" \"$os_version\" \"$arch\" vaultlink \"\$lifecycle_mode\""
        ;;
    rpm-postun)
        write_embedded
        printf '%s\n' \
            'if [ "${1:-0}" -ne 0 ]; then exit 0; fi; lifecycle_mode=remove' \
            "vaultlink_package_main postremove \"$format\" \"$os_id\" \"$os_version\" \"$arch\" vaultlink \"\$lifecycle_mode\""
        ;;
    *) exit 64 ;;
esac
if [ "$upstream" = "${VAULTLINK_UPDATE_TEST_EXTRA_SCRIPTLET_VERSION:-}" ]; then
    printf '%s\n' ': unexpected signed scriptlet command'
fi
EOF
chmod 0755 "$test_root/write-scriptlet.sh"

cat >"$test_root/install-fixture-package.sh" <<'EOF'
#!/bin/sh
set -eu
file=$1
mode=$2
read_meta=$VAULTLINK_UPDATE_TEST_ROOT/read-meta.sh
upstream=$($read_meta "$file" UPSTREAM)
if [ "$mode" = dry ]; then
    [ "$upstream" != "${VAULTLINK_UPDATE_TEST_DRY_FAIL_VERSION:-}" ]
    if [ "$upstream" = "${VAULTLINK_UPDATE_TEST_EXTRA_DEP_VERSION:-}" ] \
        && [ "${VAULTLINK_UPDATE_TEST_NATIVE_MISSING_DEP:-}" = test-extra-runtime ]; then
        exit 78
    fi
    exit
fi
[ "$upstream" != "${VAULTLINK_UPDATE_TEST_INSTALL_FAIL_VERSION:-}" ] || exit 71
printf '%s:%s\n' "$upstream" "${VAULTLINK_PACKAGE_RECOVERY-unset}" \
    >>"$VAULTLINK_UPDATE_TEST_ROOT/package-recovery-environment"
if [ "$upstream" = 0.6.0 ] \
    && [ -n "${VAULTLINK_UPDATE_TEST_SIGNAL_DURING_RECOVERY:-}" ] \
    && grep -F -x -q 0.6.1 "$VAULTLINK_UPDATE_TEST_ROOT/package-installs"; then
    kill -s "$VAULTLINK_UPDATE_TEST_SIGNAL_DURING_RECOVERY" "$PPID"
fi
tar -xzf "$file" -C / --exclude=.vaultlink-test-meta --exclude=.PKGINFO \
    --exclude=.INSTALL --exclude=.BUILDINFO --exclude=.MTREE
{
    $read_meta "$file" PACKAGE
    $read_meta "$file" UPSTREAM
    $read_meta "$file" DB_VERSION
    $read_meta "$file" ARCH
} >"$VAULTLINK_UPDATE_TEST_ROOT/package-db"
printf '%s\n' "$upstream" >>"$VAULTLINK_UPDATE_TEST_ROOT/package-installs"
EOF
chmod 0755 "$test_root/install-fixture-package.sh"

cat >"$mock_dir/dpkg-deb" <<'EOF'
#!/bin/sh
set -eu
read_meta=$VAULTLINK_UPDATE_TEST_ROOT/read-meta.sh
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
case "$1" in
    --vaultlink-test-installed-size)
        [ "$#" -eq 2 ] || exit 64
        debian_installed_size "$2" "$2.installed-size.inventory"
        ;;
    -f)
        [ "$#" -eq 3 ] || exit 64
        case "$3" in
            Package) field=PACKAGE ;;
            Version) field=DB_VERSION ;;
            Architecture) field=ARCH ;;
            Depends)
                depends='ca-certificates, curl, libc6, libgcc-s1, mawk, minisign, sqlite3, systemd'
                if [ "$("$read_meta" "$2" UPSTREAM)" = \
                    "${VAULTLINK_UPDATE_TEST_EXTRA_DEP_VERSION:-}" ]; then
                    depends="$depends, test-extra-runtime"
                fi
                printf '%s\n' "$depends"
                exit
                ;;
            Suggests) printf '%s\n' cifs-utils; exit ;;
            Recommends) exit ;;
            Essential) printf '%s\n' no; exit ;;
            Section) printf '%s\n' net; exit ;;
            Priority) printf '%s\n' optional; exit ;;
            *) exit 64 ;;
        esac
        "$read_meta" "$2" "$field"
        ;;
    --fsys-tarfile)
        [ "$#" -eq 2 ] || exit 64
        fixture=$VAULTLINK_UPDATE_TEST_ROOT/deb-payload.$$
        trap 'rm -rf "$fixture"' 0 1 2 15
        install -d "$fixture"
        tar -xzf "$2" -C "$fixture" usr
        # Real dpkg-deb data archives contain exactly one `./` directory
        # record before their usr/ payload. Preserve that invariant in the
        # mock so archive-root validation exercises production semantics.
        tar -cf - -C "$fixture" .
        ;;
    -x)
        [ "$#" -eq 3 ] || exit 64
        tar -xzf "$2" -C "$3" --exclude=.vaultlink-test-meta --exclude=.PKGINFO \
            --exclude=.INSTALL --exclude=.BUILDINFO --exclude=.MTREE
        ;;
    -e)
        [ "$#" -eq 3 ] || exit 64
        install -d "$3"
        payload=$VAULTLINK_UPDATE_TEST_ROOT/deb-control-payload.$$
        trap 'rm -rf "$payload"' 0 1 2 15
        install -d "$payload"
        tar -xzf "$2" -C "$payload" usr
        installed_size=$(debian_installed_size "$payload" \
            "$payload.installed-size.inventory")
        db_version=$("$read_meta" "$2" DB_VERSION)
        arch=$("$read_meta" "$2" ARCH)
        depends='ca-certificates, curl, libc6, libgcc-s1, mawk, minisign, sqlite3, systemd'
        if [ "$("$read_meta" "$2" UPSTREAM)" = \
            "${VAULTLINK_UPDATE_TEST_EXTRA_DEP_VERSION:-}" ]; then
            depends="$depends, test-extra-runtime"
        fi
        cat >"$3/control" <<CONTROL
Package: vaultlink
Version: $db_version
Architecture: $arch
Maintainer: VaultLink maintainers <alexhaberl@users.noreply.github.com>
Installed-Size: $installed_size
Depends: $depends
Suggests: cifs-utils
Section: net
Priority: optional
Homepage: https://github.com/alexhaberl/VaultLink
Description: secure file sharing for an existing Linux mountpoint
 VaultLink provides hardened self-hosted file sharing with explicit setup,
 signed updates, transactional activation, and verified rollback.
CONTROL
        (cd "$payload" && find usr -type f -print0 | sort -z | xargs -0 md5sum) \
            >"$3/md5sums"
        for script in preinst postinst prerm postrm; do
            "$VAULTLINK_UPDATE_TEST_ROOT/write-scriptlet.sh" "$2" "$script" >"$3/$script"
            chmod 0755 "$3/$script"
        done
        chmod 0644 "$3/control" "$3/md5sums"
        ;;
    *) exit 64 ;;
esac
EOF
chmod 0755 "$mock_dir/dpkg-deb"

# Pin the Debian Policy 5.6.20 calculation independently of the updater. This
# fixture distinguishes per-object rounding and hardlink handling from du(1).
installed_size_fixture=$test_root/installed-size-fixture
install -d "$installed_size_fixture/usr/lib/vaultlink-size-test"
: >"$installed_size_fixture/usr/lib/vaultlink-size-test/empty"
printf x >"$installed_size_fixture/usr/lib/vaultlink-size-test/one"
truncate -s 1024 "$installed_size_fixture/usr/lib/vaultlink-size-test/exact"
truncate -s 1025 "$installed_size_fixture/usr/lib/vaultlink-size-test/over"
ln "$installed_size_fixture/usr/lib/vaultlink-size-test/over" \
    "$installed_size_fixture/usr/lib/vaultlink-size-test/over-hardlink"
truncate -s 1048577 "$installed_size_fixture/usr/lib/vaultlink-size-test/sparse"
ln -s one "$installed_size_fixture/usr/lib/vaultlink-size-test/link"
installed_size_reported=$(
    VAULTLINK_UPDATE_TEST_ROOT=$test_root \
        "$mock_dir/dpkg-deb" --vaultlink-test-installed-size \
            "$installed_size_fixture"
)
[ "$installed_size_reported" = 1034 ] \
    || fail "DEB Installed-Size does not follow Debian Policy 5.6.20"

cat >"$mock_dir/dpkg-query" <<'EOF'
#!/bin/sh
set -eu
db=$VAULTLINK_UPDATE_TEST_ROOT/package-db
[ -s "$db" ] || exit 1
if [ "$#" -eq 3 ] && [ "$1" = -W ] \
    && [ "$2" = '-f=${db:Status-Status}' ] && [ "$3" != vaultlink ]; then
    [ "$3" != "${VAULTLINK_UPDATE_TEST_DPKG_MISSING:-}" ] || exit 1
    printf '%s' installed
    exit
fi
package=$(sed -n '1p' "$db")
version=$(sed -n '3p' "$db")
arch=$(sed -n '4p' "$db")
case "$*" in
    "-W -f=\${db:Status-Status} vaultlink") printf '%s' installed ;;
    "-W -f=\${Version} vaultlink") printf '%s' "$version" ;;
    "-W -f=\${Architecture} vaultlink") printf '%s' "$arch" ;;
    '-L vaultlink') printf '%s\n' /usr/lib/vaultlink/package/vaultlink ;;
    *) exit 64 ;;
esac
[ "$package" = vaultlink ]
EOF
chmod 0755 "$mock_dir/dpkg-query"

cat >"$mock_dir/dpkg" <<'EOF'
#!/bin/sh
set -eu
case "$1" in
    --simulate)
        [ "$2" = --install ] && [ "$#" -eq 3 ] || exit 64
        exec "$VAULTLINK_UPDATE_TEST_ROOT/install-fixture-package.sh" "$3" dry
        ;;
    --install)
        [ "$#" -eq 2 ] || exit 64
        exec "$VAULTLINK_UPDATE_TEST_ROOT/install-fixture-package.sh" "$2" install
        ;;
    *) exit 64 ;;
esac
EOF
chmod 0755 "$mock_dir/dpkg"

cat >"$mock_dir/rpm" <<'EOF'
#!/bin/sh
set -eu
db=$VAULTLINK_UPDATE_TEST_ROOT/package-db
read_meta=$VAULTLINK_UPDATE_TEST_ROOT/read-meta.sh
if [ "$1" = -q ] && [ "$2" = --qf ]; then
    format=$3
    [ "$4" = vaultlink ] && [ -s "$db" ] || exit 1
    case "$format" in
        '%{NAME}') sed -n '1p' "$db" ;;
        '%{EPOCHNUM}') printf '%s' "${VAULTLINK_UPDATE_TEST_INSTALLED_RPM_EPOCH:-0}" ;;
        '%{VERSION}-%{RELEASE}') sed -n '3p' "$db" ;;
        '%{ARCH}') sed -n '4p' "$db" ;;
        *) exit 64 ;;
    esac
elif [ "$1" = -qf ] && [ "$2" = --qf ]; then
    [ "$3" = '%{NAME}' ] && [ "$4" = /usr/lib/vaultlink/package/vaultlink ] || exit 64
    sed -n '1p' "$db"
elif [ "$1" = -qpl ]; then
    tar -tzf "$2" | sed -n 's#^usr/#/usr/#p'
elif [ "$1" = -qp ] && [ "$2" = --requires ]; then
    printf '%s\n' /bin/sh bash ca-certificates coreutils cpio curl diffutils \
        findutils gawk glibc grep gzip libgcc minisign rpm sed sqlite systemd tar util-linux
    if [ "$("$read_meta" "$3" UPSTREAM)" = \
        "${VAULTLINK_UPDATE_TEST_EXTRA_DEP_VERSION:-}" ]; then
        printf '%s\n' test-extra-runtime
    fi
elif [ "$1" = -qp ] && [ "$2" = --recommends ]; then
    printf '%s\n' cifs-utils
elif [ "$1" = -qp ] && [ "$2" = --suggests ]; then
    :
elif [ "$1" = -qp ] && { [ "$2" = --enhances ] || [ "$2" = --supplements ]; }; then
    :
elif [ "$1" = -qp ] && [ "$2" = --provides ]; then
    upstream=$("$read_meta" "$3" UPSTREAM)
    db_version=$("$read_meta" "$3" DB_VERSION)
    arch=$("$read_meta" "$3" ARCH)
    case "$arch" in
        x86_64) provide_arch=x86-64 ;;
        aarch64) provide_arch=aarch-64 ;;
        *) exit 64 ;;
    esac
    printf 'vaultlink = %s\nvaultlink(%s) = %s\n' \
        "$db_version" "$provide_arch" "$db_version"
elif [ "$1" = -qp ] && { [ "$2" = --conflicts ] || [ "$2" = --obsoletes ]; }; then
    :
elif [ "$1" = -qp ] && [ "$2" = --qf ]; then
    case "$3" in
        '%{NAME}') field=PACKAGE ;;
        '%{EPOCHNUM}')
            upstream=$("$read_meta" "$4" UPSTREAM)
            if [ "$upstream" = "${VAULTLINK_UPDATE_TEST_RPM_EPOCH_VERSION:-}" ]; then
                printf '%s' 1
            else
                printf '%s' 0
            fi
            exit
            ;;
        '%{VERSION}-%{RELEASE}') field=DB_VERSION ;;
        '%{ARCH}') field=ARCH ;;
        '%{LICENSE}') printf '%s' MIT; exit ;;
        '[%{REQUIRENAME}\t%{REQUIREFLAGS}\t%{REQUIREVERSION}\n]')
            upstream=$("$read_meta" "$4" UPSTREAM)
            if [ "$upstream" = "${VAULTLINK_UPDATE_TEST_RPM_REQUIRE_PRE_VERSION:-}" ]; then
                bash_require_flags=512
            else
                bash_require_flags=0
            fi
            printf '%s\t%s\t%s\n' \
                /bin/sh 768 '' /bin/sh 1280 '' /bin/sh 2304 '' /bin/sh 4352 '' \
                bash "$bash_require_flags" '' ca-certificates 0 '' coreutils 0 '' cpio 0 '' curl 0 '' \
                diffutils 0 '' findutils 0 '' gawk 0 '' glibc 0 '' grep 0 '' \
                gzip 0 '' libgcc 0 '' minisign 0 '' rpm 0 '' sed 0 '' sqlite 0 '' \
                systemd 0 '' tar 0 '' util-linux 0 '' \
                'rpmlib(CompressedFileNames)' 16777226 3.0.4-1 \
                'rpmlib(FileDigests)' 16777226 4.6.0-1 \
                'rpmlib(PayloadFilesHavePrefix)' 16777226 4.0-1 \
                'rpmlib(PayloadIsZstd)' 16777226 5.4.18-1
            if [ "$("$read_meta" "$4" UPSTREAM)" = \
                "${VAULTLINK_UPDATE_TEST_EXTRA_DEP_VERSION:-}" ]; then
                printf '%s\t0\t\n' test-extra-runtime
            fi
            exit
            ;;
        '[%{PROVIDENAME}\t%{PROVIDEFLAGS}\t%{PROVIDEVERSION}\n]')
            db_version=$("$read_meta" "$4" DB_VERSION)
            arch=$("$read_meta" "$4" ARCH)
            case "$arch" in
                x86_64) provide_arch=x86-64 ;;
                aarch64) provide_arch=aarch-64 ;;
                *) exit 64 ;;
            esac
            printf 'vaultlink\t8\t%s\nvaultlink(%s)\t8\t%s\n' \
                "$db_version" "$provide_arch" "$db_version"
            exit
            ;;
        '%{FILEDIGESTALGO}')
            if [ "$("$read_meta" "$4" UPSTREAM)" = \
                "${VAULTLINK_UPDATE_TEST_RPM_DIGEST_VERSION:-}" ]; then
                printf '%s' '(none)'
            else
                printf '%s' 8
            fi
            exit
            ;;
        '%{PAYLOADFORMAT}|%{PAYLOADCOMPRESSOR}|%{PAYLOADFLAGS}')
            if [ "$("$read_meta" "$4" UPSTREAM)" = \
                "${VAULTLINK_UPDATE_TEST_RPM_PAYLOAD_VERSION:-}" ]; then
                printf '%s' 'cpio|gzip|9'
            else
                printf '%s' 'cpio|zstd|19'
            fi
            exit
            ;;
        '%{SYSUSERS}') printf '%s' '(none)'; exit ;;
        '[%{FILEMODES:perms}\n]')
            tar -tvzf "$4" | sed -n '/ usr\//s/^\(.\).*$/\1/p'
            exit
            ;;
        '%{PREIN}') exec "$VAULTLINK_UPDATE_TEST_ROOT/write-scriptlet.sh" "$4" rpm-prein ;;
        '%{POSTIN}') exec "$VAULTLINK_UPDATE_TEST_ROOT/write-scriptlet.sh" "$4" rpm-postin ;;
        '%{PREUN}') exec "$VAULTLINK_UPDATE_TEST_ROOT/write-scriptlet.sh" "$4" rpm-preun ;;
        '%{POSTUN}') exec "$VAULTLINK_UPDATE_TEST_ROOT/write-scriptlet.sh" "$4" rpm-postun ;;
        '%{PREINPROG}'|'%{POSTINPROG}'|'%{PREUNPROG}'|'%{POSTUNPROG}')
            printf '%s' /bin/sh
            exit
            ;;
        '%{PRETRANS}')
            if [ "$("$read_meta" "$4" UPSTREAM)" = \
                "${VAULTLINK_UPDATE_TEST_RPM_PRETRANS_VERSION:-}" ]; then
                printf '%s\n' ': unexpected RPM pretrans scriptlet'
            fi
            exit
            ;;
        '[%{FILENAMES}\t%{FILECAPS}\n]')
            printf '%s\t\n' /usr/lib/vaultlink/package/vaultlink
            exit
            ;;
        '[%{FILENAMES}\t%{FILEFLAGS}\t%{FILEVERIFYFLAGS}\n]')
            tar -tzf "$4" | sed -n 's#^usr/#/usr/#p' | sed 's#/$##' \
                | while IFS= read -r rpm_path; do
                    case "$rpm_path" in
                        /usr/share/doc/vaultlink/examples/config/*.toml|\
                        /usr/share/doc/vaultlink/examples/deploy/Caddyfile|\
                        /usr/share/doc/vaultlink/examples/deploy/mnt-storage.mount.example|\
                        /usr/share/doc/vaultlink/examples/deploy/vaultlink-external-proxy-network.conf|\
                        /usr/share/doc/vaultlink/examples/deploy/vaultlink-external-storage.conf|\
                        /usr/share/doc/vaultlink/examples/deploy/vaultlink-standalone-capability.conf|\
                        /usr/share/doc/vaultlink/examples/deploy/vaultlink-update.conf.example)
                            rpm_file_flags=2 ;;
                        *) rpm_file_flags=0 ;;
                    esac
                    if [ "$("$read_meta" "$4" UPSTREAM)" = \
                        "${VAULTLINK_UPDATE_TEST_RPM_FILEFLAG_VERSION:-}" ] \
                        && [ "$rpm_path" = /usr/lib/systemd/system/vaultlink.service ]; then
                        rpm_file_flags=17
                    fi
                    printf '%s\t%s\t4294967295\n' "$rpm_path" "$rpm_file_flags"
                done
            exit
            ;;
        '%{'*) exit ;;
        *) exit 64 ;;
    esac
    "$read_meta" "$4" "$field"
else
    mode=install
    file=
    for argument in "$@"; do
        [ "$argument" != --test ] || mode=dry
        case "$argument" in *.rpm) file=$argument ;; esac
    done
    [ -n "$file" ] || exit 64
    exec "$VAULTLINK_UPDATE_TEST_ROOT/install-fixture-package.sh" "$file" "$mode"
fi
EOF
chmod 0755 "$mock_dir/rpm"

cat >"$mock_dir/rpm2cpio" <<'EOF'
#!/bin/sh
set -eu
[ "$#" -eq 1 ]
cat "$1"
EOF
chmod 0755 "$mock_dir/rpm2cpio"

cat >"$mock_dir/cpio" <<'EOF'
#!/bin/sh
set -eu
tar -xzf - --exclude=.vaultlink-test-meta --exclude=.PKGINFO \
    --exclude=.INSTALL --exclude=.BUILDINFO --exclude=.MTREE
EOF
chmod 0755 "$mock_dir/cpio"

cat >"$mock_dir/bsdtar" <<'EOF'
#!/bin/sh
set -eu
if [ "$1" = --format=mtree ]; then
    printf '%s\n' '#mtree' '/set type=file uid=0 gid=0 mode=644'
    find . -mindepth 1 ! -name .MTREE ! -name .vaultlink-test-meta -print \
        | LC_ALL=C sort | while IFS= read -r mtree_path; do
        mtree_name=${mtree_path#./}
        mtree_mode=$(stat -c %a "$mtree_path")
        if [ -d "$mtree_path" ]; then
            printf './%s time=0.0 mode=%s type=dir\n' "$mtree_name" "$mtree_mode"
        else
            mtree_size=$(stat -c %s "$mtree_path")
            mtree_sha256=$(sha256sum "$mtree_path" | awk '{ print $1 }')
            printf './%s time=0.0 mode=%s size=%s sha256digest=%s\n' \
                "$mtree_name" "$mtree_mode" "$mtree_size" "$mtree_sha256"
        fi
    done
    exit
fi
if [ "$1" = -xOf ]; then
    [ "$#" -eq 3 ] && [ "$3" = .PKGINFO ] || exit 64
    tar -xOzf "$2" .PKGINFO
    exit
fi
if [ "$1" = -tf ]; then
    [ "$#" -eq 2 ] || exit 64
    if [ "$(basename "$2")" = .MTREE ]; then
        gzip -dc "$2" | sed -n 's|^\./\([^ ]*\).*|\1|p'
        exit
    fi
    tar -tzf "$2" --exclude=.vaultlink-test-meta
    exit
fi
if [ "$1" = -df ]; then
    [ "$#" -eq 2 ] && [ "$2" = .MTREE ] || exit 64
    exit
fi
if [ "$1" = -tvf ]; then
    [ "$#" -eq 2 ] || exit 64
    tar -tvzf "$2" --exclude=.vaultlink-test-meta
    exit
fi
file=
destination=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -xpf) file=$2; shift 2 ;;
        -C) destination=$2; shift 2 ;;
        --no-same-owner|--no-same-permissions) shift ;;
        *) exit 64 ;;
    esac
done
[ -n "$file" ] && [ -n "$destination" ] || exit 64
tar -xzf "$file" -C "$destination" --exclude=.vaultlink-test-meta
EOF
chmod 0755 "$mock_dir/bsdtar"

cat >"$mock_dir/pacman" <<'EOF'
#!/bin/sh
set -eu
db=$VAULTLINK_UPDATE_TEST_ROOT/package-db
case "$1" in
    -Q)
        [ "$#" -eq 2 ] && [ "$2" = vaultlink ] || exit 64
        printf '%s %s\n' "$(sed -n '1p' "$db")" "$(sed -n '3p' "$db")"
        ;;
    -Qoq)
        [ "$#" -eq 2 ] && [ "$2" = /usr/lib/vaultlink/package/vaultlink ] || exit 64
        sed -n '1p' "$db"
        ;;
    -Qi)
        [ "$#" -eq 2 ] && [ "$2" = vaultlink ] || exit 64
        printf 'Name            : vaultlink\nArchitecture    : %s\n' \
            "${VAULTLINK_UPDATE_TEST_INSTALLED_PACMAN_ARCH:-$(sed -n '4p' "$db")}"
        ;;
    -T)
        shift
        [ "${1:-}" = -- ] && shift
        [ "$#" -ge 19 ] && [ "$#" -le 64 ] || exit 64
        printf '%s\n' "$*" >>"$VAULTLINK_UPDATE_TEST_ROOT/pacman-dependency-checks"
        if [ -n "${VAULTLINK_UPDATE_TEST_PACMAN_MISSING:-}" ]; then
            for dependency in "$@"; do
                if [ "$dependency" = "$VAULTLINK_UPDATE_TEST_PACMAN_MISSING" ]; then
                    printf '%s\n' "$dependency"
                    exit 127
                fi
            done
        fi
        ;;
    --upgrade)
        mode=install
        file=
        for argument in "$@"; do
            [ "$argument" != --print ] || mode=dry
            case "$argument" in *.pkg.tar.zst) file=$argument ;; esac
        done
        [ -n "$file" ] || exit 64
        exec "$VAULTLINK_UPDATE_TEST_ROOT/install-fixture-package.sh" "$file" "$mode"
        ;;
    *) exit 64 ;;
esac
EOF
chmod 0755 "$mock_dir/pacman"

write_os_release() {
    rm -f /etc/os-release
    if [ "$target_os_id" = arch ]; then
        printf 'ID=arch\n' >/etc/os-release
    else
        printf 'ID=%s\nVERSION_ID="%s"\n' "$target_os_id" "$target_os_version" \
            >/etc/os-release
    fi
    chmod 0644 /etc/os-release
}

write_marker() {
    marker_destination=$1
    install -d -m 0755 "$(dirname "$marker_destination")"
    printf 'FORMAT=%s\nOS_ID=%s\nOS_VERSION=%s\nARCH=%s\nPACKAGE_NAME=vaultlink\n' \
        "$target_format" "$target_os_id" "$target_os_version" "$target_arch" \
        >"$marker_destination"
    chmod 0644 "$marker_destination"
}

database_version_for() {
    database_upstream=$1
    case "$target_os_id:$target_os_version:$target_format" in
        debian:13:deb) printf '%s-1+deb13\n' "$database_upstream" ;;
        ubuntu:24.04:deb) printf '%s-1+ubuntu24.04\n' "$database_upstream" ;;
        ubuntu:26.04:deb) printf '%s-1+ubuntu26.04\n' "$database_upstream" ;;
        fedora:44:rpm) printf '%s-1.fc44\n' "$database_upstream" ;;
        arch:rolling:pkg.tar.zst) printf '%s-1\n' "$database_upstream" ;;
        *) return 1 ;;
    esac
}

asset_name_for() {
    asset_version=$1
    case "$target_os_id:$target_os_version:$target_format" in
        debian:13:deb) printf 'vaultlink_%s-1+deb13_%s.deb\n' "$asset_version" "$target_arch" ;;
        ubuntu:24.04:deb) printf 'vaultlink_%s-1+ubuntu24.04_%s.deb\n' "$asset_version" "$target_arch" ;;
        ubuntu:26.04:deb) printf 'vaultlink_%s-1+ubuntu26.04_%s.deb\n' "$asset_version" "$target_arch" ;;
        fedora:44:rpm) printf 'vaultlink-%s-1.fc44.%s.rpm\n' "$asset_version" "$target_arch" ;;
        arch:rolling:pkg.tar.zst) printf 'vaultlink-%s-1-x86_64.pkg.tar.zst\n' "$asset_version" ;;
        *) return 1 ;;
    esac
}

make_binary() {
    binary_destination=$1
    binary_version=$2
    install -d -m 0755 "$(dirname "$binary_destination")"
    cat >"$binary_destination" <<EOF
#!/bin/sh
set -eu
if [ "\$#" -eq 1 ] && [ "\$1" = --version ]; then
    printf '%s\\n' '$binary_version'
elif [ "\$#" -eq 3 ] && [ "\$1" = readiness-target ] && [ "\$2" = --config ]; then
    printf '%s\\n%s\\n%s\\n' 'http://127.0.0.1:18081/health' '-' 0
else
    exit 64
fi
EOF
    chmod 0755 "$binary_destination"
}

make_package() {
    release_version=$1
    binary_version=$2
    embedded_key=$3
    release_dir="$assets/v$release_version"
    build_dir="$test_root/build-$target_id-$release_version-$binary_version"
    asset=$(asset_name_for "$release_version")
    db_version=$(database_version_for "$release_version")
    rm -rf "$build_dir"
    install -d -m 0755 "$release_dir" \
        "$build_dir/usr/lib/vaultlink/package/deploy" \
        "$build_dir/usr/lib/systemd/system" \
        "$build_dir/usr/lib/sysusers.d" \
        "$build_dir/usr/lib/tmpfiles.d" \
        "$build_dir/usr/share/vaultlink" \
        "$build_dir/usr/share/doc/vaultlink/examples/config" \
        "$build_dir/usr/share/doc/vaultlink/examples/deploy" \
        "$build_dir/usr/share/licenses/vaultlink"
    make_binary "$build_dir/usr/lib/vaultlink/package/vaultlink" "$binary_version"
    printf '%s\n' '{"bomFormat":"CycloneDX","specVersion":"1.6"}' \
        >"$build_dir/usr/lib/vaultlink/package/vaultlink.cdx.json"
    printf '%s\n' "$release_version" >"$build_dir/usr/lib/vaultlink/package/version"
    (
        cd "$build_dir/usr/lib/vaultlink/package"
        sha256sum vaultlink >vaultlink.sha256
    )
    chmod 0644 "$build_dir/usr/lib/vaultlink/package/version" \
        "$build_dir/usr/lib/vaultlink/package/vaultlink.cdx.json" \
        "$build_dir/usr/lib/vaultlink/package/vaultlink.sha256"
    cp "$embedded_key" "$build_dir/usr/share/vaultlink/minisign.pub"
    chmod 0644 "$build_dir/usr/share/vaultlink/minisign.pub"
    install -m 0644 /work/deploy/vaultlink-update.conf.example \
        "$build_dir/usr/share/vaultlink/update.conf.example"
    if [ "$target_format" = pkg.tar.zst ]; then
        install -m 0755 /work/packaging/vaultlink-package-install.sh \
            "$build_dir/usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh"
        install -m 0755 /work/packaging/vaultlink-package-remove.sh \
            "$build_dir/usr/lib/vaultlink/package/deploy/vaultlink-package-remove.sh"
        install -d -m 0755 "$build_dir/usr/share/libalpm/hooks"
        install -m 0644 /work/packaging/vaultlink-remove.hook \
            "$build_dir/usr/share/libalpm/hooks/vaultlink-remove.hook"
        install -m 0644 /work/packaging/arch/PKGBUILD \
            "$build_dir/usr/lib/vaultlink/package/PKGBUILD"
        cat >"$build_dir/usr/lib/vaultlink/package/builder-packages.lock" <<'EOF'
fakeroot 1:1.37.2-3
pacman 7.1.0.r9.g54d9411-2
EOF
        chmod 0644 "$build_dir/usr/lib/vaultlink/package/PKGBUILD" \
            "$build_dir/usr/lib/vaultlink/package/builder-packages.lock"
    else
        write_marker "$build_dir/usr/share/vaultlink/install-method.env"
    fi
    install -m 0755 /work/packaging/vaultlink-package-lifecycle.sh \
        "$build_dir/usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh"
    install -m 0755 /work/packaging/vaultlink-runtime-guard.sh \
        "$build_dir/usr/lib/vaultlink/package/deploy/vaultlink-runtime-guard.sh"
    cat >"$build_dir/usr/lib/vaultlink/package/deploy/vaultlink-upgrade.sh" <<'EOF'
#!/bin/sh
set -eu
[ "$#" -eq 2 ]
[ "${VAULTLINK_UPDATE_TEST_UPGRADE_FAIL:-0}" = 0 ] || exit 72
install -o root -g root -m 0755 "$1" /opt/vaultlink/vaultlink
systemctl start vaultlink.service
install -d -o root -g root -m 0700 /var/lib/vaultlink-backups/helper-update-safety
printf '%s\n' /var/lib/vaultlink-backups/helper-update-safety
EOF
    cat >"$build_dir/usr/lib/vaultlink/package/deploy/vaultlink-rollback.sh" <<'EOF'
#!/bin/sh
exit 64
EOF
    chmod 0755 "$build_dir/usr/lib/vaultlink/package/deploy/"*.sh
    if [ "$target_format" = pkg.tar.zst ]; then
        install -d -m 0755 "$build_dir/usr/bin"
        install -m 0755 /work/deploy/vaultlink-update.sh "$build_dir/usr/bin/vaultlink-update"
    else
        install -d -m 0755 "$build_dir/usr/sbin"
        install -m 0755 /work/deploy/vaultlink-update.sh "$build_dir/usr/sbin/vaultlink-update"
    fi
    install -m 0644 /work/deploy/vaultlink.service /work/deploy/vaultlink-update.service \
        /work/deploy/vaultlink-update.timer "$build_dir/usr/lib/systemd/system/"
    install -m 0644 /work/packaging/vaultlink.sysusers \
        "$build_dir/usr/lib/sysusers.d/vaultlink.conf"
    install -m 0644 /work/packaging/vaultlink.tmpfiles \
        "$build_dir/usr/lib/tmpfiles.d/vaultlink.conf"
    for config_example in /work/config/*.toml; do
        install -m 0644 "$config_example" "$build_dir/usr/share/doc/vaultlink/examples/config/"
    done
    for deploy_example in Caddyfile mnt-storage.mount.example \
        vaultlink-external-proxy-network.conf vaultlink-external-storage.conf \
        vaultlink-standalone-capability.conf vaultlink-update.conf.example; do
        install -m 0644 "/work/deploy/$deploy_example" \
            "$build_dir/usr/share/doc/vaultlink/examples/deploy/$deploy_example"
    done
    install -m 0644 /work/LICENSE "$build_dir/usr/share/licenses/vaultlink/LICENSE"
    if [ "$target_format" = deb ]; then
        install -m 0644 /work/LICENSE "$build_dir/usr/share/doc/vaultlink/copyright"
        printf '%s\n' 'vaultlink (test) unstable; urgency=medium' \
            | gzip -n -9 >"$build_dir/usr/share/doc/vaultlink/changelog.Debian.gz"
        chmod 0644 "$build_dir/usr/share/doc/vaultlink/changelog.Debian.gz"
    fi
    printf 'PACKAGE=vaultlink\nUPSTREAM=%s\nDB_VERSION=%s\nARCH=%s\n' \
        "$release_version" "$db_version" "$target_arch" >"$build_dir/.vaultlink-test-meta"
    chmod 0644 "$build_dir/.vaultlink-test-meta"
    package_entries='.vaultlink-test-meta usr'
    if [ "$target_format" = pkg.tar.zst ]; then
        arch_package_size=$(du -sb "$build_dir/usr" | awk '{ print $1 }')
        arch_pkgbuild_sha256=$(sha256sum \
            "$build_dir/usr/lib/vaultlink/package/PKGBUILD" | awk '{ print $1 }')
        cat >"$build_dir/.PKGINFO" <<EOF
# Generated by makepkg 7.1.0
# using fakeroot version 1.37.2
pkgname = vaultlink
pkgbase = vaultlink
xdata = pkgtype=pkg
pkgver = $db_version
pkgdesc = Secure file sharing for an existing Linux mountpoint
url = https://github.com/alexhaberl/VaultLink
builddate = 0
packager = VaultLink maintainers <noreply@vaultlink.example>
size = $arch_package_size
arch = $target_arch
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
        lifecycle="$build_dir/usr/lib/vaultlink/package/deploy/vaultlink-package-lifecycle.sh"
        {
            printf '%s\n' '#!/bin/sh' 'VAULTLINK_PACKAGE_LIFECYCLE_EMBEDDED=1'
            printf '# VAULTLINK_PACKAGE_LIFECYCLE_SHA256=%s\n' \
                "$(sha256sum "$lifecycle" | awk '{print $1}')"
            printf '%s\n' '# BEGIN VAULTLINK PACKAGE LIFECYCLE'
            sed '1{/^#!\/bin\/sh$/d;}' "$lifecycle"
            printf '%s\n' '# END VAULTLINK PACKAGE LIFECYCLE'
            cat <<EOF
pre_install() {
    if [ -e /usr/share/vaultlink/install-method.env ] || [ -L /usr/share/vaultlink/install-method.env ]; then
        lifecycle_mode=reinstall
    else
        lifecycle_mode=fresh
    fi
    vaultlink_package_main preinstall "$target_format" "$target_os_id" "$target_os_version" "$target_arch" vaultlink "\$lifecycle_mode"
}
post_install() {
    if [ -e /usr/share/vaultlink/install-method.env ] || [ -L /usr/share/vaultlink/install-method.env ]; then
        lifecycle_mode=reinstall
    else
        lifecycle_mode=fresh
    fi
    vaultlink_package_main postinstall "$target_format" "$target_os_id" "$target_os_version" "$target_arch" vaultlink "\$lifecycle_mode" "$release_version"
}
pre_upgrade() {
    vaultlink_package_main preinstall "$target_format" "$target_os_id" "$target_os_version" "$target_arch" vaultlink upgrade
}
post_upgrade() {
    vaultlink_package_main postinstall "$target_format" "$target_os_id" "$target_os_version" "$target_arch" vaultlink upgrade "$release_version"
}
pre_remove() {
    vaultlink_package_main preremove "$target_format" "$target_os_id" "$target_os_version" "$target_arch" vaultlink remove
}
post_remove() {
    vaultlink_package_main postremove "$target_format" "$target_os_id" "$target_os_version" "$target_arch" vaultlink remove
}
EOF
        } >"$build_dir/.INSTALL"
        cat >"$build_dir/.BUILDINFO" <<EOF
format = 2
pkgname = vaultlink
pkgbase = vaultlink
pkgver = $db_version
pkgarch = $target_arch
pkgbuild_sha256sum = $arch_pkgbuild_sha256
packager = VaultLink maintainers <noreply@vaultlink.example>
builddate = 0
builddir = /build/vaultlink-package
startdir = /build/vaultlink-package
buildtool = makepkg
buildtoolver = 7.1.0
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
installed = fakeroot-1:1.37.2-3-x86_64
installed = pacman-7.1.0.r9.g54d9411-2-x86_64
EOF
        chmod 0644 "$build_dir/.PKGINFO" "$build_dir/.INSTALL" \
            "$build_dir/.BUILDINFO"
        arch_mtree_source="$test_root/arch-mtree-source.$$"
        (
            cd "$build_dir"
            bsdtar --format=mtree \
                --options='!all,use-set,type,uid,gid,mode,time,size,sha256,link' \
                --exclude .MTREE --exclude .vaultlink-test-meta -cf - . \
                | sed '/^\. /d' >"$arch_mtree_source"
        )
        gzip -n <"$arch_mtree_source" >"$build_dir/.MTREE"
        rm -f "$arch_mtree_source"
        chmod 0644 "$build_dir/.MTREE"
        package_entries=arch
    fi
    (
        cd "$build_dir"
        if [ "$package_entries" = arch ]; then
            tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
                -czf "$release_dir/$asset" .vaultlink-test-meta .PKGINFO \
                .INSTALL .BUILDINFO .MTREE usr
        else
            tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
                -czf "$release_dir/$asset" .vaultlink-test-meta usr
        fi
    )
    minisign -S -q -s "$test_root/minisign.key" -m "$release_dir/$asset" \
        -x "$release_dir/$asset.minisig"
    (
        cd "$release_dir"
        sha256sum "$asset" >SHA256SUMS
    )
    minisign -S -q -s "$test_root/minisign.key" -m "$release_dir/SHA256SUMS" \
        -x "$release_dir/SHA256SUMS.minisig"
}

add_arch_dependency_to_release() {
    dependency_version=$1
    dependency_name=$2
    dependency_asset=$(asset_name_for "$dependency_version")
    dependency_tree="$test_root/arch-additive-dependency-$dependency_version"
    rm -rf "$dependency_tree"
    install -d "$dependency_tree"
    tar -xzf "$assets/v$dependency_version/$dependency_asset" -C "$dependency_tree"
    sed -i "/^optdepend = /i depend = $dependency_name" "$dependency_tree/.PKGINFO"
    dependency_mtree_source="$test_root/arch-additive-mtree-$dependency_version"
    (
        cd "$dependency_tree"
        bsdtar --format=mtree \
            --options='!all,use-set,type,uid,gid,mode,time,size,sha256,link' \
            --exclude .MTREE --exclude .vaultlink-test-meta -cf - . \
            | sed '/^\. /d' >"$dependency_mtree_source"
    )
    gzip -n <"$dependency_mtree_source" >"$dependency_tree/.MTREE"
    rm -f "$dependency_mtree_source"
    chmod 0644 "$dependency_tree/.MTREE"
    (
        cd "$dependency_tree"
        tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
            -czf "$assets/v$dependency_version/$dependency_asset" .vaultlink-test-meta \
            .PKGINFO .INSTALL .BUILDINFO .MTREE usr
    )
    minisign -S -q -s "$test_root/minisign.key" \
        -m "$assets/v$dependency_version/$dependency_asset" \
        -x "$assets/v$dependency_version/$dependency_asset.minisig"
    (cd "$assets/v$dependency_version" && sha256sum "$dependency_asset" >SHA256SUMS)
    minisign -S -q -s "$test_root/minisign.key" \
        -m "$assets/v$dependency_version/SHA256SUMS" \
        -x "$assets/v$dependency_version/SHA256SUMS.minisig"
}

prepare_target() {
    target_id=$1
    target_os_id=$2
    target_os_version=$3
    target_format=$4
    target_arch=$5
    target_machine=$6
    rm -rf "$assets" "$records" /usr/lib/vaultlink/package
    rm -f /usr/bin/vaultlink-update /usr/sbin/vaultlink-update \
        /usr/share/vaultlink/install-method.env
    install -d -m 0700 "$assets" "$records"
    install -d -m 0755 /opt/vaultlink /etc/vaultlink /usr/share/vaultlink \
        /var/lib/vaultlink /var/lib/vaultlink-backups
    write_os_release
    make_package 0.6.0 0.6.0 "$test_root/minisign.pub"
    make_package 0.6.1 0.6.1 "$test_root/minisign.pub"
    old_asset=$(asset_name_for 0.6.0)
    tar -xzf "$assets/v0.6.0/$old_asset" -C / \
        --exclude=.vaultlink-test-meta --exclude=.PKGINFO --exclude=.INSTALL \
        --exclude=.BUILDINFO --exclude=.MTREE
    if [ "$target_format" = pkg.tar.zst ]; then
        write_marker /usr/share/vaultlink/install-method.env
    fi
    install -o root -g root -m 0644 "$test_root/minisign.pub" \
        /usr/share/vaultlink/minisign.pub
    install -o root -g root -m 0755 /usr/lib/vaultlink/package/vaultlink \
        /opt/vaultlink/vaultlink
    printf '%s\n%s\n%s\n%s\n' vaultlink 0.6.0 \
        "$(database_version_for 0.6.0)" "$target_arch" >"$test_root/package-db"
    printf '%s\n' '[server]' 'mode = "production_reverse_proxy"' \
        >/etc/vaultlink/config.toml
    chmod 0640 /etc/vaultlink/config.toml
    rm -f /etc/vaultlink/update.conf
    printf '%s\n' secret-key-material >/var/lib/vaultlink/secrets.keyring
    chmod 0600 /var/lib/vaultlink/secrets.keyring
    rm -f /var/lib/vaultlink/data.sqlite
    sqlite3 /var/lib/vaultlink/data.sqlite 'CREATE TABLE update_safety(value TEXT); INSERT INTO update_safety VALUES("old");'
    chown vaultlink:vaultlink /var/lib/vaultlink/data.sqlite /var/lib/vaultlink/secrets.keyring
    chmod 0600 /var/lib/vaultlink/data.sqlite
    : >"$test_root/service-active"
    : >"$test_root/package-installs"
    : >"$test_root/package-recovery-environment"
    : >"$test_root/daemon-reloads"
    : >"$test_root/pacman-dependency-checks"
    rm -f "$test_root/service-active-checks" "$test_root/live-swap-fired" \
        "$test_root/signal-on-stop-fired"
    prepared_marker_sha=$(sha256sum /usr/share/vaultlink/install-method.env | awk '{print $1}')
}

run_updater() {
    VAULTLINK_UPDATE_TEST_ROOT=$test_root \
    VAULTLINK_UPDATE_TEST_ASSETS=$assets \
    VAULTLINK_UPDATE_TEST_MACHINE=$target_machine \
    VAULTLINK_UPDATE_TEST_FORMAT=$target_format \
    VAULTLINK_UPDATE_TEST_OS_ID=$target_os_id \
    VAULTLINK_UPDATE_TEST_OS_VERSION=$target_os_version \
    VAULTLINK_UPDATE_TEST_ARCH=$target_arch \
    VAULTLINK_UPDATE_TEST_LATEST="${VAULTLINK_UPDATE_TEST_LATEST:-0.6.1}" \
    VAULTLINK_UPDATE_TEST_EFFECTIVE_URL="${VAULTLINK_UPDATE_TEST_EFFECTIVE_URL:-}" \
    VAULTLINK_UPDATE_TEST_ASSET_REDIRECT="${VAULTLINK_UPDATE_TEST_ASSET_REDIRECT:-}" \
    VAULTLINK_UPDATE_TEST_FAIL_ASSET="${VAULTLINK_UPDATE_TEST_FAIL_ASSET:-}" \
    VAULTLINK_UPDATE_TEST_DRY_FAIL_VERSION="${VAULTLINK_UPDATE_TEST_DRY_FAIL_VERSION:-}" \
    VAULTLINK_UPDATE_TEST_INSTALL_FAIL_VERSION="${VAULTLINK_UPDATE_TEST_INSTALL_FAIL_VERSION:-}" \
    VAULTLINK_UPDATE_TEST_PACMAN_MISSING="${VAULTLINK_UPDATE_TEST_PACMAN_MISSING:-}" \
    VAULTLINK_UPDATE_TEST_EXTRA_DEP_VERSION="${VAULTLINK_UPDATE_TEST_EXTRA_DEP_VERSION:-}" \
    VAULTLINK_UPDATE_TEST_NATIVE_MISSING_DEP="${VAULTLINK_UPDATE_TEST_NATIVE_MISSING_DEP:-}" \
    VAULTLINK_UPDATE_TEST_DPKG_MISSING="${VAULTLINK_UPDATE_TEST_DPKG_MISSING:-}" \
    VAULTLINK_UPDATE_TEST_EXTRA_SCRIPTLET_VERSION="${VAULTLINK_UPDATE_TEST_EXTRA_SCRIPTLET_VERSION:-}" \
    VAULTLINK_UPDATE_TEST_RPM_PRETRANS_VERSION="${VAULTLINK_UPDATE_TEST_RPM_PRETRANS_VERSION:-}" \
    VAULTLINK_UPDATE_TEST_RPM_REQUIRE_PRE_VERSION="${VAULTLINK_UPDATE_TEST_RPM_REQUIRE_PRE_VERSION:-}" \
    VAULTLINK_UPDATE_TEST_RPM_FILEFLAG_VERSION="${VAULTLINK_UPDATE_TEST_RPM_FILEFLAG_VERSION:-}" \
    VAULTLINK_UPDATE_TEST_RPM_PAYLOAD_VERSION="${VAULTLINK_UPDATE_TEST_RPM_PAYLOAD_VERSION:-}" \
    VAULTLINK_UPDATE_TEST_RPM_DIGEST_VERSION="${VAULTLINK_UPDATE_TEST_RPM_DIGEST_VERSION:-}" \
    VAULTLINK_UPDATE_TEST_UPGRADE_FAIL="${VAULTLINK_UPDATE_TEST_UPGRADE_FAIL:-0}" \
    VAULTLINK_UPDATE_TEST_STOP_BEFORE_TRANSACTION="${VAULTLINK_UPDATE_TEST_STOP_BEFORE_TRANSACTION:-0}" \
    VAULTLINK_UPDATE_TEST_SWAP_LIVE_AFTER_ACTIVE_CHECK="${VAULTLINK_UPDATE_TEST_SWAP_LIVE_AFTER_ACTIVE_CHECK:-0}" \
    VAULTLINK_UPDATE_TEST_SIGNAL_ON_STOP="${VAULTLINK_UPDATE_TEST_SIGNAL_ON_STOP:-}" \
    VAULTLINK_UPDATE_TEST_SIGNAL_DURING_RECOVERY="${VAULTLINK_UPDATE_TEST_SIGNAL_DURING_RECOVERY:-}" \
    VAULTLINK_UPDATE_TEST_DAEMON_RELOAD_FAIL_VERSION="${VAULTLINK_UPDATE_TEST_DAEMON_RELOAD_FAIL_VERSION:-}" \
    VAULTLINK_UPDATE_TEST_RPM_EPOCH_VERSION="${VAULTLINK_UPDATE_TEST_RPM_EPOCH_VERSION:-}" \
    VAULTLINK_UPDATE_TEST_INSTALLED_RPM_EPOCH="${VAULTLINK_UPDATE_TEST_INSTALLED_RPM_EPOCH:-0}" \
    VAULTLINK_UPDATE_TEST_IDENTITY_FAULT="${VAULTLINK_UPDATE_TEST_IDENTITY_FAULT:-}" \
        "$updater" "$@"
}

assert_old_state() {
    [ "$(/opt/vaultlink/vaultlink --version)" = 0.6.0 ] || fail "$1 did not restore the old binary"
    [ "$(sed -n '2p' "$test_root/package-db")" = 0.6.0 ] || fail "$1 did not restore the old package"
    [ -e "$test_root/service-active" ] || fail "$1 did not restore the active service"
    [ "$(sqlite3 /var/lib/vaultlink/data.sqlite 'SELECT value FROM update_safety;')" = old ] \
        || fail "$1 did not restore the database"
    [ "$(sha256sum /usr/share/vaultlink/install-method.env | awk '{print $1}')" = \
        "$prepared_marker_sha" ] || fail "$1 did not preserve the installation marker"
}

capture_mutable_identity() {
    captured_config_sha=$(sha256sum /etc/vaultlink/config.toml | awk '{ print $1 }')
    captured_config_stat=$(stat -c '%d:%i:%u:%g:%a:%y' /etc/vaultlink/config.toml)
    if [ -e /etc/vaultlink/update.conf ] || [ -L /etc/vaultlink/update.conf ]; then
        [ -f /etc/vaultlink/update.conf ] && [ ! -L /etc/vaultlink/update.conf ] \
            || fail "test fixture update.conf is not regular"
        captured_update_presence=present
        captured_update_sha=$(sha256sum /etc/vaultlink/update.conf | awk '{ print $1 }')
        captured_update_stat=$(stat -c '%d:%i:%u:%g:%a:%y' /etc/vaultlink/update.conf)
    else
        captured_update_presence=absent
        captured_update_sha=
        captured_update_stat=
    fi
}

assert_mutable_identity() {
    mutable_label=$1
    [ "$(sha256sum /etc/vaultlink/config.toml | awk '{ print $1 }')" = \
        "$captured_config_sha" ] \
        || fail "$mutable_label changed config.toml content"
    [ "$(stat -c '%d:%i:%u:%g:%a:%y' /etc/vaultlink/config.toml)" = \
        "$captured_config_stat" ] \
        || fail "$mutable_label changed config.toml inode or metadata"
    if [ "$captured_update_presence" = present ]; then
        [ -f /etc/vaultlink/update.conf ] && [ ! -L /etc/vaultlink/update.conf ] \
            || fail "$mutable_label removed or replaced update.conf"
        [ "$(sha256sum /etc/vaultlink/update.conf | awk '{ print $1 }')" = \
            "$captured_update_sha" ] \
            || fail "$mutable_label changed update.conf content"
        [ "$(stat -c '%d:%i:%u:%g:%a:%y' /etc/vaultlink/update.conf)" = \
            "$captured_update_stat" ] \
            || fail "$mutable_label changed update.conf inode or metadata"
    else
        [ ! -e /etc/vaultlink/update.conf ] && [ ! -L /etc/vaultlink/update.conf ] \
            || fail "$mutable_label created an intentionally absent update.conf"
    fi
}

assert_terminal_recovery_state() {
    terminal_label=$1
    terminal_stderr=$test_root/$terminal_label.stderr
    grep -F -q 'package/runtime recovery parity failed' "$terminal_stderr" \
        || fail "$terminal_label did not report terminal package/runtime parity failure"
    grep -F -q 'verified old package and signed evidence preserved at /var/lib/vaultlink-backups/update-evidence/vaultlink-update.' \
        "$terminal_stderr" \
        || fail "$terminal_label did not report its preserved signed evidence"
    terminal_work=$(sed -n 's/^CRITICAL: verified old package and signed evidence preserved at //p' \
        "$terminal_stderr")
    [ -d "$terminal_work/old-release" ] \
        && [ "$(stat -c %a "$terminal_work")" = 700 ] \
        || fail "$terminal_label evidence is not retained root-only"
    find "$terminal_work/old-release" -type f -name '*.minisig' -print -quit | grep -q . \
        || fail "$terminal_label evidence lacks old Minisign signatures"

    [ ! -e "$test_root/service-active" ] \
        || fail "$terminal_label restarted the service with failed recovery parity"
    terminal_live_version=$(/opt/vaultlink/vaultlink --version)
    terminal_candidate_version=$(/usr/lib/vaultlink/package/vaultlink --version)
    terminal_package_version=$(sed -n '2p' "$test_root/package-db")
    [ "$terminal_live_version" = 0.6.0 ] \
        || fail "$terminal_label did not retain the recovered old live binary"
    [ "$terminal_candidate_version" = 0.6.1 ] \
        && [ "$terminal_package_version" = 0.6.1 ] \
        || fail "$terminal_label did not expose the expected terminal package state"
    [ "$terminal_live_version" != "$terminal_package_version" ] \
        || fail "$terminal_label did not exercise mixed package/live parity"
    [ "$(sqlite3 /var/lib/vaultlink/data.sqlite 'SELECT value FROM update_safety;')" = old ] \
        || fail "$terminal_label did not retain the recovered old database"
    [ "$(sha256sum /usr/share/vaultlink/install-method.env | awk '{print $1}')" = \
        "$prepared_marker_sha" ] || fail "$terminal_label changed the installation marker"
    rm -rf "$terminal_work"
}

test_primary_safety_cases() {
    prepare_target debian13-amd64 debian 13 deb amd64 x86_64

    VAULTLINK_UPDATE_TEST_LATEST=0.6.0 run_updater check >"$test_root/current.stdout"
    grep -F -x -q 'update_available=false' "$test_root/current.stdout"
    run_updater check >"$test_root/check.stdout"
    grep -F -x -q 'installed_version=0.6.0' "$test_root/check.stdout"
    grep -F -x -q 'latest_version=0.6.1' "$test_root/check.stdout"
    grep -F -x -q 'update_available=true' "$test_root/check.stdout"
    [ ! -s "$test_root/package-installs" ] || fail "check mode changed the package database"

    printf '%s\n' auto_install=false >/etc/vaultlink/update.conf
    chmod 0644 /etc/vaultlink/update.conf
    run_updater auto >"$test_root/auto-disabled.stdout"
    grep -F -x -q 'auto_install=false' "$test_root/auto-disabled.stdout"
    chmod 0666 /etc/vaultlink/update.conf
    expect_failure writable-config run_updater auto
    chmod 0644 /etc/vaultlink/update.conf
    printf '%s\n' auto_install=true unknown=true >/etc/vaultlink/update.conf
    expect_failure unknown-config run_updater auto

    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    rm -f /usr/share/vaultlink/install-method.env
    expect_failure markerless-archive run_updater check
    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    chmod 0666 /usr/share/vaultlink/install-method.env
    expect_failure writable-marker run_updater check
    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    chown root:vaultlink /usr/share/vaultlink/install-method.env
    expect_failure non-root-group-marker run_updater check
    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    printf '%s\n%s\n%s\n%s\n%s' FORMAT=deb OS_ID=debian OS_VERSION=13 \
        ARCH=amd64 PACKAGE_NAME=vaultlink >/usr/share/vaultlink/install-method.env
    expect_failure unterminated-marker run_updater check
    for identity_fault in root-uid wrong-home wrong-shell unlocked-shadow supplementary-group; do
        prepare_target debian13-amd64 debian 13 deb amd64 x86_64
        VAULTLINK_UPDATE_TEST_IDENTITY_FAULT=$identity_fault \
            expect_failure "identity-$identity_fault" run_updater check
        assert_old_state "identity $identity_fault"
        [ ! -s "$test_root/package-installs" ] \
            || fail "identity $identity_fault mutated the package database"
        ! grep -F -q 'CRITICAL:' "$test_root/identity-$identity_fault.stderr" \
            || fail "identity $identity_fault incorrectly entered terminal recovery"
    done
    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    sed -i 's/^OS_VERSION=.*/OS_VERSION=24.04/' /usr/share/vaultlink/install-method.env
    expect_failure mismatched-marker run_updater check
    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    sed -i '3s/.*/0.5.0-1+deb13/' "$test_root/package-db"
    expect_failure mismatched-package-db run_updater check

    prepare_target archlinux-amd64 arch rolling pkg.tar.zst x86_64 x86_64
    VAULTLINK_UPDATE_TEST_INSTALLED_PACMAN_ARCH=any \
        expect_failure mismatched-pacman-db-arch run_updater check
    assert_old_state mismatched-pacman-db-arch

    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    VAULTLINK_UPDATE_TEST_EFFECTIVE_URL=https://example.test/releases/tag/v0.6.1 \
        expect_failure wrong-repository run_updater check
    VAULTLINK_UPDATE_TEST_EFFECTIVE_URL=https://github.com/alexhaberl/VaultLink/releases/tag/v0.6.1-rc.1 \
        expect_failure prerelease run_updater check
    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    VAULTLINK_UPDATE_TEST_ASSET_REDIRECT=https://example.test/untrusted-release-asset \
        expect_failure untrusted-asset-redirect run_updater install
    assert_old_state untrusted-asset-redirect
    VAULTLINK_UPDATE_TEST_ASSET_REDIRECT=http://release-assets.githubusercontent.com/github-production-release-asset/test \
        expect_failure http-asset-redirect run_updater install
    VAULTLINK_UPDATE_TEST_ASSET_REDIRECT=https://release-assets.githubusercontent.com.evil.example/github-production-release-asset/test \
        expect_failure asset-redirect-subdomain-bypass run_updater install
    VAULTLINK_UPDATE_TEST_ASSET_REDIRECT=https://release-assets.githubusercontent.com@evil.example/github-production-release-asset/test \
        expect_failure asset-redirect-userinfo-bypass run_updater install
    assert_old_state redirect-bypass-cases

    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    new_asset=$(asset_name_for 0.6.1)
    printf tampered >>"$assets/v0.6.1/$new_asset"
    expect_failure tampered-new-package run_updater install
    assert_old_state tampered-new-package
    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    old_asset=$(asset_name_for 0.6.0)
    printf tampered >>"$assets/v0.6.0/$old_asset"
    expect_failure tampered-old-package run_updater install
    assert_old_state tampered-old-package
    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    VAULTLINK_UPDATE_TEST_FAIL_ASSET="v0.6.1/$(asset_name_for 0.6.1).minisig" \
        expect_failure missing-package-signature run_updater install

    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    make_package 0.6.1 0.6.1 "$test_root/other-minisign.pub"
    expect_failure replacement-public-key run_updater install
    assert_old_state replacement-public-key
    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    make_package 0.6.1 9.9.9 "$test_root/minisign.pub"
    expect_failure wrong-candidate-version run_updater install
    assert_old_state wrong-candidate-version
    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    VAULTLINK_UPDATE_TEST_EXTRA_SCRIPTLET_VERSION=0.6.1 \
        expect_failure extra-deb-scriptlet-command run_updater install
    assert_old_state extra-deb-scriptlet-command

    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    new_asset=$(asset_name_for 0.6.1)
    unsafe_tree="$test_root/unsafe-extra-file"
    install -d "$unsafe_tree"
    tar -xzf "$assets/v0.6.1/$new_asset" -C "$unsafe_tree"
    install -d "$unsafe_tree/usr/bin"
    printf '%s\n' unexpected >"$unsafe_tree/usr/bin/unexpected-vaultlink-file"
    (
        cd "$unsafe_tree"
        tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
            -czf "$assets/v0.6.1/$new_asset" .vaultlink-test-meta usr
    )
    minisign -S -q -s "$test_root/minisign.key" -m "$assets/v0.6.1/$new_asset" \
        -x "$assets/v0.6.1/$new_asset.minisig"
    (cd "$assets/v0.6.1" && sha256sum "$new_asset" >SHA256SUMS)
    minisign -S -q -s "$test_root/minisign.key" -m "$assets/v0.6.1/SHA256SUMS" \
        -x "$assets/v0.6.1/SHA256SUMS.minisig"
    expect_failure unexpected-signed-payload run_updater install
    assert_old_state unexpected-signed-payload

    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    new_asset=$(asset_name_for 0.6.1)
    unsafe_tree="$test_root/unsafe-link"
    install -d "$unsafe_tree"
    tar -xzf "$assets/v0.6.1/$new_asset" -C "$unsafe_tree"
    rm -f "$unsafe_tree/usr/lib/vaultlink/package/vaultlink"
    ln -s /bin/true "$unsafe_tree/usr/lib/vaultlink/package/vaultlink"
    (
        cd "$unsafe_tree"
        tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
            -czf "$assets/v0.6.1/$new_asset" .vaultlink-test-meta usr
    )
    minisign -S -q -s "$test_root/minisign.key" -m "$assets/v0.6.1/$new_asset" \
        -x "$assets/v0.6.1/$new_asset.minisig"
    (cd "$assets/v0.6.1" && sha256sum "$new_asset" >SHA256SUMS)
    minisign -S -q -s "$test_root/minisign.key" -m "$assets/v0.6.1/SHA256SUMS" \
        -x "$assets/v0.6.1/SHA256SUMS.minisig"
    expect_failure signed-payload-symlink run_updater install
    assert_old_state signed-payload-symlink

    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    new_asset=$(asset_name_for 0.6.1)
    unsafe_tree="$test_root/unsafe-empty-directory"
    install -d "$unsafe_tree"
    tar -xzf "$assets/v0.6.1/$new_asset" -C "$unsafe_tree"
    install -d "$unsafe_tree/usr/share/unexpected-empty-directory"
    (
        cd "$unsafe_tree"
        tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
            -czf "$assets/v0.6.1/$new_asset" .vaultlink-test-meta usr
    )
    minisign -S -q -s "$test_root/minisign.key" -m "$assets/v0.6.1/$new_asset" \
        -x "$assets/v0.6.1/$new_asset.minisig"
    (cd "$assets/v0.6.1" && sha256sum "$new_asset" >SHA256SUMS)
    minisign -S -q -s "$test_root/minisign.key" -m "$assets/v0.6.1/SHA256SUMS" \
        -x "$assets/v0.6.1/SHA256SUMS.minisig"
    expect_failure signed-payload-empty-directory run_updater install
    assert_old_state signed-payload-empty-directory

    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    printf '%s\n' auto_install=true >/etc/vaultlink/update.conf
    chmod 0644 /etc/vaultlink/update.conf
    rm -f "$test_root/service-active"
    expect_failure inactive-auto run_updater auto
    [ "$(/opt/vaultlink/vaultlink --version)" = 0.6.0 ] || fail "inactive auto changed runtime"

    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    printf '%s\n' auto_install=true >/etc/vaultlink/update.conf
    chmod 0644 /etc/vaultlink/update.conf
    VAULTLINK_UPDATE_TEST_STOP_BEFORE_TRANSACTION=1 \
        expect_failure stopped-during-auto-preparation run_updater auto
    [ "$(/opt/vaultlink/vaultlink --version)" = 0.6.0 ] \
        || fail "late-inactive auto changed runtime"
    [ ! -s "$test_root/package-installs" ] \
        || fail "late-inactive auto mutated the package database"

    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    printf '%s\n' auto_install=true >/etc/vaultlink/update.conf
    chmod 0644 /etc/vaultlink/update.conf
    VAULTLINK_UPDATE_TEST_SWAP_LIVE_AFTER_ACTIVE_CHECK=1 \
        expect_failure same-version-live-race run_updater auto
    [ -e "$test_root/service-active" ] \
        || fail "same-version live race stopped the original service"
    [ ! -s "$test_root/package-installs" ] \
        || fail "same-version live race mutated the package database"
    ! cmp -s /opt/vaultlink/vaultlink /usr/lib/vaultlink/package/vaultlink \
        || fail "same-version live-race fixture did not alter the runtime bytes"

    for interruption_signal in HUP INT TERM; do
        prepare_target debian13-amd64 debian 13 deb amd64 x86_64
        VAULTLINK_UPDATE_TEST_SIGNAL_ON_STOP=$interruption_signal \
            expect_failure "signal-$interruption_signal-during-backup" run_updater install
        assert_old_state "signal $interruption_signal during backup"
        [ ! -s "$test_root/package-installs" ] \
            || fail "signal $interruption_signal during backup mutated the package database"
    done

    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    VAULTLINK_UPDATE_TEST_DRY_FAIL_VERSION=0.6.1 \
        expect_failure missing-dependency run_updater install
    assert_old_state missing-dependency
    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    capture_mutable_identity
    VAULTLINK_UPDATE_TEST_INSTALL_FAIL_VERSION=0.6.1 \
        expect_failure package-manager-failure run_updater install
    assert_old_state package-manager-failure
    assert_mutable_identity package-manager-failure
    grep -F -x -q 0.6.0 "$test_root/package-installs" \
        || {
            tail -n 400 "$test_root/package-manager-failure.stderr" >&2
            fail "package-manager failure did not reinstall the verified old package"
        }
    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    capture_mutable_identity
    VAULTLINK_PACKAGE_RECOVERY=1 \
    VAULTLINK_UPDATE_TEST_UPGRADE_FAIL=1 \
        expect_failure activation-failure run_updater install
    assert_old_state activation-failure
    assert_mutable_identity activation-failure
    grep -F -x -q 0.6.0 "$test_root/package-installs" \
        || fail "activation failure did not reinstall the verified old package"
    grep -F -x -q '0.6.1:unset' "$test_root/package-recovery-environment" \
        || fail "normal new-package installation inherited external recovery authority"
    grep -F -x -q '0.6.0:1' "$test_root/package-recovery-environment" \
        || fail "verified old-package reinstall lacked bounded recovery authority"

    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    capture_mutable_identity
    VAULTLINK_UPDATE_TEST_DAEMON_RELOAD_FAIL_VERSION=0.6.1 \
        expect_failure new-daemon-reload-failure run_updater install
    assert_old_state new-daemon-reload-failure
    assert_mutable_identity new-daemon-reload-failure
    grep -F -x -q 0.6.1 "$test_root/daemon-reloads" \
        || {
            tail -n 200 "$test_root/new-daemon-reload-failure.stderr" >&2
            fail "new-package daemon-reload failure was not exercised"
        }
    grep -F -x -q 0.6.0 "$test_root/daemon-reloads" \
        || fail "old package recovery did not reload units"

    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    capture_mutable_identity
    VAULTLINK_UPDATE_TEST_UPGRADE_FAIL=1 \
    VAULTLINK_UPDATE_TEST_SIGNAL_DURING_RECOVERY=TERM \
        expect_failure signal-during-recovery run_updater install
    assert_old_state signal-during-recovery
    assert_mutable_identity signal-during-recovery

    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    capture_mutable_identity
    VAULTLINK_UPDATE_TEST_UPGRADE_FAIL=1 \
    VAULTLINK_UPDATE_TEST_DAEMON_RELOAD_FAIL_VERSION=0.6.0 \
        expect_failure recovery-daemon-reload-failure run_updater install
    [ ! -e "$test_root/service-active" ] \
        || fail "recovery daemon-reload failure restarted the service"
    grep -F -q 'CRITICAL:' "$test_root/recovery-daemon-reload-failure.stderr" \
        || fail "recovery daemon-reload failure was not terminal"
    assert_mutable_identity recovery-daemon-reload-failure

    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    VAULTLINK_UPDATE_TEST_UPGRADE_FAIL=1 \
    VAULTLINK_UPDATE_TEST_INSTALL_FAIL_VERSION=0.6.0 \
        expect_failure terminal-recovery run_updater install
    assert_terminal_recovery_state terminal-recovery

    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    printf '%s\n' auto_install=true >/etc/vaultlink/update.conf
    chmod 0644 /etc/vaultlink/update.conf
    capture_mutable_identity
    run_updater auto >"$test_root/success.stdout"
    grep -F -x -q 'update_installed=true' "$test_root/success.stdout"
    grep -F -q 'recovery_directory=/var/lib/vaultlink-backups/package-update-' "$test_root/success.stdout"
    [ "$(/opt/vaultlink/vaultlink --version)" = 0.6.1 ] || fail "successful update did not activate candidate"
    [ "$(sed -n '2p' "$test_root/package-db")" = 0.6.1 ] || fail "successful update did not update package database"
    assert_mutable_identity successful-update

    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    rm -f "$test_root/service-active"
    run_updater install >"$test_root/stopped-manual.stdout"
    [ ! -e "$test_root/service-active" ] \
        || fail "manual update did not preserve a deliberately stopped service"
    [ "$(/opt/vaultlink/vaultlink --version)" = 0.6.1 ] \
        || fail "stopped-service manual update did not activate the verified candidate"
}

test_additive_native_dependency_contract() {
    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    VAULTLINK_UPDATE_TEST_EXTRA_DEP_VERSION=0.6.1 \
        run_updater install >"$test_root/deb-extra-dependency-present.stdout"
    [ "$(/opt/vaultlink/vaultlink --version)" = 0.6.1 ] \
        || fail "DEB update with an installed additive dependency failed"

    prepare_target debian13-amd64 debian 13 deb amd64 x86_64
    VAULTLINK_UPDATE_TEST_EXTRA_DEP_VERSION=0.6.1 \
    VAULTLINK_UPDATE_TEST_DPKG_MISSING=test-extra-runtime \
        expect_failure deb-extra-dependency-missing run_updater install
    assert_old_state deb-extra-dependency-missing
    [ ! -s "$test_root/package-installs" ] \
        || fail "missing additive DEB dependency mutated the package database"

    prepare_target fedora44-amd64 fedora 44 rpm x86_64 x86_64
    VAULTLINK_UPDATE_TEST_EXTRA_DEP_VERSION=0.6.1 \
        run_updater install >"$test_root/rpm-extra-dependency-present.stdout"
    [ "$(/opt/vaultlink/vaultlink --version)" = 0.6.1 ] \
        || fail "RPM update with an installed additive dependency failed"

    prepare_target fedora44-amd64 fedora 44 rpm x86_64 x86_64
    VAULTLINK_UPDATE_TEST_EXTRA_DEP_VERSION=0.6.1 \
    VAULTLINK_UPDATE_TEST_NATIVE_MISSING_DEP=test-extra-runtime \
        expect_failure rpm-extra-dependency-missing run_updater install
    assert_old_state rpm-extra-dependency-missing
    [ ! -s "$test_root/package-installs" ] \
        || fail "missing additive RPM dependency mutated the package database"
}

test_arch_marker_and_dependency_contract() {
    prepare_target archlinux-amd64 arch rolling pkg.tar.zst x86_64 x86_64
    new_asset=$(asset_name_for 0.6.1)
    arch_unsafe_tree="$test_root/arch-package-owned-marker"
    install -d "$arch_unsafe_tree"
    tar -xzf "$assets/v0.6.1/$new_asset" -C "$arch_unsafe_tree"
    write_marker "$arch_unsafe_tree/usr/share/vaultlink/install-method.env"
    (
        cd "$arch_unsafe_tree"
        tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
            -czf "$assets/v0.6.1/$new_asset" .vaultlink-test-meta .PKGINFO \
            .INSTALL .BUILDINFO .MTREE usr
    )
    minisign -S -q -s "$test_root/minisign.key" -m "$assets/v0.6.1/$new_asset" \
        -x "$assets/v0.6.1/$new_asset.minisig"
    (cd "$assets/v0.6.1" && sha256sum "$new_asset" >SHA256SUMS)
    minisign -S -q -s "$test_root/minisign.key" -m "$assets/v0.6.1/SHA256SUMS" \
        -x "$assets/v0.6.1/SHA256SUMS.minisig"
    expect_failure arch-package-owned-marker run_updater install
    assert_old_state arch-package-owned-marker

    prepare_target archlinux-amd64 arch rolling pkg.tar.zst x86_64 x86_64
    new_asset=$(asset_name_for 0.6.1)
    arch_unsafe_tree="$test_root/arch-extra-install-command"
    install -d "$arch_unsafe_tree"
    tar -xzf "$assets/v0.6.1/$new_asset" -C "$arch_unsafe_tree"
    printf '%s\n' ': unexpected Arch install command' >>"$arch_unsafe_tree/.INSTALL"
    (
        cd "$arch_unsafe_tree"
        tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
            -czf "$assets/v0.6.1/$new_asset" .vaultlink-test-meta .PKGINFO \
            .INSTALL .BUILDINFO .MTREE usr
    )
    minisign -S -q -s "$test_root/minisign.key" -m "$assets/v0.6.1/$new_asset" \
        -x "$assets/v0.6.1/$new_asset.minisig"
    (cd "$assets/v0.6.1" && sha256sum "$new_asset" >SHA256SUMS)
    minisign -S -q -s "$test_root/minisign.key" -m "$assets/v0.6.1/SHA256SUMS" \
        -x "$assets/v0.6.1/SHA256SUMS.minisig"
    expect_failure arch-extra-install-command run_updater install
    assert_old_state arch-extra-install-command

    prepare_target archlinux-amd64 arch rolling pkg.tar.zst x86_64 x86_64
    VAULTLINK_UPDATE_TEST_PACMAN_MISSING=zstd \
        expect_failure arch-missing-dependency run_updater install
    assert_old_state arch-missing-dependency
    [ ! -s "$test_root/package-installs" ] \
        || fail "Arch dependency failure mutated the package database"

    prepare_target archlinux-amd64 arch rolling pkg.tar.zst x86_64 x86_64
    add_arch_dependency_to_release 0.6.1 test-extra-runtime
    run_updater install >"$test_root/arch-extra-dependency-present.stdout"
    [ "$(/opt/vaultlink/vaultlink --version)" = 0.6.1 ] \
        || fail "Arch update with an installed additive dependency failed"

    prepare_target archlinux-amd64 arch rolling pkg.tar.zst x86_64 x86_64
    add_arch_dependency_to_release 0.6.1 test-extra-runtime
    VAULTLINK_UPDATE_TEST_PACMAN_MISSING=test-extra-runtime \
        expect_failure arch-extra-dependency-missing run_updater install
    assert_old_state arch-extra-dependency-missing
    [ ! -s "$test_root/package-installs" ] \
        || fail "missing additive Arch dependency mutated the package database"
}

test_rpm_scriptlet_contract() {
    prepare_target fedora44-amd64 fedora 44 rpm x86_64 x86_64
    VAULTLINK_UPDATE_TEST_RPM_PRETRANS_VERSION=0.6.1 \
        expect_failure unexpected-rpm-pretrans run_updater install
    assert_old_state unexpected-rpm-pretrans

    prepare_target fedora44-amd64 fedora 44 rpm x86_64 x86_64
    VAULTLINK_UPDATE_TEST_RPM_EPOCH_VERSION=0.6.1 \
        expect_failure unexpected-rpm-epoch run_updater install
    assert_old_state unexpected-rpm-epoch
    [ ! -s "$test_root/package-installs" ] \
        || fail "nonzero RPM epoch mutated package state"

    prepare_target fedora44-amd64 fedora 44 rpm x86_64 x86_64
    VAULTLINK_UPDATE_TEST_RPM_REQUIRE_PRE_VERSION=0.6.1 \
        expect_failure unexpected-rpm-require-flags run_updater install
    assert_old_state unexpected-rpm-require-flags

    prepare_target fedora44-amd64 fedora 44 rpm x86_64 x86_64
    VAULTLINK_UPDATE_TEST_RPM_FILEFLAG_VERSION=0.6.1 \
        expect_failure unexpected-rpm-file-flags run_updater install
    assert_old_state unexpected-rpm-file-flags

    prepare_target fedora44-amd64 fedora 44 rpm x86_64 x86_64
    VAULTLINK_UPDATE_TEST_RPM_PAYLOAD_VERSION=0.6.1 \
        expect_failure unexpected-rpm-payload run_updater install
    assert_old_state unexpected-rpm-payload

    prepare_target fedora44-amd64 fedora 44 rpm x86_64 x86_64
    VAULTLINK_UPDATE_TEST_RPM_DIGEST_VERSION=0.6.1 \
        expect_failure unexpected-rpm-digest run_updater install
    assert_old_state unexpected-rpm-digest
}

test_target_success() {
    prepare_target "$@"
    capture_mutable_identity
    run_updater install >"$test_root/$target_id-success.stdout"
    grep -F -x -q 'update_installed=true' "$test_root/$target_id-success.stdout"
    [ "$(/opt/vaultlink/vaultlink --version)" = 0.6.1 ] || fail "$target_id did not activate 0.6.1"
    [ "$(sed -n '2p' "$test_root/package-db")" = 0.6.1 ] || fail "$target_id package database mismatch"
    [ "$(sha256sum /usr/share/vaultlink/install-method.env | awk '{print $1}')" = \
        "$prepared_marker_sha" ] || fail "$target_id changed the persistent installation marker"
    assert_mutable_identity "$target_id successful update"
    if [ "$target_format" = pkg.tar.zst ]; then
        [ "$(wc -l <"$test_root/pacman-dependency-checks" | tr -d '[:space:]')" -eq 2 ] \
            || fail "Arch did not validate both new and rollback package dependencies"
    fi
}

test_target_terminal_recovery() {
    prepare_target "$@"
    capture_mutable_identity
    terminal_case=$target_id-terminal-recovery
    VAULTLINK_UPDATE_TEST_UPGRADE_FAIL=1 \
    VAULTLINK_UPDATE_TEST_INSTALL_FAIL_VERSION=0.6.0 \
        expect_failure "$terminal_case" run_updater install
    assert_terminal_recovery_state "$terminal_case"
    assert_mutable_identity "$terminal_case"
}

test_target_matrix_case() {
    test_target_terminal_recovery "$@"
    test_target_success "$@"
}

test_primary_safety_cases
test_additive_native_dependency_contract
test_arch_marker_and_dependency_contract
test_rpm_scriptlet_contract
test_target_matrix_case debian13-arm64 debian 13 deb arm64 aarch64
test_target_matrix_case ubuntu2404-amd64 ubuntu 24.04 deb amd64 x86_64
test_target_matrix_case ubuntu2404-arm64 ubuntu 24.04 deb arm64 aarch64
test_target_matrix_case ubuntu2604-amd64 ubuntu 26.04 deb amd64 x86_64
test_target_matrix_case ubuntu2604-arm64 ubuntu 26.04 deb arm64 aarch64
test_target_matrix_case fedora44-amd64 fedora 44 rpm x86_64 x86_64
test_target_matrix_case fedora44-arm64 fedora 44 rpm aarch64 aarch64
test_target_matrix_case archlinux-amd64 arch rolling pkg.tar.zst x86_64 x86_64

echo "VaultLink signed native-package update safety tests passed (9 targets)"
