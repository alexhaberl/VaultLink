#!/bin/sh
set -eu
umask 077

[ "$(id -u)" -eq 0 ] || {
    echo "update safety tests must run as root in a disposable container" >&2
    exit 1
}

test_root=/tmp/vaultlink-update-safety
assets="$test_root/assets"
records="$test_root/records"
updater=/work/deploy/vaultlink-update.sh
real_curl=/usr/bin/curl.real-vaultlink-test
real_systemctl=/usr/bin/systemctl.real-vaultlink-test

cleanup() {
    if [ -e "$real_curl" ]; then
        mv -f "$real_curl" /usr/bin/curl
    fi
    if [ -e "$real_systemctl" ]; then
        mv -f "$real_systemctl" /usr/bin/systemctl
    fi
    rm -rf "$test_root"
    rm -f /etc/vaultlink/update.conf
    rm -f /usr/share/vaultlink/minisign.pub
    rm -f /opt/vaultlink/vaultlink
}
trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
    echo "update safety test failed: $*" >&2
    exit 1
}

expect_failure() {
    name=$1
    shift
    if "$@" >"$test_root/$name.stdout" 2>"$test_root/$name.stderr"; then
        fail "$name unexpectedly succeeded"
    fi
}

make_binary() {
    destination=$1
    version=$2
    install -d "$(dirname "$destination")"
    printf '%s\n' \
        '#!/bin/sh' \
        "if [ \"\$#\" -eq 1 ] && [ \"\$1\" = --version ]; then" \
        "    printf '%s\\n' '$version'" \
        '    exit 0' \
        'fi' \
        'exit 64' \
        >"$destination"
    chmod 0755 "$destination"
}

make_release() {
    release_version=$1
    binary_version=$2
    release_dir="$test_root/build-$release_version-$binary_version"
    release_root="VaultLink-$release_version-debian13-$architecture"
    rm -rf "$release_dir"
    install -d "$release_dir/$release_root/bin" "$release_dir/$release_root/deploy"
    make_binary "$release_dir/$release_root/bin/vaultlink" "$binary_version"
    cp /usr/share/vaultlink/minisign.pub "$release_dir/$release_root/minisign.pub"
    cat >"$release_dir/$release_root/deploy/vaultlink-upgrade.sh" <<'EOF'
#!/bin/sh
set -eu
[ "$#" -eq 2 ]
candidate=$1
config=$2
[ "$config" = /etc/vaultlink/config.toml ]
version=$("$candidate" --version)
printf '%s\n' "$version" >"$VAULTLINK_UPDATE_TEST_RECORDS/version"
printf '%s\n' "$candidate" >"$VAULTLINK_UPDATE_TEST_RECORDS/candidate"
printf '%s\n' "$config" >"$VAULTLINK_UPDATE_TEST_RECORDS/config"
printf '%s\n' /var/lib/vaultlink-backups/update-safety-test
EOF
    chmod 0755 "$release_dir/$release_root/deploy/vaultlink-upgrade.sh"
    (
        cd "$release_dir"
        tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
            -czf "$assets/$release_root.tar.gz" "$release_root"
    )
    (
        cd "$assets"
        sha256sum "$release_root.tar.gz" >"SHA256SUMS-$architecture"
    )
    minisign -S -q -s "$test_root/minisign.key" \
        -m "$assets/$release_root.tar.gz" \
        -x "$assets/$release_root.tar.gz.minisig"
    minisign -S -q -s "$test_root/minisign.key" \
        -m "$assets/SHA256SUMS-$architecture" \
        -x "$assets/SHA256SUMS-$architecture.minisig"
}

rm -rf "$test_root"
install -d "$assets" "$records" /opt/vaultlink /etc/vaultlink /usr/share/vaultlink
architecture=$(dpkg --print-architecture)
case "$architecture" in amd64|arm64) ;; *) fail "unexpected test architecture" ;; esac

minisign -G -W -p "$test_root/minisign.pub" -s "$test_root/minisign.key" >/dev/null
install -o root -g root -m 0644 "$test_root/minisign.pub" /usr/share/vaultlink/minisign.pub
make_binary /opt/vaultlink/vaultlink 0.5.1
printf '%s\n' '[server]' 'mode = "production_reverse_proxy"' \
    >/etc/vaultlink/config.toml
chown root:root /opt/vaultlink/vaultlink /etc/vaultlink/config.toml
chmod 0755 /opt/vaultlink/vaultlink
chmod 0640 /etc/vaultlink/config.toml
make_release 0.5.2 0.5.2

[ -x /usr/bin/curl ] || fail "the container curl binary is missing"
mv /usr/bin/curl "$real_curl"
cat >/usr/bin/curl <<'EOF'
#!/bin/sh
set -eu
output=
write_out=
url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --max-redirs|--proto|--proto-redir|--connect-timeout|--max-time|--retry|--retry-delay|--retry-max-time|--user-agent|--max-filesize|--output|--write-out)
            [ "$#" -ge 2 ] || exit 64
            case "$1" in
                --output) output=$2 ;;
                --write-out) write_out=$2 ;;
            esac
            shift 2
            ;;
        --fail|--silent|--show-error|--location|--tlsv1.2)
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
        [ "$write_out" = '%{url_effective}' ] || exit 64
        printf '%s' "${VAULTLINK_UPDATE_TEST_EFFECTIVE_URL:-https://github.com/alexhaberl/VaultLink/releases/tag/v${VAULTLINK_UPDATE_TEST_VERSION:-0.5.2}}"
        ;;
    https://github.com/alexhaberl/VaultLink/releases/download/*)
        [ -n "$output" ] || exit 64
        asset=${url##*/}
        [ "${VAULTLINK_UPDATE_TEST_FAIL_ASSET:-}" != "$asset" ] || exit 22
        cp "$VAULTLINK_UPDATE_TEST_ASSETS/$asset" "$output"
        ;;
    *) exit 22 ;;
esac
EOF
chmod 0755 /usr/bin/curl
[ -x /usr/bin/systemctl ] || fail "the container systemctl binary is missing"
mv /usr/bin/systemctl "$real_systemctl"
cat >/usr/bin/systemctl <<'EOF'
#!/bin/sh
set -eu
if [ "$#" -eq 3 ] && [ "$1" = --quiet ] && [ "$2" = is-active ] \
    && [ "$3" = vaultlink.service ]; then
    [ "${VAULTLINK_UPDATE_TEST_SERVICE_ACTIVE:-1}" = 1 ]
    exit
fi
exit 64
EOF
chmod 0755 /usr/bin/systemctl

run_updater() {
    VAULTLINK_UPDATE_TEST_ASSETS="${VAULTLINK_UPDATE_TEST_ASSETS:-$assets}" \
    VAULTLINK_UPDATE_TEST_RECORDS="$records" \
    VAULTLINK_UPDATE_TEST_VERSION="${VAULTLINK_UPDATE_TEST_VERSION:-0.5.2}" \
    VAULTLINK_UPDATE_TEST_EFFECTIVE_URL="${VAULTLINK_UPDATE_TEST_EFFECTIVE_URL:-}" \
    VAULTLINK_UPDATE_TEST_FAIL_ASSET="${VAULTLINK_UPDATE_TEST_FAIL_ASSET:-}" \
    VAULTLINK_UPDATE_TEST_SERVICE_ACTIVE="${VAULTLINK_UPDATE_TEST_SERVICE_ACTIVE:-1}" \
        "$updater" "$@"
}

VAULTLINK_UPDATE_TEST_VERSION=0.5.1 run_updater check \
    >"$test_root/current.stdout"
grep -F -x -q 'update_available=false' "$test_root/current.stdout"
[ ! -e "$records/version" ] || fail "a current release invoked the upgrade helper"

run_updater check >"$test_root/check.stdout"
grep -F -x -q 'installed_version=0.5.1' "$test_root/check.stdout"
grep -F -x -q 'latest_version=0.5.2' "$test_root/check.stdout"
grep -F -x -q 'update_available=true' "$test_root/check.stdout"
[ ! -e "$records/version" ] || fail "check mode invoked the upgrade helper"

printf '%s\n' 'auto_install=false' >/etc/vaultlink/update.conf
chown root:root /etc/vaultlink/update.conf
chmod 0644 /etc/vaultlink/update.conf
run_updater auto >"$test_root/auto-disabled.stdout"
grep -F -x -q 'auto_install=false' "$test_root/auto-disabled.stdout"
[ ! -e "$records/version" ] || fail "disabled automatic updates invoked the upgrade helper"
chmod 0666 /etc/vaultlink/update.conf
expect_failure writable-config run_updater auto
chmod 0644 /etc/vaultlink/update.conf
[ ! -e "$records/version" ] || fail "a writable update configuration invoked the upgrade helper"
printf '%s\n' 'auto_install=true' 'unknown_setting=true' >/etc/vaultlink/update.conf
expect_failure unknown-config run_updater auto
printf '%s\n' 'auto_install=false' >/etc/vaultlink/update.conf
[ ! -e "$records/version" ] || fail "an unknown update setting invoked the upgrade helper"

VAULTLINK_UPDATE_TEST_EFFECTIVE_URL=https://example.test/releases/tag/v0.5.2 \
    expect_failure wrong-repository run_updater check
VAULTLINK_UPDATE_TEST_EFFECTIVE_URL=https://github.com/alexhaberl/VaultLink/releases/tag/v0.5.2-rc.1 \
    expect_failure prerelease run_updater check
VAULTLINK_UPDATE_TEST_VERSION=0.5.0 run_updater install \
    >"$test_root/downgrade.stdout"
grep -F -x -q 'update_available=false' "$test_root/downgrade.stdout"
[ ! -e "$records/version" ] || fail "a downgrade invoked the upgrade helper"

cp -R "$assets" "$test_root/tampered-assets"
printf '%s\n' tampered >>"$test_root/tampered-assets/VaultLink-0.5.2-debian13-$architecture.tar.gz"
VAULTLINK_UPDATE_TEST_ASSETS="$test_root/tampered-assets" \
    expect_failure tampered-archive run_updater install
[ ! -e "$records/version" ] || fail "a tampered archive invoked the upgrade helper"

cp -R "$assets" "$test_root/forged-checksum-assets"
printf '%064d  %s\n' 0 "VaultLink-0.5.2-debian13-$architecture.tar.gz" \
    >"$test_root/forged-checksum-assets/SHA256SUMS-$architecture"
rm -f "$test_root/forged-checksum-assets/SHA256SUMS-$architecture.minisig"
minisign -S -q -s "$test_root/minisign.key" \
    -m "$test_root/forged-checksum-assets/SHA256SUMS-$architecture" \
    -x "$test_root/forged-checksum-assets/SHA256SUMS-$architecture.minisig"
VAULTLINK_UPDATE_TEST_ASSETS="$test_root/forged-checksum-assets" \
    expect_failure forged-checksum run_updater install
[ ! -e "$records/version" ] || fail "a forged checksum invoked the upgrade helper"

VAULTLINK_UPDATE_TEST_FAIL_ASSET="SHA256SUMS-$architecture.minisig" \
    expect_failure missing-signature run_updater install
[ ! -e "$records/version" ] || fail "missing release evidence invoked the upgrade helper"

unsafe_assets="$test_root/unsafe-assets"
unsafe_build="$test_root/unsafe-build"
unsafe_root="VaultLink-0.5.2-debian13-$architecture"
install -d "$unsafe_assets" "$unsafe_build/$unsafe_root/bin" \
    "$unsafe_build/$unsafe_root/deploy"
ln -s /bin/true "$unsafe_build/$unsafe_root/bin/vaultlink"
cp /usr/share/vaultlink/minisign.pub "$unsafe_build/$unsafe_root/minisign.pub"
cp "$test_root/build-0.5.2-0.5.2/$unsafe_root/deploy/vaultlink-upgrade.sh" \
    "$unsafe_build/$unsafe_root/deploy/vaultlink-upgrade.sh"
(
    cd "$unsafe_build"
    tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
        -czf "$unsafe_assets/$unsafe_root.tar.gz" "$unsafe_root"
)
(
    cd "$unsafe_assets"
    sha256sum "$unsafe_root.tar.gz" >"SHA256SUMS-$architecture"
)
minisign -S -q -s "$test_root/minisign.key" \
    -m "$unsafe_assets/$unsafe_root.tar.gz" \
    -x "$unsafe_assets/$unsafe_root.tar.gz.minisig"
minisign -S -q -s "$test_root/minisign.key" \
    -m "$unsafe_assets/SHA256SUMS-$architecture" \
    -x "$unsafe_assets/SHA256SUMS-$architecture.minisig"
VAULTLINK_UPDATE_TEST_ASSETS="$unsafe_assets" \
    expect_failure linked-archive-entry run_updater install
[ ! -e "$records/version" ] || fail "an archive link invoked the upgrade helper"

mismatched_assets="$test_root/mismatched-key-assets"
mismatched_root="VaultLink-0.5.2-debian13-$architecture"
cp -R "$test_root/build-0.5.2-0.5.2/$mismatched_root" \
    "$test_root/$mismatched_root"
minisign -G -W -p "$test_root/other-minisign.pub" \
    -s "$test_root/other-minisign.key" >/dev/null
cp "$test_root/other-minisign.pub" "$test_root/$mismatched_root/minisign.pub"
install -d "$mismatched_assets"
(
    cd "$test_root"
    tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
        -czf "$mismatched_assets/$mismatched_root.tar.gz" "$mismatched_root"
)
rm -rf -- "${test_root:?}/${mismatched_root:?}"
(
    cd "$mismatched_assets"
    sha256sum "$mismatched_root.tar.gz" >"SHA256SUMS-$architecture"
)
minisign -S -q -s "$test_root/minisign.key" \
    -m "$mismatched_assets/$mismatched_root.tar.gz" \
    -x "$mismatched_assets/$mismatched_root.tar.gz.minisig"
minisign -S -q -s "$test_root/minisign.key" \
    -m "$mismatched_assets/SHA256SUMS-$architecture" \
    -x "$mismatched_assets/SHA256SUMS-$architecture.minisig"
VAULTLINK_UPDATE_TEST_ASSETS="$mismatched_assets" \
    expect_failure mismatched-public-key run_updater install
[ ! -e "$records/version" ] || fail "a replacement public key invoked the upgrade helper"

printf '%s\n' 'auto_install=true' >/etc/vaultlink/update.conf
VAULTLINK_UPDATE_TEST_SERVICE_ACTIVE=0 \
    expect_failure inactive-service run_updater auto
[ ! -e "$records/version" ] || fail "an inactive service was updated automatically"
run_updater auto >"$test_root/auto-install.stdout"
grep -F -x -q 'update_installed=true' "$test_root/auto-install.stdout"
grep -F -x -q 'backup_directory=/var/lib/vaultlink-backups/update-safety-test' \
    "$test_root/auto-install.stdout"
[ "$(cat "$records/version")" = 0.5.2 ] \
    || fail "the verified candidate version was not passed to the upgrade helper"
[ "$(cat "$records/config")" = /etc/vaultlink/config.toml ] \
    || fail "the live configuration was not preserved"

echo "VaultLink signed update safety tests passed ($architecture)"
