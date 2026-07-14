#!/bin/sh
set -eu

fail() {
    echo "deployment asset check failed: $*" >&2
    exit 1
}

toml_integer() {
    config=$1
    key=$2
    values=$(sed -n "s/^${key} = \([0-9][0-9]*\)$/\1/p" "$config")
    [ "$(printf '%s\n' "$values" | grep -c .)" -eq 1 ] \
        || fail "$config must define $key exactly once as an integer"
    printf '%s\n' "$values"
}

check_sample_limits() {
    config=$1
    expected_upload=$2
    [ "$(toml_integer "$config" max_upload_size)" = "$expected_upload" ] \
        || fail "$config has a non-decimal max_upload_size default"
    [ "$(toml_integer "$config" max_zip_size)" = 1000000000 ] \
        || fail "$config has a non-decimal max_zip_size default"
    [ "$(toml_integer "$config" max_preview_size)" = 1000000 ] \
        || fail "$config has a non-decimal max_preview_size default"
    [ "$(toml_integer "$config" max_media_preview_size)" = 100000000 ] \
        || fail "$config has a non-decimal max_media_preview_size default"
}

check_sample_limits config/development.toml 100000000
for config in \
    config/production-reverse-proxy.toml \
    config/production-standalone-letsencrypt.toml \
    config/production-standalone-tls.toml; do
    check_sample_limits "$config" 1000000000
done

caddy_limits=$(sed -n 's/^[[:space:]]*max_size[[:space:]][[:space:]]*\([^[:space:]][^[:space:]]*\)[[:space:]]*$/\1/p' deploy/Caddyfile)
[ "$caddy_limits" = 1002MB ] \
    || fail "deploy/Caddyfile must reserve multipart overhead above the 1GB payload sample"
caddy_megabytes=${caddy_limits%MB}
caddy_bytes=$((caddy_megabytes * 1000000))
sample_payload=$(toml_integer config/production-reverse-proxy.toml max_upload_size)
multipart_reserve=1048576
[ "$caddy_bytes" -gt $((sample_payload + multipart_reserve)) ] \
    || fail "deploy/Caddyfile request-body cap must exceed payload plus the 1MiB multipart reserve"

for removed_asset in \
    deploy/vaultlink-staging-deploy.sh \
    deploy/vaultlink-cert-deploy.sh \
    deploy/vaultlink-cert-renew.service \
    deploy/vaultlink-cert-renew.timer; do
    [ ! -e "$removed_asset" ] || fail "$removed_asset is a removed legacy component"
done

test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT HUP INT TERM
mock_bin="$test_root/bin"
trace="$test_root/trace"
output="$test_root/output"
fixture_storage="$test_root/storage/shared"
mkdir "$mock_bin"
mkdir -p "$fixture_storage"
for command in install truncate chown chmod; do
    mock="$mock_bin/$command"
    # These variables belong to the generated mock and must not expand here.
    # shellcheck disable=SC2016
    printf '%s\n' \
        '#!/bin/sh' \
        'set -eu' \
        'printf "%s" "${0##*/}" >>"$TRACE_FILE"' \
        'for argument do printf " <%s>" "$argument" >>"$TRACE_FILE"; done' \
        'printf "\n" >>"$TRACE_FILE"' \
        >"$mock"
    if [ "$command" = chmod ]; then
        # Preserve the real mode transition so the published root can be
        # verified in addition to checking the privileged command trace.
        # shellcheck disable=SC2016
        printf '%s\n' '[ "$1" != 0750 ] || command -p chmod "$@"' >>"$mock"
    fi
    chmod 0755 "$mock"
done

TRACE_FILE="$trace" PATH="$mock_bin:$PATH" \
    sh tools/prepare-load-fixture.sh "$fixture_storage" >"$output"
grep -E -x -q \
    "chown <vaultlink:vaultlink> <$fixture_storage/\.vaultlink-load\.[A-Za-z0-9]+>" \
    "$trace" || fail "load fixture does not assign the published root to the VaultLink service"
grep -E -x -q \
    "chmod <0750> <$fixture_storage/\.vaultlink-load\.[A-Za-z0-9]+>" \
    "$trace" || fail "load fixture does not make the published root traversable by VaultLink"
grep -E -x -q \
    "install <-d> <-o> <vaultlink> <-g> <vaultlink> <-m> <0750> <$fixture_storage/\.vaultlink-load\.[A-Za-z0-9]+/uploads>" \
    "$trace" || fail "load fixture does not stage its upload directory below the configured SecureRoot"
grep -E -x -q \
    "truncate <-s> <50G> <$fixture_storage/\.vaultlink-load\.[A-Za-z0-9]+/sparse-50GiB\.bin>" \
    "$trace" || fail "load fixture does not stage its sparse download below the configured SecureRoot"
[ -d "$fixture_storage/vaultlink-load" ] || \
    fail "load fixture was not atomically published below the configured SecureRoot"
[ "$(stat -c '%a' "$fixture_storage/vaultlink-load")" = 750 ] || \
    fail "published load fixture root is not traversable with mode 0750"
grep -F -x -q \
    'Create a download share for vaultlink-load/sparse-50GiB.bin and an upload share for vaultlink-load/uploads.' \
    "$output" || fail "load fixture prints incorrect SecureRoot-relative share paths"

if TRACE_FILE="$trace" PATH="$mock_bin:$PATH" \
    sh tools/prepare-load-fixture.sh relative/path >"$output" 2>&1; then
    fail "load fixture accepted a relative storage root"
fi
if TRACE_FILE="$trace" PATH="$mock_bin:$PATH" \
    sh tools/prepare-load-fixture.sh / >"$output" 2>&1; then
    fail "load fixture accepted the filesystem root"
fi
if TRACE_FILE="$trace" PATH="$mock_bin:$PATH" \
    sh tools/prepare-load-fixture.sh "$test_root/missing" >"$output" 2>&1; then
    fail "load fixture accepted a missing storage root"
fi

ln -s / "$test_root/root-link"
if TRACE_FILE="$trace" PATH="$mock_bin:$PATH" \
    sh tools/prepare-load-fixture.sh "$test_root/root-link" >"$output" 2>&1; then
    fail "load fixture accepted a storage root resolving to the filesystem root"
fi

symlink_storage="$test_root/symlink-storage"
mkdir "$symlink_storage"
ln -s / "$symlink_storage/vaultlink-load"
if TRACE_FILE="$trace" PATH="$mock_bin:$PATH" \
    sh tools/prepare-load-fixture.sh "$symlink_storage" >"$output" 2>&1; then
    fail "load fixture followed a pre-positioned fixture symlink"
fi

echo "Deployment asset checks passed"
