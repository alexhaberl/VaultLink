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

for update_asset in \
    deploy/vaultlink-update.sh \
    deploy/vaultlink-update.conf.example \
    deploy/vaultlink-update.service \
    deploy/vaultlink-update.timer \
    deploy/docker/update-safety-test.sh; do
    [ -f "$update_asset" ] || fail "$update_asset is missing"
done
[ "$(sed -n 's/^auto_install=//p' deploy/vaultlink-update.conf.example)" = false ] \
    || fail "automatic release installation must be opt-in"
grep -F -x -q 'repository=alexhaberl/VaultLink' deploy/vaultlink-update.sh \
    || fail "the updater repository must be fixed"
grep -F -x -q 'public_key=/usr/share/vaultlink/minisign.pub' deploy/vaultlink-update.sh \
    || fail "the updater trust key path must be fixed"
grep -F -q "minisign -V -q -p \"\$public_key\"" deploy/vaultlink-update.sh \
    || fail "the updater must verify release assets with the pinned Minisign key"
grep -F -x -q 'ExecStart=/usr/local/sbin/vaultlink-update auto' deploy/vaultlink-update.service \
    || fail "the update service must use the configured automatic mode"
grep -F -x -q 'Persistent=true' deploy/vaultlink-update.timer \
    || fail "the signed update timer must retain missed checks"

helper=tools/prepare-load-fixture.sh
grep -F -q '/usr/bin/env -i' "$helper" \
    || fail "load fixture root phase must clear the caller environment"
grep -F -q '/usr/sbin/runuser -u vaultlink' "$helper" \
    || fail "load fixture root phase must re-exec as vaultlink"
grep -F -q '/usr/bin/mv -T -n --' "$helper" \
    || fail "load fixture publish must be atomic and collision-safe"
if grep -E -q '(^|[[:space:]/])(chown|install)([[:space:]]|$)' "$helper"; then
    fail "load fixture must not use privileged ownership-changing helpers"
fi

# The container gate has a real vaultlink account and root privileges, so it
# also exercises UID transitions and deterministic symlink interleavings. A
# developer-side policy check remains useful on systems without either.
if [ "$(id -u)" -eq 0 ] && id vaultlink >/dev/null 2>&1 \
    && command -v strace >/dev/null 2>&1; then
    sh deploy/docker/load-fixture-smoke.sh
fi

if [ "$(uname -s)" = Linux ]; then
    sh deploy/docker/soak-evidence-smoke.sh
else
    echo "Skipping Linux-only soak evidence smoke on $(uname -s)"
fi

echo "Deployment asset checks passed"
