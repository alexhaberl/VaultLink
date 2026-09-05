#!/bin/sh
# This policy intentionally searches for literal shell/YAML expressions.
# shellcheck disable=SC2016
set -eu

fail=0

report() {
    echo "supply-chain policy: $*" >&2
    fail=1
}

check_audit_refresh_build() {
    audit_build_workflow=$1
    audit_build_recipe=$2
    audit_expected_arg_count=$3
    shift 3

    [ -f "$audit_build_workflow" ] || return
    audit_build_count=$(awk '
        $0 !~ /^[[:space:]]*#/ {
            line = $0
            sub(/^[[:space:]]*/, "", line)
            sub(/[[:space:]]*$/, "", line)
            if (line == "docker buildx build " sprintf("%c", 92)) count++
        }
        END { print count + 0 }
    ' "$audit_build_workflow")
    audit_build_invocation_count=$(awk '
        $0 !~ /^[[:space:]]*#/ {
            line = $0
            while (match(line, /docker[[:space:]]+buildx[[:space:]]+build([[:space:]]|$)/)) {
                count++
                line = substr(line, RSTART + RLENGTH)
            }
        }
        END { print count + 0 }
    ' "$audit_build_workflow")
    audit_file_arg_count=$(awk '
        $0 !~ /^[[:space:]]*#/ {
            line = $0
            count += gsub(/--file/, "", line)
        }
        END { print count + 0 }
    ' "$audit_build_workflow")
    audit_expected_file_count=$(awk -v recipe="$audit_build_recipe" '
        $0 !~ /^[[:space:]]*#/ {
            line = $0
            sub(/^[[:space:]]*/, "", line)
            sub(/[[:space:]]*$/, "", line)
            expected = "--file " recipe " " sprintf("%c", 92)
            if (line == expected) count++
        }
        END { print count + 0 }
    ' "$audit_build_workflow")
    audit_short_file_count=$(awk '
        $0 !~ /^[[:space:]]*#/ {
            line = $0
            sub(/^[[:space:]]*/, "", line)
            sub(/[[:space:]]*$/, "", line)
            if (line == "docker buildx build " sprintf("%c", 92)) in_build = 1
            if (in_build && line ~ /(^|[[:space:]])-f/) count++
            if (in_build && substr(line, length(line), 1) != sprintf("%c", 92)) in_build = 0
        }
        END { print count + 0 }
    ' "$audit_build_workflow")
    audit_build_arg_count=$(awk '
        $0 !~ /^[[:space:]]*#/ {
            line = $0
            count += gsub(/--build-arg/, "", line)
        }
        END { print count + 0 }
    ' "$audit_build_workflow")
    audit_alternate_frontend_count=$(awk '
        $0 !~ /^[[:space:]]*#/ \
            && ($0 ~ /^[[:space:]]*buildctl([[:space:]]|$)/ \
                || $0 ~ /^[[:space:]]*docker[[:space:]]+buildx[[:space:]]+bake([[:space:]]|$)/ \
                || $0 ~ /^[[:space:]]*docker[[:space:]]+build([[:space:]]|$)/ \
                || $0 ~ /^[[:space:]]*docker[[:space:]]+builder[[:space:]]+build([[:space:]]|$)/ \
                || $0 ~ /^[[:space:]]*docker[[:space:]]+image[[:space:]]+build([[:space:]]|$)/) {
                count++
            }
        END { print count + 0 }
    ' "$audit_build_workflow")

    if [ "$audit_build_count" -ne 1 ] \
        || [ "$audit_build_invocation_count" -ne 1 ] \
        || [ "$audit_file_arg_count" -ne 1 ] \
        || [ "$audit_expected_file_count" -ne 1 ] \
        || [ "$audit_short_file_count" -ne 0 ] \
        || [ "$audit_build_arg_count" -ne "$audit_expected_arg_count" ] \
        || [ "$audit_alternate_frontend_count" -ne 0 ]; then
        report "$audit_build_workflow must have one buildx build bound to $audit_build_recipe and its exact build-argument allowlist"
        return
    fi
    for audit_expected_arg in "$@"; do
        if [ "$(awk -v argument="$audit_expected_arg" '
            $0 !~ /^[[:space:]]*#/ {
                line = $0
                sub(/^[[:space:]]*/, "", line)
                sub(/[[:space:]]*$/, "", line)
                expected = "--build-arg \"" argument "=$" argument "\" " sprintf("%c", 92)
                if (line == expected) count++
            }
            END { print count + 0 }
        ' "$audit_build_workflow")" -ne 1 ]; then
            report "$audit_build_workflow must pass exactly the reviewed $audit_expected_arg build argument"
        fi
    done
}

check_audit_remediation_policy() {
    audit_root=$1
    audit_ci="$audit_root/.github/workflows/ci.yml"
    audit_frontend='docker.io/docker/dockerfile:1.7.1@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e'
    audit_frontend_line="# syntax=$audit_frontend"
    audit_package_builder="$audit_root/deploy/docker/Dockerfile.package-builder"
    audit_qemu_builder="$audit_root/deploy/docker/Dockerfile.qemu-runner"
    audit_vm_builder="$audit_root/deploy/docker/Dockerfile.distro-vm-image"

    for audit_dockerfile in \
        "$audit_package_builder" "$audit_qemu_builder" "$audit_vm_builder"; do
        if [ ! -f "$audit_dockerfile" ] || [ -L "$audit_dockerfile" ]; then
            report "release Dockerfile is missing or unsafe: $audit_dockerfile"
            continue
        fi
        if [ "$(sed -n '1p' "$audit_dockerfile")" != "$audit_frontend_line" ]; then
            report "$audit_dockerfile must use the reviewed immutable Dockerfile frontend as its exact first line"
        fi
        if [ "$(grep -E -i -c '^[[:space:]]*#[[:space:]]*syntax[[:space:]]*=' \
                "$audit_dockerfile" || true)" -ne 1 ]; then
            report "$audit_dockerfile must contain exactly one Dockerfile syntax directive"
        fi
    done
    for audit_dockerfile in "$audit_root"/deploy/docker/Dockerfile*; do
        if [ -L "$audit_dockerfile" ]; then
            report "release Dockerfile symlinks are not allowed: $audit_dockerfile"
            continue
        fi
        [ -f "$audit_dockerfile" ] || continue
        if grep -E -i -q '^[[:space:]]*#[[:space:]]*syntax[[:space:]]*=' \
                "$audit_dockerfile"; then
            case "$audit_dockerfile" in
                "$audit_package_builder"|"$audit_qemu_builder"|"$audit_vm_builder") ;;
                *) report "unreviewed Dockerfile frontend directive in $audit_dockerfile" ;;
            esac
        fi
    done

    for audit_workflow in \
        "$audit_root/.github/workflows/package-builders-refresh.yml" \
        "$audit_root/.github/workflows/qemu-runner-refresh.yml" \
        "$audit_root/.github/workflows/distro-vm-images-refresh.yml"; do
        if [ ! -f "$audit_workflow" ]; then
            report "$audit_workflow must exist"
        fi
    done
    for audit_workflow in "$audit_root"/.github/workflows/*; do
        [ -f "$audit_workflow" ] || continue
        if grep -E -i -q 'BUILDKIT[[:space:]_-]*SYNTAX' "$audit_workflow"; then
            report "$audit_workflow must not override the Dockerfile frontend"
        fi
    done

    check_audit_refresh_build \
        "$audit_root/.github/workflows/package-builders-refresh.yml" \
        deploy/docker/Dockerfile.package-builder 5 \
        BASE_IMAGE TARGET_ID DISTRIBUTION DISTRIBUTION_VERSION ARCH_SNAPSHOT_DATE
    check_audit_refresh_build \
        "$audit_root/.github/workflows/qemu-runner-refresh.yml" \
        deploy/docker/Dockerfile.qemu-runner 1 BASE_IMAGE
    check_audit_refresh_build \
        "$audit_root/.github/workflows/distro-vm-images-refresh.yml" \
        deploy/docker/Dockerfile.distro-vm-image 2 TARGET_ID UPSTREAM_SHA256

    if ! awk '
        $0 == "permissions:" { in_permissions = 1; blocks++; next }
        in_permissions && /^[^[:space:]]/ { in_permissions = 0 }
        in_permissions && $0 == "  contents: read" { contents_read++ }
        in_permissions && $0 !~ /^[[:space:]]*$/ && $0 != "  contents: read" {
            unexpected = 1
        }
        END { exit !(blocks == 1 && contents_read == 1 && unexpected == 0) }
    ' "$audit_ci"; then
        report "CI workflow permissions must default to contents: read only"
    fi
    if grep -E -q 'permissions:[[:space:]]*write-all' "$audit_ci" \
        || [ "$(grep -E -c '^[[:space:]]*statuses[[:space:]]*:' "$audit_ci" || true)" -ne 1 ] \
        || ! awk '
            $0 == "  publish_native_gates:" { in_gate = 1; gates++; next }
            in_gate && /^  [A-Za-z0-9_-]+:$/ { in_gate = 0 }
            in_gate && $0 == "    if: ${{ always() && github.event_name == '\''push'\'' }}" {
                push_only++
            }
            in_gate && $0 == "    permissions:" { in_permissions = 1; blocks++; next }
            in_gate && in_permissions && /^    [^[:space:]]/ { in_permissions = 0 }
            in_gate && in_permissions && $0 == "      statuses: write" { statuses_write++ }
            in_gate && in_permissions && $0 !~ /^[[:space:]]*$/ \
                && $0 != "      statuses: write" { unexpected = 1 }
            END {
                exit !(gates == 1 && push_only == 1 && blocks == 1 \
                    && statuses_write == 1 && unexpected == 0)
            }
        ' "$audit_ci"; then
        report "only the push-only native gate publisher may receive statuses: write"
    fi

    audit_native_job=$(awk '
        $0 == "  native:" { selected = 1 }
        selected && /^  [A-Za-z0-9_-]+:$/ && $0 != "  native:" { exit }
        selected { print }
    ' "$audit_ci")
    audit_native_step_count=$(printf '%s\n' "$audit_native_job" | awk '
        $0 !~ /^[[:space:]]*#/ \
            && $0 ~ /^[[:space:]]*-[[:space:]]+name:[[:space:]]+Parse release Dockerfiles with the pinned frontend[[:space:]]*$/ {
                count++
            }
        END { print count + 0 }
    ')
    audit_native_parse_count=$(printf '%s\n' "$audit_native_job" | awk '
        $0 !~ /^[[:space:]]*#/ \
            && $0 ~ /^[[:space:]]*docker buildx build --call=targets --file deploy\/docker\/Dockerfile\.[A-Za-z0-9_-]+ \.[[:space:]]*$/ {
                count++
            }
        END { print count + 0 }
    ')
    if [ "$audit_native_step_count" -ne 1 ] \
        || [ "$audit_native_parse_count" -ne 3 ]; then
        report "both native CI architectures must parse the release Dockerfiles with the pinned frontend"
    fi
    for audit_recipe in \
        Dockerfile.package-builder Dockerfile.qemu-runner Dockerfile.distro-vm-image; do
        if [ "$(printf '%s\n' "$audit_native_job" | awk -v recipe="deploy/docker/$audit_recipe" '
            $0 !~ /^[[:space:]]*#/ {
                line = $0
                sub(/^[[:space:]]*/, "", line)
                sub(/[[:space:]]*$/, "", line)
                if (line == "docker buildx build --call=targets --file " recipe " .") count++
            }
            END { print count + 0 }
        ')" -ne 1 ]; then
            report "native CI frontend parse is missing deploy/docker/$audit_recipe"
        fi
    done

    if ! grep -F -q 'Open `http://127.0.0.1:8090/#token=...` locally.' \
            "$audit_root/README.md" \
        || grep -F -q '?token=' "$audit_root/README.md" \
        || ! grep -F -q 'http://127.0.0.1:{port}/#token={token}' \
            "$audit_root/src/setup/routes.rs" \
        || ! grep -F -q 'new URLSearchParams(location.hash.slice(1))' \
            "$audit_root/assets/web/setup.js"; then
        report "setup documentation and implementation must use the URL fragment token"
    fi
}

if [ "${1:-}" = --audit-remediation-fixture ]; then
    if [ "$#" -ne 2 ] || [ ! -d "$2" ]; then
        echo "usage: $0 --audit-remediation-fixture ROOT" >&2
        exit 2
    fi
    check_audit_remediation_policy "$2"
    [ "$fail" -eq 0 ] || exit 1
    exit 0
fi

check_audit_remediation_policy .
if ! sh tools/test-audit-remediation-policy.sh; then
    report "audit-remediation policy negative tests failed"
fi

if ! sh tools/check-deployment-assets.sh; then
    report "deployment samples and legacy-component policy failed"
fi

if ! sh tools/check-cargo-duplicates.sh; then
    report "Cargo duplicate dependency policy failed"
fi

if ! sh tools/check-version-consistency.sh; then
    report "package, documentation, and health version policy failed"
fi
if ! python3 tools/check-release-state.py >/dev/null; then
    report "release-state and qualification policy failed"
fi
if ! grep -F -x -q 'release_version=$development_version' tools/check-version-consistency.sh \
    || ! grep -F -q 'tools/check-release-state.py --require-ready' \
        tools/check-version-consistency.sh \
    || ! grep -F -q 'tools/check-performance-evidence.py compare' \
        tools/check-version-consistency.sh \
    || ! grep -F -q -- '--baseline release/performance/baseline.json' \
        tools/check-version-consistency.sh \
    || ! grep -F -q -- '--candidate release/performance/candidate.json' \
        tools/check-version-consistency.sh; then
    report "candidate and tag version policy must use release-state and require complete qualification"
fi
if ! grep -F -q 'tools/check-version-consistency.sh --binary target/release/vaultlink' \
        .github/workflows/packages.yml \
    || ! grep -F -q 'tools/check-version-consistency.sh --release-candidate' \
        .github/workflows/soak-start.yml \
    || ! grep -F -q 'tools/check-version-consistency.sh --release-candidate' \
        .github/workflows/release.yml \
    || ! grep -F -q -- '--release-tag "$GITHUB_REF_NAME"' \
        .github/workflows/release.yml; then
    report "package, soak, candidate, and tag workflows must consume release-state and qualification through the version gate"
fi
if ! awk '
    $0 == "[profile.release]" { release_profile = 1; profiles++; next }
    /^\[/ { release_profile = 0 }
    release_profile && $0 == "panic = \"unwind\"" { unwind_settings++ }
    END { exit !(profiles == 1 && unwind_settings == 1) }
' Cargo.toml \
    || ! grep -F -q 'CatchPanicLayer::custom(web_panic_response)' src/web.rs \
    || ! grep -F -q 'CatchPanicLayer::custom(api_panic_response)' src/api.rs \
    || ! grep -F -q 'CatchPanicLayer::custom(setup_panic_response)' src/setup/routes.rs \
    || grep -R -F -q 'CatchPanicLayer::new()' src \
    || ! grep -F -q 'vaultlink::install_safe_panic_reporting();' src/server/runtime.rs \
    || ! grep -F -q 'Self::HttpRequestPanic => "http.request.panic"' src/internal_reporting.rs; then
    report "release builds must use panic=unwind and payload-blind HTTP panic boundaries"
fi
if ! grep -F -q 'sh tools/check-version-consistency.sh --binary target/debug/vaultlink' .github/workflows/ci.yml \
    || ! grep -F -q -- '--release-candidate' .github/workflows/release.yml \
    || ! grep -F -q -- "--release-tag \"\$GITHUB_REF_NAME\"" .github/workflows/release.yml; then
    report "CI, candidate preflight, and tag release must enforce their version modes"
fi

minisign_fixture=$(mktemp)
trap 'rm -f "$minisign_fixture"' EXIT HUP INT TERM
minisign_fixture_key=$(
    (printf Ed; dd if=/dev/zero bs=1 count=40 status=none) | base64 | tr -d '\n'
)
printf 'untrusted comment: minisign public key fixture\n%s\n' \
    "$minisign_fixture_key" >"$minisign_fixture"
if ! sh tools/check-minisign-public-key.sh "$minisign_fixture"; then
    report "valid 42-byte Minisign public-key fixture was rejected"
fi
printf 'untrusted comment: minisign public key fixture\n%s=\n' \
    "$minisign_fixture_key" >"$minisign_fixture"
if sh tools/check-minisign-public-key.sh "$minisign_fixture" >/dev/null 2>&1; then
    report "padded or wrong-length Minisign public-key fixture was accepted"
fi
rm -f "$minisign_fixture"
trap - EXIT HUP INT TERM

uses_lines=$(grep -R -n -E '^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]+' .github/workflows || true)
bad_uses=$(printf '%s\n' "$uses_lines" | grep -E -v 'uses:[[:space:]]+\./|@[0-9a-f]{40}([[:space:]]+#.*)?$' || true)
if [ -n "$bad_uses" ]; then
    printf '%s\n' "$bad_uses" >&2
    report "external actions must use a full 40-character commit SHA"
fi

actionlint_script=tools/run-actionlint.sh
if ! grep -F -x -q 'actionlint_version=1.7.12' "$actionlint_script" \
    || ! grep -F -x -q \
        '        actionlint_sha256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8' \
        "$actionlint_script" \
    || ! grep -F -x -q \
        '        actionlint_sha256=325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6' \
        "$actionlint_script" \
    || ! grep -F -q 'sha256sum -c -' "$actionlint_script" \
    || ! grep -F -x -q '"$work/actionlint" -shellcheck shellcheck' "$actionlint_script" \
    || [ "$(grep -F -c 'run: sh tools/run-actionlint.sh' .github/workflows/ci.yml || true)" -ne 1 ]; then
    report "native CI must run Actionlint 1.7.12 with the official amd64/arm64 archive checksums"
fi

web_assets_check=tools/check-web-assets.sh
css_linter=tools/lint-css.mjs
for web_asset in \
    assets/web/vaultlink.css \
    assets/web/app.js \
    assets/web/upload-queue.js \
    assets/web/setup.js \
    "$web_assets_check" \
    "$css_linter"; do
    if [ ! -f "$web_asset" ] || [ -L "$web_asset" ]; then
        report "embedded web asset or lint gate is missing or unsafe: $web_asset"
    fi
done
if ! grep -F -x -q '    node --check "$javascript_asset"' "$web_assets_check" \
    || ! grep -F -x -q 'node "$css_linter" "$asset_directory/vaultlink.css"' \
        "$web_assets_check" \
    || [ "$(grep -F -c 'run: sh tools/check-web-assets.sh' .github/workflows/ci.yml || true)" -ne 1 ] \
    || ! grep -F -x -q \
        'pub const STYLESHEET: &str = include_str!("../assets/web/vaultlink.css");' \
        src/ui.rs \
    || ! grep -F -q 'include_str!("../assets/web/upload-queue.js");' src/ui.rs \
    || ! grep -F -x -q \
        'const SETUP_JAVASCRIPT: &str = include_str!("../../assets/web/setup.js");' \
        src/setup/views.rs \
    || ! grep -F -x -q \
        'const APP_JAVASCRIPT: &str = include_str!("../../assets/web/app.js");' \
        src/web/rendering.rs \
    || grep -F -q 'r#"function closeActionDetails' src/web/rendering.rs; then
    report "native CI must syntax-check and CSS-lint the four include_str-bound web assets"
fi

if [ ! -f clippy.toml ] \
    || ! grep -F -x -q 'cognitive-complexity-threshold = 25' clippy.toml \
    || ! grep -F -x -q '#![warn(clippy::cognitive_complexity)]' src/lib.rs \
    || ! grep -F -x -q '#![warn(clippy::cognitive_complexity)]' src/main.rs \
    || ! grep -F -q 'python3 tools/test-architecture.py' .github/workflows/ci.yml \
    || ! grep -F -q 'python3 tools/check-architecture.py --root .' .github/workflows/ci.yml \
    || ! grep -F -q 'python3 tools/test-release-state.py' .github/workflows/ci.yml \
    || ! grep -F -q 'python3 tools/test-performance-evidence.py' .github/workflows/ci.yml \
    || ! grep -F -q 'python3 tools/test-refactoring-contracts.py' .github/workflows/ci.yml \
    || ! grep -F -q 'python3 tools/check-refactoring-contracts.py --root .' .github/workflows/ci.yml \
    || ! grep -F -q '$(MAKE) architecture-check performance-evidence-check refactoring-contracts-check' Makefile; then
    report "CI must enforce module/function/import architecture and cognitive-complexity policy"
fi

gitleaks_ignore=.gitleaksignore
gitleaks_script=tools/check-secrets.sh
ci_workflow=.github/workflows/ci.yml
gitleaks_fingerprints='a35aeccbffe926997ca69bd2b91ac340ec3af511:src/auth.rs:generic-api-key:375
ccbafdc3a8810e29ea2981f2ad65ac9673043aa9:src/auth.rs:generic-api-key:375'
if [ ! -f "$gitleaks_ignore" ]; then
    report "Gitleaks ignore file is missing"
else
    gitleaks_ignore_entries=$(grep -E -v '^[[:space:]]*(#|$)' "$gitleaks_ignore" || true)
    if [ "$(printf '%s\n' "$gitleaks_ignore_entries" | grep -c . || true)" -ne 2 ]; then
        report "Gitleaks ignore file must contain exactly the two reviewed RFC test-vector fingerprints"
    fi
    for fingerprint in $gitleaks_fingerprints; do
        if ! grep -F -x -q "$fingerprint" "$gitleaks_ignore"; then
            report "Gitleaks ignore file is missing reviewed fingerprint $fingerprint"
        fi
    done
fi
if ! grep -F -x -q 'expected_gitleaks_version=8.30.0' "$gitleaks_script" \
    || ! grep -F -q -- '--redact=100' "$gitleaks_script" \
    || ! grep -F -q -- '--max-decode-depth=5' "$gitleaks_script" \
    || ! grep -F -q -- '--max-archive-depth=2' "$gitleaks_script" \
    || ! grep -F -q -- '--log-opts="--all --full-history"' "$gitleaks_script"; then
    report "secret scan must use pinned Gitleaks with redacted full-history, decoding, and archive coverage"
fi
if ! grep -F -q 'fetch-depth: 0' "$ci_workflow" \
    || ! grep -F -q 'GITLEAKS_VERSION: 8.30.0' "$ci_workflow" \
    || ! grep -F -q 'GITLEAKS_SHA256: b4cbbb6ddf7d1b2a603088cd03a4e3f7ce48ee7fd449b51f7de6ee2906f5fa2f' "$ci_workflow" \
    || ! grep -F -q "GITLEAKS_BIN=\"\$work/gitleaks\" make secret-check" "$ci_workflow"; then
    report "native CI must run the checksum-pinned Gitleaks full-history gate"
fi
literal_dollar='$'
smoke_dockerfile=deploy/docker/Dockerfile.setup-smoke
snapshot_sources=deploy/docker/debian-snapshot.sources
package_lock=deploy/docker/debian-packages.lock
target_manifest=release/package-targets.json
package_builder=deploy/docker/Dockerfile.package-builder
qemu_builder=deploy/docker/Dockerfile.qemu-runner
vm_builder=deploy/docker/Dockerfile.distro-vm-image
qemu_lock=deploy/docker/qemu-runner-image.lock
qemu_base_lock=deploy/docker/qemu-runner-base-image.lock
qemu_packages_amd64=deploy/docker/qemu-runner-packages-amd64.lock
qemu_packages_arm64=deploy/docker/qemu-runner-packages-arm64.lock
qemu_verifier=tools/verify-qemu-runner.sh
qemu_acceleration_selector=tools/select-qemu-acceleration.sh
package_builder_dependencies=deploy/docker/install-package-builder-dependencies.sh
vm_provisioner=tools/provision-distro-vm-image.sh
package_workflow=.github/workflows/packages.yml
package_offline_smoke=tools/package-offline-smoke.sh
package_native_load_smoke=tools/package-native-load-smoke.sh
native_storage_qualification=tools/qualify-native-load-storage.py
direct_process_identity=tools/check-direct-process-identity.sh
real_package_smoke=tools/real-package-update-smoke.sh
vm_harness=tools/run-distro-vm-test.sh
vm_guest_smoke=tools/distro-vm-guest-smoke.sh
vm_runtime_smoke=tools/distro-vm-runtime-smoke.sh
load_test=tools/load-test.sh
api_smoke=deploy/docker/api-smoke.sh
vm_bootstrap_runcmd="  - [ /usr/local/sbin/vaultlink-vm-bootstrap, '\$tcg_cleanup_command' ]"

if ! python3 tools/package-targets.py validate --allow-unprovisioned >/dev/null; then
    report "the declarative nine-target package manifest is invalid even in bootstrap mode"
fi
if ! python3 tools/check-package-target-lock-policy.py; then
    report "package target bootstrap lock truth table failed"
fi
if [ "$(python3 tools/package-targets.py ids --allow-unprovisioned 2>/dev/null | wc -l)" -ne 9 ] \
    || [ "$(python3 tools/package-targets.py assets 0.7.0 --allow-unprovisioned 2>/dev/null | wc -l)" -ne 9 ]; then
    report "the package manifest must render exactly nine target IDs and nine unique 0.7.0 assets"
fi
if ! grep -F -q '"builder_image": "UNPROVISIONED"' "$target_manifest" \
    && ! grep -F -q '"vm_image": "UNPROVISIONED"' "$target_manifest"; then
    # Builder and VM output locks are independent all-nine atomic families.
    # Strict validation applies only when both families are fully provisioned.
    python3 tools/package-targets.py validate >/dev/null 2>&1 \
        || report "target pins must be either reviewed digests or explicit UNPROVISIONED bootstrap values"
fi
if ! grep -F -q 'image locks must be pinned or UNPROVISIONED' tools/package-targets.py \
    || ! grep -F -q 'pinned builder image without pinned inputs' tools/package-targets.py \
    || ! grep -F -q 'pinned VM image without pinned inputs' tools/package-targets.py \
    || ! grep -F -q 'pinned image without a pinned Arch snapshot' tools/package-targets.py \
    || ! grep -F -q 'pinned VM images require pinned QEMU runner supply-chain locks' \
        tools/package-targets.py; then
    report "builder and VM locks must remain independent all-nine atomic families with pinned inputs"
fi
if [ "$(wc -l <"$qemu_lock")" -ne 1 ]; then
    report "QEMU runner lock must contain exactly one line"
else
    qemu_image=$(sed -n '1p' "$qemu_lock")
    if [ "$qemu_image" != UNPROVISIONED ] \
        && ! printf '%s\n' "$qemu_image" \
            | grep -E -q '^ghcr\.io/alexhaberl/vaultlink-qemu-runner@sha256:[0-9a-f]{64}$'; then
        report "QEMU runner lock must be UNPROVISIONED or an immutable project GHCR digest"
    fi
fi
for qemu_supply_chain_lock in \
    "$qemu_base_lock" "$qemu_packages_amd64" "$qemu_packages_arm64"; do
    if [ ! -f "$qemu_supply_chain_lock" ] || [ -L "$qemu_supply_chain_lock" ]; then
        report "QEMU runner supply-chain lock is missing or unsafe: $qemu_supply_chain_lock"
    fi
done
if ! grep -F -q 'QEMU runner image, base, and both package closures must be pinned atomically' \
        tools/package-targets.py \
    || ! grep -F -q 'QEMU_RUNNER_BASE_LOCK' tools/package-targets.py \
    || ! grep -F -q 'QEMU_RUNNER_PACKAGE_LOCKS' tools/package-targets.py; then
    report "QEMU runner image, base, and both native package closures must be one atomic lock"
fi

if ! grep -E -q '^FROM[[:space:]]+rust:[^[:space:]]+@sha256:[0-9a-f]{64}$' "$smoke_dockerfile"; then
    report "canonical Docker smoke base must be digest-pinned"
fi
if ! grep -E -q '^ARG RUST_IMAGE=rust:[^[:space:]]+@sha256:[0-9a-f]{64}$' "$package_builder" \
    || ! grep -F -x -q 'FROM ${BASE_IMAGE}' "$package_builder" \
    || ! grep -F -x -q 'FROM ${BASE_IMAGE}' "$qemu_builder" \
    || ! grep -F -x -q 'FROM scratch' "$vm_builder"; then
    report "package-builder, QEMU-runner, and guest-image recipes must consume immutable refresh inputs"
fi
if grep -E -q '^COPY[[:space:]].*(Cargo|\.cargo|\.github|src|templates|assets|config|docs|fuzz|release/package-targets|packaging)' \
        "$package_builder" "$qemu_builder" "$vm_builder" \
    || ! grep -F -q 'install-package-builder-dependencies.sh' "$package_builder" \
    || ! grep -F -x -q 'COPY guest.qcow2 /images/guest.qcow2' "$vm_builder"; then
    report "builder and VM images must remain independent of VaultLink application source"
fi
if ! grep -F -q '/usr/local/share/vaultlink-builder-packages.lock' \
        "$package_builder_dependencies" \
    || ! grep -F -q 'builder_packages_sha256' tools/verify-package-builder.sh \
    || ! grep -F -q 'builder_base_image' tools/verify-package-builder.sh \
    || ! grep -F -x -q \
        'PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' \
        tools/verify-package-builder.sh \
    || ! grep -F -x -q \
        'RUSTUP_TOOLCHAIN="${expected_rust_version}-${expected_host}"' \
        tools/verify-package-builder.sh \
    || ! grep -F -x -q 'export RUSTUP_TOOLCHAIN' tools/verify-package-builder.sh \
    || ! grep -F -q 'rustc -vV' tools/verify-package-builder.sh \
    || ! grep -F -q 'cargo-audit cmp gh minisign readelf shellcheck ssh stat' tools/verify-package-builder.sh; then
    report "native package builders must attest their fixed toolchain, complete package closure, base digest, and Rust host"
fi
if ! grep -F -q 'test "${ID:-}" = ubuntu' "$qemu_builder" \
    || ! grep -F -q 'test "${VERSION_ID:-}" = 24.04' "$qemu_builder" \
    || ! grep -F -q 'cmp "$packages_lock" "$embedded_packages"' "$qemu_verifier" \
    || ! grep -F -q 'cmp "$packages_lock" "$work/live-packages.lock"' "$qemu_verifier" \
    || ! grep -F -q 'QEMU runner must use exactly Ubuntu 24.04' "$qemu_verifier"; then
    report "QEMU harness must bind Ubuntu 24.04, its base digest, and its live native package closure"
fi
if ! grep -F -q 'pacman -Syyuu --noconfirm --needed' "$package_builder_dependencies" \
    || ! grep -F -q 'pacman -Syyuu --noconfirm --needed' "$vm_provisioner" \
    || ! grep -F -q 'https://archive.archlinux.org/repos/{year}/{month}/{day}/$repo/os/$arch' "$target_manifest" \
    || ! grep -F -q 'arch_snapshot_path=$(printf' "$package_builder_dependencies" \
    || ! grep -F -q 'arch_snapshot_path=$(printf' "$vm_provisioner"; then
    report "Arch builder and guest provisioning must permit downgrades to the exact dated snapshot"
fi

for workflow in \
    .github/workflows/package-builders-refresh.yml \
    .github/workflows/qemu-runner-refresh.yml \
    .github/workflows/distro-vm-images-refresh.yml; do
    if ! grep -F -q 'workflow_dispatch:' "$workflow" \
        || grep -F -q 'pull_request:' "$workflow" \
        || grep -F -q '  push:' "$workflow" \
        || ! grep -F -q "github.ref == 'refs/heads/main'" "$workflow" \
        || ! grep -F -q 'environment: release-image-refresh' "$workflow" \
        || ! grep -F -q 'packages: write' "$workflow" \
        || ! grep -F -q -- '--provenance=false' "$workflow"; then
        report "$workflow must be a protected, manual, main-only immutable-image refresh"
    fi
done
buildkit_image='docker.io/moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8'
for refresh_workflow in \
    .github/workflows/package-builders-refresh.yml \
    .github/workflows/qemu-runner-refresh.yml \
    .github/workflows/distro-vm-images-refresh.yml; do
    if ! grep -F -x -q "  BUILDKIT_IMAGE: $buildkit_image" "$refresh_workflow" \
        || ! grep -F -q 'docker buildx create --driver docker-container' "$refresh_workflow" \
        || ! grep -F -q -- '--driver-opt "image=$BUILDKIT_IMAGE" --name "$builder" --use' "$refresh_workflow" \
        || ! grep -F -q 'docker buildx inspect --bootstrap' "$refresh_workflow" \
        || grep -F -q 'BUILDKIT_SYNTAX' "$refresh_workflow"; then
        report "$refresh_workflow must use the reviewed immutable BuildKit image and must not override the Dockerfile frontend"
    fi
done

if ! grep -F -q 'package-targets.py matrix --allow-unprovisioned' .github/workflows/package-builders-refresh.yml \
    || ! grep -F -q 'runs-on: ${{ matrix.runner }}' .github/workflows/package-builders-refresh.yml \
    || ! grep -F -q 'push-by-digest=true' .github/workflows/package-builders-refresh.yml \
    || ! grep -F -q "jq -r '.manifests[].platform" .github/workflows/package-builders-refresh.yml \
    || ! grep -F -q 'cmp platforms.expected platforms.actual' .github/workflows/package-builders-refresh.yml \
    || ! grep -F -q 'update-package-target-images.py' .github/workflows/package-builders-refresh.yml \
    || ! grep -F -q 'push-by-digest=true' .github/workflows/qemu-runner-refresh.yml \
    || ! grep -F -q 'qemu-runner-image.lock' .github/workflows/qemu-runner-refresh.yml \
    || ! grep -F -q 'qemu-runner-base-image.lock' .github/workflows/qemu-runner-refresh.yml \
    || ! grep -F -q 'qemu-runner-packages-amd64.lock' .github/workflows/qemu-runner-refresh.yml \
    || ! grep -F -q 'qemu-runner-packages-arm64.lock' .github/workflows/qemu-runner-refresh.yml \
    || ! grep -F -q 'sh tools/verify-qemu-runner.sh' .github/workflows/qemu-runner-refresh.yml \
    || ! grep -F -q 'update-package-target-images.py' .github/workflows/distro-vm-images-refresh.yml; then
    report "refresh workflows must build natively by digest and emit reviewed lock candidates"
fi
vm_refresh=.github/workflows/distro-vm-images-refresh.yml
if ! grep -F -q 'qemu_runner_refresh_run_id:' "$vm_refresh" \
    || ! grep -F -q 'actions: read' "$vm_refresh" \
    || ! grep -F -q 'test "$qemu_sha" = "$GITHUB_SHA"' "$vm_refresh" \
    || ! grep -F -q 'test "$qemu_branch" = main' "$vm_refresh" \
    || ! grep -F -q 'test "$qemu_conclusion" = success' "$vm_refresh" \
    || ! grep -F -q 'test "$qemu_path" = .github/workflows/qemu-runner-refresh.yml' "$vm_refresh" \
    || ! grep -F -q 'test "$qemu_event" = workflow_dispatch' "$vm_refresh" \
    || ! grep -F -q -- '--name "qemu-runner-lock-$QEMU_REFRESH_RUN"' "$vm_refresh" \
    || ! grep -F -q 'test "$QEMU_REFRESH_RUN" = 0' "$vm_refresh" \
    || ! grep -F -q 'test "$actual_qemu_locks_sha256" = "$QEMU_LOCKS_SHA256"' "$vm_refresh" \
    || ! grep -F -q 'sh tools/verify-qemu-runner.sh "$ARCHITECTURE" /qemu-lock' "$vm_refresh" \
    || grep -F -q 'inputs.qemu_runner_image' "$vm_refresh"; then
    report "VM refresh must bind a bootstrap QEMU lock artifact to one successful same-commit protected refresh, or use the committed lock"
fi
if ! grep -F -q 'actual_distribution=$(read_os_release_field ID)' "$package_builder_dependencies" \
    || ! grep -F -q 'actual_version=$(read_os_release_field VERSION_ID)' "$package_builder_dependencies" \
    || ! grep -F -q 'expected_distribution=$(manifest_value distribution)' tools/verify-package-builder.sh \
    || ! grep -F -q 'read_os_release_field VERSION_ID' tools/verify-package-builder.sh; then
    report "builder creation and use must bind the declared target to the live /etc/os-release identity"
fi
if ! grep -F -q 'package_targets.MANIFEST = args.input' tools/update-package-target-images.py \
    || ! grep -F -q -- '--input builder-lock/package-targets.json --require-complete' release/README.md \
    || ! grep -F -q '"qemu-lock/$lock"' release/README.md \
    || ! grep -F -q 'qemu-runner-base-image.lock' release/README.md \
    || ! grep -F -q 'qemu-runner-packages-amd64.lock' release/README.md \
    || ! grep -F -q 'qemu-runner-packages-arm64.lock' release/README.md \
    || ! grep -F -q 'exact successful QEMU refresh run ID' release/README.md \
    || ! grep -F -q '`qemu-runner-image.lock`,' docs/RELEASE-CHECKLIST-0.6.0.md \
    || ! grep -F -q '`qemu-runner-base-image.lock`, `qemu-runner-packages-amd64.lock`, and' docs/RELEASE-CHECKLIST-0.6.0.md \
    || ! grep -F -q '`qemu-runner-packages-arm64.lock` atomically' docs/RELEASE-CHECKLIST-0.6.0.md \
    || ! grep -F -q 'python3 tools/package-targets.py validate' release/README.md \
    || ! grep -F -q 'validate_qemu_runner_lock(allow_unprovisioned)' tools/package-targets.py \
    || ! grep -F -q 'MULTIARCH_BUILDERS' tools/package-targets.py; then
    report "the final pinning procedure must atomically validate the builder, all nine VMs, and QEMU runner"
fi

if [ "$(grep -E -c '^[[:space:]]+- (debian13|ubuntu2404|ubuntu2604|fedora44|archlinux)-(amd64|arm64)$' \
        .github/workflows/distro-vm-images-refresh.yml || true)" -ne 9 ]; then
    report "the VM refresh choice must enumerate the exact nine package targets"
fi

if [ "$(grep -E -c '^URIs: http://snapshot\.debian\.org/archive/debian(-security)?/[0-9]{8}T[0-9]{6}Z$' "$snapshot_sources" || true)" -ne 2 ] \
    || grep -E -q 'deb\.debian\.org' "$snapshot_sources"; then
    report "canonical Debian smoke sources must use immutable main and security snapshots"
fi
if ! awk '
    /^[[:space:]]*(#|$)/ { next }
    !/^[a-z0-9][a-z0-9+.-]*=[^[:space:]]+$/ { failed = 1 }
    {
        package = $0
        sub(/=.*/, "", package)
        if (seen[package]++) failed = 1
        if (previous != "" && package < previous) failed = 1
        previous = package
    }
    END { exit failed }
' "$package_lock"; then
    report "canonical Debian smoke package lock must be sorted, unique, and versioned"
fi
if ! grep -F -x -q 'inotify-tools=4.23.9.0-2+b1' "$package_lock" \
    || ! grep -F -x -q 'libinotifytools0=4.23.9.0-2+b1' "$package_lock" \
    || ! grep -F -q 'inotifywait --quiet --timeout 10' deploy/docker/load-fixture-smoke.sh; then
    report "root-helper race smoke must use the snapshot-pinned bounded inotify attacker"
fi
if ! grep -F -q 'tools/install-pinned-debian-packages.sh' "$smoke_dockerfile" \
    || ! grep -F -q 'debian-snapshot.sources' "$smoke_dockerfile" \
    || ! grep -F -q 'debian-packages.lock' "$smoke_dockerfile"; then
    report "canonical container must install the snapshot-locked Debian package closure"
fi
if ! grep -F -x -q 'USER vaultlink' "$smoke_dockerfile" \
    || ! grep -F -q 'id -u' deploy/docker/setup-smoke.sh \
    || ! grep -F -q 'Setup smoke must run as an unprivileged user' deploy/docker/setup-smoke.sh; then
    report "setup smoke container must execute as the vaultlink non-root user"
fi
if ! grep -F -q 'rm -f /etc/apt/sources.list' tools/install-pinned-debian-packages.sh \
    || ! grep -F -q "/etc/apt/sources.list.d" tools/install-pinned-debian-packages.sh \
    || ! grep -F -q 'source_count=' tools/install-pinned-debian-packages.sh \
    || ! grep -F -q "comm -13 \"\$manifest_work/before\" \"\$manifest_work/after\"" tools/install-pinned-debian-packages.sh \
    || ! grep -F -q "comm -23 \"\$manifest_work/changed\" \"\$manifest_work/locked\"" tools/install-pinned-debian-packages.sh; then
    report "pinned Debian installer must verify the sole snapshot and each base-image package delta"
fi
if grep -E -q '(apt-get|dnf|pacman)[[:space:]].*(update|install|-S)' \
        .github/workflows/packages.yml .github/workflows/reproducibility.yml \
        .github/workflows/release.yml .github/workflows/distro-vms.yml; then
    report "package, reproducibility, release, and VM jobs must not install mutable build tooling"
fi
for tool in 'cargo-cyclonedx --version 0.5.9' 'cargo-audit --version 0.22.2'; do
    grep -F -q "$tool" "$smoke_dockerfile" \
        || report "canonical container is missing pinned $tool"
    grep -F -q "$tool" "$package_builder" \
        || report "native package builder is missing pinned $tool"
done

audit_exception='--ignore RUSTSEC-2023-0071'
audit_commands=$(grep -R -h -E 'cargo audit .*--deny warnings' .github/workflows || true)
audit_exceptions=$(printf '%s\n' "$audit_commands" \
    | grep -o -E -- '--ignore[[:space:]]+RUSTSEC-[0-9-]+' | sort -u || true)
if [ "$(printf '%s\n' "$audit_commands" | grep -c . || true)" -ne 2 ] \
    || [ "$(printf '%s\n' "$audit_commands" | grep -F -c -- "$audit_exception" || true)" -ne 2 ] \
    || [ "$audit_exceptions" != "$audit_exception" ]; then
    report "RUSTSEC-2023-0071 must be the only explicit cargo-audit exception"
fi
if ! python3 - <<'PY'
import pathlib
import tomllib

packages = tomllib.loads(pathlib.Path("Cargo.lock").read_text(encoding="utf-8"))["package"]
by_name = {}
for package in packages:
    by_name.setdefault(package["name"], []).append(package)
assert len(by_name.get("rsa", [])) == 1
rsa = by_name["rsa"][0]
assert rsa["version"] == "0.9.10"
assert len(by_name.get("webauthn_rp", [])) == 1
webauthn = by_name["webauthn_rp"][0]
assert webauthn["version"] == "0.3.0"
assert "rsa" in webauthn.get("dependencies", [])
assert len(by_name.get("vaultlink", [])) == 1
assert "webauthn_rp" in by_name["vaultlink"][0].get("dependencies", [])
parents = sorted(
    package["name"]
    for package in packages
    if any(dependency.split(" ", 1)[0] == "rsa" for dependency in package.get("dependencies", []))
)
assert parents == ["webauthn_rp"]
PY
then
    report "RUSTSEC-2023-0071 must remain confined to vaultlink -> webauthn_rp 0.3.0 -> rsa 0.9.10"
fi
if [ "$(grep -F -c 'fn registration_never_advertises_the_unpatched_rs256_path()' src/webauthn.rs || true)" -ne 1 ] \
    || [ "$(grep -F -c 'fn authentication_rejects_persisted_rs256_credentials()' src/webauthn.rs || true)" -ne 1 ] \
    || ! grep -F -q 'remove(CoseAlgorithmIdentifier::Rs256)' src/webauthn.rs \
    || ! grep -F -q 'CompressedPubKey::Rsa(_)' src/webauthn.rs; then
    report "the RSA audit exception must retain registration and persisted/authentication RS256 negative tests"
fi

if ! grep -E -q '^COPY Cargo\.toml Cargo\.lock rust-toolchain\.toml Makefile clippy\.toml \.dockerignore \.gitleaksignore \./$' "$smoke_dockerfile" \
    || ! grep -F -x -q 'COPY .cargo ./.cargo' "$smoke_dockerfile" \
    || ! grep -F -x -q 'COPY .github ./.github' "$smoke_dockerfile" \
    || ! grep -F -x -q 'COPY deploy ./deploy' "$smoke_dockerfile" \
    || ! grep -F -x -q 'COPY packaging ./packaging' "$smoke_dockerfile" \
    || ! grep -F -x -q 'COPY release ./release' "$smoke_dockerfile" \
    || ! grep -F -x -q 'COPY tools ./tools' "$smoke_dockerfile"; then
    report "Docker smoke build must include package, release, policy, workflow, tool, and deployment assets"
fi
if ! grep -F -q 'shellcheck deploy/*.sh deploy/docker/*.sh packaging/*.sh tools/*.sh' "$smoke_dockerfile" \
    || ! grep -F -q 'sh tools/check-supply-chain-policy.sh' "$smoke_dockerfile"; then
    report "Docker smoke build must shellcheck package scripts and run the supply-chain policy"
fi
if ! grep -F -q 'install -m 0755 deploy/vaultlink-update.sh /usr/sbin/vaultlink-update' "$smoke_dockerfile" \
    || ! grep -F -q 'systemd-analyze verify deploy/vaultlink.service' "$smoke_dockerfile" \
    || ! grep -F -q 'deploy/vaultlink-update.service deploy/vaultlink-update.timer' "$smoke_dockerfile"; then
    report "Docker smoke build must provision and verify the package updater units"
fi
for smoke_contract in \
    "docker run --rm --network none --user root \$(DOCKER_SMOKE_IMAGE) sh deploy/docker/load-fixture-smoke.sh" \
    "docker run --rm --network none \$(DOCKER_SMOKE_IMAGE) sh deploy/docker/soak-evidence-smoke.sh" \
    "docker run --rm --network none --user root \$(DOCKER_SMOKE_IMAGE) sh deploy/docker/soak-remote-smoke.sh" \
    "docker run --rm --network none --user root \$(DOCKER_SMOKE_IMAGE) sh deploy/docker/update-safety-test.sh"; do
    grep -F -q "$smoke_contract" Makefile \
        || report "make docker-smoke is missing required offline gate: $smoke_contract"
done

updater=deploy/vaultlink-update.sh
if ! grep -F -x -q 'github_origin=https://github.com' "$updater" \
    || ! grep -F -x -q 'repository=alexhaberl/VaultLink' "$updater" \
    || ! grep -F -x -q 'install_method=/usr/share/vaultlink/install-method.env' "$updater" \
    || ! grep -F -x -q 'package_binary=/usr/lib/vaultlink/package/vaultlink' "$updater" \
    || ! grep -F -q -- "--proto '=https'" "$updater" \
    || ! grep -F -q 'SHA256SUMS.minisig' "$updater" \
    || [ "$(grep -F -c "minisign -V -q -p \"\$public_key\"" "$updater" || true)" -lt 2 ] \
    || ! grep -F -q 'verify_release_package "$installed_version"' "$updater" \
    || ! grep -F -q 'verify_release_package "$latest_version"' "$updater" \
    || ! grep -F -q 'package_dry_run "$new_package_file"' "$updater" \
    || ! grep -F -q 'package_install "$old_package_file" 1' "$updater" \
    || ! grep -F -q 'validate_installed_payload "$latest_version"' "$updater" \
    || ! grep -F -q 'cmp -s "$live_binary" "$package_binary"' "$updater" \
    || ! grep -F -q 'archive installations cannot be updated' "$updater" \
    || ! grep -F -q 'verified old package and signed evidence preserved at' "$updater"; then
    report "the updater must remain package-only, repository-bound, doubly signed, offline, and recoverable"
fi
if ! grep -F -q 'deb) dpkg --install' "$updater" \
    || ! grep -F -q 'rpm --nocontexts --upgrade' "$updater" \
    || grep -E -q 'rpm --(test |upgrade )' "$updater" \
    || ! grep -F -q 'pkg.tar.zst) pacman --upgrade' "$updater" \
    || ! grep -F -q 'auto_install=false' deploy/vaultlink-update.conf.example \
    || ! grep -F -x -q 'ConditionPathExists=/usr/share/vaultlink/install-method.env' deploy/vaultlink-update.service; then
    report "the updater must use each native package manager and remain opt-in/package-bound"
fi
update_service=deploy/vaultlink-update.service
update_capabilities='CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_SETGID CAP_SETUID'
if [ "$(grep -c '^NoNewPrivileges=' "$update_service" || true)" -ne 1 ] \
    || ! grep -F -x -q 'NoNewPrivileges=true' "$update_service" \
    || [ "$(grep -c '^CapabilityBoundingSet=' "$update_service" || true)" -ne 1 ] \
    || ! grep -F -x -q "CapabilityBoundingSet=$update_capabilities" "$update_service" \
    || [ "$(grep -c '^AmbientCapabilities=' "$update_service" || true)" -ne 1 ] \
    || ! grep -F -x -q "AmbientCapabilities=$update_capabilities" "$update_service" \
    || grep -q '^SecureBits=' "$update_service" \
    || grep -F -x -q 'NoNewPrivileges=false' "$update_service"; then
    report "the root update transaction must preserve only its bounded capabilities across exec while retaining no-new-privileges"
fi

arch_installer=packaging/vaultlink-package-install.sh
if ! grep -F -q '[ "$(id -u)" -eq 0 ]' "$arch_installer" \
    || ! grep -F -q "stat -c '%u:%g' \"\$0\"" "$arch_installer" \
    || ! grep -F -q 'exec 7>"$install_lock"' "$arch_installer" \
    || ! grep -F -q 'flock -n 7' "$arch_installer" \
    || ! grep -F -q 'exec 9>"$update_lock"' "$arch_installer" \
    || ! grep -F -q 'flock -n 9' "$arch_installer" \
    || ! grep -F -q 'exec 8>"$maintenance_lock"' "$arch_installer" \
    || ! grep -F -q 'flock -n 8' "$arch_installer" \
    || ! grep -F -q 'pacman -Q vaultlink' "$arch_installer" \
    || ! grep -F -q 'package archive inventory differs from the reviewed allowlist' "$arch_installer" \
    || ! grep -F -q 'installer does not belong to the selected signed package' "$arch_installer" \
    || ! grep -F -q 'initial_install_mode=reinstall' "$arch_installer" \
    || ! grep -F -q 'initial_install_mode=fresh' "$arch_installer" \
    || ! grep -F -q 'preinstall pkg.tar.zst arch rolling x86_64 vaultlink "$initial_install_mode"' "$arch_installer" \
    || ! grep -F -q 'pacman -U --noconfirm -- "$package_path"' "$arch_installer" \
    || ! grep -F -q 'installed package marker is invalid' "$arch_installer"; then
    report "Arch initial installation must use the package-embedded root/lock/preflight wrapper"
fi
if ! grep -F -q 'packaging/vaultlink-package-install.sh' tools/build-native-package.sh \
    || ! grep -F -q 'usr/bin/vaultlink-update' tools/build-native-package.sh \
    || ! grep -F -q "sed -i '/^usr\\/share\\/vaultlink\\/install-method.env\$/d'" tools/verify-native-package.sh \
    || ! grep -F -q 'usr/lib/vaultlink/package/deploy/vaultlink-package-install.sh' \
        tools/verify-native-package.sh \
    || ! grep -F -q 'vaultlink-package-install.sh "/var/tmp/$ASSET"' \
        tools/arch-rolling-compatibility.sh; then
    report "Arch package inventory, verifier, and rolling gate must enforce wrapper-only initial installation"
fi

toolchain_resolver_reference="channel=${literal_dollar}(sh tools/rust-toolchain-channel.sh)"
toolchain_output_value="${literal_dollar}{{ steps.rust_toolchain.outputs.channel }}"
safe_directory_reference="git config --global --add safe.directory \"${literal_dollar}GITHUB_WORKSPACE\""
publish_job=$(awk '
    $0 == "  publish:" { publish = 1 }
    publish && /^  [[:alnum:]_-]+:$/ && $0 != "  publish:" { exit }
    publish { print }
' .github/workflows/release.yml)
publish_container_value="${literal_dollar}{{ vars.VAULTLINK_PACKAGE_SIGNING_IMAGE }}"
if [ "$(printf '%s\n' "$publish_job" | grep -F -c "image: $publish_container_value" || true)" -ne 1 ] \
    || [ "$(printf '%s\n' "$publish_job" | grep -F -c "PACKAGE_SIGNING_IMAGE: $publish_container_value" || true)" -ne 1 ] \
    || ! printf '%s\n' "$publish_job" | grep -F -q 'environment: release-signing' \
    || ! printf '%s\n' "$publish_job" | grep -F -q 'contents: write' \
    || [ "$(printf '%s\n' "$publish_job" | grep -F -c 'RELEASE_ADMIN_READ_TOKEN: ${{ secrets.RELEASE_ADMIN_READ_TOKEN }}' || true)" -ne 2 ] \
    || [ "$(printf '%s\n' "$publish_job" | grep -F -c 'repos/$GITHUB_REPOSITORY/immutable-releases' || true)" -ne 2 ] \
    || ! printf '%s\n' "$publish_job" | grep -F -q 'test "$PACKAGE_SIGNING_IMAGE" = "$expected"' \
    || ! printf '%s\n' "$publish_job" | grep -F -q 'sh tools/verify-package-builder.sh debian13-amd64'; then
    report "the protected publish job must use the pinned builder and prove immutable-release policy before publication"
fi
credential_user="username: ${literal_dollar}{{ github.actor }}"
credential_password="password: ${literal_dollar}{{ secrets.GITHUB_TOKEN }}"
for workflow in .github/workflows/packages.yml .github/workflows/reproducibility.yml \
    .github/workflows/release.yml .github/workflows/soak-start.yml; do
    if ! grep -F -q "$credential_user" "$workflow" \
        || ! grep -F -q "$credential_password" "$workflow" \
        || ! grep -E -q '^[[:space:]]+packages:[[:space:]]+read$' "$workflow"; then
        report "$workflow must authenticate digest-pinned private GHCR containers with a job-scoped token"
    fi
done
dry_run_job=$(awk '
    $0 == "  dry_run:" { selected = 1 }
    selected && /^  [[:alnum:]_-]+:$/ && $0 != "  dry_run:" { exit }
    selected { print }
' .github/workflows/release.yml)
if ! printf '%s\n' "$dry_run_job" | grep -F -q 'image: ${{ needs.prepare.outputs.signing_image }}' \
    || ! printf '%s\n' "$dry_run_job" | grep -F -q 'sh tools/verify-package-builder.sh debian13-amd64' \
    || ! grep -F -q 'image: ${{ vars.VAULTLINK_PACKAGE_SIGNING_IMAGE }}' .github/workflows/soak-start.yml \
    || ! grep -F -q 'test "$SOAK_TOOL_IMAGE" =' .github/workflows/soak-start.yml \
    || [ "$(grep -F -c "$safe_directory_reference" .github/workflows/soak-start.yml || true)" -ne 1 ] \
    || ! grep -F -q 'sh tools/verify-package-builder.sh debian13-amd64' .github/workflows/soak-start.yml; then
    report "release verification and soak start must use the pinned complete package-tool image and trust only the checked-out workspace"
fi
for workflow in .github/workflows/packages.yml .github/workflows/reproducibility.yml; do
    if ! grep -F -q 'image: ${{ matrix.builder_image }}' "$workflow" \
        || ! grep -F -q 'sh tools/verify-package-builder.sh "$TARGET_ID"' "$workflow" \
        || ! grep -F -q 'tools/normalize-cyclonedx-sbom.py' "$workflow" \
        || ! grep -F -q 'tools/build-native-package.sh' "$workflow" \
        || ! grep -F -q 'tools/lint-native-package.sh' "$workflow"; then
        report "$workflow must consume and verify each target builder before native package work"
    fi
done
if grep -E -q '(install-package-builder-dependencies\.sh|cargo[[:space:]]+install[[:space:]])' \
        .github/workflows/packages.yml .github/workflows/reproducibility.yml \
        .github/workflows/release.yml; then
    report "package, reproducibility, and release jobs must not install build tooling at runtime"
fi

stable_toolchain=$(sh tools/rust-toolchain-channel.sh 2>/dev/null || true)
ci_toolchain_uses=$(grep -h -c 'uses:[[:space:]]*dtolnay/rust-toolchain@' \
    .github/workflows/ci.yml .github/workflows/security-audit.yml \
    | awk '{ total += $1 } END { print total + 0 }')
ci_toolchain_values=$(sed -n 's/^[[:space:]]*toolchain:[[:space:]]*//p' \
    .github/workflows/ci.yml .github/workflows/security-audit.yml)
ci_toolchain_value_count=$(printf '%s\n' "$ci_toolchain_values" | grep -c . || true)
ci_toolchain_refs=$(printf '%s\n' "$ci_toolchain_values" | grep -F -x -c "$toolchain_output_value" || true)
ci_toolchain_resolvers=$(grep -h -F -c "$toolchain_resolver_reference" \
    .github/workflows/ci.yml .github/workflows/security-audit.yml \
    | awk '{ total += $1 } END { print total + 0 }')
docker_image=$(sed -n 's/^FROM[[:space:]][[:space:]]*\([^[:space:]][^[:space:]]*\)[[:space:]]*$/\1/p' deploy/docker/Dockerfile.setup-smoke | head -n 1)
builder_rust_image=$(sed -n 's/^ARG RUST_IMAGE=\([^[:space:]][^[:space:]]*\)$/\1/p' "$package_builder" | head -n 1)

if [ -z "$stable_toolchain" ] || [ -z "$docker_image" ] || [ -z "$builder_rust_image" ]; then
    report "stable Rust toolchain and canonical/package-builder Rust pins must be readable"
else
    if [ "$ci_toolchain_uses" -ne 4 ] || [ "$ci_toolchain_value_count" -ne 4 ] \
        || [ "$ci_toolchain_refs" -ne 4 ] || [ "$ci_toolchain_resolvers" -ne 4 ]; then
        report "every stable Rust toolchain action must resolve rust-toolchain.toml exactly once"
    fi
    case "$docker_image" in
        "rust:${stable_toolchain}-trixie@sha256:"*) ;;
        *) report "container image version must match rust-toolchain.toml" ;;
    esac
    if [ "$builder_rust_image" != "$docker_image" ]; then
        report "native package builders and Docker smoke must share the reviewed Rust toolchain digest"
    fi
fi

for workflow in \
    .github/workflows/ci.yml \
    .github/workflows/fuzz.yml; do
    if ! grep -F -q 'runs_on: ubuntu-24.04' "$workflow"; then
        report "$workflow must keep amd64 on the pinned GitHub-hosted Ubuntu 24.04 runner"
    fi
    if ! grep -F -q 'runs_on: ubuntu-24.04-arm' "$workflow"; then
        report "$workflow must keep arm64 on the pinned GitHub-hosted Ubuntu 24.04 runner"
    fi
done

hosted_runner_lines=$(grep -R -H -E 'runs[_-]on:.*(ubuntu-|windows-|macos-)' .github/workflows || true)
unexpected_hosted_runners=$(printf '%s\n' "$hosted_runner_lines" \
    | grep -E -v 'runs[_-]on: ubuntu-24\.04(-arm)?$' || true)
unexpected_self_hosted=$(grep -R -H -F 'self-hosted' .github/workflows || true)
publish_runner=$(awk '
    $0 == "  publish:" { publish = 1; next }
    publish && /^  [[:alnum:]_-]+:$/ { exit }
    publish && /^    runs-on:/ { print; exit }
' .github/workflows/release.yml)
if [ "$publish_runner" != '    runs-on: ubuntu-24.04' ]; then
    report "the tag-only publish job must use the pinned GitHub-hosted ubuntu-24.04 runner"
fi
if ! printf '%s\n' "$publish_job" | grep -F -q '    environment: release-signing'; then
    report "the tag-only publish job must use the protected release-signing environment"
fi
if ! printf '%s\n' "$publish_job" \
    | grep -F -q "$safe_directory_reference"; then
    report "the containerized publish job must trust only its ephemeral checked-out workspace"
fi
if ! printf '%s\n' "$publish_job" \
    | grep -F -q "if: startsWith(github.ref, 'refs/tags/v')" \
    || ! grep -F -q 'test "$REPOSITORY_VISIBILITY" = public' .github/workflows/release.yml; then
    report "the tag-only publish chain must fail closed until the repository is public"
fi
if ! grep -F -q "printf '%s\\n' \"\$MINISIGN_PASSWORD\"" .github/workflows/release.yml \
    || ! grep -F -q "| minisign -S -s \"\$key\"" .github/workflows/release.yml; then
    report "encrypted Minisign keys must receive their secret password non-interactively over stdin"
fi
if [ -n "$unexpected_hosted_runners" ]; then
    printf '%s\n' "$unexpected_hosted_runners" >&2
    report "workflows may use only pinned GitHub-hosted Ubuntu 24.04 runner labels"
fi
if [ -n "$unexpected_self_hosted" ]; then
    printf '%s\n' "$unexpected_self_hosted" >&2
    report "public-repository workflows must not target persistent self-hosted runners"
fi

if [ "$(grep -F -c 'test "$candidate_commit" = "$main_commit"' .github/workflows/release.yml || true)" -lt 1 ] \
    || grep -F -q 'git merge-base --is-ancestor' .github/workflows/release.yml; then
    report "release tags must target the exact current main candidate, not merely an ancestor"
fi
if ! grep -F -q "repos/\$GITHUB_REPOSITORY/git/ref/tags/\$GITHUB_REF_NAME" .github/workflows/release.yml \
    || ! grep -F -q "test \"\$remote_tag_object\" = \"\$local_tag_object\"" .github/workflows/release.yml \
    || ! grep -F -q "repos/\$GITHUB_REPOSITORY/git/ref/heads/main" .github/workflows/release.yml; then
    report "release publish must revalidate the live remote tag object and main commit immediately before creation"
fi
if ! grep -F -q '.verification.verified,.verification.reason' .github/workflows/release.yml \
    || ! grep -F -q 'test "$remote_tag_verified" = true' .github/workflows/release.yml \
    || ! grep -F -q 'test "$remote_tag_verification_reason" = valid' .github/workflows/release.yml; then
    report "release publish must require a cryptographically verified remote tag signature"
fi

if grep -R -n -E 'curl[^|]*\|[[:space:]]*(ba)?sh' .github/workflows; then
    report "workflows must not pipe remote scripts into a shell"
fi

cargo_installs=$(grep -R -n -E 'cargo[[:space:]]+install[[:space:]]' .github/workflows || true)
bad_cargo_installs=$(printf '%s\n' "$cargo_installs" | grep -F -v -- '--version' || true)
if [ -n "$bad_cargo_installs" ]; then
    printf '%s\n' "$bad_cargo_installs" >&2
    report "cargo-installed CI tools must use an exact --version"
fi

dependabot_config=.github/dependabot.yml
stable_minor_dependencies='data-encoding http mime_guess percent-encoding rpassword rustix serde serde_json subtle tempfile thiserror tokio toml url'
if ! awk '
    $0 == "  - package-ecosystem: cargo" {
        cargo = 1
        cargo_found = 1
        next
    }
    cargo && /^  - package-ecosystem:/ {
        cargo = 0
    }
    !cargo { next }
    /^    (allow|ignore):/ {
        print "dependabot policy: Cargo updates must not be filtered by allow or ignore" > "/dev/stderr"
        failed = 1
    }
    $0 == "    open-pull-requests-limit: 10" { open_limit++ }
    END {
        if (!cargo_found || open_limit != 1) {
            print "dependabot policy: Cargo updates need ten visible PR slots" > "/dev/stderr"
            failed = 1
        }
        exit failed
    }
' "$dependabot_config"; then
    report "Dependabot Cargo updates must keep every finding visible"
fi

if ! dependabot_grouped_minors=$(awk '
    function invalid(message) {
        print "dependabot groups: " message > "/dev/stderr"
        failed = 1
    }
    function finish_group() {
        if (group_name == "")
            return
        if (group_name == "cargo-patch-updates") {
            patch_groups++
            if (applies_to != "version-updates" || patterns != "*" || update_types != "patch")
                invalid("cargo-patch-updates must group version patch updates")
        } else if (group_name == "cargo-stable-minor-updates") {
            minor_groups++
            if (applies_to != "version-updates" || update_types != "minor")
                invalid("cargo-stable-minor-updates must group version minor updates")
            grouped_minors = patterns
        }
        group_name = ""
        applies_to = ""
        patterns = ""
        update_types = ""
        section = ""
    }
    $0 == "  - package-ecosystem: cargo" { cargo = 1; next }
    cargo && /^  - package-ecosystem:/ {
        finish_group()
        cargo = 0
    }
    !cargo { next }
    /^      [[:alnum:]_-]+:$/ {
        finish_group()
        group_name = $0
        sub(/^      /, "", group_name)
        sub(/:$/, "", group_name)
        next
    }
    group_name != "" && /^        applies-to: / {
        applies_to = $0
        sub(/^        applies-to: /, "", applies_to)
        next
    }
    group_name != "" && $0 == "        patterns:" { section = "patterns"; next }
    group_name != "" && $0 == "        update-types:" { section = "update-types"; next }
    group_name != "" && /^          - / {
        value = $0
        sub(/^          - /, "", value)
        gsub(/^"|"$/, "", value)
        if (section == "patterns")
            patterns = patterns (patterns == "" ? "" : " ") value
        else if (section == "update-types")
            update_types = update_types (update_types == "" ? "" : " ") value
        next
    }
    END {
        finish_group()
        if (patch_groups != 1 || minor_groups != 1)
            invalid("expected exactly one patch group and one stable-minor group")
        print grouped_minors
        exit failed
    }
' "$dependabot_config"); then
    report "Dependabot Cargo update groups are invalid"
    dependabot_grouped_minors=
fi

dependabot_grouped_minor_count=0
for dependency in $dependabot_grouped_minors; do
    dependabot_grouped_minor_count=$((dependabot_grouped_minor_count + 1))
done
if [ "$dependabot_grouped_minor_count" -ne 14 ]; then
    report "Dependabot Cargo stable-minor group has the wrong size"
fi
for dependency in $stable_minor_dependencies; do
    case " $dependabot_grouped_minors " in
        *" $dependency "*) ;;
        *) report "Dependabot Cargo stable-minor group is missing $dependency" ;;
    esac
done

for pattern in /config.toml .env '.env.*' '*.sqlite*' .agents .codex .tmp dist; do
    if ! grep -F -x -q "$pattern" .dockerignore; then
        report ".dockerignore is missing $pattern"
    fi
done

for target in path_normalization byte_range filename zip_search_preview_paths upload_overwrite_policy upload_request_state share_request_policy file_mutation_policy multipart_guard; do
    if ! grep -E -q "(^|[[:space:]])${target}([[:space:]]|$)" Makefile; then
        report "Makefile fuzz target list is missing $target"
    fi
done

for workflow in .github/workflows/soak-start.yml .github/workflows/soak-collect.yml; do
    if ! grep -F -q 'runs-on: ubuntu-24.04' "$workflow" \
        || ! grep -F -q 'tools/configure-soak-ssh.sh' "$workflow"; then
        report "$workflow must use protected GitHub-hosted orchestration with pinned SSH transport"
    fi
    if grep -F -q 'pull_request:' "$workflow"; then
        report "$workflow must never accept pull-request execution"
    fi
done
if ! grep -F -q 'environment: release-soak' .github/workflows/soak-start.yml \
    || ! grep -F -q 'environment: release-soak-collector' .github/workflows/soak-collect.yml \
    || ! grep -F -q "cron: '17 * * * *'" .github/workflows/soak-collect.yml \
    || ! grep -F -q 'workflow_dispatch:' .github/workflows/soak-collect.yml; then
    report "soak start must require approval while the branch-restricted collector runs hourly and on demand"
fi
if ! grep -F -q 'vaultlink/72h-soak' .github/workflows/soak-start.yml \
    || ! grep -F -q 'vaultlink/72h-soak' .github/workflows/soak-collect.yml \
    || ! grep -F -q 'vaultlink/72h-soak' .github/workflows/release.yml \
    || ! grep -F -q 'tools/check-soak-evidence.sh' .github/workflows/release.yml; then
    report "start, collector, and tag release must share the exact-commit soak evidence contract"
fi
if grep -F -q 'git fetch' .github/workflows/soak-start.yml \
    || ! grep -F -q 'git/ref/heads/main' .github/workflows/soak-start.yml; then
    report "soak start must resolve the exact main ref through the authenticated GitHub API"
fi
if ! grep -F -q 'StrictHostKeyChecking yes' tools/configure-soak-ssh.sh \
    || ! grep -F -q 'IdentitiesOnly yes' tools/configure-soak-ssh.sh \
    || ! grep -F -q 'SOAK_SSH_HOST_KEYS' tools/configure-soak-ssh.sh \
    || ! grep -F -q 'SSH_ORIGINAL_COMMAND' deploy/vaultlink-soak-remote.sh \
    || ! grep -F -q "allowed_mode=\$1" deploy/vaultlink-soak-remote.sh \
    || ! grep -F -q 'the SSH key cannot start a soak' deploy/vaultlink-soak-remote.sh \
    || ! grep -F -q 'the SSH key cannot collect soak evidence' deploy/vaultlink-soak-remote.sh \
    || ! grep -F -q 'unsupported bridge command' deploy/vaultlink-soak-remote.sh \
    || ! grep -F -q "ssh -F \"\$SSH_CONFIG\" vaultlink-soak" .github/workflows/soak-start.yml \
    || ! grep -F -q "ssh -F \"\$SSH_CONFIG\" vaultlink-soak collect" .github/workflows/soak-collect.yml; then
    report "soak transport must pin the host and expose only the restricted start/collect bridge"
fi
if ! grep -F -q 'SOAK_ORCHESTRATION_SHA256' deploy/vaultlink-soak-control.sh \
    || ! grep -F -q '/usr/local/sbin/vaultlink-soak-remote' deploy/vaultlink-soak-control.sh \
    || ! grep -F -q '/usr/local/libexec/vaultlink/collect-soak-evidence.sh' deploy/vaultlink-soak-control.sh \
    || ! grep -F -q 'deploy/vaultlink-soak-remote.sh' .github/workflows/soak-start.yml \
    || ! grep -F -q 'tools/collect-soak-evidence.sh' .github/workflows/soak-start.yml \
    || ! grep -F -q 'orchestration_sha256=' tools/soak-monitor.sh \
    || ! grep -F -q 'approved_orchestration_sha256=' tools/check-soak-evidence.sh \
    || ! grep -F -q 'load profiles do not cover all 12 six-hour soak buckets' tools/check-soak-evidence.sh \
    || ! grep -F -q 'upload_integrity=server_readback' tools/load-test.sh \
    || ! grep -F -q 'holder_token=$ADMISSION_DOWNLOAD_TOKEN' tools/load-test.sh \
    || ! grep -F -q '"$VAULTLINK_BASE_URL/v/$holder_token/download" &' tools/load-test.sh \
    || ! grep -F -q 'validate_distinct_token_set "download token set"' tools/load-test.sh \
    || ! grep -F -q 'validate_distinct_token_set "upload token set"' tools/load-test.sh \
    || ! grep -F -q 'case $((download % 3)) in' tools/load-test.sh \
    || ! grep -F -q '2) download_token=$RANGE_DOWNLOAD_TOKEN' tools/load-test.sh \
    || ! grep -F -q 'case $((upload % 5)) in' tools/load-test.sh \
    || ! grep -F -q '4) upload_token=$UPLOAD_TOKEN_5' tools/load-test.sh \
    || ! grep -F -q 'range_share_count=3' tools/load-test.sh \
    || ! grep -F -q 'range_streams_per_share_max=14' tools/load-test.sh \
    || ! grep -F -q 'upload_share_count=5' tools/load-test.sh \
    || ! grep -F -q 'uploads_per_share=2' tools/load-test.sh \
    || ! grep -F -q 'soak load result does not prove bounded per-share sharding' tools/check-soak-evidence.sh \
    || ! grep -F -q 'ADMISSION_DOWNLOAD_TOKEN' docs/SOAK-RUNNER.md \
    || ! grep -F -q 'RANGE_DOWNLOAD_TOKEN' docs/SOAK-RUNNER.md \
    || ! grep -F -q 'UPLOAD_TOKEN_5' docs/SOAK-RUNNER.md \
    || ! grep -F -q 'UPLOAD_VERIFY_TOKEN' docs/SOAK-RUNNER.md \
    || ! grep -F -q '14/13/13 streams' docs/SOAK-RUNNER.md \
    || ! grep -F -q 'two per share' docs/SOAK-RUNNER.md; then
    report "soak evidence must bind orchestration, distributed load windows, and server-side upload readback"
fi
if ! grep -F -q 'SOAK_START_EPOCH=' deploy/vaultlink-soak-control.sh \
    || ! grep -F -q 'SOAK_DEADLINE_EPOCH=' deploy/vaultlink-soak-control.sh \
    || ! grep -F -q "systemctl --quiet is-active \"\$unit\"" tools/collect-soak-evidence.sh \
    || ! grep -F -q "systemctl --quiet is-failed \"\$unit\"" tools/collect-soak-evidence.sh \
    || ! grep -F -q 'monitor_deadline_exceeded' tools/collect-soak-evidence.sh \
    || ! grep -F -q 'collector-failure.env' tools/collect-soak-evidence.sh; then
    report "collector must turn a dead or overdue monitor into atomic partial failure evidence"
fi
if ! grep -F -q "[ \"\$(uname -m)\" = x86_64 ]" deploy/vaultlink-soak-control.sh \
    || ! grep -F -q "[ \"\$os_id\" = debian ]" deploy/vaultlink-soak-control.sh \
    || ! grep -F -q "[ \"\$os_version_id\" = 13 ]" deploy/vaultlink-soak-control.sh \
    || ! grep -F -q 'SOAK_ARCHITECTURE=amd64' deploy/vaultlink-soak-control.sh \
    || ! grep -F -q 'os_version_id' tools/check-soak-evidence.sh; then
    report "soak host and evidence must be bound to Debian 13 amd64"
fi
if ! grep -F -q 'dd if=/dev/urandom' tools/load-test.sh \
    || grep -F -q "truncate -s 64M \"\$work/upload.bin\"" tools/load-test.sh \
    || ! grep -F -q 'at least 16 GiB' docs/SOAK-RUNNER.md; then
    report "soak uploads must use non-sparse payloads with documented quota reserve"
fi
if ! grep -F -x -q 'p95_limit=2.000' tools/load-test.sh \
    || ! grep -F -q 'p95_policy=${LOAD_P95_POLICY:-strict}' tools/load-test.sh \
    || ! grep -F -q "'BEGIN { exit !(p95 < limit) }'" tools/load-test.sh \
    || ! grep -F -q 'p95 < 2.000' tools/check-soak-evidence.sh \
    || ! grep -F -q 'strict performance gate' docs/SOAK-RUNNER.md \
    || ! grep -F -q '2 seconds' docs/SOAK-RUNNER.md \
    || ! grep -F -q 'p95 `<2 s`' docs/RELEASE-CHECKLIST-0.6.0.md; then
    report "native/soak load execution, soak evidence verification, and release documentation must share the strict 2-second metadata p95 gate"
fi
if ! grep -F -q 'LOAD_P95_POLICY=strict' tools/soak-monitor.sh \
    || ! grep -F -q 'LOAD_CONNECT_TIMEOUT_SECONDS=5' tools/soak-monitor.sh \
    || ! grep -F -q 'LOAD_METADATA_MAX_TIME_SECONDS=30' tools/soak-monitor.sh \
    || ! grep -F -q 'LOAD_TRANSFER_MAX_TIME_SECONDS=300' tools/soak-monitor.sh \
    || ! grep -F -q 'LOAD_ADMISSION_READY_TIMEOUT_SECONDS=10' tools/soak-monitor.sh \
    || ! grep -F -q 'LOAD_ADMISSION_HOLDER_MAX_TIME_SECONDS=30' tools/soak-monitor.sh \
    || ! grep -F -q 'LOAD_ADMISSION_PROBE_MAX_TIME_SECONDS=5' tools/soak-monitor.sh \
    || ! grep -F -q 'LOAD_PROFILE_READY_TIMEOUT_SECONDS=10' tools/soak-monitor.sh \
    || ! grep -F -q "VAULTLINK_PROCESS_PID='' \\" tools/soak-monitor.sh \
    || ! grep -F -q "VAULTLINK_PROCESS_UID='' \\" tools/soak-monitor.sh \
    || ! grep -F -q "VAULTLINK_PROCESS_GID='' \\" tools/soak-monitor.sh \
    || ! grep -F -q "VAULTLINK_EXPECTED_BINARY_PATH='' \\" tools/soak-monitor.sh \
    || ! grep -F -q "VAULTLINK_EXPECTED_BINARY_SHA256='' \\" tools/soak-monitor.sh \
    || [ "$(grep -F -c 'VAULTLINK_PROCESS_PID=' tools/soak-monitor.sh || true)" -ne 1 ] \
    || [ "$(grep -F -c 'VAULTLINK_PROCESS_UID=' tools/soak-monitor.sh || true)" -ne 1 ] \
    || [ "$(grep -F -c 'VAULTLINK_PROCESS_GID=' tools/soak-monitor.sh || true)" -ne 1 ] \
    || [ "$(grep -F -c 'VAULTLINK_EXPECTED_BINARY_PATH=' tools/soak-monitor.sh || true)" -ne 1 ] \
    || [ "$(grep -F -c 'VAULTLINK_EXPECTED_BINARY_SHA256=' tools/soak-monitor.sh || true)" -ne 1 ] \
    || ! grep -F -q 'supervision_mode=systemd' tools/check-soak-evidence.sh \
    || ! grep -F -q 'metadata_p95_policy=strict' tools/check-soak-evidence.sh \
    || ! grep -F -q 'metadata_p95_limit_seconds=2.000' tools/check-soak-evidence.sh \
    || ! grep -F -q 'metadata_p95_within_limit=true' tools/check-soak-evidence.sh \
    || ! grep -F -q 'metadata_p95_enforced=true' tools/check-soak-evidence.sh \
    || ! grep -F -q 'process_starttime_ticks' tools/check-soak-evidence.sh \
    || ! grep -F -q 'process_starttime_ticks=5000' deploy/docker/soak-evidence-smoke.sh; then
    report "the 72-hour soak must pin normal timeouts, systemd supervision, and strict p95 evidence"
fi
for soak_strict_file in \
    .github/workflows/soak-start.yml \
    .github/workflows/soak-collect.yml \
    deploy/vaultlink-soak-control.sh \
    deploy/vaultlink-soak-remote.sh \
    deploy/vaultlink-soak@.service \
    tools/soak-monitor.sh \
    tools/collect-soak-evidence.sh; do
    if grep -F -q 'LOAD_P95_POLICY=diagnostic' "$soak_strict_file"; then
        report "$soak_strict_file must not opt the release soak into diagnostic p95"
    fi
    if [ "$soak_strict_file" != tools/soak-monitor.sh ] \
        && grep -F -q 'VAULTLINK_PROCESS_PID' "$soak_strict_file"; then
        report "$soak_strict_file must not opt the release soak into direct-PID supervision"
    fi
done
if grep -R -F -q \
        --exclude=check-supply-chain-policy.sh \
        --exclude=load-test.sh \
        --exclude=package-native-load-smoke.sh \
        --exclude=soak-monitor.sh \
        --exclude=distro-vm-runtime-smoke.sh \
        'VAULTLINK_PROCESS_PID=' .github deploy tools; then
    report "direct-PID load execution must remain confined to the native exact-package harness"
fi
for numeric_script in \
    tools/load-test.sh \
    tools/check-direct-process-identity.sh \
    tools/soak-monitor.sh \
    tools/check-soak-evidence.sh \
    tools/collect-soak-evidence.sh \
    tools/configure-soak-ssh.sh \
    deploy/vaultlink-soak-control.sh \
    deploy/vaultlink-soak-remote.sh \
    deploy/docker/soak-remote-smoke.sh \
    deploy/docker/soak-evidence-smoke.sh; do
    if ! grep -F -x -q 'LC_ALL=C' "$numeric_script" \
        || ! grep -F -x -q 'LANG=C' "$numeric_script" \
        || ! grep -F -x -q 'export LC_ALL LANG' "$numeric_script"; then
        report "$numeric_script must pin C locale for numeric and ordering evidence"
    fi
done
if ! grep -F -q 'continue-on-error: true' .github/workflows/soak-collect.yml \
    || ! grep -F -q 'collector_verification_failed' .github/workflows/soak-collect.yml \
    || [ "$(grep -F -c "if: ${literal_dollar}{{ always()" .github/workflows/soak-collect.yml || true)" -lt 4 ]; then
    report "soak collector must publish failure status and evidence after verification errors"
fi
for gate_context in \
    vaultlink/native-amd64 \
    vaultlink/native-arm64 \
    vaultlink/fuzz-600s-amd64 \
    vaultlink/fuzz-600s-arm64 \
    vaultlink/release-dry-run; do
    case "$gate_context" in
        vaultlink/native-*)
            producer=.github/workflows/ci.yml
            producer_context="vaultlink/native-${literal_dollar}architecture"
            release_context=$gate_context
            ;;
        vaultlink/fuzz-*)
            producer=.github/workflows/fuzz.yml
            producer_context="vaultlink/fuzz-600s-${literal_dollar}{{ matrix.architecture }}"
            release_context=$gate_context
            ;;
        vaultlink/release-dry-run)
            producer=.github/workflows/release.yml
            producer_context=$gate_context
            release_context=$gate_context
            ;;
    esac
    if ! grep -F -q "$producer_context" "$producer" \
        || ! grep -F -q "$release_context" .github/workflows/release.yml; then
        report "release preflight and producer must share exact-commit gate $gate_context"
    fi
done
for aggregate_context in \
    vaultlink/packages \
    vaultlink/package-reproducibility \
    vaultlink/distro-vms; do
    case "$aggregate_context" in
        vaultlink/packages) producer=.github/workflows/packages.yml ;;
        vaultlink/package-reproducibility) producer=.github/workflows/reproducibility.yml ;;
        vaultlink/distro-vms) producer=.github/workflows/distro-vms.yml ;;
    esac
    if ! grep -F -q "context='$aggregate_context'" "$producer" \
        || ! grep -F -q "$aggregate_context" .github/workflows/release.yml \
        || ! grep -F -q "$aggregate_context" .github/workflows/soak-start.yml; then
        report "candidate, soak, tag, and producer must share aggregate gate $aggregate_context"
    fi
done
for workflow in \
    .github/workflows/packages.yml \
    .github/workflows/reproducibility.yml \
    .github/workflows/distro-vms.yml; do
    publish_gate=$(awk '
        $0 == "  publish_gate:" { selected = 1 }
        selected && /^  [[:alnum:]_-]+:$/ && $0 != "  publish_gate:" { exit }
        selected { print }
    ' "$workflow")
    if [ "$(grep -E -c '^[[:space:]]+statuses:[[:space:]]+write$' "$workflow" || true)" -ne 1 ] \
        || ! printf '%s\n' "$publish_gate" \
            | grep -F -x -q '      statuses: write'; then
        report "$workflow must grant statuses: write only to its publish_gate job"
    fi
done
for release_context in vaultlink/release-candidate-preflight vaultlink/release-evidence-preflight; do
    if ! grep -F -q "$release_context" .github/workflows/release.yml; then
        report "release workflow must produce and consume $release_context"
    fi
done
if ! grep -F -q "Release candidate \$candidate_commit" .github/workflows/release.yml \
    || ! grep -F -q "Release evidence \$candidate_commit" .github/workflows/release.yml \
    || ! grep -F -q '.display_title' .github/workflows/release.yml; then
    report "release preflight statuses must bind provenance to their workflow-dispatch mode"
fi
for gate_context in \
    vaultlink/native-amd64 \
    vaultlink/native-arm64 \
    vaultlink/fuzz-600s-amd64 \
    vaultlink/fuzz-600s-arm64 \
    vaultlink/packages \
    vaultlink/package-reproducibility \
    vaultlink/distro-vms \
    vaultlink/release-dry-run \
    vaultlink/release-candidate-preflight; do
    if ! grep -F -q "$gate_context" .github/workflows/soak-start.yml; then
        report "soak start must require exact-commit gate $gate_context"
    fi
done
for workflow in .github/workflows/release.yml .github/workflows/soak-start.yml; do
    if ! grep -F -q "commits/\$candidate_commit/statuses?per_page=100" "$workflow" \
        && ! grep -F -q "commits/\$APPROVED_COMMIT/statuses?per_page=100" "$workflow"; then
        report "$workflow must paginate exact-commit status provenance"
    fi
    if ! grep -F -q "run_path=\${run_path%%@*}" "$workflow" \
        || ! grep -E -q '^[[:space:]]+actions:[[:space:]]+read$' "$workflow"; then
        report "$workflow must normalize Actions workflow paths and grant actions: read"
    fi
done
if ! grep -F -q -- '--name "vaultlink-release-unsigned-$APPROVED_COMMIT"' .github/workflows/soak-start.yml \
    || ! grep -F -q 'tools/verify-package-release.sh "$candidate_artifact" 0.7.0' .github/workflows/soak-start.yml \
    || ! grep -F -q 'package-targets.py asset debian13-amd64 0.7.0' .github/workflows/soak-start.yml \
    || ! grep -F -q 'dpkg-deb -x "$candidate_artifact/$deb" "$extracted"' .github/workflows/soak-start.yml \
    || ! grep -F -q 'usr/lib/vaultlink/package/vaultlink' .github/workflows/soak-start.yml \
    || ! grep -F -q 'candidate_binary_sha256' .github/workflows/soak-start.yml \
    || ! grep -F -q 'steps.validate.outputs.binary_sha256' .github/workflows/soak-start.yml; then
    report "soak start must bind its live binary hash to the final Debian 13 amd64 DEB payload"
fi
if ! grep -F -q 'ExecStart=/usr/local/libexec/vaultlink/soak-monitor.sh' deploy/vaultlink-soak@.service \
    || ! grep -F -x -q 'Group=vaultlink-soak' deploy/vaultlink-soak@.service \
    || ! grep -F -x -q 'CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE' deploy/vaultlink-soak@.service \
    || ! grep -F -x -q 'AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE' deploy/vaultlink-soak@.service \
    || [ "$(grep -F -c -- '-m 2750' deploy/vaultlink-soak-control.sh || true)" -lt 2 ] \
    || ! grep -F -q "install -d -m 2750 \"\$SOAK_EVIDENCE_DIR\"" tools/soak-monitor.sh \
    || ! grep -F -q 'SOAK_SECONDS=259200' deploy/vaultlink-soak-control.sh; then
    report "host-side systemd soak must retain the 72-hour monitor contract"
fi

repro_workflow=.github/workflows/reproducibility.yml
if ! grep -F -q 'python3 tools/package-targets.py matrix' "$repro_workflow" \
    || ! grep -F -q 'target/repro-first' "$repro_workflow" \
    || ! grep -F -q 'target/repro-second' "$repro_workflow" \
    || ! grep -F -q 'cmp repro/first/vaultlink repro/second/vaultlink' "$repro_workflow" \
    || ! grep -F -q 'cmp "candidate/$TARGET_ID.cdx.json" "repro/first/$TARGET_ID.cdx.json"' "$repro_workflow" \
    || ! grep -F -q 'cmp "candidate/$asset" "repro/first/$asset"' "$repro_workflow" \
    || ! grep -F -q 'package-reproducibility-binding-${{ github.sha }}' "$repro_workflow" \
    || ! grep -F -q 'distro-vm-binding-${{ inputs.commit_sha }}' .github/workflows/distro-vms.yml \
    || ! grep -F -q 'cmp "$binding_dir/expected.env" "$binding_dir/reproducibility-binding.env"' .github/workflows/release.yml \
    || ! grep -F -q 'cmp "$binding_dir/expected.env" "$vm_binding_dir/distro-vm-binding.env"' .github/workflows/release.yml; then
    report "reproducibility and VM gates must compare and bind the exact release-candidate package run"
fi
if ! grep -F -q 'SOURCE_DATE_EPOCH=$(git show -s --format=%ct "$GITHUB_SHA")' "$repro_workflow" \
    || ! grep -F -q 'source_date_epoch=$(git show -s --format=%ct "$GITHUB_SHA")' .github/workflows/packages.yml \
    || grep -E -q 'SOURCE_DATE_EPOCH="?0"?([[:space:]]|$)' \
        .github/workflows/packages.yml "$repro_workflow"; then
    report "native packages and both clean reproductions must use commit-derived SOURCE_DATE_EPOCH"
fi
if ! grep -F -q 'tools/package-offline-smoke.sh' .github/workflows/packages.yml \
    || ! grep -F -q 'docker run --rm --network none --user root' .github/workflows/packages.yml \
    || ! grep -F -q 'upgrade_migration_backup_rollback=ok' .github/workflows/packages.yml \
    || ! grep -F -q 'tools/package-targets.py matrix' .github/workflows/distro-vms.yml \
    || ! grep -F -q 'docker run --rm --network none --user root' .github/workflows/distro-vms.yml \
    || ! grep -F -q 'sh tools/verify-qemu-runner.sh "$ARCHITECTURE"' .github/workflows/distro-vms.yml \
    || ! grep -F -q 'sh tools/verify-qemu-runner.sh "$ARCHITECTURE"' .github/workflows/distro-vm-images-refresh.yml \
    || ! grep -F -q 'restrict=on' tools/run-distro-vm-test.sh \
    || ! grep -F -q 'restrict=on' tools/provision-distro-vm-image.sh \
    || ! grep -F -q 'sh tools/select-qemu-acceleration.sh' tools/run-distro-vm-test.sh \
    || ! grep -F -q 'sh tools/select-qemu-acceleration.sh' tools/provision-distro-vm-image.sh \
    || ! grep -F -q -- '--env ACCELERATION_POLICY=force-tcg' .github/workflows/distro-vms.yml \
    || ! grep -F -q -- '--env ACCELERATION_POLICY=auto' .github/workflows/distro-vm-images-refresh.yml \
    || ! grep -F -q 'VM provisioning QEMU exited with status' tools/provision-distro-vm-image.sh \
    || ! grep -F -q 'cold-boot QEMU exited with status' tools/provision-distro-vm-image.sh \
    || [ "$(grep -F -c 'cloud-init-output.log /dev/console' tools/provision-distro-vm-image.sh || true)" -ne 2 ] \
    || [ "$(grep -F -c 'tail -n 2000' tools/provision-distro-vm-image.sh || true)" -ne 6 ] \
    || ! grep -F -q 'distro-vm-failure-${{ inputs.target_id }}-${{ github.run_id }}-${{ github.run_attempt }}' .github/workflows/distro-vm-images-refresh.yml \
    || ! grep -F -q 'vm-build/*.serial.log' .github/workflows/distro-vm-images-refresh.yml \
    || ! grep -F -q -- '-device virtio-net-pci,netdev=net0,romfile=' tools/provision-distro-vm-image.sh \
    || ! grep -F -q -- '-device virtio-net-pci,netdev=verify-net,romfile=' tools/provision-distro-vm-image.sh \
    || ! grep -F -q -- '-device virtio-net-pci,netdev=net0,romfile=' tools/run-distro-vm-test.sh \
    || ! grep -F -q 'metadata_clients=100' tools/run-distro-vm-test.sh \
    || ! grep -F -q 'cmp /usr/local/share/vaultlink-vm-packages.lock "$live_vm_packages"' tools/distro-vm-guest-smoke.sh \
    || ! grep -F -q 'cmp /usr/local/share/vaultlink-vm-packages.lock /run/vaultlink-vm-packages.live' tools/provision-distro-vm-image.sh \
    || ! grep -F -q '[ "$(getenforce)" = Enforcing ]' tools/distro-vm-runtime-smoke.sh \
    || ! grep -F -q '[ "$(systemctl is-active auditd.service)" = active ]' tools/distro-vm-runtime-smoke.sh \
    || ! grep -F -q 'auditctl -m "$fedora_audit_marker"' tools/distro-vm-runtime-smoke.sh \
    || ! grep -F -q 'audit-window.log' tools/distro-vm-runtime-smoke.sh \
    || ! grep -F -q 'kernel-audit.journal' tools/distro-vm-runtime-smoke.sh \
    || ! grep -F -q 'VaultLink-related AVC denial' tools/distro-vm-runtime-smoke.sh; then
    report "all nine packages need offline lifecycle gates and restricted full-system QEMU/load/SELinux gates"
fi
if [ ! -f "$qemu_acceleration_selector" ] \
    || [ -L "$qemu_acceleration_selector" ] \
    || ! grep -F -q 'acceleration_policy=${ACCELERATION_POLICY:-force-tcg}' \
        "$qemu_acceleration_selector" \
    || ! grep -F -q 'force-tcg | auto)' "$qemu_acceleration_selector" \
    || ! grep -F -q 'for _probe_second in 1 2 3 4 5; do' \
        "$qemu_acceleration_selector" \
    || ! grep -F -q 'client.settimeout(3)' "$qemu_acceleration_selector" \
    || ! grep -F -q '"execute":"query-kvm"' \
        "$qemu_acceleration_selector" \
    || ! grep -F -q 'state.get("present") is not True' \
        "$qemu_acceleration_selector" \
    || ! grep -F -q 'state.get("enabled") is not True' \
        "$qemu_acceleration_selector" \
    || ! grep -F -q 'if [ "$probe_status" -eq 0 ]; then' \
        "$qemu_acceleration_selector" \
    || ! grep -F -q 'selected_acceleration=kvm' \
        "$qemu_acceleration_selector"; then
    report "KVM may be selected only after a bounded QMP query proves it present and enabled"
fi
if grep -F -q -- '--device /dev/kvm' .github/workflows/distro-vms.yml \
    || grep -F -q -- '--privileged' .github/workflows/distro-vms.yml \
    || grep -F -q -- '--cap-add' .github/workflows/distro-vms.yml \
    || [ "$(grep -F -c -- '--env ACCELERATION_POLICY=force-tcg' \
        .github/workflows/distro-vms.yml || true)" -ne 1 ] \
    || [ "$(grep -F -c 'sh tools/run-distro-vm-test.sh' \
        .github/workflows/distro-vms.yml || true)" -ne 1 ] \
    || ! grep -F -q "grep -F -x -q 'acceleration_policy=force-tcg'" \
        .github/workflows/distro-vms.yml \
    || ! grep -F -q "grep -F -x -q 'acceleration=tcg'" \
        .github/workflows/distro-vms.yml \
    || ! grep -F -q "grep -F -x -q 'selected_acceleration=tcg'" \
        .github/workflows/distro-vms.yml \
    || ! grep -F -q "grep -F -x -q 'kvm_probe_result=not-requested'" \
        .github/workflows/distro-vms.yml; then
    report "the single commit-bound nine-target VM matrix must force and prove TCG without exposing KVM"
fi
if [ "$(grep -F -c -- '--device /dev/kvm' \
        .github/workflows/distro-vm-images-refresh.yml || true)" -ne 1 ] \
    || ! grep -F -q 'kvm_args+=(--device /dev/kvm:/dev/kvm:rw)' \
        .github/workflows/distro-vm-images-refresh.yml \
    || ! grep -F -q '"$ARCHITECTURE" == amd64 && -c /dev/kvm' \
        .github/workflows/distro-vm-images-refresh.yml \
    || [ "$(grep -F -c -- '--env ACCELERATION_POLICY=auto' \
        .github/workflows/distro-vm-images-refresh.yml || true)" -ne 1 ] \
    || ! grep -F -q 'guest.qcow2.acceleration-selection.env' \
        .github/workflows/distro-vm-images-refresh.yml \
    || grep -F -q -- '--privileged' .github/workflows/distro-vm-images-refresh.yml \
    || grep -F -q -- '--cap-add' .github/workflows/distro-vm-images-refresh.yml; then
    report "guest-image refresh may expose only exact amd64 KVM and must use the bounded automatic probe"
fi
if ! grep -F -q 'forces TCG for every one of the nine matrix targets' \
        docs/GITHUB-HOSTED-RUNNERS.md \
    || ! grep -F -q 'bounded QMP probe reports KVM as both present and enabled' \
        docs/GITHUB-HOSTED-RUNNERS.md \
    || ! grep -F -q 'commit-bound nine-target workflow forces and records TCG' \
        docs/PACKAGING.md \
    || ! grep -F -q '`acceleration_policy=force-tcg`' \
        docs/RELEASE-CHECKLIST-0.6.0.md \
    || ! grep -F -q 'nine-target workflow forces and records TCG' \
        release/README.md; then
    report "runner, packaging, release, and checklist docs must distinguish forced-TCG gates from probed refresh acceleration"
fi
if [ "$(grep -F -c 'LOAD_P95_POLICY=diagnostic' "$vm_runtime_smoke" || true)" -ne 1 ] \
    || grep -R -F -q --exclude=check-supply-chain-policy.sh \
        --exclude=distro-vm-runtime-smoke.sh \
        'LOAD_P95_POLICY=diagnostic' .github deploy tools \
    || ! grep -F -q 'case "$acceleration" in kvm|tcg)' "$vm_runtime_smoke" \
    || ! grep -F -q 'if [ "$acceleration" = tcg ]; then' "$vm_runtime_smoke" \
    || ! grep -F -q 'load_connect_timeout_seconds=60' "$vm_runtime_smoke" \
    || ! grep -F -q 'load_metadata_max_time_seconds=300' "$vm_runtime_smoke" \
    || ! grep -F -q 'load_transfer_max_time_seconds=3600' "$vm_runtime_smoke" \
    || ! grep -F -q 'load_admission_ready_timeout_seconds=600' "$vm_runtime_smoke" \
    || ! grep -F -q 'load_admission_holder_max_time_seconds=1800' "$vm_runtime_smoke" \
    || ! grep -F -q 'load_admission_probe_max_time_seconds=120' "$vm_runtime_smoke" \
    || ! grep -F -q 'load_profile_ready_timeout_seconds=600' "$vm_runtime_smoke" \
    || ! grep -F -q 'bounded 60-minute request deadline' \
        docs/GITHUB-HOSTED-RUNNERS.md; then
    report "only the QEMU runtime gate may use diagnostic p95, with bounded TCG-only timeout allowances"
fi
if ! grep -F -q 'evidence_value "$p95_evidence" metadata_p95_policy)" = diagnostic' "$vm_runtime_smoke" \
    || ! grep -F -q 'evidence_value "$p95_evidence" metadata_p95_limit_seconds)" = 2.000' "$vm_runtime_smoke" \
    || ! grep -F -q 'evidence_value "$p95_evidence" metadata_p95_enforced)" = false' "$vm_runtime_smoke" \
    || ! grep -F -q 'expected_p95_within_limit=$(awk -v value="$p95"' "$vm_runtime_smoke" \
    || ! grep -F -q 'print (value < 2.000) ? "true" : "false"' "$vm_runtime_smoke" \
    || ! grep -F -q 'evidence_value "$p95_evidence" metadata_p95_within_limit' "$vm_runtime_smoke" \
    || ! grep -F -q 'evidence_value "$p95_evidence" supervision_mode)" = systemd' "$vm_runtime_smoke" \
    || ! grep -F -q "VAULTLINK_PROCESS_PID='' \\" "$vm_runtime_smoke" \
    || ! grep -F -q "VAULTLINK_PROCESS_UID='' \\" "$vm_runtime_smoke" \
    || ! grep -F -q "VAULTLINK_PROCESS_GID='' \\" "$vm_runtime_smoke" \
    || ! grep -F -q "VAULTLINK_EXPECTED_BINARY_PATH='' \\" "$vm_runtime_smoke" \
    || ! grep -F -q "VAULTLINK_EXPECTED_BINARY_SHA256='' \\" "$vm_runtime_smoke" \
    || ! grep -F -q 'metadata_p95_policy=diagnostic' "$vm_harness" \
    || ! grep -F -q 'metadata_p95_limit_seconds=2.000' "$vm_harness" \
    || ! grep -F -q 'metadata_p95_enforced=false' "$vm_harness" \
    || ! grep -F -q 'expected_p95_within_limit=$(awk -v value="$load_result_p95"' "$vm_harness" \
    || ! grep -F -q 'print (value < 2.000) ? "true" : "false"' "$vm_harness" \
    || ! grep -F -q 'evidence_value "$p95_evidence" metadata_p95_within_limit' "$vm_harness" \
    || ! grep -F -q 'evidence_value "$p95_evidence" supervision_mode)" = systemd' "$vm_harness" \
    || ! grep -F -q 'metadata_rows=2000' "$vm_harness" \
    || ! grep -F -q 'range_rows=40' "$vm_harness" \
    || ! grep -F -q 'upload_rows=10' "$vm_harness" \
    || ! grep -F -q 'upload_integrity=server_readback' "$vm_harness" \
    || ! grep -F -q 'admission_download_token=$(create_share vaultlink-load/sparse-50GiB.bin download_only)' "$vm_runtime_smoke" \
    || ! grep -F -q 'range_download_token=$(create_share vaultlink-load/sparse-50GiB.bin download_only)' "$vm_runtime_smoke" \
    || ! grep -F -q 'ADMISSION_DOWNLOAD_TOKEN=$admission_download_token' "$vm_runtime_smoke" \
    || ! grep -F -q 'RANGE_DOWNLOAD_TOKEN=$range_download_token' "$vm_runtime_smoke" \
    || ! grep -F -q 'UPLOAD_TOKEN_5=$upload_token_5' "$vm_runtime_smoke" \
    || ! grep -F -q 'range_share_count)" = 3' "$vm_runtime_smoke" \
    || ! grep -F -q 'upload_share_count)" = 5' "$vm_runtime_smoke" \
    || ! grep -F -q 'redact_runtime_load_log "$evidence/load.log"' "$vm_runtime_smoke" \
    || ! grep -F -q 'VM_REDACT_RANGE_DOWNLOAD_TOKEN' "$vm_runtime_smoke" \
    || ! grep -F -q 'VM_REDACT_UPLOAD_TOKEN_5' "$vm_runtime_smoke" \
    || ! grep -F -q 'integrity=ok' "$vm_runtime_smoke" \
    || ! grep -F -q 'sudo sqlite3 /var/lib/vaultlink/data.sqlite "PRAGMA integrity_check;"' "$vm_harness" \
    || ! grep -F -q '$2 !~ /^2[0-9][0-9]$/' "$load_test" \
    || ! grep -F -q '[ "$status" = 206 ]' "$load_test" \
    || ! grep -F -q '[ "$hash" = "$expected_range_hash" ]' "$load_test" \
    || ! grep -F -q '[ "$verify_status" = 200 ]' "$load_test" \
    || ! grep -F -q '[ "$server_hash" = "$upload_hash" ]' "$load_test" \
    || ! grep -F -q '[ "$current_pid" = "$pid" ] || return 1' "$load_test" \
    || ! grep -F -q '[ "$rss_kib" -gt 262144 ]' "$load_test" \
    || ! grep -F -q '[ "$integrity" = ok ] || return 1' "$load_test"; then
    report "QEMU must record numeric diagnostic p95 while keeping 100/40/10, status, hash, RSS, PID, readiness, and SQLite checks hard"
fi
if grep -E -q '\[[^]]*p95[^]]*within[^]]*(=|!=)[^]]*true[^]]*\]' \
        "$vm_runtime_smoke" "$vm_harness"; then
    report "QEMU p95 threshold results must be recorded, not required to be true"
fi
harness_evidence_line=$(grep -n -F '>"$evidence/harness.env"' "$vm_harness" \
    | cut -d: -f1 | head -n 1)
qemu_start_line=$(grep -n -F '$qemu $machine_args $firmware_args $acceleration_args' \
    "$vm_harness" | cut -d: -f1 | head -n 1)
if [ -z "$harness_evidence_line" ] || [ -z "$qemu_start_line" ] \
    || [ "$harness_evidence_line" -ge "$qemu_start_line" ]; then
    report "QEMU harness policy and acceleration evidence must be persisted before guest launch"
fi
if ! grep -F -q 'section == "[reverse_proxy]" && $0 == "enabled = false"' "$vm_runtime_smoke" \
    || ! grep -F -q 'runtime_mount_base=/mnt/storage' "$vm_runtime_smoke" \
    || ! grep -F -q 'runtime_root=$runtime_mount_base/shared' "$vm_runtime_smoke" \
    || ! grep -F -q 'runtime_internal=$runtime_mount_base/.vaultlink-internal' "$vm_runtime_smoke" \
    || ! grep -F -q 'install -d -o vaultlink -g vaultlink -m 0700 "$runtime_internal"' "$vm_runtime_smoke" \
    || ! grep -F -q 'chmod 0700 "$runtime_internal"' "$vm_runtime_smoke" \
    || ! grep -F -q '"$runtime_root/vaultlink-load" "$runtime_root/vaultlink-load/uploads"' "$vm_runtime_smoke" \
    || ! grep -F -q 'root_mount_path = "/mnt/storage/shared"' "$vm_runtime_smoke" \
    || ! grep -F -q 'internal_directory = "/mnt/storage/.vaultlink-internal"' "$vm_runtime_smoke" \
    || grep -F -q 'internal_directory = "/mnt/.vaultlink-internal"' "$vm_runtime_smoke" \
    || ! grep -F -q 'function finish_storage()' "$vm_runtime_smoke" \
    || ! grep -F -q 'print "expected_filesystem_type = \"ext4\""' "$vm_runtime_smoke" \
    || ! grep -F -q 'print "expected_mount_source = \"/dev/vdb\""' "$vm_runtime_smoke" \
    || ! grep -F -q 'storage_filesystem != 1 || storage_source != 1' "$vm_runtime_smoke" \
    || ! grep -F -q 'print "enabled = true"' "$vm_runtime_smoke" \
    || ! grep -F -q 'section == "[reverse_proxy]" && /^trusted_proxies = /' "$vm_runtime_smoke" \
    || ! grep -F -q 'print "trusted_proxies = [\"127.0.0.1\"]"' "$vm_runtime_smoke" \
    || ! grep -F -q 'if ($0 == "trusted_proxies = [") skipping_proxies = 1' "$vm_runtime_smoke" \
    || ! grep -F -q 'if ($0 == "]") skipping_proxies = 0' "$vm_runtime_smoke" \
    || ! grep -F -q 'section == "[reverse_proxy]" && $0 == "trust_x_forwarded_headers = false"' "$vm_runtime_smoke" \
    || ! grep -F -q 'print "trust_x_forwarded_headers = true"' "$vm_runtime_smoke" \
    || ! grep -F -q 'if (skipping_proxies || rewritten_enabled != 1' "$vm_runtime_smoke" \
    || ! grep -F -q 'rewritten_proxies != 1 || rewritten_forwarded != 1' "$vm_runtime_smoke" \
    || ! grep -F -q 'section == "[reverse_proxy]" && /^enabled[[:space:]]*=/' "$vm_runtime_smoke" \
    || ! grep -F -q 'enabled_ok += ($0 == "enabled = true")' "$vm_runtime_smoke" \
    || ! grep -F -q 'proxies_ok += ($0 == "trusted_proxies = [\"127.0.0.1\"]")' "$vm_runtime_smoke" \
    || ! grep -F -q 'forwarded_ok += ($0 == "trust_x_forwarded_headers = true")' "$vm_runtime_smoke" \
    || ! grep -F -q 'section == "[tls]" && /^enabled[[:space:]]*=/' "$vm_runtime_smoke" \
    || ! grep -F -q 'tls_ok += ($0 == "enabled = false")' "$vm_runtime_smoke"; then
    report "the distro VM runtime gate must build and verify minimal storage and section-scoped reverse-proxy configuration"
fi
vm_evidence_upload=$(awk '
    $0 == "      - name: Upload full-system evidence" { selected = 1 }
    selected { print }
    selected && /^          retention-days:/ { exit }
' .github/workflows/distro-vms.yml)
if ! grep -F -q 'runtime_status=$?' "$vm_runtime_smoke" \
    || ! grep -F -q 'trap finalize_runtime_evidence EXIT' "$vm_runtime_smoke" \
    || ! grep -F -q 'rm -f "$evidence/cookies.txt" || true' "$vm_runtime_smoke" \
    || ! grep -F -q 'runtime-command.env' "$vm_runtime_smoke" \
    || ! grep -F -q 'runtime-failure-systemd.env' "$vm_runtime_smoke" \
    || ! grep -F -q 'runtime-failure.journal' "$vm_runtime_smoke" \
    || ! grep -F -q '2>"$evidence/readiness-last.stderr"' "$vm_runtime_smoke" \
    || ! grep -F -q 'totp_wait_seconds=$((31 - totp_epoch % 30))' "$vm_runtime_smoke" \
    || ! grep -F -q 'sleep "$totp_wait_seconds"' "$vm_runtime_smoke" \
    || ! grep -F -q 'VAULTLINK_HEALTH_URL=http://127.0.0.1:18081/api/v2/health/ready' "$vm_runtime_smoke" \
    || ! grep -F -q 'load_tmp="$runtime_mount_base/.distro-vm-load-work"' "$vm_runtime_smoke" \
    || ! grep -F -q 'install -d -o root -g root -m 0700 "$load_tmp"' "$vm_runtime_smoke" \
    || ! grep -F -q 'TMPDIR="$load_tmp"' "$vm_runtime_smoke" \
    || ! grep -F -q 'rmdir "$load_tmp"' "$vm_runtime_smoke" \
    || ! grep -F -q 'find "$evidence" -type d -exec chmod 0755 {} +' "$vm_runtime_smoke" \
    || ! grep -F -q 'find "$evidence" -type f -exec chmod 0644 {} +' "$vm_runtime_smoke" \
    || ! grep -F -q 'exit "$runtime_status"' "$vm_runtime_smoke" \
    || ! grep -F -q '|| guest_smoke_status=$?' "$vm_harness" \
    || ! grep -F -q '|| runtime_evidence_status=$?' "$vm_harness" \
    || ! grep -F -q '|| guest_system_status=$?' "$vm_harness" \
    || ! grep -F -q '|| sqlite_status=$?' "$vm_harness" \
    || ! grep -F -q 'sudo sqlite3 /var/lib/vaultlink/data.sqlite "PRAGMA integrity_check;"' "$vm_harness" \
    || grep -F -q 'name "*.sqlite*"' "$vm_harness" \
    || ! grep -F -q 'guest-commands.env' "$vm_harness" \
    || ! grep -F -q 'runtime-evidence-scp.stderr' "$vm_harness" \
    || ! grep -F -q 'sudo journalctl -u vaultlink.service --no-pager' "$vm_harness" \
    || ! grep -F -q 'tail -n 200 "$evidence/serial.log" >&2 || true' "$vm_harness" \
    || ! grep -F -q 'exit "$guest_smoke_status"' "$vm_harness" \
    || ! grep -F -q 'unit_credential_probe=/usr/local/sbin/vaultlink-update-credential-probe' "$vm_guest_smoke" \
    || ! grep -F -q 'unit_package_probe=/usr/local/sbin/vaultlink-update-package-probe' "$vm_guest_smoke" \
    || ! grep -F -q '[ "$cap_inheritable" = 00000000000000cf ]' "$vm_guest_smoke" \
    || ! grep -F -q '[ "$cap_permitted" = 0000000000000000 ]' "$vm_guest_smoke" \
    || ! grep -F -q '[ "$cap_effective" = 0000000000000000 ]' "$vm_guest_smoke" \
    || ! grep -F -q '[ "$cap_bounding" = 00000000000000cf ]' "$vm_guest_smoke" \
    || ! grep -F -q '[ "$cap_ambient" = 0000000000000000 ]' "$vm_guest_smoke" \
    || ! grep -F -q '[ "$no_new_privileges" = 1 ]' "$vm_guest_smoke" \
    || ! grep -F -q -- '-p NoNewPrivileges -p CapabilityBoundingSet -p AmbientCapabilities' "$vm_guest_smoke" \
    || ! grep -F -q "'NoNewPrivileges=yes'" "$vm_guest_smoke" \
    || ! grep -F -q 'launcher_no_new_privileges=\$(awk' "$vm_guest_smoke" \
    || ! grep -F -q 'if launcher_context_value=\$(tr -d' "$vm_guest_smoke" \
    || ! grep -F -q '</proc/self/attr/current 2>/dev/null); then' "$vm_guest_smoke" \
    || ! grep -F -q '|| launcher_context=\$launcher_context_value' "$vm_guest_smoke" \
    || ! grep -F -q 'ExecStart=$unit_package_probe' "$vm_guest_smoke" \
    || grep -F -q 'ExecStart=$unit_probe_command' "$vm_guest_smoke" \
    || ! grep -F -q '/usr/bin/rpm --nocontexts --upgrade --replacepkgs' "$vm_guest_smoke" \
    || ! grep -F -q 'unconfined_service_t' "$vm_guest_smoke" \
    || ! grep -F -q 'update-unit-package-manager-launcher.env' "$vm_guest_smoke" \
    || ! grep -F -q "'AmbientCapabilities=cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_setgid cap_setuid'" "$vm_guest_smoke" \
    || ! grep -F -q "'SecureBits=0'" "$vm_guest_smoke" \
    || ! grep -F -q 'update-unit-credential.env' "$vm_guest_smoke" \
    || ! grep -F -q 'stat -c '\''%u:%g:%a'\'' /var/lib/vaultlink-backups' "$vm_guest_smoke" \
    || grep -F -q 'install -d -m 0750 /etc/vaultlink /var/lib/vaultlink /var/lib/vaultlink-backups' "$vm_guest_smoke" \
    || ! grep -F -q "grep -F -x -q 'stage=complete'" "$vm_harness" \
    || ! grep -F -q "grep -F -x -q 'exit_status=0'" "$vm_harness" \
    || ! grep -F -q 'load_evidence=$evidence/runtime/load' "$vm_harness" \
    || ! grep -F -q 'metadata_rows=2000' "$vm_harness" \
    || ! grep -F -q 'range_rows=40' "$vm_harness" \
    || ! grep -F -q 'upload_rows=10' "$vm_harness" \
    || ! grep -F -q "find \"\$load_evidence\" -type f -name '*.partial.*'" "$vm_harness" \
    || ! grep -F -q 'load_exit_status=$?' "$load_test" \
    || ! grep -F -q 'trap cleanup EXIT' "$load_test" \
    || ! grep -F -q "trap 'exit 129' HUP" "$load_test" \
    || ! grep -F -q 'persist_load_evidence "$load_exit_status"' "$load_test" \
    || ! grep -F -q 'rm -f "$work/upload.bin" "$work"/range-*.bin' "$load_test" \
    || ! grep -F -q 'metadata-load.partial.csv' "$load_test" \
    || ! grep -F -q 'metadata-capacity-retries.partial.csv' "$load_test" \
    || ! grep -F -q 'range-results.partial.csv' "$load_test" \
    || ! grep -F -q 'upload-results.partial.csv' "$load_test" \
    || ! grep -F -q 'cat "$work"/metadata-*.csv >"$work/metadata.csv"' "$load_test" \
    || ! grep -F -q 'profile-status.env' "$load_test" \
    || ! grep -F -q 'metadata_status=$metadata_status' "$load_test" \
    || ! grep -F -q 'metadata_observed_p95_seconds=$observed_p95' "$load_test" \
    || ! grep -F -q '%{time_starttransfer},%{speed_download},%{time_total}' "$load_test" \
    || ! grep -F -q 'range_ttfb_observed_p95_seconds=$observed_range_ttfb_p95' "$load_test" \
    || ! grep -F -q 'range_throughput_median_bytes_per_second=$observed_range_throughput_median' "$load_test" \
    || ! grep -F -q 'range_duration_observed_p95_seconds=$observed_range_duration_p95' "$load_test" \
    || ! grep -F -q 'redact_failure_log() {' "$api_smoke" \
    || ! grep -F -q 'service_token = re.compile(r"vlk_st_v1_[A-Za-z0-9_-]{43}")' "$api_smoke" \
    || ! grep -F -q 'if re.search(r"authorization", line, re.IGNORECASE):' "$api_smoke" \
    || ! grep -F -q 'setup_token.sub(r"\1[REDACTED]", line)' "$api_smoke" \
    || ! grep -F -q 'tail -n 80 "$SETUP_LOG" | redact_failure_log >&2 || true' "$api_smoke" \
    || ! grep -F -q 'tail -n 120 "$APP_LOG" | redact_failure_log >&2 || true' "$api_smoke" \
    || ! grep -F -q "printf 'API smoke failed: %s\\n' \"\$*\" | redact_failure_log >&2" "$api_smoke" \
    || grep -F -q 'tail -n 120 "$APP_LOG" >&2' "$api_smoke" \
    || ! grep -F -q '[ ! -e "$evidence/runtime/cookies.txt" ]' "$vm_harness" \
    || ! printf '%s\n' "$vm_evidence_upload" | grep -F -q '        if: always()' \
    || ! printf '%s\n' "$vm_evidence_upload" | grep -F -q '            vm-test/${{ matrix.id }}/evidence' \
    || ! printf '%s\n' "$vm_evidence_upload" | grep -F -q '          if-no-files-found: error'; then
    report "distro VM failures must preserve sanitized partial evidence without masking the original guest status"
fi
metadata_aggregate_line=$(grep -n -F 'cat "$work"/metadata-*.csv >"$work/metadata.csv"' "$load_test" \
    | cut -d: -f1 | head -n 1)
metadata_failure_line=$(grep -n -F '[ "$metadata_failed" -eq 0 ] || return 1' "$load_test" \
    | cut -d: -f1 | head -n 1)
if [ -z "$metadata_aggregate_line" ] || [ -z "$metadata_failure_line" ] \
    || [ "$metadata_aggregate_line" -ge "$metadata_failure_line" ]; then
    report "metadata load failures must aggregate completed client results before returning"
fi
if ! grep -F -q 'metadata_capacity_retry_limit_per_client=3' "$load_test" \
    || ! grep -F -q 'metadata_capacity_retry_after_seconds=1' "$load_test" \
    || ! grep -F -q 'metadata_capacity_response_limit=1.100' "$load_test" \
    || ! grep -F -q -- '--dump-header "$headers"' "$load_test" \
    || ! grep -F -q '[ "$retry_after" = "$metadata_capacity_retry_after_seconds" ]' \
        "$load_test" \
    || ! grep -F -q 'value + 0 <= limit' "$load_test" \
    || ! grep -F -q 'sleep "$retry_after"' "$load_test" \
    || ! grep -F -q 'metadata-capacity-retries.csv' "$load_test" \
    || ! grep -F -q 'metadata_attempts=$metadata_attempts' "$load_test" \
    || ! grep -F -q 'soak load result does not retain the bounded capacity retry contract' \
        tools/check-soak-evidence.sh \
    || ! grep -F -q 'metadata-capacity-retries.csv' tools/check-soak-evidence.sh \
    || ! grep -F -q 'accepted a capacity response beyond 1.1 seconds' \
        deploy/docker/soak-evidence-smoke.sh \
    || ! grep -F -q 'accepted an uncounted unterminated capacity row' \
        deploy/docker/soak-evidence-smoke.sh \
    || ! grep -F -q 'rejected a successful profile without capacity retries' \
        deploy/docker/soak-evidence-smoke.sh \
    || ! grep -F -q 'metadata_capacity_retry_limit_per_client' "$vm_runtime_smoke" \
    || ! grep -F -q 'metadata_capacity_retry_limit_per_client=3' "$vm_harness" \
    || ! grep -F -q 'metadata-capacity-retries.csv' "$vm_harness" \
    || ! grep -F -q 'retry at most three capacity responses' docs/SOAK-RUNNER.md \
    || ! grep -F -q '`metadata-capacity-retries.csv`' docs/SOAK-RUNNER.md; then
    report "metadata load capacity retries must be bounded and prove Retry-After plus the 1.1-second overload SLO"
fi
if [ "$(grep -F -x -c 'ssh_deletekeys: true' "$vm_harness" || true)" -ne 1 ] \
    || [ "$(grep -F -x -c 'ssh_keys:' "$vm_harness" || true)" -ne 1 ] \
    || [ "$(grep -F -x -c '  ed25519_private: |' "$vm_harness" || true)" -ne 1 ] \
    || [ "$(grep -F -x -c '  ed25519_public: |' "$vm_harness" || true)" -ne 1 ] \
    || ! grep -F -q 'host_private=$(sed '\''s/^/    /'\'' "$work/host-key")' "$vm_harness" \
    || ! grep -F -q 'host_public=$(sed '\''s/^/    /'\'' "$work/host-key.pub")' "$vm_harness" \
    || [ "$(grep -F -x -c '$host_private' "$vm_harness" || true)" -ne 1 ] \
    || [ "$(grep -F -x -c '$host_public' "$vm_harness" || true)" -ne 1 ] \
    || ! grep -F -q '$(cat "$work/host-key.pub")" >"$work/known_hosts"' "$vm_harness" \
    || [ "$(grep -F -c 'HostKeyAlgorithms=ssh-ed25519' "$vm_harness" || true)" -ne 2 ] \
    || [ "$(grep -F -c 'StrictHostKeyChecking=yes' "$vm_harness" || true)" -ne 2 ] \
    || [ "$(grep -F -c 'UserKnownHostsFile=$work/known_hosts' "$vm_harness" || true)" -ne 2 ] \
    || grep -F -q 'path: /etc/ssh/ssh_host_' "$vm_harness" \
    || ! grep -F -q 'install -m 0644 "$ssh_readiness_error"' "$vm_harness" \
    || ! grep -F -q 'cat "$evidence/ssh-readiness-last.stderr" >&2 || true' "$vm_harness" \
    || ! grep -F -q 'ssh-readiness-diagnostic.stderr' "$vm_harness" \
    || ! grep -F -q 'run_ssh -vv vaultlink-ci@127.0.0.1 true' "$vm_harness" \
    || ! grep -F -q 'ready_marker_present=' "$vm_harness" \
    || ! grep -F -q 'qemu_alive=' "$vm_harness" \
    || ! grep -F -q '&& [ "$qemu_alive" = true ]; then' "$vm_harness" \
    || ! grep -F -q 'tail -n 200 "$evidence/serial.log" >&2 || true' "$vm_harness" \
    || ! grep -F -q 'SSH readiness timed out after ${ssh_timeout}s' "$vm_harness" \
    || ! grep -F -q 'full-system QEMU exited before SSH readiness' "$vm_harness"; then
    report "distro VM SSH must use a cloud-init-managed ephemeral Ed25519 host key with fail-closed diagnostics"
fi
if [ "$(grep -F -x -c '  - label: vaultlink-data' "$vm_harness" || true)" -ne 1 ] \
    || [ "$(grep -F -x -c "  - [ 'LABEL=vaultlink-data', '/mnt', 'ext4', 'defaults,nofail', '0', '2' ]" "$vm_harness" || true)" -ne 1 ] \
    || [ "$(grep -F -x -c '    filesystem: ext4' "$vm_harness" || true)" -ne 1 ] \
    || [ "$(grep -F -x -c '    device: /dev/vdb' "$vm_harness" || true)" -ne 1 ] \
    || [ "$(grep -F -x -c '    overwrite: false' "$vm_harness" || true)" -ne 1 ] \
    || grep -F -q 'overwrite: true' "$vm_harness" \
    || grep -F -q 'vaultlink-storage' "$vm_harness" \
    || [ "$(grep -F -x -c '  - path: /usr/local/sbin/vaultlink-vm-bootstrap' "$vm_harness" || true)" -ne 1 ] \
    || [ "$(grep -F -x -c '    owner: root:root' "$vm_harness" || true)" -ne 1 ] \
    || [ "$(grep -F -x -c "    permissions: '0700'" "$vm_harness" || true)" -ne 1 ] \
    || [ "$(grep -F -x -c "$vm_bootstrap_runcmd" "$vm_harness" || true)" -ne 1 ] \
    || ! grep -F -q '[ "$storage_source" = /dev/vdb ] || mount_failure wrong_source' "$vm_harness" \
    || ! grep -F -q '[ "$storage_fstype" = ext4 ] || mount_failure wrong_mount_fstype' "$vm_harness" \
    || ! grep -F -q '[ "$storage_device_fstype" = ext4 ] || mount_failure wrong_device_fstype' "$vm_harness" \
    || ! grep -F -q '[ "$storage_label" = vaultlink-data ] || mount_failure wrong_label' "$vm_harness" \
    || ! grep -F -q 'findmnt -n -o SOURCE --mountpoint /mnt' "$vm_harness" \
    || ! grep -F -q 'VAULTLINK_VM_MOUNT_FAILED reason=%s' "$vm_harness" \
    || ! grep -F -q "grep -F -q 'VAULTLINK_VM_MOUNT_FAILED '" "$vm_harness" \
    || ! grep -F -q 'echo VAULTLINK_VM_STORAGE_READY | tee /dev/console' "$vm_harness" \
    || ! grep -F -q 'storage_ready_marker_present=' "$vm_harness" \
    || ! grep -F -q 'lsblk -o NAME,PATH,TYPE,FSTYPE,LABEL,MOUNTPOINTS || true' "$vm_harness" \
    || ! grep -F -q 'findmnt --raw -o SOURCE,TARGET,FSTYPE,OPTIONS || true' "$vm_harness" \
    || ! grep -F -q 'blkid || true' "$vm_harness" \
    || ! grep -F -q "sed -n '1,200p' /etc/fstab || true" "$vm_harness" \
    || ! grep -F -q 'cloud-init status --long || true' "$vm_harness" \
    || ! grep -F -q 'storage_source=%s\nstorage_filesystem=%s\nstorage_device_filesystem=%s\nstorage_label=%s' "$vm_guest_smoke" \
    || ! grep -F -q 'findmnt -n -o SOURCE --mountpoint /mnt' "$vm_guest_smoke" \
    || ! grep -F -q 'if [ "$storage_source" != /dev/vdb ]' "$vm_guest_smoke" \
    || ! grep -F -q '|| [ "$storage_fstype" != ext4 ]' "$vm_guest_smoke" \
    || ! grep -F -q '|| [ "$storage_device_fstype" != ext4 ]' "$vm_guest_smoke" \
    || ! grep -F -q '[ "$storage_label" != vaultlink-data ]' "$vm_guest_smoke"; then
    report "distro VM storage must use an ext4-safe label and fail closed with pre-install diagnostics"
fi
guest_storage_check_line=$(grep -n -F 'storage_source=$(findmnt -n -o SOURCE --mountpoint /mnt' "$vm_guest_smoke" \
    | cut -d: -f1 | head -n 1)
guest_package_inventory_line=$(grep -n -F 'live_vm_packages=$(mktemp)' "$vm_guest_smoke" \
    | cut -d: -f1 | head -n 1)
if [ -z "$guest_storage_check_line" ] || [ -z "$guest_package_inventory_line" ] \
    || [ "$guest_storage_check_line" -ge "$guest_package_inventory_line" ]; then
    report "distro VM storage identity must be verified before package inventory or mutation"
fi
guest_package_quiescence_line=$(grep -n -F '    quiesce_deb_package_maintenance' \
    "$vm_guest_smoke" | cut -d: -f1 | head -n 1)
if [ -z "$guest_package_quiescence_line" ] \
    || [ "$guest_package_quiescence_line" -ge "$guest_package_inventory_line" ] \
    || ! grep -F -q 'timeout 60 systemctl mask --runtime "$unit"' \
        "$vm_guest_smoke" \
    || ! grep -F -q 'timeout 60 systemctl stop "$timer"' \
        "$vm_guest_smoke" \
    || ! grep -F -q 'for unit in $automatic_services; do' \
        "$vm_guest_smoke" \
    || grep -E -q 'systemctl stop .*\.service' "$vm_guest_smoke" \
    || ! grep -F -q 'timeout 30 dpkg --audit' "$vm_guest_smoke" \
    || ! grep -F -q '[ ! -s "$audit_stdout" ] && [ ! -s "$audit_stderr" ]' \
        "$vm_guest_smoke" \
    || ! grep -F -q 'policy=runtime-mask-and-drain' "$vm_guest_smoke" \
    || ! grep -F -q 'lock_files_removed=false' "$vm_guest_smoke" \
    || grep -E -q 'rm[[:space:]].*/var/lib/dpkg/(lock|lock-frontend)' \
        "$vm_guest_smoke" \
    || ! grep -F -q 'package_quiescence=$evidence/runtime/package-manager-quiescence.env' \
        "$vm_harness" \
    || ! grep -F -q '= runtime-mask-and-drain ]' "$vm_harness" \
    || ! grep -F -q 'lock_files_removed)" = false ]' "$vm_harness"; then
    report "Debian and Ubuntu VM package tests must runtime-mask and drain automatic maintenance without deleting locks"
fi
if grep -F -q 'sleep 31' "$vm_runtime_smoke" \
    || ! grep -F -q 'guard_wait_seconds=240' "$vm_runtime_smoke" \
    || ! grep -F -q 'runtime-guard-stability.env' "$vm_runtime_smoke" \
    || ! grep -F -q '[ "$guard_restarts_after" -le 3 ]' "$vm_runtime_smoke" \
    || ! grep -F -q '[ "$guard_settled" = true ]' "$vm_runtime_smoke" \
    || ! grep -F -q 'runtime_guard_wait=$evidence/runtime/runtime-guard-wait.env' \
        "$vm_harness" \
    || ! grep -F -q 'runtime_guard_elapsed" -le 240' "$vm_harness" \
    || ! grep -F -q 'Runtime-integrity restart-limit evidence is' \
        docs/GITHUB-HOSTED-RUNNERS.md \
    || ! grep -F -q 'fixed 240-second ceiling' docs/PACKAGING.md \
    || ! grep -F -q 'restart limit reached a stable terminal state' \
        docs/RELEASE-CHECKLIST-0.6.0.md; then
    report "the runtime-integrity VM gate must prove a bounded stable restart-limit failure without assuming emulator speed"
fi
if ! grep -F -q 'rm -f "$identity_backup_dir/$identity_file"' tools/package-container-smoke.sh \
    || ! grep -F -q 'rmdir "$identity_backup_dir"' tools/package-container-smoke.sh \
    || [ "$(grep -F -x -c 'identity_backup_dir=' tools/package-container-smoke.sh || true)" -ne 2 ] \
    || ! grep -F -q 'package lifecycle smoke did not preserve the service identity' tools/package-offline-smoke.sh; then
    report "package smoke must retire probe-only identity rollback before preserving the installed service account"
fi

tcg_timeout_manager=tools/manage-tcg-device-timeout.sh
tcg_timeout_cleanup=tools/clear-tcg-device-timeout.sh
root_capacity_check=tools/check-vm-root-capacity.sh
if ! grep -F -q 'libguestfs-tools' deploy/docker/Dockerfile.qemu-runner \
    || ! grep -F -q 'linux-image-virtual' deploy/docker/Dockerfile.qemu-runner \
    || ! grep -F -q 'policycoreutils' deploy/docker/Dockerfile.qemu-runner \
    || ! grep -F -q 'guestfs_path=$(guestfish get-path)' deploy/docker/Dockerfile.qemu-runner \
    || ! grep -F -q 'packages-vaultlink-selinux' deploy/docker/Dockerfile.qemu-runner \
    || ! grep -F -q 'test ! -e "$fragment" && test ! -L "$fragment"' deploy/docker/Dockerfile.qemu-runner \
    || ! grep -F -q "stat -c '%u:%g:%a' \"\$fragment\"" deploy/docker/Dockerfile.qemu-runner \
    || ! grep -F -q 'command -v guestfish' tools/verify-qemu-runner.sh \
    || ! grep -F -q 'selinux_fragment=$supermin_directory/packages-vaultlink-selinux' tools/verify-qemu-runner.sh \
    || ! grep -F -q 'LIBGUESTFS_CACHEDIR=$work/libguestfs-cache' tools/verify-qemu-runner.sh \
    || ! grep -F -q "dpkg-query -W -f='\${Status}' policycoreutils" tools/verify-qemu-runner.sh \
    || ! grep -F -q 'guestfish-probe.img=fs:ext4:64M' tools/verify-qemu-runner.sh \
    || ! grep -F -q 'feature-available selinuxrelabel' tools/verify-qemu-runner.sh \
    || ! grep -F -q 'LIBGUESTFS_BACKEND_SETTINGS=force_tcg' tools/verify-qemu-runner.sh \
    || ! grep -F -q 'guestfish get-backend-settings' tools/verify-qemu-runner.sh \
    || ! grep -F -q 'LIBGUESTFS_BACKEND_SETTINGS=force_tcg' "$tcg_timeout_manager" \
    || ! grep -F -q 'guestfish get-backend-settings' "$tcg_timeout_manager" \
    || ! grep -F -q 'DefaultDeviceTimeoutSec=5min' "$tcg_timeout_manager" \
    || ! grep -F -q 'DefaultDeviceTimeoutSec=5min' "$tcg_timeout_cleanup" \
    || ! grep -F -q 'cleanup=/usr/local/bin/vaultlink-clear-tcg-device-timeout' "$tcg_timeout_manager" \
    || ! grep -F -q 'cleanup=/usr/local/bin/vaultlink-clear-tcg-device-timeout' "$tcg_timeout_cleanup" \
    || ! grep -F -q 'tcg_cleanup_command=/usr/local/bin/vaultlink-clear-tcg-device-timeout' "$vm_provisioner" \
    || ! grep -F -q 'tcg_cleanup_command=/usr/local/bin/vaultlink-clear-tcg-device-timeout' tools/run-distro-vm-test.sh \
    || ! grep -F -q 'rmdir -- /etc/systemd/system.conf.d' "$tcg_timeout_cleanup" \
    || ! grep -F -q 'rm -f -- "$cleanup"' "$tcg_timeout_cleanup" \
    || ! grep -F -q 'state_file=$image.vaultlink-tcg-state' "$tcg_timeout_manager" \
    || ! grep -F -q 'clean-missing-directory' "$tcg_timeout_manager" \
    || ! grep -F -q 'clean-existing-directory' "$tcg_timeout_manager" \
    || ! grep -F -q 'feature-available selinuxrelabel' "$tcg_timeout_manager" \
    || ! grep -F -q 'is-dir /etc/systemd' "$tcg_timeout_manager" \
    || ! grep -F -q 'is-symlink /usr/local/bin' "$tcg_timeout_manager" \
    || ! grep -F -q 'is-dir /usr/local/bin' "$tcg_timeout_manager" \
    || ! grep -F -q 'report_unexpected_state' "$tcg_timeout_manager" \
    || ! grep -F -q 'state_boolean_lines=' "$tcg_timeout_manager" \
    || [ "$(grep -F -c -- '--format=qcow2' "$tcg_timeout_manager" || true)" -ne 2 ] \
    || ! grep -F -q 'selinux-relabel $selinux_policy $override force:true' "$tcg_timeout_manager" \
    || ! grep -F -q 'selinux-relabel $selinux_policy $cleanup force:true' "$tcg_timeout_manager" \
    || ! grep -F -q 'selinux-relabel $selinux_policy /etc/systemd/system.conf.d force:true' "$tcg_timeout_manager" \
    || ! grep -F -q 'getxattr /etc/systemd/system.conf.d security.selinux' "$tcg_timeout_manager" \
    || ! grep -F -q 'getxattr $override security.selinux' "$tcg_timeout_manager" \
    || [ "$(grep -F -c 'manage-tcg-device-timeout.sh inject' "$vm_provisioner" || true)" -ne 2 ] \
    || [ "$(grep -F -c 'manage-tcg-device-timeout.sh assert-clean' "$vm_provisioner" || true)" -ne 2 ] \
    || ! grep -F -q 'manage-tcg-device-timeout.sh inject' tools/run-distro-vm-test.sh \
    || ! grep -F -q 'manage-tcg-device-timeout.sh assert-clean' tools/run-distro-vm-test.sh \
    || ! grep -F -q 'reviewed_virtual_size=8589934592' "$vm_provisioner" \
    || ! grep -F -q 's == 8589934592' tools/run-distro-vm-test.sh \
    || ! grep -F -q 'growpart:' "$vm_provisioner" \
    || ! grep -F -q 'resize_rootfs: true' "$vm_provisioner" \
    || ! grep -F -q 'minimum_root_size=6979321856' "$vm_provisioner" \
    || ! grep -F -q 'vaultlink-check-root-capacity $minimum_root_size $minimum_root_available' "$vm_provisioner" \
    || ! grep -F -q '/tmp/check-vm-root-capacity.sh 6979321856 1073741824' tools/distro-vm-guest-smoke.sh \
    || ! grep -F -q 'virtual_size=8589934592' .github/workflows/distro-vms.yml \
    || ! grep -F -q 'test "$(wc -l <"vm-test/$TARGET_ID/guest-image.env")" -eq 7' .github/workflows/distro-vms.yml \
    || ! grep -F -q 'cold_boot_verified=true' .github/workflows/distro-vms.yml \
    || ! grep -F -q 'provision_acceleration=(kvm|tcg)' .github/workflows/distro-vms.yml \
    || ! grep -F -q 'provision_acceleration=tcg' .github/workflows/distro-vms.yml \
    || ! grep -F -q 'guest.qcow2.virtual-size' .github/workflows/distro-vm-images-refresh.yml \
    || ! grep -F -q 'virtual_size=$(cat vm-build/guest.qcow2.virtual-size)' .github/workflows/distro-vm-images-refresh.yml \
    || ! grep -F -q 'docker image rm "$qemu_runner"' .github/workflows/distro-vm-images-refresh.yml \
    || ! grep -F -q 'docker image rm "$VM_IMAGE"' .github/workflows/distro-vms.yml \
    || ! grep -F -q 'host-storage.txt' .github/workflows/distro-vm-images-refresh.yml \
    || ! grep -F -q 'host-storage.txt' .github/workflows/distro-vms.yml \
    || ! grep -F -q 'qemu-img check "$work/overlay.qcow2"' "$vm_provisioner" \
    || ! grep -F -q "inputs.target_id == 'fedora44-arm64' && 240 || inputs.target_id == 'ubuntu2604-arm64' && 150 || 90" .github/workflows/distro-vm-images-refresh.yml \
    || ! grep -F -q 'if [ "$target_id" = ubuntu2604-arm64 ]; then' "$vm_provisioner" \
    || [ "$(grep -F -c 'provision_timeout=5400' "$vm_provisioner" || true)" -ne 2 ] \
    || ! grep -F -q 'cold_boot_timeout=3600' "$vm_provisioner" \
    || ! grep -F -q 'ssh_timeout=3600' tools/run-distro-vm-test.sh \
    || ! grep -F -q 'grep -F -q VAULTLINK_VM_READY "$evidence/serial.log"' tools/run-distro-vm-test.sh \
    || ! grep -F -q 'full-system QEMU exited with status' tools/run-distro-vm-test.sh \
    || ! grep -F -q 'root filesystem is smaller than the reviewed minimum' "$root_capacity_check"; then
    report "guest images must enforce reviewed capacity and a removable Fedora arm64 TCG device-timeout override"
fi
if grep -F -q '/usr/local/sbin/vaultlink-clear-tcg-device-timeout' \
    "$tcg_timeout_manager" "$tcg_timeout_cleanup" "$vm_provisioner" \
    tools/run-distro-vm-test.sh; then
    report "the Fedora TCG cleanup helper must not traverse the /usr/local/sbin compatibility symlink"
fi
if grep -F -q 'supermin.d/packages' deploy/docker/Dockerfile.qemu-runner \
    || grep -F -q 'supermin.d/hostfiles' deploy/docker/Dockerfile.qemu-runner; then
    report "the QEMU runner must extend Supermin additively instead of modifying vendor appliance inputs"
fi
if ! grep -F -q "arch_time_sync_command='systemctl mask systemd-time-wait-sync.service" "$vm_provisioner" \
    || ! grep -F -q "arch_time_sync_verify='test -L /etc/systemd/system/systemd-time-wait-sync.service" "$vm_provisioner" \
    || ! grep -F -q 'readlink /etc/systemd/system/systemd-time-wait-sync.service' tools/distro-vm-guest-smoke.sh \
    || ! grep -F -q 'systemctl is-enabled systemd-time-wait-sync.service | grep -F -x -q masked' tools/distro-vm-guest-smoke.sh \
    || ! grep -F -q 'systemctl show -p LoadState --value systemd-time-wait-sync.service' tools/distro-vm-guest-smoke.sh \
    || ! grep -F -q 'systemctl is-enabled systemd-timesyncd.service' tools/distro-vm-guest-smoke.sh \
    || ! grep -F -q 'clock_source=qemu-rtc' tools/run-distro-vm-test.sh; then
    report "the egressless Arch test guest must not block indefinitely on external time synchronization"
fi

package_build_job=$(awk '
    $0 == "  build:" { selected = 1 }
    selected && /^  [[:alnum:]_-]+:$/ && $0 != "  build:" { exit }
    selected { print }
' "$package_workflow")
package_smoke_job=$(awk '
    $0 == "  smoke:" { selected = 1 }
    selected && /^  [[:alnum:]_-]+:$/ && $0 != "  smoke:" { exit }
    selected { print }
' "$package_workflow")
package_native_smoke_step=$(printf '%s\n' "$package_smoke_job" | awk '
    $0 == "      - name: Run lifecycle, API, migration, rollback, and native load gates offline" {
        selected = 1
    }
    selected && /^      - name:/ \
        && $0 != "      - name: Run lifecycle, API, migration, rollback, and native load gates offline" {
        exit
    }
    selected { print }
')
package_offline_evidence_upload=$(printf '%s\n' "$package_smoke_job" | awk '
    $0 == "      - name: Upload offline smoke evidence" { selected = 1 }
    selected { print }
    selected && /^          retention-days:/ { exit }
')
if [ ! -f "$package_native_load_smoke" ] || [ -L "$package_native_load_smoke" ] \
    || ! printf '%s\n' "$package_smoke_job" \
        | grep -F -q 'runs-on: ${{ matrix.runner }}' \
    || ! printf '%s\n' "$package_smoke_job" \
        | grep -F -q 'timeout-minutes: 120' \
    || ! printf '%s\n' "$package_smoke_job" \
        | grep -F -q "test \"\$(uname -m)\" = '${literal_dollar}{{ matrix.uname }}'" \
    || ! printf '%s\n' "$package_smoke_job" \
        | grep -F -q 'BUILDER_IMAGE: ${{ matrix.builder_image }}' \
    || ! printf '%s\n' "$package_smoke_job" \
        | grep -F -q 'name: vaultlink-package-${{ matrix.id }}' \
    || ! printf '%s\n' "$package_smoke_job" \
        | grep -F -q 'docker run --rm --network none --user root' \
    || ! printf '%s\n' "$package_smoke_job" \
        | grep -F -q -- '--mount type=volume,destination=/mnt/storage' \
    || ! printf '%s\n' "$package_smoke_job" \
        | grep -F -q 'sh tools/package-offline-smoke.sh' \
    || ! printf '%s\n' "$package_smoke_job" \
        | grep -F -q '"/work/offline-smoke/$TARGET_ID/native-load"' \
    || ! printf '%s\n' "$package_offline_evidence_upload" \
        | grep -F -q 'offline-smoke/${{ matrix.id }}/native-load/**' \
    || ! printf '%s\n' "$package_offline_evidence_upload" \
        | grep -F -q '        if: always()' \
    || ! printf '%s\n' "$package_offline_evidence_upload" \
        | grep -F -q '          if-no-files-found: error' \
    || ! grep -F -q 'sh tools/package-container-smoke.sh "$target_id" "$version" "$package"' \
        "$package_offline_smoke" \
    || ! grep -F -q 'sh tools/package-native-load-smoke.sh' "$package_offline_smoke" \
    || ! grep -F -q '"$target_id" "$version" "$package" "$api_work" "$native_load_evidence"' \
        "$package_offline_smoke"; then
    report "all nine exact packages must run the strict native load gate offline on their matching managed architecture and upload full evidence"
fi
if ! printf '%s\n' "$package_native_smoke_step" \
        | grep -F -q 'host_nproc=$(nproc)' \
    || ! printf '%s\n' "$package_native_smoke_step" \
        | grep -F -q '[[ "$host_nproc" =~ ^[0-9]+$ && "$host_nproc" -ge 4 ]]' \
    || ! printf '%s\n' "$package_native_smoke_step" \
        | grep -F -q "host_mem_total_kib=\$(awk '/^MemTotal:/ { print \$2; exit }' /proc/meminfo)" \
    || ! printf '%s\n' "$package_native_smoke_step" \
        | grep -F -q '&& "$host_mem_total_kib" -ge 8388608 ]]' \
    || ! printf '%s\n' "$package_native_smoke_step" \
        | grep -F -q 'taskset --cpu-list 0-3 true' \
    || ! printf '%s\n' "$package_native_smoke_step" \
        | grep -F -q "docker_nproc=\$(docker info --format '{{.NCPU}}')" \
    || ! printf '%s\n' "$package_native_smoke_step" \
        | grep -F -q '[[ "$docker_nproc" =~ ^[0-9]+$ && "$docker_nproc" -ge 4 ]]' \
    || [ "$(printf '%s\n' "$package_native_smoke_step" \
        | grep -F -c -- '--cpuset-cpus 0-3' || true)" -ne 1 ] \
    || [ "$(printf '%s\n' "$package_native_smoke_step" \
        | grep -F -c -- '--cpuset-cpus' || true)" -ne 1 ] \
    || [ "$(printf '%s\n' "$package_native_smoke_step" \
        | grep -F -c -- '--tmpfs /mnt/load-client:rw,nosuid,nodev,noexec,size=4g,mode=0700' \
        || true)" -ne 1 ] \
    || [ "$(printf '%s\n' "$package_native_smoke_step" \
        | grep -F -c -- '--tmpfs' || true)" -ne 1 ] \
    || [ "$(printf '%s\n' "$package_native_smoke_step" \
        | grep -F -c -- '--env VAULTLINK_NATIVE_' || true)" -ne 4 ] \
    || ! printf '%s\n' "$package_native_smoke_step" \
        | grep -F -q -- '--env VAULTLINK_NATIVE_HOST_NPROC="$host_nproc"' \
    || ! printf '%s\n' "$package_native_smoke_step" \
        | grep -F -q -- '--env VAULTLINK_NATIVE_HOST_MEM_TOTAL_KIB="$host_mem_total_kib"' \
    || ! printf '%s\n' "$package_native_smoke_step" \
        | grep -F -q -- '--env VAULTLINK_NATIVE_DOCKER_NPROC="$docker_nproc"' \
    || ! printf '%s\n' "$package_native_smoke_step" \
        | grep -F -q -- '--env VAULTLINK_NATIVE_CONTAINER_CPUSET=0-3'; then
    report "the native package Docker gate must qualify at least four CPUs and 8 GiB RAM, use exactly CPUs 0-3 and one hardened dedicated 4-GiB client tmpfs, and pass the qualification into evidence"
fi
package_lifecycle_line=$(grep -n -F \
    'sh tools/package-container-smoke.sh "$target_id" "$version" "$package"' \
    "$package_offline_smoke" | cut -d: -f1 | head -n 1)
package_native_load_line=$(grep -n -F 'sh tools/package-native-load-smoke.sh' \
    "$package_offline_smoke" | cut -d: -f1 | head -n 1)
if [ -z "$package_lifecycle_line" ] || [ -z "$package_native_load_line" ] \
    || [ "$package_lifecycle_line" -ge "$package_native_load_line" ]; then
    report "native load must execute the package payload only after the exact package lifecycle installation"
fi
if ! grep -F -q '[ "$evidence" = "/work/offline-smoke/$target_id/native-load" ]' \
        "$package_native_load_smoke" \
    || ! grep -F -q 'python3 tools/package-targets.py validate' "$package_native_load_smoke" \
    || ! grep -F -q 'package_database_snapshot "$evidence/package-database-before.env"' \
        "$package_native_load_smoke" \
    || ! grep -F -q 'package_database_snapshot "$evidence/package-database-after.env"' \
        "$package_native_load_smoke" \
    || ! grep -F -q 'cmp -s "$evidence/package-database-before.env"' \
        "$package_native_load_smoke" \
    || ! grep -F -q 'cmp -s "$candidate" "$live_binary"' "$package_native_load_smoke" \
    || ! grep -F -q 'sha256sum -c vaultlink.sha256' "$package_native_load_smoke" \
    || ! grep -F -q 'setpriv --reuid="$vaultlink_uid" --regid="$vaultlink_gid" --init-groups' \
        "$package_native_load_smoke" \
    || ! grep -F -q 'VAULTLINK_PROCESS_PID="$service_pid"' "$package_native_load_smoke" \
    || ! grep -F -q 'VAULTLINK_PROCESS_UID="$vaultlink_uid"' "$package_native_load_smoke" \
    || ! grep -F -q 'VAULTLINK_PROCESS_GID="$vaultlink_gid"' "$package_native_load_smoke" \
    || ! grep -F -q 'VAULTLINK_EXPECTED_BINARY_PATH="$live_binary"' "$package_native_load_smoke" \
    || ! grep -F -q 'VAULTLINK_EXPECTED_BINARY_SHA256="$live_sha256"' "$package_native_load_smoke" \
    || ! grep -F -q 'LOAD_P95_POLICY=strict' "$package_native_load_smoke" \
    || ! grep -F -q 'LOAD_CONNECT_TIMEOUT_SECONDS=5' "$package_native_load_smoke" \
    || ! grep -F -q 'LOAD_METADATA_MAX_TIME_SECONDS=30' "$package_native_load_smoke" \
    || ! grep -F -q 'LOAD_TRANSFER_MAX_TIME_SECONDS=300' "$package_native_load_smoke" \
    || ! grep -F -q 'LOAD_PROFILE_READY_TIMEOUT_SECONDS=10' "$package_native_load_smoke" \
    || ! grep -F -q 'LOAD_ADMISSION_READY_TIMEOUT_SECONDS=10' "$package_native_load_smoke" \
    || ! grep -F -q 'LOAD_ADMISSION_HOLDER_MAX_TIME_SECONDS=30' "$package_native_load_smoke" \
    || ! grep -F -q 'LOAD_ADMISSION_PROBE_MAX_TIME_SECONDS=5' "$package_native_load_smoke" \
    || ! grep -F -q 'admission_download_token=$(create_share vaultlink-load/sparse-50GiB.bin download_only)' "$package_native_load_smoke" \
    || ! grep -F -q 'range_download_token=$(create_share vaultlink-load/sparse-50GiB.bin download_only)' "$package_native_load_smoke" \
    || ! grep -F -q 'ADMISSION_DOWNLOAD_TOKEN=$admission_download_token' "$package_native_load_smoke" \
    || ! grep -F -q 'RANGE_DOWNLOAD_TOKEN=$range_download_token' "$package_native_load_smoke" \
    || ! grep -F -q 'UPLOAD_TOKEN_5=$upload_token_5' "$package_native_load_smoke"; then
    report "native performance must use the exact installed package payload, package database, unprivileged PID, and normal strict timeouts"
fi
if [ ! -f "$native_storage_qualification" ] \
    || [ -L "$native_storage_qualification" ] \
    || ! grep -F -q 'storage_qualification_helper=$repo_root/tools/qualify-native-load-storage.py' \
        "$package_native_load_smoke" \
    || ! grep -F -q 'native_stage=storage_qualification' "$package_native_load_smoke" \
    || ! grep -F -q '/mnt/storage "$evidence/storage-qualification.env"' \
        "$package_native_load_smoke" \
    || ! grep -F -q "grep -F -x -q 'qualification=pass'" \
        "$package_native_load_smoke" \
    || ! grep -F -q 'STORAGE_ROOT = Path("/mnt/storage")' \
        "$native_storage_qualification" \
    || ! grep -F -q 'WRITER_THREADS = 4' "$native_storage_qualification" \
    || ! grep -F -q 'TRANSACTIONS_PER_WRITER = 32' "$native_storage_qualification" \
    || ! grep -F -q 'MINIMUM_READER_QUERIES = 256' "$native_storage_qualification" \
    || ! grep -F -q 'WRITER_P95_LIMIT_MS = 1_000.0' "$native_storage_qualification" \
    || ! grep -F -q 'WRITER_MAX_LIMIT_MS = 5_000.0' "$native_storage_qualification" \
    || ! grep -F -q 'READER_P95_LIMIT_MS = 250.0' "$native_storage_qualification" \
    || ! grep -F -q 'READER_MAX_LIMIT_MS = 2_000.0' "$native_storage_qualification" \
    || ! grep -F -q 'CHECKPOINT_LIMIT_MS = 5_000.0' "$native_storage_qualification" \
    || ! grep -F -q 'WALL_LIMIT_MS = 30_000.0' "$native_storage_qualification" \
    || ! grep -F -q 'PRAGMA journal_mode=WAL' "$native_storage_qualification" \
    || ! grep -F -q 'PRAGMA synchronous=FULL' "$native_storage_qualification" \
    || ! grep -F -q 'synchronous_mode == 2' "$native_storage_qualification" \
    || ! grep -F -q 'PRAGMA integrity_check' "$native_storage_qualification" \
    || ! grep -F -q 'next(storage.iterdir(), None)' "$native_storage_qualification" \
    || ! grep -F -q 'barrier.abort()' "$native_storage_qualification" \
    || ! grep -F -q 'shutil.rmtree(probe)' "$native_storage_qualification"; then
    report "native package timing must fail closed on an evidenced four-writer SQLite WAL and concurrent-reader storage qualification"
fi
if ! grep -F -q 'fn queued_transfer_writers_do_not_exhaust_persistent_read_pool()' \
        src/db/tests/required_audit.rs \
    || ! grep -F -q 'cargo test --locked --all-targets' .github/workflows/ci.yml; then
    report "CI must execute the behavioral transfer-writer fairness and read-capacity regression test"
fi
for native_resource_contract_line in \
    'host_nproc=${VAULTLINK_NATIVE_HOST_NPROC:-}' \
    'host_mem_total_kib=${VAULTLINK_NATIVE_HOST_MEM_TOTAL_KIB:-}' \
    'docker_nproc=${VAULTLINK_NATIVE_DOCKER_NPROC:-}' \
    'requested_container_cpu_set=${VAULTLINK_NATIVE_CONTAINER_CPUSET:-}' \
    '[ "$host_nproc" -ge 4 ]' \
    '[ "$host_mem_total_kib" -ge 8388608 ]' \
    '[ "$docker_nproc" -ge 4 ]' \
    '[ "$requested_container_cpu_set" = "$container_cpu_set" ]' \
    'container_cpu_set=0-3' \
    'service_cpu_set=0-1' \
    'load_client_cpu_set=2-3' \
    '[ "$container_nproc" -eq 4 ]' \
    "'s/^Cpus_allowed_list:[[:space:]]*//p' /proc/self/status" \
    '[ "$container_effective_cpu_set" = "$container_cpu_set" ]' \
    'taskset --cpu-list "$service_cpu_set" true' \
    'load_client_probe_cpu_set=$(taskset --cpu-list "$load_client_cpu_set" sh -c' \
    '[ "$load_client_probe_cpu_set" = "$load_client_cpu_set" ]' \
    'load_client_mount=/mnt/load-client' \
    '[ ! -d "$load_client_mount" ] || [ -L "$load_client_mount" ]' \
    '[ "$(stat -c '\''%u:%g:%a'\'' "$load_client_mount")" = 0:0:700 ]' \
    '[ -z "$(find "$load_client_mount" -mindepth 1 -maxdepth 1 -print -quit)" ]' \
    'findmnt -n -o TARGET --target "$load_client_mount"' \
    '[ "$load_client_mount_target" = "$load_client_mount" ]' \
    'findmnt -n -o FSTYPE --target "$load_client_mount"' \
    '[ "$load_client_mount_fstype" = tmpfs ]' \
    'findmnt -n -o SOURCE --target "$load_client_mount"' \
    '[ "$load_client_mount_source" = tmpfs ]' \
    'findmnt -n -o OPTIONS --target "$load_client_mount"' \
    'for required_mount_option in rw nosuid nodev noexec; do' \
    'df -B1 --output=size,avail "$load_client_mount"' \
    '[ "$load_client_capacity_bytes" -ge 4294967296 ]' \
    '[ "$load_client_available_bytes" -ge 4294967296 ]' \
    'runtime_base="/mnt/storage/vaultlink-native-load-$target_id"' \
    'load_client_workspace=$load_client_mount/work' \
    'load_log=$load_client_workspace/load.log' \
    'cookie=$load_client_workspace/cookies.txt' \
    'load_tmp=$load_client_mount/tmp' \
    'TMPDIR="$load_tmp"' \
    'taskset --cpu-list "$load_client_cpu_set" sh tools/load-test.sh' \
    '>"$evidence/resource-isolation.env"' \
    '"host_nproc=$host_nproc"' \
    '"host_mem_total_kib=$host_mem_total_kib"' \
    '"docker_nproc=$docker_nproc"' \
    '"requested_container_cpu_set=$requested_container_cpu_set"' \
    '"container_nproc=$container_nproc"' \
    '"container_cpu_set=$container_effective_cpu_set"' \
    '"service_cpu_set=$service_effective_cpu_set"' \
    '"load_generator_cpu_set=$load_client_probe_cpu_set"' \
    '"load_client_mount_target=$load_client_mount_target"' \
    '"load_client_mount_source=$load_client_mount_source"' \
    '"load_client_mount_fstype=$load_client_mount_fstype"' \
    '"load_client_mount_options=$load_client_mount_options"' \
    '"load_client_capacity_bytes=$load_client_capacity_bytes"' \
    '"load_client_available_bytes=$load_client_available_bytes"' \
    "'load_client_initial_state=empty'" \
    "'load_client_owner=0:0'" \
    "'load_client_mode=700'" \
    "'load_client_tmpdir=/mnt/load-client/tmp'" \
    "'load_client_cookie_path=/mnt/load-client/work/cookies.txt'" \
    "'server_storage_parent=/mnt/storage'"; do
    grep -F -q "$native_resource_contract_line" "$package_native_load_smoke" \
        || report "native package resource isolation is missing hard contract: $native_resource_contract_line"
done
if ! grep -F -A1 "taskset --cpu-list \"\$service_cpu_set\" \\" \
        "$package_native_load_smoke" \
        | grep -F -q 'setpriv --reuid="$vaultlink_uid" --regid="$vaultlink_gid" --init-groups --' \
    || [ "$(grep -F -c 'sh tools/load-test.sh' "$package_native_load_smoke" || true)" -ne 1 ] \
    || [ "$(grep -F -c 'TMPDIR=' "$package_native_load_smoke" || true)" -ne 1 ] \
    || grep -F -q 'load_tmp=$runtime_base' "$package_native_load_smoke" \
    || grep -F -q 'cookie=$runtime_base' "$package_native_load_smoke" \
    || grep -F -q '>"$runtime_base/load.log"' "$package_native_load_smoke" \
    || ! grep -F -q 'package service CPU isolation changed during native load' \
        "$package_native_load_smoke"; then
    report "native package timing must pin the server to CPUs 0-1, pin the load client to CPUs 2-3, keep client temporary I/O off server storage, and recheck service affinity"
fi
if [ ! -f "$direct_process_identity" ] || [ -L "$direct_process_identity" ] \
    || ! grep -F -q 'setpriv --reuid="$direct_process_uid" --regid="$direct_process_gid"' \
        "$load_test" \
    || ! grep -F -q -- '--clear-groups --no-new-privs -- sh "$direct_identity_helper"' \
        "$load_test" \
    || ! grep -F -q 'VAULTLINK_PROCESS_GID' "$load_test" \
    || ! grep -F -q 'setpriv --reuid="$vaultlink_uid" --regid="$vaultlink_gid"' \
        "$package_native_load_smoke" \
    || ! grep -F -q -- '--clear-groups --no-new-privs -- sh "$process_identity_helper"' \
        "$package_native_load_smoke" \
    || grep -F -q 'readlink "/proc/$service_pid/exe"' "$package_native_load_smoke" \
    || grep -F -q 'sha256sum "/proc/$service_pid/exe"' "$package_native_load_smoke" \
    || ! grep -F -q '[ "$(id -u)" = "$expected_uid" ]' "$direct_process_identity" \
    || ! grep -F -q '[ "$(id -g)" = "$expected_gid" ]' "$direct_process_identity" \
    || ! grep -F -q 'target process UID/GID does not match' "$direct_process_identity" \
    || ! grep -F -q 'identity helper retained supplementary groups' "$direct_process_identity" \
    || ! grep -F -q 'identity helper retained privileges' "$direct_process_identity" \
    || ! grep -F -q '$2 != "0000000000000000"' "$direct_process_identity" \
    || ! grep -F -q '$2 != "1"' "$direct_process_identity" \
    || ! grep -F -q 'starttime_before=$(process_starttime)' "$direct_process_identity" \
    || ! grep -F -q 'observed_path=$(readlink "/proc/$pid/exe")' "$direct_process_identity" \
    || ! grep -F -q 'observed_sha256=$(sha256sum "/proc/$pid/exe"' "$direct_process_identity" \
    || ! grep -F -q 'starttime_after=$(process_starttime)' "$direct_process_identity" \
    || ! grep -F -q '[ "$starttime_after" = "$starttime_before" ]' "$direct_process_identity"; then
    report "direct-PID package verification must use the fixed fail-closed same-UID/GID helper with no supplementary groups"
fi
if grep -E -q -- '--privileged|--cap-add([=[:space:]]|$)|--pid([=[:space:]]+)host|/proc:/proc|source=/proc([,[:space:]]|$)|destination=/proc([,[:space:]]|$)|target=/proc([,[:space:]]|$)|:/proc([/:,[:space:]]|$)' \
        "$package_workflow"; then
    report "the package gate must not gain privilege, capabilities, host PID access, or a host proc bind"
fi
native_failure_service_line=$(grep -n -F \
    'write_redacted_tail "$runtime_base/service.log"' \
    "$package_native_load_smoke" | cut -d: -f1 | head -n 1)
native_failure_load_line=$(grep -n -F 'write_redacted_tail "$load_log"' \
    "$package_native_load_smoke" | cut -d: -f1 | head -n 1)
native_runtime_remove_line=$(grep -n -F 'rm -rf -- "$runtime_base"' \
    "$package_native_load_smoke" | cut -d: -f1 | head -n 1)
native_client_workspace_remove_line=$(grep -n -F 'rm -rf -- "$load_client_workspace"' \
    "$package_native_load_smoke" | cut -d: -f1 | head -n 1)
if ! grep -F -q 'if [ "$native_status" -ne 0 ]; then' "$package_native_load_smoke" \
    || ! grep -F -q 'failure-status.env' "$package_native_load_smoke" \
    || ! grep -F -q 'write_redacted_tail "$runtime_base/service.log"' \
        "$package_native_load_smoke" \
    || ! grep -F -q '"$evidence/failure-service.log" 200' \
        "$package_native_load_smoke" \
    || ! grep -F -q 'write_redacted_tail "$load_log"' \
        "$package_native_load_smoke" \
    || ! grep -F -q '"$evidence/failure-load.log" 200' \
        "$package_native_load_smoke" \
    || ! grep -F -q 'known_secrets = sorted(' "$package_native_load_smoke" \
    || ! grep -F -q 'text = text.replace(secret, "[REDACTED]")' \
        "$package_native_load_smoke" \
    || ! grep -F -q 'NATIVE_REDACT_RANGE_DOWNLOAD_TOKEN' \
        "$package_native_load_smoke" \
    || ! grep -F -q 'NATIVE_REDACT_UPLOAD_TOKEN_5' \
        "$package_native_load_smoke" \
    || ! grep -F -q 'authorization\s*:\s*bearer' "$package_native_load_smoke" \
    || ! grep -F -q '(?:set-)?cookie' "$package_native_load_smoke" \
    || ! grep -F -q 'x-csrf-token' "$package_native_load_smoke" \
    || ! grep -F -q '(?:token|preview_token|csrf_token)' \
        "$package_native_load_smoke" \
    || ! grep -F -q 'runtime-policy.env' "$package_native_load_smoke" \
    || grep -F -q '"$evidence/runtime-config.toml"' "$package_native_load_smoke" \
    || [ -z "$native_failure_service_line" ] \
    || [ -z "$native_failure_load_line" ] \
    || [ -z "$native_runtime_remove_line" ] \
    || [ -z "$native_client_workspace_remove_line" ] \
    || [ "$native_failure_service_line" -ge "$native_runtime_remove_line" ] \
    || [ "$native_failure_load_line" -ge "$native_client_workspace_remove_line" ]; then
    report "native package failures must upload bounded secret-redacted diagnostics before deleting private runtime state"
fi
for native_result_line in \
    'assert_field "$result" supervision_mode direct_pid' \
    'assert_field "$result" metadata_p95_policy strict' \
    'assert_field "$result" metadata_p95_limit_seconds 2.000' \
    'assert_field "$result" metadata_p95_within_limit true' \
    'assert_field "$result" metadata_p95_enforced true' \
    'assert_field "$result" metadata_clients 100' \
    'assert_field "$result" metadata_requests 2000' \
    'assert_field "$result" metadata_capacity_retry_limit_per_client 3' \
    'assert_field "$result" metadata_capacity_retry_after_seconds 1' \
    'assert_field "$result" metadata_capacity_response_limit_seconds 1.100' \
    'assert_field "$result" range_streams 40' \
    'assert_field "$result" range_share_count 3' \
    'assert_field "$result" range_streams_per_share_max 14' \
    'assert_field "$result" uploads 10' \
    'assert_field "$result" upload_share_count 5' \
    'assert_field "$result" uploads_per_share 2' \
    'assert_field "$result" upload_integrity server_readback' \
    'assert_field "$load_command" stage complete' \
    'assert_field "$load_command" exit_status 0' \
    'assert_field "$profile" metadata_status 0' \
    'assert_field "$profile" download_status 0' \
    'assert_field "$profile" upload_status 0' \
    'assert_field "$profile" rss_status 0' \
    'assert_field "$profile" metadata_rows 2000' \
    'assert_field "$profile" range_rows 40' \
    'assert_field "$profile" upload_rows 10' \
    'assert_field "$profile" supervision_mode direct_pid' \
    'assert_field "$profile" metadata_p95_policy strict' \
    'assert_field "$profile" metadata_p95_limit_seconds 2.000' \
    'assert_field "$profile" metadata_p95_within_limit true' \
    'assert_field "$profile" metadata_p95_enforced true' \
    'assert_field "$pre_load" supervision_mode direct_pid' \
    'assert_field "$post_load" supervision_mode direct_pid' \
    'assert_field "$pre_load" integrity ok' \
    'assert_field "$post_load" integrity ok' \
    'assert_field "$pre_load" pid "$service_pid"' \
    'assert_field "$post_load" pid "$service_pid"' \
    'assert_field "$pre_load" process_starttime_ticks "$service_starttime"' \
    'assert_field "$post_load" process_starttime_ticks "$service_starttime"' \
    'assert_field "$pre_load" binary_sha256 "$live_sha256"' \
    'assert_field "$post_load" binary_sha256 "$live_sha256"' \
    'assert_field "$pre_load" health_sha256 "$readiness_sha256"' \
    'assert_field "$post_load" health_sha256 "$readiness_sha256"'; do
    grep -F -q "$native_result_line" "$package_native_load_smoke" \
        || report "native package load evidence is missing hard assertion: $native_result_line"
done
if ! grep -F -q 'value < 2.000' "$package_native_load_smoke" \
    || ! grep -F -q 'NR != 2000' "$package_native_load_smoke" \
    || ! grep -F -q '$2 !~ /^2[0-9][0-9]$/' "$package_native_load_smoke" \
    || ! grep -F -q 'seen["198.18.1." client] != 20' "$package_native_load_smoke" \
    || ! grep -F -q 'NR == 1900 { print; exit }' "$package_native_load_smoke" \
    || ! grep -F -q '[ "$recomputed_p95" = "$p95" ]' "$package_native_load_smoke" \
    || ! grep -F -q '[ "$metadata_capacity_retries" -le 300 ]' \
        "$package_native_load_smoke" \
    || ! grep -F -q 'metadata-capacity-retries.csv' "$package_native_load_smoke" \
    || ! grep -F -q '$5 + 0 > 1.100 || $6 != 1' "$package_native_load_smoke" \
    || ! grep -F -q 'if ($3 != ++retries[$1]) exit 1' "$package_native_load_smoke" \
    || ! grep -F -q 'END { if (NR != expected) exit 1 }' \
        "$package_native_load_smoke" \
    || ! grep -F -q '[ "$max_rss_kib" -le 262144 ]' "$package_native_load_smoke" \
    || ! grep -F -q '$2 != expected_pid || $3 !~ /^[0-9]+$/' "$package_native_load_smoke" \
    || ! grep -F -q '[ "$recomputed_max_rss" = "$max_rss_kib" ]' "$package_native_load_smoke" \
    || ! grep -F -q '$2 != "198.18.2." ($1 + 1) || $3 != 206 || $4 != 67108864' \
        "$package_native_load_smoke" \
    || ! grep -F -q 'NF != 9' "$package_native_load_smoke" \
    || ! grep -F -q '$5 != expected_hash' "$package_native_load_smoke" \
    || ! grep -F -q '$6 != expected_content_range || seen[$1]++' "$package_native_load_smoke" \
    || ! grep -F -q 'if (NR != 40) exit 1' "$package_native_load_smoke" \
    || ! grep -F -q '$2 != "198.18.3." ($1 + 1) || $3 != 303 || $4 != "created"' \
        "$package_native_load_smoke" \
    || ! grep -F -q '$6 != 200 || $7 != expected_hash' "$package_native_load_smoke" \
    || ! grep -F -q 'if (NR != 10) exit 1' "$package_native_load_smoke" \
    || ! grep -F -q "sqlite3 \"\$runtime_data/data.sqlite\" 'PRAGMA integrity_check;'" \
        "$package_native_load_smoke" \
    || ! grep -F -q 'install -m 0644 "$runtime_base/readiness.json" "$evidence/readiness.json"' \
        "$package_native_load_smoke" \
    || ! grep -F -q '[ "$(cat "$runtime_base/readiness.json")" = "$expected_health" ]' \
        "$package_native_load_smoke" \
    || ! grep -F -q 'service PID does not execute the exact active package payload' \
        "$package_native_load_smoke" \
    || ! grep -F -q 'package service identity or payload changed during native load' \
        "$package_native_load_smoke" \
    || ! grep -F -q 'load_profile=100_metadata_40_ranges_10_uploads' "$package_native_load_smoke" \
    || ! grep -F -q 'package_database_parity=ok' "$package_native_load_smoke" \
    || ! grep -F -q 'payload_integrity=ok' "$package_native_load_smoke" \
    || ! grep -F -q 'readiness=ok' "$package_native_load_smoke" \
    || ! grep -F -q 'readiness_sha256=$readiness_sha256' "$package_native_load_smoke" \
    || ! grep -F -q 'sqlite_integrity=ok' "$package_native_load_smoke"; then
    report "native exact-package evidence must independently enforce p95, status/hash, RSS, PID, readiness, SQLite, and 100/40/10 completeness"
fi
if ! grep -F -q 'REAL_UPDATE_NEW_VERSION: 0.7.1' "$package_workflow" \
    || ! grep -F -x -q 'REAL_PACKAGE_NEW_VERSION ?= 0.7.1' Makefile \
    || ! printf '%s\n' "$package_build_job" \
        | grep -F -q 'git archive "$GITHUB_SHA" | tar -x -C "$fixture_source"' \
    || ! printf '%s\n' "$package_build_job" \
        | grep -F -q 'CARGO_TARGET_DIR="$GITHUB_WORKSPACE/target"' \
    || ! printf '%s\n' "$package_build_job" \
        | grep -F -q 'cargo build --locked --release' \
    || ! printf '%s\n' "$package_build_job" \
        | grep -F -q 'vaultlink-real-package-update-fixture-${{ matrix.id }}' \
    || ! printf '%s\n' "$package_smoke_job" \
        | grep -F -q 'runs-on: ${{ matrix.runner }}' \
    || ! printf '%s\n' "$package_smoke_job" \
        | grep -F -q 'make docker-real-package-update-smoke' \
    || ! printf '%s\n' "$package_smoke_job" \
        | grep -F -q 'missing_dependency_zero_mutation=ok' \
    || ! printf '%s\n' "$package_smoke_job" \
        | grep -F -q 'activation_old_package_reinstall=ok' \
    || ! printf '%s\n' "$package_smoke_job" \
        | grep -F -q 'archive_parser_negative_fixtures=ok' \
    || ! printf '%s\n' "$package_smoke_job" \
        | grep -F -q 'vaultlink-real-package-update-evidence-${{ matrix.id }}' \
    || ! grep -F -q 'docker-real-package-update-smoke:' Makefile \
    || ! grep -F -q -- '--network none --user root' Makefile \
    || ! grep -F -q -- '--volume "$(CURDIR):/work:ro"' Makefile \
    || ! grep -F -q 'sh tools/real-package-update-smoke.sh' Makefile; then
    report "all native package targets must run the same-commit real package-manager update/recovery gate and upload evidence"
fi
fresh_schema_security_test='db::tests::fresh_database_is_exactly_schema_eight_without_plaintext_secret_columns'
if ! grep -F -q "fresh_schema_test='$fresh_schema_security_test'" Makefile \
    || ! grep -F -q 'cargo test -- --list >"$$listed_tests"' Makefile \
    || ! grep -F -q 'test "$$match_count" -eq 1' Makefile \
    || ! grep -F -q 'cargo test "$$fresh_schema_test" -- --exact' Makefile; then
    report "security-test must fail closed unless the exact fresh schema-8 secret-column test exists and runs"
fi
if ! grep -F -q '[ -f /.dockerenv ]' "$real_package_smoke" \
    || ! grep -F -q 'minisign -G -W' "$real_package_smoke" \
    || ! grep -F -q 'exec "$real_manager" "$@"' "$real_package_smoke" \
    || ! grep -F -q 'real_manager_directory/$native_manager' "$real_package_smoke" \
    || ! grep -F -q 'rpm:--upgrade) mutation=1' "$real_package_smoke" \
    || [ "$(grep -F -c '^MUTATE rpm --nocontexts --upgrade ' \
        "$real_package_smoke" || true)" -ne 2 ] \
    || ! grep -F -q 'sh "$repo_root/deploy/vaultlink-update.sh" install' \
        "$real_package_smoke" \
    || ! grep -F -q 'missing_dependency_zero_mutation=ok' "$real_package_smoke" \
    || ! grep -F -q 'success_parity=ok' "$real_package_smoke" \
    || ! grep -F -q 'activation_old_package_reinstall=ok' "$real_package_smoke"; then
    report "real package update smoke must stay Docker-only, audit position-independent RPM upgrades with --nocontexts, and delegate to the production updater and native package manager"
fi
if ! grep -F -q "cron: '23 4 * * 1'" .github/workflows/arch-compatibility.yml \
    || ! grep -F -q 'workflow_dispatch:' .github/workflows/arch-compatibility.yml \
    || grep -E -q '^[[:space:]]+(contents|packages|statuses):[[:space:]]+write$' \
        .github/workflows/arch-compatibility.yml \
    || ! grep -F -q 'docker pull archlinux:base' .github/workflows/arch-compatibility.yml \
    || ! grep -F -q "RepoDigests" .github/workflows/arch-compatibility.yml \
    || ! grep -F -q 'tools/check-release-state.py --print-supported-version' \
        .github/workflows/arch-compatibility.yml \
    || ! grep -F -q 'tools/verify-supported-release.py' \
        .github/workflows/arch-compatibility.yml \
    || ! grep -F -q 'sh tools/arch-rolling-compatibility.sh' \
        .github/workflows/arch-compatibility.yml \
    || grep -F -q 'sh -c' .github/workflows/arch-compatibility.yml \
    || ! grep -F -q 'vaultlink-package-install.sh' \
        tools/arch-rolling-compatibility.sh; then
    report "the weekly read-only Arch rolling gate must record the current image and use the initial-install wrapper"
fi
if ! grep -F -q 'unsigned_asset_count=11' tools/assemble-package-release.sh \
    || ! grep -F -q 'expected_count=11' tools/verify-package-release.sh \
    || ! grep -F -q 'expected_count=21' tools/verify-package-release.sh \
    || ! grep -F -q 'tools/assemble-package-release.sh' .github/workflows/release.yml \
    || [ "$(grep -F -c 'tools/verify-package-release.sh' .github/workflows/release.yml || true)" -lt 4 ] \
    || ! grep -F -q 'test "$(find dist -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 11' .github/workflows/release.yml \
    || ! grep -F -q 'test "$(find dist -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 21' .github/workflows/release.yml \
    || ! grep -F -q 'gh release create "$GITHUB_REF_NAME" --verify-tag --draft' .github/workflows/release.yml \
    || ! grep -F -q 'gh release download "$GITHUB_REF_NAME"' .github/workflows/release.yml \
    || ! grep -F -q 'gh release edit "$GITHUB_REF_NAME" --draft=false' .github/workflows/release.yml \
    || ! grep -F -q -- "--jq '.immutable'" .github/workflows/release.yml; then
    report "release assembly must enforce 11/21 assets, verify the draft, and prove immutable publication"
fi
if grep -E -q '(assemble-release-archive|VaultLink-.*\.tar\.gz|SHA256SUMS-(amd64|arm64)|vaultlink-release-(amd64|arm64))' \
        .github/workflows/release.yml .github/workflows/reproducibility.yml \
        .github/workflows/soak-start.yml; then
    report "package-only release workflows must not publish legacy archives or standalone binaries"
fi
if grep -R -E -q 'gh[[:space:]]+release[[:space:]]+(delete|delete-asset)' .github/workflows tools deploy packaging; then
    report "0.6.0+ package assets are rollback inputs and workflows must not delete them"
fi
if ! grep -F -q 'exactly those 21 project assets' release/README.md \
    || ! grep -F -q '`UNPROVISIONED`' release/README.md \
    || ! grep -F -q '`SOURCE_DATE_EPOCH`' release/README.md \
    || ! grep -F -q 'package-only GitHub release' docs/RELEASE-CHECKLIST-0.6.0.md \
    || ! grep -F -q 'exactly 21 project-provided assets' docs/PACKAGING.md \
    || ! grep -F -q 'exact final Debian 13 amd64 DEB' docs/SOAK-RUNNER.md; then
    report "0.6.0 package, signing, bootstrap, and final-DEB soak contracts must be documented"
fi
if grep -F -q 'Persistent native CI runners' THREAT_MODEL.md \
    || grep -F -q 'Signed private GitHub release' THREAT_MODEL.md \
    || grep -F -q 'docs/SELF-HOSTED-RUNNER.md' THREAT_MODEL.md \
    || ! grep -F -q 'Public visibility is not release authorization' THREAT_MODEL.md \
    || ! grep -F -q 'docs/GITHUB-HOSTED-RUNNERS.md' THREAT_MODEL.md; then
    report "the threat model must describe the public-release boundary and GitHub-hosted runner strategy"
fi

if ! grep -F -q 'runs_on: ubuntu-24.04' .github/workflows/fuzz.yml \
    || ! grep -F -q 'runs_on: ubuntu-24.04-arm' .github/workflows/fuzz.yml; then
    report "fuzz workflow must retain native amd64 and arm64 matrix runners"
fi
if ! grep -F -q 'runs-on: ubuntu-24.04-arm' .github/workflows/security-audit.yml; then
    report "security audit workflow must use the pinned GitHub-hosted arm64 runner"
fi

if ! grep -F -q 'run: make fuzz-parallel' .github/workflows/fuzz.yml; then
    report "fuzz workflow must run all targets through the parallel Make target"
fi

if ! grep -F -q "FUZZ_JOBS: ${literal_dollar}{{ github.repository_visibility == 'public' && '4' || '2' }}" .github/workflows/fuzz.yml; then
    report "fuzz workflow must cap private runners at two and public runners at four workers"
fi

if ! grep -E -q '^[[:space:]]+CARGO_BUILD_JOBS:[[:space:]]+2$' .github/workflows/fuzz.yml; then
    report "fuzz workflow must bound memory-intensive instrumented builds to two jobs"
fi

if ! grep -E -q '^[[:space:]]+timeout-minutes:[[:space:]]+120$' .github/workflows/fuzz.yml; then
    report "fuzz workflow must allow two hours for instrumented builds and three target waves"
fi

if ! grep -F -x -q 'LimitNOFILE=4096' deploy/vaultlink.service; then
    report "vaultlink.service must retain its explicit file-descriptor ceiling"
fi
if ! grep -F -x -q 'TimeoutStopSec=45s' deploy/vaultlink.service; then
    report "vaultlink.service must allow the bounded 35-second shutdown within a 45-second stop timeout"
fi
if ! grep -F -x -q 'LimitCORE=0' deploy/vaultlink.service; then
    report "vaultlink.service must disable core dumps"
fi
if ! grep -F -x -q 'TasksMax=512' deploy/vaultlink.service; then
    report "vaultlink.service must retain its explicit task ceiling"
fi
if grep -F -x -q 'RestrictSUIDSGID=true' deploy/vaultlink.service; then
    report "vaultlink.service must not block the required openat2(O_CREAT) storage workflows"
fi
if ! grep -F -x -q 'NoNewPrivileges=true' deploy/vaultlink.service \
    || ! grep -F -x -q 'UMask=0077' deploy/vaultlink.service \
    || ! grep -F -x -q 'CapabilityBoundingSet=' deploy/vaultlink.service; then
    report "vaultlink.service must retain its unprivileged no-escalation boundary"
fi

if ! grep -E -q '^[[:space:]]+cancel-in-progress:[[:space:]]+true$' .github/workflows/fuzz.yml; then
    report "fuzz workflow must cancel superseded runs"
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi

echo "Supply-chain policy checks passed"
