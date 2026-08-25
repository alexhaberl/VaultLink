#!/bin/sh
# This policy intentionally searches for literal shell/YAML expressions.
# shellcheck disable=SC2016
set -eu

fail=0

report() {
    echo "supply-chain policy: $*" >&2
    fail=1
}

if ! sh tools/check-deployment-assets.sh; then
    report "deployment samples and legacy-component policy failed"
fi

if ! sh tools/check-cargo-duplicates.sh; then
    report "Cargo duplicate dependency policy failed"
fi

if ! sh tools/check-version-consistency.sh; then
    report "package, documentation, and health version policy failed"
fi
if ! grep -F -x -q 'release_version=0.6.0' tools/check-version-consistency.sh; then
    report "candidate and tag version policy must be fixed to the 0.6.0 release line"
fi
if ! awk '
    $0 == "[profile.release]" { release_profile = 1; profiles++; next }
    /^\[/ { release_profile = 0 }
    release_profile && $0 == "panic = \"unwind\"" { unwind_settings++ }
    END { exit !(profiles == 1 && unwind_settings == 1) }
' Cargo.toml \
    || [ "$(grep -F -c '#[cfg(panic = "unwind")]' src/web.rs || true)" -ne 2 ] \
    || [ "$(grep -F -c 'CatchPanicLayer' src/web.rs || true)" -ne 2 ] \
    || ! grep -F -q 'use tower_http::catch_panic::CatchPanicLayer;' src/web.rs \
    || ! grep -F -q 'let router = router.layer(CatchPanicLayer::new());' src/web.rs; then
    report "release builds must use panic=unwind and keep CatchPanicLayer active"
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

gitleaks_ignore=.gitleaksignore
gitleaks_script=tools/check-secrets.sh
gitleaks_ci=.github/workflows/ci.yml
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
if ! grep -F -q 'fetch-depth: 0' "$gitleaks_ci" \
    || ! grep -F -q 'GITLEAKS_VERSION: 8.30.0' "$gitleaks_ci" \
    || ! grep -F -q 'GITLEAKS_SHA256: b4cbbb6ddf7d1b2a603088cd03a4e3f7ce48ee7fd449b51f7de6ee2906f5fa2f' "$gitleaks_ci" \
    || ! grep -F -q "GITLEAKS_BIN=\"\$work/gitleaks\" make secret-check" "$gitleaks_ci"; then
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
package_builder_dependencies=deploy/docker/install-package-builder-dependencies.sh
vm_provisioner=tools/provision-distro-vm-image.sh
package_workflow=.github/workflows/packages.yml
real_package_smoke=tools/real-package-update-smoke.sh

if ! python3 tools/package-targets.py validate --allow-unprovisioned >/dev/null; then
    report "the declarative nine-target package manifest is invalid even in bootstrap mode"
fi
if [ "$(python3 tools/package-targets.py ids --allow-unprovisioned 2>/dev/null | wc -l)" -ne 9 ] \
    || [ "$(python3 tools/package-targets.py assets 0.6.0 --allow-unprovisioned 2>/dev/null | wc -l)" -ne 9 ]; then
    report "the package manifest must render exactly nine target IDs and nine unique 0.6.0 assets"
fi
if ! grep -F -q '"builder_image": "UNPROVISIONED"' "$target_manifest" \
    || ! grep -F -q '"vm_image": "UNPROVISIONED"' "$target_manifest"; then
    # A fully provisioned follow-up PR is valid; this branch merely documents
    # that bootstrap placeholders are an intentional, validated state.
    python3 tools/package-targets.py validate >/dev/null 2>&1 \
        || report "target pins must be either reviewed digests or explicit UNPROVISIONED bootstrap values"
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
    || ! grep -F -q 'rustc -vV' tools/verify-package-builder.sh \
    || ! grep -F -q 'cargo-audit cmp gh minisign readelf shellcheck ssh stat' tools/verify-package-builder.sh; then
    report "native package builders must attest the complete package closure, base digest, and Rust host"
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
        || ! grep -F -q 'docker buildx inspect --bootstrap' "$refresh_workflow"; then
        report "$refresh_workflow must use the reviewed immutable BuildKit image with the docker-container driver"
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

if ! grep -E -q '^COPY Cargo\.toml Cargo\.lock rust-toolchain\.toml Makefile \.dockerignore \.gitleaksignore \./$' "$smoke_dockerfile" \
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
    || ! grep -F -q 'rpm --upgrade' "$updater" \
    || ! grep -F -q 'pkg.tar.zst) pacman --upgrade' "$updater" \
    || ! grep -F -q 'auto_install=false' deploy/vaultlink-update.conf.example \
    || ! grep -F -x -q 'ConditionPathExists=/usr/share/vaultlink/install-method.env' deploy/vaultlink-update.service; then
    report "the updater must use each native package manager and remain opt-in/package-bound"
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
        .github/workflows/arch-compatibility.yml; then
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
    || ! grep -F -q 'sh tools/verify-package-builder.sh debian13-amd64' .github/workflows/soak-start.yml; then
    report "release verification and soak start must use and verify the pinned complete package-tool image"
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
    || ! grep -F -q 'UPLOAD_VERIFY_TOKEN' docs/SOAK-RUNNER.md; then
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
if ! grep -F -q 'p95 < 2.000' tools/load-test.sh \
    || ! grep -F -q 'p95 < 2.000' tools/check-soak-evidence.sh \
    || ! grep -F -q 'strictly below' docs/SOAK-RUNNER.md \
    || ! grep -F -q '2 seconds' docs/SOAK-RUNNER.md \
    || ! grep -F -q 'p95 `<2 s`' docs/RELEASE-CHECKLIST-0.6.0.md; then
    report "load execution, evidence verification, and release documentation must share the strict 2-second metadata p95 gate"
fi
for numeric_script in \
    tools/load-test.sh \
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
    || ! grep -F -q 'tools/verify-package-release.sh "$candidate_artifact" 0.6.0' .github/workflows/soak-start.yml \
    || ! grep -F -q 'package-targets.py asset debian13-amd64 0.6.0' .github/workflows/soak-start.yml \
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
    || ! grep -F -q 'acceleration=tcg' tools/run-distro-vm-test.sh \
    || ! grep -F -q '[ "$architecture" = amd64 ]' tools/run-distro-vm-test.sh \
    || ! grep -F -q '[ "$architecture" = amd64 ]' tools/provision-distro-vm-image.sh \
    || ! grep -F -q '"$ARCHITECTURE" == amd64' .github/workflows/distro-vms.yml \
    || ! grep -F -q '"$ARCHITECTURE" == amd64' .github/workflows/distro-vm-images-refresh.yml \
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

tcg_timeout_manager=tools/manage-tcg-device-timeout.sh
tcg_timeout_cleanup=tools/clear-tcg-device-timeout.sh
root_capacity_check=tools/check-vm-root-capacity.sh
if ! grep -F -q 'libguestfs-tools' deploy/docker/Dockerfile.qemu-runner \
    || ! grep -F -q 'linux-image-virtual' deploy/docker/Dockerfile.qemu-runner \
    || ! grep -F -q 'policycoreutils' deploy/docker/Dockerfile.qemu-runner \
    || ! grep -F -q 'command -v guestfish' tools/verify-qemu-runner.sh \
    || ! grep -F -q 'guestfish-probe.img=fs:ext4:64M' tools/verify-qemu-runner.sh \
    || ! grep -F -q 'feature-available selinuxrelabel' tools/verify-qemu-runner.sh \
    || ! grep -F -q 'LIBGUESTFS_BACKEND_SETTINGS=force_tcg' tools/verify-qemu-runner.sh \
    || ! grep -F -q 'guestfish get-backend-settings' tools/verify-qemu-runner.sh \
    || ! grep -F -q 'LIBGUESTFS_BACKEND_SETTINGS=force_tcg' "$tcg_timeout_manager" \
    || ! grep -F -q 'guestfish get-backend-settings' "$tcg_timeout_manager" \
    || ! grep -F -q 'DefaultDeviceTimeoutSec=5min' "$tcg_timeout_manager" \
    || ! grep -F -q 'DefaultDeviceTimeoutSec=5min' "$tcg_timeout_cleanup" \
    || ! grep -F -q 'rmdir -- /etc/systemd/system.conf.d' "$tcg_timeout_cleanup" \
    || ! grep -F -q 'rm -f -- "$cleanup"' "$tcg_timeout_cleanup" \
    || ! grep -F -q 'state_file=$image.vaultlink-tcg-state' "$tcg_timeout_manager" \
    || ! grep -F -q 'clean-missing-directory' "$tcg_timeout_manager" \
    || ! grep -F -q 'clean-existing-directory' "$tcg_timeout_manager" \
    || ! grep -F -q 'feature-available selinuxrelabel' "$tcg_timeout_manager" \
    || ! grep -F -q 'is-dir /etc/systemd' "$tcg_timeout_manager" \
    || ! grep -F -q 'is-dir /usr/local/sbin' "$tcg_timeout_manager" \
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
    || ! grep -F -q "inputs.target_id == 'fedora44-arm64' && 240 || 90" .github/workflows/distro-vm-images-refresh.yml \
    || ! grep -F -q 'provision_timeout=5400' "$vm_provisioner" \
    || ! grep -F -q 'cold_boot_timeout=3600' "$vm_provisioner" \
    || ! grep -F -q 'ssh_timeout=3600' tools/run-distro-vm-test.sh \
    || ! grep -F -q 'grep -F -q VAULTLINK_VM_READY "$evidence/serial.log"' tools/run-distro-vm-test.sh \
    || ! grep -F -q 'full-system QEMU exited with status' tools/run-distro-vm-test.sh \
    || ! grep -F -q 'root filesystem is smaller than the reviewed minimum' "$root_capacity_check"; then
    report "guest images must enforce reviewed capacity and a removable Fedora arm64 TCG device-timeout override"
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
if ! grep -F -q 'REAL_UPDATE_NEW_VERSION: 0.6.1' "$package_workflow" \
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
if ! grep -F -q '[ -f /.dockerenv ]' "$real_package_smoke" \
    || ! grep -F -q 'minisign -G -W' "$real_package_smoke" \
    || ! grep -F -q 'exec "$real_manager" "$@"' "$real_package_smoke" \
    || ! grep -F -q 'real_manager_directory/$native_manager' "$real_package_smoke" \
    || ! grep -F -q 'sh "$repo_root/deploy/vaultlink-update.sh" install' \
        "$real_package_smoke" \
    || ! grep -F -q 'missing_dependency_zero_mutation=ok' "$real_package_smoke" \
    || ! grep -F -q 'success_parity=ok' "$real_package_smoke" \
    || ! grep -F -q 'activation_old_package_reinstall=ok' "$real_package_smoke"; then
    report "real package update smoke must stay Docker-only and delegate to the production updater and native package manager"
fi
if ! grep -F -q "cron: '23 4 * * 1'" .github/workflows/arch-compatibility.yml \
    || ! grep -F -q 'workflow_dispatch:' .github/workflows/arch-compatibility.yml \
    || grep -E -q '^[[:space:]]+(contents|packages|statuses):[[:space:]]+write$' \
        .github/workflows/arch-compatibility.yml \
    || ! grep -F -q 'docker pull archlinux:base' .github/workflows/arch-compatibility.yml \
    || ! grep -F -q "RepoDigests" .github/workflows/arch-compatibility.yml \
    || ! grep -F -q 'vaultlink-package-install.sh' .github/workflows/arch-compatibility.yml; then
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
