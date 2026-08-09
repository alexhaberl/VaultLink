#!/bin/sh
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
if ! grep -F -x -q 'release_version=0.5.0' tools/check-version-consistency.sh; then
    report "candidate and tag version policy must be fixed to the 0.5.0 release line"
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

smoke_dockerfile=deploy/docker/Dockerfile.setup-smoke
builder_dockerfile=deploy/docker/Dockerfile.release-builder
snapshot_sources=deploy/docker/debian-snapshot.sources
package_lock=deploy/docker/debian-packages.lock
builder_image_lock=deploy/docker/release-builder-image.lock
for dockerfile in "$smoke_dockerfile" "$builder_dockerfile"; do
    if ! grep -E -q '^FROM[[:space:]]+[^[:space:]]+@sha256:[0-9a-f]{64}$' "$dockerfile"; then
        report "$dockerfile base image must be pinned by digest"
    fi
done
locked_builder=$(sed -n '1p' "$builder_image_lock")
if [ "$(wc -l <"$builder_image_lock")" -ne 1 ]; then
    report "release builder image lock must contain exactly one line"
elif [ "$locked_builder" != UNPROVISIONED ] \
    && ! printf '%s\n' "$locked_builder" \
        | grep -E -q '^ghcr\.io/alexhaberl/vaultlink-release-builder@sha256:[0-9a-f]{64}$'; then
    report "release builder image lock must be UNPROVISIONED or the fixed full GHCR digest"
fi
if grep -E -q '^COPY[[:space:]].*(Cargo|\.github|src|release-builder-image\.lock)' "$builder_dockerfile" \
    || ! grep -F -q 'debian-snapshot.sources deploy/docker/debian-packages.lock' "$builder_dockerfile" \
    || ! grep -F -q 'tools/install-pinned-debian-packages.sh' "$builder_dockerfile"; then
    report "release builder Dockerfile must be independent of application source and its own image lock"
fi
if [ "$(grep -E -c '^URIs: http://snapshot\.debian\.org/archive/debian(-security)?/[0-9]{8}T[0-9]{6}Z$' "$snapshot_sources" || true)" -ne 2 ] \
    || grep -E -q 'deb\.debian\.org' "$snapshot_sources"; then
    report "Debian package sources must use one immutable main and security snapshot"
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
    report "Debian package lock must be sorted, unique, and fully versioned"
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
    report "pinned package installer must verify the sole snapshot and every base-image package delta"
fi
if grep -E -q 'apt-get[[:space:]]+(update|install)' "$smoke_dockerfile" "$builder_dockerfile" \
    || grep -E -q 'apt-get[[:space:]]+(update|install)' \
        .github/workflows/release.yml .github/workflows/reproducibility.yml; then
    report "Dockerfile, release, and reproducibility workflows must not contain ad-hoc apt operations"
fi
for tool in 'cargo-cyclonedx --version 0.5.9' 'cargo-audit --version 0.22.2'; do
    grep -F -q "$tool" "$smoke_dockerfile" \
        || report "canonical container is missing pinned $tool"
    grep -F -q "$tool" "$builder_dockerfile" \
        || report "release builder is missing pinned $tool"
done

audit_exception='--ignore RUSTSEC-2023-0071'
audit_commands=$(grep -R -h -E 'cargo audit .*--deny warnings' .github/workflows || true)
audit_exceptions=$(printf '%s\n' "$audit_commands" \
    | grep -o -E -- '--ignore[[:space:]]+RUSTSEC-[0-9-]+' | sort -u || true)
if [ "$(printf '%s\n' "$audit_commands" | grep -c . || true)" -ne 3 ] \
    || [ "$(printf '%s\n' "$audit_commands" | grep -F -c -- "$audit_exception" || true)" -ne 3 ] \
    || [ "$audit_exceptions" != "$audit_exception" ]; then
    report "RUSTSEC-2023-0071 must be the only explicit cargo-audit exception"
fi

if ! grep -E -q '^COPY Cargo\.toml Cargo\.lock rust-toolchain\.toml Makefile \.dockerignore \.gitleaksignore \./$' "$smoke_dockerfile" \
    || ! grep -F -x -q 'COPY .cargo ./.cargo' "$smoke_dockerfile" \
    || ! grep -F -x -q 'COPY .github ./.github' "$smoke_dockerfile" \
    || ! grep -F -x -q 'COPY deploy ./deploy' "$smoke_dockerfile" \
    || ! grep -F -x -q 'COPY tools ./tools' "$smoke_dockerfile"; then
    report "Docker smoke build must include policy, workflow, tool, and deployment assets"
fi
if ! grep -F -q 'shellcheck deploy/*.sh deploy/docker/*.sh tools/*.sh' "$smoke_dockerfile" \
    || ! grep -F -q 'sh tools/check-supply-chain-policy.sh' "$smoke_dockerfile"; then
    report "Docker smoke build must run shell and supply-chain policy gates"
fi
if ! grep -F -q "docker run --rm --network none --user root \$(DOCKER_SMOKE_IMAGE) sh deploy/docker/load-fixture-smoke.sh" Makefile; then
    report "make docker-smoke must run load-fixture-smoke.sh as root without network access"
fi
if ! grep -F -q "docker run --rm --network none \$(DOCKER_SMOKE_IMAGE) sh deploy/docker/soak-evidence-smoke.sh" Makefile; then
    report "make docker-smoke must run soak-evidence-smoke.sh as vaultlink without network access"
fi
if ! grep -F -q "docker run --rm --network none --user root \$(DOCKER_SMOKE_IMAGE) sh deploy/docker/soak-remote-smoke.sh" Makefile; then
    report "make docker-smoke must exercise the restricted soak bridge without network access"
fi

literal_dollar='$'
release_container_value="${literal_dollar}{{ needs.release_environment.outputs.image }}"
publish_container_value="${literal_dollar}{{ vars.VAULTLINK_RELEASE_BUILDER_IMAGE }}"
toolchain_resolver_reference="channel=${literal_dollar}(sh tools/rust-toolchain-channel.sh)"
toolchain_output_value="${literal_dollar}{{ steps.rust_toolchain.outputs.channel }}"
exact_main_tag_reference="test \"${literal_dollar}tag_commit\" = \"${literal_dollar}main_commit\""
ancestor_tag_reference="git merge-base --is-ancestor \"${literal_dollar}tag_commit\" \"${literal_dollar}main_commit\""
release_container_count=$(grep -F -c "image: $release_container_value" .github/workflows/release.yml || true)
if [ "$release_container_count" -ne 2 ]; then
    report "release build containers must consume the validated prebuilt release image"
fi
publish_job=$(awk '
    $0 == "  publish:" { publish = 1 }
    publish && /^  [[:alnum:]_-]+:$/ && $0 != "  publish:" { exit }
    publish { print }
' .github/workflows/release.yml)
if [ "$(printf '%s\n' "$publish_job" | grep -F -c "image: $publish_container_value" || true)" -ne 1 ] \
    || [ "$(printf '%s\n' "$publish_job" | grep -F -c "RELEASE_BUILDER_IMAGE: $publish_container_value" || true)" -ne 1 ] \
    || printf '%s\n' "$publish_job" | grep -F -q "$release_container_value"; then
    report "the secret-bearing publish job must select its image directly from GitHub configuration"
fi
repro_container_value="${literal_dollar}{{ needs.release_environment.outputs.image }}"
if [ "$(grep -F -c "image: $repro_container_value" .github/workflows/reproducibility.yml || true)" -ne 1 ]; then
    report "reproducibility builds must consume the digest-pinned release builder variable"
fi
credential_user="username: ${literal_dollar}{{ github.actor }}"
credential_password="password: ${literal_dollar}{{ secrets.GITHUB_TOKEN }}"
if [ "$(grep -F -c "$credential_user" .github/workflows/release.yml || true)" -ne 3 ] \
    || [ "$(grep -F -c "$credential_password" .github/workflows/release.yml || true)" -ne 3 ] \
    || [ "$(grep -F -c "$credential_user" .github/workflows/reproducibility.yml || true)" -ne 1 ] \
    || [ "$(grep -F -c "$credential_password" .github/workflows/reproducibility.yml || true)" -ne 1 ] \
    || [ "$(grep -E -c '^[[:space:]]+packages:[[:space:]]+read$' .github/workflows/release.yml || true)" -ne 3 ] \
    || [ "$(grep -E -c '^[[:space:]]+packages:[[:space:]]+read$' .github/workflows/reproducibility.yml || true)" -ne 1 ]; then
    report "private GHCR job containers require packages: read and explicit GitHub token credentials"
fi
if ! grep -F -q 'VAULTLINK_RELEASE_BUILDER_IMAGE' .github/workflows/release.yml \
    || ! grep -F -q 'ghcr.io/alexhaberl/vaultlink-release-builder@sha256:*' .github/workflows/release.yml \
    || ! grep -F -q 'deploy/docker/release-builder-image.lock' .github/workflows/release.yml \
    || ! grep -F -q 'deploy/docker/release-builder-image.lock' .github/workflows/reproducibility.yml \
    || [ "$(grep -h -F -c "test \"\$image\" = \"\$locked_image\"" .github/workflows/release.yml .github/workflows/reproducibility.yml | awk '{ total += $1 } END { print total + 0 }')" -ne 2 ] \
    || [ "$(grep -F -c 'sh tools/verify-release-builder.sh' .github/workflows/release.yml || true)" -ne 3 ] \
    || ! grep -F -q 'sh tools/verify-release-builder.sh' .github/workflows/reproducibility.yml; then
    report "release and reproducibility jobs must fail closed on the verified digest-pinned builder"
fi
if ! grep -F -q 'release-builder-image.lock' tools/verify-release-builder.sh \
    || ! grep -F -q "RELEASE_BUILDER_IMAGE\" != \"\$locked_image" tools/verify-release-builder.sh \
    || ! grep -F -q 'UNPROVISIONED' release/README.md \
    || ! grep -F -q 'Dockerfile.release-builder' docs/GITHUB-HOSTED-RUNNERS.md; then
    report "checked-in builder pin, exact variable equality, and provisioning blocker must be documented"
fi
if ! grep -F -q 'workflow_dispatch:' .github/workflows/release-builder.yml \
    || grep -F -q 'pull_request:' .github/workflows/release-builder.yml \
    || ! grep -F -q 'runner: ubuntu-24.04' .github/workflows/release-builder.yml \
    || ! grep -F -q 'runner: ubuntu-24.04-arm' .github/workflows/release-builder.yml \
    || ! grep -F -q 'push-by-digest=true' .github/workflows/release-builder.yml \
    || ! grep -F -q -- '--provenance=false' .github/workflows/release-builder.yml \
    || ! grep -F -q 'packages: write' .github/workflows/release-builder.yml \
    || ! grep -F -q 'ghcr.io/alexhaberl/vaultlink-release-builder' .github/workflows/release-builder.yml; then
    report "release builder refresh must be manual, main-only, native multiarch, and digest-published to GHCR"
fi
if ! grep -F -q "inspection=${literal_dollar}(docker buildx imagetools inspect \"${literal_dollar}IMAGE:dependency-refresh\")" .github/workflows/release-builder.yml \
    || ! grep -F -q "sed -n 's/^Digest:[[:space:]]*//p'" .github/workflows/release-builder.yml \
    || ! grep -F -q "[[ \"${literal_dollar}manifest_digest\" =~ ^sha256:[0-9a-f]{64}${literal_dollar} ]]" .github/workflows/release-builder.yml \
    || ! grep -F -q "reference=\"${literal_dollar}IMAGE@${literal_dollar}manifest_digest\"" .github/workflows/release-builder.yml \
    || grep -F -q "sed -n 's/^Name:[[:space:]]*//p'" .github/workflows/release-builder.yml; then
    report "release builder summary must construct its immutable reference from the inspected manifest Digest"
fi
if grep -E -q '(install-pinned-debian-packages\.sh|cargo[[:space:]]+install[[:space:]])' \
    .github/workflows/release.yml .github/workflows/reproducibility.yml; then
    report "release and reproducibility jobs must not install APT or Cargo tooling at runtime"
fi
for workflow in .github/workflows/release.yml .github/workflows/reproducibility.yml; do
    if ! grep -F -q 'sh tools/assemble-release-archive.sh' "$workflow"; then
        report "$workflow must assemble the same final release archive"
    fi
    if ! grep -F -q 'tools/normalize-cyclonedx-sbom.py' "$workflow"; then
        report "$workflow must normalize its independently generated CycloneDX SBOM"
    fi
done

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
builder_base_image=$(sed -n 's/^FROM[[:space:]][[:space:]]*\([^[:space:]][^[:space:]]*\)[[:space:]]*$/\1/p' deploy/docker/Dockerfile.release-builder | head -n 1)

if [ -z "$stable_toolchain" ] || [ -z "$docker_image" ] || [ -z "$builder_base_image" ]; then
    report "stable Rust toolchain and canonical container pin must be readable"
else
    if [ "$ci_toolchain_uses" -ne 4 ] || [ "$ci_toolchain_value_count" -ne 4 ] \
        || [ "$ci_toolchain_refs" -ne 4 ] || [ "$ci_toolchain_resolvers" -ne 4 ]; then
        report "every stable Rust toolchain action must resolve rust-toolchain.toml exactly once"
    fi
    case "$docker_image" in
        "rust:${stable_toolchain}-trixie@sha256:"*) ;;
        *) report "container image version must match rust-toolchain.toml" ;;
    esac
    if [ "$builder_base_image" != "$docker_image" ]; then
        report "release builder and Docker smoke must share the reviewed Rust/Debian base digest"
    fi
fi

for workflow in \
    .github/workflows/ci.yml \
    .github/workflows/fuzz.yml \
    .github/workflows/release.yml \
    .github/workflows/reproducibility.yml; do
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
    | grep -F -x -q "    if: github.repository_visibility == 'public' && startsWith(github.ref, 'refs/tags/v')"; then
    report "the tag-only publish job must fail closed until the repository is public"
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

for architecture in amd64 arm64; do
    if ! grep -F -q "release_architecture: $architecture" .github/workflows/release.yml; then
        report "release workflow is missing the $architecture native build"
    fi
done

exact_main_tag_gates=$(grep -F -c "$exact_main_tag_reference" .github/workflows/release.yml || true)
if [ "$exact_main_tag_gates" -ne 3 ] \
    || grep -F -q "$ancestor_tag_reference" .github/workflows/release.yml; then
    report "release tags must target the exact approved main candidate in build, verification, and publish jobs"
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

for pattern in /config.toml .env '.env.*' '*.sqlite*'; do
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
    vaultlink/release-dry-run \
    vaultlink/reproducibility-amd64 \
    vaultlink/reproducibility-arm64; do
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
        vaultlink/reproducibility-*)
            producer=.github/workflows/reproducibility.yml
            producer_context="vaultlink/reproducibility-${literal_dollar}{{ matrix.architecture }}"
            release_context="vaultlink/reproducibility-${literal_dollar}RELEASE_ARCHITECTURE"
            ;;
    esac
    if ! grep -F -q "$producer_context" "$producer" \
        || ! grep -F -q "$release_context" .github/workflows/release.yml; then
        report "release preflight and producer must share exact-commit gate $gate_context"
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
    vaultlink/reproducibility-amd64 \
    vaultlink/reproducibility-arm64 \
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
if ! grep -F -q -- '--name vaultlink-release-amd64' .github/workflows/soak-start.yml \
    || ! grep -F -q 'sha256sum -c SHA256SUMS-amd64' .github/workflows/soak-start.yml \
    || ! grep -F -q 'candidate_binary_sha256' .github/workflows/soak-start.yml \
    || ! grep -F -q 'steps.validate.outputs.binary_sha256' .github/workflows/soak-start.yml; then
    report "soak start must bind its live binary hash to the candidate-preflight amd64 artifact"
fi
if ! grep -F -q 'ExecStart=/usr/local/libexec/vaultlink/soak-monitor.sh' deploy/vaultlink-soak@.service \
    || ! grep -F -x -q 'Group=vaultlink-soak' deploy/vaultlink-soak@.service \
    || [ "$(grep -F -c -- '-m 2750' deploy/vaultlink-soak-control.sh || true)" -lt 2 ] \
    || ! grep -F -q "install -d -m 2750 \"\$SOAK_EVIDENCE_DIR\"" tools/soak-monitor.sh \
    || ! grep -F -q 'SOAK_SECONDS=259200' deploy/vaultlink-soak-control.sh; then
    report "host-side systemd soak must retain the 72-hour monitor contract"
fi

repro_workflow=.github/workflows/reproducibility.yml
if ! grep -F -q 'runs_on: ubuntu-24.04' "$repro_workflow" \
    || ! grep -F -q 'runs_on: ubuntu-24.04-arm' "$repro_workflow" \
    || ! grep -F -q 'target/repro-first' "$repro_workflow" \
    || ! grep -F -q 'target/repro-second' "$repro_workflow" \
    || [ "$(grep -E -c '^[[:space:]]+cmp[[:space:]]+' "$repro_workflow" || true)" -ne 3 ]; then
    report "reproducibility workflow must compare two clean native binary, SBOM, and archive builds"
fi
if ! grep -F -q 'release_environment:' "$repro_workflow" \
    || ! grep -F -q 'needs: release_environment' "$repro_workflow" \
    || ! grep -F -q 'Validate pinned release image before matrix startup' "$repro_workflow" \
    || ! grep -F -q "image: ${literal_dollar}{{ needs.release_environment.outputs.image }}" "$repro_workflow"; then
    report "reproducibility matrix must resolve its digest-pinned builder before container startup"
fi
if grep -E -i -q 'APT packages are installed from Debian.s signed live repositories|Do not describe builds as bit-for-bit reproducible' release/README.md \
    || ! grep -F -q 'debian-snapshot.sources' release/README.md; then
    report "release signing documentation must describe the immutable snapshot and reproducibility gate"
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

arm64_release_jobs=$(grep -F -c 'runs-on: ubuntu-24.04-arm' .github/workflows/release.yml || true)
if [ "$arm64_release_jobs" -ne 3 ]; then
    report "architecture-independent release jobs other than tag publication must use GitHub-hosted arm64"
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
