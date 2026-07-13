#!/bin/sh
set -eu

fail=0

report() {
    echo "supply-chain policy: $*" >&2
    fail=1
}

uses_lines=$(grep -R -n -E '^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]+' .github/workflows || true)
bad_uses=$(printf '%s\n' "$uses_lines" | grep -E -v 'uses:[[:space:]]+\./|@[0-9a-f]{40}([[:space:]]+#.*)?$' || true)
if [ -n "$bad_uses" ]; then
    printf '%s\n' "$bad_uses" >&2
    report "external actions must use a full 40-character commit SHA"
fi

if ! grep -E -q '^FROM[[:space:]]+[^[:space:]]+@sha256:[0-9a-f]{64}$' deploy/docker/Dockerfile.setup-smoke; then
    report "Docker smoke base image must be pinned by digest"
fi

literal_dollar='$'
release_container_value="${literal_dollar}{{ needs.release_environment.outputs.image }}"
toolchain_resolver_reference="channel=${literal_dollar}(sh tools/rust-toolchain-channel.sh)"
toolchain_output_value="${literal_dollar}{{ steps.rust_toolchain.outputs.channel }}"
release_container_values=$(sed -n 's/^[[:space:]]*container:[[:space:]]*//p' .github/workflows/release.yml)
release_container_count=$(printf '%s\n' "$release_container_values" | grep -c . || true)
bad_release_containers=$(printf '%s\n' "$release_container_values" | grep -F -x -v "$release_container_value" || true)
if [ "$release_container_count" -ne 3 ] || [ -n "$bad_release_containers" ]; then
    printf '%s\n' "$bad_release_containers" >&2
    report "every release container must consume the validated Docker smoke image"
fi
if ! grep -F -q "$toolchain_resolver_reference" .github/workflows/release.yml \
    || ! grep -F -q "deploy/docker/Dockerfile.setup-smoke" .github/workflows/release.yml; then
    report "release environment must validate the canonical Docker smoke image before containers start"
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

if [ -z "$stable_toolchain" ] || [ -z "$docker_image" ]; then
    report "stable Rust toolchain and canonical container pin must be readable"
else
    if [ "$ci_toolchain_uses" -ne 2 ] || [ "$ci_toolchain_value_count" -ne 2 ] \
        || [ "$ci_toolchain_refs" -ne 2 ] || [ "$ci_toolchain_resolvers" -ne 2 ]; then
        report "every stable Rust toolchain action must resolve rust-toolchain.toml exactly once"
    fi
    case "$docker_image" in
        "rust:${stable_toolchain}-trixie@sha256:"*) ;;
        *) report "container image version must match rust-toolchain.toml" ;;
    esac
fi

for workflow in .github/workflows/ci.yml .github/workflows/release.yml; do
    if ! grep -F -q '["self-hosted", "Linux", "X64", "vaultlink"]' "$workflow"; then
        report "$workflow must keep amd64 on the dedicated self-hosted runner"
    fi
    if ! grep -F -q '["ubuntu-24.04-arm"]' "$workflow"; then
        report "$workflow must run arm64 natively on the GitHub-hosted ARM runner"
    fi
    if grep -F -q '["ubuntu-24.04"]' "$workflow" || grep -F -q 'ubuntu-latest' "$workflow"; then
        report "$workflow must not move amd64 to a GitHub-hosted runner"
    fi
done

unexpected_hosted_runners=$(grep -R -n -E 'runs[_-]on:.*ubuntu-' .github/workflows \
    | grep -F -v 'ubuntu-24.04-arm' || true)
if [ -n "$unexpected_hosted_runners" ]; then
    printf '%s\n' "$unexpected_hosted_runners" >&2
    report "only the arm64 ubuntu-24.04-arm runner may be GitHub-hosted"
fi

for architecture in amd64 arm64; do
    if ! grep -F -q "release_architecture: $architecture" .github/workflows/release.yml; then
        report "release workflow is missing the $architecture native build"
    fi
done

if grep -R -n -E 'curl[^|]*\|[[:space:]]*(ba)?sh' .github/workflows; then
    report "workflows must not pipe remote scripts into a shell"
fi

cargo_installs=$(grep -R -n -E 'cargo[[:space:]]+install[[:space:]]' .github/workflows || true)
bad_cargo_installs=$(printf '%s\n' "$cargo_installs" | grep -F -v -- '--version' || true)
if [ -n "$bad_cargo_installs" ]; then
    printf '%s\n' "$bad_cargo_installs" >&2
    report "cargo-installed CI tools must use an exact --version"
fi

for pattern in /config.toml .env '.env.*' '*.sqlite*'; do
    if ! grep -F -x -q "$pattern" .dockerignore; then
        report ".dockerignore is missing $pattern"
    fi
done

for target in path_normalization byte_range filename zip_search_preview_paths upload_overwrite_policy upload_validation_policy api_request_policy file_mutation_policy; do
    if ! grep -E -q "(^|[[:space:]])${target}([[:space:]]|$)" Makefile; then
        report "Makefile fuzz target list is missing $target"
    fi
done

if ! grep -F -q 'runs-on: [self-hosted, Linux, X64, vaultlink]' .github/workflows/fuzz.yml; then
    report "fuzz workflow must use the dedicated self-hosted runner"
fi

if ! grep -F -q 'run: make fuzz-parallel' .github/workflows/fuzz.yml; then
    report "fuzz workflow must run all targets through the parallel Make target"
fi

if ! grep -E -q '^[[:space:]]+FUZZ_JOBS:[[:space:]]+8$' .github/workflows/fuzz.yml; then
    report "fuzz workflow must run all eight targets concurrently"
fi

if ! grep -E -q '^[[:space:]]+cancel-in-progress:[[:space:]]+true$' .github/workflows/fuzz.yml; then
    report "fuzz workflow must cancel superseded runs"
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi

echo "Supply-chain policy checks passed"
