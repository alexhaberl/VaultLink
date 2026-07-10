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

if ! grep -E -q '^[[:space:]]+container:[[:space:]]+[^[:space:]]+@sha256:[0-9a-f]{64}$' .github/workflows/release.yml; then
    report "release container must be pinned by digest"
fi

stable_toolchain=$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\([^"]*\)"[[:space:]]*$/\1/p' rust-toolchain.toml)
ci_toolchains=$(sed -n 's/^[[:space:]]*toolchain:[[:space:]]*\([^[:space:]][^[:space:]]*\)[[:space:]]*$/\1/p' .github/workflows/ci.yml)
ci_toolchain_uses=$(grep -c 'uses:[[:space:]]*dtolnay/rust-toolchain@' .github/workflows/ci.yml || true)
ci_toolchain_count=$(printf '%s\n' "$ci_toolchains" | grep -c . || true)
docker_image=$(sed -n 's/^FROM[[:space:]][[:space:]]*\([^[:space:]][^[:space:]]*\)[[:space:]]*$/\1/p' deploy/docker/Dockerfile.setup-smoke | head -n 1)
release_image=$(sed -n 's/^[[:space:]]*container:[[:space:]]*\([^[:space:]][^[:space:]]*\)[[:space:]]*$/\1/p' .github/workflows/release.yml | head -n 1)

if [ -z "$stable_toolchain" ] || [ -z "$ci_toolchains" ] || [ -z "$docker_image" ] || [ -z "$release_image" ]; then
    report "stable Rust toolchain and container pins must be readable"
else
    if [ "$ci_toolchain_uses" -ne "$ci_toolchain_count" ]; then
        report "every CI Rust toolchain action must declare an exact toolchain"
    fi
    for ci_toolchain in $ci_toolchains; do
        if [ "$ci_toolchain" != "$stable_toolchain" ]; then
            report "CI Rust toolchains must match rust-toolchain.toml"
            break
        fi
    done
    if [ "$docker_image" != "$release_image" ]; then
        report "Docker smoke and release containers must use the same image ref"
    fi
    case "$docker_image" in
        "rust:${stable_toolchain}-trixie@sha256:"*) ;;
        *) report "container image version must match rust-toolchain.toml" ;;
    esac
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

for pattern in /config.toml .env '.env.*' '*.sqlite*'; do
    if ! grep -F -x -q "$pattern" .dockerignore; then
        report ".dockerignore is missing $pattern"
    fi
done

for target in path_normalization byte_range filename zip_search_preview_paths upload_overwrite_policy upload_validation_policy api_request_policy; do
    if ! grep -E -q "(^|[[:space:]])${target}([[:space:]]|$)" Makefile; then
        report "Makefile fuzz target list is missing $target"
    fi
done

if [ "$fail" -ne 0 ]; then
    exit 1
fi

echo "Supply-chain policy checks passed"
