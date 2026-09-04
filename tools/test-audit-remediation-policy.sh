#!/bin/sh
# These fixtures intentionally contain literal shell variables and trailing
# backslashes that are copied into synthetic YAML command blocks.
# shellcheck disable=SC1003,SC2016
set -eu

checker=tools/check-supply-chain-policy.sh
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
base="$work/base"
mkdir -p \
    "$base/.github/workflows" \
    "$base/assets/web" \
    "$base/deploy/docker" \
    "$base/src/setup"

for fixture in \
    .github/workflows/ci.yml \
    .github/workflows/package-builders-refresh.yml \
    .github/workflows/qemu-runner-refresh.yml \
    .github/workflows/distro-vm-images-refresh.yml \
    assets/web/setup.js \
    deploy/docker/Dockerfile.package-builder \
    deploy/docker/Dockerfile.qemu-runner \
    deploy/docker/Dockerfile.distro-vm-image \
    README.md \
    src/setup/routes.rs; do
    cp "$fixture" "$base/$fixture"
done

if ! sh "$checker" --audit-remediation-fixture "$base"; then
    echo "audit-remediation policy tests: valid baseline was rejected" >&2
    exit 1
fi

fail=0
expect_rejected() {
    case_name=$1
    case_root="$work/$case_name"
    mkdir -p "$case_root"
    cp -R "$base/." "$case_root"

    case "$case_name" in
        mutable_frontend)
            sed -i '1c\# syntax=docker.io/docker/dockerfile:1.7.1' \
                "$case_root/deploy/docker/Dockerfile.package-builder"
            ;;
        wrong_index_digest)
            sed -i '1s/a57df69d/b57df69d/' \
                "$case_root/deploy/docker/Dockerfile.package-builder"
            ;;
        platform_child_digest)
            sed -i \
                '1c\# syntax=docker.io/docker/dockerfile:1.7.1@sha256:b5f3b260a9678e1d83d2fce86eeddf79420b79147eaba2a25986f47133d73720' \
                "$case_root/deploy/docker/Dockerfile.package-builder"
            ;;
        spelling_variant)
            sed -i \
                '1c\   # SyNtAx = docker.io/docker/dockerfile:1.7.1@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e' \
                "$case_root/deploy/docker/Dockerfile.package-builder"
            ;;
        second_syntax_directive)
            printf '%s\n' \
                '  # SyNtAx =docker.io/docker/dockerfile:1.7.1' \
                >>"$case_root/deploy/docker/Dockerfile.package-builder"
            ;;
        additional_dockerfile)
            printf '%s\n' \
                '# SYNTAX=docker.io/docker/dockerfile:1.7.1' \
                'FROM scratch' \
                >"$case_root/deploy/docker/Dockerfile.release-extra"
            ;;
        buildkit_syntax_override)
            printf '%s\n' '  BUILDKIT_SYNTAX: docker/dockerfile:1' \
                >>"$case_root/.github/workflows/package-builders-refresh.yml"
            ;;
        buildkit_syntax_ci_override)
            printf '%s\n' '      --build-arg BuIlDkIt_SyNtAx=docker/dockerfile:1' \
                >>"$case_root/.github/workflows/ci.yml"
            ;;
        refresh_wrong_recipe)
            sed -i \
                's|--file deploy/docker/Dockerfile.package-builder|--file deploy/docker/Dockerfile.setup-smoke|' \
                "$case_root/.github/workflows/package-builders-refresh.yml"
            ;;
        refresh_duplicate_file)
            printf '%s\n' '            --file deploy/docker/Dockerfile.setup-smoke \' \
                >>"$case_root/.github/workflows/qemu-runner-refresh.yml"
            ;;
        refresh_dynamic_build_arg)
            printf '%s\n' '            --build-arg "$EXTRA_BUILD_ARG" \' \
                >>"$case_root/.github/workflows/distro-vm-images-refresh.yml"
            ;;
        refresh_inline_dynamic_build_arg)
            sed -i \
                's|--build-arg "BASE_IMAGE=$BASE_IMAGE" \\|--build-arg "BASE_IMAGE=$BASE_IMAGE" --build-arg "$EXTRA_BUILD_ARG" \\|' \
                "$case_root/.github/workflows/qemu-runner-refresh.yml"
            ;;
        refresh_inline_short_file)
            sed -i \
                's|--metadata-file "$metadata" \\|--metadata-file "$metadata" -f deploy/docker/Dockerfile.setup-smoke \\|' \
                "$case_root/.github/workflows/qemu-runner-refresh.yml"
            ;;
        refresh_separate_short_file_build)
            printf '%s\n' \
                '          docker buildx build -f deploy/docker/Dockerfile.setup-smoke .' \
                >>"$case_root/.github/workflows/qemu-runner-refresh.yml"
            ;;
        direct_docker_build)
            printf '%s\n' \
                '          docker build -f deploy/docker/Dockerfile.setup-smoke .' \
                >>"$case_root/.github/workflows/qemu-runner-refresh.yml"
            ;;
        alternate_frontend_entrypoint)
            printf '%s\n' '          docker buildx bake release' \
                >>"$case_root/.github/workflows/package-builders-refresh.yml"
            ;;
        global_status_write)
            sed -i '/^  contents: read$/a\  statuses: write' \
                "$case_root/.github/workflows/ci.yml"
            ;;
        missing_native_parse)
            sed -i '/docker buildx build --call=targets/d' \
                "$case_root/.github/workflows/ci.yml"
            ;;
        commented_native_parse)
            sed -i \
                '0,/docker buildx build --call=targets/s|docker buildx build --call=targets|# docker buildx build --call=targets|' \
                "$case_root/.github/workflows/ci.yml"
            ;;
        commented_native_recipe)
            sed -i \
                's|docker buildx build --call=targets --file deploy/docker/Dockerfile.qemu-runner \.$|echo deploy/docker/Dockerfile.qemu-runner|' \
                "$case_root/.github/workflows/ci.yml"
            ;;
        query_setup_token)
            sed -i 's|/#token=|/?token=|' "$case_root/README.md"
            ;;
        *)
            echo "unknown negative policy fixture: $case_name" >&2
            exit 2
            ;;
    esac

    if sh "$checker" --audit-remediation-fixture "$case_root" >/dev/null 2>&1; then
        echo "audit-remediation policy tests: accepted invalid fixture $case_name" >&2
        fail=1
    fi
}

for case_name in \
    mutable_frontend \
    wrong_index_digest \
    platform_child_digest \
    spelling_variant \
    second_syntax_directive \
    additional_dockerfile \
    buildkit_syntax_override \
    buildkit_syntax_ci_override \
    refresh_wrong_recipe \
    refresh_duplicate_file \
    refresh_dynamic_build_arg \
    refresh_inline_dynamic_build_arg \
    refresh_inline_short_file \
    refresh_separate_short_file_build \
    direct_docker_build \
    alternate_frontend_entrypoint \
    global_status_write \
    missing_native_parse \
    commented_native_parse \
    commented_native_recipe \
    query_setup_token; do
    expect_rejected "$case_name"
done

[ "$fail" -eq 0 ] || exit 1
echo "audit-remediation policy tests: OK"
