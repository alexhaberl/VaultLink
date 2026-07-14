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
    if ! grep -F -q '["self-hosted", "Linux", "ARM64", "vaultlink"]' "$workflow"; then
        report "$workflow must keep arm64 on the dedicated self-hosted runner"
    fi
done

unexpected_hosted_runners=$(grep -R -n -E 'runs[_-]on:.*(ubuntu-|windows-|macos-)' .github/workflows || true)
if [ -n "$unexpected_hosted_runners" ]; then
    printf '%s\n' "$unexpected_hosted_runners" >&2
    report "workflows must not use GitHub-hosted compute"
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

dependabot_config=.github/dependabot.yml
stable_minor_dependencies='data-encoding http mime_guess percent-encoding rpassword rustix serde serde_json subtle tempfile thiserror tokio toml url uuid'
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
if [ "$dependabot_grouped_minor_count" -ne 15 ]; then
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

for target in path_normalization byte_range filename zip_search_preview_paths upload_overwrite_policy upload_validation_policy api_request_policy file_mutation_policy multipart_guard; do
    if ! grep -E -q "(^|[[:space:]])${target}([[:space:]]|$)" Makefile; then
        report "Makefile fuzz target list is missing $target"
    fi
done

for workflow in .github/workflows/fuzz.yml .github/workflows/security-audit.yml; do
    if ! grep -F -q 'runs-on: [self-hosted, Linux, ARM64, vaultlink]' "$workflow"; then
        report "$workflow must use the dedicated self-hosted arm64 runner"
    fi
done

arm64_release_jobs=$(grep -F -c 'runs-on: [self-hosted, Linux, ARM64, vaultlink]' .github/workflows/release.yml || true)
if [ "$arm64_release_jobs" -ne 3 ]; then
    report "architecture-independent release jobs must use the self-hosted arm64 runner"
fi

if ! grep -F -q 'run: make fuzz-parallel' .github/workflows/fuzz.yml; then
    report "fuzz workflow must run all targets through the parallel Make target"
fi

if ! grep -E -q '^[[:space:]]+FUZZ_JOBS:[[:space:]]+4$' .github/workflows/fuzz.yml; then
    report "fuzz workflow must run all nine targets across four workers"
fi

if ! grep -E -q '^[[:space:]]+timeout-minutes:[[:space:]]+60$' .github/workflows/fuzz.yml; then
    report "fuzz workflow must allow one hour for instrumented builds and three target waves"
fi

if ! grep -F -x -q 'LimitNOFILE=4096' deploy/vaultlink.service; then
    report "vaultlink.service must retain its explicit file-descriptor ceiling"
fi
if ! grep -F -x -q 'TasksMax=512' deploy/vaultlink.service; then
    report "vaultlink.service must retain its explicit task ceiling"
fi

if ! grep -E -q '^[[:space:]]+cancel-in-progress:[[:space:]]+true$' .github/workflows/fuzz.yml; then
    report "fuzz workflow must cancel superseded runs"
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi

echo "Supply-chain policy checks passed"
