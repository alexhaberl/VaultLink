#!/bin/sh
set -eu

usage() {
    echo "usage: $0 [--binary PATH] [--release-candidate | --release-tag TAG]" >&2
    exit 64
}

binary=
release_candidate=0
release_tag=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary)
            [ "$#" -ge 2 ] || usage
            binary=$2
            shift 2
            ;;
        --release-tag)
            [ "$#" -ge 2 ] || usage
            release_tag=$2
            shift 2
            ;;
        --release-candidate)
            release_candidate=1
            shift
            ;;
        *) usage ;;
    esac
done

[ "$release_candidate" -eq 0 ] || [ -z "$release_tag" ] || usage

cd "$(dirname "$0")/.."

package_version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | sed -n '1p')
[ -n "$package_version" ] || {
    echo "Cargo.toml package version is missing" >&2
    exit 1
}
release_version=0.5.0
if [ "$release_candidate" -eq 1 ] || [ -n "$release_tag" ]; then
    [ "$package_version" = "$release_version" ] || {
        echo "release preflight is fixed to $release_version, not $package_version" >&2
        exit 1
    }
fi

lock_version=$(awk '
    /^\[\[package\]\]$/ { in_package = 0 }
    $0 == "name = \"vaultlink\"" { in_package = 1; next }
    in_package && /^version = / {
        value = $0
        sub(/^version = "/, "", value)
        sub(/"$/, "", value)
        print value
        exit
    }
' Cargo.lock)
[ "$lock_version" = "$package_version" ] || {
    echo "VaultLink Cargo.lock version $lock_version does not match Cargo.toml $package_version" >&2
    exit 1
}

grep -Fq "Status: \`$package_version\`" README.md || {
    echo "README status does not identify $package_version" >&2
    exit 1
}
grep -Fq "Release line: \`$package_version\`" SECURITY.md || {
    echo "SECURITY.md does not identify the $package_version release line" >&2
    exit 1
}

changelog_version=$(sed -n 's/^## \([^ ]*\).*/\1/p' CHANGELOG.md | sed -n '1p')
[ "$changelog_version" = "$package_version" ] || {
    echo "top CHANGELOG version $changelog_version does not match $package_version" >&2
    exit 1
}
changelog_heading=$(sed -n 's/^## //p' CHANGELOG.md | sed -n '1p')
unreleased_heading="$package_version — Unreleased release candidate"
released_prefix="$package_version — "
released_date=
case "$changelog_heading" in
    "$unreleased_heading") ;;
    "$released_prefix"????-??-??)
        released_date=${changelog_heading#"$released_prefix"}
        printf '%s\n' "$released_date" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' || {
            echo "top CHANGELOG release date is not ISO formatted: $released_date" >&2
            exit 1
        }
        ;;
    *)
        echo "top CHANGELOG entry must be '$unreleased_heading' or a committed ISO release date" >&2
        exit 1
        ;;
esac

if [ "$release_candidate" -eq 1 ] || [ -n "$release_tag" ]; then
    [ -n "$released_date" ] || {
        echo "release preflight requires a committed ISO date and rejects an Unreleased candidate" >&2
        exit 1
    }
    normalized_date=$(date -u -d "$released_date" +%F 2>/dev/null) || {
        echo "CHANGELOG release date is not a real UTC calendar date: $released_date" >&2
        exit 1
    }
    [ "$normalized_date" = "$released_date" ] || {
        echo "CHANGELOG release date is not canonical: $released_date" >&2
        exit 1
    }
    sh tools/check-minisign-public-key.sh release/minisign.pub || {
        echo "release/minisign.pub must be provisioned before the release-candidate preflight" >&2
        exit 1
    }
fi

grep -Fq 'env!("CARGO_PKG_VERSION")' src/main.rs
grep -Fq 'env!("CARGO_PKG_VERSION")' src/api.rs

if [ -n "$binary" ]; then
    [ -x "$binary" ] || {
        echo "version-check binary is not executable: $binary" >&2
        exit 1
    }
    binary_version=$("$binary" --version)
    [ "$binary_version" = "$package_version" ] || {
        echo "binary reports $binary_version instead of $package_version" >&2
        exit 1
    }
fi

if [ "$release_candidate" -eq 1 ] || [ -n "$release_tag" ]; then
    grep -Fq "# v$package_version release checklist" docs/RELEASE-CHECKLIST.md
    grep -Fq "VaultLink-$package_version-debian13-amd64.tar.gz" docs/SELF-HOSTED-RUNNER.md
    grep -Fq "VaultLink-$package_version-debian13-arm64.tar.gz" docs/SELF-HOSTED-RUNNER.md
fi

if [ -n "$release_tag" ]; then
    [ "$release_tag" = "v$package_version" ] || {
        echo "release tag $release_tag does not match v$package_version" >&2
        exit 1
    }
    today=$(date -u +%F)
    [ "$released_date" = "$today" ] || {
        echo "release tag date $today does not match committed CHANGELOG date $released_date" >&2
        exit 1
    }
fi

echo "version consistency: $package_version"
