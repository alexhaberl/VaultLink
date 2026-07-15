#!/bin/sh
set -eu

LC_ALL=C
export LC_ALL

allowlist=${CARGO_DUPLICATE_ALLOWLIST:-tools/cargo-duplicate-allowlist.txt}

if [ ! -f "$allowlist" ]; then
    echo "cargo duplicate policy: missing allowlist: $allowlist" >&2
    exit 1
fi

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
tree_output="$work_dir/cargo-tree.txt"
actual="$work_dir/actual.txt"
expected="$work_dir/expected.txt"
expected_unsorted="$work_dir/expected-unsorted.txt"

if ! cargo tree --locked --workspace --target all -d --depth 0 \
    --prefix none --format '{p}' >"$tree_output"; then
    echo "cargo duplicate policy: cargo tree failed" >&2
    exit 1
fi

# Cargo package names are ASCII and treat '-'/'_' as the same crate-name family.
# Count distinct versions so duplicate graph entries for the same package version
# do not create a false positive.
awk '
    NF >= 2 {
        name = tolower($1)
        gsub(/_/, "-", name)
        version = $2
        sub(/^v/, "", version)
        package = name SUBSEP version
        if (!seen_package[package]++)
            version_count[name]++
    }
    END {
        for (name in version_count)
            if (version_count[name] > 1)
                print name
    }
' "$tree_output" | sort -u >"$actual"

if ! awk '
    {
        sub(/[[:space:]]*#.*/, "")
        gsub(/^[[:space:]]+|[[:space:]]+$/, "")
    }
    NF == 0 { next }
    NF != 1 {
        print "cargo duplicate policy: invalid allowlist entry: " $0 > "/dev/stderr"
        invalid = 1
        next
    }
    {
        name = tolower($1)
        gsub(/_/, "-", name)
        print name
    }
    END { exit invalid }
' "$allowlist" >"$expected_unsorted"; then
    exit 1
fi
sort -u "$expected_unsorted" >"$expected"

new_families=$(comm -13 "$expected" "$actual")
stale_families=$(comm -23 "$expected" "$actual")
failed=0

if [ -n "$new_families" ]; then
    printf '%s\n' "cargo duplicate policy: unapproved duplicate families:" >&2
    printf '%s\n' "$new_families" | sed 's/^/  /' >&2
    failed=1
fi

if [ -n "$stale_families" ]; then
    printf '%s\n' "cargo duplicate policy: stale allowlist families:" >&2
    printf '%s\n' "$stale_families" | sed 's/^/  /' >&2
    failed=1
fi

if [ "$failed" -ne 0 ]; then
    exit 1
fi

family_count=$(wc -l <"$actual" | tr -d '[:space:]')
echo "Cargo duplicate policy checks passed ($family_count approved families)"
