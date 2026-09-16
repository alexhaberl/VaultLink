#!/bin/sh
# Audit committed bytes against a newly fetched database without changing the candidate.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 COMMIT REPORT_DIRECTORY" >&2
    exit 64
fi
commit=$1
report=$2
case "$commit" in ''|*[!0-9a-f]*) exit 64 ;; esac
[ "${#commit}" -eq 40 ] || exit 64
[ "$(git rev-parse "$commit^{commit}")" = "$commit" ] || exit 65
[ "$(cargo audit --version | awk '{print $NF}')" = 0.22.2 ] || exit 65

# Each invocation has its own empty database: a fetch failure cannot silently
# reuse an earlier successful audit. Keep the report outside the source tree.
[ ! -e "$report" ] || exit 73
mkdir -p "$report"
git show "$commit:Cargo.lock" >"$report/Cargo.lock"
lock_sha256=$(sha256sum "$report/Cargo.lock" | awk '{print $1}')
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM

result=0
cargo audit --deny warnings --ignore RUSTSEC-2023-0071 \
    --db "$work/advisory-db" --file "$report/Cargo.lock" --json \
    >"$report/audit.json" 2>"$report/audit.log" || result=$?
database_commit=$(git -C "$work/advisory-db" rev-parse HEAD 2>/dev/null || true)
case "$database_commit" in
    ''|*[!0-9a-f]*) database_commit=unavailable; result=1 ;;
esac
if [ "$database_commit" != unavailable ] && [ "${#database_commit}" -ne 40 ]; then
    database_commit=unavailable
    result=1
fi
test "$lock_sha256" = "$(sha256sum "$report/Cargo.lock" | awk '{print $1}')" || result=1
{
    printf 'commit=%s\nlock_sha256=%s\n' "$commit" "$lock_sha256"
    printf 'database_commit=%s\naudit_version=0.22.2\n' "$database_commit"
    printf 'started_at=%s\nfinished_at=%s\n' "$started_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'exit_code=%s\n' "$result"
} >"$report/receipt.env"
cat "$report/receipt.env"
cat "$report/audit.log"
if [ "$result" -ne 0 ]; then
    cat "$report/audit.json"
    echo "Candidate security audit failed; retry the audit or review the advisory before release." >&2
fi
exit "$result"
