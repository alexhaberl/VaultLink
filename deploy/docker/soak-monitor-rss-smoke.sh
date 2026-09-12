#!/bin/sh
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG
umask 077

fail() {
    echo "soak monitor RSS smoke failed: $*" >&2
    exit 1
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
stub_dir="$work/bin"
mkdir "$stub_dir"

# Run the real monitor at its persisted deadline with synthetic measurements.
# Only host identity, services and time are stubbed: its median calculations, both growth
# checks, candidate output and EXIT result writer execute without modification.
# A fixed Debian-13/amd64 identity permits this isolated smoke on Ubuntu and arm64 CI.
cat >"$stub_dir/date" <<'EOF'
#!/bin/sh
[ "$#" -eq 1 ] && [ "$1" = +%s ] || exit 90
printf '%s\n' "$SOAK_DEADLINE_EPOCH"
EOF
cat >"$stub_dir/uname" <<'EOF'
#!/bin/sh
[ "$#" -eq 1 ] && [ "$1" = -m ] || exit 90
printf '%s\n' x86_64
EOF
cat >"$stub_dir/sed" <<'EOF'
#!/bin/sh
if [ "$#" -eq 3 ] && [ "$1" = -n ] && [ "$3" = /etc/os-release ]; then
    case "$2" in
        's/^ID=//p') printf '%s\n' debian; exit 0 ;;
        's/^VERSION_ID=//p') printf '%s\n' 13; exit 0 ;;
    esac
fi
exec /usr/bin/sed "$@"
EOF
cat >"$stub_dir/systemctl" <<'EOF'
#!/bin/sh
case "$*" in
    'show -p MainPID --value vaultlink.service') printf '%s\n' "$SMOKE_PROCESS_PID" ;;
    'show -p NRestarts --value vaultlink.service') printf '%s\n' 0 ;;
    *) exit 90 ;;
esac
EOF
cat >"$stub_dir/journalctl" <<'EOF'
#!/bin/sh
set -eu
[ "$*" = "--quiet --unit=vaultlink.service --since=@$SOAK_START_EPOCH --no-pager" ] || exit 90
# The first final journal read follows the monitor's fresh CSV header. Restore
# the test's completed measurement history before the actual RSS checks run.
cp "$SMOKE_METRICS" "$SOAK_EVIDENCE_DIR/metrics.csv"
EOF
chmod 0755 "$stub_dir/date" "$stub_dir/uname" "$stub_dir/sed" \
    "$stub_dir/systemctl" "$stub_dir/journalctl"

assert_field() {
    field=$1
    expected=$2
    file=$3
    [ "$(grep -c "^$field=" "$file" || true)" -eq 1 ] \
        || fail "$case_name must write $field exactly once"
    grep -F -x -q "$field=$expected" "$file" \
        || fail "$case_name wrote an unexpected $field"
}

run_case() {
    case_name=$1
    warm=$2
    late=$3
    final=$4
    warm_limit=$5
    late_limit=$6
    expected_state=$7
    expected_reason=$8
    expected_status=$9
    case_dir="$work/$case_name"
    mkdir "$case_dir"
    printf '%s\n' '# Synthetic configuration: only its digest is inspected.' >"$case_dir/config.toml"
    start=1000000
    deadline=$((start + 259200))
    # Distinct, deliberately unsorted RSS values exercise real odd/even medians.
    # Very large values outside the windows must not affect their results.
    awk -v start="$start" -v deadline="$deadline" -v pid="$$" \
        -v warm="$warm" -v late="$late" -v final="$final" '
        function sample(epoch, rss) {
            printf "%d,synthetic,%d,%d,0,health,config,ok\n", epoch, pid, rss
        }
        BEGIN {
            print "epoch,timestamp,pid,rss_kib,restarts,health_sha256,config_sha256,integrity"
            sample(start + 1799, 200000)
            sample(start + 1800, warm + 20)
            sample(start + 3600, warm - 20)
            sample(start + 5400, warm)
            sample(start + 5401, 200000)
            sample(start + 172799, 200000)
            sample(start + 172800, late + 20)
            sample(start + 183600, late - 20)
            sample(start + 194400, late)
            sample(start + 194401, 200000)
            sample(deadline - 3601, 200000)
            sample(deadline - 3600, final + 21)
            sample(deadline - 2400, final - 19)
            sample(deadline - 1200, final + 1)
            sample(deadline, final - 1)
        }
    ' >"$case_dir/measurements.csv"
    binary_hash=$(sha256sum "/proc/$$/exe" | awk '{ print $1 }')
    commit=0123456789abcdef0123456789abcdef01234567
    status=0
    PATH="$stub_dir:$PATH" \
        SMOKE_PROCESS_PID=$$ \
        SMOKE_METRICS="$case_dir/measurements.csv" \
        SOAK_COMMIT_SHA=$commit \
        SOAK_BINARY_SHA256=$binary_hash \
        SOAK_ORCHESTRATION_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
        SOAK_EVIDENCE_DIR="$case_dir/evidence" \
        SOAK_NAMESPACE="$commit-$start-0123456789abcdef" \
        SOAK_START_EPOCH=$start SOAK_DEADLINE_EPOCH=$deadline \
        SOAK_SECONDS=259200 SOAK_INTERVAL_SECONDS=300 SOAK_LOAD_INTERVAL_SECONDS=21600 \
        SOAK_ARCHITECTURE=amd64 SOAK_OS_ID=debian SOAK_OS_VERSION_ID=13 \
        SOAK_EXPECTED_VERSION=0.7.0 SOAK_LOAD_SCRIPT=/bin/false \
        VAULTLINK_CONFIG="$case_dir/config.toml" \
        sh tools/soak-monitor.sh >"$case_dir/monitor.log" 2>&1 || status=$?
    if [ "$status" -ne "$expected_status" ]; then
        cat "$case_dir/monitor.log" >&2
        fail "$case_name exited $status instead of $expected_status"
    fi
    result="$case_dir/evidence/result.env"
    candidate="$case_dir/evidence/candidate.env"
    if [ ! -f "$result" ] || [ ! -f "$candidate" ]; then
        fail "$case_name did not persist its result and candidate evidence"
    fi
    assert_field state "$expected_state" "$result"
    assert_field reason "$expected_reason" "$result"
    assert_field duration_seconds 259200 "$result"
    assert_field warm_rss_median_kib "$warm" "$candidate"
    assert_field late_rss_median_kib "$late" "$candidate"
    assert_field final_rss_median_kib "$final" "$candidate"
    assert_field warm_rss_growth_limit_kib "$warm_limit" "$candidate"
    assert_field late_rss_growth_limit_kib "$late_limit" "$candidate"
}

# Expected limits are fixed test values rather than recomputed by the test.
run_case pass 35000 45000 49096 59576 49096 success passed 0
run_case warm-failure 48948 72000 73525 73524 76096 failure rss_growth_exceeded_warm_allowance 1
run_case late-failure 50000 55000 59097 74576 59096 failure rss_growth_exceeded_late_allowance 1

echo "Soak monitor preserves RSS diagnostics for passing and failed growth checks"
