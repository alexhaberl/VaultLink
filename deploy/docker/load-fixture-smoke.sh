#!/bin/sh
set -eu
umask 077

fail() {
    echo "load fixture smoke failed: $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "test must run as root"
command -v strace >/dev/null || fail "strace is required"
command -v inotifywait >/dev/null || fail "inotifywait is required"
id vaultlink >/dev/null 2>&1 || fail "vaultlink account is required"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
chmod 0755 "$work"
vaultlink_uid=$(id -u vaultlink)
vaultlink_gid=$(id -g vaultlink)
helper=$(realpath -e tools/prepare-load-fixture.sh)
output="$work/output"

new_storage() {
    storage=$1
    install -d -o vaultlink -g vaultlink -m 0750 "$storage"
}

expect_status() {
    expected=$1
    shift
    set +e
    "$@" >"$output" 2>&1
    actual=$?
    set -e
    [ "$actual" -eq "$expected" ] \
        || fail "expected exit $expected, got $actual: $(cat "$output")"
}

assert_sentinel() {
    sentinel=$1
    expected=$2
    [ "$(cat "$sentinel")" = "$expected" ] || fail "root sentinel content changed"
    [ "$(stat -c '%u:%g:%a' "$sentinel")" = '0:0:600' ] \
        || fail "root sentinel ownership or mode changed"
}

assert_storage_mutations_unprivileged() {
    trace_file=$1
    traced_storage=$2
    awk -v service_uid="$vaultlink_uid" -v storage="$traced_storage" '
        function mutation(line) {
            if (index(line, storage) == 0)
                return 0
            if (line ~ /^(mkdir|mkdirat|rmdir|unlink|unlinkat|rename|renameat|renameat2|link|linkat|symlink|symlinkat|chmod|fchmod|fchmodat|fchmodat2|chown|fchown|fchownat|truncate|ftruncate|fallocate|write|pwrite64)\(/)
                return 1
            return line ~ /^(open|openat|openat2)\(/ && line ~ /O_(WRONLY|RDWR|CREAT|TRUNC)/
        }
        {
            pid = $1
            line = $0
            sub(/^[0-9]+[[:space:]]+/, "", line)
            if (line ~ ("^setuid\\(" service_uid "([[:space:]]|\\))"))
                service_switch_started[pid] = 1
            if (line ~ ("^setuid\\(" service_uid "\\)[[:space:]]+= 0$") \
                || (service_switch_started[pid] && line ~ /^<\.\.\. setuid resumed>.* = 0$/))
                service_switch[pid] = 1
            if (service_switch[pid] && line ~ /^setuid\(/ \
                && line !~ ("^setuid\\(" service_uid "\\)") && line ~ / = 0$/)
                privilege_regained[pid] = 1
            if (line ~ /^(clone|clone3|fork|vfork)\(/ || line ~ /^<\.\.\. (clone|clone3|fork|vfork) resumed>/) {
                child = line
                sub(/^.* = /, "", child)
                if (child ~ /^[0-9]+$/)
                    parent[child] = pid
            }
            if (mutation(line)) {
                mutations++
                mutation_pid[mutations] = pid
                mutation_line[mutations] = $0
            }
        }
        END {
            for (pid in service_switch)
                unprivileged[pid] = 1
            do {
                changed = 0
                for (child in parent)
                    if (unprivileged[parent[child]] && !unprivileged[child]) {
                        unprivileged[child] = 1
                        changed = 1
                    }
            } while (changed)
            for (pid in privilege_regained) {
                print "service process regained privilege: " pid > "/dev/stderr"
                failed = 1
            }
            for (i = 1; i <= mutations; i++)
                if (!unprivileged[mutation_pid[i]]) {
                    print "privileged storage mutation: " mutation_line[i] > "/dev/stderr"
                    failed = 1
                }
            if (mutations == 0) {
                print "trace contained no storage mutations" > "/dev/stderr"
                failed = 1
            }
            exit failed
        }
    ' "$trace_file" || fail "storage mutation escaped the vaultlink UID"
}

# Happy path through the privileged validator and runuser boundary.
storage="$work/happy/shared"
new_storage "$storage"
trace="$work/happy.strace"
strace -f -qq -y -o "$trace" \
    -e trace=process,setuid,setgid,setgroups,%file,ftruncate,fchmod,fchown,write,pwrite64,fallocate \
    /bin/sh "$helper" "$storage" >"$output"
fixture="$storage/vaultlink-load"
[ -d "$fixture/uploads" ] || fail "upload directory was not published"
[ -f "$fixture/sparse-50GiB.bin" ] || fail "sparse file was not published"
[ "$(stat -c '%u:%g:%a' "$fixture")" = "$vaultlink_uid:$vaultlink_gid:750" ] \
    || fail "fixture root has incorrect owner, group, or mode"
[ "$(stat -c '%u:%g:%a' "$fixture/uploads")" = "$vaultlink_uid:$vaultlink_gid:750" ] \
    || fail "upload directory has incorrect owner, group, or mode"
[ "$(stat -c '%u:%g:%a:%s' "$fixture/sparse-50GiB.bin")" \
    = "$vaultlink_uid:$vaultlink_gid:640:53687091200" ] \
    || fail "sparse file has incorrect owner, group, mode, or size"
[ "$(stat -c '%b' "$fixture/sparse-50GiB.bin")" -le 8 ] \
    || fail "50 GiB fixture unexpectedly allocated data blocks"
grep -F -q 'execve("/usr/sbin/runuser"' "$trace" \
    || fail "trace did not cross the runuser boundary"
assert_storage_mutations_unprivileged "$trace" "$storage"
grep -E -q '(mkdir|mkdirat)\(' "$trace" \
    || fail "trace is missing a directory-creation mutation"
grep -E -q '(chmod|fchmod|fchmodat|fchmodat2)\(' "$trace" \
    || fail "trace is missing a mode mutation"
grep -F -q 'O_WRONLY|O_CREAT' "$trace" \
    || fail "trace is missing a write/create open mutation"
grep -E -q '(rename|renameat|renameat2)\(' "$trace" \
    || fail "trace is missing an atomic publish mutation"
if grep -E -q '(execve\("[^\"]*/(chown|install)"|(^|[[:space:]])(chown|fchownat)\()' "$trace"; then
    fail "trace contains a forbidden ownership-changing mutation"
fi
grep -F -x -q \
    'Create a download share for vaultlink-load/sparse-50GiB.bin and an upload share for vaultlink-load/uploads.' \
    "$output" || fail "helper printed incorrect SecureRoot-relative paths"

# Validation failures have stable sysexits-style statuses.
expect_status 64 /bin/sh "$helper" relative/path
expect_status 64 /bin/sh "$helper" /
expect_status 66 /bin/sh "$helper" "$work/missing"
wrong_owner="$work/wrong-owner"
install -d -o root -g root -m 0750 "$wrong_owner"
expect_status 77 /bin/sh "$helper" "$wrong_owner"
expect_status 77 /usr/sbin/runuser -u nobody -- \
    /bin/sh "$helper" --vaultlink-phase "$storage"

# A pre-positioned publish symlink is a collision, never a traversal target.
sentinel="$work/root-sentinel"
sentinel_text='root-owned sentinel must remain unchanged'
printf '%s\n' "$sentinel_text" >"$sentinel"
chmod 0600 "$sentinel"
storage="$work/pre-positioned/shared"
new_storage "$storage"
ln -s "$sentinel" "$storage/vaultlink-load"
expect_status 73 /bin/sh "$helper" "$storage"
assert_sentinel "$sentinel" "$sentinel_text"

# Delay descendant execve calls in the test harness. The helper creates the
# sparse pathname with `touch` before invoking `truncate`; the inotify-driven
# service-account process therefore replaces it deterministically between those
# two commands, without adding a production test hook to the helper.
storage="$work/truncate-race/shared"
new_storage "$storage"
attacker_result="$work/truncate-attacker"
(
    staging_name=$(inotifywait --quiet --timeout 10 --event create \
        --include '/?\.vaultlink-load\.[^/]+$' --format '%f' "$storage") || exit 1
    staging="$storage/$staging_name"
    sparse_name=$(inotifywait --quiet --timeout 10 --event create \
        --include '/?sparse-50GiB\.bin$' --format '%f' "$staging") || exit 1
    [ "$sparse_name" = sparse-50GiB.bin ] || exit 1
    # shellcheck disable=SC2016 # positional parameters expand in the child shell
    /usr/sbin/runuser -u vaultlink -- /bin/sh -c '
        rm -f -- "$1" && ln -s -- "$2" "$1"
    ' attacker "$staging/$sparse_name" "$sentinel"
    printf '%s\n' hit >"$attacker_result"
) &
attacker=$!
set +e
truncate_trace="$work/truncate-race.strace"
strace -f -qq -y -o "$truncate_trace" \
    -e trace=process,setuid,setgid,setgroups,%file,ftruncate,fchmod,fchown,write,pwrite64,fallocate \
    -e inject=execve:delay_enter=200ms \
    /bin/sh "$helper" "$storage" >"$output" 2>&1
status=$?
set -e
wait "$attacker" || fail "truncate-race attacker timed out"
[ "$status" -ne 0 ] || fail "truncate race unexpectedly published a fixture"
[ "$(cat "$attacker_result")" = hit ] || fail "truncate race was not exercised"
assert_storage_mutations_unprivileged "$truncate_trace" "$storage"
grep -E -q '(unlink|unlinkat|rmdir)\(' "$truncate_trace" \
    || fail "truncate race did not trace unprivileged staging cleanup"
assert_sentinel "$sentinel" "$sentinel_text"

# Interpose a target symlink after inotify reports sparse-file metadata activity
# but before the deliberately delayed `mv`. `mv -n` must retain the staging
# name, after which the helper reports exit 73.
storage="$work/publish-race/shared"
new_storage "$storage"
attacker_result="$work/publish-attacker"
(
    staging_name=$(inotifywait --quiet --timeout 10 --event create \
        --include '/?\.vaultlink-load\.[^/]+$' --format '%f' "$storage") || exit 1
    staging="$storage/$staging_name"
    sparse_name=$(inotifywait --quiet --timeout 10 --event attrib \
        --include '/?sparse-50GiB\.bin$' --format '%f' "$staging") || exit 1
    [ "$sparse_name" = sparse-50GiB.bin ] || exit 1
    /usr/sbin/runuser -u vaultlink -- \
        ln -s "$sentinel" "$storage/vaultlink-load"
    printf '%s\n' hit >"$attacker_result"
) &
attacker=$!
set +e
publish_trace="$work/publish-race.strace"
strace -f -qq -y -o "$publish_trace" \
    -e trace=process,setuid,setgid,setgroups,%file,ftruncate,fchmod,fchown,write,pwrite64,fallocate \
    -e inject=execve:delay_enter=200ms \
    /bin/sh "$helper" "$storage" >"$output" 2>&1
status=$?
set -e
wait "$attacker" || fail "publish-race attacker timed out"
[ "$status" -eq 73 ] || fail "publish race returned $status instead of 73"
[ "$(cat "$attacker_result")" = hit ] || fail "publish race was not exercised"
[ -L "$storage/vaultlink-load" ] || fail "publish collision replaced the attacker symlink"
assert_storage_mutations_unprivileged "$publish_trace" "$storage"
grep -E -q '(unlink|unlinkat|rmdir)\(' "$publish_trace" \
    || fail "publish race did not trace unprivileged staging cleanup"
assert_sentinel "$sentinel" "$sentinel_text"

echo "Load fixture privilege and symlink-race smoke tests passed"
