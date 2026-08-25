#!/bin/sh
# Compound guards intentionally use `A && B || fail` for fail-closed exits.
# shellcheck disable=SC2015
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CDPATH=
LC_ALL=C
LANG=C
export PATH CDPATH LC_ALL LANG
umask 077

fail() {
    echo "native package ELF check failed: $*" >&2
    exit 1
}

[ "$#" -eq 2 ] || {
    echo "usage: check-native-package-elf.sh TARGET_ID BINARY" >&2
    exit 64
}
target_id=$1
binary=$2
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
cd "$repo_root"

[ -f "$binary" ] && [ ! -L "$binary" ] && [ -x "$binary" ] \
    || fail "binary must be an executable regular file"
command -v readelf >/dev/null || fail "readelf is required"
python3 tools/package-targets.py validate --allow-unprovisioned >/dev/null
expected_uname=$(python3 tools/package-targets.py get \
    "$target_id" uname --allow-unprovisioned)

work=$(mktemp -d "${TMPDIR:-/tmp}/vaultlink-elf-check.XXXXXXXX")
cleanup() {
    rm -rf "$work"
}
trap cleanup 0 1 2 15

readelf -W -h "$binary" >"$work/header" \
    || fail "binary is not a readable ELF object"
grep -E -q '^  Class:[[:space:]]+ELF64$' "$work/header" \
    || fail "binary must be ELF64"
grep -E -q '^  Data:[[:space:]]+2.s complement, little endian$' "$work/header" \
    || fail "binary must be little-endian"
grep -E -q '^  Type:[[:space:]]+DYN \(Position-Independent Executable file\)$' "$work/header" \
    || fail "binary must be a position-independent executable"

case "$expected_uname" in
    x86_64)
        expected_machine='Advanced Micro Devices X86-64'
        expected_interpreter=/lib64/ld-linux-x86-64.so.2
        loader_soname=ld-linux-x86-64.so.2
        ;;
    aarch64)
        expected_machine=AArch64
        expected_interpreter=/lib/ld-linux-aarch64.so.1
        loader_soname=ld-linux-aarch64.so.1
        ;;
    *) fail "unsupported manifest machine: $expected_uname" ;;
esac
grep -F -x -q "  Machine:                           $expected_machine" "$work/header" \
    || fail "ELF machine does not match $expected_uname"

readelf -W -l "$binary" >"$work/program-headers"
interpreter=$(sed -n 's/^.*\[Requesting program interpreter: \(.*\)\]$/\1/p' \
    "$work/program-headers")
[ "$interpreter" = "$expected_interpreter" ] \
    || fail "unexpected ELF interpreter: ${interpreter:-missing}"
grep -E -q '^  GNU_RELRO[[:space:]]' "$work/program-headers" \
    || fail "ELF lacks GNU_RELRO"
gnu_stack=$(grep -E '^  GNU_STACK[[:space:]]' "$work/program-headers")
[ -n "$gnu_stack" ] || fail "ELF lacks GNU_STACK metadata"
printf '%s\n' "$gnu_stack" | grep -E -q '[[:space:]]RW[[:space:]]' \
    || fail "ELF stack is executable or has unexpected permissions"

readelf -W -d "$binary" >"$work/dynamic"
grep -E -q 'BIND_NOW|Flags:.*(^|[[:space:]])NOW([[:space:]]|$)' "$work/dynamic" \
    || fail "ELF lacks immediate relocation binding"
if grep -E -q '\((RPATH|RUNPATH|TEXTREL)\)' "$work/dynamic"; then
    fail "ELF contains a forbidden RPATH, RUNPATH, or TEXTREL entry"
fi
sed -n 's/^.*Shared library: \[\([^]]*\)\].*$/\1/p' "$work/dynamic" \
    | sort -u >"$work/needed"
cat >"$work/allowed-needed" <<EOF
$loader_soname
libc.so.6
libgcc_s.so.1
libm.so.6
EOF
sort -u "$work/allowed-needed" -o "$work/allowed-needed"
comm -23 "$work/needed" "$work/allowed-needed" >"$work/unexpected-needed"
[ ! -s "$work/unexpected-needed" ] \
    || { sed 's/^/unexpected ELF dependency: /' "$work/unexpected-needed" >&2; exit 1; }
for required_soname in libc.so.6 libgcc_s.so.1 libm.so.6; do
    grep -F -x -q "$required_soname" "$work/needed" \
        || fail "ELF is missing required runtime closure member $required_soname"
done

echo "$(basename "$binary"): native package ELF closure passed"
