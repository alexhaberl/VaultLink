#!/bin/sh
# Cached dependencies are reusable; successful VM-test results must run again.
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG

[ "$#" -eq 1 ] || {
    echo "usage: $0 x86_64-linux|aarch64-linux" >&2
    exit 64
}
system=$1
case "$system" in
    x86_64-linux|aarch64-linux) ;;
    *) echo "unsupported Nix qualification system: $system" >&2; exit 64 ;;
esac

for check in local smb upgrade; do
    output=$(nix eval --raw ".#checks.$system.$check.outPath" --no-write-lock-file)
    if [ "$(printf '%s\n' "$output" | wc -l)" -ne 1 ] \
        || ! printf '%s\n' "$output" \
            | grep -E -x -q '/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[-A-Za-z0-9+._?=]+'; then
        echo "unsafe Nix VM-test output path for $check" >&2
        exit 65
    fi
    if nix-store --check-validity "$output" 2>/dev/null; then
        # Nix refuses deletion of roots or paths with referrers. Do not bypass
        # that protection or remove dependency closures to make deletion work.
        nix-store --delete "$output"
        printf 'Nix VM result cache: cleared %s\n' "$check"
    else
        printf 'Nix VM result cache: no existing %s result\n' "$check"
    fi
done
