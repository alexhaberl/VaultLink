#!/bin/sh
set -eu

toolchain_file=${1:-rust-toolchain.toml}
channel=$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\([^"]*\)"[[:space:]]*$/\1/p' "$toolchain_file")

if [ "$(printf '%s\n' "$channel" | grep -E -c '^[0-9]+\.[0-9]+\.[0-9]+$')" -ne 1 ]; then
    echo "invalid stable Rust channel in $toolchain_file" >&2
    exit 1
fi

printf '%s\n' "$channel"
