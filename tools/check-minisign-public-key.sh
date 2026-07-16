#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { echo "usage: $0 PUBLIC_KEY" >&2; exit 64; }
public_key=$1
[ -s "$public_key" ] || { echo "minisign public key is missing or empty" >&2; exit 1; }
if [ "$(wc -l <"$public_key")" -ne 2 ] \
    || ! grep -E -q '^untrusted comment: minisign public key' "$public_key"; then
    echo "minisign public key has an invalid header" >&2
    exit 1
fi
encoded=$(sed -n '2p' "$public_key")
printf '%s\n' "$encoded" | grep -Eq '^[A-Za-z0-9+/]{56}$' \
    || { echo "minisign public key must be exactly 56 Base64 characters" >&2; exit 1; }
decoded=$(mktemp)
trap 'rm -f "$decoded"' EXIT HUP INT TERM
printf '%s' "$encoded" | base64 --decode >"$decoded" 2>/dev/null \
    || { echo "minisign public key is not valid Base64" >&2; exit 1; }
[ "$(wc -c <"$decoded")" -eq 42 ] \
    || { echo "minisign public key must decode to 42 bytes" >&2; exit 1; }
[ "$(od -An -N2 -tx1 "$decoded" | tr -d ' \n')" = 4564 ] \
    || { echo "minisign public key is not an Ed25519 key" >&2; exit 1; }
