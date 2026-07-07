#!/bin/sh
set -eu

: "${VAULTLINK_BASE_URL:?set VAULTLINK_BASE_URL}"
: "${DOWNLOAD_TOKEN:?set DOWNLOAD_TOKEN}"
: "${UPLOAD_TOKEN:?set UPLOAD_TOKEN}"
command -v curl >/dev/null
command -v hey >/dev/null || { echo "hey is required for the 100-user metadata profile" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
truncate -s 64M "$work/upload.bin"

pid=$(systemctl show -p MainPID --value vaultlink.service 2>/dev/null || true)
rss_before=0
if [ -n "$pid" ] && [ "$pid" -gt 0 ] 2>/dev/null; then
    rss_before=$(awk '/VmRSS:/ { print $2 * 1024 }' "/proc/$pid/status")
fi

hey -n 2000 -c 100 "$VAULTLINK_BASE_URL/v/$DOWNLOAD_TOKEN" > "$work/hey.txt"
grep -E '99%|95%|Status code distribution' "$work/hey.txt"
p95=$(awk '$1 == "95%" { print $3 }' "$work/hey.txt")
[ -n "$p95" ] || { echo "could not parse metadata p95" >&2; exit 1; }
awk -v p95="$p95" 'BEGIN { exit !(p95 < 0.750) }' || { echo "metadata p95 gate exceeded: $p95 seconds" >&2; exit 1; }
if grep -Eq '\[(5[0-9][0-9])\]' "$work/hey.txt"; then
    echo "metadata profile returned 5xx" >&2
    exit 1
fi

downloads=0
while [ "$downloads" -lt 40 ]; do
    curl --fail --silent --show-error --range 0-1073741823 \
        "$VAULTLINK_BASE_URL/v/$DOWNLOAD_TOKEN/download" -o /dev/null &
    downloads=$((downloads + 1))
done
wait

uploads=0
while [ "$uploads" -lt 10 ]; do
    curl --fail --silent --show-error \
        -F "file=@$work/upload.bin;filename=load-$uploads.bin" \
        "$VAULTLINK_BASE_URL/v/$UPLOAD_TOKEN/upload" -o /dev/null &
    uploads=$((uploads + 1))
done
wait

if [ -n "$pid" ] && [ "$pid" -gt 0 ] 2>/dev/null; then
    rss_after=$(awk '/VmRSS:/ { print $2 * 1024 }' "/proc/$pid/status")
    added=$((rss_after - rss_before))
    [ "$added" -le 268435456 ] || { echo "RSS gate exceeded: $added bytes" >&2; exit 1; }
    echo "additional RSS: $added bytes"
fi

echo "Load profile passed; metadata p95: $p95 seconds."
