#!/bin/sh
set -eu

duration=${SOAK_SECONDS:-259200}
interval=${SOAK_INTERVAL_SECONDS:-300}
database=${VAULTLINK_DATABASE:-/var/lib/vaultlink/data.sqlite}
output=${SOAK_LOG:-/var/log/vaultlink/soak.csv}
command -v sqlite3 >/dev/null

pid=$(systemctl show -p MainPID --value vaultlink.service)
[ "$pid" -gt 0 ]
restart_start=$(systemctl show -p NRestarts --value vaultlink.service)
rss_start=$(awk '/VmRSS:/ { print $2 }' "/proc/$pid/status")
deadline=$(($(date +%s) + duration))
install -d -o root -g vaultlink -m 0750 "$(dirname "$output")"
printf 'timestamp,pid,rss_kib,restarts,integrity\n' > "$output"

while [ "$(date +%s)" -lt "$deadline" ]; do
    systemctl --quiet is-active vaultlink.service
    pid=$(systemctl show -p MainPID --value vaultlink.service)
    restarts=$(systemctl show -p NRestarts --value vaultlink.service)
    rss=$(awk '/VmRSS:/ { print $2 }' "/proc/$pid/status")
    integrity=$(sqlite3 "$database" 'PRAGMA integrity_check')
    printf '%s,%s,%s,%s,%s\n' "$(date -u +%FT%TZ)" "$pid" "$rss" "$restarts" "$integrity" >> "$output"
    [ "$restarts" = "$restart_start" ] || { echo "unplanned restart detected" >&2; exit 1; }
    [ "$integrity" = ok ] || { echo "SQLite integrity check failed" >&2; exit 1; }
    sleep "$interval"
done

rss_end=$(awk '/VmRSS:/ { print $2 }' "/proc/$pid/status")
limit=$((rss_start + (rss_start * 15 / 100)))
[ "$rss_end" -le "$limit" ] || { echo "RSS grew by more than 15 percent" >&2; exit 1; }
echo "72-hour soak gate passed; evidence: $output"
