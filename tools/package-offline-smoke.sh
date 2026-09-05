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
migration_pid=

cleanup() {
    if [ -n "$migration_pid" ] && kill -0 "$migration_pid" 2>/dev/null; then
        kill "$migration_pid" 2>/dev/null || true
        wait "$migration_pid" 2>/dev/null || true
    fi
}
trap cleanup 0 1 2 15

fail() {
    echo "offline package smoke failed: $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "the offline package smoke must run as root"
[ "$#" -eq 4 ] || {
    echo "usage: $0 TARGET_ID VERSION PACKAGE NATIVE_LOAD_EVIDENCE" >&2
    exit 64
}
target_id=$1
version=$2
package=$3
native_load_evidence=$4
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
cd "$repo_root"

[ -f "$package" ] && [ ! -L "$package" ] || fail "package input is unsafe"
sh tools/verify-package-builder.sh "$target_id"
sh tools/package-container-smoke.sh "$target_id" "$version" "$package"
id vaultlink >/dev/null 2>&1 \
    || fail "package lifecycle smoke did not preserve the service identity"

systemd-analyze verify \
    /usr/lib/systemd/system/vaultlink.service \
    /usr/lib/systemd/system/vaultlink-update.service \
    /usr/lib/systemd/system/vaultlink-update.timer

api_work=/tmp/vaultlink-offline-package-api
rm -rf "$api_work"
runuser -u vaultlink -- env \
    VAULTLINK_BIN=/opt/vaultlink/vaultlink \
    VAULTLINK_SMOKE_DIR="$api_work" \
    bash deploy/docker/api-smoke.sh

database="$api_work/data/data.sqlite"
sqlite3 "$database" <<'SQL'
BEGIN IMMEDIATE;
INSERT INTO audit(occurred_at,actor,action,object_id,detail,priority)
VALUES('2026-08-30T00:00:00Z','container-gate','upload','migration-probe','preserve',100);
DROP TRIGGER trg_share_search_insert;
DROP TRIGGER trg_share_search_delete;
DROP TRIGGER trg_share_search_update;
DROP TABLE share_search_fts;
DROP INDEX idx_audit_time_id;
DROP INDEX idx_audit_action_id;
DROP INDEX idx_audit_actor_id;
DROP INDEX idx_audit_object_id_id;
DROP INDEX idx_audit_detail_id;
DROP INDEX idx_audit_client_ip_id;
DROP INDEX idx_audit_action_time_id;
ALTER TABLE shares DROP COLUMN path_search_key;
ALTER TABLE shares DROP COLUMN alias_search_key;
DELETE FROM vaultlink_schema_migrations WHERE target_version=8;
UPDATE vaultlink_schema
SET fingerprint='vaultlink-schema-7-monitoring-service-tokens-2026-08-30'
WHERE singleton=1;
PRAGMA user_version=7;
COMMIT;
SQL
[ "$(sqlite3 "$database" 'PRAGMA user_version;')" = 7 ]
runuser -u vaultlink -- /opt/vaultlink/vaultlink \
    --config "$api_work/config.toml" >"$api_work/migration.log" 2>&1 &
migration_pid=$!
for attempt in $(seq 1 100); do
    if curl --fail --silent --show-error \
        http://127.0.0.1:18081/api/v2/health/ready >/dev/null; then
        break
    fi
    [ "$attempt" -lt 100 ] || fail "migrated service did not become ready"
    sleep 0.2
done
kill "$migration_pid"
wait "$migration_pid" || true
migration_pid=
[ "$(sqlite3 "$database" 'PRAGMA user_version;')" = 8 ]
[ "$(sqlite3 "$database" \
    'SELECT COUNT(*) FROM service_tokens;')" = 0 ]
[ "$(sqlite3 "$database" \
    'SELECT COUNT(*) FROM vaultlink_schema_migrations WHERE target_version=8;')" = 1 ]
[ "$(sqlite3 "$database" \
    "SELECT priority FROM audit WHERE object_id='migration-probe';")" = 100 ]
[ "$(sqlite3 "$database" 'PRAGMA integrity_check;')" = ok ]

# The exact installed package payload is then exercised natively on the
# target's same-architecture runner with the smaller CI smoke workload.
# Full-load performance is qualified by the dedicated 72-hour soak VM.
sh tools/package-native-load-smoke.sh \
    "$target_id" "$version" "$package" "$api_work" "$native_load_evidence"

# These fault-injection tests cover transactional migration, backup, start,
# readiness, integrity, and rollback behavior without package repositories.
bash deploy/docker/upgrade-safety-test.sh

printf 'target=%s\nversion=%s\nnetwork=none\nlifecycle=ok\n' \
    "$target_id" "$version"
printf 'systemd_analyze=ok\napi_smoke=ok\nreal_migration=ok\nupgrade_migration_backup_rollback=ok\n'
printf 'native_package_load=ok\nmetadata_p95_limit_seconds=2.000\n'
printf 'load_profile=50_metadata_20_ranges_5_uploads\nload_authority=ci_smoke\n'
