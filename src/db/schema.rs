use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

pub(super) const SCHEMA_VERSION: i64 = 10;
pub(super) const SCHEMA_1_FINGERPRINT: &str = "vaultlink-schema-1-encrypted-secrets-2026-07-17";
pub(super) const SCHEMA_2_FINGERPRINT: &str = "vaultlink-schema-2-migration-history-2026-07-17";
pub(super) const SCHEMA_3_FINGERPRINT: &str = "vaultlink-schema-3-share-indexes-2026-07-17";
pub(super) const SCHEMA_4_FINGERPRINT: &str =
    "vaultlink-schema-4-admin-session-activity-2026-07-18";
pub(super) const SCHEMA_5_FINGERPRINT: &str = "vaultlink-schema-5-audit-priority-2026-07-19";
pub(super) const SCHEMA_6_FINGERPRINT: &str = "vaultlink-schema-6-typed-audit-policy-2026-07-20";
pub(super) const SCHEMA_7_FINGERPRINT: &str =
    "vaultlink-schema-7-monitoring-service-tokens-2026-08-30";
pub(super) const SCHEMA_8_FINGERPRINT: &str =
    "vaultlink-schema-8-indexed-share-search-audit-keyset-2026-09-04";

pub(super) const SCHEMA_9_FINGERPRINT: &str =
    "vaultlink-schema-9-pending-transfer-index-2026-09-05";
const PENDING_TRANSFER_INDEX_SQL: &str =
    "CREATE INDEX idx_transfer_grants_pending_id ON public_transfer_grants(id) WHERE counted=0";

pub(super) const SCHEMA_10_FINGERPRINT: &str =
    "vaultlink-schema-10-share-filter-indexes-2026-09-06";
const SHARE_FILTER_INDEXES: [(&str, &str); 4] = [
    ("idx_shares_protected_id", "CREATE INDEX idx_shares_protected_id ON shares(id) WHERE password_hash IS NOT NULL"),
    ("idx_shares_limit_id", "CREATE INDEX idx_shares_limit_id ON shares(id) WHERE max_downloads IS NOT NULL AND download_count>=max_downloads"),
    ("idx_shares_expires_id", "CREATE INDEX idx_shares_expires_id ON shares(expires_at,id) WHERE expires_at IS NOT NULL"),
    ("idx_shares_available_expires_id", "CREATE INDEX idx_shares_available_expires_id ON shares(expires_at,id) WHERE active=1 AND (max_downloads IS NULL OR download_count<max_downloads)"),
];

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_SCHEMA_9_TO_10_MIGRATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_SCHEMA_1_TO_2_MIGRATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_SCHEMA_2_TO_3_MIGRATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_SCHEMA_3_TO_4_MIGRATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_SCHEMA_4_TO_5_MIGRATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_SCHEMA_5_TO_6_MIGRATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_SCHEMA_6_TO_7_MIGRATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_SCHEMA_8_TO_9_MIGRATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_SCHEMA_7_TO_8_MIGRATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(super) fn migrate(conn: &mut Connection) -> rusqlite::Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version == 0 {
        return initialize_empty_database(conn);
    }
    if !(1..=SCHEMA_VERSION).contains(&version) {
        return Err(schema_error(format!(
            "unsupported VaultLink database schema {version}; this build accepts schemas 1 through {SCHEMA_VERSION}"
        )));
    }
    for current in version..SCHEMA_VERSION {
        match current {
            1 => migrate_schema_1_to_2(conn)?,
            2 => migrate_schema_2_to_3(conn)?,
            3 => migrate_schema_3_to_4(conn)?,
            4 => migrate_schema_4_to_5(conn)?,
            5 => migrate_schema_5_to_6(conn)?,
            6 => migrate_schema_6_to_7(conn)?,
            7 => migrate_schema_7_to_8(conn)?,
            8 => migrate_schema_8_to_9(conn)?,
            9 => migrate_schema_9_to_10(conn)?,
            _ => return Err(schema_error("missing forward migration")),
        }
    }
    validate_current(conn)
}
pub(super) fn validate_current(conn: &Connection) -> rusqlite::Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != SCHEMA_VERSION {
        return Err(schema_error(format!(
            "backup schema {version} does not match this VaultLink binary's schema {SCHEMA_VERSION}"
        )));
    }
    validate_schema_10(conn)?;
    validate_database(conn)
}

include!("schema/bootstrap.rs");
include!("schema/migrations.rs");
include!("schema/validation.rs");

#[cfg(test)]
mod pending_index_tests {
    use super::*;
    #[test]
    fn schema_ten_migration_rolls_back_every_index_and_validates_shape() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        for (name, _) in SHARE_FILTER_INDEXES {
            conn.execute_batch(&format!("DROP INDEX {name}")).unwrap();
        }
        conn.execute_batch("DELETE FROM vaultlink_schema_migrations WHERE target_version=10; PRAGMA user_version=9;").unwrap();
        conn.execute(
            "UPDATE vaultlink_schema SET fingerprint=?1",
            [SCHEMA_9_FINGERPRINT],
        )
        .unwrap();
        FAIL_NEXT_SCHEMA_9_TO_10_MIGRATION.with(|flag| flag.set(true));
        assert!(migrate(&mut conn).is_err());
        validate_schema_9(&conn).unwrap();
        assert_eq!(
            conn.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            9
        );
        for (name, _) in SHARE_FILTER_INDEXES {
            assert_eq!(
                conn.query_row::<i64, _, _>(
                    "SELECT count(*) FROM sqlite_schema WHERE name=?1",
                    [name],
                    |r| r.get(0)
                )
                .unwrap(),
                0
            );
        }
        migrate(&mut conn).unwrap();
        validate_current(&conn).unwrap();
        conn.execute_batch("DROP INDEX idx_shares_protected_id; CREATE INDEX idx_shares_protected_id ON shares(id);").unwrap();
        assert!(validate_current(&conn).is_err());
    }
    #[test]
    fn schema_nine_migration_is_atomic_and_validates_index() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        conn.execute_batch(
            "DROP INDEX idx_shares_protected_id;
             DROP INDEX idx_shares_limit_id;
             DROP INDEX idx_shares_expires_id;
             DROP INDEX idx_shares_available_expires_id;
             DROP INDEX idx_transfer_grants_pending_id;
            DELETE FROM vaultlink_schema_migrations WHERE target_version>=9;
            PRAGMA user_version=8;",
        )
        .unwrap();
        conn.execute(
            "UPDATE vaultlink_schema SET fingerprint=?1",
            [SCHEMA_8_FINGERPRINT],
        )
        .unwrap();
        FAIL_NEXT_SCHEMA_8_TO_9_MIGRATION.with(|flag| flag.set(true));
        assert!(migrate(&mut conn).is_err());
        validate_schema_8(&conn).unwrap();
        assert_eq!(
            conn.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            8
        );
        assert_eq!(
            conn.query_row::<i64, _, _>(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name='idx_transfer_grants_pending_id'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            0
        );
        migrate(&mut conn).unwrap();
        validate_current(&conn).unwrap();
        conn.execute_batch("DROP INDEX idx_transfer_grants_pending_id;
            CREATE INDEX idx_transfer_grants_pending_id ON public_transfer_grants(id) WHERE counted=1;").unwrap();
        assert!(validate_current(&conn).is_err());
    }
}
