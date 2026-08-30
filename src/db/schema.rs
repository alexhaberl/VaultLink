use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

pub(super) const SCHEMA_VERSION: i64 = 7;
pub(super) const SCHEMA_1_FINGERPRINT: &str = "vaultlink-schema-1-encrypted-secrets-2026-07-17";
pub(super) const SCHEMA_2_FINGERPRINT: &str = "vaultlink-schema-2-migration-history-2026-07-17";
pub(super) const SCHEMA_3_FINGERPRINT: &str = "vaultlink-schema-3-share-indexes-2026-07-17";
pub(super) const SCHEMA_4_FINGERPRINT: &str =
    "vaultlink-schema-4-admin-session-activity-2026-07-18";
pub(super) const SCHEMA_5_FINGERPRINT: &str = "vaultlink-schema-5-audit-priority-2026-07-19";
pub(super) const SCHEMA_6_FINGERPRINT: &str = "vaultlink-schema-6-typed-audit-policy-2026-07-20";
pub(super) const SCHEMA_7_FINGERPRINT: &str =
    "vaultlink-schema-7-monitoring-service-tokens-2026-08-30";

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_SCHEMA_1_TO_2_MIGRATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_SCHEMA_2_TO_3_MIGRATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_SCHEMA_3_TO_4_MIGRATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_SCHEMA_4_TO_5_MIGRATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_SCHEMA_5_TO_6_MIGRATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_SCHEMA_6_TO_7_MIGRATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(super) fn migrate(conn: &mut Connection) -> rusqlite::Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    match version {
        0 => initialize_empty_database(conn),
        1 => {
            migrate_schema_1_to_2(conn)?;
            migrate_schema_2_to_3(conn)?;
            migrate_schema_3_to_4(conn)?;
            migrate_schema_4_to_5(conn)?;
            migrate_schema_5_to_6(conn)?;
            migrate_schema_6_to_7(conn)
        }
        2 => {
            migrate_schema_2_to_3(conn)?;
            migrate_schema_3_to_4(conn)?;
            migrate_schema_4_to_5(conn)?;
            migrate_schema_5_to_6(conn)?;
            migrate_schema_6_to_7(conn)
        }
        3 => {
            migrate_schema_3_to_4(conn)?;
            migrate_schema_4_to_5(conn)?;
            migrate_schema_5_to_6(conn)?;
            migrate_schema_6_to_7(conn)
        }
        4 => {
            migrate_schema_4_to_5(conn)?;
            migrate_schema_5_to_6(conn)?;
            migrate_schema_6_to_7(conn)
        }
        5 => {
            migrate_schema_5_to_6(conn)?;
            migrate_schema_6_to_7(conn)
        }
        6 => migrate_schema_6_to_7(conn),
        SCHEMA_VERSION => validate_schema_7(conn).and_then(|()| validate_database(conn)),
        _ => Err(schema_error(format!(
            "unsupported VaultLink database schema {version}; this build accepts schemas 1, 2, 3, 4, 5, 6, and {SCHEMA_VERSION}"
        ))),
    }
}

fn initialize_empty_database(conn: &mut Connection) -> rusqlite::Result<()> {
    let existing: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if existing != 0 {
        return Err(schema_error(
            "unversioned database is not empty; legacy databases are not supported",
        ));
    }

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(
        r#"
CREATE TABLE vaultlink_schema(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    fingerprint TEXT NOT NULL
);
INSERT INTO vaultlink_schema(singleton,fingerprint)
VALUES(1,'vaultlink-schema-7-monitoring-service-tokens-2026-08-30');

CREATE TABLE vaultlink_schema_migrations(
    target_version INTEGER PRIMARY KEY CHECK(target_version > 0),
    applied_at TEXT NOT NULL
);

CREATE TABLE admins(
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    totp_key_id INTEGER NOT NULL,
    totp_ciphertext BLOB NOT NULL,
    totp_generation INTEGER NOT NULL DEFAULT 1 CHECK(totp_generation > 0),
    totp_enabled INTEGER NOT NULL DEFAULT 1 CHECK(totp_enabled IN (0,1)),
    created_at TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))
);

CREATE TABLE sessions(
    token_hash TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    mfa_verified INTEGER NOT NULL DEFAULT 0 CHECK(mfa_verified IN (0,1)),
    expires_at TEXT NOT NULL,
    last_activity_at TEXT NOT NULL
);
CREATE INDEX idx_sessions_exp ON sessions(expires_at);
CREATE INDEX idx_sessions_admin ON sessions(admin_id);

CREATE TABLE service_tokens(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE
        CHECK(name=trim(name) AND length(name) BETWEEN 1 AND 80),
    token_hash TEXT NOT NULL UNIQUE
        CHECK(length(token_hash)=64 AND token_hash NOT GLOB '*[^0-9a-f]*'),
    scope_mask INTEGER NOT NULL DEFAULT 1 CHECK(scope_mask=1),
    created_by INTEGER NOT NULL REFERENCES admins(id),
    created_at TEXT NOT NULL,
    expires_at TEXT,
    last_used_at TEXT
);
CREATE INDEX idx_service_tokens_expires ON service_tokens(expires_at);
CREATE TRIGGER trg_service_tokens_capacity
BEFORE INSERT ON service_tokens
WHEN (SELECT COUNT(*) FROM service_tokens)>=64
BEGIN
    SELECT RAISE(ABORT,'service token capacity reached');
END;

CREATE TABLE shares(
    id INTEGER PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    token_key_id INTEGER NOT NULL,
    token_ciphertext BLOB NOT NULL,
    alias TEXT UNIQUE,
    relative_path TEXT NOT NULL,
    is_directory INTEGER NOT NULL CHECK(is_directory IN (0,1)),
    permission TEXT NOT NULL CHECK(permission IN ('download_only','upload_only','download_upload')),
    expires_at TEXT,
    max_downloads INTEGER CHECK(max_downloads IS NULL OR max_downloads > 0),
    max_upload_size INTEGER CHECK(max_upload_size IS NULL OR max_upload_size > 0),
    max_upload_total_size INTEGER CHECK(max_upload_total_size IS NULL OR max_upload_total_size > 0),
    max_upload_files INTEGER CHECK(max_upload_files IS NULL OR max_upload_files > 0),
    download_count INTEGER NOT NULL DEFAULT 0 CHECK(download_count >= 0),
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    created_by INTEGER NOT NULL REFERENCES admins(id),
    created_at TEXT NOT NULL,
    password_hash TEXT,
    upload_conflict_strategy TEXT NOT NULL DEFAULT 'reject'
        CHECK(upload_conflict_strategy IN ('reject','overwrite_allowed')),
    upload_policy_epoch INTEGER NOT NULL DEFAULT 0 CHECK(upload_policy_epoch >= 0)
);
CREATE INDEX idx_shares_relative_path ON shares(relative_path);
CREATE INDEX idx_shares_active_id ON shares(active,id);
CREATE INDEX idx_shares_active_expires ON shares(active,expires_at);

CREATE TABLE audit(
    id INTEGER PRIMARY KEY,
    occurred_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    object_id TEXT,
    detail TEXT,
    client_ip TEXT,
    priority INTEGER NOT NULL DEFAULT 0 CHECK(priority BETWEEN 0 AND 100)
);
CREATE INDEX idx_audit_time ON audit(occurred_at);
CREATE INDEX idx_audit_action ON audit(action);
CREATE INDEX idx_audit_client_ip ON audit(client_ip) WHERE client_ip IS NOT NULL;
CREATE INDEX idx_audit_priority_id ON audit(priority,id);

CREATE TABLE public_unlock_sessions(
    token_hash TEXT PRIMARY KEY,
    share_id INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    csrf_token TEXT NOT NULL
);
CREATE INDEX idx_unlock_exp ON public_unlock_sessions(expires_at);
CREATE INDEX idx_unlock_share ON public_unlock_sessions(share_id);

CREATE TABLE runtime_settings(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_by INTEGER NOT NULL REFERENCES admins(id),
    updated_at TEXT NOT NULL
);

CREATE TABLE public_preview_sessions(
    token_hash TEXT PRIMARY KEY,
    share_id INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    relative_path TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    owner_key_hash TEXT NOT NULL
);
CREATE INDEX idx_preview_exp ON public_preview_sessions(expires_at);
CREATE INDEX idx_preview_share_path_owner
    ON public_preview_sessions(share_id,relative_path,owner_key_hash);

CREATE TABLE public_transfer_grants(
    id INTEGER PRIMARY KEY,
    session_token_hash TEXT NOT NULL,
    share_id INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    resource_key TEXT NOT NULL CHECK(length(resource_key)>0),
    action TEXT NOT NULL CHECK(length(action)>0),
    counted INTEGER NOT NULL DEFAULT 0 CHECK(counted IN (0,1)),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    UNIQUE(session_token_hash,share_id,resource_key,action)
);
CREATE INDEX idx_transfer_grants_exp ON public_transfer_grants(expires_at);
CREATE INDEX idx_transfer_grants_reservations
    ON public_transfer_grants(share_id,counted,expires_at);

CREATE TABLE public_transfer_leases(
    token_hash TEXT PRIMARY KEY,
    grant_id INTEGER NOT NULL REFERENCES public_transfer_grants(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX idx_transfer_leases_grant ON public_transfer_leases(grant_id);
CREATE INDEX idx_transfer_leases_exp ON public_transfer_leases(expires_at);

CREATE TABLE transfer_monthly_counts(
    month TEXT NOT NULL CHECK(month GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]'
        AND substr(month,6,2) BETWEEN '01' AND '12'),
    action TEXT NOT NULL CHECK(action IN ('download','zip_download','preview')),
    count INTEGER NOT NULL DEFAULT 0 CHECK(count >= 0),
    PRIMARY KEY(month,action)
);
CREATE TABLE transfer_statistics(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    started_at TEXT NOT NULL
);

CREATE TABLE admin_mfa_enrollments(
    admin_id INTEGER PRIMARY KEY REFERENCES admins(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    totp_key_id INTEGER NOT NULL,
    totp_ciphertext BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX idx_admin_mfa_enrollments_exp ON admin_mfa_enrollments(expires_at);

CREATE TABLE admin_webauthn_credentials(
    id INTEGER PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    label TEXT NOT NULL CHECK(length(label) BETWEEN 1 AND 80),
    credential_id TEXT NOT NULL UNIQUE,
    credential_blob BLOB NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT
);
CREATE INDEX idx_admin_webauthn_credentials_admin
    ON admin_webauthn_credentials(admin_id);

CREATE TABLE admin_totp_replay(
    admin_id INTEGER PRIMARY KEY REFERENCES admins(id) ON DELETE CASCADE,
    last_step INTEGER NOT NULL CHECK(last_step >= 0)
);

CREATE TABLE public_upload_usage(
    share_id INTEGER PRIMARY KEY REFERENCES shares(id) ON DELETE CASCADE,
    uploaded_bytes INTEGER NOT NULL DEFAULT 0 CHECK(uploaded_bytes >= 0),
    uploaded_files INTEGER NOT NULL DEFAULT 0 CHECK(uploaded_files >= 0)
);
CREATE TABLE public_upload_reservations(
    token_hash TEXT PRIMARY KEY,
    share_id INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    reserved_bytes INTEGER NOT NULL DEFAULT 0 CHECK(reserved_bytes >= 0),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    upload_policy_epoch INTEGER NOT NULL DEFAULT 0 CHECK(upload_policy_epoch >= 0)
);
CREATE INDEX idx_upload_reservations_exp ON public_upload_reservations(expires_at);
CREATE INDEX idx_upload_reservations_share_epoch
    ON public_upload_reservations(share_id,upload_policy_epoch);
"#,
    )?;
    tx.execute(
        "INSERT INTO transfer_statistics(singleton,started_at) VALUES(1,?1)",
        [Utc::now().to_rfc3339()],
    )?;
    tx.execute(
        "INSERT INTO vaultlink_schema_migrations(target_version,applied_at) VALUES(2,?1)",
        [Utc::now().to_rfc3339()],
    )?;
    tx.execute(
        "INSERT INTO vaultlink_schema_migrations(target_version,applied_at) VALUES(3,?1)",
        [Utc::now().to_rfc3339()],
    )?;
    tx.execute(
        "INSERT INTO vaultlink_schema_migrations(target_version,applied_at) VALUES(4,?1)",
        [Utc::now().to_rfc3339()],
    )?;
    tx.execute(
        "INSERT INTO vaultlink_schema_migrations(target_version,applied_at) VALUES(5,?1)",
        [Utc::now().to_rfc3339()],
    )?;
    tx.execute(
        "INSERT INTO vaultlink_schema_migrations(target_version,applied_at) VALUES(6,?1)",
        [Utc::now().to_rfc3339()],
    )?;
    tx.execute(
        "INSERT INTO vaultlink_schema_migrations(target_version,applied_at) VALUES(7,?1)",
        [Utc::now().to_rfc3339()],
    )?;
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    validate_schema_7(&tx)?;
    validate_database(&tx)?;
    tx.commit()
}

fn migrate_schema_1_to_2(conn: &mut Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_schema_1(&tx)?;
    validate_database(&tx)?;
    tx.execute_batch(
        "CREATE TABLE vaultlink_schema_migrations(
             target_version INTEGER PRIMARY KEY CHECK(target_version > 0),
             applied_at TEXT NOT NULL
         );",
    )?;
    tx.execute(
        "INSERT INTO vaultlink_schema_migrations(target_version,applied_at) VALUES(2,?1)",
        [Utc::now().to_rfc3339()],
    )?;
    tx.execute(
        "UPDATE vaultlink_schema SET fingerprint=?1 WHERE singleton=1",
        [SCHEMA_2_FINGERPRINT],
    )?;

    #[cfg(test)]
    if FAIL_NEXT_SCHEMA_1_TO_2_MIGRATION.with(|flag| flag.replace(false)) {
        return Err(schema_error("injected schema 1 to 2 migration failure"));
    }

    // Keep this as the final mutation so a rollback always leaves a schema-1
    // database with its matching fingerprint and no migration table.
    tx.pragma_update(None, "user_version", 2)?;
    validate_schema_2(&tx)?;
    validate_database(&tx)?;
    tx.commit()
}

fn migrate_schema_2_to_3(conn: &mut Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_schema_2(&tx)?;
    validate_database(&tx)?;
    tx.execute_batch(
        "CREATE INDEX idx_shares_active_id ON shares(active,id);
         CREATE INDEX idx_shares_active_expires ON shares(active,expires_at);",
    )?;
    tx.execute(
        "INSERT INTO vaultlink_schema_migrations(target_version,applied_at) VALUES(3,?1)",
        [Utc::now().to_rfc3339()],
    )?;
    tx.execute(
        "UPDATE vaultlink_schema SET fingerprint=?1 WHERE singleton=1",
        [SCHEMA_3_FINGERPRINT],
    )?;

    #[cfg(test)]
    if FAIL_NEXT_SCHEMA_2_TO_3_MIGRATION.with(|flag| flag.replace(false)) {
        return Err(schema_error("injected schema 2 to 3 migration failure"));
    }

    tx.pragma_update(None, "user_version", 3)?;
    validate_schema_3(&tx)?;
    validate_database(&tx)?;
    tx.commit()
}

fn migrate_schema_3_to_4(conn: &mut Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_schema_3(&tx)?;
    validate_database(&tx)?;
    tx.execute_batch(
        "ALTER TABLE sessions RENAME TO sessions_schema_3;
         DROP INDEX idx_sessions_exp;
         DROP INDEX idx_sessions_admin;
         CREATE TABLE sessions(
             token_hash TEXT PRIMARY KEY,
             admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
             csrf_token TEXT NOT NULL,
             mfa_verified INTEGER NOT NULL DEFAULT 0 CHECK(mfa_verified IN (0,1)),
             expires_at TEXT NOT NULL,
             last_activity_at TEXT NOT NULL
         );
         CREATE INDEX idx_sessions_exp ON sessions(expires_at);
         CREATE INDEX idx_sessions_admin ON sessions(admin_id);
         DROP TABLE sessions_schema_3;",
    )?;
    tx.execute(
        "INSERT INTO vaultlink_schema_migrations(target_version,applied_at) VALUES(4,?1)",
        [Utc::now().to_rfc3339()],
    )?;
    tx.execute(
        "UPDATE vaultlink_schema SET fingerprint=?1 WHERE singleton=1",
        [SCHEMA_4_FINGERPRINT],
    )?;

    #[cfg(test)]
    if FAIL_NEXT_SCHEMA_3_TO_4_MIGRATION.with(|flag| flag.replace(false)) {
        return Err(schema_error("injected schema 3 to 4 migration failure"));
    }

    tx.pragma_update(None, "user_version", 4)?;
    validate_schema_4(&tx)?;
    validate_database(&tx)?;
    tx.commit()
}

fn migrate_schema_4_to_5(conn: &mut Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_schema_4(&tx)?;
    validate_database(&tx)?;
    tx.execute_batch(
        "ALTER TABLE audit ADD COLUMN priority INTEGER NOT NULL DEFAULT 0
             CHECK(priority BETWEEN 0 AND 100);
         UPDATE audit SET priority=100 WHERE action IN (
             'initial_admin_created','admin_created','admin_activated','admin_deactivated',
             'admin_recovered','admin_password_reset','admin_totp_reset',
             'admin_totp_enabled','admin_totp_disabled','account_password_changed',
             'account_mfa_enrollment_started','account_mfa_changed',
             'webauthn_credential_added','webauthn_credential_deleted',
             'password_verified','login_success','login_success_webauthn','login_failed',
             'mfa_failed','mfa_replayed','logout','security_key_reauth_failed',
             'account_totp_setting_reauth_failed','settings_updated',
             'audit_client_ips_deleted','share_created','share_activated',
             'share_deactivated','share_deleted','share_password_set',
             'share_password_removed','share_controls_updated',
             'share_upload_conflict_updated','share_upload_limits_updated',
             'share_unlocked','share_unlock_failed','directory_created',
             'path_renamed','path_deleted'
         );
         CREATE INDEX idx_audit_priority_id ON audit(priority,id);",
    )?;
    tx.execute(
        "INSERT INTO vaultlink_schema_migrations(target_version,applied_at) VALUES(5,?1)",
        [Utc::now().to_rfc3339()],
    )?;
    tx.execute(
        "UPDATE vaultlink_schema SET fingerprint=?1 WHERE singleton=1",
        [SCHEMA_5_FINGERPRINT],
    )?;

    #[cfg(test)]
    if FAIL_NEXT_SCHEMA_4_TO_5_MIGRATION.with(|flag| flag.replace(false)) {
        return Err(schema_error("injected schema 4 to 5 migration failure"));
    }

    tx.pragma_update(None, "user_version", 5)?;
    validate_schema_5(&tx)?;
    validate_database(&tx)?;
    tx.commit()
}

fn migrate_schema_5_to_6(conn: &mut Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_schema_5(&tx)?;
    validate_database(&tx)?;
    tx.execute(
        "UPDATE audit SET priority=100 WHERE action IN (
             'share_toggled','upload_directories_created',
             'admin_upload','admin_upload_replaced',
             'upload','upload_replaced',
             'admin_upload_durability_uncertain','upload_durability_uncertain'
         )",
        [],
    )?;
    tx.execute(
        "INSERT INTO vaultlink_schema_migrations(target_version,applied_at) VALUES(6,?1)",
        [Utc::now().to_rfc3339()],
    )?;
    tx.execute(
        "UPDATE vaultlink_schema SET fingerprint=?1 WHERE singleton=1",
        [SCHEMA_6_FINGERPRINT],
    )?;

    #[cfg(test)]
    if FAIL_NEXT_SCHEMA_5_TO_6_MIGRATION.with(|flag| flag.replace(false)) {
        return Err(schema_error("injected schema 5 to 6 migration failure"));
    }

    tx.pragma_update(None, "user_version", 6)?;
    validate_schema_6(&tx)?;
    validate_database(&tx)?;
    tx.commit()
}

fn migrate_schema_6_to_7(conn: &mut Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_schema_6(&tx)?;
    validate_database(&tx)?;
    tx.execute_batch(
        "CREATE TABLE service_tokens(
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             name TEXT NOT NULL UNIQUE COLLATE NOCASE
                 CHECK(name=trim(name) AND length(name) BETWEEN 1 AND 80),
             token_hash TEXT NOT NULL UNIQUE
                 CHECK(length(token_hash)=64 AND token_hash NOT GLOB '*[^0-9a-f]*'),
             scope_mask INTEGER NOT NULL DEFAULT 1 CHECK(scope_mask=1),
             created_by INTEGER NOT NULL REFERENCES admins(id),
             created_at TEXT NOT NULL,
             expires_at TEXT,
             last_used_at TEXT
         );
         CREATE INDEX idx_service_tokens_expires ON service_tokens(expires_at);
         CREATE TRIGGER trg_service_tokens_capacity
         BEFORE INSERT ON service_tokens
         WHEN (SELECT COUNT(*) FROM service_tokens)>=64
         BEGIN
             SELECT RAISE(ABORT,'service token capacity reached');
         END;",
    )?;
    tx.execute(
        "INSERT INTO vaultlink_schema_migrations(target_version,applied_at) VALUES(7,?1)",
        [Utc::now().to_rfc3339()],
    )?;
    tx.execute(
        "UPDATE vaultlink_schema SET fingerprint=?1 WHERE singleton=1",
        [SCHEMA_7_FINGERPRINT],
    )?;

    #[cfg(test)]
    if FAIL_NEXT_SCHEMA_6_TO_7_MIGRATION.with(|flag| flag.replace(false)) {
        return Err(schema_error("injected schema 6 to 7 migration failure"));
    }

    // Keep the version bump as the final mutation. A failed migration must
    // remain a self-consistent schema-6 database without service-token state.
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    validate_schema_7(&tx)?;
    validate_database(&tx)?;
    tx.commit()
}

fn validate_schema_1(conn: &Connection) -> rusqlite::Result<()> {
    validate_fingerprint(conn, SCHEMA_1_FINGERPRINT)?;
    let migration_table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='vaultlink_schema_migrations')",
        [],
        |row| row.get(0),
    )?;
    if migration_table {
        return Err(schema_error(
            "schema 1 unexpectedly contains the schema migration table",
        ));
    }
    validate_encrypted_shape(conn)
}

fn validate_schema_2(conn: &Connection) -> rusqlite::Result<()> {
    validate_fingerprint(conn, SCHEMA_2_FINGERPRINT)?;
    let migration_record = conn
        .query_row(
            "SELECT applied_at FROM vaultlink_schema_migrations WHERE target_version=2",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if migration_record.as_deref().is_none_or(str::is_empty) {
        return Err(schema_error(
            "schema 2 migration record is missing or invalid",
        ));
    }
    validate_encrypted_shape(conn)
}

fn validate_schema_3(conn: &Connection) -> rusqlite::Result<()> {
    validate_fingerprint(conn, SCHEMA_3_FINGERPRINT)?;
    for target_version in [2, 3] {
        let migration_record = conn
            .query_row(
                "SELECT applied_at FROM vaultlink_schema_migrations WHERE target_version=?1",
                [target_version],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if migration_record.as_deref().is_none_or(str::is_empty) {
            return Err(schema_error(format!(
                "schema {target_version} migration record is missing or invalid"
            )));
        }
    }
    for index in ["idx_shares_active_id", "idx_shares_active_expires"] {
        let present: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name=?1)",
            [index],
            |row| row.get(0),
        )?;
        if !present {
            return Err(schema_error(format!("schema 3 index {index} is missing")));
        }
    }
    validate_encrypted_shape(conn)
}

fn validate_schema_4(conn: &Connection) -> rusqlite::Result<()> {
    validate_fingerprint(conn, SCHEMA_4_FINGERPRINT)?;
    for target_version in [2, 3, 4] {
        let migration_record = conn
            .query_row(
                "SELECT applied_at FROM vaultlink_schema_migrations WHERE target_version=?1",
                [target_version],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if migration_record.as_deref().is_none_or(str::is_empty) {
            return Err(schema_error(format!(
                "schema {target_version} migration record is missing or invalid"
            )));
        }
    }
    let last_activity_not_null: Option<i64> = conn
        .query_row(
            "SELECT \"notnull\" FROM pragma_table_info('sessions') WHERE name='last_activity_at'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if last_activity_not_null != Some(1) {
        return Err(schema_error(
            "schema 4 sessions.last_activity_at is missing or nullable",
        ));
    }
    validate_encrypted_shape(conn)
}

fn validate_schema_5(conn: &Connection) -> rusqlite::Result<()> {
    validate_fingerprint(conn, SCHEMA_5_FINGERPRINT)?;
    for target_version in [2, 3, 4, 5] {
        let migration_record = conn
            .query_row(
                "SELECT applied_at FROM vaultlink_schema_migrations WHERE target_version=?1",
                [target_version],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if migration_record.as_deref().is_none_or(str::is_empty) {
            return Err(schema_error(format!(
                "schema {target_version} migration record is missing or invalid"
            )));
        }
    }
    let priority_not_null: Option<i64> = conn
        .query_row(
            "SELECT \"notnull\" FROM pragma_table_info('audit') WHERE name='priority'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if priority_not_null != Some(1) {
        return Err(schema_error(
            "schema 5 audit.priority is missing or nullable",
        ));
    }
    let priority_index: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name='idx_audit_priority_id')",
        [],
        |row| row.get(0),
    )?;
    if !priority_index {
        return Err(schema_error("schema 5 audit priority index is missing"));
    }
    validate_encrypted_shape(conn)
}

fn validate_schema_6(conn: &Connection) -> rusqlite::Result<()> {
    validate_fingerprint(conn, SCHEMA_6_FINGERPRINT)?;
    for target_version in [2, 3, 4, 5, 6] {
        let migration_record = conn
            .query_row(
                "SELECT applied_at FROM vaultlink_schema_migrations WHERE target_version=?1",
                [target_version],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if migration_record.as_deref().is_none_or(str::is_empty) {
            return Err(schema_error(format!(
                "schema {target_version} migration record is missing or invalid"
            )));
        }
    }
    let priority_not_null: Option<i64> = conn
        .query_row(
            "SELECT \"notnull\" FROM pragma_table_info('audit') WHERE name='priority'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if priority_not_null != Some(1) {
        return Err(schema_error(
            "schema 6 audit.priority is missing or nullable",
        ));
    }
    let priority_index: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name='idx_audit_priority_id')",
        [],
        |row| row.get(0),
    )?;
    if !priority_index {
        return Err(schema_error("schema 6 audit priority index is missing"));
    }
    validate_encrypted_shape(conn)
}

fn validate_schema_7(conn: &Connection) -> rusqlite::Result<()> {
    validate_fingerprint(conn, SCHEMA_7_FINGERPRINT)?;
    for target_version in [2, 3, 4, 5, 6, 7] {
        let migration_record = conn
            .query_row(
                "SELECT applied_at FROM vaultlink_schema_migrations WHERE target_version=?1",
                [target_version],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if migration_record.as_deref().is_none_or(str::is_empty) {
            return Err(schema_error(format!(
                "schema {target_version} migration record is missing or invalid"
            )));
        }
    }
    let priority_not_null: Option<i64> = conn
        .query_row(
            "SELECT \"notnull\" FROM pragma_table_info('audit') WHERE name='priority'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if priority_not_null != Some(1) {
        return Err(schema_error(
            "schema 7 audit.priority is missing or nullable",
        ));
    }
    let priority_index: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name='idx_audit_priority_id')",
        [],
        |row| row.get(0),
    )?;
    if !priority_index {
        return Err(schema_error("schema 7 audit priority index is missing"));
    }
    validate_service_tokens_shape(conn)?;
    validate_encrypted_shape(conn)
}

fn validate_service_tokens_shape(conn: &Connection) -> rusqlite::Result<()> {
    let columns = conn
        .prepare(
            "SELECT name,type,\"notnull\",pk
             FROM pragma_table_info('service_tokens') ORDER BY cid",
        )?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let expected = [
        ("id", "INTEGER", 0, 1),
        ("name", "TEXT", 1, 0),
        ("token_hash", "TEXT", 1, 0),
        ("scope_mask", "INTEGER", 1, 0),
        ("created_by", "INTEGER", 1, 0),
        ("created_at", "TEXT", 1, 0),
        ("expires_at", "TEXT", 0, 0),
        ("last_used_at", "TEXT", 0, 0),
    ];
    if columns.len() != expected.len()
        || columns.iter().zip(expected).any(|(actual, expected)| {
            actual.0 != expected.0
                || !actual.1.eq_ignore_ascii_case(expected.1)
                || actual.2 != expected.2
                || actual.3 != expected.3
        })
    {
        return Err(schema_error(
            "schema 7 service_tokens table has an unexpected column shape",
        ));
    }

    let table_sql = conn
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name='service_tokens'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(table_sql) = table_sql else {
        return Err(schema_error("schema 7 service_tokens table is missing"));
    };
    let expected_table_sql = normalize_schema_sql(
        "CREATE TABLE service_tokens(
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             name TEXT NOT NULL UNIQUE COLLATE NOCASE
                 CHECK(name=trim(name) AND length(name) BETWEEN 1 AND 80),
             token_hash TEXT NOT NULL UNIQUE
                 CHECK(length(token_hash)=64 AND token_hash NOT GLOB '*[^0-9a-f]*'),
             scope_mask INTEGER NOT NULL DEFAULT 1 CHECK(scope_mask=1),
             created_by INTEGER NOT NULL REFERENCES admins(id),
             created_at TEXT NOT NULL,
             expires_at TEXT,
             last_used_at TEXT
         )",
    );
    if normalize_schema_sql(&table_sql) != expected_table_sql {
        return Err(schema_error(
            "schema 7 service_tokens table definition is missing or invalid",
        ));
    }

    // UNIQUE constraints are represented as SQLite-owned origin='u'
    // autoindexes with a NULL sql definition. Validate their actual key
    // columns so an unrelated UNIQUE constraint cannot stand in for the
    // required name or token-hash constraint.
    let index_metadata = conn
        .prepare(
            "SELECT name,\"unique\",origin,partial
             FROM pragma_index_list('service_tokens') ORDER BY name",
        )?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut unique_constraint_indexes = Vec::new();
    for (name, unique, origin, partial) in &index_metadata {
        match origin.as_str() {
            "c" if name == "idx_service_tokens_expires" && *unique == 0 && *partial == 0 => {}
            "u" if *unique == 1 && *partial == 0 => {
                unique_constraint_indexes.push(name.as_str());
            }
            _ => {
                return Err(schema_error(
                    "schema 7 service_tokens index metadata is unexpected",
                ));
            }
        }
    }
    if index_metadata.len() != 3 || unique_constraint_indexes.len() != 2 {
        return Err(schema_error(
            "schema 7 service_tokens unique-constraint indexes are missing or invalid",
        ));
    }
    let mut unique_constraint_shapes = Vec::new();
    for index_name in unique_constraint_indexes {
        let key_columns = index_key_columns(conn, index_name)?;
        let [key_column] = key_columns.as_slice() else {
            return Err(schema_error(
                "schema 7 service_tokens unique-constraint index is not single-column",
            ));
        };
        if key_column.sequence != 0 || key_column.descending {
            return Err(schema_error(
                "schema 7 service_tokens unique-constraint index has invalid ordering",
            ));
        }
        unique_constraint_shapes.push((
            key_column.column_id,
            key_column.name.clone().unwrap_or_default(),
            key_column
                .collation
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase(),
        ));
    }
    unique_constraint_shapes.sort_unstable();
    if unique_constraint_shapes
        != [
            (1, "name".to_owned(), "nocase".to_owned()),
            (2, "token_hash".to_owned(), "binary".to_owned()),
        ]
    {
        return Err(schema_error(
            "schema 7 service_tokens unique-constraint indexes target unexpected columns",
        ));
    }

    let user_indexes = conn
        .prepare(
            "SELECT name,sql FROM sqlite_schema
             WHERE type='index' AND tbl_name='service_tokens' AND sql IS NOT NULL
             ORDER BY name",
        )?
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let expected_index_sql = normalize_schema_sql(
        "CREATE INDEX idx_service_tokens_expires ON service_tokens(expires_at)",
    );
    if user_indexes.len() != 1
        || user_indexes[0].0 != "idx_service_tokens_expires"
        || normalize_schema_sql(&user_indexes[0].1) != expected_index_sql
    {
        return Err(schema_error(
            "schema 7 service_tokens user-defined index set is missing or invalid",
        ));
    }
    let expires_index_columns = index_key_columns(conn, "idx_service_tokens_expires")?;
    if expires_index_columns
        != [IndexKeyColumn {
            sequence: 0,
            column_id: 6,
            name: Some("expires_at".to_owned()),
            descending: false,
            collation: Some("BINARY".to_owned()),
        }]
    {
        return Err(schema_error(
            "schema 7 service_tokens expiry index has an unexpected column shape",
        ));
    }

    let triggers = conn
        .prepare(
            "SELECT name,sql FROM sqlite_schema
             WHERE type='trigger' AND tbl_name='service_tokens'
             ORDER BY name",
        )?
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let expected_trigger_sql = normalize_schema_sql(
        "CREATE TRIGGER trg_service_tokens_capacity
         BEFORE INSERT ON service_tokens
         WHEN (SELECT COUNT(*) FROM service_tokens)>=64
         BEGIN
             SELECT RAISE(ABORT,'service token capacity reached');
         END",
    );
    if triggers.len() != 1
        || triggers[0].0 != "trg_service_tokens_capacity"
        || normalize_schema_sql(&triggers[0].1) != expected_trigger_sql
    {
        return Err(schema_error(
            "schema 7 service_tokens capacity trigger is missing or invalid",
        ));
    }
    Ok(())
}

fn normalize_schema_sql(sql: &str) -> String {
    let mut normalized = String::with_capacity(sql.len());
    let mut characters = sql.chars().peekable();
    let mut quote = None;
    let mut pending_space = false;

    while let Some(character) = characters.next() {
        if let Some(delimiter) = quote {
            normalized.push(character);
            if character == delimiter {
                if characters.peek() == Some(&delimiter) {
                    normalized.push(
                        characters
                            .next()
                            .expect("peeked escaped quote must remain available"),
                    );
                } else {
                    quote = None;
                }
            }
            continue;
        }

        if character == '\'' || character == '"' {
            if pending_space && !normalized.is_empty() {
                normalized.push(' ');
            }
            pending_space = false;
            quote = Some(character);
            normalized.push(character);
        } else if character.is_whitespace() {
            pending_space = true;
        } else {
            if pending_space && !normalized.is_empty() {
                normalized.push(' ');
            }
            pending_space = false;
            normalized.push(character.to_ascii_lowercase());
        }
    }

    normalized
}

#[derive(Debug, Eq, PartialEq)]
struct IndexKeyColumn {
    sequence: i64,
    column_id: i64,
    name: Option<String>,
    descending: bool,
    collation: Option<String>,
}

fn index_key_columns(conn: &Connection, index_name: &str) -> rusqlite::Result<Vec<IndexKeyColumn>> {
    conn.prepare(
        "SELECT seqno,cid,name,\"desc\",coll
         FROM pragma_index_xinfo(?1) WHERE \"key\"=1 ORDER BY seqno",
    )?
    .query_map([index_name], |row| {
        Ok(IndexKeyColumn {
            sequence: row.get(0)?,
            column_id: row.get(1)?,
            name: row.get(2)?,
            descending: row.get::<_, i64>(3)? != 0,
            collation: row.get(4)?,
        })
    })?
    .collect()
}

fn validate_fingerprint(conn: &Connection, expected: &str) -> rusqlite::Result<()> {
    let fingerprint = conn
        .query_row(
            "SELECT fingerprint FROM vaultlink_schema WHERE singleton=1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if fingerprint.as_deref() != Some(expected) {
        return Err(schema_error(
            "database schema fingerprint is missing or does not match this build",
        ));
    }
    Ok(())
}

fn validate_encrypted_shape(conn: &Connection) -> rusqlite::Result<()> {
    for (table, forbidden) in [
        ("shares", "token"),
        ("admins", "totp_secret"),
        ("admin_mfa_enrollments", "totp_secret"),
        ("admin_webauthn_credentials", "credential_json"),
    ] {
        let sql = format!("SELECT 1 FROM pragma_table_info('{table}') WHERE name=?1");
        if conn
            .query_row(&sql, [forbidden], |_| Ok(()))
            .optional()?
            .is_some()
        {
            return Err(schema_error(format!(
                "legacy plaintext column {table}.{forbidden} is not supported"
            )));
        }
    }
    Ok(())
}

fn validate_database(conn: &Connection) -> rusqlite::Result<()> {
    let foreign_key_violation = conn
        .query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
        .optional()?;
    if foreign_key_violation.is_some() {
        return Err(schema_error("database foreign-key validation failed"));
    }
    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(schema_error(format!(
            "database integrity_check failed: {integrity}"
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn fail_next_schema_1_to_2_migration() {
    FAIL_NEXT_SCHEMA_1_TO_2_MIGRATION.with(|flag| flag.set(true));
}

#[cfg(test)]
pub(super) fn fail_next_schema_2_to_3_migration() {
    FAIL_NEXT_SCHEMA_2_TO_3_MIGRATION.with(|flag| flag.set(true));
}

#[cfg(test)]
pub(super) fn fail_next_schema_3_to_4_migration() {
    FAIL_NEXT_SCHEMA_3_TO_4_MIGRATION.with(|flag| flag.set(true));
}

#[cfg(test)]
pub(super) fn fail_next_schema_4_to_5_migration() {
    FAIL_NEXT_SCHEMA_4_TO_5_MIGRATION.with(|flag| flag.set(true));
}

#[cfg(test)]
pub(super) fn fail_next_schema_5_to_6_migration() {
    FAIL_NEXT_SCHEMA_5_TO_6_MIGRATION.with(|flag| flag.set(true));
}

#[cfg(test)]
pub(super) fn fail_next_schema_6_to_7_migration() {
    FAIL_NEXT_SCHEMA_6_TO_7_MIGRATION.with(|flag| flag.set(true));
}

#[derive(Debug)]
struct SchemaFailure(String);

impl std::fmt::Display for SchemaFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for SchemaFailure {}

pub(crate) fn is_schema_error(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::ToSqlConversionFailure(source)
            if source.downcast_ref::<SchemaFailure>().is_some()
    )
}

fn schema_error(message: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(SchemaFailure(message.into())))
}
