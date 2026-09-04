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
    tx.pragma_update(None, "user_version", 7)?;
    validate_schema_7(&tx)?;
    validate_database(&tx)?;
    tx.commit()
}

fn migrate_schema_7_to_8(conn: &mut Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_schema_7(&tx)?;
    validate_database(&tx)?;
    tx.execute_batch(
        "ALTER TABLE shares ADD COLUMN alias_search_key TEXT;
         ALTER TABLE shares ADD COLUMN path_search_key TEXT NOT NULL DEFAULT '';

         CREATE INDEX idx_audit_time_id ON audit(occurred_at,id);
         CREATE INDEX idx_audit_action_id ON audit(action COLLATE NOCASE,id);
         CREATE INDEX idx_audit_actor_id ON audit(actor COLLATE NOCASE,id);
         CREATE INDEX idx_audit_object_id_id
             ON audit(COALESCE(object_id,'') COLLATE NOCASE,id);
         CREATE INDEX idx_audit_detail_id
             ON audit(COALESCE(detail,'') COLLATE NOCASE,id);
         CREATE INDEX idx_audit_client_ip_id
             ON audit(COALESCE(client_ip,'') COLLATE NOCASE,id);
         CREATE INDEX idx_audit_action_time_id ON audit(action,occurred_at,id);",
    )?;
    backfill_share_search_keys(&tx)?;
    tx.execute_batch(
        "CREATE VIRTUAL TABLE share_search_fts USING fts5(
             alias_search_key,
             path_search_key,
             content='shares',
             content_rowid='id',
             tokenize='trigram'
         );
         CREATE TRIGGER trg_share_search_insert AFTER INSERT ON shares BEGIN
             INSERT INTO share_search_fts(rowid,alias_search_key,path_search_key)
             VALUES(new.id,new.alias_search_key,new.path_search_key);
         END;
         CREATE TRIGGER trg_share_search_delete AFTER DELETE ON shares BEGIN
             INSERT INTO share_search_fts(
                 share_search_fts,rowid,alias_search_key,path_search_key
             ) VALUES('delete',old.id,old.alias_search_key,old.path_search_key);
         END;
         CREATE TRIGGER trg_share_search_update
         AFTER UPDATE OF alias_search_key,path_search_key ON shares BEGIN
             INSERT INTO share_search_fts(
                 share_search_fts,rowid,alias_search_key,path_search_key
             ) VALUES('delete',old.id,old.alias_search_key,old.path_search_key);
             INSERT INTO share_search_fts(rowid,alias_search_key,path_search_key)
             VALUES(new.id,new.alias_search_key,new.path_search_key);
         END;
         INSERT INTO share_search_fts(share_search_fts) VALUES('rebuild');",
    )?;
    tx.execute(
        "INSERT INTO vaultlink_schema_migrations(target_version,applied_at) VALUES(8,?1)",
        [Utc::now().to_rfc3339()],
    )?;
    tx.execute(
        "UPDATE vaultlink_schema SET fingerprint=?1 WHERE singleton=1",
        [SCHEMA_8_FINGERPRINT],
    )?;

    #[cfg(test)]
    if FAIL_NEXT_SCHEMA_7_TO_8_MIGRATION.with(|flag| flag.replace(false)) {
        return Err(schema_error("injected schema 7 to 8 migration failure"));
    }

    // The schema version is the final mutation so every error, including an
    // unavailable FTS5/trigram module, rolls back to a complete schema 7.
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    validate_schema_8(&tx)?;
    validate_database(&tx)?;
    tx.commit()
}

fn backfill_share_search_keys(transaction: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    const BATCH_SIZE: i64 = 1_000;
    let mut cursor = 0_i64;
    loop {
        let batch = {
            let mut statement = transaction.prepare(
                "SELECT id,alias,relative_path FROM shares
                 WHERE id>?1 ORDER BY id LIMIT ?2",
            )?;
            let rows = statement
                .query_map([cursor, BATCH_SIZE], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        if batch.is_empty() {
            break;
        }
        for (id, alias, relative_path) in &batch {
            transaction.execute(
                "UPDATE shares SET alias_search_key=?2,path_search_key=?3 WHERE id=?1",
                rusqlite::params![
                    id,
                    alias.as_deref().map(super::shares::unicode_search_key),
                    super::shares::unicode_search_key(relative_path),
                ],
            )?;
        }
        cursor = batch
            .last()
            .map(|row| row.0)
            .expect("non-empty migration batch has a final row");
    }
    Ok(())
}
