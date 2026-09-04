#[test]
fn rejects_unknown_newer_schema() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("future.sqlite");
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
        .unwrap();
    drop(connection);
    assert!(matches!(
        Database::open(path),
        Err(DatabaseError::Schema(_))
    ));
}

#[test]
fn fresh_database_is_exactly_schema_eight_without_plaintext_secret_columns() {
    let database = Database::open(":memory:").unwrap();
    let connection = database.conn();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        SCHEMA_VERSION
    );
    let migration_records: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM vaultlink_schema_migrations WHERE target_version IN (2,3,4,5,6,7,8) AND length(applied_at)>0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(migration_records, 7);
    let service_token_columns: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('service_tokens')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(service_token_columns, 8);
    let service_token_capacity_trigger: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema
             WHERE type='trigger' AND name='trg_service_tokens_capacity')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(service_token_capacity_trigger);
    for index in ["idx_shares_active_id", "idx_shares_active_expires"] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name=?1)",
                [index],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "schema 3 index {index} is missing");
    }
    for index in [
        "idx_audit_time_id",
        "idx_audit_action_id",
        "idx_audit_actor_id",
        "idx_audit_object_id_id",
        "idx_audit_detail_id",
        "idx_audit_client_ip_id",
        "idx_audit_action_time_id",
    ] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name=?1)",
                [index],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "schema 8 index {index} is missing");
    }
    let fts_and_triggers: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name IN (
                 'share_search_fts','trg_share_search_insert',
                 'trg_share_search_delete','trg_share_search_update'
             )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fts_and_triggers, 4);
    let last_activity_not_null: i64 = connection
        .query_row(
            "SELECT \"notnull\" FROM pragma_table_info('sessions') WHERE name='last_activity_at'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(last_activity_not_null, 1);
    let priority_not_null: i64 = connection
        .query_row(
            "SELECT \"notnull\" FROM pragma_table_info('audit') WHERE name='priority'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(priority_not_null, 1);
    for (table, forbidden) in [
        ("shares", "token"),
        ("admins", "totp_secret"),
        ("admin_mfa_enrollments", "totp_secret"),
        ("admin_webauthn_credentials", "credential_json"),
    ] {
        let sql = format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name=?1");
        let count: i64 = connection
            .query_row(&sql, [forbidden], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0, "legacy column {table}.{forbidden} exists");
    }
    for (table, encrypted_columns) in [
        ("shares", &["token_key_id", "token_ciphertext"][..]),
        ("admins", &["totp_key_id", "totp_ciphertext"][..]),
        (
            "admin_mfa_enrollments",
            &["totp_key_id", "totp_ciphertext"][..],
        ),
        ("admin_webauthn_credentials", &["credential_blob"][..]),
    ] {
        for column in encrypted_columns {
            let sql = format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name=?1");
            let count: i64 = connection
                .query_row(&sql, [column], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 1, "encrypted column {table}.{column} missing");
        }
    }
}

fn downgrade_schema_eight_to_seven(connection: &Connection) {
    connection
        .execute_batch(
            "DROP TRIGGER trg_share_search_insert;
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
             DELETE FROM vaultlink_schema_migrations WHERE target_version=8;",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE vaultlink_schema SET fingerprint=?1 WHERE singleton=1",
            [schema::SCHEMA_7_FINGERPRINT],
        )
        .unwrap();
    connection.pragma_update(None, "user_version", 7).unwrap();
}

fn downgrade_audit_to_schema_four(connection: &Connection) {
    downgrade_schema_eight_to_seven(connection);
    connection
        .execute_batch(
            "DROP TABLE service_tokens;
             DROP INDEX idx_audit_priority_id;
             ALTER TABLE audit DROP COLUMN priority;
             DELETE FROM vaultlink_schema_migrations WHERE target_version IN (5,6,7);",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE vaultlink_schema SET fingerprint=?1 WHERE singleton=1",
            [schema::SCHEMA_4_FINGERPRINT],
        )
        .unwrap();
    connection.pragma_update(None, "user_version", 4).unwrap();
}

fn schema_five_fixture() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-five.sqlite");
    drop(Database::open(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    downgrade_schema_eight_to_seven(&connection);
    connection
        .execute_batch(
            "DROP TABLE service_tokens;
             DELETE FROM vaultlink_schema_migrations WHERE target_version=7;",
        )
        .unwrap();
    connection
        .execute(
            "DELETE FROM vaultlink_schema_migrations WHERE target_version=6",
            [],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE vaultlink_schema SET fingerprint=?1 WHERE singleton=1",
            [schema::SCHEMA_5_FINGERPRINT],
        )
        .unwrap();
    connection.pragma_update(None, "user_version", 5).unwrap();
    for (index, action) in [
        "share_toggled",
        "upload_directories_created",
        "admin_upload",
        "admin_upload_replaced",
        "upload",
        "upload_replaced",
        "admin_upload_durability_uncertain",
        "upload_durability_uncertain",
        "download",
    ]
    .into_iter()
    .enumerate()
    {
        connection
            .execute(
                "INSERT INTO audit(id,occurred_at,actor,action,object_id,detail,priority)
                 VALUES(?1,'2026-07-19T00:00:00Z','fixture',?2,?3,'preserved',0)",
                params![(index + 1) as i64, action, format!("object-{index}")],
            )
            .unwrap();
    }
    drop(connection);
    (directory, path)
}

fn schema_six_fixture() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-six.sqlite");
    let database = Database::open(&path).unwrap();
    database
        .create_admin("schema-six-admin", "password-hash", "TOTP-SECRET")
        .unwrap();
    drop(database);
    let connection = Connection::open(&path).unwrap();
    downgrade_schema_eight_to_seven(&connection);
    connection
        .execute_batch(
            "DROP TABLE service_tokens;
             DELETE FROM vaultlink_schema_migrations WHERE target_version=7;",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE vaultlink_schema SET fingerprint=?1 WHERE singleton=1",
            [schema::SCHEMA_6_FINGERPRINT],
        )
        .unwrap();
    connection.pragma_update(None, "user_version", 6).unwrap();
    drop(connection);
    (directory, path)
}

fn schema_seven_fixture() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-seven.sqlite");
    let database = Database::open(&path).unwrap();
    database
        .create_admin("schema-seven-admin", "password-hash", "TOTP-SECRET")
        .unwrap();
    database
        .create_share(
            "schema-seven-token",
            Some("Grüße"),
            "Ablage/Grüße.txt",
            false,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    drop(database);
    let connection = Connection::open(&path).unwrap();
    downgrade_schema_eight_to_seven(&connection);
    drop(connection);
    (directory, path)
}

fn populated_schema_one_fixture() -> (tempfile::TempDir, PathBuf, Vec<u8>, Vec<u8>) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-one.sqlite");
    let database = Database::open(&path).unwrap();
    database
        .create_admin("admin", "password-hash", "TOTP-SECRET")
        .unwrap();
    database
        .create_share(
            "share-token",
            Some("fixture"),
            "fixture.txt",
            false,
            &Permission::DownloadOnly,
            None,
            Some(7),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    database
        .replace_runtime_settings(&[("public_base_url", "https://fixture.invalid".into())], 1)
        .unwrap();
    database
        .audit("admin", "fixture_event", Some("1"), Some("preserved"))
        .unwrap();
    let (share_ciphertext, totp_ciphertext) = database
        .conn()
        .query_row(
            "SELECT shares.token_ciphertext,admins.totp_ciphertext
             FROM shares JOIN admins ON admins.id=shares.created_by",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    drop(database);

    let connection = Connection::open(&path).unwrap();
    downgrade_audit_to_schema_four(&connection);
    connection
        .execute_batch(
            "DROP TABLE vaultlink_schema_migrations;
             DROP INDEX idx_shares_active_id;
             DROP INDEX idx_shares_active_expires;",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE vaultlink_schema SET fingerprint=?1 WHERE singleton=1",
            [schema::SCHEMA_1_FINGERPRINT],
        )
        .unwrap();
    connection.pragma_update(None, "user_version", 1).unwrap();
    drop(connection);
    (directory, path, share_ciphertext, totp_ciphertext)
}

fn schema_two_fixture() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-two.sqlite");
    drop(Database::open(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    downgrade_audit_to_schema_four(&connection);
    connection
        .execute_batch(
            "DROP INDEX idx_shares_active_id;
             DROP INDEX idx_shares_active_expires;
             DELETE FROM vaultlink_schema_migrations WHERE target_version IN (3,4);",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE vaultlink_schema SET fingerprint=?1 WHERE singleton=1",
            [schema::SCHEMA_2_FINGERPRINT],
        )
        .unwrap();
    connection.pragma_update(None, "user_version", 2).unwrap();
    drop(connection);
    (directory, path)
}

fn schema_three_fixture() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-three.sqlite");
    let database = Database::open(&path).unwrap();
    database
        .create_admin("admin", "password-hash", "TOTP-SECRET")
        .unwrap();
    database
        .create_session(
            "schema-three-session",
            1,
            "csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    database
        .audit(
            "admin",
            "schema_three_fixture",
            Some("1"),
            Some("preserved"),
        )
        .unwrap();
    drop(database);

    let connection = Connection::open(&path).unwrap();
    downgrade_audit_to_schema_four(&connection);
    connection
        .execute_batch(
            "ALTER TABLE sessions RENAME TO sessions_schema_4;
             DROP INDEX idx_sessions_exp;
             DROP INDEX idx_sessions_admin;
             CREATE TABLE sessions(
                 token_hash TEXT PRIMARY KEY,
                 admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
                 csrf_token TEXT NOT NULL,
                 mfa_verified INTEGER NOT NULL DEFAULT 0 CHECK(mfa_verified IN (0,1)),
                 expires_at TEXT NOT NULL
             );
             INSERT INTO sessions(token_hash,admin_id,csrf_token,mfa_verified,expires_at)
             SELECT token_hash,admin_id,csrf_token,mfa_verified,expires_at FROM sessions_schema_4;
             CREATE INDEX idx_sessions_exp ON sessions(expires_at);
             CREATE INDEX idx_sessions_admin ON sessions(admin_id);
             DROP TABLE sessions_schema_4;
             DELETE FROM vaultlink_schema_migrations WHERE target_version=4;",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE vaultlink_schema SET fingerprint=?1 WHERE singleton=1",
            [schema::SCHEMA_3_FINGERPRINT],
        )
        .unwrap();
    connection.pragma_update(None, "user_version", 3).unwrap();
    drop(connection);
    (directory, path)
}

fn schema_four_fixture() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-four.sqlite");
    let database = Database::open(&path).unwrap();
    database
        .audit("local_recovery", "admin_recovered", Some("1"), None)
        .unwrap();
    database
        .audit("public", "download", Some("2"), None)
        .unwrap();
    drop(database);

    let connection = Connection::open(&path).unwrap();
    downgrade_audit_to_schema_four(&connection);
    drop(connection);
    (directory, path)
}
