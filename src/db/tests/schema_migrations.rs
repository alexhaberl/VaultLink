#[test]
fn schema_one_migrates_once_and_preserves_data_and_encrypted_secrets() {
    let (_directory, path, share_ciphertext, totp_ciphertext) = populated_schema_one_fixture();
    let database = Database::open(&path).unwrap();
    assert_eq!(database.active_admin_usernames().unwrap(), ["admin"]);
    assert_eq!(
        database
            .admin("admin")
            .unwrap()
            .unwrap()
            .totp_secret
            .expose_secret(),
        "TOTP-SECRET"
    );
    assert_eq!(
        database
            .share_by_token("share-token")
            .unwrap()
            .unwrap()
            .alias
            .as_deref(),
        Some("fixture")
    );
    assert_eq!(
        database.runtime_settings().unwrap(),
        [("public_base_url".into(), "https://fixture.invalid".into())]
    );
    assert_eq!(database.count_audit(Some("fixture_event")).unwrap(), 1);
    let connection = database.conn();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        SCHEMA_VERSION
    );
    let (migrated_share_ciphertext, migrated_totp_ciphertext): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT shares.token_ciphertext,admins.totp_ciphertext
             FROM shares JOIN admins ON admins.id=shares.created_by",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(migrated_share_ciphertext, share_ciphertext);
    assert_eq!(migrated_totp_ciphertext, totp_ciphertext);
    let applied_at: Vec<(i64, String)> = connection
        .prepare(
            "SELECT target_version,applied_at FROM vaultlink_schema_migrations
             WHERE target_version IN (2,3,4,5,6,7,8) ORDER BY target_version",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    drop(connection);
    drop(database);

    let reopened = Database::open(&path).unwrap();
    let reopened_connection = reopened.conn();
    let reopened_applied_at: Vec<(i64, String)> = reopened_connection
        .prepare(
            "SELECT target_version,applied_at FROM vaultlink_schema_migrations
             WHERE target_version IN (2,3,4,5,6,7,8) ORDER BY target_version",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(reopened_applied_at, applied_at);
}

#[test]
fn schema_two_migrates_to_seven_with_expected_indexes() {
    let (_directory, path) = schema_two_fixture();
    let database = Database::open(path).unwrap();
    let connection = database.conn();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        SCHEMA_VERSION
    );
    for index in ["idx_shares_active_id", "idx_shares_active_expires"] {
        let present: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name=?1)",
                [index],
                |row| row.get(0),
            )
            .unwrap();
        assert!(present);
    }
}

#[test]
fn schema_four_migration_backfills_security_priority() {
    let (_directory, path) = schema_four_fixture();
    let database = Database::open(path).unwrap();
    let connection = database.conn();
    let priorities: Vec<(String, i64)> = connection
        .prepare("SELECT action,priority FROM audit ORDER BY id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        priorities,
        [("admin_recovered".into(), 100), ("download".into(), 0)]
    );
}

#[test]
fn schema_five_migration_reclassifies_file_mutations_and_preserves_rows() {
    let (_directory, path) = schema_five_fixture();
    let database = Database::open(path).unwrap();
    let connection = database.conn();
    let rows: Vec<(i64, String, String, String, i64)> = connection
        .prepare("SELECT id,action,object_id,detail,priority FROM audit ORDER BY id")
        .unwrap()
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(rows.len(), 9);
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row.0, (index + 1) as i64);
        assert_eq!(row.2, format!("object-{index}"));
        assert_eq!(row.3, "preserved");
        assert_eq!(row.4, if row.1 == "download" { 0 } else { 100 });
    }
}

#[test]
fn schema_six_migrates_to_seven_and_preserves_admins() {
    let (_directory, path) = schema_six_fixture();
    let database = Database::open(path).unwrap();
    assert_eq!(
        database.active_admin_usernames().unwrap(),
        ["schema-six-admin"]
    );
    let connection = database.conn();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        SCHEMA_VERSION
    );
    let table_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema
             WHERE type='table' AND name='service_tokens')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(table_exists);
}

#[test]
fn schema_seven_migrates_to_eight_and_backfills_indexed_search() {
    let (_directory, path) = schema_seven_fixture();
    let database = Database::open(path).unwrap();
    let page = database
        .list_share_page(&ShareListOptions {
            query: Some("GRÜS".to_owned()),
            status: ShareListStatus::All,
            sort: ShareListSort::Newest,
            cursor: None,
            limit: 100,
            now: Utc::now(),
        })
        .unwrap();
    assert_eq!(page.shares.len(), 1);
    assert_eq!(page.shares[0].alias.as_deref(), Some("Grüße"));
    let connection = database.conn();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        SCHEMA_VERSION
    );
    let migration_record: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM vaultlink_schema_migrations WHERE target_version=8",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(migration_record, 1);
}

#[test]
fn schema_three_migration_revokes_sessions_and_preserves_other_data() {
    let (_directory, path) = schema_three_fixture();
    let database = Database::open(path).unwrap();
    assert!(database.session("schema-three-session").unwrap().is_none());
    assert_eq!(database.active_admin_usernames().unwrap(), ["admin"]);
    assert_eq!(
        database.count_audit(Some("schema_three_fixture")).unwrap(),
        1
    );
    let connection = database.conn();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        SCHEMA_VERSION
    );
    let session_columns: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='last_activity_at' AND \"notnull\"=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(session_columns, 1);
}

#[test]
fn corrupt_schema_fingerprint_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("corrupt-fingerprint.sqlite");
    drop(Database::open(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE vaultlink_schema SET fingerprint='corrupt' WHERE singleton=1",
            [],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        Database::open(path),
        Err(DatabaseError::Schema(_))
    ));
}

#[test]
fn corrupt_schema_seven_service_token_shape_and_history_are_rejected() {
    let index_directory = tempfile::tempdir().unwrap();
    let index_path = index_directory.path().join("missing-token-index.sqlite");
    drop(Database::open(&index_path).unwrap());
    let connection = Connection::open(&index_path).unwrap();
    connection
        .execute_batch("DROP INDEX idx_service_tokens_expires")
        .unwrap();
    drop(connection);
    assert!(matches!(
        Database::open(index_path),
        Err(DatabaseError::Schema(_))
    ));

    let history_directory = tempfile::tempdir().unwrap();
    let history_path = history_directory
        .path()
        .join("missing-token-history.sqlite");
    drop(Database::open(&history_path).unwrap());
    let connection = Connection::open(&history_path).unwrap();
    connection
        .execute(
            "DELETE FROM vaultlink_schema_migrations WHERE target_version=7",
            [],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        Database::open(history_path),
        Err(DatabaseError::Schema(_))
    ));

    let constraint_directory = tempfile::tempdir().unwrap();
    let constraint_path = constraint_directory
        .path()
        .join("missing-token-constraint.sqlite");
    drop(Database::open(&constraint_path).unwrap());
    let connection = Connection::open(&constraint_path).unwrap();
    connection
        .execute_batch(
            "DROP TABLE service_tokens;
             CREATE TABLE service_tokens(
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                 token_hash TEXT NOT NULL UNIQUE,
                 scope_mask INTEGER NOT NULL DEFAULT 1,
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
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        Database::open(constraint_path),
        Err(DatabaseError::Schema(_))
    ));
}

fn assert_schema_seven_service_token_corruption_rejected(
    database_name: &str,
    corruption_sql: &str,
) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(database_name);
    drop(Database::open(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch(corruption_sql).unwrap();
    drop(connection);
    assert!(matches!(
        Database::open(path),
        Err(DatabaseError::Schema(_))
    ));
}

#[test]
fn corrupt_schema_seven_service_token_index_and_trigger_definitions_are_rejected() {
    assert_schema_seven_service_token_corruption_rejected(
        "wrong-token-index-column.sqlite",
        "DROP INDEX idx_service_tokens_expires;
         CREATE INDEX idx_service_tokens_expires ON service_tokens(created_at);",
    );
    assert_schema_seven_service_token_corruption_rejected(
        "ineffective-token-capacity-trigger.sqlite",
        "DROP TRIGGER trg_service_tokens_capacity;
         CREATE TRIGGER trg_service_tokens_capacity
         BEFORE INSERT ON service_tokens
         WHEN (SELECT COUNT(*) FROM service_tokens)>=64
         BEGIN
             SELECT 1;
         END;",
    );
}

#[test]
fn corrupt_schema_seven_extra_service_token_index_and_trigger_are_rejected() {
    assert_schema_seven_service_token_corruption_rejected(
        "extra-token-index.sqlite",
        "CREATE INDEX idx_service_tokens_created_at ON service_tokens(created_at);",
    );
    assert_schema_seven_service_token_corruption_rejected(
        "extra-token-trigger.sqlite",
        "CREATE TRIGGER trg_service_tokens_noop
         AFTER UPDATE ON service_tokens
         BEGIN
             SELECT 1;
         END;",
    );
}

#[test]
fn corrupt_schema_seven_service_token_unique_autoindex_columns_are_rejected() {
    assert_schema_seven_service_token_corruption_rejected(
        "wrong-token-unique-autoindex-columns.sqlite",
        "DROP TABLE service_tokens;
         CREATE TABLE service_tokens(
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             name TEXT NOT NULL UNIQUE COLLATE NOCASE
                 CHECK(name=trim(name) AND length(name) BETWEEN 1 AND 80),
             token_hash TEXT NOT NULL
                 CHECK(length(token_hash)=64 AND token_hash NOT GLOB '*[^0-9a-f]*'),
             scope_mask INTEGER NOT NULL DEFAULT 1 CHECK(scope_mask=1),
             created_by INTEGER NOT NULL REFERENCES admins(id),
             created_at TEXT NOT NULL UNIQUE,
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
    );
}

#[test]
fn corrupt_schema_seven_service_token_constraint_comments_are_rejected() {
    assert_schema_seven_service_token_corruption_rejected(
        "decoy-token-constraint-comments.sqlite",
        "DROP TABLE service_tokens;
         CREATE TABLE service_tokens(
             id INTEGER PRIMARY KEY /* PRIMARY KEY AUTOINCREMENT */,
             name TEXT NOT NULL UNIQUE COLLATE NOCASE
                 /* CHECK(name=trim(name) AND length(name) BETWEEN 1 AND 80) */,
             token_hash TEXT NOT NULL UNIQUE
                 /* CHECK(length(token_hash)=64 AND token_hash NOT GLOB '*[^0-9a-f]*') */,
             scope_mask INTEGER NOT NULL DEFAULT 1 /* CHECK(scope_mask=1) */,
             created_by INTEGER NOT NULL /* REFERENCES admins(id) */,
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
    );
}

#[test]
fn corrupt_schema_seven_service_token_constraint_literal_case_is_rejected() {
    assert_schema_seven_service_token_corruption_rejected(
        "weakened-token-hash-glob.sqlite",
        "DROP TABLE service_tokens;
         CREATE TABLE service_tokens(
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             name TEXT NOT NULL UNIQUE COLLATE NOCASE
                 CHECK(name=trim(name) AND length(name) BETWEEN 1 AND 80),
             token_hash TEXT NOT NULL UNIQUE
                 CHECK(length(token_hash)=64 AND token_hash NOT GLOB '*[^0-9A-f]*'),
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
    );
}

#[test]
fn failed_schema_one_migration_rolls_back_every_change() {
    let (_directory, path, _, _) = populated_schema_one_fixture();
    schema::fail_next_schema_1_to_2_migration();
    assert!(matches!(
        Database::open(&path),
        Err(DatabaseError::Schema(_))
    ));

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        1
    );
    let fingerprint: String = connection
        .query_row(
            "SELECT fingerprint FROM vaultlink_schema WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fingerprint, schema::SCHEMA_1_FINGERPRINT);
    let migration_table: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='vaultlink_schema_migrations')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!migration_table);
}

#[test]
fn failed_schema_two_migration_rolls_back_indexes_and_metadata() {
    let (_directory, path) = schema_two_fixture();
    schema::fail_next_schema_2_to_3_migration();
    assert!(matches!(
        Database::open(&path),
        Err(DatabaseError::Schema(_))
    ));

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        2
    );
    let fingerprint: String = connection
        .query_row(
            "SELECT fingerprint FROM vaultlink_schema WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fingerprint, schema::SCHEMA_2_FINGERPRINT);
    let schema_three_artifacts: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type='index' AND name IN ('idx_shares_active_id','idx_shares_active_expires')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(schema_three_artifacts, 0);
}

#[test]
fn failed_schema_three_migration_restores_sessions_and_metadata() {
    let (_directory, path) = schema_three_fixture();
    schema::fail_next_schema_3_to_4_migration();
    assert!(matches!(
        Database::open(&path),
        Err(DatabaseError::Schema(_))
    ));

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        3
    );
    let fingerprint: String = connection
        .query_row(
            "SELECT fingerprint FROM vaultlink_schema WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fingerprint, schema::SCHEMA_3_FINGERPRINT);
    let session_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(session_count, 1);
    let last_activity_column: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='last_activity_at'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(last_activity_column, 0);
}

#[test]
fn failed_schema_four_migration_restores_audit_shape_and_metadata() {
    let (_directory, path) = schema_four_fixture();
    schema::fail_next_schema_4_to_5_migration();
    assert!(matches!(
        Database::open(&path),
        Err(DatabaseError::Schema(_))
    ));

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        4
    );
    let fingerprint: String = connection
        .query_row(
            "SELECT fingerprint FROM vaultlink_schema WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fingerprint, schema::SCHEMA_4_FINGERPRINT);
    let priority_column: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('audit') WHERE name='priority'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(priority_column, 0);
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM audit", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
}

#[test]
fn failed_schema_five_migration_restores_priorities_and_metadata() {
    let (_directory, path) = schema_five_fixture();
    schema::fail_next_schema_5_to_6_migration();
    assert!(matches!(
        Database::open(&path),
        Err(DatabaseError::Schema(_))
    ));

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        5
    );
    let fingerprint: String = connection
        .query_row(
            "SELECT fingerprint FROM vaultlink_schema WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fingerprint, schema::SCHEMA_5_FINGERPRINT);
    let priorities: Vec<i64> = connection
        .prepare("SELECT priority FROM audit ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(priorities, vec![0; 9]);
    let schema_six_record: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM vaultlink_schema_migrations WHERE target_version=6",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(schema_six_record, 0);
}

#[test]
fn failed_schema_six_migration_rolls_back_service_token_schema_and_metadata() {
    let (_directory, path) = schema_six_fixture();
    schema::fail_next_schema_6_to_7_migration();
    assert!(matches!(
        Database::open(&path),
        Err(DatabaseError::Schema(_))
    ));

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        6
    );
    let fingerprint: String = connection
        .query_row(
            "SELECT fingerprint FROM vaultlink_schema WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fingerprint, schema::SCHEMA_6_FINGERPRINT);
    let artifacts: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE name IN ('service_tokens','idx_service_tokens_expires',
                            'trg_service_tokens_capacity')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(artifacts, 0);
    let migration_record: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM vaultlink_schema_migrations WHERE target_version=7",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(migration_record, 0);
}

#[test]
fn failed_schema_seven_migration_rolls_back_fts_indexes_columns_and_metadata() {
    let (_directory, path) = schema_seven_fixture();
    let before = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT id,alias,relative_path,token_hash,token_key_id,token_ciphertext
             FROM shares",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .unwrap();
    schema::fail_next_schema_7_to_8_migration();
    assert!(matches!(
        Database::open(&path),
        Err(DatabaseError::Schema(_))
    ));

    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        7
    );
    let fingerprint: String = connection
        .query_row(
            "SELECT fingerprint FROM vaultlink_schema WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fingerprint, schema::SCHEMA_7_FINGERPRINT);
    let schema_eight_artifacts: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name IN (
                 'share_search_fts','trg_share_search_insert','trg_share_search_delete',
                 'trg_share_search_update','idx_audit_time_id','idx_audit_action_id',
                 'idx_audit_actor_id','idx_audit_object_id_id','idx_audit_detail_id',
                 'idx_audit_client_ip_id','idx_audit_action_time_id'
             )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(schema_eight_artifacts, 0);
    let search_columns: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('shares')
             WHERE name IN ('alias_search_key','path_search_key')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(search_columns, 0);
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM shares", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
    let after = connection
        .query_row(
            "SELECT id,alias,relative_path,token_hash,token_key_id,token_ciphertext
             FROM shares",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(after, before);
    drop(connection);

    // Fault injection is one-shot; the same untouched schema-7 fixture must
    // remain eligible for a successful retry.
    assert!(Database::open(path).is_ok());
}
