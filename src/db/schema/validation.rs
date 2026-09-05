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

fn validate_schema_8(conn: &Connection) -> rusqlite::Result<()> {
    validate_fingerprint(conn, SCHEMA_8_FINGERPRINT)?;
    validate_indexed_schema(conn, 8)
}

fn validate_schema_9(conn: &Connection) -> rusqlite::Result<()> {
    validate_fingerprint(conn, SCHEMA_9_FINGERPRINT)?;
    let sql: Option<String> = conn.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='index' AND name='idx_transfer_grants_pending_id'",
        [], |row| row.get(0),
    ).optional()?;
    if sql.as_deref() != Some(PENDING_TRANSFER_INDEX_SQL) {
        return Err(schema_error(
            "schema 9 pending transfer index is missing or invalid",
        ));
    }
    validate_indexed_schema(conn, 9)
}

fn validate_indexed_schema(conn: &Connection, version: i64) -> rusqlite::Result<()> {
    for target_version in 2..=version {
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

    validate_share_search_shape(conn)?;
    validate_audit_indexes_shape(conn)?;
    validate_service_tokens_shape(conn)?;
    validate_encrypted_shape(conn)
}

fn validate_share_search_shape(conn: &Connection) -> rusqlite::Result<()> {
    let search_columns = conn
        .prepare(
            "SELECT name,\"notnull\",dflt_value FROM pragma_table_info('shares')
             WHERE name IN ('alias_search_key','path_search_key') ORDER BY name",
        )?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if search_columns
        != [
            ("alias_search_key".to_owned(), 0, None),
            ("path_search_key".to_owned(), 1, Some("''".to_owned())),
        ]
    {
        return Err(schema_error(
            "schema 8 share search-key columns are missing or invalid",
        ));
    }
    let mut statement = conn.prepare(
        "SELECT alias,relative_path,alias_search_key,path_search_key FROM shares ORDER BY id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    for row in rows {
        let (alias, path, alias_key, path_key) = row?;
        if alias.as_deref().map(super::shares::unicode_search_key) != alias_key
            || super::shares::unicode_search_key(&path) != path_key
        {
            return Err(schema_error(
                "schema 8 share search keys are missing or invalid",
            ));
        }
    }

    validate_schema_object_sql(
        conn,
        "table",
        "share_search_fts",
        "CREATE VIRTUAL TABLE share_search_fts USING fts5(
             alias_search_key,
             path_search_key,
             content='shares',
             content_rowid='id',
             tokenize='trigram'
         )",
    )?;
    for (name, sql) in [
        (
            "trg_share_search_insert",
            "CREATE TRIGGER trg_share_search_insert AFTER INSERT ON shares BEGIN
                 INSERT INTO share_search_fts(rowid,alias_search_key,path_search_key)
                 VALUES(new.id,new.alias_search_key,new.path_search_key);
             END",
        ),
        (
            "trg_share_search_delete",
            "CREATE TRIGGER trg_share_search_delete AFTER DELETE ON shares BEGIN
                 INSERT INTO share_search_fts(
                     share_search_fts,rowid,alias_search_key,path_search_key
                 ) VALUES('delete',old.id,old.alias_search_key,old.path_search_key);
             END",
        ),
        (
            "trg_share_search_update",
            "CREATE TRIGGER trg_share_search_update
             AFTER UPDATE OF alias_search_key,path_search_key ON shares BEGIN
                 INSERT INTO share_search_fts(
                     share_search_fts,rowid,alias_search_key,path_search_key
                 ) VALUES('delete',old.id,old.alias_search_key,old.path_search_key);
                 INSERT INTO share_search_fts(rowid,alias_search_key,path_search_key)
                 VALUES(new.id,new.alias_search_key,new.path_search_key);
             END",
        ),
    ] {
        validate_schema_object_sql(conn, "trigger", name, sql)?;
    }
    // Preparing and executing MATCH proves both FTS5 and the trigram tokenizer
    // are available in the SQLite runtime used for subsequent requests.
    conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM share_search_fts
             WHERE share_search_fts MATCH '\"vaultlink-schema-8-probe\"'
         )",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    Ok(())
}

fn validate_audit_indexes_shape(conn: &Connection) -> rusqlite::Result<()> {
    for (name, sql) in [
        (
            "idx_audit_time_id",
            "CREATE INDEX idx_audit_time_id ON audit(occurred_at,id)",
        ),
        (
            "idx_audit_action_id",
            "CREATE INDEX idx_audit_action_id ON audit(action COLLATE NOCASE,id)",
        ),
        (
            "idx_audit_actor_id",
            "CREATE INDEX idx_audit_actor_id ON audit(actor COLLATE NOCASE,id)",
        ),
        (
            "idx_audit_object_id_id",
            "CREATE INDEX idx_audit_object_id_id
             ON audit(COALESCE(object_id,'') COLLATE NOCASE,id)",
        ),
        (
            "idx_audit_detail_id",
            "CREATE INDEX idx_audit_detail_id
             ON audit(COALESCE(detail,'') COLLATE NOCASE,id)",
        ),
        (
            "idx_audit_client_ip_id",
            "CREATE INDEX idx_audit_client_ip_id
             ON audit(COALESCE(client_ip,'') COLLATE NOCASE,id)",
        ),
        (
            "idx_audit_action_time_id",
            "CREATE INDEX idx_audit_action_time_id ON audit(action,occurred_at,id)",
        ),
    ] {
        validate_schema_object_sql(conn, "index", name, sql)?;
    }
    Ok(())
}

fn validate_schema_object_sql(
    conn: &Connection,
    object_type: &str,
    name: &str,
    expected: &str,
) -> rusqlite::Result<()> {
    let actual = conn
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type=?1 AND name=?2",
            [object_type, name],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let expected = normalize_schema_sql(expected);
    if actual.as_deref().map(normalize_schema_sql) != Some(expected) {
        return Err(schema_error(format!(
            "schema 8 {object_type} {name} is missing or invalid"
        )));
    }
    Ok(())
}

fn validate_service_tokens_shape(conn: &Connection) -> rusqlite::Result<()> {
    validate_service_token_columns(conn)?;
    validate_service_token_table_sql(conn)?;
    validate_service_token_unique_indexes(conn)?;
    validate_service_token_expiry_index(conn)?;
    validate_service_token_capacity_trigger(conn)
}

fn validate_service_token_columns(conn: &Connection) -> rusqlite::Result<()> {
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
    Ok(())
}

fn validate_service_token_table_sql(conn: &Connection) -> rusqlite::Result<()> {
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
    Ok(())
}

fn validate_service_token_unique_indexes(conn: &Connection) -> rusqlite::Result<()> {
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
    Ok(())
}

fn validate_service_token_expiry_index(conn: &Connection) -> rusqlite::Result<()> {
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
    Ok(())
}

fn validate_service_token_capacity_trigger(conn: &Connection) -> rusqlite::Result<()> {
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

#[cfg(test)]
pub(super) fn fail_next_schema_7_to_8_migration() {
    FAIL_NEXT_SCHEMA_7_TO_8_MIGRATION.with(|flag| flag.set(true));
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
