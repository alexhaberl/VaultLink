const INITIAL_SCHEMA_SQL: &str = r#"
CREATE TABLE vaultlink_schema(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    fingerprint TEXT NOT NULL
);
INSERT INTO vaultlink_schema(singleton,fingerprint)
VALUES(1,'vaultlink-schema-8-indexed-share-search-audit-keyset-2026-09-04');

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
    upload_policy_epoch INTEGER NOT NULL DEFAULT 0 CHECK(upload_policy_epoch >= 0),
    alias_search_key TEXT,
    path_search_key TEXT NOT NULL DEFAULT ''
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
CREATE INDEX idx_audit_time_id ON audit(occurred_at,id);
CREATE INDEX idx_audit_action_id ON audit(action COLLATE NOCASE,id);
CREATE INDEX idx_audit_actor_id ON audit(actor COLLATE NOCASE,id);
CREATE INDEX idx_audit_object_id_id ON audit(COALESCE(object_id,'') COLLATE NOCASE,id);
CREATE INDEX idx_audit_detail_id ON audit(COALESCE(detail,'') COLLATE NOCASE,id);
CREATE INDEX idx_audit_client_ip_id ON audit(COALESCE(client_ip,'') COLLATE NOCASE,id);
CREATE INDEX idx_audit_action_time_id ON audit(action,occurred_at,id);

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

CREATE VIRTUAL TABLE share_search_fts USING fts5(
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
        "#;

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
    tx.execute_batch(INITIAL_SCHEMA_SQL)?;
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
    tx.execute(
        "INSERT INTO vaultlink_schema_migrations(target_version,applied_at) VALUES(8,?1)",
        [Utc::now().to_rfc3339()],
    )?;
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    validate_schema_8(&tx)?;
    validate_database(&tx)?;
    tx.commit()
}
