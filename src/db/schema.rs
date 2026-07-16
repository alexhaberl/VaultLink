use super::{DEFAULT_SHARE_UPLOAD_FILE_COUNT, DEFAULT_SHARE_UPLOAD_TOTAL_SIZE};
use chrono::Utc;
use rusqlite::{params, Connection};

pub(super) const SCHEMA_VERSION: i64 = 16;

pub(super) fn migrate(conn: &mut Connection) -> rusqlite::Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let tx = conn.transaction()?;
    if version < 1 {
        tx.execute_batch(r#"
CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, totp_secret TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE, csrf_token TEXT NOT NULL, mfa_verified INTEGER NOT NULL DEFAULT 0, expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS shares(id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, token TEXT NOT NULL, alias TEXT UNIQUE, relative_path TEXT NOT NULL, is_directory INTEGER NOT NULL, permission TEXT NOT NULL, expires_at TEXT, max_downloads INTEGER, download_count INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1, created_by INTEGER NOT NULL REFERENCES admins(id), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, object_id TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_shares_alias ON shares(alias);
"#)?;
        tx.pragma_update(None, "user_version", 1)?;
    }
    if version < 2 {
        let has_password: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('shares') WHERE name='password_hash')",
            [],
            |row| row.get(0),
        )?;
        if !has_password {
            tx.execute("ALTER TABLE shares ADD COLUMN password_hash TEXT", [])?;
        }
        tx.execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS public_unlock_sessions(
    token_hash TEXT PRIMARY KEY,
    share_id INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_unlock_exp ON public_unlock_sessions(expires_at);
"#,
        )?;
        tx.pragma_update(None, "user_version", 2)?;
    }
    if version < 3 {
        let has_upload_limit: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('shares') WHERE name='max_upload_size')",
            [],
            |row| row.get(0),
        )?;
        if !has_upload_limit {
            tx.execute("ALTER TABLE shares ADD COLUMN max_upload_size INTEGER", [])?;
        }
        tx.execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS runtime_settings(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_by INTEGER NOT NULL REFERENCES admins(id),
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit(occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit(action);
"#,
        )?;
        tx.pragma_update(None, "user_version", 3)?;
    }
    if version < 4 {
        tx.execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS public_preview_sessions(
    token_hash TEXT PRIMARY KEY,
    share_id INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    relative_path TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_preview_exp ON public_preview_sessions(expires_at);
"#,
        )?;
        tx.pragma_update(None, "user_version", 4)?;
    }
    if version < 5 {
        let has_conflict_strategy: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('shares') WHERE name='upload_conflict_strategy')",
            [],
            |row| row.get(0),
        )?;
        if !has_conflict_strategy {
            tx.execute(
                "ALTER TABLE shares ADD COLUMN upload_conflict_strategy TEXT NOT NULL DEFAULT 'reject'",
                [],
            )?;
        }
        tx.pragma_update(None, "user_version", 5)?;
    }
    if version < 6 {
        let has_active: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('admins') WHERE name='active')",
            [],
            |row| row.get(0),
        )?;
        if !has_active {
            tx.execute(
                "ALTER TABLE admins ADD COLUMN active INTEGER NOT NULL DEFAULT 1",
                [],
            )?;
        }
        tx.pragma_update(None, "user_version", 6)?;
    }
    if version < 7 {
        tx.execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS public_transfer_grants(
    id INTEGER PRIMARY KEY,
    session_token_hash TEXT NOT NULL,
    share_id INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    resource_key TEXT NOT NULL CHECK(length(resource_key) > 0),
    action TEXT NOT NULL CHECK(length(action) > 0),
    counted INTEGER NOT NULL DEFAULT 0 CHECK(counted IN (0, 1)),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    UNIQUE(session_token_hash, share_id, resource_key, action)
);
CREATE INDEX IF NOT EXISTS idx_transfer_grants_exp
    ON public_transfer_grants(expires_at);
CREATE INDEX IF NOT EXISTS idx_transfer_grants_reservations
    ON public_transfer_grants(share_id, counted, expires_at);

CREATE TABLE IF NOT EXISTS public_transfer_leases(
    token_hash TEXT PRIMARY KEY,
    grant_id INTEGER NOT NULL REFERENCES public_transfer_grants(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_transfer_leases_grant
    ON public_transfer_leases(grant_id);
CREATE INDEX IF NOT EXISTS idx_transfer_leases_exp
    ON public_transfer_leases(expires_at);
"#,
        )?;
        tx.pragma_update(None, "user_version", 7)?;
    }
    if version < 8 {
        let has_client_ip: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('audit') WHERE name='client_ip')",
            [],
            |row| row.get(0),
        )?;
        if !has_client_ip {
            tx.execute("ALTER TABLE audit ADD COLUMN client_ip TEXT", [])?;
        }
        tx.execute_batch(
            r#"
CREATE INDEX IF NOT EXISTS idx_audit_client_ip
    ON audit(client_ip) WHERE client_ip IS NOT NULL;

CREATE TABLE IF NOT EXISTS transfer_monthly_counts(
    month TEXT NOT NULL
        CHECK(month GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]'
              AND substr(month, 6, 2) BETWEEN '01' AND '12'),
    action TEXT NOT NULL
        CHECK(action IN ('download', 'zip_download', 'preview')),
    count INTEGER NOT NULL DEFAULT 0 CHECK(count >= 0),
    PRIMARY KEY(month, action)
);

CREATE TABLE IF NOT EXISTS transfer_statistics(
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    started_at TEXT NOT NULL
);
"#,
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO transfer_statistics(singleton,started_at) VALUES(1,?1)",
            [Utc::now().to_rfc3339()],
        )?;
        tx.pragma_update(None, "user_version", 8)?;
    }
    if version < 9 {
        tx.execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS admin_mfa_enrollments(
    admin_id INTEGER PRIMARY KEY REFERENCES admins(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    totp_secret TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_admin_mfa_enrollments_exp
    ON admin_mfa_enrollments(expires_at);
"#,
        )?;
        tx.pragma_update(None, "user_version", 9)?;
    }
    if version < 10 {
        tx.execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS admin_webauthn_credentials(
    id INTEGER PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    label TEXT NOT NULL CHECK(length(label) BETWEEN 1 AND 80),
    credential_id TEXT NOT NULL UNIQUE,
    credential_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_admin_webauthn_credentials_admin
    ON admin_webauthn_credentials(admin_id);
"#,
        )?;
        tx.pragma_update(None, "user_version", 10)?;
    }
    if version < 11 {
        tx.execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS admin_totp_replay(
    admin_id INTEGER PRIMARY KEY REFERENCES admins(id) ON DELETE CASCADE,
    last_step INTEGER NOT NULL CHECK(last_step >= 0)
);
"#,
        )?;
        tx.pragma_update(None, "user_version", 11)?;
    }
    if version < 12 {
        let has_runtime_settings: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sqlite_schema
                 WHERE type='table' AND name='runtime_settings'
             )",
            [],
            |row| row.get(0),
        )?;
        if has_runtime_settings {
            tx.execute(
                "DELETE FROM runtime_settings
                 WHERE key='share_password_max_bytes'
                   AND EXISTS(
                       SELECT 1 FROM runtime_settings
                       WHERE key='share_password_max_length'
                   )",
                [],
            )?;
            tx.execute(
                "UPDATE runtime_settings
                 SET key='share_password_max_length'
                 WHERE key='share_password_max_bytes'",
                [],
            )?;
        }
        tx.pragma_update(None, "user_version", 12)?;
    }
    if version < 13 {
        let has_shares: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='shares')",
            [],
            |row| row.get(0),
        )?;
        let has_upload_total: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('shares') WHERE name='max_upload_total_size')",
            [],
            |row| row.get(0),
        )?;
        if has_shares && !has_upload_total {
            tx.execute(
                "ALTER TABLE shares ADD COLUMN max_upload_total_size INTEGER",
                [],
            )?;
        }
        let has_upload_files: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('shares') WHERE name='max_upload_files')",
            [],
            |row| row.get(0),
        )?;
        if has_shares && !has_upload_files {
            tx.execute("ALTER TABLE shares ADD COLUMN max_upload_files INTEGER", [])?;
        }
        let has_share_permission_columns: bool = tx.query_row(
            "SELECT
                 EXISTS(SELECT 1 FROM pragma_table_info('shares') WHERE name='is_directory')
                 AND EXISTS(SELECT 1 FROM pragma_table_info('shares') WHERE name='permission')",
            [],
            |row| row.get(0),
        )?;
        if has_share_permission_columns {
            tx.execute(
                "UPDATE shares
                 SET max_upload_total_size=CASE
                         WHEN max_upload_size>?1 THEN max_upload_size ELSE ?1
                     END,
                     max_upload_files=?2
                 WHERE is_directory=1 AND permission IN ('upload_only','download_upload')
                   AND (max_upload_total_size IS NULL OR max_upload_files IS NULL)",
                params![
                    DEFAULT_SHARE_UPLOAD_TOTAL_SIZE,
                    DEFAULT_SHARE_UPLOAD_FILE_COUNT
                ],
            )?;
        }
        tx.execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS public_upload_usage(
    share_id INTEGER PRIMARY KEY REFERENCES shares(id) ON DELETE CASCADE,
    uploaded_bytes INTEGER NOT NULL DEFAULT 0 CHECK(uploaded_bytes >= 0),
    uploaded_files INTEGER NOT NULL DEFAULT 0 CHECK(uploaded_files >= 0)
);

CREATE TABLE IF NOT EXISTS public_upload_reservations(
    token_hash TEXT PRIMARY KEY,
    share_id INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    reserved_bytes INTEGER NOT NULL DEFAULT 0 CHECK(reserved_bytes >= 0),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_upload_reservations_share
    ON public_upload_reservations(share_id);
CREATE INDEX IF NOT EXISTS idx_upload_reservations_exp
    ON public_upload_reservations(expires_at);
"#,
        )?;

        let has_unlock_csrf: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('public_unlock_sessions') WHERE name='csrf_token')",
            [],
            |row| row.get(0),
        )?;
        let has_unlock_sessions: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sqlite_schema
                 WHERE type='table' AND name='public_unlock_sessions'
             )",
            [],
            |row| row.get(0),
        )?;
        if has_unlock_sessions && !has_unlock_csrf {
            tx.execute(
                "ALTER TABLE public_unlock_sessions ADD COLUMN csrf_token TEXT NOT NULL DEFAULT ''",
                [],
            )?;
            // Pre-v13 cookies have no independently-bound CSRF secret. Invalidating
            // them forces one clean password unlock instead of presenting a page
            // whose state-changing upload form can never succeed.
            tx.execute("DELETE FROM public_unlock_sessions", [])?;
        }
        tx.pragma_update(None, "user_version", 13)?;
    }
    if version < 14 {
        let has_preview_sessions: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sqlite_schema
                 WHERE type='table' AND name='public_preview_sessions'
             )",
            [],
            |row| row.get(0),
        )?;
        if has_preview_sessions {
            let has_owner_key: bool = tx.query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM pragma_table_info('public_preview_sessions')
                     WHERE name='owner_key_hash'
                 )",
                [],
                |row| row.get(0),
            )?;
            if !has_owner_key {
                tx.execute(
                    "ALTER TABLE public_preview_sessions
                     ADD COLUMN owner_key_hash TEXT NOT NULL DEFAULT ''",
                    [],
                )?;
            }
            tx.execute_batch(
                r#"
CREATE INDEX IF NOT EXISTS idx_preview_share_path_owner
    ON public_preview_sessions(share_id, relative_path, owner_key_hash);
"#,
            )?;
        }
        tx.pragma_update(None, "user_version", 14)?;
    }
    if version < 15 {
        let has_shares: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sqlite_schema WHERE type='table' AND name='shares'
             )",
            [],
            |row| row.get(0),
        )?;
        if has_shares {
            let has_upload_policy_epoch: bool = tx.query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM pragma_table_info('shares')
                     WHERE name='upload_policy_epoch'
                 )",
                [],
                |row| row.get(0),
            )?;
            if !has_upload_policy_epoch {
                tx.execute(
                    "ALTER TABLE shares
                     ADD COLUMN upload_policy_epoch INTEGER NOT NULL DEFAULT 0",
                    [],
                )?;
            }
        }
        let has_upload_reservations: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sqlite_schema
                 WHERE type='table' AND name='public_upload_reservations'
             )",
            [],
            |row| row.get(0),
        )?;
        if has_upload_reservations {
            let has_upload_policy_epoch: bool = tx.query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM pragma_table_info('public_upload_reservations')
                     WHERE name='upload_policy_epoch'
                 )",
                [],
                |row| row.get(0),
            )?;
            if !has_upload_policy_epoch {
                tx.execute(
                    "ALTER TABLE public_upload_reservations
                     ADD COLUMN upload_policy_epoch INTEGER NOT NULL DEFAULT 0",
                    [],
                )?;
                // A legacy row did not record which share authority granted it.
                // Invalidating it is safer than silently binding it to the current policy.
                if has_shares {
                    tx.execute("DELETE FROM public_upload_reservations", [])?;
                } else {
                    let legacy_rows: i64 = tx.query_row(
                        "SELECT COUNT(*) FROM public_upload_reservations",
                        [],
                        |row| row.get(0),
                    )?;
                    if legacy_rows != 0 {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                }
            }
            tx.execute_batch(
                r#"
CREATE INDEX IF NOT EXISTS idx_upload_reservations_share_epoch
    ON public_upload_reservations(share_id, upload_policy_epoch);
"#,
            )?;
        }
        tx.pragma_update(None, "user_version", 15)?;
    }
    if version < 16 {
        let has_admins: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sqlite_schema WHERE type='table' AND name='admins'
             )",
            [],
            |row| row.get(0),
        )?;
        if has_admins {
            let has_totp_enabled: bool = tx.query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM pragma_table_info('admins')
                     WHERE name='totp_enabled'
                 )",
                [],
                |row| row.get(0),
            )?;
            if !has_totp_enabled {
                tx.execute(
                    "ALTER TABLE admins
                     ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 1
                     CHECK(totp_enabled IN (0, 1))",
                    [],
                )?;
            }
        }
        tx.pragma_update(None, "user_version", 16)?;
    }
    tx.commit()
}
