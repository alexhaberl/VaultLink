use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

const SCHEMA_VERSION: i64 = 6;

#[derive(Clone)]
pub struct Database(Arc<Mutex<Connection>>);

#[derive(Clone, Debug)]
pub struct Admin {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub totp_secret: String,
    pub active: bool,
}
#[derive(Clone, Debug)]
pub struct AdminSummary {
    pub id: i64,
    pub username: String,
    pub created_at: String,
    pub active: bool,
}
#[derive(Clone, Debug)]
pub struct Session {
    pub admin_id: i64,
    pub username: String,
    pub csrf_token: String,
    pub mfa_verified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    DownloadOnly,
    UploadOnly,
    DownloadUpload,
}
impl Permission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DownloadOnly => "download_only",
            Self::UploadOnly => "upload_only",
            Self::DownloadUpload => "download_upload",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "download_only" => Some(Self::DownloadOnly),
            "upload_only" => Some(Self::UploadOnly),
            "download_upload" => Some(Self::DownloadUpload),
            _ => None,
        }
    }
    pub fn can_download(&self) -> bool {
        !matches!(self, Self::UploadOnly)
    }
    pub fn can_upload(&self) -> bool {
        !matches!(self, Self::DownloadOnly)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UploadConflictStrategy {
    Reject,
    OverwriteAllowed,
}
impl UploadConflictStrategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::OverwriteAllowed => "overwrite_allowed",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "reject" => Some(Self::Reject),
            "overwrite_allowed" => Some(Self::OverwriteAllowed),
            _ => None,
        }
    }
    pub fn can_overwrite(&self) -> bool {
        matches!(self, Self::OverwriteAllowed)
    }
}

#[derive(Clone, Debug)]
pub struct Share {
    pub id: i64,
    pub token: String,
    pub alias: Option<String>,
    pub relative_path: String,
    pub is_directory: bool,
    pub permission: Permission,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_downloads: Option<u64>,
    pub max_upload_size: Option<u64>,
    pub download_count: u64,
    pub active: bool,
    pub password_hash: Option<String>,
    pub upload_conflict_strategy: UploadConflictStrategy,
}

#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub occurred_at: String,
    pub actor: String,
    pub action: String,
    pub object_id: Option<String>,
    pub detail: Option<String>,
}

fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let path = path.as_ref();
        let mut conn = Connection::open(path)?;
        #[cfg(unix)]
        if path != Path::new(":memory:") {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        migrate(&mut conn)?;
        Ok(Self(Arc::new(Mutex::new(conn))))
    }
}

fn migrate(conn: &mut Connection) -> rusqlite::Result<()> {
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
    tx.commit()
}

impl Database {
    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.0.lock().expect("database mutex poisoned")
    }
    pub fn create_admin(
        &self,
        username: &str,
        password_hash: &str,
        totp_secret: &str,
    ) -> rusqlite::Result<()> {
        self.conn().execute(
            "INSERT INTO admins(username,password_hash,totp_secret,created_at,active) VALUES(?1,?2,?3,?4,1)",
            params![
                username,
                password_hash,
                totp_secret,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }
    pub fn admin(&self, username: &str) -> rusqlite::Result<Option<Admin>> {
        self.conn()
            .query_row(
                "SELECT id,username,password_hash,totp_secret,active FROM admins WHERE username=?1 AND active=1",
                [username],
                |r| {
                    Ok(Admin {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        password_hash: r.get(2)?,
                        totp_secret: r.get(3)?,
                        active: r.get::<_, i64>(4)? != 0,
                    })
                },
            )
            .optional()
    }
    pub fn admin_count(&self) -> rusqlite::Result<i64> {
        self.conn()
            .query_row("SELECT COUNT(*) FROM admins", [], |row| row.get(0))
    }
    pub fn active_admin_count(&self) -> rusqlite::Result<i64> {
        self.conn()
            .query_row("SELECT COUNT(*) FROM admins WHERE active=1", [], |row| {
                row.get(0)
            })
    }
    pub fn list_admins(&self) -> rusqlite::Result<Vec<AdminSummary>> {
        let c = self.conn();
        let mut statement = c.prepare(
            "SELECT id,username,created_at,active FROM admins ORDER BY username COLLATE NOCASE",
        )?;
        let admins = statement
            .query_map([], |row| {
                Ok(AdminSummary {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    created_at: row.get(2)?,
                    active: row.get::<_, i64>(3)? != 0,
                })
            })?
            .collect();
        admins
    }
    pub fn set_admin_active(&self, id: i64, active: bool) -> rusqlite::Result<bool> {
        let mut connection = self.conn();
        let transaction = connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE admins SET active=?2 WHERE id=?1",
            params![id, active as i64],
        )? == 1;
        if changed && !active {
            transaction.execute("DELETE FROM sessions WHERE admin_id=?1", [id])?;
        }
        transaction.commit()?;
        Ok(changed)
    }
    pub fn create_session(
        &self,
        token: &str,
        admin_id: i64,
        csrf: &str,
        expires: DateTime<Utc>,
    ) -> rusqlite::Result<()> {
        let c = self.conn();
        c.execute(
            "DELETE FROM sessions WHERE expires_at < ?1",
            [Utc::now().to_rfc3339()],
        )?;
        c.execute(
            "INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at) VALUES(?1,?2,?3,?4)",
            params![token_hash(token), admin_id, csrf, expires.to_rfc3339()],
        )?;
        Ok(())
    }
    pub fn session(&self, token: &str) -> rusqlite::Result<Option<Session>> {
        self.conn().query_row("SELECT a.id,a.username,s.csrf_token,s.mfa_verified FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=?1 AND s.expires_at>?2 AND a.active=1",params![token_hash(token),Utc::now().to_rfc3339()],|r|Ok(Session{admin_id:r.get(0)?,username:r.get(1)?,csrf_token:r.get(2)?,mfa_verified:r.get::<_,i64>(3)?!=0})).optional()
    }
    pub fn verify_mfa(&self, token: &str) -> rusqlite::Result<bool> {
        Ok(self.conn().execute(
            "UPDATE sessions SET mfa_verified=1 WHERE token_hash=?1 AND expires_at>?2",
            params![token_hash(token), Utc::now().to_rfc3339()],
        )? == 1)
    }
    pub fn delete_session(&self, token: &str) -> rusqlite::Result<()> {
        self.conn().execute(
            "DELETE FROM sessions WHERE token_hash=?1",
            [token_hash(token)],
        )?;
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn create_share(
        &self,
        token: &str,
        alias: Option<&str>,
        path: &str,
        is_dir: bool,
        permission: &Permission,
        expires: Option<DateTime<Utc>>,
        max: Option<u64>,
        upload_max: Option<u64>,
        admin: i64,
        password_hash: Option<&str>,
        upload_conflict_strategy: &UploadConflictStrategy,
    ) -> rusqlite::Result<i64> {
        let c = self.conn();
        c.execute("INSERT INTO shares(token_hash,token,alias,relative_path,is_directory,permission,expires_at,max_downloads,max_upload_size,created_by,created_at,password_hash,upload_conflict_strategy) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",params![token_hash(token),token,alias,path,is_dir as i64,permission.as_str(),expires.map(|v|v.to_rfc3339()),max,upload_max,admin,Utc::now().to_rfc3339(),password_hash,upload_conflict_strategy.as_str()])?;
        Ok(c.last_insert_rowid())
    }
    fn map_share(r: &rusqlite::Row<'_>) -> rusqlite::Result<Share> {
        let exp: Option<String> = r.get(6)?;
        Ok(Share {
            id: r.get(0)?,
            token: r.get(1)?,
            alias: r.get(2)?,
            relative_path: r.get(3)?,
            is_directory: r.get::<_, i64>(4)? != 0,
            permission: Permission::parse(&r.get::<_, String>(5)?)
                .ok_or(rusqlite::Error::InvalidQuery)?,
            expires_at: exp
                .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                .map(|d| d.with_timezone(&Utc)),
            max_downloads: r.get(7)?,
            max_upload_size: r.get(8)?,
            download_count: r.get(9)?,
            active: r.get::<_, i64>(10)? != 0,
            password_hash: r.get(11)?,
            upload_conflict_strategy: UploadConflictStrategy::parse(&r.get::<_, String>(12)?)
                .ok_or(rusqlite::Error::InvalidQuery)?,
        })
    }
    pub fn share_by_token(&self, token: &str) -> rusqlite::Result<Option<Share>> {
        self.conn().query_row("SELECT id,token,alias,relative_path,is_directory,permission,expires_at,max_downloads,max_upload_size,download_count,active,password_hash,upload_conflict_strategy FROM shares WHERE token_hash=?1",[token_hash(token)],Self::map_share).optional()
    }
    pub fn share_by_alias(&self, alias: &str) -> rusqlite::Result<Option<Share>> {
        self.conn().query_row("SELECT id,token,alias,relative_path,is_directory,permission,expires_at,max_downloads,max_upload_size,download_count,active,password_hash,upload_conflict_strategy FROM shares WHERE alias=?1",[alias],Self::map_share).optional()
    }
    pub fn list_shares(&self) -> rusqlite::Result<Vec<Share>> {
        let c = self.conn();
        let mut s=c.prepare("SELECT id,token,alias,relative_path,is_directory,permission,expires_at,max_downloads,max_upload_size,download_count,active,password_hash,upload_conflict_strategy FROM shares ORDER BY id DESC")?;
        let shares = s
            .query_map([], Self::map_share)?
            .filter_map(Result::ok)
            .collect();
        Ok(shares)
    }
    pub fn set_share_active(&self, id: i64, active: bool) -> rusqlite::Result<()> {
        self.conn().execute(
            "UPDATE shares SET active=?2 WHERE id=?1",
            params![id, active as i64],
        )?;
        Ok(())
    }
    pub fn set_upload_conflict_strategy(
        &self,
        id: i64,
        strategy: &UploadConflictStrategy,
    ) -> rusqlite::Result<bool> {
        Ok(self.conn().execute(
            "UPDATE shares SET upload_conflict_strategy=?2 WHERE id=?1",
            params![id, strategy.as_str()],
        )? == 1)
    }
    pub fn delete_share(&self, id: i64) -> rusqlite::Result<()> {
        self.conn()
            .execute("DELETE FROM shares WHERE id=?1", [id])?;
        Ok(())
    }
    pub fn count_download(&self, id: i64) -> rusqlite::Result<bool> {
        Ok(self.conn().execute("UPDATE shares SET download_count=download_count+1 WHERE id=?1 AND active=1 AND (expires_at IS NULL OR expires_at>?2) AND (max_downloads IS NULL OR download_count<max_downloads)",params![id,Utc::now().to_rfc3339()])?==1)
    }
    pub fn set_share_password(&self, id: i64, hash: Option<&str>) -> rusqlite::Result<bool> {
        let mut connection = self.conn();
        let transaction = connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE shares SET password_hash=?2 WHERE id=?1",
            params![id, hash],
        )? == 1;
        transaction.execute("DELETE FROM public_unlock_sessions WHERE share_id=?1", [id])?;
        transaction.commit()?;
        Ok(changed)
    }
    pub fn create_unlock_session(
        &self,
        token: &str,
        share_id: i64,
        expires: DateTime<Utc>,
    ) -> rusqlite::Result<()> {
        let c = self.conn();
        c.execute(
            "DELETE FROM public_unlock_sessions WHERE expires_at<=?1",
            [Utc::now().to_rfc3339()],
        )?;
        c.execute(
            "INSERT INTO public_unlock_sessions(token_hash,share_id,expires_at) VALUES(?1,?2,?3)",
            params![token_hash(token), share_id, expires.to_rfc3339()],
        )?;
        Ok(())
    }
    pub fn unlock_session(&self, token: &str, share_id: i64) -> rusqlite::Result<bool> {
        self.conn().query_row("SELECT EXISTS(SELECT 1 FROM public_unlock_sessions WHERE token_hash=?1 AND share_id=?2 AND expires_at>?3)", params![token_hash(token), share_id, Utc::now().to_rfc3339()], |row| row.get(0))
    }
    pub fn create_preview_session(
        &self,
        token: &str,
        share_id: i64,
        relative_path: &str,
        expires: DateTime<Utc>,
    ) -> rusqlite::Result<()> {
        let c = self.conn();
        c.execute(
            "DELETE FROM public_preview_sessions WHERE expires_at<=?1",
            [Utc::now().to_rfc3339()],
        )?;
        c.execute(
            "INSERT INTO public_preview_sessions(token_hash,share_id,relative_path,expires_at) VALUES(?1,?2,?3,?4)",
            params![token_hash(token), share_id, relative_path, expires.to_rfc3339()],
        )?;
        Ok(())
    }
    pub fn preview_session(
        &self,
        token: &str,
        share_id: i64,
        relative_path: &str,
    ) -> rusqlite::Result<bool> {
        self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM public_preview_sessions WHERE token_hash=?1 AND share_id=?2 AND relative_path=?3 AND expires_at>?4)",
            params![token_hash(token), share_id, relative_path, Utc::now().to_rfc3339()],
            |row| row.get(0),
        )
    }
    pub fn audit(
        &self,
        actor: &str,
        action: &str,
        object: Option<&str>,
        detail: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.conn().execute(
            "INSERT INTO audit(occurred_at,actor,action,object_id,detail) VALUES(?1,?2,?3,?4,?5)",
            params![Utc::now().to_rfc3339(), actor, action, object, detail],
        )?;
        tracing::info!(target: "vaultlink::audit", actor, action, object_id = object.unwrap_or(""), detail = detail.unwrap_or(""), "audit event");
        Ok(())
    }
    pub fn runtime_settings(&self) -> rusqlite::Result<Vec<(String, String)>> {
        let c = self.conn();
        let mut statement = c.prepare("SELECT key,value FROM runtime_settings ORDER BY key")?;
        let settings = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect();
        settings
    }
    pub fn set_runtime_setting(&self, key: &str, value: &str, admin: i64) -> rusqlite::Result<()> {
        self.conn().execute(
            "INSERT INTO runtime_settings(key,value,updated_by,updated_at) VALUES(?1,?2,?3,?4)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_by=excluded.updated_by,updated_at=excluded.updated_at",
            params![key, value, admin, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }
    pub fn list_audit(
        &self,
        action: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> rusqlite::Result<Vec<AuditEvent>> {
        let c = self.conn();
        if let Some(action) = action {
            let mut statement = c.prepare(
                "SELECT occurred_at,actor,action,object_id,detail FROM audit WHERE action=?1 ORDER BY id DESC LIMIT ?2 OFFSET ?3",
            )?;
            let events = statement
                .query_map(params![action, limit as i64, offset as i64], |row| {
                    Ok(AuditEvent {
                        occurred_at: row.get(0)?,
                        actor: row.get(1)?,
                        action: row.get(2)?,
                        object_id: row.get(3)?,
                        detail: row.get(4)?,
                    })
                })?
                .collect();
            events
        } else {
            let mut statement = c.prepare(
                "SELECT occurred_at,actor,action,object_id,detail FROM audit ORDER BY id DESC LIMIT ?1 OFFSET ?2",
            )?;
            let events = statement
                .query_map(params![limit as i64, offset as i64], |row| {
                    Ok(AuditEvent {
                        occurred_at: row.get(0)?,
                        actor: row.get(1)?,
                        action: row.get(2)?,
                        object_id: row.get(3)?,
                        detail: row.get(4)?,
                    })
                })?
                .collect();
            events
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn download_limit_is_atomic() {
        let d = Database::open(":memory:").unwrap();
        d.create_admin("a", "h", "s").unwrap();
        let id = d
            .create_share(
                "token",
                None,
                "x",
                false,
                &Permission::DownloadOnly,
                None,
                Some(1),
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        assert!(d.count_download(id).unwrap());
        assert!(!d.count_download(id).unwrap());
    }
    #[test]
    fn alias_unique() {
        let d = Database::open(":memory:").unwrap();
        d.create_admin("a", "h", "s").unwrap();
        d.create_share(
            "a",
            Some("alias"),
            "x",
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
        assert!(d
            .create_share(
                "b",
                Some("alias"),
                "y",
                false,
                &Permission::DownloadOnly,
                None,
                None,
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .is_err());
    }

    #[test]
    fn session_mfa_and_logout_lifecycle() {
        let d = Database::open(":memory:").unwrap();
        d.create_admin("admin", "hash", "secret").unwrap();
        d.create_session(
            "session-token",
            1,
            "csrf",
            Utc::now() + chrono::Duration::hours(1),
        )
        .unwrap();
        let session = d.session("session-token").unwrap().unwrap();
        assert!(!session.mfa_verified);
        assert_eq!(session.csrf_token, "csrf");
        assert!(d.verify_mfa("session-token").unwrap());
        assert!(d.session("session-token").unwrap().unwrap().mfa_verified);
        d.delete_session("session-token").unwrap();
        assert!(d.session("session-token").unwrap().is_none());
    }

    #[test]
    fn disabled_and_deleted_links_change_state() {
        let d = Database::open(":memory:").unwrap();
        d.create_admin("admin", "hash", "secret").unwrap();
        let id = d
            .create_share(
                "token",
                None,
                "file",
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
        d.set_share_active(id, false).unwrap();
        assert!(!d.share_by_token("token").unwrap().unwrap().active);
        d.delete_share(id).unwrap();
        assert!(d.share_by_token("token").unwrap().is_none());
    }

    #[test]
    fn migrates_unversioned_installation_without_losing_data() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy.sqlite");
        {
            let connection = Connection::open(&path).unwrap();
            connection.execute_batch(r#"
CREATE TABLE admins(id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, totp_secret TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE sessions(token_hash TEXT PRIMARY KEY, admin_id INTEGER NOT NULL REFERENCES admins(id), csrf_token TEXT NOT NULL, mfa_verified INTEGER NOT NULL DEFAULT 0, expires_at TEXT NOT NULL);
CREATE TABLE shares(id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, token TEXT NOT NULL, alias TEXT UNIQUE, relative_path TEXT NOT NULL, is_directory INTEGER NOT NULL, permission TEXT NOT NULL, expires_at TEXT, max_downloads INTEGER, download_count INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1, created_by INTEGER NOT NULL REFERENCES admins(id), created_at TEXT NOT NULL);
CREATE TABLE audit(id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, object_id TEXT, detail TEXT);
INSERT INTO admins VALUES(1,'admin','hash','secret','2026-01-01T00:00:00Z');
INSERT INTO sessions VALUES('session-hash',1,'csrf',1,'2099-01-01T00:00:00Z');
INSERT INTO audit VALUES(1,'2026-01-01T00:00:00Z','admin','share_created','1','download_only');
"#).unwrap();
            connection.execute("INSERT INTO shares VALUES(1,?1,'share-token','alias','folder',1,'download_only',NULL,7,3,1,1,'2026-01-01T00:00:00Z')", [token_hash("share-token")]).unwrap();
        }
        let database = Database::open(&path).unwrap();
        assert_eq!(
            database
                .conn()
                .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
                .unwrap(),
            SCHEMA_VERSION
        );
        let share = database.share_by_token("share-token").unwrap().unwrap();
        assert_eq!(share.download_count, 3);
        assert_eq!(share.max_downloads, Some(7));
        assert!(share.password_hash.is_none());
        assert_eq!(
            share.upload_conflict_strategy,
            UploadConflictStrategy::Reject
        );
        assert_eq!(
            database
                .conn()
                .query_row::<i64, _, _>("SELECT COUNT(*) FROM audit", [], |row| row.get(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn rejects_unknown_newer_schema() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("future.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        drop(connection);
        assert!(Database::open(path).is_err());
    }

    #[test]
    fn unlock_sessions_are_hashed_and_cascade_with_share() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let share_id = database
            .create_share(
                "share",
                None,
                "folder",
                true,
                &Permission::DownloadOnly,
                None,
                None,
                None,
                1,
                Some("password-hash"),
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        database
            .create_unlock_session(
                "unlock-secret",
                share_id,
                Utc::now() + chrono::Duration::minutes(60),
            )
            .unwrap();
        assert!(database.unlock_session("unlock-secret", share_id).unwrap());
        let stored: String = database
            .conn()
            .query_row("SELECT token_hash FROM public_unlock_sessions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_ne!(stored, "unlock-secret");
        database
            .set_share_password(share_id, Some("new-password-hash"))
            .unwrap();
        assert!(!database.unlock_session("unlock-secret", share_id).unwrap());
        database
            .create_unlock_session(
                "new-unlock-secret",
                share_id,
                Utc::now() + chrono::Duration::minutes(60),
            )
            .unwrap();
        database.delete_share(share_id).unwrap();
        assert_eq!(
            database
                .conn()
                .query_row::<i64, _, _>("SELECT COUNT(*) FROM public_unlock_sessions", [], |row| {
                    row.get(0)
                })
                .unwrap(),
            0
        );
    }

    #[test]
    fn preview_sessions_are_hashed_share_and_path_bound() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let share_id = database
            .create_share(
                "share",
                None,
                "folder",
                true,
                &Permission::DownloadOnly,
                None,
                None,
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        database
            .create_preview_session(
                "preview-secret",
                share_id,
                "folder/image.png",
                Utc::now() + chrono::Duration::minutes(5),
            )
            .unwrap();
        assert!(database
            .preview_session("preview-secret", share_id, "folder/image.png")
            .unwrap());
        assert!(!database
            .preview_session("preview-secret", share_id, "folder/other.png")
            .unwrap());
        assert!(!database
            .preview_session("wrong", share_id, "folder/image.png")
            .unwrap());
        let stored: String = database
            .conn()
            .query_row(
                "SELECT token_hash FROM public_preview_sessions",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_ne!(stored, "preview-secret");
    }
}
