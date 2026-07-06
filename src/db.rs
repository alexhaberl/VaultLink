use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub struct Database(Arc<Mutex<Connection>>);

#[derive(Clone, Debug)]
pub struct Admin {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub totp_secret: String,
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
    pub download_count: u64,
    pub active: bool,
}

fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let path = path.as_ref();
        let conn = Connection::open(path)?;
        #[cfg(unix)]
        if path != Path::new(":memory:") {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(r#"
CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, totp_secret TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE, csrf_token TEXT NOT NULL, mfa_verified INTEGER NOT NULL DEFAULT 0, expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS shares(id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, token TEXT NOT NULL, alias TEXT UNIQUE, relative_path TEXT NOT NULL, is_directory INTEGER NOT NULL, permission TEXT NOT NULL, expires_at TEXT, max_downloads INTEGER, download_count INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1, created_by INTEGER NOT NULL REFERENCES admins(id), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, object_id TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_shares_alias ON shares(alias);
"#)?;
        Ok(Self(Arc::new(Mutex::new(conn))))
    }
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
            "INSERT INTO admins(username,password_hash,totp_secret,created_at) VALUES(?1,?2,?3,?4)",
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
                "SELECT id,username,password_hash,totp_secret FROM admins WHERE username=?1",
                [username],
                |r| {
                    Ok(Admin {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        password_hash: r.get(2)?,
                        totp_secret: r.get(3)?,
                    })
                },
            )
            .optional()
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
        self.conn().query_row("SELECT a.id,a.username,s.csrf_token,s.mfa_verified FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=?1 AND s.expires_at>?2",params![token_hash(token),Utc::now().to_rfc3339()],|r|Ok(Session{admin_id:r.get(0)?,username:r.get(1)?,csrf_token:r.get(2)?,mfa_verified:r.get::<_,i64>(3)?!=0})).optional()
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
        admin: i64,
    ) -> rusqlite::Result<i64> {
        let c = self.conn();
        c.execute("INSERT INTO shares(token_hash,token,alias,relative_path,is_directory,permission,expires_at,max_downloads,created_by,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",params![token_hash(token),token,alias,path,is_dir as i64,permission.as_str(),expires.map(|v|v.to_rfc3339()),max,admin,Utc::now().to_rfc3339()])?;
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
            download_count: r.get(8)?,
            active: r.get::<_, i64>(9)? != 0,
        })
    }
    pub fn share_by_token(&self, token: &str) -> rusqlite::Result<Option<Share>> {
        self.conn().query_row("SELECT id,token,alias,relative_path,is_directory,permission,expires_at,max_downloads,download_count,active FROM shares WHERE token_hash=?1",[token_hash(token)],Self::map_share).optional()
    }
    pub fn share_by_alias(&self, alias: &str) -> rusqlite::Result<Option<Share>> {
        self.conn().query_row("SELECT id,token,alias,relative_path,is_directory,permission,expires_at,max_downloads,download_count,active FROM shares WHERE alias=?1",[alias],Self::map_share).optional()
    }
    pub fn list_shares(&self) -> rusqlite::Result<Vec<Share>> {
        let c = self.conn();
        let mut s=c.prepare("SELECT id,token,alias,relative_path,is_directory,permission,expires_at,max_downloads,download_count,active FROM shares ORDER BY id DESC")?;
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
    pub fn delete_share(&self, id: i64) -> rusqlite::Result<()> {
        self.conn()
            .execute("DELETE FROM shares WHERE id=?1", [id])?;
        Ok(())
    }
    pub fn count_download(&self, id: i64) -> rusqlite::Result<bool> {
        Ok(self.conn().execute("UPDATE shares SET download_count=download_count+1 WHERE id=?1 AND active=1 AND (expires_at IS NULL OR expires_at>?2) AND (max_downloads IS NULL OR download_count<max_downloads)",params![id,Utc::now().to_rfc3339()])?==1)
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
        Ok(())
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
                1,
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
            1,
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
                1
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
                1,
            )
            .unwrap();
        d.set_share_active(id, false).unwrap();
        assert!(!d.share_by_token("token").unwrap().unwrap().active);
        d.delete_share(id).unwrap();
        assert!(d.share_by_token("token").unwrap().is_none());
    }
}
