use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

const SCHEMA_VERSION: i64 = 7;

pub const TRANSFER_SESSION_TTL_SECONDS: i64 = 15 * 60;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitialAdminOutcome {
    Created,
    AlreadyInitialized,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminDeactivationOutcome {
    Deactivated,
    AlreadyInactive,
    LastActive,
    NotFound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferLeaseBeginOutcome {
    AlreadyCounted,
    NewLease,
    LimitReached,
    ShareUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferAvailabilityOutcome {
    Available,
    AlreadyCounted,
    LimitReached,
    ShareUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransferAccessState {
    Available,
    ExistingGrant { grant_id: i64, counted: bool },
    LimitReached,
    ShareUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferLeaseCompleteOutcome {
    Counted,
    AlreadyCounted,
    NotFound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferLeaseCancelOutcome {
    Cancelled,
    NotFound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferLeaseHeartbeatOutcome {
    Extended,
    NotFound,
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
    tx.commit()
}

fn transfer_deadlines() -> (String, String) {
    let now = Utc::now();
    let expires = now + Duration::seconds(TRANSFER_SESSION_TTL_SECONDS);
    (now.to_rfc3339(), expires.to_rfc3339())
}

fn cleanup_transfer_state(transaction: &Transaction<'_>, now: &str) -> rusqlite::Result<()> {
    transaction.execute(
        "DELETE FROM public_transfer_leases WHERE expires_at<=?1",
        [now],
    )?;
    transaction.execute(
        "DELETE FROM public_transfer_grants
         WHERE expires_at<=?1
            OR (counted=0 AND NOT EXISTS(
                SELECT 1 FROM public_transfer_leases leases
                WHERE leases.grant_id=public_transfer_grants.id AND leases.expires_at>?1
            ))",
        [now],
    )?;
    Ok(())
}

fn transfer_access_state(
    connection: &Connection,
    session_token_hash: &str,
    share_id: i64,
    resource_key: &str,
    action: &str,
    now: &str,
) -> rusqlite::Result<TransferAccessState> {
    let share = connection
        .query_row(
            "SELECT max_downloads,download_count FROM shares
             WHERE id=?1 AND active=1 AND (expires_at IS NULL OR expires_at>?2)
               AND permission IN ('download_only','download_upload')",
            params![share_id, now],
            |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let Some((max_downloads, download_count)) = share else {
        return Ok(TransferAccessState::ShareUnavailable);
    };

    let existing_grant = connection
        .query_row(
            "SELECT id,counted FROM public_transfer_grants
             WHERE session_token_hash=?1 AND share_id=?2
               AND resource_key=?3 AND action=?4 AND expires_at>?5",
            params![session_token_hash, share_id, resource_key, action, now],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)? != 0)),
        )
        .optional()?;
    if let Some((grant_id, counted)) = existing_grant {
        return Ok(TransferAccessState::ExistingGrant { grant_id, counted });
    }

    let pending_grants: i64 = connection.query_row(
        "SELECT COUNT(*) FROM public_transfer_grants grants
         WHERE grants.share_id=?1 AND grants.counted=0 AND grants.expires_at>?2
           AND EXISTS(
               SELECT 1 FROM public_transfer_leases leases
               WHERE leases.grant_id=grants.id AND leases.expires_at>?2
           )",
        params![share_id, now],
        |row| row.get(0),
    )?;
    if max_downloads.is_some_and(|maximum| download_count.saturating_add(pending_grants) >= maximum)
    {
        Ok(TransferAccessState::LimitReached)
    } else {
        Ok(TransferAccessState::Available)
    }
}

impl Database {
    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.0.lock().expect("database mutex poisoned")
    }
    pub fn create_initial_admin(
        &self,
        username: &str,
        password_hash: &str,
        totp_secret: &str,
    ) -> rusqlite::Result<InitialAdminOutcome> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let initialized: bool =
            transaction.query_row("SELECT EXISTS(SELECT 1 FROM admins)", [], |row| row.get(0))?;
        let outcome = if initialized {
            InitialAdminOutcome::AlreadyInitialized
        } else {
            transaction.execute(
                "INSERT INTO admins(username,password_hash,totp_secret,created_at,active) VALUES(?1,?2,?3,?4,1)",
                params![username, password_hash, totp_secret, Utc::now().to_rfc3339()],
            )?;
            InitialAdminOutcome::Created
        };
        transaction.commit()?;
        Ok(outcome)
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
        let mut statement =
            c.prepare("SELECT id,username,created_at,active FROM admins ORDER BY id ASC")?;
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
    pub fn activate_admin(&self, id: i64) -> rusqlite::Result<bool> {
        Ok(self
            .conn()
            .execute("UPDATE admins SET active=1 WHERE id=?1", [id])?
            == 1)
    }

    pub fn deactivate_admin(&self, id: i64) -> rusqlite::Result<AdminDeactivationOutcome> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active = transaction
            .query_row("SELECT active FROM admins WHERE id=?1", [id], |row| {
                row.get::<_, i64>(0).map(|active| active != 0)
            })
            .optional()?;
        let outcome = match active {
            None => AdminDeactivationOutcome::NotFound,
            Some(false) => {
                // Preserve the session-revocation invariant even if an older database
                // somehow contains sessions for an already inactive administrator.
                transaction.execute("DELETE FROM sessions WHERE admin_id=?1", [id])?;
                AdminDeactivationOutcome::AlreadyInactive
            }
            Some(true) => {
                let changed = transaction.execute(
                    "UPDATE admins SET active=0
                     WHERE id=?1 AND active=1
                       AND EXISTS(SELECT 1 FROM admins WHERE active=1 AND id<>?1)",
                    [id],
                )? == 1;
                if changed {
                    transaction.execute("DELETE FROM sessions WHERE admin_id=?1", [id])?;
                    AdminDeactivationOutcome::Deactivated
                } else {
                    AdminDeactivationOutcome::LastActive
                }
            }
        };
        transaction.commit()?;
        Ok(outcome)
    }

    pub fn reset_admin_password(&self, id: i64, password_hash: &str) -> rusqlite::Result<bool> {
        let mut connection = self.conn();
        let transaction = connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE admins SET password_hash=?2 WHERE id=?1",
            params![id, password_hash],
        )? == 1;
        if changed {
            transaction.execute("DELETE FROM sessions WHERE admin_id=?1", [id])?;
        }
        transaction.commit()?;
        Ok(changed)
    }
    pub fn reset_admin_totp(&self, id: i64, totp_secret: &str) -> rusqlite::Result<Option<String>> {
        let mut connection = self.conn();
        let transaction = connection.transaction()?;
        let username = transaction
            .query_row("SELECT username FROM admins WHERE id=?1", [id], |row| {
                row.get::<_, String>(0)
            })
            .optional()?;
        if username.is_some() {
            transaction.execute(
                "UPDATE admins SET totp_secret=?2 WHERE id=?1",
                params![id, totp_secret],
            )?;
            transaction.execute("DELETE FROM sessions WHERE admin_id=?1", [id])?;
        }
        transaction.commit()?;
        Ok(username)
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
        let now = Utc::now().to_rfc3339();
        Ok(self.conn().execute(
            "UPDATE shares
             SET download_count=download_count+1
             WHERE id=?1 AND active=1 AND (expires_at IS NULL OR expires_at>?2)
               AND (max_downloads IS NULL OR download_count + (
                    SELECT COUNT(*) FROM public_transfer_grants grants
                    WHERE grants.share_id=shares.id AND grants.counted=0
                      AND grants.expires_at>?2
                      AND EXISTS(
                          SELECT 1 FROM public_transfer_leases leases
                          WHERE leases.grant_id=grants.id AND leases.expires_at>?2
                      )
               ) < max_downloads)",
            params![id, now],
        )? == 1)
    }

    /// Starts one HTTP request lease for a route-scoped client transfer session.
    ///
    /// `session_token` is the client session cookie value. HTTP surfaces should use
    /// separate tokens (and cookie paths) when their sessions must not overlap.
    /// `resource_key` and `action` form the logical, count-once transfer identity.
    /// Each concrete request supplies a fresh `lease_token`.
    pub fn begin_transfer_lease(
        &self,
        session_token: &str,
        lease_token: &str,
        share_id: i64,
        resource_key: &str,
        action: &str,
    ) -> rusqlite::Result<TransferLeaseBeginOutcome> {
        let (now, expires) = transfer_deadlines();
        let session_token_hash = token_hash(session_token);
        let lease_token_hash = token_hash(lease_token);
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_transfer_state(&transaction, &now)?;
        let access = transfer_access_state(
            &transaction,
            &session_token_hash,
            share_id,
            resource_key,
            action,
            &now,
        )?;

        match access {
            TransferAccessState::ExistingGrant { grant_id, counted } => {
                if !counted {
                    transaction.execute(
                        "UPDATE public_transfer_grants SET expires_at=?2 WHERE id=?1",
                        params![grant_id, expires],
                    )?;
                }
                transaction.execute(
                    "INSERT INTO public_transfer_leases(token_hash,grant_id,created_at,heartbeat_at,expires_at)
                     VALUES(?1,?2,?3,?3,?4)",
                    params![lease_token_hash, grant_id, now, expires],
                )?;
                transaction.commit()?;
                return Ok(if counted {
                    TransferLeaseBeginOutcome::AlreadyCounted
                } else {
                    TransferLeaseBeginOutcome::NewLease
                });
            }
            TransferAccessState::LimitReached => {
                transaction.commit()?;
                return Ok(TransferLeaseBeginOutcome::LimitReached);
            }
            TransferAccessState::ShareUnavailable => {
                transaction.commit()?;
                return Ok(TransferLeaseBeginOutcome::ShareUnavailable);
            }
            TransferAccessState::Available => {}
        }

        transaction.execute(
            "INSERT INTO public_transfer_grants(
                session_token_hash,share_id,resource_key,action,counted,created_at,expires_at
             ) VALUES(?1,?2,?3,?4,0,?5,?6)",
            params![
                session_token_hash,
                share_id,
                resource_key,
                action,
                now,
                expires
            ],
        )?;
        let grant_id = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO public_transfer_leases(token_hash,grant_id,created_at,heartbeat_at,expires_at)
             VALUES(?1,?2,?3,?3,?4)",
            params![lease_token_hash, grant_id, now, expires],
        )?;
        transaction.commit()?;
        Ok(TransferLeaseBeginOutcome::NewLease)
    }

    /// Checks whether the same logical transfer could start without reserving or
    /// counting quota. This is used by bodyless HTTP methods such as HEAD.
    pub fn check_transfer_availability(
        &self,
        session_token: &str,
        share_id: i64,
        resource_key: &str,
        action: &str,
    ) -> rusqlite::Result<TransferAvailabilityOutcome> {
        let (now, _) = transfer_deadlines();
        let session_token_hash = token_hash(session_token);
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_transfer_state(&transaction, &now)?;
        let outcome = match transfer_access_state(
            &transaction,
            &session_token_hash,
            share_id,
            resource_key,
            action,
            &now,
        )? {
            TransferAccessState::Available => TransferAvailabilityOutcome::Available,
            TransferAccessState::ExistingGrant { counted: true, .. } => {
                TransferAvailabilityOutcome::AlreadyCounted
            }
            TransferAccessState::ExistingGrant { counted: false, .. } => {
                TransferAvailabilityOutcome::Available
            }
            TransferAccessState::LimitReached => TransferAvailabilityOutcome::LimitReached,
            TransferAccessState::ShareUnavailable => TransferAvailabilityOutcome::ShareUnavailable,
        };
        transaction.commit()?;
        Ok(outcome)
    }

    /// Completes one request lease. The first successful request for a pending
    /// grant increments the share counter; later requests for that grant do not.
    pub fn complete_transfer_lease(
        &self,
        lease_token: &str,
    ) -> rusqlite::Result<TransferLeaseCompleteOutcome> {
        let (now, expires) = transfer_deadlines();
        let lease_token_hash = token_hash(lease_token);
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_transfer_state(&transaction, &now)?;
        let lease = transaction
            .query_row(
                "SELECT grants.id,grants.share_id,grants.counted
                 FROM public_transfer_leases leases
                 JOIN public_transfer_grants grants ON grants.id=leases.grant_id
                 WHERE leases.token_hash=?1 AND leases.expires_at>?2 AND grants.expires_at>?2",
                params![lease_token_hash, now],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)? != 0,
                    ))
                },
            )
            .optional()?;
        let Some((grant_id, share_id, already_counted)) = lease else {
            transaction.commit()?;
            return Ok(TransferLeaseCompleteOutcome::NotFound);
        };

        let outcome = if already_counted {
            TransferLeaseCompleteOutcome::AlreadyCounted
        } else {
            if transaction.execute(
                "UPDATE shares SET download_count=download_count+1 WHERE id=?1",
                [share_id],
            )? != 1
            {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            if transaction.execute(
                "UPDATE public_transfer_grants SET counted=1,expires_at=?2
                 WHERE id=?1 AND counted=0",
                params![grant_id, expires],
            )? != 1
            {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            TransferLeaseCompleteOutcome::Counted
        };
        transaction.execute(
            "DELETE FROM public_transfer_leases WHERE token_hash=?1",
            [lease_token_hash],
        )?;
        transaction.commit()?;
        Ok(outcome)
    }

    /// Cancels only the specified request. A pending grant reservation is released
    /// when its final lease disappears; counted grants remain resumable until expiry.
    pub fn cancel_transfer_lease(
        &self,
        lease_token: &str,
    ) -> rusqlite::Result<TransferLeaseCancelOutcome> {
        let (now, _) = transfer_deadlines();
        let lease_token_hash = token_hash(lease_token);
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_transfer_state(&transaction, &now)?;
        let grant = transaction
            .query_row(
                "SELECT grants.id,grants.counted
                 FROM public_transfer_leases leases
                 JOIN public_transfer_grants grants ON grants.id=leases.grant_id
                 WHERE leases.token_hash=?1",
                [lease_token_hash.as_str()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)? != 0)),
            )
            .optional()?;
        let Some((grant_id, counted)) = grant else {
            transaction.commit()?;
            return Ok(TransferLeaseCancelOutcome::NotFound);
        };
        transaction.execute(
            "DELETE FROM public_transfer_leases WHERE token_hash=?1",
            [lease_token_hash],
        )?;
        if !counted {
            transaction.execute(
                "DELETE FROM public_transfer_grants
                 WHERE id=?1 AND counted=0
                   AND NOT EXISTS(SELECT 1 FROM public_transfer_leases WHERE grant_id=?1)",
                [grant_id],
            )?;
        }
        transaction.commit()?;
        Ok(TransferLeaseCancelOutcome::Cancelled)
    }

    pub fn heartbeat_transfer_lease(
        &self,
        lease_token: &str,
    ) -> rusqlite::Result<TransferLeaseHeartbeatOutcome> {
        let (now, expires) = transfer_deadlines();
        let lease_token_hash = token_hash(lease_token);
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_transfer_state(&transaction, &now)?;
        let grant = transaction
            .query_row(
                "SELECT leases.grant_id,grants.counted
                 FROM public_transfer_leases leases
                 JOIN public_transfer_grants grants ON grants.id=leases.grant_id
                 WHERE leases.token_hash=?1 AND leases.expires_at>?2",
                params![lease_token_hash, now],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)? != 0)),
            )
            .optional()?;
        let Some((grant_id, counted)) = grant else {
            transaction.commit()?;
            return Ok(TransferLeaseHeartbeatOutcome::NotFound);
        };
        transaction.execute(
            "UPDATE public_transfer_leases
             SET heartbeat_at=?2,expires_at=?3 WHERE token_hash=?1",
            params![lease_token_hash, now, expires],
        )?;
        if !counted {
            transaction.execute(
                "UPDATE public_transfer_grants SET expires_at=?2 WHERE id=?1",
                params![grant_id, expires],
            )?;
        }
        transaction.commit()?;
        Ok(TransferLeaseHeartbeatOutcome::Extended)
    }

    /// Number of distinct, uncounted grants currently reserving a download slot.
    pub fn active_transfer_reservations(&self, share_id: i64) -> rusqlite::Result<u64> {
        let now = Utc::now().to_rfc3339();
        self.conn().query_row(
            "SELECT COUNT(*) FROM public_transfer_grants grants
             WHERE grants.share_id=?1 AND grants.counted=0 AND grants.expires_at>?2
               AND EXISTS(
                   SELECT 1 FROM public_transfer_leases leases
                   WHERE leases.grant_id=grants.id AND leases.expires_at>?2
               )",
            params![share_id, now],
            |row| row.get(0),
        )
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
    pub fn replace_runtime_settings(
        &self,
        settings: &[(&str, String)],
        admin: i64,
    ) -> rusqlite::Result<()> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute("DELETE FROM runtime_settings", [])?;
        let updated_at = Utc::now().to_rfc3339();
        {
            let mut statement = transaction.prepare(
                "INSERT INTO runtime_settings(key,value,updated_by,updated_at)
                 VALUES(?1,?2,?3,?4)",
            )?;
            for (key, value) in settings {
                statement.execute(params![*key, value.as_str(), admin, updated_at])?;
            }
        }
        transaction.commit()
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
    fn initial_admin_creation_is_atomic() {
        let database = Database::open(":memory:").unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for username in ["first", "second"] {
            let database = database.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                database
                    .create_initial_admin(username, "hash", "secret")
                    .unwrap()
            }));
        }
        barrier.wait();
        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == InitialAdminOutcome::Created)
                .count(),
            1
        );
        assert_eq!(database.admin_count().unwrap(), 1);
    }

    #[test]
    fn concurrent_admin_deactivation_preserves_one_active_admin() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("one", "hash", "secret").unwrap();
        database.create_admin("two", "hash", "secret").unwrap();
        database
            .create_session("one-session", 1, "csrf", Utc::now() + Duration::hours(1))
            .unwrap();
        database
            .create_session("two-session", 2, "csrf", Utc::now() + Duration::hours(1))
            .unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let first = {
            let database = database.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                database.deactivate_admin(2).unwrap()
            })
        };
        let second = {
            let database = database.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                database.deactivate_admin(1).unwrap()
            })
        };
        barrier.wait();
        let outcomes = [first.join().unwrap(), second.join().unwrap()];
        assert!(outcomes.contains(&AdminDeactivationOutcome::Deactivated));
        assert!(outcomes.contains(&AdminDeactivationOutcome::LastActive));
        assert_eq!(database.active_admin_count().unwrap(), 1);
        assert_eq!(
            database
                .conn()
                .query_row::<i64, _, _>("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn runtime_settings_replacement_rolls_back_as_one_snapshot() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let original = [
            ("max_upload_size", "10".to_string()),
            ("max_zip_size", "20".to_string()),
        ];
        database.replace_runtime_settings(&original, 1).unwrap();
        database
            .conn()
            .execute_batch(
                "CREATE TEMP TRIGGER fail_runtime_replace
                 BEFORE INSERT ON runtime_settings
                 WHEN NEW.key='max_zip_size'
                 BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
            )
            .unwrap();
        let replacement = [
            ("max_upload_size", "100".to_string()),
            ("max_zip_size", "200".to_string()),
        ];
        assert!(database.replace_runtime_settings(&replacement, 1).is_err());
        assert_eq!(
            database.runtime_settings().unwrap(),
            vec![
                ("max_upload_size".to_string(), "10".to_string()),
                ("max_zip_size".to_string(), "20".to_string()),
            ]
        );
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
        let path = directory.path().join("old_schema.sqlite");
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
    fn migrates_v6_database_to_transfer_grants_without_losing_shares() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("v6.sqlite");
        {
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE shares(id INTEGER PRIMARY KEY, marker TEXT NOT NULL);
                     INSERT INTO shares VALUES(7, 'preserved');
                     PRAGMA user_version=6;",
                )
                .unwrap();
        }
        let database = Database::open(&path).unwrap();
        let connection = database.conn();
        assert_eq!(
            connection
                .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
                .unwrap(),
            7
        );
        assert_eq!(
            connection
                .query_row::<String, _, _>("SELECT marker FROM shares WHERE id=7", [], |row| {
                    row.get(0)
                })
                .unwrap(),
            "preserved"
        );
        assert_eq!(
            connection
                .query_row::<i64, _, _>(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE type='table' AND name IN ('public_transfer_grants','public_transfer_leases')",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            2
        );
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

    #[test]
    fn transfer_grant_reserves_and_counts_once_across_request_leases() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let share_id = database
            .create_share(
                "share",
                None,
                "file.bin",
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

        assert_eq!(
            database
                .check_transfer_availability("client", share_id, "file.bin", "download")
                .unwrap(),
            TransferAvailabilityOutcome::Available
        );

        assert_eq!(
            database
                .begin_transfer_lease("client", "lease-one", share_id, "file.bin", "download")
                .unwrap(),
            TransferLeaseBeginOutcome::NewLease
        );
        assert_eq!(
            database
                .begin_transfer_lease("client", "lease-two", share_id, "file.bin", "download")
                .unwrap(),
            TransferLeaseBeginOutcome::NewLease
        );
        assert_eq!(database.active_transfer_reservations(share_id).unwrap(), 1);
        assert_eq!(
            database
                .check_transfer_availability("client", share_id, "file.bin", "download")
                .unwrap(),
            TransferAvailabilityOutcome::Available
        );
        assert_eq!(
            database
                .check_transfer_availability("other", share_id, "file.bin", "download")
                .unwrap(),
            TransferAvailabilityOutcome::LimitReached
        );
        assert_eq!(
            database
                .begin_transfer_lease("other", "blocked", share_id, "file.bin", "download")
                .unwrap(),
            TransferLeaseBeginOutcome::LimitReached
        );
        assert_eq!(
            database.complete_transfer_lease("lease-one").unwrap(),
            TransferLeaseCompleteOutcome::Counted
        );
        assert_eq!(
            database
                .share_by_token("share")
                .unwrap()
                .unwrap()
                .download_count,
            1
        );
        assert_eq!(
            database.complete_transfer_lease("lease-two").unwrap(),
            TransferLeaseCompleteOutcome::AlreadyCounted
        );
        assert_eq!(
            database
                .check_transfer_availability("client", share_id, "file.bin", "download")
                .unwrap(),
            TransferAvailabilityOutcome::AlreadyCounted
        );
        assert_eq!(
            database
                .check_transfer_availability("other", share_id, "file.bin", "download")
                .unwrap(),
            TransferAvailabilityOutcome::LimitReached
        );
        assert_eq!(
            database
                .share_by_token("share")
                .unwrap()
                .unwrap()
                .download_count,
            1
        );
        let counted_expiry: String = database
            .conn()
            .query_row(
                "SELECT expires_at FROM public_transfer_grants WHERE share_id=?1",
                [share_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            database
                .begin_transfer_lease("client", "resume", share_id, "file.bin", "download")
                .unwrap(),
            TransferLeaseBeginOutcome::AlreadyCounted
        );
        let resumed_expiry: String = database
            .conn()
            .query_row(
                "SELECT expires_at FROM public_transfer_grants WHERE share_id=?1",
                [share_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(resumed_expiry, counted_expiry);
        assert_eq!(
            database
                .begin_transfer_lease("client", "new-resource", share_id, "other.bin", "download")
                .unwrap(),
            TransferLeaseBeginOutcome::LimitReached
        );
    }

    #[test]
    fn transfer_cancel_releases_only_the_final_pending_lease() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let share_id = database
            .create_share(
                "share",
                None,
                "file.bin",
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
        database
            .begin_transfer_lease("client", "one", share_id, "file.bin", "download")
            .unwrap();
        database
            .begin_transfer_lease("client", "two", share_id, "file.bin", "download")
            .unwrap();
        assert_eq!(
            database.cancel_transfer_lease("one").unwrap(),
            TransferLeaseCancelOutcome::Cancelled
        );
        assert_eq!(database.active_transfer_reservations(share_id).unwrap(), 1);
        assert_eq!(
            database.cancel_transfer_lease("two").unwrap(),
            TransferLeaseCancelOutcome::Cancelled
        );
        assert_eq!(database.active_transfer_reservations(share_id).unwrap(), 0);
        assert_eq!(
            database
                .begin_transfer_lease("other", "replacement", share_id, "file.bin", "download")
                .unwrap(),
            TransferLeaseBeginOutcome::NewLease
        );
    }

    #[test]
    fn concurrent_transfer_grants_cannot_overbook_the_limit() {
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
                Some(1),
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for (client, lease, resource) in [
            ("client-a", "lease-a", "folder/a"),
            ("client-b", "lease-b", "folder/b"),
        ] {
            let database = database.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                database
                    .begin_transfer_lease(client, lease, share_id, resource, "download")
                    .unwrap()
            }));
        }
        barrier.wait();
        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == TransferLeaseBeginOutcome::NewLease)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == TransferLeaseBeginOutcome::LimitReached)
                .count(),
            1
        );
        assert_eq!(database.active_transfer_reservations(share_id).unwrap(), 1);
    }

    #[test]
    fn transfer_heartbeat_and_expiry_are_enforced() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let share_id = database
            .create_share(
                "share",
                None,
                "file.bin",
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
        database
            .begin_transfer_lease("client", "lease", share_id, "file.bin", "download")
            .unwrap();
        assert_eq!(
            database.heartbeat_transfer_lease("lease").unwrap(),
            TransferLeaseHeartbeatOutcome::Extended
        );
        database
            .conn()
            .execute(
                "UPDATE public_transfer_leases SET expires_at='2000-01-01T00:00:00Z'",
                [],
            )
            .unwrap();
        assert_eq!(
            database.heartbeat_transfer_lease("lease").unwrap(),
            TransferLeaseHeartbeatOutcome::NotFound
        );
        assert_eq!(database.active_transfer_reservations(share_id).unwrap(), 0);
    }
}
