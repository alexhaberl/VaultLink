mod public_sessions;
mod runtime_settings;
mod schema;

use chrono::{DateTime, Duration, Utc};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
#[cfg(test)]
use schema::{migrate, SCHEMA_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io,
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

pub(crate) const MAX_SQLITE_UNSIGNED: u64 = i64::MAX as u64;
pub(crate) const MAX_AUDIT_ROWS: i64 = 100_000;

/// Existing and newly-created upload shares receive finite cumulative defaults.
/// Administrators can tighten or raise them explicitly through the share API/UI.
pub const DEFAULT_SHARE_UPLOAD_TOTAL_SIZE: u64 = 100_000_000_000;
pub const DEFAULT_SHARE_UPLOAD_FILE_COUNT: u64 = 1_000;
const UPLOAD_RESERVATION_TTL_SECONDS: i64 = 15 * 60;
const MAX_ACTIVE_PREVIEW_SESSIONS_PER_RESOURCE: i64 = 8;
const MAX_ACTIVE_PREVIEW_SESSIONS_PER_OWNER_SHARE: i64 = 64;
const MAX_ACTIVE_PREVIEW_SESSIONS_PER_SHARE: i64 = 512;
const MAX_ACTIVE_PREVIEW_SESSIONS_GLOBAL: i64 = 10_000;

pub const TRANSFER_SESSION_TTL_SECONDS: i64 = 15 * 60;
pub const TRANSFER_LEASE_MAX_LIFETIME_SECONDS: i64 = 24 * 60 * 60;
pub const ADMIN_MFA_ENROLLMENT_TTL_SECONDS: i64 = 10 * 60;

#[derive(Clone)]
pub struct Database(Arc<DatabaseInner>);

struct DatabaseInner {
    connection: Mutex<Connection>,
    // Keep the descriptor behind /proc/self/fd alive for the whole connection
    // so the validated directory capability cannot be rebound through file-
    // descriptor reuse while SQLite uses the supplied path.
    _directory_capability: Option<File>,
}

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminWebauthnCredential {
    pub id: i64,
    pub label: String,
    pub credential_id: String,
    pub credential_json: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordSessionCreationOutcome {
    Created,
    StalePassword,
    AdminInactive,
    AdminNotFound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminWebauthnCredentialRegistrationOutcome {
    Registered(i64),
    SessionUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminWebauthnCredentialDeletionOutcome {
    Deleted,
    ReauthenticationRejected,
    TotpRejected,
    NotDeleted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditClientIpDeletionOutcome {
    Deleted(usize),
    LoggingEnabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadReservationBeginOutcome {
    Reserved,
    ByteQuotaReached,
    FileQuotaReached,
    ShareUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadReservationExtendOutcome {
    Extended,
    ByteQuotaReached,
    NotFound,
    ShareUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadReservationCommitOutcome {
    Committed,
    NotFound,
    ShareUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreviewSessionCreateOutcome {
    Created,
    OwnerCapacityReached,
    ShareCapacityReached,
    GlobalCapacityReached,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareControlsUpdateOutcome {
    Updated,
    NotFound,
    QuotaConflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitialAdminOutcome {
    Created,
    AlreadyInitialized,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminRecoveryOutcome {
    Recovered {
        admin_id: i64,
        username: String,
        active: bool,
    },
    NotFound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminPasswordChangeOutcome {
    Changed,
    StalePassword,
    Inactive,
    NotFound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAdminMfaEnrollment {
    pub admin_id: i64,
    pub totp_secret: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminMfaEnrollmentStartOutcome {
    Started { expires_at: String },
    AdminInactive,
    AdminNotFound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminMfaEnrollmentActivationOutcome {
    Activated,
    NotFoundOrExpired,
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
    CappedAndCounted,
    CappedAlreadyCounted,
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
    pub max_upload_total_size: Option<u64>,
    pub max_upload_files: Option<u64>,
    pub uploaded_bytes: u64,
    pub uploaded_files: u64,
    pub download_count: u64,
    pub active: bool,
    pub password_hash: Option<String>,
    pub upload_conflict_strategy: UploadConflictStrategy,
    pub created_at: String,
    pub upload_policy_epoch: i64,
}

#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub occurred_at: String,
    pub actor: String,
    pub action: String,
    pub object_id: Option<String>,
    pub detail: Option<String>,
    pub client_ip: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferMonthlyCounts {
    pub month: String,
    pub download: u64,
    pub zip_download: u64,
    pub preview: u64,
}

impl TransferMonthlyCounts {
    pub fn total(&self) -> u64 {
        self.download
            .saturating_add(self.zip_download)
            .saturating_add(self.preview)
    }
}

fn token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    data_encoding::HEXLOWER.encode(digest.as_ref())
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        Self::open_inner(path.as_ref(), None)
    }

    #[doc(hidden)]
    pub fn open_in_directory(directory: File) -> rusqlite::Result<Self> {
        let metadata = directory.metadata().map_err(database_io_error)?;
        if !metadata.is_dir() {
            return Err(database_io_error(io::Error::new(
                io::ErrorKind::InvalidInput,
                "validated database directory capability is not a directory",
            )));
        }
        let effective_uid = rustix::process::geteuid().as_raw();
        if metadata.uid() != effective_uid || metadata.mode() & 0o022 != 0 {
            return Err(database_io_error(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "database directory capability must be service-owned and not writable by group or other users",
            )));
        }
        let path = PathBuf::from(format!(
            "/proc/self/fd/{}/data.sqlite",
            directory.as_raw_fd()
        ));
        Self::open_inner(&path, Some(directory))
    }

    fn open_inner(path: &Path, directory_capability: Option<File>) -> rusqlite::Result<Self> {
        let persistent = path != Path::new(":memory:");
        if persistent {
            match std::fs::symlink_metadata(path) {
                Ok(metadata) => validate_database_metadata(path, &metadata, false)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(database_io_error(error)),
            }
        }
        let mut conn = if persistent {
            // SQLite's NOFOLLOW mode rejects the intentional /proc/self/fd
            // magic-link used for a validated directory capability. Those
            // opens are already anchored to a service-owned directory FD and
            // receive the same pre/post final-file metadata checks below.
            let flags = if directory_capability.is_some() {
                OpenFlags::default()
            } else {
                OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW
            };
            Connection::open_with_flags(path, flags)?
        } else {
            Connection::open(path)?
        };
        if persistent {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(database_io_error)?;
            let metadata = std::fs::symlink_metadata(path).map_err(database_io_error)?;
            validate_database_metadata(path, &metadata, true)?;
        }
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        schema::migrate(&mut conn)?;
        Ok(Self(Arc::new(DatabaseInner {
            connection: Mutex::new(conn),
            _directory_capability: directory_capability,
        })))
    }
}

fn database_io_error(error: io::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

fn invalid_database_file(path: &Path, reason: &str) -> rusqlite::Error {
    database_io_error(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unsafe database file {}: {reason}", path.display()),
    ))
}

fn validate_database_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
    require_private_mode: bool,
) -> rusqlite::Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(invalid_database_file(
            path,
            "symbolic links are not allowed",
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(invalid_database_file(path, "path is not a regular file"));
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(invalid_database_file(
            path,
            "file is not owned by the effective service user",
        ));
    }
    if metadata.nlink() != 1 {
        return Err(invalid_database_file(path, "hard links are not allowed"));
    }
    if require_private_mode && metadata.mode() & 0o7777 != 0o600 {
        return Err(invalid_database_file(path, "file mode is not 0600"));
    }
    Ok(())
}

fn consume_admin_totp_step(
    transaction: &Transaction<'_>,
    admin_id: i64,
    step: u64,
) -> rusqlite::Result<bool> {
    if step > i64::MAX as u64 {
        return Ok(false);
    }
    let active = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM admins WHERE id=?1 AND active=1)",
        [admin_id],
        |row| row.get::<_, bool>(0),
    )?;
    if !active {
        return Ok(false);
    }
    Ok(transaction.execute(
        "INSERT INTO admin_totp_replay(admin_id,last_step) VALUES(?1,?2)
         ON CONFLICT(admin_id) DO UPDATE SET last_step=excluded.last_step
         WHERE excluded.last_step>admin_totp_replay.last_step",
        params![admin_id, step as i64],
    )? == 1)
}

fn transfer_deadlines() -> (String, String) {
    let now = Utc::now();
    let expires = now + Duration::seconds(TRANSFER_SESSION_TTL_SECONDS);
    (now.to_rfc3339(), expires.to_rfc3339())
}

fn current_utc_month() -> String {
    Utc::now().format("%Y-%m").to_string()
}

fn valid_utc_month(month: &str) -> bool {
    let bytes = month.as_bytes();
    if !(bytes.len() == 7
        && bytes[4] == b'-'
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..].iter().all(u8::is_ascii_digit))
    {
        return false;
    }
    let numeric_month = (bytes[5] - b'0') * 10 + (bytes[6] - b'0');
    (1..=12).contains(&numeric_month)
}

fn increment_transfer_monthly_count(
    transaction: &Transaction<'_>,
    month: &str,
    action: &str,
) -> rusqlite::Result<()> {
    if !matches!(action, "download" | "zip_download" | "preview") {
        return Ok(());
    }
    transaction.execute(
        "INSERT INTO transfer_monthly_counts(month,action,count) VALUES(?1,?2,1)
         ON CONFLICT(month,action) DO UPDATE SET count=count+1",
        params![month, action],
    )?;
    Ok(())
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

fn cleanup_admin_mfa_enrollments(
    transaction: &Transaction<'_>,
    now: &str,
) -> rusqlite::Result<usize> {
    transaction.execute(
        "DELETE FROM admin_mfa_enrollments WHERE expires_at<=?1",
        [now],
    )
}

fn enforce_audit_retention(connection: &Connection, maximum_rows: i64) -> rusqlite::Result<usize> {
    if maximum_rows < 1 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    connection.execute(
        "DELETE FROM audit
         WHERE id IN (
             SELECT id FROM audit
             ORDER BY id ASC
             LIMIT MAX((SELECT COUNT(*) FROM audit) - ?1, 0)
         )",
        [maximum_rows],
    )
}

fn insert_audit_event(
    transaction: &Transaction<'_>,
    actor: &str,
    action: &str,
    object_id: Option<&str>,
    detail: Option<&str>,
    client_ip: Option<&str>,
) -> rusqlite::Result<()> {
    // Runtime settings and audit events live in the same database so privacy
    // decisions can be enforced at commit time. A request that captured an IP
    // before logging was disabled must not be able to write it afterwards.
    let client_ip = if persisted_audit_client_ip_enabled(transaction, client_ip.is_some())? {
        client_ip
    } else {
        None
    };
    transaction.execute(
        "INSERT INTO audit(occurred_at,actor,action,object_id,detail,client_ip)
         VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            Utc::now().to_rfc3339(),
            actor,
            action,
            object_id,
            detail,
            client_ip
        ],
    )?;
    enforce_audit_retention(transaction, MAX_AUDIT_ROWS)?;
    Ok(())
}

fn persisted_audit_client_ip_enabled(
    transaction: &Transaction<'_>,
    fallback: bool,
) -> rusqlite::Result<bool> {
    let persisted = transaction
        .query_row(
            "SELECT value FROM runtime_settings WHERE key='audit_client_ip_enabled'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    Ok(match persisted.as_deref() {
        Some(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        ),
        None => fallback,
    })
}

fn available_upload_share_total_limit(
    transaction: &Transaction<'_>,
    share_id: i64,
    upload_policy_epoch: i64,
    now: &str,
) -> rusqlite::Result<Option<u64>> {
    Ok(transaction
        .query_row(
            "SELECT max_upload_total_size
             FROM shares
             WHERE id=?1
               AND upload_policy_epoch=?3
               AND active=1
               AND (expires_at IS NULL OR expires_at>?2)
               AND is_directory=1
               AND permission IN ('upload_only','download_upload')
               AND max_upload_files IS NOT NULL",
            params![share_id, now, upload_policy_epoch],
            |row| row.get::<_, Option<u64>>(0),
        )
        .optional()?
        .flatten())
}

fn revoke_admin_auth_state(transaction: &Transaction<'_>, admin_id: i64) -> rusqlite::Result<()> {
    transaction.execute("DELETE FROM sessions WHERE admin_id=?1", [admin_id])?;
    transaction.execute(
        "DELETE FROM admin_mfa_enrollments WHERE admin_id=?1",
        [admin_id],
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
        self.0.connection.lock().expect("database mutex poisoned")
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
                revoke_admin_auth_state(&transaction, id)?;
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
                    revoke_admin_auth_state(&transaction, id)?;
                    AdminDeactivationOutcome::Deactivated
                } else {
                    AdminDeactivationOutcome::LastActive
                }
            }
        };
        transaction.commit()?;
        Ok(outcome)
    }

    /// Applies a local operator recovery as one credential/session/audit transaction.
    /// Credential values are deliberately excluded from the persisted and tracing audit data.
    pub fn recover_admin(
        &self,
        username: &str,
        password_hash: Option<&str>,
        totp_secret: Option<&str>,
    ) -> rusqlite::Result<AdminRecoveryOutcome> {
        if password_hash.is_none() && totp_secret.is_none() {
            return Err(rusqlite::Error::InvalidParameterName(
                "password_hash or totp_secret".into(),
            ));
        }
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let admin = transaction
            .query_row(
                "SELECT id,username,active FROM admins WHERE username=?1",
                [username],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)? != 0,
                    ))
                },
            )
            .optional()?;
        let Some((admin_id, canonical_username, active)) = admin else {
            transaction.commit()?;
            return Ok(AdminRecoveryOutcome::NotFound);
        };
        transaction.execute(
            "UPDATE admins
             SET password_hash=COALESCE(?2,password_hash),
                 totp_secret=COALESCE(?3,totp_secret)
             WHERE id=?1",
            params![admin_id, password_hash, totp_secret],
        )?;
        if totp_secret.is_some() {
            transaction.execute(
                "DELETE FROM admin_webauthn_credentials WHERE admin_id=?1",
                [admin_id],
            )?;
            transaction.execute(
                "DELETE FROM admin_totp_replay WHERE admin_id=?1",
                [admin_id],
            )?;
        }
        revoke_admin_auth_state(&transaction, admin_id)?;
        let object_id = admin_id.to_string();
        let detail = format!(
            "reset_password={};reset_mfa={}",
            password_hash.is_some(),
            totp_secret.is_some()
        );
        insert_audit_event(
            &transaction,
            "local_recovery",
            "admin_recovered",
            Some(&object_id),
            Some(&detail),
            None,
        )?;
        transaction.commit()?;
        tracing::warn!(
            target: "vaultlink::audit",
            actor = "local_recovery",
            action = "admin_recovered",
            object_id = object_id,
            username = canonical_username,
            reset_password = password_hash.is_some(),
            reset_mfa = totp_secret.is_some(),
            "local administrator recovery completed"
        );
        Ok(AdminRecoveryOutcome::Recovered {
            admin_id,
            username: canonical_username,
            active,
        })
    }

    /// Changes an administrator password only if the hash verified by the caller is still current.
    pub fn change_admin_password_cas(
        &self,
        id: i64,
        expected_password_hash: &str,
        new_password_hash: &str,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<AdminPasswordChangeOutcome> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let admin = transaction
            .query_row(
                "SELECT username,password_hash,active FROM admins WHERE id=?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)? != 0,
                    ))
                },
            )
            .optional()?;
        let Some((username, current_password_hash, active)) = admin else {
            transaction.commit()?;
            return Ok(AdminPasswordChangeOutcome::NotFound);
        };
        if !active {
            transaction.commit()?;
            return Ok(AdminPasswordChangeOutcome::Inactive);
        }
        if current_password_hash != expected_password_hash {
            transaction.commit()?;
            return Ok(AdminPasswordChangeOutcome::StalePassword);
        }
        let changed = transaction.execute(
            "UPDATE admins SET password_hash=?3 WHERE id=?1 AND password_hash=?2",
            params![id, expected_password_hash, new_password_hash],
        )?;
        if changed != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        revoke_admin_auth_state(&transaction, id)?;
        let object_id = id.to_string();
        insert_audit_event(
            &transaction,
            &username,
            "account_password_changed",
            Some(&object_id),
            None,
            client_ip,
        )?;
        transaction.commit()?;
        tracing::info!(target: "vaultlink::audit", actor = username, action = "account_password_changed", object_id, "audit event");
        Ok(AdminPasswordChangeOutcome::Changed)
    }

    /// Starts or replaces one short-lived enrollment. Only a hash of `token` is persisted.
    pub fn start_admin_mfa_enrollment(
        &self,
        admin_id: i64,
        token: &str,
        totp_secret: &str,
    ) -> rusqlite::Result<AdminMfaEnrollmentStartOutcome> {
        let now = Utc::now();
        let now_string = now.to_rfc3339();
        let expires_at = (now + Duration::seconds(ADMIN_MFA_ENROLLMENT_TTL_SECONDS)).to_rfc3339();
        let enrollment_token_hash = token_hash(token);
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_admin_mfa_enrollments(&transaction, &now_string)?;
        let active = transaction
            .query_row("SELECT active FROM admins WHERE id=?1", [admin_id], |row| {
                row.get::<_, i64>(0).map(|active| active != 0)
            })
            .optional()?;
        match active {
            None => {
                transaction.commit()?;
                return Ok(AdminMfaEnrollmentStartOutcome::AdminNotFound);
            }
            Some(false) => {
                transaction.commit()?;
                return Ok(AdminMfaEnrollmentStartOutcome::AdminInactive);
            }
            Some(true) => {}
        }
        transaction.execute(
            "INSERT INTO admin_mfa_enrollments(
                 admin_id,token_hash,totp_secret,created_at,expires_at
             ) VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(admin_id) DO UPDATE SET
                 token_hash=excluded.token_hash,
                 totp_secret=excluded.totp_secret,
                 created_at=excluded.created_at,
                 expires_at=excluded.expires_at",
            params![
                admin_id,
                enrollment_token_hash,
                totp_secret,
                now_string,
                expires_at
            ],
        )?;
        transaction.commit()?;
        Ok(AdminMfaEnrollmentStartOutcome::Started { expires_at })
    }

    /// Returns a pending secret only to a caller presenting the raw enrollment token.
    pub fn admin_mfa_enrollment(
        &self,
        admin_id: i64,
        token: &str,
    ) -> rusqlite::Result<Option<PendingAdminMfaEnrollment>> {
        let now = Utc::now().to_rfc3339();
        let enrollment_token_hash = token_hash(token);
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_admin_mfa_enrollments(&transaction, &now)?;
        let enrollment = transaction
            .query_row(
                "SELECT admin_mfa_enrollments.admin_id,
                        admin_mfa_enrollments.totp_secret,
                        admin_mfa_enrollments.expires_at
                 FROM admin_mfa_enrollments
                 JOIN admins ON admins.id=admin_mfa_enrollments.admin_id
                 WHERE admin_mfa_enrollments.admin_id=?1
                   AND admin_mfa_enrollments.token_hash=?2
                   AND admin_mfa_enrollments.expires_at>?3
                   AND admins.active=1",
                params![admin_id, enrollment_token_hash, now],
                |row| {
                    Ok(PendingAdminMfaEnrollment {
                        admin_id: row.get(0)?,
                        totp_secret: row.get(1)?,
                        expires_at: row.get(2)?,
                    })
                },
            )
            .optional()?;
        transaction.commit()?;
        Ok(enrollment)
    }

    /// Activates and consumes an enrollment after the caller verified a code against its secret.
    /// The secret is never included in the audit event.
    pub fn activate_admin_mfa_enrollment(
        &self,
        admin_id: i64,
        token: &str,
        verified_totp_step: u64,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<AdminMfaEnrollmentActivationOutcome> {
        if verified_totp_step > i64::MAX as u64 {
            return Err(rusqlite::Error::InvalidParameterName(
                "verified_totp_step".into(),
            ));
        }
        let now = Utc::now().to_rfc3339();
        let enrollment_token_hash = token_hash(token);
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_admin_mfa_enrollments(&transaction, &now)?;
        let enrollment = transaction
            .query_row(
                "SELECT admins.username,admin_mfa_enrollments.totp_secret
                 FROM admin_mfa_enrollments
                 JOIN admins ON admins.id=admin_mfa_enrollments.admin_id
                 WHERE admin_mfa_enrollments.admin_id=?1
                   AND admin_mfa_enrollments.token_hash=?2
                   AND admin_mfa_enrollments.expires_at>?3
                   AND admins.active=1",
                params![admin_id, enrollment_token_hash, now],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((username, totp_secret)) = enrollment else {
            transaction.commit()?;
            return Ok(AdminMfaEnrollmentActivationOutcome::NotFoundOrExpired);
        };
        transaction.execute(
            "UPDATE admins SET totp_secret=?2 WHERE id=?1",
            params![admin_id, totp_secret],
        )?;
        transaction.execute(
            "INSERT INTO admin_totp_replay(admin_id,last_step) VALUES(?1,?2)
             ON CONFLICT(admin_id) DO UPDATE SET last_step=excluded.last_step",
            params![admin_id, verified_totp_step as i64],
        )?;
        revoke_admin_auth_state(&transaction, admin_id)?;
        let object_id = admin_id.to_string();
        insert_audit_event(
            &transaction,
            &username,
            "account_mfa_changed",
            Some(&object_id),
            None,
            client_ip,
        )?;
        transaction.commit()?;
        tracing::info!(target: "vaultlink::audit", actor = username, action = "account_mfa_changed", object_id, "audit event");
        Ok(AdminMfaEnrollmentActivationOutcome::Activated)
    }

    pub fn cleanup_expired_admin_mfa_enrollments(&self) -> rusqlite::Result<usize> {
        self.conn().execute(
            "DELETE FROM admin_mfa_enrollments WHERE expires_at<=?1",
            [Utc::now().to_rfc3339()],
        )
    }

    pub fn reset_admin_password(&self, id: i64, password_hash: &str) -> rusqlite::Result<bool> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE admins SET password_hash=?2 WHERE id=?1",
            params![id, password_hash],
        )? == 1;
        if changed {
            revoke_admin_auth_state(&transaction, id)?;
        }
        transaction.commit()?;
        Ok(changed)
    }
    pub fn reset_admin_totp(&self, id: i64, totp_secret: &str) -> rusqlite::Result<Option<String>> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
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
            transaction.execute(
                "DELETE FROM admin_webauthn_credentials WHERE admin_id=?1",
                [id],
            )?;
            transaction.execute("DELETE FROM admin_totp_replay WHERE admin_id=?1", [id])?;
            revoke_admin_auth_state(&transaction, id)?;
        }
        transaction.commit()?;
        Ok(username)
    }
    pub fn admin_webauthn_credentials(
        &self,
        admin_id: i64,
    ) -> rusqlite::Result<Vec<AdminWebauthnCredential>> {
        let connection = self.conn();
        let mut statement = connection.prepare(
            "SELECT id,label,credential_id,credential_json,created_at,last_used_at
             FROM admin_webauthn_credentials WHERE admin_id=?1 ORDER BY id",
        )?;
        let rows = statement
            .query_map([admin_id], |row| {
                Ok(AdminWebauthnCredential {
                    id: row.get(0)?,
                    label: row.get(1)?,
                    credential_id: row.get(2)?,
                    credential_json: row.get(3)?,
                    created_at: row.get(4)?,
                    last_used_at: row.get(5)?,
                })
            })?
            .collect();
        rows
    }

    #[cfg(test)]
    fn add_admin_webauthn_credential(
        &self,
        admin_id: i64,
        label: &str,
        credential_id: &str,
        credential_json: &str,
    ) -> rusqlite::Result<i64> {
        let connection = self.conn();
        connection.execute(
            "INSERT INTO admin_webauthn_credentials(
                 admin_id,label,credential_id,credential_json,created_at
             ) VALUES(?1,?2,?3,?4,?5)",
            params![
                admin_id,
                label,
                credential_id,
                credential_json,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(connection.last_insert_rowid())
    }

    /// Persists a completed WebAuthn registration only if the session that
    /// authorized the ceremony is still active, unexpired and MFA-verified.
    /// The session predicate, credential insert and audit event share one
    /// transaction so an MFA reset either removes the new key afterwards or
    /// makes a stale completion fail before it can restore a credential.
    #[allow(clippy::too_many_arguments)]
    pub fn add_admin_webauthn_credential_for_session(
        &self,
        session_token: &str,
        admin_id: i64,
        label: &str,
        credential_id: &str,
        credential_json: &str,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<AdminWebauthnCredentialRegistrationOutcome> {
        let now = Utc::now().to_rfc3339();
        let session_token_hash = token_hash(session_token);
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let username = transaction
            .query_row(
                "SELECT admins.username
                 FROM sessions
                 JOIN admins ON admins.id=sessions.admin_id
                 WHERE sessions.token_hash=?1
                   AND sessions.admin_id=?2
                   AND sessions.mfa_verified=1
                   AND sessions.expires_at>?3
                   AND admins.active=1",
                params![session_token_hash, admin_id, now],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(username) = username else {
            transaction.commit()?;
            return Ok(AdminWebauthnCredentialRegistrationOutcome::SessionUnavailable);
        };
        transaction.execute(
            "INSERT INTO admin_webauthn_credentials(
                 admin_id,label,credential_id,credential_json,created_at
             ) VALUES(?1,?2,?3,?4,?5)",
            params![admin_id, label, credential_id, credential_json, now],
        )?;
        let credential_row_id = transaction.last_insert_rowid();
        insert_audit_event(
            &transaction,
            &username,
            "webauthn_credential_added",
            None,
            None,
            client_ip,
        )?;
        transaction.commit()?;
        tracing::info!(target: "vaultlink::audit", actor = username, action = "webauthn_credential_added", "audit event");
        Ok(AdminWebauthnCredentialRegistrationOutcome::Registered(
            credential_row_id,
        ))
    }

    pub fn update_admin_webauthn_credential(
        &self,
        id: i64,
        admin_id: i64,
        credential_json: &str,
    ) -> rusqlite::Result<bool> {
        Ok(self.conn().execute(
            "UPDATE admin_webauthn_credentials
             SET credential_json=?3,last_used_at=?4
             WHERE id=?1 AND admin_id=?2",
            params![id, admin_id, credential_json, Utc::now().to_rfc3339()],
        )? == 1)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn complete_webauthn_mfa(
        &self,
        old_session_token: &str,
        new_session_token: &str,
        new_csrf_token: &str,
        credential_id: i64,
        admin_id: i64,
        expected_credential_json: &str,
        updated_credential_json: &str,
    ) -> rusqlite::Result<bool> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let credential_updated = transaction.execute(
            "UPDATE admin_webauthn_credentials
             SET credential_json=?5,last_used_at=?6
             WHERE id=?1 AND admin_id=?2 AND credential_json=?3
               AND EXISTS(
                   SELECT 1 FROM sessions
                   WHERE token_hash=?4 AND admin_id=?2 AND mfa_verified=0 AND expires_at>?6
               )",
            params![
                credential_id,
                admin_id,
                expected_credential_json,
                token_hash(old_session_token),
                updated_credential_json,
                Utc::now().to_rfc3339()
            ],
        )? == 1;
        if !credential_updated {
            transaction.rollback()?;
            return Ok(false);
        }
        let session_updated = transaction.execute(
            "UPDATE sessions
             SET token_hash=?4,csrf_token=?5,mfa_verified=1
             WHERE token_hash=?1 AND admin_id=?2 AND mfa_verified=0 AND expires_at>?3",
            params![
                token_hash(old_session_token),
                admin_id,
                Utc::now().to_rfc3339(),
                token_hash(new_session_token),
                new_csrf_token,
            ],
        )? == 1;
        if !session_updated {
            transaction.rollback()?;
            return Ok(false);
        }
        transaction.commit()?;
        Ok(true)
    }

    pub fn webauthn_credential_count(&self) -> rusqlite::Result<u64> {
        self.conn().query_row(
            "SELECT COUNT(*) FROM admin_webauthn_credentials",
            [],
            |row| row.get(0),
        )
    }

    pub fn delete_admin_webauthn_credential(
        &self,
        id: i64,
        admin_id: i64,
    ) -> rusqlite::Result<bool> {
        Ok(self.conn().execute(
            "DELETE FROM admin_webauthn_credentials
             WHERE id=?1 AND admin_id=?2
               AND (SELECT COUNT(*) FROM admin_webauthn_credentials WHERE admin_id=?2) <> 2",
            params![id, admin_id],
        )? == 1)
    }

    /// Re-checks the exact live MFA session and credential snapshot, consumes
    /// the reauthentication TOTP step, applies the credential deletion policy
    /// and records the success audit as one serialized transaction. This closes
    /// both cancellation gaps and credential/session reset races.
    #[allow(clippy::too_many_arguments)]
    pub fn delete_admin_webauthn_credential_with_totp(
        &self,
        session_token: &str,
        id: i64,
        admin_id: i64,
        expected_password_hash: &str,
        expected_totp_secret: &str,
        totp_step: u64,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<AdminWebauthnCredentialDeletionOutcome> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let username = transaction
            .query_row(
                "SELECT admins.username
                 FROM sessions
                 JOIN admins ON admins.id=sessions.admin_id
                 WHERE sessions.token_hash=?1
                   AND sessions.admin_id=?2
                   AND sessions.mfa_verified=1
                   AND sessions.expires_at>?3
                   AND admins.active=1
                   AND admins.password_hash=?4
                   AND admins.totp_secret=?5",
                params![
                    token_hash(session_token),
                    admin_id,
                    Utc::now().to_rfc3339(),
                    expected_password_hash,
                    expected_totp_secret,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(username) = username else {
            transaction.rollback()?;
            return Ok(AdminWebauthnCredentialDeletionOutcome::ReauthenticationRejected);
        };
        if !consume_admin_totp_step(&transaction, admin_id, totp_step)? {
            transaction.commit()?;
            return Ok(AdminWebauthnCredentialDeletionOutcome::TotpRejected);
        }
        let deleted = transaction.execute(
            "DELETE FROM admin_webauthn_credentials
             WHERE id=?1 AND admin_id=?2
               AND (SELECT COUNT(*) FROM admin_webauthn_credentials WHERE admin_id=?2) <> 2",
            params![id, admin_id],
        )? == 1;
        if !deleted {
            transaction.rollback()?;
            return Ok(AdminWebauthnCredentialDeletionOutcome::NotDeleted);
        }
        let object_id = id.to_string();
        insert_audit_event(
            &transaction,
            &username,
            "webauthn_credential_deleted",
            Some(&object_id),
            None,
            client_ip,
        )?;
        transaction.commit()?;
        tracing::info!(target: "vaultlink::audit", actor = username, action = "webauthn_credential_deleted", object_id, "audit event");
        Ok(AdminWebauthnCredentialDeletionOutcome::Deleted)
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

    /// Creates a pre-MFA session only while the password hash verified by the caller is current.
    /// The active/hash predicate and insertion intentionally share one SQL statement.
    pub fn create_session_for_verified_password(
        &self,
        token: &str,
        admin_id: i64,
        expected_password_hash: &str,
        csrf: &str,
        expires: DateTime<Utc>,
    ) -> rusqlite::Result<PasswordSessionCreationOutcome> {
        let now = Utc::now().to_rfc3339();
        let session_token_hash = token_hash(token);
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute("DELETE FROM sessions WHERE expires_at < ?1", [&now])?;
        let created = transaction.execute(
            "INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at)
             SELECT ?1,admins.id,?4,?5
             FROM admins
             WHERE admins.id=?2 AND admins.password_hash=?3 AND admins.active=1",
            params![
                session_token_hash,
                admin_id,
                expected_password_hash,
                csrf,
                expires.to_rfc3339()
            ],
        )?;
        let outcome = if created == 1 {
            PasswordSessionCreationOutcome::Created
        } else {
            let admin = transaction
                .query_row(
                    "SELECT password_hash,active FROM admins WHERE id=?1",
                    [admin_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? != 0)),
                )
                .optional()?;
            match admin {
                None => PasswordSessionCreationOutcome::AdminNotFound,
                Some((_, false)) => PasswordSessionCreationOutcome::AdminInactive,
                Some((password_hash, true)) if password_hash != expected_password_hash => {
                    PasswordSessionCreationOutcome::StalePassword
                }
                Some(_) => return Err(rusqlite::Error::InvalidQuery),
            }
        };
        transaction.commit()?;
        Ok(outcome)
    }

    pub fn session(&self, token: &str) -> rusqlite::Result<Option<Session>> {
        self.conn().query_row("SELECT a.id,a.username,s.csrf_token,s.mfa_verified FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=?1 AND s.expires_at>?2 AND a.active=1",params![token_hash(token),Utc::now().to_rfc3339()],|r|Ok(Session{admin_id:r.get(0)?,username:r.get(1)?,csrf_token:r.get(2)?,mfa_verified:r.get::<_,i64>(3)?!=0})).optional()
    }
    /// Consumes a TOTP counter and verifies exactly the bound, unexpired session.
    /// Both writes share an IMMEDIATE transaction so one code cannot unlock two sessions.
    pub fn verify_mfa_with_totp_step(
        &self,
        old_token: &str,
        new_token: &str,
        new_csrf_token: &str,
        admin_id: i64,
        step: u64,
    ) -> rusqlite::Result<bool> {
        let now = Utc::now().to_rfc3339();
        let session_token_hash = token_hash(old_token);
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let valid_session = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sessions
                 JOIN admins ON admins.id=sessions.admin_id
                 WHERE sessions.token_hash=?1 AND sessions.admin_id=?2
                   AND sessions.expires_at>?3 AND sessions.mfa_verified=0
                   AND admins.active=1
             )",
            params![session_token_hash, admin_id, now],
            |row| row.get::<_, bool>(0),
        )?;
        if !valid_session || !consume_admin_totp_step(&transaction, admin_id, step)? {
            transaction.commit()?;
            return Ok(false);
        }
        let changed = transaction.execute(
            "UPDATE sessions
             SET token_hash=?4,csrf_token=?5,mfa_verified=1
             WHERE token_hash=?1 AND admin_id=?2 AND expires_at>?3 AND mfa_verified=0",
            params![
                session_token_hash,
                admin_id,
                now,
                token_hash(new_token),
                new_csrf_token,
            ],
        )?;
        if changed != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        transaction.commit()?;
        Ok(true)
    }

    /// Consumes one TOTP counter for a sensitive authenticated operation.
    pub fn consume_admin_totp_step(&self, admin_id: i64, step: u64) -> rusqlite::Result<bool> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let consumed = consume_admin_totp_step(&transaction, admin_id, step)?;
        transaction.commit()?;
        Ok(consumed)
    }

    #[cfg(test)]
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
        let (upload_total, upload_files) = if is_dir && permission.can_upload() {
            (
                Some(DEFAULT_SHARE_UPLOAD_TOTAL_SIZE.max(upload_max.unwrap_or_default())),
                Some(DEFAULT_SHARE_UPLOAD_FILE_COUNT),
            )
        } else {
            (None, None)
        };
        self.create_share_with_upload_limits(
            token,
            alias,
            path,
            is_dir,
            permission,
            expires,
            max,
            upload_max,
            upload_total,
            upload_files,
            admin,
            password_hash,
            upload_conflict_strategy,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_share_with_upload_limits(
        &self,
        token: &str,
        alias: Option<&str>,
        path: &str,
        is_dir: bool,
        permission: &Permission,
        expires: Option<DateTime<Utc>>,
        max: Option<u64>,
        upload_max: Option<u64>,
        upload_total: Option<u64>,
        upload_files: Option<u64>,
        admin: i64,
        password_hash: Option<&str>,
        upload_conflict_strategy: &UploadConflictStrategy,
    ) -> rusqlite::Result<i64> {
        let expects_upload_limits = is_dir && permission.can_upload();
        if expects_upload_limits != (upload_total.is_some() && upload_files.is_some())
            || upload_total.is_some_and(|value| value == 0 || value > MAX_SQLITE_UNSIGNED)
            || upload_files.is_some_and(|value| value == 0 || value > MAX_SQLITE_UNSIGNED)
            || upload_total
                .zip(upload_max)
                .is_some_and(|(total, single)| total < single)
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let c = self.conn();
        c.execute(
            "INSERT INTO shares(
                 token_hash,token,alias,relative_path,is_directory,permission,expires_at,
                 max_downloads,max_upload_size,created_by,created_at,password_hash,
                 upload_conflict_strategy,max_upload_total_size,max_upload_files
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![
                token_hash(token),
                token,
                alias,
                path,
                is_dir as i64,
                permission.as_str(),
                expires.map(|value| value.to_rfc3339()),
                max,
                upload_max,
                admin,
                Utc::now().to_rfc3339(),
                password_hash,
                upload_conflict_strategy.as_str(),
                upload_total,
                upload_files,
            ],
        )?;
        Ok(c.last_insert_rowid())
    }
    fn map_share(r: &rusqlite::Row<'_>) -> rusqlite::Result<Share> {
        let exp: Option<String> = r.get(6)?;
        let expires_at = exp
            .map(|value| {
                DateTime::parse_from_rfc3339(&value)
                    .map(|parsed| parsed.with_timezone(&Utc))
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            6,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })
            })
            .transpose()?;
        Ok(Share {
            id: r.get(0)?,
            token: r.get(1)?,
            alias: r.get(2)?,
            relative_path: r.get(3)?,
            is_directory: r.get::<_, i64>(4)? != 0,
            permission: Permission::parse(&r.get::<_, String>(5)?)
                .ok_or(rusqlite::Error::InvalidQuery)?,
            expires_at,
            max_downloads: r.get(7)?,
            max_upload_size: r.get(8)?,
            max_upload_total_size: r.get(9)?,
            max_upload_files: r.get(10)?,
            uploaded_bytes: r.get(11)?,
            uploaded_files: r.get(12)?,
            download_count: r.get(13)?,
            active: r.get::<_, i64>(14)? != 0,
            password_hash: r.get(15)?,
            upload_conflict_strategy: UploadConflictStrategy::parse(&r.get::<_, String>(16)?)
                .ok_or(rusqlite::Error::InvalidQuery)?,
            created_at: r.get(17)?,
            upload_policy_epoch: r.get(18)?,
        })
    }
    pub fn share_by_token(&self, token: &str) -> rusqlite::Result<Option<Share>> {
        self.conn().query_row("SELECT id,token,alias,relative_path,is_directory,permission,expires_at,max_downloads,max_upload_size,max_upload_total_size,max_upload_files,COALESCE(usage.uploaded_bytes,0),COALESCE(usage.uploaded_files,0),download_count,active,password_hash,upload_conflict_strategy,created_at,upload_policy_epoch FROM shares LEFT JOIN public_upload_usage usage ON usage.share_id=shares.id WHERE token_hash=?1",[token_hash(token)],Self::map_share).optional()
    }
    pub fn share_by_alias(&self, alias: &str) -> rusqlite::Result<Option<Share>> {
        self.conn().query_row("SELECT id,token,alias,relative_path,is_directory,permission,expires_at,max_downloads,max_upload_size,max_upload_total_size,max_upload_files,COALESCE(usage.uploaded_bytes,0),COALESCE(usage.uploaded_files,0),download_count,active,password_hash,upload_conflict_strategy,created_at,upload_policy_epoch FROM shares LEFT JOIN public_upload_usage usage ON usage.share_id=shares.id WHERE alias=?1",[alias],Self::map_share).optional()
    }
    pub fn list_shares(&self) -> rusqlite::Result<Vec<Share>> {
        let c = self.conn();
        let mut s=c.prepare("SELECT id,token,alias,relative_path,is_directory,permission,expires_at,max_downloads,max_upload_size,max_upload_total_size,max_upload_files,COALESCE(usage.uploaded_bytes,0),COALESCE(usage.uploaded_files,0),download_count,active,password_hash,upload_conflict_strategy,created_at,upload_policy_epoch FROM shares LEFT JOIN public_upload_usage usage ON usage.share_id=shares.id ORDER BY shares.id DESC")?;
        let shares = s
            .query_map([], Self::map_share)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(shares)
    }
    pub fn count_active_shares_for_path(
        &self,
        path: &str,
        is_directory: bool,
    ) -> rusqlite::Result<usize> {
        let connection = self.conn();
        let mut statement =
            connection.prepare("SELECT relative_path FROM shares WHERE active=1")?;
        let mut count = 0usize;
        for relative_path in statement.query_map([], |row| row.get::<_, String>(0))? {
            if share_path_matches(&relative_path?, path, is_directory) {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }
    pub fn rename_share_paths(
        &self,
        old_path: &str,
        new_path: &str,
        is_directory: bool,
    ) -> rusqlite::Result<usize> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updates = {
            let mut statement = transaction.prepare("SELECT id,relative_path FROM shares")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            let mut updates = Vec::new();
            for row in rows {
                let (id, path) = row?;
                if let Some(rewritten) = rewrite_share_path(&path, old_path, new_path, is_directory)
                {
                    updates.push((id, rewritten));
                }
            }
            updates
        };
        for (id, path) in &updates {
            transaction.execute(
                "UPDATE shares
                 SET relative_path=?2,upload_policy_epoch=upload_policy_epoch+1
                 WHERE id=?1",
                params![id, path],
            )?;
        }
        transaction.commit()?;
        Ok(updates.len())
    }
    pub fn deactivate_shares_for_path(
        &self,
        path: &str,
        is_directory: bool,
    ) -> rusqlite::Result<usize> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let ids = {
            let mut statement =
                transaction.prepare("SELECT id,relative_path FROM shares WHERE active=1")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            let mut ids = Vec::new();
            for row in rows {
                let (id, relative_path) = row?;
                if share_path_matches(&relative_path, path, is_directory) {
                    ids.push(id);
                }
            }
            ids
        };
        for id in &ids {
            transaction.execute(
                "UPDATE shares
                 SET active=0,upload_policy_epoch=upload_policy_epoch+1
                 WHERE id=?1",
                [id],
            )?;
        }
        transaction.commit()?;
        Ok(ids.len())
    }
    pub fn set_share_active(&self, id: i64, active: bool) -> rusqlite::Result<bool> {
        Ok(self.conn().execute(
            "UPDATE shares
             SET upload_policy_epoch=upload_policy_epoch+
                     CASE WHEN active<>?2 THEN 1 ELSE 0 END,
                 active=?2
             WHERE id=?1",
            params![id, active as i64],
        )? == 1)
    }
    pub fn update_share_controls(
        &self,
        id: i64,
        active: Option<bool>,
        strategy: Option<&UploadConflictStrategy>,
        upload_limits: Option<(u64, u64)>,
    ) -> rusqlite::Result<ShareControlsUpdateOutcome> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = Utc::now().to_rfc3339();
        transaction.execute(
            "DELETE FROM public_upload_reservations WHERE expires_at<=?1",
            [&now],
        )?;
        let share = transaction
            .query_row(
                "SELECT is_directory,permission,
                        COALESCE((SELECT uploaded_bytes FROM public_upload_usage WHERE share_id=?1),0),
                        COALESCE((SELECT uploaded_files FROM public_upload_usage WHERE share_id=?1),0),
                        COALESCE((
                            SELECT SUM(reservations.reserved_bytes)
                            FROM public_upload_reservations reservations
                            WHERE reservations.share_id=?1
                              AND reservations.upload_policy_epoch=shares.upload_policy_epoch
                        ),0),
                        (
                            SELECT COUNT(*) FROM public_upload_reservations reservations
                            WHERE reservations.share_id=?1
                              AND reservations.upload_policy_epoch=shares.upload_policy_epoch
                        )
                 FROM shares WHERE id=?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, bool>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, u64>(4)?,
                        row.get::<_, u64>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            is_directory,
            permission,
            uploaded_bytes,
            uploaded_files,
            reserved_bytes,
            reserved_files,
        )) = share
        else {
            transaction.commit()?;
            return Ok(ShareControlsUpdateOutcome::NotFound);
        };
        if let Some((total, files)) = upload_limits {
            let committed_and_reserved_bytes = uploaded_bytes.checked_add(reserved_bytes);
            let committed_and_reserved_files = uploaded_files.checked_add(reserved_files);
            if total == 0
                || files == 0
                || total > MAX_SQLITE_UNSIGNED
                || files > MAX_SQLITE_UNSIGNED
                || !is_directory
                || !Permission::parse(&permission).is_some_and(|value| value.can_upload())
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            if committed_and_reserved_bytes.is_none_or(|used| total < used)
                || committed_and_reserved_files.is_none_or(|used| files < used)
            {
                transaction.commit()?;
                return Ok(ShareControlsUpdateOutcome::QuotaConflict);
            }
        }
        transaction.execute(
            "UPDATE shares SET
                 upload_policy_epoch=upload_policy_epoch+CASE WHEN
                     (?2 IS NOT NULL AND active IS NOT ?2)
                     OR (?3 IS NOT NULL AND upload_conflict_strategy IS NOT ?3)
                     OR (?4 IS NOT NULL AND max_upload_total_size IS NOT ?4)
                     OR (?5 IS NOT NULL AND max_upload_files IS NOT ?5)
                 THEN 1 ELSE 0 END,
                 active=COALESCE(?2,active),
                 upload_conflict_strategy=COALESCE(?3,upload_conflict_strategy),
                 max_upload_total_size=COALESCE(?4,max_upload_total_size),
                 max_upload_files=COALESCE(?5,max_upload_files)
             WHERE id=?1",
            params![
                id,
                active.map(i64::from),
                strategy.map(UploadConflictStrategy::as_str),
                upload_limits.map(|value| value.0),
                upload_limits.map(|value| value.1),
            ],
        )?;
        transaction.commit()?;
        Ok(ShareControlsUpdateOutcome::Updated)
    }

    pub fn begin_upload_reservation(
        &self,
        token: &str,
        share_id: i64,
    ) -> rusqlite::Result<UploadReservationBeginOutcome> {
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let expires = (now + Duration::seconds(UPLOAD_RESERVATION_TTL_SECONDS)).to_rfc3339();
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM public_upload_reservations WHERE expires_at<=?1",
            [&now_text],
        )?;
        let limits = transaction
            .query_row(
                "SELECT max_upload_total_size,max_upload_files,
                        active,(expires_at IS NULL OR expires_at>?2),
                        is_directory,permission,upload_policy_epoch
                 FROM shares WHERE id=?1",
                params![share_id, now_text],
                |row| {
                    Ok((
                        row.get::<_, Option<u64>>(0)?,
                        row.get::<_, Option<u64>>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, bool>(3)?,
                        row.get::<_, bool>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            Some(total_limit),
            Some(file_limit),
            active,
            unexpired,
            is_directory,
            permission,
            upload_policy_epoch,
        )) = limits
        else {
            transaction.commit()?;
            return Ok(UploadReservationBeginOutcome::ShareUnavailable);
        };
        if !active
            || !unexpired
            || !is_directory
            || !Permission::parse(&permission).is_some_and(|value| value.can_upload())
        {
            transaction.commit()?;
            return Ok(UploadReservationBeginOutcome::ShareUnavailable);
        }
        let (uploaded_bytes, uploaded_files): (u64, u64) = transaction.query_row(
            "SELECT COALESCE(uploaded_bytes,0),COALESCE(uploaded_files,0)
             FROM (SELECT 1) LEFT JOIN public_upload_usage ON share_id=?1",
            [share_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let active_reservations: u64 = transaction.query_row(
            "SELECT COUNT(*) FROM public_upload_reservations
             WHERE share_id=?1 AND upload_policy_epoch=?2",
            params![share_id, upload_policy_epoch],
            |row| row.get(0),
        )?;
        if uploaded_bytes >= total_limit {
            transaction.commit()?;
            return Ok(UploadReservationBeginOutcome::ByteQuotaReached);
        }
        if uploaded_files.saturating_add(active_reservations) >= file_limit {
            transaction.commit()?;
            return Ok(UploadReservationBeginOutcome::FileQuotaReached);
        }
        transaction.execute(
            "INSERT INTO public_upload_reservations(
                 token_hash,share_id,reserved_bytes,created_at,expires_at,upload_policy_epoch
             ) VALUES(?1,?2,0,?3,?4,?5)",
            params![
                token_hash(token),
                share_id,
                now_text,
                expires,
                upload_policy_epoch
            ],
        )?;
        transaction.commit()?;
        Ok(UploadReservationBeginOutcome::Reserved)
    }

    pub fn extend_upload_reservation(
        &self,
        token: &str,
        reserved_bytes: u64,
    ) -> rusqlite::Result<UploadReservationExtendOutcome> {
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let expires = (now + Duration::seconds(UPLOAD_RESERVATION_TTL_SECONDS)).to_rfc3339();
        let reservation_hash = token_hash(token);
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM public_upload_reservations WHERE expires_at<=?1",
            [&now_text],
        )?;
        let reservation = transaction
            .query_row(
                "SELECT share_id,reserved_bytes,upload_policy_epoch
                 FROM public_upload_reservations WHERE token_hash=?1",
                [&reservation_hash],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((share_id, current_bytes, upload_policy_epoch)) = reservation else {
            transaction.commit()?;
            return Ok(UploadReservationExtendOutcome::NotFound);
        };
        let Some(total_limit) = available_upload_share_total_limit(
            &transaction,
            share_id,
            upload_policy_epoch,
            &now_text,
        )?
        else {
            transaction.execute(
                "DELETE FROM public_upload_reservations WHERE token_hash=?1",
                [&reservation_hash],
            )?;
            transaction.commit()?;
            return Ok(UploadReservationExtendOutcome::ShareUnavailable);
        };
        if reserved_bytes < current_bytes {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if reserved_bytes > MAX_SQLITE_UNSIGNED {
            transaction.commit()?;
            return Ok(UploadReservationExtendOutcome::ByteQuotaReached);
        }
        let uploaded: u64 = transaction.query_row(
            "SELECT COALESCE((SELECT uploaded_bytes FROM public_upload_usage WHERE share_id=?1),0)",
            [share_id],
            |row| row.get(0),
        )?;
        let other_reserved: u64 = transaction.query_row(
            "SELECT COALESCE(SUM(reserved_bytes),0)
             FROM public_upload_reservations
             WHERE share_id=?1 AND token_hash<>?2 AND upload_policy_epoch=?3",
            params![share_id, reservation_hash, upload_policy_epoch],
            |row| row.get(0),
        )?;
        if uploaded
            .checked_add(other_reserved)
            .and_then(|value| value.checked_add(reserved_bytes))
            .is_none_or(|value| value > total_limit)
        {
            transaction.commit()?;
            return Ok(UploadReservationExtendOutcome::ByteQuotaReached);
        }
        transaction.execute(
            "UPDATE public_upload_reservations
             SET reserved_bytes=?2,expires_at=?3 WHERE token_hash=?1",
            params![reservation_hash, reserved_bytes, expires],
        )?;
        transaction.commit()?;
        Ok(UploadReservationExtendOutcome::Extended)
    }

    pub fn commit_upload_reservation(
        &self,
        token: &str,
        uploaded_bytes: u64,
    ) -> rusqlite::Result<UploadReservationCommitOutcome> {
        let reservation_hash = token_hash(token);
        let now_text = Utc::now().to_rfc3339();
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM public_upload_reservations WHERE expires_at<=?1",
            [&now_text],
        )?;
        let reservation = transaction
            .query_row(
                "SELECT share_id,reserved_bytes,upload_policy_epoch
                 FROM public_upload_reservations
                 WHERE token_hash=?1",
                [&reservation_hash],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((share_id, reserved_bytes, upload_policy_epoch)) = reservation else {
            transaction.commit()?;
            return Ok(UploadReservationCommitOutcome::NotFound);
        };
        if available_upload_share_total_limit(
            &transaction,
            share_id,
            upload_policy_epoch,
            &now_text,
        )?
        .is_none()
        {
            transaction.execute(
                "DELETE FROM public_upload_reservations WHERE token_hash=?1",
                [&reservation_hash],
            )?;
            transaction.commit()?;
            return Ok(UploadReservationCommitOutcome::ShareUnavailable);
        }
        if uploaded_bytes > MAX_SQLITE_UNSIGNED {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if uploaded_bytes > reserved_bytes {
            return Err(rusqlite::Error::InvalidQuery);
        }
        transaction.execute(
            "INSERT INTO public_upload_usage(share_id,uploaded_bytes,uploaded_files)
             VALUES(?1,?2,1)
             ON CONFLICT(share_id) DO UPDATE SET
                 uploaded_bytes=uploaded_bytes+excluded.uploaded_bytes,
                 uploaded_files=uploaded_files+1",
            params![share_id, uploaded_bytes],
        )?;
        transaction.execute(
            "DELETE FROM public_upload_reservations WHERE token_hash=?1",
            [reservation_hash],
        )?;
        transaction.commit()?;
        Ok(UploadReservationCommitOutcome::Committed)
    }

    pub fn cancel_upload_reservation(&self, token: &str) -> rusqlite::Result<bool> {
        Ok(self.conn().execute(
            "DELETE FROM public_upload_reservations WHERE token_hash=?1",
            [token_hash(token)],
        )? == 1)
    }

    #[cfg(test)]
    pub fn active_upload_reservations(&self, share_id: i64) -> rusqlite::Result<u64> {
        self.conn().query_row(
            "SELECT COUNT(*)
             FROM public_upload_reservations reservations
             JOIN shares ON shares.id=reservations.share_id
             WHERE reservations.share_id=?1 AND reservations.expires_at>?2
               AND reservations.upload_policy_epoch=shares.upload_policy_epoch",
            params![share_id, Utc::now().to_rfc3339()],
            |row| row.get(0),
        )
    }
    pub fn delete_share(&self, id: i64) -> rusqlite::Result<bool> {
        Ok(self
            .conn()
            .execute("DELETE FROM shares WHERE id=?1", [id])?
            == 1)
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
                "SELECT grants.id,grants.share_id,grants.counted,grants.action
                 FROM public_transfer_leases leases
                 JOIN public_transfer_grants grants ON grants.id=leases.grant_id
                 WHERE leases.token_hash=?1 AND leases.expires_at>?2 AND grants.expires_at>?2",
                params![lease_token_hash, now],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)? != 0,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((grant_id, share_id, already_counted, action)) = lease else {
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
            let month = now.get(..7).ok_or(rusqlite::Error::InvalidQuery)?;
            increment_transfer_monthly_count(&transaction, month, &action)?;
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
        let now_datetime = Utc::now();
        let now = now_datetime.to_rfc3339();
        let rolling_expiry = now_datetime + Duration::seconds(TRANSFER_SESSION_TTL_SECONDS);
        let lease_token_hash = token_hash(lease_token);
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let grant = transaction
            .query_row(
                "SELECT leases.grant_id,grants.share_id,grants.counted,grants.action,
                        leases.created_at,leases.expires_at
                 FROM public_transfer_leases leases
                 JOIN public_transfer_grants grants ON grants.id=leases.grant_id
                 WHERE leases.token_hash=?1",
                [lease_token_hash.as_str()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)? != 0,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((grant_id, share_id, counted, action, created_at, lease_expires_at)) = grant
        else {
            cleanup_transfer_state(&transaction, &now)?;
            transaction.commit()?;
            return Ok(TransferLeaseHeartbeatOutcome::NotFound);
        };
        let created_at = DateTime::parse_from_rfc3339(&created_at)
            .map(|value| value.with_timezone(&Utc))
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    4,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
        let lease_expires_at = DateTime::parse_from_rfc3339(&lease_expires_at)
            .map(|value| value.with_timezone(&Utc))
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
        let absolute_expiry = created_at + Duration::seconds(TRANSFER_LEASE_MAX_LIFETIME_SECONDS);
        if absolute_expiry <= now_datetime {
            let outcome = if counted {
                TransferLeaseHeartbeatOutcome::CappedAlreadyCounted
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
                    params![grant_id, rolling_expiry.to_rfc3339()],
                )? != 1
                {
                    return Err(rusqlite::Error::QueryReturnedNoRows);
                }
                let month = now.get(..7).ok_or(rusqlite::Error::InvalidQuery)?;
                increment_transfer_monthly_count(&transaction, month, &action)?;
                TransferLeaseHeartbeatOutcome::CappedAndCounted
            };
            transaction.execute(
                "DELETE FROM public_transfer_leases WHERE token_hash=?1",
                [lease_token_hash],
            )?;
            cleanup_transfer_state(&transaction, &now)?;
            transaction.commit()?;
            return Ok(outcome);
        }
        if lease_expires_at <= now_datetime {
            cleanup_transfer_state(&transaction, &now)?;
            transaction.commit()?;
            return Ok(TransferLeaseHeartbeatOutcome::NotFound);
        }
        cleanup_transfer_state(&transaction, &now)?;
        let expires = std::cmp::min(rolling_expiry, absolute_expiry).to_rfc3339();
        transaction.execute(
            "UPDATE public_transfer_leases
             SET heartbeat_at=?2,expires_at=?3 WHERE token_hash=?1",
            params![lease_token_hash, now, expires],
        )?;
        if !counted {
            transaction.execute(
                "UPDATE public_transfer_grants
                 SET expires_at=(
                     SELECT MAX(expires_at) FROM public_transfer_leases WHERE grant_id=?1
                 )
                 WHERE id=?1",
                [grant_id],
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
            "UPDATE shares
             SET upload_policy_epoch=upload_policy_epoch+1,
                 password_hash=?2
             WHERE id=?1",
            params![id, hash],
        )? == 1;
        transaction.execute("DELETE FROM public_unlock_sessions WHERE share_id=?1", [id])?;
        transaction.commit()?;
        Ok(changed)
    }
    pub fn audit(
        &self,
        actor: &str,
        action: &str,
        object: Option<&str>,
        detail: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.audit_with_client_ip(actor, action, object, detail, None)
    }
    pub fn audit_with_client_ip(
        &self,
        actor: &str,
        action: &str,
        object: Option<&str>,
        detail: Option<&str>,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<()> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_audit_event(&transaction, actor, action, object, detail, client_ip)?;
        transaction.commit()?;
        drop(connection);
        // Client IP retention is SQLite-only. Never mirror it into tracing/journald.
        tracing::info!(target: "vaultlink::audit", actor, action, object_id = object.unwrap_or(""), detail = detail.unwrap_or(""), "audit event");
        Ok(())
    }
    pub fn count_audit_client_ips(&self) -> rusqlite::Result<u64> {
        self.conn().query_row(
            "SELECT COUNT(*) FROM audit WHERE client_ip IS NOT NULL",
            [],
            |row| row.get(0),
        )
    }
    pub fn delete_audit_client_ips_if_disabled(
        &self,
        fallback_logging_enabled: bool,
    ) -> rusqlite::Result<AuditClientIpDeletionOutcome> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if persisted_audit_client_ip_enabled(&transaction, fallback_logging_enabled)? {
            return Ok(AuditClientIpDeletionOutcome::LoggingEnabled);
        }
        let deleted = transaction.execute(
            "UPDATE audit SET client_ip=NULL WHERE client_ip IS NOT NULL",
            [],
        )?;
        transaction.commit()?;
        Ok(AuditClientIpDeletionOutcome::Deleted(deleted))
    }
    pub fn transfer_statistics_started_at(&self) -> rusqlite::Result<String> {
        self.conn().query_row(
            "SELECT started_at FROM transfer_statistics WHERE singleton=1",
            [],
            |row| row.get(0),
        )
    }
    pub fn transfer_monthly_counts(&self, month: &str) -> rusqlite::Result<TransferMonthlyCounts> {
        if !valid_utc_month(month) {
            return Err(rusqlite::Error::InvalidParameterName(
                "month must use UTC YYYY-MM".into(),
            ));
        }
        let connection = self.conn();
        let mut statement = connection.prepare(
            "SELECT action,count FROM transfer_monthly_counts WHERE month=?1 ORDER BY action",
        )?;
        let mut counts = TransferMonthlyCounts {
            month: month.to_string(),
            download: 0,
            zip_download: 0,
            preview: 0,
        };
        for row in statement.query_map([month], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
        })? {
            let (action, count) = row?;
            match action.as_str() {
                "download" => counts.download = count,
                "zip_download" => counts.zip_download = count,
                "preview" => counts.preview = count,
                _ => return Err(rusqlite::Error::InvalidQuery),
            }
        }
        Ok(counts)
    }
    pub fn current_transfer_monthly_counts(&self) -> rusqlite::Result<TransferMonthlyCounts> {
        self.transfer_monthly_counts(&current_utc_month())
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
                "SELECT occurred_at,actor,action,object_id,detail,client_ip FROM audit WHERE action=?1 ORDER BY id DESC LIMIT ?2 OFFSET ?3",
            )?;
            let events = statement
                .query_map(params![action, limit as i64, offset as i64], |row| {
                    Ok(AuditEvent {
                        occurred_at: row.get(0)?,
                        actor: row.get(1)?,
                        action: row.get(2)?,
                        object_id: row.get(3)?,
                        detail: row.get(4)?,
                        client_ip: row.get(5)?,
                    })
                })?
                .collect();
            events
        } else {
            let mut statement = c.prepare(
                "SELECT occurred_at,actor,action,object_id,detail,client_ip FROM audit ORDER BY id DESC LIMIT ?1 OFFSET ?2",
            )?;
            let events = statement
                .query_map(params![limit as i64, offset as i64], |row| {
                    Ok(AuditEvent {
                        occurred_at: row.get(0)?,
                        actor: row.get(1)?,
                        action: row.get(2)?,
                        object_id: row.get(3)?,
                        detail: row.get(4)?,
                        client_ip: row.get(5)?,
                    })
                })?
                .collect();
            events
        }
    }

    pub fn count_audit(&self, action: Option<&str>) -> rusqlite::Result<usize> {
        let connection = self.conn();
        let count: i64 = if let Some(action) = action {
            connection.query_row(
                "SELECT COUNT(*) FROM audit WHERE action=?1",
                params![action],
                |row| row.get(0),
            )?
        } else {
            connection.query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))?
        };
        Ok(count.max(0) as usize)
    }
}

fn share_path_matches(candidate: &str, target: &str, is_directory: bool) -> bool {
    candidate == target
        || (is_directory
            && candidate
                .strip_prefix(target)
                .is_some_and(|suffix| suffix.starts_with('/')))
}

pub fn rewrite_share_path(
    candidate: &str,
    target: &str,
    replacement: &str,
    is_directory: bool,
) -> Option<String> {
    if candidate == target {
        return Some(replacement.to_string());
    }
    if !is_directory {
        return None;
    }
    candidate
        .strip_prefix(target)
        .filter(|suffix| suffix.starts_with('/'))
        .map(|suffix| format!("{replacement}{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hash_keeps_lowercase_sha256_encoding() {
        assert_eq!(
            token_hash("test"),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn fallible_unsigned_sqlite_values_reject_out_of_range_data() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute("CREATE TABLE numbers(value INTEGER NOT NULL)", [])
            .unwrap();
        connection
            .execute(
                "INSERT INTO numbers(value) VALUES(?1)",
                [MAX_SQLITE_UNSIGNED],
            )
            .unwrap();
        let maximum: u64 = connection
            .query_row("SELECT value FROM numbers", [], |row| row.get(0))
            .unwrap();
        assert_eq!(maximum, MAX_SQLITE_UNSIGNED);
        assert!(connection
            .execute(
                "INSERT INTO numbers(value) VALUES(?1)",
                [MAX_SQLITE_UNSIGNED + 1]
            )
            .is_err());

        connection.execute("DELETE FROM numbers", []).unwrap();
        connection
            .execute("INSERT INTO numbers(value) VALUES(-1)", [])
            .unwrap();
        assert!(connection
            .query_row("SELECT value FROM numbers", [], |row| row.get::<_, u64>(0))
            .is_err());
    }

    #[test]
    fn persistent_database_is_regular_private_and_not_linked() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("data.sqlite");
        std::fs::write(&path, []).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

        let database = Database::open(&path).unwrap();
        drop(database);
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.mode() & 0o7777, 0o600);

        let hard_link = directory.path().join("data-hard-link.sqlite");
        std::fs::hard_link(&path, &hard_link).unwrap();
        assert!(Database::open(&path).is_err());

        let symlink = directory.path().join("data-symlink.sqlite");
        std::os::unix::fs::symlink(&path, &symlink).unwrap();
        assert!(Database::open(&symlink).is_err());
        assert!(Database::open(directory.path()).is_err());
    }

    #[test]
    fn database_open_stays_bound_to_the_validated_directory_capability() {
        let parent = tempfile::tempdir().unwrap();
        let configured = parent.path().join("data");
        let displaced = parent.path().join("data-validated");
        std::fs::create_dir(&configured).unwrap();
        std::fs::set_permissions(&configured, std::fs::Permissions::from_mode(0o700)).unwrap();
        let capability = File::open(&configured).unwrap();

        std::fs::rename(&configured, &displaced).unwrap();
        std::fs::create_dir(&configured).unwrap();

        let database = Database::open_in_directory(capability).unwrap();
        assert_eq!(database.admin_count().unwrap(), 0);
        drop(database);

        assert!(displaced.join("data.sqlite").is_file());
        assert!(!configured.join("data.sqlite").exists());
    }

    #[test]
    fn file_mutations_update_only_exact_share_subtrees() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let mut ids = Vec::new();
        for (index, path) in ["foo", "foo/child.txt", "foobar", "other"]
            .into_iter()
            .enumerate()
        {
            ids.push(
                database
                    .create_share(
                        &format!("token-{index}"),
                        None,
                        path,
                        path == "foo",
                        &Permission::DownloadOnly,
                        None,
                        None,
                        None,
                        1,
                        None,
                        &UploadConflictStrategy::Reject,
                    )
                    .unwrap(),
            );
        }
        database.set_share_active(ids[1], false).unwrap();
        assert_eq!(
            database.rename_share_paths("foo", "renamed", true).unwrap(),
            2
        );
        let shares = database.list_shares().unwrap();
        assert!(shares.iter().any(|share| share.relative_path == "renamed"));
        assert!(shares
            .iter()
            .any(|share| share.relative_path == "renamed/child.txt" && !share.active));
        assert!(shares.iter().any(|share| share.relative_path == "foobar"));
        assert_eq!(
            database
                .count_active_shares_for_path("renamed", true)
                .unwrap(),
            1
        );
        assert_eq!(
            database
                .deactivate_shares_for_path("renamed", true)
                .unwrap(),
            1
        );
        assert_eq!(
            database
                .count_active_shares_for_path("renamed", true)
                .unwrap(),
            0
        );
    }

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
    fn totp_step_is_consumed_once_across_racing_sessions() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        for token in ["first-session", "second-session"] {
            database
                .create_session(token, 1, "csrf", Utc::now() + Duration::hours(1))
                .unwrap();
        }

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let workers = ["first-session", "second-session"].map(|token| {
            let database = database.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let rotated = format!("{token}-rotated");
                let accepted = database
                    .verify_mfa_with_totp_step(token, &rotated, "rotated-csrf", 1, 42)
                    .unwrap();
                (token, rotated, accepted)
            })
        });
        barrier.wait();
        let outcomes = workers.map(|worker| worker.join().unwrap());
        assert_eq!(
            outcomes.iter().filter(|(_, _, accepted)| *accepted).count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(
                    |(_, rotated, _)| database.session(rotated).unwrap().is_some_and(|session| {
                        session.mfa_verified && session.csrf_token == "rotated-csrf"
                    })
                )
                .count(),
            1
        );
        assert!(outcomes
            .iter()
            .all(|(old, _, accepted)| { !accepted || database.session(old).unwrap().is_none() }));

        let pending_token = outcomes
            .iter()
            .find(|(_, _, accepted)| !accepted)
            .map(|(old, _, _)| *old)
            .unwrap();
        assert!(!database
            .verify_mfa_with_totp_step(pending_token, "retry-1", "csrf-1", 1, 42)
            .unwrap());
        assert!(database
            .verify_mfa_with_totp_step(pending_token, "retry-2", "csrf-2", 1, 43)
            .unwrap());
        assert!(database.session(pending_token).unwrap().is_none());
        assert_eq!(
            database.session("retry-2").unwrap().unwrap().csrf_token,
            "csrf-2"
        );
    }

    #[test]
    fn verified_password_session_creation_rejects_a_stale_hash_without_a_zombie_session() {
        let database = Database::open(":memory:").unwrap();
        database
            .create_admin("admin", "verified-hash", "secret")
            .unwrap();
        database.reset_admin_password(1, "rotated-hash").unwrap();

        assert_eq!(
            database
                .create_session_for_verified_password(
                    "stale-session",
                    1,
                    "verified-hash",
                    "csrf",
                    Utc::now() + Duration::hours(1),
                )
                .unwrap(),
            PasswordSessionCreationOutcome::StalePassword
        );
        assert!(database.session("stale-session").unwrap().is_none());
        assert_eq!(
            database
                .conn()
                .query_row::<i64, _, _>(
                    "SELECT COUNT(*) FROM sessions WHERE token_hash=?1",
                    [token_hash("stale-session")],
                    |row| row.get(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn verified_password_session_creation_rejects_an_inactive_admin_without_a_zombie_session() {
        let database = Database::open(":memory:").unwrap();
        database
            .create_admin("disabled", "verified-hash", "secret")
            .unwrap();
        database
            .create_admin("survivor", "other-hash", "other-secret")
            .unwrap();
        assert_eq!(
            database.deactivate_admin(1).unwrap(),
            AdminDeactivationOutcome::Deactivated
        );

        assert_eq!(
            database
                .create_session_for_verified_password(
                    "inactive-session",
                    1,
                    "verified-hash",
                    "csrf",
                    Utc::now() + Duration::hours(1),
                )
                .unwrap(),
            PasswordSessionCreationOutcome::AdminInactive
        );
        assert!(database.session("inactive-session").unwrap().is_none());
        assert_eq!(
            database
                .conn()
                .query_row::<i64, _, _>(
                    "SELECT COUNT(*) FROM sessions WHERE token_hash=?1",
                    [token_hash("inactive-session")],
                    |row| row.get(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn verified_password_session_creation_accepts_the_current_active_hash() {
        let database = Database::open(":memory:").unwrap();
        database
            .create_admin("admin", "verified-hash", "secret")
            .unwrap();

        assert_eq!(
            database
                .create_session_for_verified_password(
                    "current-session",
                    1,
                    "verified-hash",
                    "csrf",
                    Utc::now() + Duration::hours(1),
                )
                .unwrap(),
            PasswordSessionCreationOutcome::Created
        );
        assert!(database.session("current-session").unwrap().is_some());
    }

    #[test]
    fn audit_client_ips_are_optional_listed_and_purgeable_without_deleting_events() {
        let database = Database::open(":memory:").unwrap();
        database
            .audit("admin", "settings_updated", None, None)
            .unwrap();
        database
            .audit_with_client_ip(
                "public",
                "share_unlock_failed",
                Some("7"),
                Some("rate limited"),
                Some("203.0.113.24"),
            )
            .unwrap();

        assert_eq!(database.count_audit_client_ips().unwrap(), 1);
        assert_eq!(database.count_audit(None).unwrap(), 2);
        assert_eq!(database.count_audit(Some("settings_updated")).unwrap(), 1);
        assert_eq!(database.count_audit(Some("missing_action")).unwrap(), 0);
        let events = database.list_audit(None, 10, 0).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].client_ip.as_deref(), Some("203.0.113.24"));
        assert!(events[1].client_ip.is_none());

        assert_eq!(
            database.delete_audit_client_ips_if_disabled(false).unwrap(),
            AuditClientIpDeletionOutcome::Deleted(1)
        );
        assert_eq!(database.count_audit_client_ips().unwrap(), 0);
        assert_eq!(
            database.delete_audit_client_ips_if_disabled(false).unwrap(),
            AuditClientIpDeletionOutcome::Deleted(0)
        );
        let events = database.list_audit(None, 10, 0).unwrap();
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| event.client_ip.is_none()));
    }

    #[test]
    fn audit_ip_writes_and_purge_follow_the_persisted_privacy_setting() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        database
            .replace_runtime_settings(&[("audit_client_ip_enabled", "true".to_string())], 1)
            .unwrap();
        database
            .audit_with_client_ip("public", "before_disable", None, None, Some("203.0.113.40"))
            .unwrap();

        // The committed setting wins over a stale in-memory fallback.
        assert_eq!(
            database.delete_audit_client_ips_if_disabled(false).unwrap(),
            AuditClientIpDeletionOutcome::LoggingEnabled
        );

        database
            .replace_runtime_settings(&[("audit_client_ip_enabled", "false".to_string())], 1)
            .unwrap();
        // Model a delayed request that captured the IP while logging was still
        // enabled but reaches SQLite only after the disabling commit.
        database
            .audit_with_client_ip(
                "public",
                "delayed_after_disable",
                None,
                None,
                Some("203.0.113.41"),
            )
            .unwrap();
        let delayed = database
            .list_audit(Some("delayed_after_disable"), 1, 0)
            .unwrap();
        assert_eq!(delayed.len(), 1);
        assert!(delayed[0].client_ip.is_none());
        assert_eq!(database.count_audit_client_ips().unwrap(), 1);

        assert_eq!(
            database.delete_audit_client_ips_if_disabled(true).unwrap(),
            AuditClientIpDeletionOutcome::Deleted(1)
        );
        assert_eq!(database.count_audit_client_ips().unwrap(), 0);

        database
            .replace_runtime_settings(&[("audit_client_ip_enabled", "true".to_string())], 1)
            .unwrap();
        assert_eq!(
            database.delete_audit_client_ips_if_disabled(false).unwrap(),
            AuditClientIpDeletionOutcome::LoggingEnabled
        );
    }

    #[test]
    fn audit_retention_keeps_only_the_newest_rows() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        {
            let mut connection = database.conn();
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            for index in 0..6 {
                transaction
                    .execute(
                        "INSERT INTO audit(
                             occurred_at,actor,action,object_id,detail,client_ip
                         ) VALUES(?1,'test',?2,NULL,NULL,NULL)",
                        params![Utc::now().to_rfc3339(), format!("event-{index}")],
                    )
                    .unwrap();
                enforce_audit_retention(&transaction, 3).unwrap();
            }
            transaction.commit().unwrap();
        }

        let actions: Vec<String> = {
            let connection = database.conn();
            let mut statement = connection
                .prepare("SELECT action FROM audit ORDER BY id")
                .unwrap();
            statement
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        assert_eq!(
            actions,
            vec![
                "event-3".to_string(),
                "event-4".to_string(),
                "event-5".to_string()
            ]
        );
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
    fn initial_admin_creation_refuses_an_initialized_database() {
        let database = Database::open(":memory:").unwrap();
        database
            .create_admin("existing", "existing-hash", "existing-secret")
            .unwrap();

        assert_eq!(
            database
                .create_initial_admin("second", "second-hash", "second-secret")
                .unwrap(),
            InitialAdminOutcome::AlreadyInitialized
        );
        assert_eq!(database.admin_count().unwrap(), 1);
        assert!(database.admin("second").unwrap().is_none());
    }

    #[test]
    fn combined_admin_recovery_is_atomic_and_revokes_sessions() {
        let database = Database::open(":memory:").unwrap();
        database
            .create_admin("admin", "old-hash", "old-secret")
            .unwrap();
        database
            .create_session("session-token", 1, "csrf", Utc::now() + Duration::hours(1))
            .unwrap();
        database
            .start_admin_mfa_enrollment(1, "stale-enrollment", "stale-pending-secret")
            .unwrap();

        let outcome = database
            .recover_admin("ADMIN", Some("new-hash"), Some("new-secret"))
            .unwrap();
        assert_eq!(
            outcome,
            AdminRecoveryOutcome::Recovered {
                admin_id: 1,
                username: "admin".into(),
                active: true,
            }
        );
        let admin = database.admin("admin").unwrap().unwrap();
        assert_eq!(admin.password_hash, "new-hash");
        assert_eq!(admin.totp_secret, "new-secret");
        assert!(database.session("session-token").unwrap().is_none());
        assert_eq!(
            database
                .activate_admin_mfa_enrollment(1, "stale-enrollment", 42, None)
                .unwrap(),
            AdminMfaEnrollmentActivationOutcome::NotFoundOrExpired
        );
        assert_eq!(
            database.admin("admin").unwrap().unwrap().totp_secret,
            "new-secret"
        );
        assert!(database.consume_admin_totp_step(1, 42).unwrap());
        assert!(!database.consume_admin_totp_step(1, 42).unwrap());
        let events = database.list_audit(Some("admin_recovered"), 10, 0).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor, "local_recovery");
        assert_eq!(
            events[0].detail.as_deref(),
            Some("reset_password=true;reset_mfa=true")
        );
        assert!(events[0].client_ip.is_none());
        let serialized_event = format!("{events:?}");
        assert!(!serialized_event.contains("new-hash"));
        assert!(!serialized_event.contains("new-secret"));
    }

    #[test]
    fn combined_admin_recovery_rolls_back_all_changes_when_audit_fails() {
        let database = Database::open(":memory:").unwrap();
        database
            .create_admin("admin", "old-hash", "old-secret")
            .unwrap();
        database
            .create_session("session-token", 1, "csrf", Utc::now() + Duration::hours(1))
            .unwrap();
        database
            .start_admin_mfa_enrollment(1, "pending-token", "pending-secret")
            .unwrap();
        database
            .conn()
            .execute_batch(
                "CREATE TEMP TRIGGER fail_admin_recovery_audit
                 BEFORE INSERT ON audit
                 WHEN NEW.action='admin_recovered'
                 BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;",
            )
            .unwrap();

        assert!(database
            .recover_admin("admin", Some("new-hash"), Some("new-secret"))
            .is_err());
        let admin = database.admin("admin").unwrap().unwrap();
        assert_eq!(admin.password_hash, "old-hash");
        assert_eq!(admin.totp_secret, "old-secret");
        assert!(database.session("session-token").unwrap().is_some());
        assert!(database
            .admin_mfa_enrollment(1, "pending-token")
            .unwrap()
            .is_some());
        assert_eq!(database.count_audit(Some("admin_recovered")).unwrap(), 0);
    }

    #[test]
    fn admin_recovery_returns_not_found_without_side_effects() {
        let database = Database::open(":memory:").unwrap();

        assert_eq!(
            database
                .recover_admin("missing", Some("new-hash"), None)
                .unwrap(),
            AdminRecoveryOutcome::NotFound
        );
        assert_eq!(database.admin_count().unwrap(), 0);
        assert_eq!(database.count_audit(Some("admin_recovered")).unwrap(), 0);
    }

    #[test]
    fn password_change_compare_and_swap_allows_only_one_racing_update() {
        let database = Database::open(":memory:").unwrap();
        database
            .create_admin("admin", "old-hash", "secret")
            .unwrap();
        database
            .create_session("session-token", 1, "csrf", Utc::now() + Duration::hours(1))
            .unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for new_hash in ["first-hash", "second-hash"] {
            let database = database.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                database
                    .change_admin_password_cas(1, "old-hash", new_hash, Some("198.51.100.10"))
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
                .filter(|outcome| **outcome == AdminPasswordChangeOutcome::Changed)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == AdminPasswordChangeOutcome::StalePassword)
                .count(),
            1
        );
        let admin = database.admin("admin").unwrap().unwrap();
        assert!(matches!(
            admin.password_hash.as_str(),
            "first-hash" | "second-hash"
        ));
        assert!(database.session("session-token").unwrap().is_none());
        assert_eq!(
            database
                .count_audit(Some("account_password_changed"))
                .unwrap(),
            1
        );
        assert_eq!(
            database
                .list_audit(Some("account_password_changed"), 10, 0)
                .unwrap()[0]
                .client_ip
                .as_deref(),
            Some("198.51.100.10")
        );
    }

    #[test]
    fn pending_mfa_enrollment_has_a_ttl_and_replaces_the_previous_token() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();

        let first = database
            .start_admin_mfa_enrollment(1, "first-token", "first-secret")
            .unwrap();
        let AdminMfaEnrollmentStartOutcome::Started { expires_at } = first else {
            panic!("known administrator must start an enrollment");
        };
        let expires_at = DateTime::parse_from_rfc3339(&expires_at).unwrap();
        let remaining = expires_at.signed_duration_since(Utc::now());
        assert!(remaining <= Duration::seconds(ADMIN_MFA_ENROLLMENT_TTL_SECONDS));
        assert!(remaining > Duration::seconds(ADMIN_MFA_ENROLLMENT_TTL_SECONDS - 5));
        assert_eq!(
            database
                .admin_mfa_enrollment(1, "first-token")
                .unwrap()
                .unwrap()
                .totp_secret,
            "first-secret"
        );

        database
            .start_admin_mfa_enrollment(1, "second-token", "second-secret")
            .unwrap();
        assert!(database
            .admin_mfa_enrollment(1, "first-token")
            .unwrap()
            .is_none());
        assert_eq!(
            database
                .admin_mfa_enrollment(1, "second-token")
                .unwrap()
                .unwrap()
                .totp_secret,
            "second-secret"
        );
        let stored_token_hash = database
            .conn()
            .query_row::<String, _, _>(
                "SELECT token_hash FROM admin_mfa_enrollments WHERE admin_id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_token_hash, token_hash("second-token"));
        assert_ne!(stored_token_hash, "second-token");

        database
            .conn()
            .execute(
                "UPDATE admin_mfa_enrollments SET expires_at=?1 WHERE admin_id=1",
                [Utc::now()
                    .checked_sub_signed(Duration::seconds(1))
                    .unwrap()
                    .to_rfc3339()],
            )
            .unwrap();
        assert_eq!(database.cleanup_expired_admin_mfa_enrollments().unwrap(), 1);
        assert!(database
            .admin_mfa_enrollment(1, "second-token")
            .unwrap()
            .is_none());
    }

    #[test]
    fn pending_mfa_activation_is_single_use_and_revokes_sessions() {
        let database = Database::open(":memory:").unwrap();
        database
            .create_admin("admin", "hash", "old-secret")
            .unwrap();
        database
            .create_session("session-token", 1, "csrf", Utc::now() + Duration::hours(1))
            .unwrap();
        database
            .start_admin_mfa_enrollment(1, "enrollment-token", "new-secret")
            .unwrap();

        assert_eq!(
            database
                .activate_admin_mfa_enrollment(1, "enrollment-token", 42, Some("203.0.113.24"),)
                .unwrap(),
            AdminMfaEnrollmentActivationOutcome::Activated
        );
        assert_eq!(
            database.admin("admin").unwrap().unwrap().totp_secret,
            "new-secret"
        );
        assert!(database.session("session-token").unwrap().is_none());
        assert!(!database.consume_admin_totp_step(1, 42).unwrap());
        assert!(database.consume_admin_totp_step(1, 43).unwrap());
        assert!(database
            .admin_mfa_enrollment(1, "enrollment-token")
            .unwrap()
            .is_none());
        assert_eq!(
            database
                .activate_admin_mfa_enrollment(1, "enrollment-token", 42, None)
                .unwrap(),
            AdminMfaEnrollmentActivationOutcome::NotFoundOrExpired
        );
        let events = database
            .list_audit(Some("account_mfa_changed"), 10, 0)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].detail.is_none());
        assert_eq!(events[0].client_ip.as_deref(), Some("203.0.113.24"));
        assert!(!format!("{events:?}").contains("new-secret"));
    }

    #[test]
    fn deactivation_removes_pending_mfa_and_blocks_inactive_account_operations() {
        let database = Database::open(":memory:").unwrap();
        database
            .create_admin("one", "one-hash", "one-secret")
            .unwrap();
        database
            .create_admin("two", "two-hash", "two-secret")
            .unwrap();
        database
            .start_admin_mfa_enrollment(1, "pending-token", "pending-secret")
            .unwrap();

        assert_eq!(
            database.deactivate_admin(1).unwrap(),
            AdminDeactivationOutcome::Deactivated
        );
        assert_eq!(
            database
                .conn()
                .query_row::<i64, _, _>(
                    "SELECT COUNT(*) FROM admin_mfa_enrollments WHERE admin_id=1",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            database
                .start_admin_mfa_enrollment(1, "new-token", "new-secret")
                .unwrap(),
            AdminMfaEnrollmentStartOutcome::AdminInactive
        );
        assert_eq!(
            database
                .change_admin_password_cas(1, "one-hash", "new-hash", None)
                .unwrap(),
            AdminPasswordChangeOutcome::Inactive
        );

        database
            .conn()
            .execute(
                "INSERT INTO admin_mfa_enrollments(
                    admin_id,token_hash,totp_secret,created_at,expires_at
                 ) VALUES(1,?1,'injected-secret',?2,?3)",
                params![
                    token_hash("injected-token"),
                    Utc::now().to_rfc3339(),
                    (Utc::now() + Duration::minutes(5)).to_rfc3339()
                ],
            )
            .unwrap();
        assert!(database
            .admin_mfa_enrollment(1, "injected-token")
            .unwrap()
            .is_none());
        assert_eq!(
            database
                .activate_admin_mfa_enrollment(1, "injected-token", 42, None)
                .unwrap(),
            AdminMfaEnrollmentActivationOutcome::NotFoundOrExpired
        );
        let inactive = database
            .conn()
            .query_row::<(String, String), _, _>(
                "SELECT password_hash,totp_secret FROM admins WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(inactive, ("one-hash".into(), "one-secret".into()));
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
        assert!(d.set_share_active(id, false).unwrap());
        assert!(!d.set_share_active(id + 1, false).unwrap());
        assert!(!d.share_by_token("token").unwrap().unwrap().active);
        assert!(d.delete_share(id).unwrap());
        assert!(!d.delete_share(id).unwrap());
        assert!(d.share_by_token("token").unwrap().is_none());
    }

    #[test]
    fn malformed_share_expiry_fails_individual_and_list_queries() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        for (token, path) in [("valid", "valid.txt"), ("corrupt", "corrupt.txt")] {
            database
                .create_share(
                    token,
                    None,
                    path,
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
        }
        database
            .conn()
            .execute(
                "UPDATE shares SET expires_at='not-a-timestamp' WHERE token_hash=?1",
                [token_hash("corrupt")],
            )
            .unwrap();

        assert!(database.share_by_token("corrupt").is_err());
        assert!(database.list_shares().is_err());
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
        assert_eq!(share.created_at, "2026-01-01T00:00:00Z");
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
    fn migrates_legacy_password_max_runtime_key_to_the_canonical_name() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE runtime_settings(
                     key TEXT PRIMARY KEY,
                     value TEXT NOT NULL
                 );
                 INSERT INTO runtime_settings VALUES('share_password_max_bytes','128');
                 PRAGMA user_version=11;",
            )
            .unwrap();

        migrate(&mut connection).unwrap();

        assert_eq!(
            connection
                .query_row::<String, _, _>(
                    "SELECT value FROM runtime_settings
                     WHERE key='share_password_max_length'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            "128"
        );
        assert_eq!(
            connection
                .query_row::<i64, _, _>(
                    "SELECT COUNT(*) FROM runtime_settings
                     WHERE key='share_password_max_bytes'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
                .unwrap(),
            SCHEMA_VERSION
        );
    }

    #[test]
    fn canonical_runtime_key_wins_if_both_password_max_names_exist() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE runtime_settings(
                     key TEXT PRIMARY KEY,
                     value TEXT NOT NULL
                 );
                 INSERT INTO runtime_settings VALUES('share_password_max_bytes','128');
                 INSERT INTO runtime_settings VALUES('share_password_max_length','256');
                 PRAGMA user_version=11;",
            )
            .unwrap();

        migrate(&mut connection).unwrap();

        assert_eq!(
            connection
                .query_row::<String, _, _>(
                    "SELECT value FROM runtime_settings
                     WHERE key='share_password_max_length'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            "256"
        );
        assert_eq!(
            connection
                .query_row::<i64, _, _>("SELECT COUNT(*) FROM runtime_settings", [], |row| {
                    row.get(0)
                })
                .unwrap(),
            1
        );
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
                     CREATE TABLE audit(id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, object_id TEXT, detail TEXT);
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
            SCHEMA_VERSION
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
    fn migrates_v7_audit_and_initializes_persistent_transfer_statistics() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("v7.sqlite");
        {
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE audit(
                        id INTEGER PRIMARY KEY,
                        occurred_at TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        action TEXT NOT NULL,
                        object_id TEXT,
                        detail TEXT
                     );
                     INSERT INTO audit VALUES(
                        1,'2026-01-01T00:00:00Z','admin','share_created','1','download_only'
                     );
                     PRAGMA user_version=7;",
                )
                .unwrap();
        }

        let database = Database::open(&path).unwrap();
        assert_eq!(
            database
                .conn()
                .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
                .unwrap(),
            SCHEMA_VERSION
        );
        let event = database.list_audit(None, 10, 0).unwrap().remove(0);
        assert_eq!(event.action, "share_created");
        assert!(event.client_ip.is_none());
        let started_at = database.transfer_statistics_started_at().unwrap();
        DateTime::parse_from_rfc3339(&started_at).unwrap();
        assert_eq!(
            database
                .conn()
                .query_row::<i64, _, _>(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE type='table' AND name IN ('transfer_monthly_counts','transfer_statistics')",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            2
        );
        assert!(database
            .conn()
            .execute(
                "INSERT INTO transfer_monthly_counts(month,action,count) VALUES('2026-13','download',1)",
                [],
            )
            .is_err());
        assert!(database
            .conn()
            .execute(
                "INSERT INTO transfer_monthly_counts(month,action,count) VALUES('2026-07','upload',1)",
                [],
            )
            .is_err());
        drop(database);

        let reopened = Database::open(&path).unwrap();
        assert_eq!(
            reopened.transfer_statistics_started_at().unwrap(),
            started_at
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
        let original_share = database.share_by_token("share").unwrap().unwrap();
        assert!(database
            .create_unlock_session_for_verified_password(
                "unlock-secret",
                share_id,
                original_share.password_hash.as_deref().unwrap(),
                original_share.upload_policy_epoch,
                "unlock-csrf",
                Utc::now() + chrono::Duration::minutes(60),
            )
            .unwrap());
        assert!(database.unlock_session("unlock-secret", share_id).unwrap());
        assert_eq!(
            database
                .unlock_session_csrf("unlock-secret", share_id)
                .unwrap()
                .as_deref(),
            Some("unlock-csrf")
        );
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
        assert!(!database
            .create_unlock_session_for_verified_password(
                "stale-unlock-secret",
                share_id,
                original_share.password_hash.as_deref().unwrap(),
                original_share.upload_policy_epoch,
                "stale-unlock-csrf",
                Utc::now() + chrono::Duration::minutes(60),
            )
            .unwrap());
        assert!(!database
            .unlock_session("stale-unlock-secret", share_id)
            .unwrap());
        let updated_share = database.share_by_token("share").unwrap().unwrap();
        assert!(updated_share.upload_policy_epoch > original_share.upload_policy_epoch);
        assert!(database
            .create_unlock_session_for_verified_password(
                "new-unlock-secret",
                share_id,
                updated_share.password_hash.as_deref().unwrap(),
                updated_share.upload_policy_epoch,
                "new-unlock-csrf",
                Utc::now() + chrono::Duration::minutes(60),
            )
            .unwrap());
        database
            .set_share_password(share_id, updated_share.password_hash.as_deref())
            .unwrap();
        assert!(!database
            .unlock_session("new-unlock-secret", share_id)
            .unwrap());
        assert!(!database
            .create_unlock_session_for_verified_password(
                "same-hash-stale-secret",
                share_id,
                updated_share.password_hash.as_deref().unwrap(),
                updated_share.upload_policy_epoch,
                "same-hash-stale-csrf",
                Utc::now() + chrono::Duration::minutes(60),
            )
            .unwrap());
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
    fn migrates_v12_upload_shares_with_finite_quotas_and_read_only_unlocks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("v12.sqlite");
        {
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE admins(
                         id INTEGER PRIMARY KEY,username TEXT NOT NULL UNIQUE,
                         password_hash TEXT NOT NULL,totp_secret TEXT NOT NULL,
                         created_at TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1
                     );
                     CREATE TABLE shares(
                         id INTEGER PRIMARY KEY,token_hash TEXT NOT NULL UNIQUE,token TEXT NOT NULL,
                         alias TEXT UNIQUE,relative_path TEXT NOT NULL,is_directory INTEGER NOT NULL,
                         permission TEXT NOT NULL,expires_at TEXT,max_downloads INTEGER,
                         max_upload_size INTEGER,download_count INTEGER NOT NULL DEFAULT 0,
                         active INTEGER NOT NULL DEFAULT 1,created_by INTEGER NOT NULL,
                         created_at TEXT NOT NULL,password_hash TEXT,
                         upload_conflict_strategy TEXT NOT NULL DEFAULT 'reject'
                     );
                     CREATE TABLE public_unlock_sessions(
                         token_hash TEXT PRIMARY KEY,share_id INTEGER NOT NULL,
                         expires_at TEXT NOT NULL
                     );
                     INSERT INTO admins VALUES(1,'admin','hash','secret','now',1);
                     INSERT INTO shares VALUES(
                         1,'hash','token',NULL,'folder',1,'upload_only',NULL,NULL,
                         150000000000,0,1,1,'now','password-hash','reject'
                     );
                     INSERT INTO public_unlock_sessions VALUES(
                         'legacy-hash',1,'2999-01-01T00:00:00Z'
                     );
                     PRAGMA user_version=12;",
                )
                .unwrap();
        }
        let database = Database::open(&path).unwrap();
        let share = database.list_shares().unwrap().remove(0);
        assert_eq!(share.max_upload_total_size, Some(150_000_000_000));
        assert_eq!(
            share.max_upload_files,
            Some(DEFAULT_SHARE_UPLOAD_FILE_COUNT)
        );
        let migrated_unlocks: u64 = database
            .conn()
            .query_row("SELECT COUNT(*) FROM public_unlock_sessions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(migrated_unlocks, 0);
        assert!(database
            .unlock_session_csrf("unavailable-plaintext-token", 1)
            .unwrap()
            .is_none());
    }

    #[test]
    fn migrates_v13_preview_sessions_with_bounded_lookup_index() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE public_preview_sessions(
                     token_hash TEXT PRIMARY KEY,
                     share_id INTEGER NOT NULL,
                     relative_path TEXT NOT NULL,
                     expires_at TEXT NOT NULL
                 );
                 PRAGMA user_version=13;",
            )
            .unwrap();

        migrate(&mut connection).unwrap();

        let index_exists: bool = connection
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM sqlite_schema
                     WHERE type='index' AND name='idx_preview_share_path_owner'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(index_exists);
        let owner_column_exists: bool = connection
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM pragma_table_info('public_preview_sessions')
                     WHERE name='owner_key_hash' AND \"notnull\"=1
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(owner_column_exists);
        assert_eq!(
            connection
                .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
                .unwrap(),
            SCHEMA_VERSION
        );
    }

    #[test]
    fn migrates_v14_upload_reservations_with_policy_epoch_fail_closed() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE shares(id INTEGER PRIMARY KEY);
                 CREATE TABLE public_upload_reservations(
                     token_hash TEXT PRIMARY KEY,
                     share_id INTEGER NOT NULL,
                     reserved_bytes INTEGER NOT NULL,
                     created_at TEXT NOT NULL,
                     expires_at TEXT NOT NULL
                 );
                 INSERT INTO shares VALUES(1);
                 INSERT INTO public_upload_reservations
                     VALUES('legacy-reservation',1,42,'now','later');
                 PRAGMA user_version=14;",
            )
            .unwrap();

        migrate(&mut connection).unwrap();

        for table in ["shares", "public_upload_reservations"] {
            let epoch_column_exists: bool = connection
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM pragma_table_info(?1)
                         WHERE name='upload_policy_epoch' AND \"notnull\"=1
                     )",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(epoch_column_exists, "missing epoch column on {table}");
        }
        let legacy_reservations: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM public_upload_reservations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy_reservations, 0);
        assert_eq!(
            connection
                .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
                .unwrap(),
            SCHEMA_VERSION
        );
    }

    #[test]
    fn upload_quota_reservations_are_atomic_cumulative_and_cancellable() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let share_id = database
            .create_share_with_upload_limits(
                "upload-share",
                None,
                "folder",
                true,
                &Permission::UploadOnly,
                None,
                None,
                Some(6),
                Some(10),
                Some(2),
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        assert_eq!(
            database.begin_upload_reservation("one", share_id).unwrap(),
            UploadReservationBeginOutcome::Reserved
        );
        assert_eq!(
            database.begin_upload_reservation("two", share_id).unwrap(),
            UploadReservationBeginOutcome::Reserved
        );
        assert_eq!(
            database
                .begin_upload_reservation("three", share_id)
                .unwrap(),
            UploadReservationBeginOutcome::FileQuotaReached
        );
        assert_eq!(
            database.extend_upload_reservation("one", 6).unwrap(),
            UploadReservationExtendOutcome::Extended
        );
        assert_eq!(
            database.extend_upload_reservation("two", 5).unwrap(),
            UploadReservationExtendOutcome::ByteQuotaReached
        );
        assert!(database.cancel_upload_reservation("two").unwrap());
        assert_eq!(
            database.commit_upload_reservation("one", 6).unwrap(),
            UploadReservationCommitOutcome::Committed
        );

        assert_eq!(
            database
                .begin_upload_reservation("three", share_id)
                .unwrap(),
            UploadReservationBeginOutcome::Reserved
        );
        assert_eq!(
            database.extend_upload_reservation("three", 4).unwrap(),
            UploadReservationExtendOutcome::Extended
        );
        assert_eq!(
            database.commit_upload_reservation("three", 4).unwrap(),
            UploadReservationCommitOutcome::Committed
        );
        let share = database.share_by_token("upload-share").unwrap().unwrap();
        assert_eq!((share.uploaded_bytes, share.uploaded_files), (10, 2));
        assert_eq!(
            database.begin_upload_reservation("four", share_id).unwrap(),
            UploadReservationBeginOutcome::ByteQuotaReached
        );
        assert_eq!(
            database.commit_upload_reservation("missing", 0).unwrap(),
            UploadReservationCommitOutcome::NotFound
        );
    }

    #[test]
    fn upload_reservations_are_revoked_when_share_authority_changes() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let revocations = [
            "UPDATE shares SET active=0 WHERE id=?1",
            "UPDATE shares SET expires_at='2000-01-01T00:00:00Z' WHERE id=?1",
            "UPDATE shares SET is_directory=0 WHERE id=?1",
            "UPDATE shares SET permission='download_only' WHERE id=?1",
        ];

        for (index, revocation) in revocations.into_iter().enumerate() {
            let share_token = format!("revoked-share-{index}");
            let extend_token = format!("extend-{index}");
            let commit_token = format!("commit-{index}");
            let share_id = database
                .create_share_with_upload_limits(
                    &share_token,
                    None,
                    &format!("folder-{index}"),
                    true,
                    &Permission::UploadOnly,
                    None,
                    None,
                    Some(100),
                    Some(1_000),
                    Some(10),
                    1,
                    None,
                    &UploadConflictStrategy::Reject,
                )
                .unwrap();
            assert_eq!(
                database
                    .begin_upload_reservation(&extend_token, share_id)
                    .unwrap(),
                UploadReservationBeginOutcome::Reserved
            );
            assert_eq!(
                database
                    .begin_upload_reservation(&commit_token, share_id)
                    .unwrap(),
                UploadReservationBeginOutcome::Reserved
            );
            database.conn().execute(revocation, [share_id]).unwrap();

            assert_eq!(
                database
                    .extend_upload_reservation(&extend_token, 1)
                    .unwrap(),
                UploadReservationExtendOutcome::ShareUnavailable
            );
            assert_eq!(
                database
                    .commit_upload_reservation(&commit_token, 0)
                    .unwrap(),
                UploadReservationCommitOutcome::ShareUnavailable
            );
            assert_eq!(database.active_upload_reservations(share_id).unwrap(), 0);
            assert!(!database.cancel_upload_reservation(&extend_token).unwrap());
            assert!(!database.cancel_upload_reservation(&commit_token).unwrap());
            let usage: u64 = database
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM public_upload_usage WHERE share_id=?1",
                    [share_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(usage, 0);
        }

        let read_write_share = database
            .create_share_with_upload_limits(
                "read-write-share",
                None,
                "read-write-folder",
                true,
                &Permission::DownloadUpload,
                None,
                None,
                Some(100),
                Some(1_000),
                Some(2),
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        assert_eq!(
            database
                .begin_upload_reservation("read-write-upload", read_write_share)
                .unwrap(),
            UploadReservationBeginOutcome::Reserved
        );
        assert_eq!(
            database
                .extend_upload_reservation("read-write-upload", 1)
                .unwrap(),
            UploadReservationExtendOutcome::Extended
        );
        assert_eq!(
            database
                .commit_upload_reservation("read-write-upload", 1)
                .unwrap(),
            UploadReservationCommitOutcome::Committed
        );
    }

    #[test]
    fn upload_reservation_policy_epoch_rejects_reactivation_and_policy_rotation() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let share_id = database
            .create_share_with_upload_limits(
                "epoch-share",
                None,
                "folder",
                true,
                &Permission::UploadOnly,
                None,
                None,
                Some(100),
                Some(1_000),
                Some(10),
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();

        assert_eq!(
            database
                .begin_upload_reservation("before-reactivation", share_id)
                .unwrap(),
            UploadReservationBeginOutcome::Reserved
        );
        assert!(database.set_share_active(share_id, false).unwrap());
        assert!(database.set_share_active(share_id, true).unwrap());
        assert_eq!(database.active_upload_reservations(share_id).unwrap(), 0);
        assert_eq!(
            database
                .extend_upload_reservation("before-reactivation", 1)
                .unwrap(),
            UploadReservationExtendOutcome::ShareUnavailable
        );

        assert_eq!(
            database
                .begin_upload_reservation("before-password", share_id)
                .unwrap(),
            UploadReservationBeginOutcome::Reserved
        );
        assert!(database
            .set_share_password(share_id, Some("rotated-password-hash"))
            .unwrap());
        assert_eq!(
            database
                .commit_upload_reservation("before-password", 0)
                .unwrap(),
            UploadReservationCommitOutcome::ShareUnavailable
        );

        assert_eq!(
            database
                .begin_upload_reservation("before-strategy", share_id)
                .unwrap(),
            UploadReservationBeginOutcome::Reserved
        );
        assert_eq!(
            database
                .update_share_controls(
                    share_id,
                    None,
                    Some(&UploadConflictStrategy::OverwriteAllowed),
                    None,
                )
                .unwrap(),
            ShareControlsUpdateOutcome::Updated
        );
        assert_eq!(
            database
                .extend_upload_reservation("before-strategy", 1)
                .unwrap(),
            UploadReservationExtendOutcome::ShareUnavailable
        );

        assert_eq!(
            database
                .begin_upload_reservation("before-quota", share_id)
                .unwrap(),
            UploadReservationBeginOutcome::Reserved
        );
        assert_eq!(
            database
                .update_share_controls(share_id, None, None, Some((2_000, 20)))
                .unwrap(),
            ShareControlsUpdateOutcome::Updated
        );
        assert_eq!(
            database
                .commit_upload_reservation("before-quota", 0)
                .unwrap(),
            UploadReservationCommitOutcome::ShareUnavailable
        );

        assert_eq!(
            database
                .begin_upload_reservation("current-policy", share_id)
                .unwrap(),
            UploadReservationBeginOutcome::Reserved
        );
        assert_eq!(
            database
                .extend_upload_reservation("current-policy", 1)
                .unwrap(),
            UploadReservationExtendOutcome::Extended
        );
        assert_eq!(
            database
                .commit_upload_reservation("current-policy", 1)
                .unwrap(),
            UploadReservationCommitOutcome::Committed
        );
    }

    #[test]
    fn stale_upload_quota_update_does_not_partially_change_strategy() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let share_id = database
            .create_share_with_upload_limits(
                "atomic-share",
                None,
                "folder",
                true,
                &Permission::UploadOnly,
                None,
                None,
                Some(5),
                Some(20),
                Some(3),
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        // These reservations represent concurrent uploads started after the UI
        // read its share snapshot but before it submitted strategy plus limits.
        for token in ["upload-one", "upload-two"] {
            database.begin_upload_reservation(token, share_id).unwrap();
            database.extend_upload_reservation(token, 5).unwrap();
        }

        assert_eq!(
            database
                .update_share_controls(
                    share_id,
                    None,
                    Some(&UploadConflictStrategy::OverwriteAllowed),
                    Some((5, 1)),
                )
                .unwrap(),
            ShareControlsUpdateOutcome::QuotaConflict
        );
        let share = database.share_by_token("atomic-share").unwrap().unwrap();
        assert_eq!(
            share.upload_conflict_strategy,
            UploadConflictStrategy::Reject
        );
        assert_eq!(share.max_upload_total_size, Some(20));
        assert_eq!(share.max_upload_files, Some(3));

        assert!(database.cancel_upload_reservation("upload-two").unwrap());
        assert_eq!(
            database
                .update_share_controls(
                    share_id,
                    None,
                    Some(&UploadConflictStrategy::OverwriteAllowed),
                    Some((5, 1)),
                )
                .unwrap(),
            ShareControlsUpdateOutcome::Updated
        );
        let share = database.share_by_token("atomic-share").unwrap().unwrap();
        assert_eq!(
            share.upload_conflict_strategy,
            UploadConflictStrategy::OverwriteAllowed
        );
        assert_eq!(share.max_upload_total_size, Some(5));
        assert_eq!(share.max_upload_files, Some(1));

        database
            .conn()
            .execute(
                "UPDATE public_upload_reservations SET expires_at=?2 WHERE token_hash=?1",
                params![
                    token_hash("upload-one"),
                    (Utc::now() - Duration::seconds(1)).to_rfc3339()
                ],
            )
            .unwrap();
        assert_eq!(
            database
                .update_share_controls(share_id, None, None, Some((1, 1)))
                .unwrap(),
            ShareControlsUpdateOutcome::Updated
        );
        let share = database.share_by_token("atomic-share").unwrap().unwrap();
        assert_eq!(share.max_upload_total_size, Some(1));
        assert_eq!(share.max_upload_files, Some(1));
    }

    #[test]
    fn invalid_atomic_share_insert_leaves_no_row() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        assert!(database
            .create_share_with_upload_limits(
                "invalid-share",
                None,
                "folder",
                true,
                &Permission::UploadOnly,
                None,
                None,
                Some(10),
                Some(9),
                Some(2),
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .is_err());
        assert!(database.share_by_token("invalid-share").unwrap().is_none());
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
                "preview-owner",
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
    fn preview_sessions_are_expiry_cleaned_and_bounded_per_share_path() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let share_id = database
            .create_share(
                "bounded-preview-share",
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
        let path = "folder/image.png";
        for index in 0..MAX_ACTIVE_PREVIEW_SESSIONS_PER_RESOURCE {
            database
                .create_preview_session(
                    &format!("owner-b-preview-{index}"),
                    "owner-b",
                    share_id,
                    path,
                    Utc::now() + Duration::minutes(30 + index),
                )
                .unwrap();
        }
        for index in 0..10 {
            database
                .create_preview_session(
                    &format!("preview-{index}"),
                    "owner-a",
                    share_id,
                    path,
                    Utc::now() + Duration::minutes(10 + index),
                )
                .unwrap();
        }

        let active: u64 = database
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM public_preview_sessions
                 WHERE share_id=?1 AND relative_path=?2
                   AND owner_key_hash=?3 AND expires_at>?4",
                params![
                    share_id,
                    path,
                    token_hash("owner-a"),
                    Utc::now().to_rfc3339()
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active, MAX_ACTIVE_PREVIEW_SESSIONS_PER_RESOURCE as u64);
        assert!(!database
            .preview_session("preview-0", share_id, path)
            .unwrap());
        assert!(!database
            .preview_session("preview-1", share_id, path)
            .unwrap());
        assert!(database
            .preview_session("preview-9", share_id, path)
            .unwrap());
        for index in 0..MAX_ACTIVE_PREVIEW_SESSIONS_PER_RESOURCE {
            assert!(database
                .preview_session(&format!("owner-b-preview-{index}"), share_id, path)
                .unwrap());
        }

        database
            .conn()
            .execute(
                "INSERT INTO public_preview_sessions(
                     token_hash,share_id,relative_path,expires_at
                 ) VALUES(?1,?2,?3,?4)",
                params![
                    token_hash("expired-preview"),
                    share_id,
                    "folder/expired.png",
                    (Utc::now() - Duration::minutes(1)).to_rfc3339()
                ],
            )
            .unwrap();
        database
            .create_preview_session(
                "other-path",
                "owner-a",
                share_id,
                "folder/other.png",
                Utc::now() + Duration::minutes(5),
            )
            .unwrap();
        let expired: u64 = database
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM public_preview_sessions WHERE expires_at<=?1",
                [Utc::now().to_rfc3339()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(expired, 0);
        let index_exists: bool = database
            .conn()
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM sqlite_schema
                     WHERE type='index' AND name='idx_preview_share_path_owner'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(index_exists);
    }

    #[test]
    fn preview_sessions_are_bounded_per_owner_and_share_without_cross_owner_eviction() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let share_id = database
            .create_share(
                "owner-bounded-preview-share",
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
        let expires = Utc::now() + Duration::hours(1);
        assert_eq!(
            database
                .create_preview_session(
                    "foreign-preview",
                    "owner-b",
                    share_id,
                    "folder/foreign.png",
                    expires,
                )
                .unwrap(),
            PreviewSessionCreateOutcome::Created
        );
        for index in 0..56 {
            assert_eq!(
                database
                    .create_preview_session(
                        &format!("owner-a-path-{index}"),
                        "owner-a",
                        share_id,
                        &format!("folder/path-{index}.png"),
                        expires,
                    )
                    .unwrap(),
                PreviewSessionCreateOutcome::Created
            );
        }
        for index in 0..MAX_ACTIVE_PREVIEW_SESSIONS_PER_RESOURCE {
            assert_eq!(
                database
                    .create_preview_session(
                        &format!("owner-a-bucket-{index}"),
                        "owner-a",
                        share_id,
                        "folder/bucket.png",
                        expires + Duration::minutes(index),
                    )
                    .unwrap(),
                PreviewSessionCreateOutcome::Created
            );
        }

        assert_eq!(
            database
                .create_preview_session(
                    "owner-a-over-capacity",
                    "owner-a",
                    share_id,
                    "folder/new-path.png",
                    expires,
                )
                .unwrap(),
            PreviewSessionCreateOutcome::OwnerCapacityReached
        );
        assert!(database
            .preview_session("foreign-preview", share_id, "folder/foreign.png")
            .unwrap());
        assert_eq!(
            database
                .create_preview_session(
                    "owner-a-bucket-replacement",
                    "owner-a",
                    share_id,
                    "folder/bucket.png",
                    expires + Duration::hours(2),
                )
                .unwrap(),
            PreviewSessionCreateOutcome::Created
        );
        assert!(!database
            .preview_session("owner-a-bucket-0", share_id, "folder/bucket.png")
            .unwrap());
        let owner_rows: i64 = database
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM public_preview_sessions
                 WHERE share_id=?1 AND owner_key_hash=?2",
                params![share_id, token_hash("owner-a")],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(owner_rows, MAX_ACTIVE_PREVIEW_SESSIONS_PER_OWNER_SHARE);
    }

    #[test]
    fn preview_sessions_enforce_per_share_capacity_without_cross_share_eviction() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let create_share = |token: &str, path: &str| {
            database
                .create_share(
                    token,
                    None,
                    path,
                    true,
                    &Permission::DownloadOnly,
                    None,
                    None,
                    None,
                    1,
                    None,
                    &UploadConflictStrategy::Reject,
                )
                .unwrap()
        };
        let full_share_id = create_share("full-preview-share", "full-folder");
        let isolated_share_id = create_share("isolated-preview-share", "isolated-folder");
        let expires = (Utc::now() + Duration::hours(1)).to_rfc3339();
        {
            let mut connection = database.conn();
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            {
                let mut insert = transaction
                    .prepare(
                        "INSERT INTO public_preview_sessions(
                             token_hash,share_id,relative_path,expires_at,owner_key_hash
                         ) VALUES(?1,?2,'full-folder/image.png',?3,?4)",
                    )
                    .unwrap();
                for index in 0..MAX_ACTIVE_PREVIEW_SESSIONS_PER_SHARE {
                    insert
                        .execute(params![
                            format!("share-cap-token-{index}"),
                            full_share_id,
                            expires,
                            format!("share-cap-owner-{index}")
                        ])
                        .unwrap();
                }
            }
            transaction.commit().unwrap();
        }

        assert_eq!(
            database
                .create_preview_session(
                    "share-over-capacity",
                    "new-owner",
                    full_share_id,
                    "full-folder/new.png",
                    Utc::now() + Duration::hours(1),
                )
                .unwrap(),
            PreviewSessionCreateOutcome::ShareCapacityReached
        );
        let retained_full_share_row: bool = database
            .conn()
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM public_preview_sessions
                     WHERE token_hash='share-cap-token-0'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(retained_full_share_row);
        assert_eq!(
            database
                .create_preview_session(
                    "isolated-share-preview",
                    "new-owner",
                    isolated_share_id,
                    "isolated-folder/image.png",
                    Utc::now() + Duration::hours(1),
                )
                .unwrap(),
            PreviewSessionCreateOutcome::Created
        );
        let full_share_rows: i64 = database
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM public_preview_sessions WHERE share_id=?1",
                [full_share_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(full_share_rows, MAX_ACTIVE_PREVIEW_SESSIONS_PER_SHARE);
        assert!(database
            .preview_session(
                "isolated-share-preview",
                isolated_share_id,
                "isolated-folder/image.png"
            )
            .unwrap());
    }

    #[test]
    fn preview_sessions_enforce_global_capacity_after_expiry_purge() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let target_share_id = database
            .create_share(
                "globally-bounded-preview-share",
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
        let source_share_ids: Vec<i64> = (0..20)
            .map(|index| {
                database
                    .create_share(
                        &format!("global-preview-source-{index}"),
                        None,
                        &format!("source-folder-{index}"),
                        true,
                        &Permission::DownloadOnly,
                        None,
                        None,
                        None,
                        1,
                        None,
                        &UploadConflictStrategy::Reject,
                    )
                    .unwrap()
            })
            .collect();
        let expires = (Utc::now() + Duration::hours(1)).to_rfc3339();
        {
            let mut connection = database.conn();
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            {
                let mut insert = transaction
                    .prepare(
                        "INSERT INTO public_preview_sessions(
                             token_hash,share_id,relative_path,expires_at,owner_key_hash
                         ) VALUES(?1,?2,'folder/image.png',?3,?4)",
                    )
                    .unwrap();
                for index in 0..MAX_ACTIVE_PREVIEW_SESSIONS_GLOBAL {
                    let source_share_id = source_share_ids[index as usize % source_share_ids.len()];
                    insert
                        .execute(params![
                            format!("global-token-{index}"),
                            source_share_id,
                            expires,
                            format!("global-owner-{index}")
                        ])
                        .unwrap();
                }
            }
            transaction.commit().unwrap();
        }

        assert_eq!(
            database
                .create_preview_session(
                    "global-over-capacity",
                    "new-owner",
                    target_share_id,
                    "folder/new.png",
                    Utc::now() + Duration::hours(1),
                )
                .unwrap(),
            PreviewSessionCreateOutcome::GlobalCapacityReached
        );
        let retained_foreign_row: bool = database
            .conn()
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM public_preview_sessions
                     WHERE token_hash='global-token-0'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(retained_foreign_row);

        let expired = (Utc::now() - Duration::minutes(1)).to_rfc3339();
        let updated = database
            .conn()
            .execute(
                "UPDATE public_preview_sessions SET expires_at=?2 WHERE token_hash=?1",
                params!["global-token-0", expired],
            )
            .unwrap();
        assert_eq!(updated, 1);
        let now = Utc::now().to_rfc3339();
        let expired_rows: i64 = database
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM public_preview_sessions WHERE expires_at<=?1",
                [&now],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(expired_rows, 1, "expired={expired};now={now}");
        assert_eq!(
            database
                .create_preview_session(
                    "global-after-expiry",
                    "new-owner",
                    target_share_id,
                    "folder/new.png",
                    Utc::now() + Duration::hours(1),
                )
                .unwrap(),
            PreviewSessionCreateOutcome::Created
        );
        let global_rows: i64 = database
            .conn()
            .query_row("SELECT COUNT(*) FROM public_preview_sessions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(global_rows, MAX_ACTIVE_PREVIEW_SESSIONS_GLOBAL);
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
            database.current_transfer_monthly_counts().unwrap().total(),
            0
        );

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
            database.current_transfer_monthly_counts().unwrap().download,
            1
        );
        assert_eq!(
            database.complete_transfer_lease("lease-two").unwrap(),
            TransferLeaseCompleteOutcome::AlreadyCounted
        );
        assert_eq!(
            database.current_transfer_monthly_counts().unwrap().download,
            1
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
            database.complete_transfer_lease("resume").unwrap(),
            TransferLeaseCompleteOutcome::AlreadyCounted
        );
        assert_eq!(
            database.current_transfer_monthly_counts().unwrap().download,
            1
        );
        assert_eq!(
            database
                .begin_transfer_lease("client", "new-resource", share_id, "other.bin", "download")
                .unwrap(),
            TransferLeaseBeginOutcome::LimitReached
        );
    }

    #[test]
    fn completed_transfers_increment_each_supported_monthly_action() {
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

        for (index, action) in ["download", "zip_download", "preview"]
            .into_iter()
            .enumerate()
        {
            let session = format!("client-{index}");
            let lease = format!("lease-{index}");
            let resource = format!("resource-{index}");
            assert_eq!(
                database
                    .begin_transfer_lease(&session, &lease, share_id, &resource, action)
                    .unwrap(),
                TransferLeaseBeginOutcome::NewLease
            );
            assert_eq!(
                database.complete_transfer_lease(&lease).unwrap(),
                TransferLeaseCompleteOutcome::Counted
            );
        }

        let counts = database.current_transfer_monthly_counts().unwrap();
        assert_eq!(counts.month, current_utc_month());
        assert_eq!(counts.download, 1);
        assert_eq!(counts.zip_download, 1);
        assert_eq!(counts.preview, 1);
        assert_eq!(counts.total(), 3);
        assert_eq!(
            database.transfer_monthly_counts("2000-01").unwrap().total(),
            0
        );
        assert!(database.transfer_monthly_counts("2026-00").is_err());
        assert!(database.transfer_monthly_counts("2026-1").is_err());
    }

    #[test]
    fn monthly_count_failure_rolls_back_the_counted_transfer() {
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
                .begin_transfer_lease("client", "lease", share_id, "file.bin", "download")
                .unwrap(),
            TransferLeaseBeginOutcome::NewLease
        );
        database
            .conn()
            .execute("DROP TABLE transfer_monthly_counts", [])
            .unwrap();

        assert!(database.complete_transfer_lease("lease").is_err());
        assert_eq!(
            database
                .share_by_token("share")
                .unwrap()
                .unwrap()
                .download_count,
            0
        );
        let counted: i64 = database
            .conn()
            .query_row(
                "SELECT counted FROM public_transfer_grants WHERE share_id=?1",
                [share_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(counted, 0);
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
        assert_eq!(
            database.current_transfer_monthly_counts().unwrap().total(),
            0
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

    #[test]
    fn transfer_heartbeat_cannot_extend_lease_past_absolute_lifetime() {
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
        let older_than_absolute_limit =
            Utc::now() - Duration::seconds(TRANSFER_LEASE_MAX_LIFETIME_SECONDS + 1);
        {
            let connection = database.conn();
            connection
                .execute(
                    "UPDATE public_transfer_leases
                     SET created_at=?1,expires_at='2000-01-01T00:00:00Z'",
                    [older_than_absolute_limit.to_rfc3339()],
                )
                .unwrap();
            connection
                .execute(
                    "UPDATE public_transfer_grants SET expires_at='2099-01-01T00:00:00Z'",
                    [],
                )
                .unwrap();
        }

        assert_eq!(
            database.heartbeat_transfer_lease("lease").unwrap(),
            TransferLeaseHeartbeatOutcome::CappedAndCounted
        );
        assert_eq!(database.active_transfer_reservations(share_id).unwrap(), 0);
        assert_eq!(
            database
                .share_by_token("share")
                .unwrap()
                .unwrap()
                .download_count,
            1
        );
        assert_eq!(
            database.complete_transfer_lease("lease").unwrap(),
            TransferLeaseCompleteOutcome::NotFound
        );
        assert_eq!(
            database
                .begin_transfer_lease("other", "other-lease", share_id, "file.bin", "download")
                .unwrap(),
            TransferLeaseBeginOutcome::LimitReached
        );
    }

    #[test]
    fn webauthn_credentials_are_scoped_unique_and_mutable() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        database.create_admin("other", "hash", "secret").unwrap();

        let id = database
            .add_admin_webauthn_credential(1, "Primary YubiKey", "credential-a", "{\"v\":1}")
            .unwrap();
        let rows = database.admin_webauthn_credentials(1).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, id);
        assert_eq!(rows[0].label, "Primary YubiKey");
        assert!(rows[0].last_used_at.is_none());
        assert!(database.admin_webauthn_credentials(2).unwrap().is_empty());
        assert!(database
            .add_admin_webauthn_credential(1, "", "credential-empty-label", "{}")
            .is_err());
        assert!(database
            .add_admin_webauthn_credential(1, &"x".repeat(81), "credential-long-label", "{}")
            .is_err());

        assert!(database
            .add_admin_webauthn_credential(2, "Duplicate", "credential-a", "{}")
            .is_err());
        assert!(!database
            .update_admin_webauthn_credential(id, 2, "{\"v\":2}")
            .unwrap());
        assert!(database
            .update_admin_webauthn_credential(id, 1, "{\"v\":2}")
            .unwrap());
        let rows = database.admin_webauthn_credentials(1).unwrap();
        assert_eq!(rows[0].credential_json, "{\"v\":2}");
        assert!(rows[0].last_used_at.is_some());

        assert!(!database.delete_admin_webauthn_credential(id, 2).unwrap());
        assert!(database.delete_admin_webauthn_credential(id, 1).unwrap());
        assert!(database.admin_webauthn_credentials(1).unwrap().is_empty());

        let first = database
            .add_admin_webauthn_credential(1, "Primary", "credential-c", "{}")
            .unwrap();
        database
            .add_admin_webauthn_credential(1, "Backup", "credential-d", "{}")
            .unwrap();
        assert!(!database.delete_admin_webauthn_credential(first, 1).unwrap());
        database
            .add_admin_webauthn_credential(1, "Replacement", "credential-e", "{}")
            .unwrap();
        assert!(database.delete_admin_webauthn_credential(first, 1).unwrap());
        assert_eq!(database.admin_webauthn_credentials(1).unwrap().len(), 2);

        database
            .add_admin_webauthn_credential(2, "Backup", "credential-b", "{}")
            .unwrap();
        database
            .conn()
            .execute("DELETE FROM admins WHERE id=2", [])
            .unwrap();
        assert!(database.admin_webauthn_credentials(2).unwrap().is_empty());
    }

    #[test]
    fn security_mutation_webauthn_deletion_consumes_totp_and_audits_atomically() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        database
            .create_session(
                "authorized-session",
                1,
                "csrf",
                Utc::now() + Duration::hours(1),
            )
            .unwrap();
        assert!(database.verify_mfa("authorized-session").unwrap());
        let first = database
            .add_admin_webauthn_credential(1, "First", "credential-a", "{}")
            .unwrap();
        let second = database
            .add_admin_webauthn_credential(1, "Second", "credential-b", "{}")
            .unwrap();
        let third = database
            .add_admin_webauthn_credential(1, "Third", "credential-c", "{}")
            .unwrap();
        let delete = |credential_id, step, client_ip| {
            database.delete_admin_webauthn_credential_with_totp(
                "authorized-session",
                credential_id,
                1,
                "hash",
                "secret",
                step,
                client_ip,
            )
        };

        assert_eq!(
            delete(first, 42, Some("203.0.113.40")).unwrap(),
            AdminWebauthnCredentialDeletionOutcome::Deleted
        );
        let audit = database
            .list_audit(Some("webauthn_credential_deleted"), 10, 0)
            .unwrap();
        assert_eq!(audit.len(), 1);
        let first_object = first.to_string();
        assert_eq!(audit[0].object_id.as_deref(), Some(first_object.as_str()));
        assert_eq!(audit[0].client_ip.as_deref(), Some("203.0.113.40"));

        assert_eq!(
            delete(second, 42, None).unwrap(),
            AdminWebauthnCredentialDeletionOutcome::TotpRejected
        );
        assert_eq!(
            delete(second, 43, None).unwrap(),
            AdminWebauthnCredentialDeletionOutcome::NotDeleted
        );
        database
            .add_admin_webauthn_credential(1, "Fourth", "credential-d", "{}")
            .unwrap();

        assert_eq!(
            delete(second, 43, None).unwrap(),
            AdminWebauthnCredentialDeletionOutcome::Deleted
        );
        database
            .add_admin_webauthn_credential(1, "Fifth", "credential-e", "{}")
            .unwrap();

        database
            .conn()
            .execute_batch(
                "CREATE TRIGGER fail_webauthn_delete_audit
                 BEFORE INSERT ON audit
                 WHEN NEW.action='webauthn_credential_deleted'
                 BEGIN
                     SELECT RAISE(ABORT, 'forced audit failure');
                 END;",
            )
            .unwrap();
        assert!(delete(third, 44, None).is_err());
        assert_eq!(database.admin_webauthn_credentials(1).unwrap().len(), 3);
        database
            .conn()
            .execute_batch("DROP TRIGGER fail_webauthn_delete_audit")
            .unwrap();

        assert_eq!(
            delete(third, 44, None).unwrap(),
            AdminWebauthnCredentialDeletionOutcome::Deleted
        );
        assert_eq!(
            database
                .count_audit(Some("webauthn_credential_deleted"))
                .unwrap(),
            3
        );
    }

    #[test]
    fn security_mutation_webauthn_deletion_rejects_stale_credentials_and_session() {
        let database = Database::open(":memory:").unwrap();
        database
            .create_admin("admin", "original-hash", "original-secret")
            .unwrap();
        database
            .create_session("stale-session", 1, "csrf", Utc::now() + Duration::hours(1))
            .unwrap();
        assert!(database.verify_mfa("stale-session").unwrap());
        let first = database
            .add_admin_webauthn_credential(1, "First", "credential-a", "{}")
            .unwrap();
        database
            .add_admin_webauthn_credential(1, "Second", "credential-b", "{}")
            .unwrap();
        database
            .add_admin_webauthn_credential(1, "Third", "credential-c", "{}")
            .unwrap();

        assert_eq!(
            database
                .delete_admin_webauthn_credential_with_totp(
                    "stale-session",
                    first,
                    1,
                    "wrong-hash",
                    "original-secret",
                    42,
                    None,
                )
                .unwrap(),
            AdminWebauthnCredentialDeletionOutcome::ReauthenticationRejected
        );
        assert_eq!(
            database
                .delete_admin_webauthn_credential_with_totp(
                    "stale-session",
                    first,
                    1,
                    "original-hash",
                    "wrong-secret",
                    42,
                    None,
                )
                .unwrap(),
            AdminWebauthnCredentialDeletionOutcome::ReauthenticationRejected
        );

        assert!(database
            .reset_admin_password(1, "replacement-hash")
            .unwrap());
        assert_eq!(
            database
                .delete_admin_webauthn_credential_with_totp(
                    "stale-session",
                    first,
                    1,
                    "original-hash",
                    "original-secret",
                    42,
                    None,
                )
                .unwrap(),
            AdminWebauthnCredentialDeletionOutcome::ReauthenticationRejected
        );
        assert_eq!(database.admin_webauthn_credentials(1).unwrap().len(), 3);
        assert_eq!(
            database
                .count_audit(Some("webauthn_credential_deleted"))
                .unwrap(),
            0
        );

        database
            .create_session(
                "replacement-session",
                1,
                "csrf",
                Utc::now() + Duration::hours(1),
            )
            .unwrap();
        assert!(database.verify_mfa("replacement-session").unwrap());
        assert_eq!(
            database
                .delete_admin_webauthn_credential_with_totp(
                    "replacement-session",
                    first,
                    1,
                    "replacement-hash",
                    "original-secret",
                    42,
                    None,
                )
                .unwrap(),
            AdminWebauthnCredentialDeletionOutcome::Deleted
        );
    }

    #[test]
    fn webauthn_registration_cannot_restore_keys_after_mfa_reset() {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let expires = Utc::now() + chrono::Duration::hours(1);

        database
            .create_session("authorized-session", 1, "csrf", expires)
            .unwrap();
        assert!(database.verify_mfa("authorized-session").unwrap());
        assert!(matches!(
            database
                .add_admin_webauthn_credential_for_session(
                    "authorized-session",
                    1,
                    "Primary",
                    "credential-a",
                    "{}",
                    Some("203.0.113.24"),
                )
                .unwrap(),
            AdminWebauthnCredentialRegistrationOutcome::Registered(_)
        ));
        assert_eq!(
            database
                .count_audit(Some("webauthn_credential_added"))
                .unwrap(),
            1
        );
        assert_eq!(
            database
                .list_audit(Some("webauthn_credential_added"), 1, 0)
                .unwrap()[0]
                .client_ip
                .as_deref(),
            Some("203.0.113.24")
        );

        database
            .create_session("stale-session", 1, "csrf", expires)
            .unwrap();
        assert!(database.verify_mfa("stale-session").unwrap());
        assert_eq!(
            database.reset_admin_totp(1, "replacement-secret").unwrap(),
            Some("admin".to_string())
        );
        assert!(database.admin_webauthn_credentials(1).unwrap().is_empty());

        assert_eq!(
            database
                .add_admin_webauthn_credential_for_session(
                    "stale-session",
                    1,
                    "Stale",
                    "credential-stale",
                    "{}",
                    None,
                )
                .unwrap(),
            AdminWebauthnCredentialRegistrationOutcome::SessionUnavailable
        );
        assert!(database.admin_webauthn_credentials(1).unwrap().is_empty());
        assert_eq!(
            database
                .count_audit(Some("webauthn_credential_added"))
                .unwrap(),
            1
        );

        database
            .create_session("pre-mfa-session", 1, "csrf", expires)
            .unwrap();
        assert_eq!(
            database
                .add_admin_webauthn_credential_for_session(
                    "pre-mfa-session",
                    1,
                    "Pre MFA",
                    "credential-pre-mfa",
                    "{}",
                    None,
                )
                .unwrap(),
            AdminWebauthnCredentialRegistrationOutcome::SessionUnavailable
        );
    }
}
