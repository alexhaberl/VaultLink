mod audit;
mod auth;
mod keyring;
mod public_sessions;
mod required_audit;
mod runtime_settings;
mod schema;
mod service_tokens;
mod shares;
mod transfers;

use required_audit::{insert_required_audits, trace_required_audits};
pub use required_audit::{is_audit_unavailable, AuditContext, RequiredAuditEvent};
#[cfg(any(test, feature = "fuzzing"))]
pub use shares::rewrite_share_path;

#[cfg(test)]
use audit::enforce_audit_retention;
#[cfg(test)]
use transfers::current_utc_month;

#[cfg(test)]
use chrono::Duration;
use chrono::{DateTime, Utc};
use r2d2_sqlite::SqliteConnectionManager;
#[cfg(test)]
use rusqlite::{params, TransactionBehavior};
use rusqlite::{Connection, OpenFlags};
#[cfg(test)]
use schema::SCHEMA_VERSION;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io,
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, Mutex, MutexGuard,
    },
};

pub(crate) const MAX_SQLITE_UNSIGNED: u64 = i64::MAX as u64;
pub(crate) const MAX_AUDIT_ROWS: i64 = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i64)]
pub(crate) enum AuditPriority {
    Routine = 0,
    Security = 100,
}

impl AuditPriority {
    const fn as_i64(self) -> i64 {
        self as i64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuditAction {
    AccountMfaChanged,
    AccountMfaEnrollmentStarted,
    AccountPasswordChanged,
    AccountTotpSettingReauthFailed,
    AdminActivated,
    AdminCreated,
    AdminDeactivated,
    AdminDownload,
    AdminPasswordReset,
    AdminPreview,
    AdminRecovered,
    AdminTotpDisabled,
    AdminTotpEnabled,
    AdminTotpReset,
    AdminUpload,
    AdminUploadDurabilityUncertain,
    AdminUploadReplaced,
    AuditClientIpsDeleted,
    DirectoryCreated,
    Download,
    InitialAdminCreated,
    LoginFailed,
    LoginSuccess,
    LoginSuccessWebauthn,
    Logout,
    MfaFailed,
    MfaReplayed,
    PasswordVerified,
    PathDeleted,
    PathRenamed,
    Preview,
    SecurityKeyReauthFailed,
    ServiceTokenCreated,
    ServiceTokenRevoked,
    ServiceTokensRevokedAll,
    SettingsUpdated,
    ShareActivated,
    ShareCreated,
    ShareDeactivated,
    ShareDeleted,
    SharePasswordRemoved,
    SharePasswordSet,
    ShareToggled,
    ShareUnlockFailed,
    ShareUnlocked,
    ShareUploadConflictUpdated,
    ShareUploadLimitsUpdated,
    Upload,
    UploadDirectoriesCreated,
    UploadDurabilityUncertain,
    UploadQuotaCommitted,
    UploadReplaced,
    WebauthnCredentialAdded,
    WebauthnCredentialDeleted,
    ZipDownload,
}

impl AuditAction {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AccountMfaChanged => "account_mfa_changed",
            Self::AccountMfaEnrollmentStarted => "account_mfa_enrollment_started",
            Self::AccountPasswordChanged => "account_password_changed",
            Self::AccountTotpSettingReauthFailed => "account_totp_setting_reauth_failed",
            Self::AdminActivated => "admin_activated",
            Self::AdminCreated => "admin_created",
            Self::AdminDeactivated => "admin_deactivated",
            Self::AdminDownload => "admin_download",
            Self::AdminPasswordReset => "admin_password_reset",
            Self::AdminPreview => "admin_preview",
            Self::AdminRecovered => "admin_recovered",
            Self::AdminTotpDisabled => "admin_totp_disabled",
            Self::AdminTotpEnabled => "admin_totp_enabled",
            Self::AdminTotpReset => "admin_totp_reset",
            Self::AdminUpload => "admin_upload",
            Self::AdminUploadDurabilityUncertain => "admin_upload_durability_uncertain",
            Self::AdminUploadReplaced => "admin_upload_replaced",
            Self::AuditClientIpsDeleted => "audit_client_ips_deleted",
            Self::DirectoryCreated => "directory_created",
            Self::Download => "download",
            Self::InitialAdminCreated => "initial_admin_created",
            Self::LoginFailed => "login_failed",
            Self::LoginSuccess => "login_success",
            Self::LoginSuccessWebauthn => "login_success_webauthn",
            Self::Logout => "logout",
            Self::MfaFailed => "mfa_failed",
            Self::MfaReplayed => "mfa_replayed",
            Self::PasswordVerified => "password_verified",
            Self::PathDeleted => "path_deleted",
            Self::PathRenamed => "path_renamed",
            Self::Preview => "preview",
            Self::SecurityKeyReauthFailed => "security_key_reauth_failed",
            Self::ServiceTokenCreated => "service_token_created",
            Self::ServiceTokenRevoked => "service_token_revoked",
            Self::ServiceTokensRevokedAll => "service_tokens_revoked_all",
            Self::SettingsUpdated => "settings_updated",
            Self::ShareActivated => "share_activated",
            Self::ShareCreated => "share_created",
            Self::ShareDeactivated => "share_deactivated",
            Self::ShareDeleted => "share_deleted",
            Self::SharePasswordRemoved => "share_password_removed",
            Self::SharePasswordSet => "share_password_set",
            Self::ShareToggled => "share_toggled",
            Self::ShareUnlockFailed => "share_unlock_failed",
            Self::ShareUnlocked => "share_unlocked",
            Self::ShareUploadConflictUpdated => "share_upload_conflict_updated",
            Self::ShareUploadLimitsUpdated => "share_upload_limits_updated",
            Self::Upload => "upload",
            Self::UploadDirectoriesCreated => "upload_directories_created",
            Self::UploadDurabilityUncertain => "upload_durability_uncertain",
            Self::UploadQuotaCommitted => "upload_quota_committed",
            Self::UploadReplaced => "upload_replaced",
            Self::WebauthnCredentialAdded => "webauthn_credential_added",
            Self::WebauthnCredentialDeleted => "webauthn_credential_deleted",
            Self::ZipDownload => "zip_download",
        }
    }

    const fn priority(self) -> AuditPriority {
        match self {
            Self::AdminDownload
            | Self::AdminPreview
            | Self::Download
            | Self::Preview
            | Self::UploadQuotaCommitted
            | Self::ZipDownload => AuditPriority::Routine,
            Self::AccountMfaChanged
            | Self::AccountMfaEnrollmentStarted
            | Self::AccountPasswordChanged
            | Self::AccountTotpSettingReauthFailed
            | Self::AdminActivated
            | Self::AdminCreated
            | Self::AdminDeactivated
            | Self::AdminPasswordReset
            | Self::AdminRecovered
            | Self::AdminTotpDisabled
            | Self::AdminTotpEnabled
            | Self::AdminTotpReset
            | Self::AdminUpload
            | Self::AdminUploadDurabilityUncertain
            | Self::AdminUploadReplaced
            | Self::AuditClientIpsDeleted
            | Self::DirectoryCreated
            | Self::InitialAdminCreated
            | Self::LoginFailed
            | Self::LoginSuccess
            | Self::LoginSuccessWebauthn
            | Self::Logout
            | Self::MfaFailed
            | Self::MfaReplayed
            | Self::PasswordVerified
            | Self::PathDeleted
            | Self::PathRenamed
            | Self::SecurityKeyReauthFailed
            | Self::ServiceTokenCreated
            | Self::ServiceTokenRevoked
            | Self::ServiceTokensRevokedAll
            | Self::SettingsUpdated
            | Self::ShareActivated
            | Self::ShareCreated
            | Self::ShareDeactivated
            | Self::ShareDeleted
            | Self::SharePasswordRemoved
            | Self::SharePasswordSet
            | Self::ShareToggled
            | Self::ShareUnlockFailed
            | Self::ShareUnlocked
            | Self::ShareUploadConflictUpdated
            | Self::ShareUploadLimitsUpdated
            | Self::Upload
            | Self::UploadDirectoriesCreated
            | Self::UploadDurabilityUncertain
            | Self::UploadReplaced
            | Self::WebauthnCredentialAdded
            | Self::WebauthnCredentialDeleted => AuditPriority::Security,
        }
    }

    #[cfg(test)]
    const ALL: &'static [Self] = &[
        Self::AccountMfaChanged,
        Self::AccountMfaEnrollmentStarted,
        Self::AccountPasswordChanged,
        Self::AccountTotpSettingReauthFailed,
        Self::AdminActivated,
        Self::AdminCreated,
        Self::AdminDeactivated,
        Self::AdminDownload,
        Self::AdminPasswordReset,
        Self::AdminPreview,
        Self::AdminRecovered,
        Self::AdminTotpDisabled,
        Self::AdminTotpEnabled,
        Self::AdminTotpReset,
        Self::AdminUpload,
        Self::AdminUploadDurabilityUncertain,
        Self::AdminUploadReplaced,
        Self::AuditClientIpsDeleted,
        Self::DirectoryCreated,
        Self::Download,
        Self::InitialAdminCreated,
        Self::LoginFailed,
        Self::LoginSuccess,
        Self::LoginSuccessWebauthn,
        Self::Logout,
        Self::MfaFailed,
        Self::MfaReplayed,
        Self::PasswordVerified,
        Self::PathDeleted,
        Self::PathRenamed,
        Self::Preview,
        Self::SecurityKeyReauthFailed,
        Self::ServiceTokenCreated,
        Self::ServiceTokenRevoked,
        Self::ServiceTokensRevokedAll,
        Self::SettingsUpdated,
        Self::ShareActivated,
        Self::ShareCreated,
        Self::ShareDeactivated,
        Self::ShareDeleted,
        Self::SharePasswordRemoved,
        Self::SharePasswordSet,
        Self::ShareToggled,
        Self::ShareUnlockFailed,
        Self::ShareUnlocked,
        Self::ShareUploadConflictUpdated,
        Self::ShareUploadLimitsUpdated,
        Self::Upload,
        Self::UploadDirectoriesCreated,
        Self::UploadDurabilityUncertain,
        Self::UploadQuotaCommitted,
        Self::UploadReplaced,
        Self::WebauthnCredentialAdded,
        Self::WebauthnCredentialDeleted,
        Self::ZipDownload,
    ];
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditRetentionOutcome {
    pub routine_deleted: usize,
    pub security_deleted: usize,
}

impl AuditRetentionOutcome {
    pub fn total_deleted(self) -> usize {
        self.routine_deleted.saturating_add(self.security_deleted)
    }
}

/// Existing and newly-created upload shares receive finite cumulative defaults.
/// Administrators can tighten or raise them explicitly through the share API/UI.
pub const DEFAULT_SHARE_UPLOAD_TOTAL_SIZE: u64 = 100_000_000_000;
pub const DEFAULT_SHARE_UPLOAD_FILE_COUNT: u64 = 1_000;
const MAX_ACTIVE_PREVIEW_SESSIONS_PER_RESOURCE: i64 = 8;
const MAX_ACTIVE_PREVIEW_SESSIONS_PER_OWNER_SHARE: i64 = 64;
const MAX_ACTIVE_PREVIEW_SESSIONS_PER_SHARE: i64 = 512;
const MAX_ACTIVE_PREVIEW_SESSIONS_GLOBAL: i64 = 10_000;

pub const TRANSFER_SESSION_TTL_SECONDS: i64 = 15 * 60;
pub const TRANSFER_LEASE_MAX_LIFETIME_SECONDS: i64 = 24 * 60 * 60;
pub const ADMIN_MFA_ENROLLMENT_TTL_SECONDS: i64 = 10 * 60;
pub const SERVICE_TOKEN_SCOPE_MONITORING_READ: i64 = 1;
pub const MAX_SERVICE_TOKENS: usize = 64;
pub const SERVICE_TOKEN_NAME_MIN_CHARACTERS: usize = 1;
pub const SERVICE_TOKEN_NAME_MAX_CHARACTERS: usize = 80;

#[derive(Clone)]
pub struct Database(Arc<DatabaseInner>);

struct DatabaseInner {
    pool: r2d2::Pool<SqliteConnectionManager>,
    // SQLite admits one writer at a time. Transfer requests can otherwise
    // occupy every pooled connection while waiting for that writer slot,
    // starving unrelated metadata reads and readiness checks. Admission must
    // therefore happen before a transfer writer checks out a connection.
    transfer_write_admission: Mutex<()>,
    keyring: keyring::Keyring,
    session_idle_minutes: AtomicI64,
    // Keep the descriptor behind /proc/self/fd alive for the whole connection
    // so the validated directory capability cannot be rebound through file-
    // descriptor reuse while SQLite uses the supplied path.
    _directory_capability: Option<File>,
}

pub type DatabaseResult<T> = std::result::Result<T, DatabaseError>;

#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("database connection pool unavailable: {0}")]
    Pool(#[source] r2d2::Error),
    #[error("database is busy: {0}")]
    Busy(#[source] rusqlite::Error),
    #[error("database invariant violated: {0}")]
    Invariant(#[source] rusqlite::Error),
    #[error("database schema rejected: {0}")]
    Schema(#[source] rusqlite::Error),
    #[error("database secret cryptography failed: {0}")]
    Cryptography(#[source] rusqlite::Error),
    #[error("database is corrupt: {0}")]
    Corruption(#[source] rusqlite::Error),
    #[error("database operation failed: {0}")]
    Sqlite(#[source] rusqlite::Error),
}

impl From<rusqlite::Error> for DatabaseError {
    fn from(error: rusqlite::Error) -> Self {
        if schema::is_schema_error(&error) {
            return Self::Schema(error);
        }
        if keyring::is_crypto_error(&error) {
            return Self::Cryptography(error);
        }
        if let rusqlite::Error::SqliteFailure(sqlite, _) = &error {
            let primary = sqlite.extended_code & 0xff;
            if primary == rusqlite::ffi::SQLITE_BUSY || primary == rusqlite::ffi::SQLITE_LOCKED {
                return Self::Busy(error);
            }
            if primary == rusqlite::ffi::SQLITE_CORRUPT || primary == rusqlite::ffi::SQLITE_NOTADB {
                return Self::Corruption(error);
            }
        }
        if matches!(
            error,
            rusqlite::Error::InvalidQuery
                | rusqlite::Error::QueryReturnedNoRows
                | rusqlite::Error::InvalidParameterName(_)
                | rusqlite::Error::FromSqlConversionFailure(..)
                | rusqlite::Error::IntegralValueOutOfRange(..)
        ) {
            return Self::Invariant(error);
        }
        Self::Sqlite(error)
    }
}

#[derive(Debug)]
pub struct Admin {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub(crate) totp_secret: crate::sensitive::SecretString,
    pub(crate) totp_generation: u64,
    pub totp_enabled: bool,
    pub active: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminTotpSettingOutcome {
    Updated,
    Unchanged,
    ReauthenticationRejected,
    TotpRejected,
    InsufficientSecurityKeys,
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
    pub credential_blob: Vec<u8>,
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
pub enum AuditSortColumn {
    Time,
    Actor,
    Action,
    Object,
    Detail,
    ClientIp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditSortDirection {
    Ascending,
    Descending,
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

#[derive(Debug)]
pub struct PendingAdminMfaEnrollment {
    pub admin_id: i64,
    pub(crate) totp_secret: crate::sensitive::SecretString,
    pub expires_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminMfaEnrollmentStartOutcome {
    Started { expires_at: String },
    AdminInactive,
    AdminNotFound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditedAdminMfaEnrollmentStartOutcome {
    Started { expires_at: String },
    AdminInactive,
    AdminNotFound,
    TotpRejected,
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ShareListStatus {
    #[default]
    All,
    Active,
    Protected,
    Expired,
    LimitReached,
    Inactive,
}

impl ShareListStatus {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "all" => Some(Self::All),
            "active" => Some(Self::Active),
            "protected" => Some(Self::Protected),
            "expired" => Some(Self::Expired),
            "limit" => Some(Self::LimitReached),
            "inactive" => Some(Self::Inactive),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Active => "active",
            Self::Protected => "protected",
            Self::Expired => "expired",
            Self::LimitReached => "limit",
            Self::Inactive => "inactive",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ShareListSort {
    #[default]
    Newest,
    Oldest,
}

impl ShareListSort {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "newest" => Some(Self::Newest),
            "oldest" => Some(Self::Oldest),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ShareListOptions {
    pub query: Option<String>,
    pub status: ShareListStatus,
    pub sort: ShareListSort,
    pub cursor: Option<i64>,
    pub limit: usize,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct SharePage {
    pub shares: Vec<Share>,
    pub next_cursor: Option<i64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShareSummary {
    pub available: usize,
    pub protected: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceToken {
    pub id: i64,
    pub name: String,
    pub scope_mask: i64,
    pub created_by: i64,
    pub created_by_username: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceTokenCreationOutcome {
    Created(ServiceToken),
    ReauthenticationRejected,
    CapacityReached,
    NameConflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceTokenAuthorizationOutcome {
    Authorized { token_id: i64 },
    Unauthorized,
    InsufficientScope,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MonitoringShareListStatus {
    #[default]
    All,
    Available,
    Inactive,
    Expired,
    DownloadLimitReached,
}

impl MonitoringShareListStatus {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "all" => Some(Self::All),
            "available" => Some(Self::Available),
            "inactive" => Some(Self::Inactive),
            "expired" => Some(Self::Expired),
            "download_limit_reached" => Some(Self::DownloadLimitReached),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Available => "available",
            Self::Inactive => "inactive",
            Self::Expired => "expired",
            Self::DownloadLimitReached => "download_limit_reached",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitoringShareStatus {
    Available,
    Inactive,
    Expired,
    DownloadLimitReached,
}

impl MonitoringShareStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Inactive => "inactive",
            Self::Expired => "expired",
            Self::DownloadLimitReached => "download_limit_reached",
        }
    }
}

#[derive(Clone, Debug)]
pub struct MonitoringShareListOptions {
    pub status: MonitoringShareListStatus,
    pub cursor: Option<i64>,
    pub limit: usize,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MonitoringShare {
    pub id: i64,
    pub status: MonitoringShareStatus,
    pub permission: Permission,
    pub is_directory: bool,
    pub password_protected: bool,
    pub created_at: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub download_count: u64,
    pub max_downloads: Option<u64>,
    pub max_upload_size_bytes: Option<u64>,
    pub uploaded_bytes: u64,
    pub max_upload_total_size_bytes: Option<u64>,
    pub uploaded_files: u64,
    pub max_upload_files: Option<u64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MonitoringSharePage {
    pub shares: Vec<MonitoringShare>,
    pub next_cursor: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MonitoringSummary {
    pub total: u64,
    pub available: u64,
    pub inactive: u64,
    pub expired: u64,
    pub download_limit_reached: u64,
    pub protected: u64,
    pub transfers: TransferMonthlyCounts,
    pub statistics_started_at: String,
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

pub(crate) fn token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    data_encoding::HEXLOWER.encode(digest.as_ref())
}

pub fn valid_service_token_name(name: &str) -> bool {
    name == name.trim()
        && (SERVICE_TOKEN_NAME_MIN_CHARACTERS..=SERVICE_TOKEN_NAME_MAX_CHARACTERS)
            .contains(&name.chars().count())
        && !name.chars().any(char::is_control)
}

impl Database {
    pub fn rotate_secrets(path: impl AsRef<Path>) -> DatabaseResult<()> {
        keyring::rotate_database(path.as_ref()).map_err(Into::into)
    }

    pub fn open(path: impl AsRef<Path>) -> DatabaseResult<Self> {
        Self::open_inner(path.as_ref(), None)
    }

    #[doc(hidden)]
    pub fn open_in_directory(directory: File) -> DatabaseResult<Self> {
        let metadata = directory
            .metadata()
            .map_err(database_io_error)
            .map_err(DatabaseError::from)?;
        if !metadata.is_dir() {
            return Err(DatabaseError::from(database_io_error(io::Error::new(
                io::ErrorKind::InvalidInput,
                "validated database directory capability is not a directory",
            ))));
        }
        let effective_uid = rustix::process::geteuid().as_raw();
        if metadata.uid() != effective_uid || metadata.mode() & 0o022 != 0 {
            return Err(DatabaseError::from(database_io_error(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "database directory capability must be service-owned and not writable by group or other users",
            ))));
        }
        let path = PathBuf::from(format!(
            "/proc/self/fd/{}/data.sqlite",
            directory.as_raw_fd()
        ));
        Self::open_inner(&path, Some(directory))
    }

    fn open_inner(path: &Path, directory_capability: Option<File>) -> DatabaseResult<Self> {
        let persistent = path != Path::new(":memory:");
        if persistent {
            match std::fs::symlink_metadata(path) {
                Ok(metadata) => validate_database_metadata(path, &metadata, false)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(DatabaseError::from(database_io_error(error))),
            }
        }
        let flags = if persistent {
            // SQLite's NOFOLLOW mode rejects the intentional /proc/self/fd
            // magic-link used for a validated directory capability. Those
            // opens are already anchored to a service-owned directory FD and
            // receive the same pre/post final-file metadata checks below.
            if directory_capability.is_some() {
                OpenFlags::default()
            } else {
                OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW
            }
        } else {
            OpenFlags::default()
        };
        let manager = if persistent {
            SqliteConnectionManager::file(path).with_flags(flags)
        } else {
            SqliteConnectionManager::memory()
        }
        .with_init(configure_connection);
        let pool = r2d2::Pool::builder()
            .max_size(if persistent { 4 } else { 1 })
            .build(manager)
            .map_err(DatabaseError::Pool)?;
        let mut conn = pool.get().map_err(DatabaseError::Pool)?;
        if persistent {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(database_io_error)?;
            let metadata = std::fs::symlink_metadata(path).map_err(database_io_error)?;
            validate_database_metadata(path, &metadata, true)?;
        }
        let initialize_keyring = if persistent {
            let schema_version: i64 =
                conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
            let object_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )?;
            schema_version == 0 && object_count == 0
        } else {
            false
        };
        let keyring = if initialize_keyring {
            let keyring = keyring::Keyring::open(path, persistent, true)?;
            schema::migrate(&mut conn)?;
            keyring
        } else {
            // Existing databases are schema-validated before consulting the
            // keyring so operators receive the fail-closed schema diagnosis
            // for legacy or unexpected layouts even when no keyring exists.
            schema::migrate(&mut conn)?;
            keyring::Keyring::open(path, persistent, false)?
        };
        validate_encrypted_secrets(&conn, &keyring)?;
        drop(conn);
        Ok(Self(Arc::new(DatabaseInner {
            pool,
            transfer_write_admission: Mutex::new(()),
            keyring,
            session_idle_minutes: AtomicI64::new(30),
            _directory_capability: directory_capability,
        })))
    }

    fn encrypt_secret(&self, plaintext: &[u8], aad: &[u8]) -> rusqlite::Result<(u64, Vec<u8>)> {
        self.0.keyring.encrypt(plaintext, aad)
    }

    fn decrypt_secret(
        &self,
        key_id: u64,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> rusqlite::Result<Vec<u8>> {
        self.0.keyring.decrypt(key_id, ciphertext, aad)
    }
}

fn configure_connection(connection: &mut Connection) -> rusqlite::Result<()> {
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.set_prepared_statement_cache_capacity(128);
    Ok(())
}

fn pool_error(error: &r2d2::Error) -> rusqlite::Error {
    database_io_error(io::Error::other(format!(
        "database connection pool unavailable: {error}"
    )))
}

fn validate_encrypted_secrets(
    connection: &Connection,
    keyring: &keyring::Keyring,
) -> rusqlite::Result<()> {
    for (stable_id, key_id, ciphertext) in connection
        .prepare("SELECT token_hash,token_key_id,token_ciphertext FROM shares")?
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get(1)?, row.get(2)?))
        })?
        .collect::<rusqlite::Result<Vec<(String, u64, Vec<u8>)>>>()?
    {
        let aad = format!("shares.token:{stable_id}");
        let _plaintext =
            zeroize::Zeroizing::new(keyring.decrypt(key_id, &ciphertext, aad.as_bytes())?);
    }
    for (username, key_id, ciphertext) in connection
        .prepare("SELECT username,totp_key_id,totp_ciphertext FROM admins")?
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get(1)?, row.get(2)?))
        })?
        .collect::<rusqlite::Result<Vec<(String, u64, Vec<u8>)>>>()?
    {
        let aad = format!("admins.totp:{}", username.to_lowercase());
        let _plaintext =
            zeroize::Zeroizing::new(keyring.decrypt(key_id, &ciphertext, aad.as_bytes())?);
    }
    for (stable_id, key_id, ciphertext) in connection
        .prepare("SELECT token_hash,totp_key_id,totp_ciphertext FROM admin_mfa_enrollments")?
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get(1)?, row.get(2)?))
        })?
        .collect::<rusqlite::Result<Vec<(String, u64, Vec<u8>)>>>()?
    {
        let aad = format!("admin_mfa_enrollments.totp:{stable_id}");
        let _plaintext =
            zeroize::Zeroizing::new(keyring.decrypt(key_id, &ciphertext, aad.as_bytes())?);
    }
    Ok(())
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

impl Database {
    pub(crate) fn configure_session_idle_timeout(&self, minutes: i64) {
        self.0
            .session_idle_minutes
            .store(minutes, Ordering::Relaxed);
    }

    fn session_idle_minutes(&self) -> i64 {
        self.0.session_idle_minutes.load(Ordering::Relaxed)
    }

    pub(crate) fn readiness_check(&self) -> Result<(), String> {
        let connection = self
            .0
            .pool
            .try_get()
            .ok_or_else(|| "database connection pool is exhausted".to_string())?;
        let value = connection
            .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
            .map_err(|error| error.to_string())?;
        if value != 1 {
            return Err("database readiness query returned an invalid value".into());
        }
        Ok(())
    }

    fn try_conn(&self) -> rusqlite::Result<r2d2::PooledConnection<SqliteConnectionManager>> {
        self.0.pool.get().map_err(|error| pool_error(&error))
    }

    fn transfer_write_guard(&self) -> rusqlite::Result<MutexGuard<'_, ()>> {
        self.0.transfer_write_admission.lock().map_err(|_| {
            database_io_error(io::Error::other(
                "transfer database writer admission is poisoned",
            ))
        })
    }

    #[cfg(test)]
    fn conn(&self) -> r2d2::PooledConnection<SqliteConnectionManager> {
        self.try_conn().expect("database connection unavailable")
    }

    pub(crate) fn required_transaction<T, F>(
        &self,
        context: &AuditContext,
        operation: F,
    ) -> rusqlite::Result<T>
    where
        F: FnOnce(&rusqlite::Transaction<'_>) -> rusqlite::Result<(T, Vec<RequiredAuditEvent>)>,
    {
        let mut connection = self.try_conn()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (outcome, events) = operation(&transaction)?;
        insert_required_audits(&transaction, context, &events)?;
        transaction.commit()?;
        trace_required_audits(context, &events);
        Ok(outcome)
    }
}

#[cfg(test)]
#[path = "db/tests.rs"]
mod tests;
