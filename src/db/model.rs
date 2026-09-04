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
    // Admission mirrors the pool capacity and is acquired while still on the
    // async runtime. This prevents an unbounded number of blocking workers
    // from queueing inside r2d2 when SQLite or all pooled connections are
    // saturated. Tokio's semaphore queue is FIFO/fair.
    runtime_admission: Arc<tokio::sync::Semaphore>,
    // The server starts one retention worker per instance. This guard also
    // serializes explicit cleanup calls made through clones of this handle.
    audit_retention_admission: Mutex<()>,
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

pub(crate) fn is_sqlite_busy_or_locked(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(sqlite, _)
            if matches!(
                sqlite.extended_code & 0xff,
                rusqlite::ffi::SQLITE_BUSY | rusqlite::ffi::SQLITE_LOCKED
            )
    )
}

pub(crate) fn is_sqlite_unique_constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(sqlite, _)
            if sqlite.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
    )
}

impl From<rusqlite::Error> for DatabaseError {
    fn from(error: rusqlite::Error) -> Self {
        if schema::is_schema_error(&error) {
            return Self::Schema(error);
        }
        if keyring::is_crypto_error(&error) {
            return Self::Cryptography(error);
        }
        if is_sqlite_busy_or_locked(&error) {
            return Self::Busy(error);
        }
        if let rusqlite::Error::SqliteFailure(sqlite, _) = &error {
            let primary = sqlite.extended_code & 0xff;
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

/// Opaque identity of the exact MFA session that authorized a later mutation.
///
/// Only the already one-way token hash is retained, so long-running requests do
/// not keep a reusable bearer token alive while they hash passwords, stream an
/// upload, or wait for a mutation lock.  The database still treats the value as
/// untrusted and revalidates every predicate immediately before the mutation.
#[derive(PartialEq, Eq)]
pub(crate) struct MfaSessionProof {
    token_hash: String,
    admin_id: i64,
}

impl MfaSessionProof {
    fn from_token(token: &str, admin_id: i64) -> Self {
        Self {
            token_hash: token_hash(token),
            admin_id,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(token: &str, admin_id: i64) -> Self {
        Self::from_token(token, admin_id)
    }

    pub(crate) fn admin_id(&self) -> i64 {
        self.admin_id
    }

    pub(crate) fn webauthn_registration_key(&self) -> crate::webauthn::RegistrationCeremonyKey {
        crate::webauthn::RegistrationCeremonyKey::from_session_token_hash(&self.token_hash)
    }
}

impl std::fmt::Debug for MfaSessionProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MfaSessionProof")
            .field("token_hash", &"[REDACTED]")
            .field("admin_id", &self.admin_id)
            .finish()
    }
}

/// Non-forgeable authorization context for one privileged request mutation.
///
/// Only the database-owned MFA authentication path can construct this value.
/// It is deliberately not `Clone`: a handler must eventually consume it to
/// obtain the exact-session proof used by its commit boundary.
pub(crate) struct MfaMutationContext {
    session: Session,
    proof: MfaSessionProof,
}

impl MfaMutationContext {
    fn new(token: &str, session: Session) -> Self {
        let proof = MfaSessionProof::from_token(token, session.admin_id);
        Self { session, proof }
    }

    pub(crate) fn into_parts(self) -> (Session, MfaSessionProof) {
        (self.session, self.proof)
    }
}

/// Result of the database-owned request authentication step. Only the DB
/// module can construct the authenticated variant and its opaque proof.
pub(crate) enum MfaSessionAuthentication {
    Authenticated(MfaMutationContext),
    MfaRequired,
}

impl std::ops::Deref for MfaMutationContext {
    type Target = Session;

    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

/// Outcome of a mutation whose exact MFA session is checked at commit time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SessionBound<T> {
    Authorized(T),
    SessionUnavailable,
}

/// Rollback guard for an in-memory snapshot installed before a session-bound
/// SQLite transaction commits. Implementations must make this operation
/// infallible and must not perform any additional externally visible mutation.
pub(crate) trait CommitPublication {
    fn accept_commit(&mut self);
}

impl<T> SessionBound<T> {
    pub(crate) fn map<U>(self, operation: impl FnOnce(T) -> U) -> SessionBound<U> {
        match self {
            Self::Authorized(value) => SessionBound::Authorized(operation(value)),
            Self::SessionUnavailable => SessionBound::SessionUnavailable,
        }
    }
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
pub enum AuditKeysetPosition {
    After,
    Before,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditCursor {
    pub value: String,
    pub id: i64,
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
    pub(crate) id: i64,
    pub occurred_at: String,
    pub actor: String,
    pub action: String,
    pub object_id: Option<String>,
    pub detail: Option<String>,
    pub client_ip: Option<String>,
}

impl AuditEvent {
    pub fn cursor(&self, column: AuditSortColumn) -> AuditCursor {
        let value = match column {
            AuditSortColumn::Time => self.occurred_at.clone(),
            AuditSortColumn::Actor => self.actor.clone(),
            AuditSortColumn::Action => self.action.clone(),
            AuditSortColumn::Object => self.object_id.clone().unwrap_or_default(),
            AuditSortColumn::Detail => self.detail.clone().unwrap_or_default(),
            AuditSortColumn::ClientIp => self.client_ip.clone().unwrap_or_default(),
        };
        AuditCursor { value, id: self.id }
    }
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
