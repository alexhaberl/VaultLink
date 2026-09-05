use axum::{
    body::Bytes,
    extract::Multipart,
    http::{header, HeaderMap, StatusCode},
};
use chrono::Utc;
use futures_util::StreamExt;
use tokio::sync::OwnedSemaphorePermit;
use tracing::Instrument as _;

#[path = "multipart.rs"]
mod multipart;
use multipart::PublicUploadFormPhase;
#[path = "finalizer.rs"]
mod finalizer;
use finalizer::{run_public_upload_finalizer, PublicUploadFinalizer};
#[path = "reservation.rs"]
mod reservation;
use reservation::{begin_upload_reservation_cancellation_safe, UploadQuotaReservation};

#[cfg(test)]
#[path = "test_support.rs"]
mod test_support;
#[cfg(test)]
pub(crate) use test_support::{
    install_public_upload_test_hook, PublicUploadTestHook, PublicUploadTestPhase,
};
#[cfg(test)]
use test_support::{upload_blocking_phase_test_checkpoint, upload_phase_test_checkpoint};

use crate::{
    auth,
    db::{
        AuditAction, AuditContext, Share, UploadReservationBeginOutcome,
        UploadReservationCommitOutcome, UploadReservationExtendOutcome,
    },
    file_ops,
    http_auth::{
        audit_observation, current_audit_client_ip, current_client_limit_key, database,
        enabled_audit_client_ip, required_audited_transfer_database, runtime_settings,
        share_is_unlocked, share_unlock_csrf, transfer_database, with_audit_client_ip,
        ClientActivityPermit, ShareActivityPermit,
    },
    http_contract::{
        request_body_timed_out, MAX_UPLOAD_OPTION_FIELD_BYTES, MAX_UPLOAD_PATH_FIELD_BYTES,
    },
    i18n::{self},
    internal_reporting::{report_internal, InternalOperation},
    log_safety::{EscapedLogPath, EscapedLogValue},
    policy::{
        self, PublicUploadPolicyError, ShareAvailability, UploadFormField, UploadFormState,
        UploadFormStateError,
    },
    runtime::RuntimeSettings,
    secure_fs::{PendingUpload, PublishOutcome, SecureDirectory},
    services::{
        public_upload::{PublicUploadSuccess, UploadDisposition},
        upload::{storage_full_error, storage_has_room, StagedFileError, StagedUploadFile},
    },
    AppState,
};

const MAX_UPLOAD_MULTIPART_FIELDS: usize = 5;
const UPLOAD_QUOTA_RESERVATION_STEP: u64 = 1024 * 1024;
const UPLOAD_QUOTA_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5 * 60);

#[derive(Debug)]
pub(crate) struct PublicUploadTransportError {
    status: StatusCode,
    message: &'static str,
}

impl PublicUploadTransportError {
    pub(crate) const fn new(status: StatusCode, message: &'static str) -> Self {
        Self { status, message }
    }

    pub(crate) const fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) const fn message(&self) -> &'static str {
        self.message
    }
}

use PublicUploadTransportError as AppError;
type Result<T> = std::result::Result<T, PublicUploadTransportError>;

impl From<crate::internal_reporting::ReportedInternalError> for PublicUploadTransportError {
    fn from(_: crate::internal_reporting::ReportedInternalError) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    }
}

impl From<crate::http_auth::HttpAuthError> for PublicUploadTransportError {
    fn from(error: crate::http_auth::HttpAuthError) -> Self {
        Self::new(error.status, error.message)
    }
}

fn add_upload_bytes(total: u64, chunk: usize, maximum: u64) -> Option<u64> {
    policy::add_upload_bytes(total, chunk as u64, maximum).ok()
}

fn join_display(base: &str, child: &str) -> String {
    if base.is_empty() || base == "." {
        child.to_string()
    } else {
        format!("{base}/{child}")
    }
}

fn storage_recovery_app_error(error: crate::file_ops::FileOperationError) -> AppError {
    match error {
        crate::file_ops::FileOperationError::DatabaseCapacity => AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            crate::http_auth::DATABASE_BUSY_MESSAGE,
        ),
        crate::file_ops::FileOperationError::Database(database_error)
            if crate::db::is_audit_unavailable(&database_error)
                || crate::db::is_sqlite_busy_or_locked(&database_error) =>
        {
            AppError::from(crate::http_auth::database_error(database_error))
        }
        _ => AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Storage state is being recovered",
        ),
    }
}

fn upload_io_error(error: std::io::Error) -> AppError {
    if storage_full_error(&error) {
        AppError::new(StatusCode::INSUFFICIENT_STORAGE, "Not enough free storage")
    } else {
        AppError::from(report_internal(
            InternalOperation::WebUploadIoFailure,
            error,
        ))
    }
}

enum PendingUploadFileError {
    Begin,
    Take(std::io::Error),
}

async fn get_share(state: &AppState, token: &str) -> Result<Share> {
    let token = token.to_string();
    let share = database(state.db().clone(), move |database| {
        database.share_by_token(&token)
    })
    .await?
    .ok_or(AppError::new(StatusCode::NOT_FOUND, "Link not found"))?;
    match policy::share_availability(&share, Utc::now()) {
        ShareAvailability::Available => Ok(share),
        ShareAvailability::Inactive
        | ShareAvailability::Expired
        | ShareAvailability::LimitReached => Err(AppError::new(
            StatusCode::GONE,
            "This link is no longer active",
        )),
    }
}

async fn get_storage_share(
    state: &AppState,
    token: &str,
    expected_id: i64,
) -> Result<(Share, crate::storage_authority::StorageReadGuard)> {
    let guard = file_ops::acquire_storage_read(state)
        .await
        .map_err(storage_recovery_app_error)?;
    let share = get_share(state, token).await?;
    if share.id != expected_id {
        return Err(AppError::new(
            StatusCode::GONE,
            "Share changed in the meantime",
        ));
    }
    Ok((share, guard))
}

async fn persist_required_file_audit(
    state: &AppState,
    context: AuditContext,
    action: AuditAction,
    object: String,
    detail: String,
) -> bool {
    database(state.db().clone(), move |database| {
        database.audit_action_with_client_ip(
            action,
            &context.actor,
            Some(&object),
            Some(&detail),
            context.client_ip.as_deref(),
        )
    })
    .await
    .is_err()
}

struct PublicUploadTarget {
    share_id: i64,
    upload_policy_epoch: i64,
    upload_base_scope: SecureDirectory,
    expected_destination: Option<SecureDirectory>,
    upload_base: String,
    folder_path: String,
    upload_subdir: String,
    file_name: String,
}

impl PublicUploadTarget {
    fn destination_exists(&self, directory: &SecureDirectory) -> std::io::Result<bool> {
        match directory.metadata(&self.file_name) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, Copy)]
struct PublicUploadIntent {
    overwrite_requested: bool,
}

enum PublicUploadPhaseError {
    Rejection(PublicUploadRejection),
    App(AppError),
}

pub(crate) struct PublicUploadRejection {
    upload_subdir: String,
    status: StatusCode,
    message: &'static str,
}

impl PublicUploadRejection {
    pub(crate) fn upload_subdir(&self) -> &str {
        &self.upload_subdir
    }

    pub(crate) const fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) const fn message(&self) -> &'static str {
        self.message
    }
}

pub(crate) enum PublicUploadOutcome {
    Success(PublicUploadSuccess),
    Rejected(PublicUploadRejection),
}

fn rejected(upload_subdir: &str, status: StatusCode, message: &'static str) -> PublicUploadOutcome {
    PublicUploadOutcome::Rejected(PublicUploadRejection {
        upload_subdir: upload_subdir.to_string(),
        status,
        message,
    })
}

impl From<AppError> for PublicUploadPhaseError {
    fn from(error: AppError) -> Self {
        Self::App(error)
    }
}

type PublicUploadPhaseResult<T> = std::result::Result<T, PublicUploadPhaseError>;

fn public_upload_rejection(
    _token: &str,
    upload_subdir: &str,
    status: StatusCode,
    message: &'static str,
) -> PublicUploadPhaseError {
    PublicUploadPhaseError::Rejection(PublicUploadRejection {
        upload_subdir: upload_subdir.to_string(),
        status,
        message,
    })
}

struct AuthorizedUpload {
    admission: PublicUploadAdmission,
}

impl AuthorizedUpload {
    fn new(admission: PublicUploadAdmission) -> Self {
        Self { admission }
    }

    /// Begins staging and atomically transfers admission into the next phase.
    async fn begin_staging(
        self,
        state: &AppState,
        token: &str,
        target: PublicUploadTarget,
    ) -> PublicUploadPhaseResult<StagedUpload> {
        StagedUpload::begin(state, token, target, self.admission).await
    }
}

/// Owns every durable and filesystem resource from the moment staging starts.
/// A cancelled multipart future therefore cannot leave the fragment, open file,
/// quota reservation, or admission permit outside one RAII boundary.
struct StagedUpload {
    file: StagedUploadFile,
    reservation: UploadQuotaReservation,
    target: PublicUploadTarget,
    admission: PublicUploadAdmission,
}

fn map_staged_file_error(
    token: &str,
    upload_subdir: &str,
    error: StagedFileError,
) -> PublicUploadPhaseError {
    match error {
        StagedFileError::TooLarge => public_upload_rejection(
            token,
            upload_subdir,
            StatusCode::PAYLOAD_TOO_LARGE,
            "Upload is too large",
        ),
        StagedFileError::CapacityUnavailable => public_upload_rejection(
            token,
            upload_subdir,
            StatusCode::SERVICE_UNAVAILABLE,
            "Storage capacity could not be determined",
        ),
        StagedFileError::InsufficientStorage => public_upload_rejection(
            token,
            upload_subdir,
            StatusCode::INSUFFICIENT_STORAGE,
            "Not enough free storage",
        ),
        StagedFileError::Io(error) if storage_full_error(&error) => public_upload_rejection(
            token,
            upload_subdir,
            StatusCode::INSUFFICIENT_STORAGE,
            "Not enough free storage",
        ),
        StagedFileError::Io(error) => PublicUploadPhaseError::App(upload_io_error(error)),
    }
}

impl StagedUpload {
    async fn begin(
        state: &AppState,
        token: &str,
        target: PublicUploadTarget,
        admission: PublicUploadAdmission,
    ) -> PublicUploadPhaseResult<Self> {
        let reservation_token = auth::random_token(32);
        let share_id = target.share_id;
        let upload_policy_epoch = target.upload_policy_epoch;
        let pending_ownership = begin_upload_reservation_cancellation_safe(
            state.db().clone(),
            reservation_token.clone(),
            share_id,
            upload_policy_epoch,
        )
        .await?;
        let reservation = match pending_ownership.outcome() {
            UploadReservationBeginOutcome::Reserved => {
                let reservation =
                    UploadQuotaReservation::new(state.db().clone(), reservation_token);
                pending_ownership.claim();
                reservation
            }
            UploadReservationBeginOutcome::ByteQuotaReached => {
                return Err(public_upload_rejection(
                    token,
                    &target.upload_subdir,
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Cumulative upload limit reached",
                ));
            }
            UploadReservationBeginOutcome::FileQuotaReached => {
                return Err(public_upload_rejection(
                    token,
                    &target.upload_subdir,
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Maximum number of uploaded files reached",
                ));
            }
            UploadReservationBeginOutcome::ShareUnavailable => {
                return Err(public_upload_rejection(
                    token,
                    &target.upload_subdir,
                    StatusCode::GONE,
                    "Share unavailable",
                ));
            }
        };

        let upload_scope = target.upload_base_scope.clone();
        let pending_file = tokio::task::spawn_blocking(move || {
            let mut pending = upload_scope
                .begin_staged_upload()
                .map_err(|_| PendingUploadFileError::Begin)?;
            let file = pending.take_file().map_err(PendingUploadFileError::Take)?;
            Ok::<_, PendingUploadFileError>((pending, file))
        })
        .await
        .map_err(|error| {
            PublicUploadPhaseError::App(AppError::from(report_internal(
                InternalOperation::WebPublicUploadStageTaskJoin,
                error,
            )))
        })?;
        let (pending, file) = match pending_file {
            Ok(value) => value,
            Err(PendingUploadFileError::Begin) => {
                return Err(public_upload_rejection(
                    token,
                    &target.upload_subdir,
                    StatusCode::NOT_FOUND,
                    "Target folder unavailable",
                ));
            }
            Err(PendingUploadFileError::Take(error)) => {
                return Err(PublicUploadPhaseError::App(upload_io_error(error)));
            }
        };
        Ok(Self {
            file: StagedUploadFile::new(pending, file),
            reservation,
            target,
            admission,
        })
    }

    async fn write_chunk(
        &mut self,
        state: &AppState,
        token: &str,
        maximum: u64,
        chunk: Bytes,
    ) -> PublicUploadPhaseResult<()> {
        let Some(new_total) = add_upload_bytes(self.file.total(), chunk.len(), maximum) else {
            return Err(public_upload_rejection(
                token,
                &self.target.upload_subdir,
                StatusCode::PAYLOAD_TOO_LARGE,
                "Upload is too large",
            ));
        };
        if new_total > self.reservation.reserved_bytes
            || self.reservation.last_heartbeat.elapsed() >= UPLOAD_QUOTA_HEARTBEAT_INTERVAL
        {
            let rounded_target = if new_total > self.reservation.reserved_bytes {
                new_total
                    .checked_add(UPLOAD_QUOTA_RESERVATION_STEP - 1)
                    .map(|value| value / UPLOAD_QUOTA_RESERVATION_STEP)
                    .and_then(|value| value.checked_mul(UPLOAD_QUOTA_RESERVATION_STEP))
                    .unwrap_or(new_total)
                    .min(maximum)
            } else {
                self.reservation.reserved_bytes
            };
            let reservation_token = self.reservation.token().to_string();
            let outcome = transfer_database(state.db().clone(), move |database| {
                database.extend_upload_reservation(&reservation_token, rounded_target)
            })
            .await
            .map_err(AppError::from)?;
            let mut accepted_target = rounded_target;
            let outcome = if outcome == UploadReservationExtendOutcome::ByteQuotaReached
                && rounded_target != new_total
            {
                accepted_target = new_total;
                let reservation_token = self.reservation.token().to_string();
                transfer_database(state.db().clone(), move |database| {
                    database.extend_upload_reservation(&reservation_token, new_total)
                })
                .await
                .map_err(AppError::from)?
            } else {
                outcome
            };
            match outcome {
                UploadReservationExtendOutcome::Extended => {
                    self.reservation.reserved_bytes = accepted_target;
                    self.reservation.last_heartbeat = std::time::Instant::now();
                }
                UploadReservationExtendOutcome::ByteQuotaReached => {
                    return Err(public_upload_rejection(
                        token,
                        &self.target.upload_subdir,
                        StatusCode::INSUFFICIENT_STORAGE,
                        "Cumulative upload limit reached",
                    ));
                }
                UploadReservationExtendOutcome::NotFound => {
                    return Err(public_upload_rejection(
                        token,
                        &self.target.upload_subdir,
                        StatusCode::REQUEST_TIMEOUT,
                        "Upload reservation has expired",
                    ));
                }
                UploadReservationExtendOutcome::ShareUnavailable => {
                    return Err(public_upload_rejection(
                        token,
                        &self.target.upload_subdir,
                        StatusCode::GONE,
                        "Share was disabled during upload",
                    ));
                }
            }
        }

        self.file
            .write_chunk(state, maximum, &chunk)
            .await
            .map_err(|error| map_staged_file_error(token, &self.target.upload_subdir, error))
    }

    async fn finish_staging(&mut self, token: &str) -> PublicUploadPhaseResult<()> {
        self.file
            .flush()
            .await
            .map_err(|error| map_staged_file_error(token, &self.target.upload_subdir, error))?;
        #[cfg(test)]
        upload_phase_test_checkpoint(token, PublicUploadTestPhase::StagingSync)
            .await
            .map_err(|error| PublicUploadPhaseError::App(upload_io_error(error)))?;
        self.file
            .sync_and_close()
            .await
            .map_err(|error| map_staged_file_error(token, &self.target.upload_subdir, error))
    }

    /// Intent may legally appear after the file part. The parser therefore
    /// consumes the fully-synced staged owner only after the multipart envelope
    /// has ended.
    fn prepare(self, intent: PublicUploadIntent) -> PreparedUpload {
        let Self {
            file,
            reservation,
            target,
            admission,
        } = self;
        let (pending, total) = file.into_parts();
        PreparedUpload {
            pending,
            reservation,
            target,
            intent,
            total,
            admission,
        }
    }
}

/// A prepared public upload cannot exist without its fragment, quota owner,
/// immutable user intent, and descriptor-bound upload base. The final target
/// is bound only after quota admission. Every terminal method consumes the
/// owner, guaranteeing one cleanup or one publication transition.
struct PreparedUpload {
    pending: PendingUpload,
    reservation: UploadQuotaReservation,
    target: PublicUploadTarget,
    intent: PublicUploadIntent,
    total: u64,
    admission: PublicUploadAdmission,
}

enum PublicUploadCommit {
    Committed(Box<CommittedUpload>),
    ReservationExpired,
    ShareUnavailable,
}

struct CommittedUpload {
    pending: PendingUpload,
    target: PublicUploadTarget,
    total: u64,
    replace: bool,
    replaced: bool,
    admission: PublicUploadAdmission,
    storage_guard: crate::storage_authority::StorageMutationGuard,
}

struct PublishedUpload {
    target: PublicUploadTarget,
    total: u64,
    replaced: bool,
    outcome: PublishOutcome,
    _admission: PublicUploadAdmission,
}

impl PreparedUpload {
    fn share_id(&self) -> i64 {
        self.target.share_id
    }

    fn upload_subdir(&self) -> &str {
        &self.target.upload_subdir
    }

    fn upload_base(&self) -> &str {
        &self.target.upload_base
    }

    fn folder_path(&self) -> &str {
        &self.target.folder_path
    }

    fn upload_base_matches(&self, current: &SecureDirectory) -> std::io::Result<bool> {
        self.target.upload_base_scope.same_directory(current)
    }

    fn expected_destination_matches(
        &self,
        current: Option<&SecureDirectory>,
    ) -> std::io::Result<bool> {
        match (&self.target.expected_destination, current) {
            (Some(expected), Some(current)) => expected.same_directory(current),
            (Some(_), None) => Ok(false),
            (None, _) => Ok(true),
        }
    }

    fn overwrite_requested(&self) -> bool {
        self.intent.overwrite_requested
    }

    fn destination_exists(&self, directory: &SecureDirectory) -> std::io::Result<bool> {
        self.target.destination_exists(directory)
    }

    #[cfg(test)]
    fn fail_next_directory_sync(&mut self, kind: std::io::ErrorKind) {
        self.pending.fail_next_directory_sync(kind);
    }

    async fn cancel(self) -> Result<()> {
        let Self {
            pending,
            reservation,
            ..
        } = self;
        drop(pending);
        reservation.cancel().await
    }

    async fn commit(
        self,
        database_handle: crate::db::Database,
        audit_context: AuditContext,
        replace: bool,
        replaced: bool,
        storage_guard: crate::storage_authority::StorageMutationGuard,
    ) -> Result<PublicUploadCommit> {
        let reservation_token = self.reservation.token().to_string();
        let total = self.total;
        let quota_commit = required_audited_transfer_database(database_handle, move |database| {
            database.commit_upload_reservation_and_audit_audited(
                &reservation_token,
                total,
                &audit_context,
            )
        })
        .await?;
        match quota_commit {
            UploadReservationCommitOutcome::Committed => {
                let Self {
                    pending,
                    reservation,
                    target,
                    total,
                    admission,
                    ..
                } = self;
                reservation.committed();
                Ok(PublicUploadCommit::Committed(Box::new(CommittedUpload {
                    pending,
                    target,
                    total,
                    replace,
                    replaced,
                    admission,
                    storage_guard,
                })))
            }
            UploadReservationCommitOutcome::NotFound => {
                let Self { reservation, .. } = self;
                reservation.database_finalized();
                storage_guard.finish_clean();
                Ok(PublicUploadCommit::ReservationExpired)
            }
            UploadReservationCommitOutcome::ShareUnavailable => {
                let Self { reservation, .. } = self;
                reservation.database_finalized();
                storage_guard.finish_clean();
                Ok(PublicUploadCommit::ShareUnavailable)
            }
        }
    }
}

impl CommittedUpload {
    fn bind_destination(mut self, destination: &SecureDirectory) -> std::io::Result<Self> {
        self.pending.bind_destination(destination)?;
        Ok(self)
    }

    async fn publish(
        self,
    ) -> std::result::Result<std::io::Result<PublishedUpload>, tokio::task::JoinError> {
        tokio::task::spawn_blocking(move || {
            // Publication owns the storage guard. Dropping the HTTP request or
            // finalizer JoinHandle cannot release serialization mid-rename.
            let Self {
                mut pending,
                target,
                total,
                replace,
                replaced,
                admission,
                storage_guard,
            } = self;
            let outcome = if replace {
                pending.publish_replace(&target.file_name)
            } else {
                pending.publish(&target.file_name)
            }?;
            let published = PublishedUpload {
                target,
                total,
                replaced,
                outcome,
                _admission: admission,
            };
            storage_guard.finish_clean();
            Ok(published)
        })
        .await
    }
}

impl PublishedUpload {
    fn into_parts(
        self,
    ) -> (
        PublicUploadTarget,
        u64,
        bool,
        PublishOutcome,
        PublicUploadAdmission,
    ) {
        (
            self.target,
            self.total,
            self.replaced,
            self.outcome,
            self._admission,
        )
    }
}

struct PublicUploadAdmission {
    _public: OwnedSemaphorePermit,
    _upload: OwnedSemaphorePermit,
    _peer: ClientActivityPermit,
    _share: ShareActivityPermit,
}

pub(crate) async fn execute_public_upload(
    state: AppState,
    headers: &HeaderMap,
    token: String,
    multipart: Multipart,
) -> Result<PublicUploadOutcome> {
    let share = get_share(&state, &token).await?;
    if !share_is_unlocked(&state, headers, &share).await? {
        return Err(AppError::new(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    if !share.is_directory || !share.permission.can_upload() {
        return Err(AppError::new(StatusCode::FORBIDDEN, "Upload not allowed"));
    }
    let required_csrf = share_unlock_csrf(&state, headers, &share).await?;
    if share.password_hash.is_some() && required_csrf.is_none() {
        return Err(AppError::new(StatusCode::UNAUTHORIZED, "Share is locked"));
    }

    let expected_id = share.id;
    let (share, storage_guard) = get_storage_share(&state, &token, expected_id).await?;
    if !share_is_unlocked(&state, headers, &share).await? {
        return Err(AppError::new(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    if !share.is_directory || !share.permission.can_upload() {
        return Err(AppError::new(StatusCode::FORBIDDEN, "Upload not allowed"));
    }
    let required_csrf = share_unlock_csrf(&state, headers, &share).await?;
    if share.password_hash.is_some() && required_csrf.is_none() {
        return Err(AppError::new(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    let csrf_header_valid = required_csrf.as_deref().is_some_and(|expected| {
        headers
            .get("x-vaultlink-upload-csrf")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| auth::constant_time_eq(expected, value))
    });

    let public_upload_permit = state.try_acquire_public_upload().map_err(|_| {
        AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many concurrent public uploads",
        )
    })?;
    let upload_permit = state.try_acquire_upload().map_err(|_| {
        AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many concurrent uploads",
        )
    })?;
    let upload_peer_permit = state
        .try_acquire_upload_peer(current_client_limit_key())
        .ok_or(AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many concurrent uploads from this client",
        ))?;
    let upload_share_permit = state
        .try_acquire_upload_share(share.id)
        .ok_or(AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many concurrent uploads for this share",
        ))?;
    let authorized_upload = AuthorizedUpload::new(PublicUploadAdmission {
        _public: public_upload_permit,
        _upload: upload_permit,
        _peer: upload_peer_permit,
        _share: upload_share_permit,
    });
    let secure_root = state.secure_root().clone();
    let share_path = share.relative_path.clone();
    let share_scope = tokio::task::spawn_blocking(move || {
        // The capability open can block on remote storage. Retain namespace
        // authority in the detached blocking task if the HTTP request is
        // cancelled, then release it as soon as the descriptor is bound.
        let _storage_guard = storage_guard;
        secure_root.bind_directory(&share_path)
    })
    .await
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebPublicUploadBindDestination,
            error,
        ))
    })?
    .map_err(|_| AppError::new(StatusCode::NOT_FOUND, "Target folder unavailable"))?;
    // The descriptor remains bound to the revalidated directory, so a long
    // request body cannot block admin namespace operations.

    let settings = runtime_settings(&state);
    let maximum = share
        .max_upload_size
        .unwrap_or(settings.max_upload_size)
        .min(crate::config::MAX_UPLOAD_SIZE);
    if let Some(length) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    {
        match storage_has_room(&state, length).await {
            Ok(true) => {}
            Ok(false) => {
                return Ok(rejected(
                    "",
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Not enough free storage",
                ))
            }
            Err(_) => {
                return Ok(rejected(
                    "",
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Storage capacity could not be determined",
                ))
            }
        }
    }

    let form_phase = PublicUploadFormPhase {
        state: &state,
        token: &token,
        share: &share,
        share_scope,
        settings: &settings,
        maximum,
        required_csrf: required_csrf.as_deref(),
        csrf_header_valid,
        authorized_upload,
    };
    let upload = match form_phase.run(multipart).await {
        Ok(upload) => upload,
        Err(PublicUploadPhaseError::Rejection(rejection)) => {
            return Ok(PublicUploadOutcome::Rejected(rejection))
        }
        Err(PublicUploadPhaseError::App(error)) => return Err(error),
    };

    let audit_client_ip = current_audit_client_ip();
    let locale = i18n::current_locale();
    let return_to = i18n::current_return_to();
    let audit_context = AuditContext::new("public", enabled_audit_client_ip(&state));
    let finalizer = PublicUploadFinalizer {
        state,
        token,
        upload,
        audit_context,
    };
    run_public_upload_finalizer(finalizer, audit_client_ip, locale, return_to).await
}
