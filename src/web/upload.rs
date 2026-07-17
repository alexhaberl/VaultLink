use axum::{
    body::Bytes,
    extract::{Json, Multipart, OriginalUri, Path as AxPath, State},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Redirect, Response},
};
use futures_util::StreamExt;
use serde::Serialize;
use tokio::io::AsyncWriteExt;

use super::{
    common::{add_upload_bytes, encoded, internal, join_display},
    files::persist_required_file_audit,
    public::{get_share, get_storage_share},
    rendering::{
        storage_full_error, storage_has_room, StorageReservationError, UploadChunkReservation,
    },
    storage_recovery_app_error,
    transfer_runtime::{
        begin_upload_reservation_cancellation_safe, limited_multipart_text, public_share_route,
        public_upload_error, upload_io_error, PendingUploadFileError, UploadQuotaReservation,
    },
    AppError, Result, MAX_UPLOAD_MULTIPART_FIELDS, MAX_UPLOAD_OPTION_FIELD_BYTES,
    MAX_UPLOAD_PATH_FIELD_BYTES, UPLOAD_QUOTA_HEARTBEAT_INTERVAL, UPLOAD_QUOTA_RESERVATION_STEP,
};
use crate::{
    auth,
    db::{
        AuditContext, Share, UploadReservationBeginOutcome, UploadReservationCommitOutcome,
        UploadReservationExtendOutcome,
    },
    file_ops,
    http_auth::{
        audit_observation, current_audit_client_ip, current_client_limit_key, database,
        enabled_audit_client_ip, required_database, runtime_settings, share_is_unlocked,
        share_unlock_csrf, try_acquire_client_activity, with_audit_client_ip, ClientActivityPermit,
    },
    i18n::{self},
    policy::{
        self, PublicUploadPolicyError, UploadFormField, UploadFormState, UploadFormStateError,
    },
    runtime::RuntimeSettings,
    secure_fs::{PendingUpload, PublishOutcome, SecureDirectory},
    AppState,
};

struct PublicUploadTarget {
    share_id: i64,
    upload_policy_epoch: i64,
    share_scope: SecureDirectory,
    upload_subdir: String,
    file_name: String,
}

impl PublicUploadTarget {
    fn destination(&self) -> String {
        join_display(&self.upload_subdir, &self.file_name)
    }

    fn destination_exists(&self) -> std::io::Result<bool> {
        match self.share_scope.metadata(&self.destination()) {
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
    Response(Response),
    App(AppError),
}

impl From<AppError> for PublicUploadPhaseError {
    fn from(error: AppError) -> Self {
        Self::App(error)
    }
}

type PublicUploadPhaseResult<T> = std::result::Result<T, PublicUploadPhaseError>;

fn public_upload_rejection(
    token: &str,
    upload_subdir: &str,
    status: StatusCode,
    message: &'static str,
) -> PublicUploadPhaseError {
    PublicUploadPhaseError::Response(public_upload_error(token, upload_subdir, status, message))
}

/// Owns every durable and filesystem resource from the moment staging starts.
/// A cancelled multipart future therefore cannot leave the fragment, open file,
/// or quota reservation outside one RAII boundary.
struct PublicUploadStaging {
    output: tokio::fs::File,
    pending: PendingUpload,
    reservation: UploadQuotaReservation,
    target: PublicUploadTarget,
    total: u64,
}

impl PublicUploadStaging {
    async fn begin(
        state: &AppState,
        token: &str,
        target: PublicUploadTarget,
    ) -> PublicUploadPhaseResult<Self> {
        let reservation_token = auth::random_token(32);
        let share_id = target.share_id;
        let upload_policy_epoch = target.upload_policy_epoch;
        let pending_ownership = begin_upload_reservation_cancellation_safe(
            state.db.clone(),
            reservation_token.clone(),
            share_id,
            upload_policy_epoch,
        )
        .await?;
        let reservation = match pending_ownership.outcome() {
            UploadReservationBeginOutcome::Reserved => {
                let reservation = UploadQuotaReservation::new(state.db.clone(), reservation_token);
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

        let secure_root = target.share_scope.clone();
        let upload_directory = target.upload_subdir.clone();
        let pending_file = tokio::task::spawn_blocking(move || {
            let mut pending = secure_root
                .begin_upload(&upload_directory)
                .map_err(|_| PendingUploadFileError::Begin)?;
            let file = pending.take_file().map_err(PendingUploadFileError::Take)?;
            Ok::<_, PendingUploadFileError>((pending, file))
        })
        .await
        .map_err(|error| PublicUploadPhaseError::App(internal(error)))?;
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
            output: tokio::fs::File::from_std(file),
            pending,
            reservation,
            target,
            total: 0,
        })
    }

    async fn write_chunk(
        &mut self,
        state: &AppState,
        token: &str,
        maximum: u64,
        chunk: Bytes,
    ) -> PublicUploadPhaseResult<()> {
        let Some(new_total) = add_upload_bytes(self.total, chunk.len(), maximum) else {
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
            let outcome = database(state.db.clone(), move |database| {
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
                database(state.db.clone(), move |database| {
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

        let _chunk_reservation =
            match UploadChunkReservation::acquire(state, chunk.len() as u64).await {
                Ok(reservation) => reservation,
                Err(StorageReservationError::CapacityUnavailable) => {
                    return Err(public_upload_rejection(
                        token,
                        &self.target.upload_subdir,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Storage capacity could not be determined",
                    ))
                }
                Err(StorageReservationError::InsufficientStorage) => {
                    return Err(public_upload_rejection(
                        token,
                        &self.target.upload_subdir,
                        StatusCode::INSUFFICIENT_STORAGE,
                        "Not enough free storage",
                    ))
                }
            };
        self.total = new_total;
        if let Err(error) = self.output.write_all(&chunk).await {
            return if storage_full_error(&error) {
                Err(public_upload_rejection(
                    token,
                    &self.target.upload_subdir,
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Not enough free storage",
                ))
            } else {
                Err(PublicUploadPhaseError::App(upload_io_error(error)))
            };
        }
        Ok(())
    }

    async fn finish(mut self, token: &str) -> PublicUploadPhaseResult<StagedPublicUpload> {
        if let Err(error) = self.output.flush().await {
            return if storage_full_error(&error) {
                Err(public_upload_rejection(
                    token,
                    &self.target.upload_subdir,
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Not enough free storage",
                ))
            } else {
                Err(PublicUploadPhaseError::App(upload_io_error(error)))
            };
        }
        #[cfg(test)]
        upload_phase_test_checkpoint(token, PublicUploadTestPhase::StagingSync)
            .await
            .map_err(|error| PublicUploadPhaseError::App(upload_io_error(error)))?;
        if let Err(error) = self.output.sync_all().await {
            return if storage_full_error(&error) {
                Err(public_upload_rejection(
                    token,
                    &self.target.upload_subdir,
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Not enough free storage",
                ))
            } else {
                Err(PublicUploadPhaseError::App(upload_io_error(error)))
            };
        }
        let Self {
            output,
            pending,
            reservation,
            target,
            total,
        } = self;
        drop(output);
        Ok(StagedPublicUpload {
            pending,
            reservation,
            target,
            total,
        })
    }
}

/// Parser-only owner. Intent may legally appear after the file part, so the
/// fully prepared state is created only once the multipart envelope is done.
struct StagedPublicUpload {
    pending: PendingUpload,
    reservation: UploadQuotaReservation,
    target: PublicUploadTarget,
    total: u64,
}

impl StagedPublicUpload {
    fn prepare(self, intent: PublicUploadIntent) -> PreparedPublicUpload {
        let Self {
            pending,
            reservation,
            target,
            total,
        } = self;
        PreparedPublicUpload {
            pending,
            reservation,
            target,
            intent,
            total,
        }
    }
}

/// A prepared public upload cannot exist without its fragment, quota owner,
/// immutable user intent, and descriptor-bound target. Every terminal method
/// consumes the owner, guaranteeing one cleanup or one publication transition.
struct PreparedPublicUpload {
    pending: PendingUpload,
    reservation: UploadQuotaReservation,
    target: PublicUploadTarget,
    intent: PublicUploadIntent,
    total: u64,
}

enum PublicUploadCommit {
    Committed(Box<CommittedPublicUpload>),
    ReservationExpired,
    ShareUnavailable,
}

struct CommittedPublicUpload {
    pending: PendingUpload,
    target: PublicUploadTarget,
    total: u64,
    replace: bool,
    replaced: bool,
}

struct PublishedPublicUpload {
    target: PublicUploadTarget,
    total: u64,
    replaced: bool,
    outcome: PublishOutcome,
}

impl PreparedPublicUpload {
    fn share_id(&self) -> i64 {
        self.target.share_id
    }

    fn upload_subdir(&self) -> &str {
        &self.target.upload_subdir
    }

    fn overwrite_requested(&self) -> bool {
        self.intent.overwrite_requested
    }

    fn destination_matches(&self, destination: &SecureDirectory) -> std::io::Result<bool> {
        self.pending.destination_matches(destination)
    }

    fn destination_exists(&self) -> std::io::Result<bool> {
        self.target.destination_exists()
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
    ) -> Result<PublicUploadCommit> {
        let reservation_token = self.reservation.token().to_string();
        let total = self.total;
        let quota_commit = required_database(database_handle, move |database| {
            database.commit_upload_reservation_and_audit(&reservation_token, total, &audit_context)
        })
        .await?;
        match quota_commit {
            UploadReservationCommitOutcome::Committed => {
                let Self {
                    pending,
                    reservation,
                    target,
                    total,
                    ..
                } = self;
                reservation.committed();
                Ok(PublicUploadCommit::Committed(Box::new(
                    CommittedPublicUpload {
                        pending,
                        target,
                        total,
                        replace,
                        replaced,
                    },
                )))
            }
            UploadReservationCommitOutcome::NotFound => {
                let Self { reservation, .. } = self;
                reservation.database_finalized();
                Ok(PublicUploadCommit::ReservationExpired)
            }
            UploadReservationCommitOutcome::ShareUnavailable => {
                let Self { reservation, .. } = self;
                reservation.database_finalized();
                Ok(PublicUploadCommit::ShareUnavailable)
            }
        }
    }
}

impl CommittedPublicUpload {
    async fn publish(
        self,
        storage_guard: tokio::sync::OwnedMutexGuard<()>,
    ) -> std::result::Result<std::io::Result<PublishedPublicUpload>, tokio::task::JoinError> {
        tokio::task::spawn_blocking(move || {
            // Publication owns the storage guard. Dropping the HTTP request or
            // finalizer JoinHandle cannot release serialization mid-rename.
            let _storage_guard = storage_guard;
            let Self {
                mut pending,
                target,
                total,
                replace,
                replaced,
            } = self;
            let outcome = if replace {
                pending.publish_replace(&target.file_name)
            } else {
                pending.publish(&target.file_name)
            }?;
            Ok(PublishedPublicUpload {
                target,
                total,
                replaced,
                outcome,
            })
        })
        .await
    }
}

impl PublishedPublicUpload {
    fn into_parts(self) -> (PublicUploadTarget, u64, bool, PublishOutcome) {
        (self.target, self.total, self.replaced, self.outcome)
    }
}

struct PublicUploadAdmission {
    _upload: tokio::sync::OwnedSemaphorePermit,
    _peer: ClientActivityPermit,
}

async fn ensure_public_upload_directory(
    state: &AppState,
    token: &str,
    expected_share_id: i64,
    base: &str,
    relative: &str,
) -> Result<String> {
    let relative = crate::path_security::validate_relative(relative)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid folder path"))?
        .to_string_lossy()
        .replace('\\', "/");
    if relative.is_empty() {
        return Ok(base.to_string());
    }
    let target = join_display(base, &relative);
    let (share, guard) = get_storage_share(state, token, expected_share_id).await?;
    if !share.is_directory || !share.permission.can_upload() {
        return Err(AppError(StatusCode::GONE, "Share changed"));
    }
    let secure_root = state.secure_root.clone();
    let share_path = share.relative_path;
    let tree = target.clone();
    let created = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        secure_root
            .bind_directory(&share_path)?
            .ensure_directory_tree(&tree)
    })
    .await
    .map_err(internal)?
    .map_err(|error| match error.kind() {
        std::io::ErrorKind::InvalidInput => {
            AppError(StatusCode::BAD_REQUEST, "Invalid folder path")
        }
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
            AppError(StatusCode::CONFLICT, "Upload folder could not be created")
        }
        _ => internal(error),
    })?;
    if !created.is_empty() {
        audit_observation(
            state,
            "public".into(),
            "upload_directories_created",
            Some(expected_share_id.to_string()),
            Some(format!("path={target};created={}", created.len())),
        )
        .await;
    }
    Ok(target)
}

struct PublicUploadFinalizer {
    state: AppState,
    token: String,
    uri: Uri,
    upload: PreparedPublicUpload,
    audit_context: AuditContext,
    admission: PublicUploadAdmission,
}

impl PublicUploadFinalizer {
    async fn run(self) -> Result<Response> {
        let Self {
            state,
            token,
            uri,
            upload,
            audit_context,
            admission,
        } = self;
        let _admission = admission;
        #[cfg(test)]
        let mut upload = upload;
        #[cfg(not(test))]
        let upload = upload;
        #[cfg(test)]
        upload_phase_test_checkpoint(&token, PublicUploadTestPhase::Finalizer)
            .await
            .map_err(internal)?;
        #[cfg(test)]
        if let Some(kind) = state
            .upload_directory_sync_failure
            .lock()
            .expect("upload sync fault lock")
            .take()
        {
            upload.fail_next_directory_sync(kind);
        }

        let storage_guard = state.storage_mutation.clone().lock_owned().await;
        #[cfg(test)]
        upload_phase_test_checkpoint(&token, PublicUploadTestPhase::StorageLocked)
            .await
            .map_err(internal)?;
        let storage_guard =
            file_ops::recover_pending_file_operations_with_guard(&state, storage_guard)
                .await
                .map_err(storage_recovery_app_error)?;
        let upload_subdir = upload.upload_subdir().to_string();
        let current_share = match get_share(&state, &token).await {
            Ok(share) => share,
            Err(error) => {
                upload.cancel().await?;
                return Err(error);
            }
        };
        if current_share.id != upload.share_id()
            || !current_share.is_directory
            || !current_share.permission.can_upload()
        {
            upload.cancel().await?;
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::GONE,
                "Share changed during upload",
            ));
        }
        // Carry only the uploader's immutable intent across request streaming.
        // Replacement authority is derived from the current share policy while
        // the storage lock is held through quota commit and publication.
        let allow_replace = state.config.storage.replacements_allowed()
            && current_share.upload_conflict_strategy.can_overwrite()
            && upload.overwrite_requested();
        let current_destination = match state
            .secure_root
            .bind_directory(&current_share.relative_path)
            .and_then(|scope| scope.bind_directory(upload.upload_subdir()))
        {
            Ok(directory) => directory,
            Err(_) => {
                upload.cancel().await?;
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::CONFLICT,
                    "Upload target changed during upload",
                ));
            }
        };
        let destination_matches = match upload.destination_matches(&current_destination) {
            Ok(matches) => matches,
            Err(error) => {
                upload.cancel().await?;
                return Err(internal(error));
            }
        };
        if !destination_matches {
            upload.cancel().await?;
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::CONFLICT,
                "Upload target changed during upload",
            ));
        }
        let existed = match upload.destination_exists() {
            Ok(existed) => existed,
            Err(error) => {
                upload.cancel().await?;
                return Err(internal(error));
            }
        };
        let replaced = allow_replace && existed;
        if existed && !allow_replace {
            upload.cancel().await?;
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::CONFLICT,
                "File already exists.",
            ));
        }

        // Account for the upload before making the filesystem name visible. A crash
        // can therefore consume quota without publishing a file, but can never leave
        // a published file uncounted and reopen the storage-exhaustion bypass.
        let committed_upload = match upload
            .commit(
                state.db.clone(),
                audit_context.clone(),
                allow_replace,
                replaced,
            )
            .await?
        {
            PublicUploadCommit::Committed(upload) => *upload,
            PublicUploadCommit::ReservationExpired => {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::REQUEST_TIMEOUT,
                    "Upload reservation has expired",
                ));
            }
            PublicUploadCommit::ShareUnavailable => {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::GONE,
                    "Share was disabled during upload",
                ));
            }
        };
        let published_upload = match committed_upload
            .publish(storage_guard)
            .await
            .map_err(internal)?
        {
            Ok(upload) => upload,
            Err(error) => {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    return Ok(public_upload_error(
                        &token,
                        &upload_subdir,
                        StatusCode::CONFLICT,
                        "File already exists.",
                    ));
                }
                return if storage_full_error(&error) {
                    Ok(public_upload_error(
                        &token,
                        &upload_subdir,
                        StatusCode::INSUFFICIENT_STORAGE,
                        "Not enough free storage",
                    ))
                } else {
                    Err(internal(error))
                };
            }
        };
        let (target, total, replaced, publish_outcome) = published_upload.into_parts();
        let name = target.file_name;
        let durability_uncertain = !publish_outcome.is_durable();
        let audit_detail = format!("file={name};bytes={total}");
        if let Some(error) = publish_outcome.sync_error() {
            tracing::warn!(share_id = target.share_id, file = %name, %error, "upload published but directory fsync failed");
            audit_observation(
                &state,
                "public".into(),
                "upload_durability_uncertain",
                Some(target.share_id.to_string()),
                Some(audit_detail.clone()),
            )
            .await;
        }
        let audit_durability_uncertain = persist_required_file_audit(
            &state,
            audit_context,
            if replaced {
                "upload_replaced"
            } else {
                "upload"
            },
            target.share_id.to_string(),
            audit_detail,
        )
        .await;
        let upload_status = if audit_durability_uncertain {
            "audit_uncertain"
        } else {
            match (replaced, durability_uncertain) {
                (true, true) => "replaced_uncertain",
                (false, true) => "uncertain",
                (true, false) => "replaced",
                (false, false) => "ok",
            }
        };
        let public_route = public_share_route(&uri, &token);
        let redirect_target = if target.upload_subdir.is_empty() {
            format!("{public_route}?upload={upload_status}")
        } else {
            format!(
                "{public_route}?path={}&upload={upload_status}",
                encoded(&target.upload_subdir)
            )
        };
        let outcome = match (replaced, durability_uncertain) {
            (true, true) => "replaced_uncertain",
            (false, true) => "created_uncertain",
            (true, false) => "replaced",
            (false, false) => "created",
        };
        let mut response = Redirect::to(&redirect_target).into_response();
        response.headers_mut().insert(
            "x-vaultlink-upload-file",
            HeaderValue::from_str(&encoded(&name)).map_err(internal)?,
        );
        response.headers_mut().insert(
            "x-vaultlink-upload-outcome",
            HeaderValue::from_static(outcome),
        );
        if durability_uncertain {
            response.headers_mut().insert(
                "x-vaultlink-durability",
                HeaderValue::from_static("uncertain"),
            );
        }
        if audit_durability_uncertain {
            response.headers_mut().insert(
                "x-vaultlink-audit-durability",
                HeaderValue::from_static("uncertain"),
            );
        }
        Ok(response)
    }
}

struct PublicUploadFormPhase<'a> {
    state: &'a AppState,
    token: &'a str,
    share: &'a Share,
    share_scope: SecureDirectory,
    settings: &'a RuntimeSettings,
    maximum: u64,
    required_csrf: Option<&'a str>,
    csrf_header_valid: bool,
}

impl PublicUploadFormPhase<'_> {
    async fn run(self, mut multipart: Multipart) -> PublicUploadPhaseResult<PreparedPublicUpload> {
        let Self {
            state,
            token,
            share,
            share_scope,
            settings,
            maximum,
            required_csrf,
            csrf_header_valid,
        } = self;
        let mut upload_subdir = String::new();
        let mut folder_path: Option<String> = None;
        let mut overwrite_requested = false;
        let mut form_state = UploadFormState::default();
        let mut csrf_validated = required_csrf.is_none() || csrf_header_valid;
        let mut staged_upload: Option<StagedPublicUpload> = None;

        while let Some(field) = multipart.next_field().await.map_err(|_| {
            public_upload_rejection(
                token,
                &upload_subdir,
                StatusCode::BAD_REQUEST,
                "Invalid upload",
            )
        })? {
            let field_kind = match field.name().unwrap_or("") {
                "path" => UploadFormField::Path,
                "folder_path" => UploadFormField::FolderPath,
                "overwrite_existing" => UploadFormField::Overwrite,
                "csrf" => UploadFormField::Csrf,
                "file" => UploadFormField::File,
                _ => UploadFormField::Unknown,
            };
            if let Err(error) = form_state.observe(field_kind, MAX_UPLOAD_MULTIPART_FIELDS) {
                let message = match error {
                    UploadFormStateError::TooManyFields => "Too many multipart fields",
                    UploadFormStateError::DuplicateOrLatePath => {
                        "Upload path was submitted more than once or too late"
                    }
                    UploadFormStateError::DuplicateOrLateFolderPath => {
                        "Folder path was submitted more than once or too late"
                    }
                    UploadFormStateError::DuplicateOverwrite => {
                        "Upload option was submitted more than once"
                    }
                    UploadFormStateError::DuplicateOrLateCsrf => {
                        "CSRF token was submitted more than once or too late"
                    }
                    UploadFormStateError::MultipleFiles => {
                        "Exactly one file is allowed per request"
                    }
                    UploadFormStateError::UnknownField => "Unknown multipart field",
                };
                return Err(public_upload_rejection(
                    token,
                    &upload_subdir,
                    StatusCode::BAD_REQUEST,
                    message,
                ));
            }

            match field_kind {
                UploadFormField::Path => {
                    let value = limited_multipart_text(field, MAX_UPLOAD_PATH_FIELD_BYTES)
                        .await
                        .map_err(|_| {
                            public_upload_rejection(
                                token,
                                &upload_subdir,
                                StatusCode::BAD_REQUEST,
                                "Invalid upload path",
                            )
                        })?;
                    upload_subdir =
                        policy::normalize_public_upload_subdir(share.permission, &value).map_err(
                            |_| {
                                public_upload_rejection(
                                    token,
                                    &upload_subdir,
                                    StatusCode::BAD_REQUEST,
                                    "Invalid upload path",
                                )
                            },
                        )?;
                }
                UploadFormField::FolderPath => {
                    let value = limited_multipart_text(field, MAX_UPLOAD_PATH_FIELD_BYTES)
                        .await
                        .map_err(|_| {
                            public_upload_rejection(
                                token,
                                &upload_subdir,
                                StatusCode::BAD_REQUEST,
                                "Invalid folder path",
                            )
                        })?;
                    let value = crate::path_security::validate_relative(&value)
                        .map_err(|_| {
                            public_upload_rejection(
                                token,
                                &upload_subdir,
                                StatusCode::BAD_REQUEST,
                                "Invalid folder path",
                            )
                        })?
                        .to_string_lossy()
                        .replace('\\', "/");
                    folder_path = Some(value);
                }
                UploadFormField::Overwrite => {
                    let value = limited_multipart_text(field, MAX_UPLOAD_OPTION_FIELD_BYTES)
                        .await
                        .map_err(|_| {
                            public_upload_rejection(
                                token,
                                &upload_subdir,
                                StatusCode::BAD_REQUEST,
                                "Invalid upload",
                            )
                        })?;
                    overwrite_requested = value == "1";
                    if overwrite_requested && !state.config.storage.replacements_allowed() {
                        return Err(public_upload_rejection(
                            token,
                            &upload_subdir,
                            StatusCode::BAD_REQUEST,
                            "Overwriting is disabled with external storage writers",
                        ));
                    }
                }
                UploadFormField::Csrf => {
                    let value = limited_multipart_text(field, 256).await.map_err(|_| {
                        public_upload_rejection(
                            token,
                            &upload_subdir,
                            StatusCode::FORBIDDEN,
                            "Invalid CSRF token",
                        )
                    })?;
                    csrf_validated = required_csrf
                        .is_none_or(|expected| auth::constant_time_eq(expected, &value));
                    if !csrf_validated {
                        return Err(public_upload_rejection(
                            token,
                            &upload_subdir,
                            StatusCode::FORBIDDEN,
                            "Invalid CSRF token",
                        ));
                    }
                }
                UploadFormField::File => {
                    if !csrf_validated {
                        return Err(public_upload_rejection(
                            token,
                            &upload_subdir,
                            StatusCode::FORBIDDEN,
                            "CSRF token missing",
                        ));
                    }
                    let Some(file_name) = field.file_name() else {
                        return Err(public_upload_rejection(
                            token,
                            &upload_subdir,
                            StatusCode::BAD_REQUEST,
                            "File name missing",
                        ));
                    };
                    let name = match policy::validate_public_upload_filename(
                        file_name,
                        &settings.blocked_extensions,
                    ) {
                        Ok(name) => name.to_string(),
                        Err(PublicUploadPolicyError::BlockedExtension) => {
                            return Err(public_upload_rejection(
                                token,
                                &upload_subdir,
                                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                                "File type blocked",
                            ));
                        }
                        Err(_) => {
                            return Err(public_upload_rejection(
                                token,
                                &upload_subdir,
                                StatusCode::BAD_REQUEST,
                                "Invalid file name",
                            ));
                        }
                    };
                    if let Some(folder_path) = folder_path.as_deref() {
                        upload_subdir = ensure_public_upload_directory(
                            state,
                            token,
                            share.id,
                            &upload_subdir,
                            folder_path,
                        )
                        .await
                        .map_err(PublicUploadPhaseError::App)?;
                    }
                    let target = PublicUploadTarget {
                        share_id: share.id,
                        upload_policy_epoch: share.upload_policy_epoch,
                        share_scope: share_scope.clone(),
                        upload_subdir: upload_subdir.clone(),
                        file_name: name,
                    };
                    let mut staging = PublicUploadStaging::begin(state, token, target).await?;
                    #[cfg(test)]
                    upload_phase_test_checkpoint(token, PublicUploadTestPhase::Staging)
                        .await
                        .map_err(|error| PublicUploadPhaseError::App(upload_io_error(error)))?;
                    let stream = field;
                    tokio::pin!(stream);
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk.map_err(|_| {
                            public_upload_rejection(
                                token,
                                &upload_subdir,
                                StatusCode::BAD_REQUEST,
                                "Upload aborted",
                            )
                        })?;
                        staging.write_chunk(state, token, maximum, chunk).await?;
                    }
                    staged_upload = Some(staging.finish(token).await?);
                }
                UploadFormField::Unknown => {
                    // Keep the adapter fail-closed even if UploadFormState is
                    // extended later and accidentally admits an unknown field.
                    return Err(public_upload_rejection(
                        token,
                        &upload_subdir,
                        StatusCode::BAD_REQUEST,
                        "Unknown multipart field",
                    ));
                }
            }
        }

        let staged_upload = staged_upload.ok_or_else(|| {
            public_upload_rejection(
                token,
                &upload_subdir,
                StatusCode::BAD_REQUEST,
                "File is missing",
            )
        })?;
        Ok(staged_upload.prepare(PublicUploadIntent {
            overwrite_requested,
        }))
    }
}

async fn run_public_upload_finalizer(
    finalizer: PublicUploadFinalizer,
    audit_client_ip: Option<std::net::IpAddr>,
    locale: i18n::Locale,
    return_to: String,
) -> Result<Response> {
    // The finalizer is detached from the request future. Once ownership crosses
    // this boundary, cancellation cannot strand committed quota before publish.
    let task = tokio::spawn(with_audit_client_ip(
        audit_client_ip,
        i18n::scope(locale, return_to, finalizer.run()),
    ));
    task.await.map_err(internal)?
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PublicUploadTestPhase {
    Staging,
    StagingSync,
    Finalizer,
    StorageLocked,
}

#[cfg(test)]
pub(super) struct PublicUploadTestHook {
    token: String,
    phase: PublicUploadTestPhase,
    entered: std::sync::atomic::AtomicUsize,
    entered_wake: tokio::sync::Notify,
    released: std::sync::atomic::AtomicBool,
    release_wake: tokio::sync::Notify,
    failure: Option<std::io::ErrorKind>,
}

#[cfg(test)]
impl PublicUploadTestHook {
    pub(super) fn blocking(token: &str, phase: PublicUploadTestPhase) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            token: token.to_string(),
            phase,
            entered: std::sync::atomic::AtomicUsize::new(0),
            entered_wake: tokio::sync::Notify::new(),
            released: std::sync::atomic::AtomicBool::new(false),
            release_wake: tokio::sync::Notify::new(),
            failure: None,
        })
    }

    pub(super) fn failing(
        token: &str,
        phase: PublicUploadTestPhase,
        failure: std::io::ErrorKind,
    ) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            token: token.to_string(),
            phase,
            entered: std::sync::atomic::AtomicUsize::new(0),
            entered_wake: tokio::sync::Notify::new(),
            released: std::sync::atomic::AtomicBool::new(true),
            release_wake: tokio::sync::Notify::new(),
            failure: Some(failure),
        })
    }

    pub(super) async fn wait_until_entered(&self) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while self.entered.load(std::sync::atomic::Ordering::Acquire) == 0 {
                self.entered_wake.notified().await;
            }
        })
        .await
        .expect("public upload test phase should be reached");
    }

    pub(super) fn release(&self) {
        self.released
            .store(true, std::sync::atomic::Ordering::Release);
        self.release_wake.notify_one();
    }
}

#[cfg(test)]
pub(super) struct PublicUploadTestGuard(std::sync::Arc<PublicUploadTestHook>);

#[cfg(test)]
impl Drop for PublicUploadTestGuard {
    fn drop(&mut self) {
        self.0.release();
        let mut hooks = PUBLIC_UPLOAD_TEST_HOOKS
            .get_or_init(|| std::sync::Mutex::new(Vec::new()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        hooks.retain(|active| !std::sync::Arc::ptr_eq(active, &self.0));
    }
}

#[cfg(test)]
static PUBLIC_UPLOAD_TEST_HOOKS: std::sync::OnceLock<
    std::sync::Mutex<Vec<std::sync::Arc<PublicUploadTestHook>>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
pub(super) fn install_public_upload_test_hook(
    hook: std::sync::Arc<PublicUploadTestHook>,
) -> PublicUploadTestGuard {
    PUBLIC_UPLOAD_TEST_HOOKS
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(hook.clone());
    PublicUploadTestGuard(hook)
}

#[cfg(test)]
async fn upload_phase_test_checkpoint(
    token: &str,
    phase: PublicUploadTestPhase,
) -> std::io::Result<()> {
    let hook = PUBLIC_UPLOAD_TEST_HOOKS
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|hook| hook.token == token && hook.phase == phase)
        .cloned();
    let Some(hook) = hook else {
        return Ok(());
    };
    hook.entered
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    hook.entered_wake.notify_one();
    if let Some(kind) = hook.failure {
        return Err(std::io::Error::new(kind, "injected upload staging failure"));
    }
    while !hook.released.load(std::sync::atomic::Ordering::Acquire) {
        hook.release_wake.notified().await;
    }
    Ok(())
}

pub(crate) async fn upload(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    multipart: Multipart,
) -> Result<Response> {
    let share = get_share(&state, &token).await?;
    if !share_is_unlocked(&state, &headers, &share).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    if !share.is_directory || !share.permission.can_upload() {
        return Err(AppError(StatusCode::FORBIDDEN, "Upload not allowed"));
    }
    let required_csrf = share_unlock_csrf(&state, &headers, &share).await?;
    if share.password_hash.is_some() && required_csrf.is_none() {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Share is locked"));
    }

    let expected_id = share.id;
    let (share, storage_guard) = get_storage_share(&state, &token, expected_id).await?;
    if !share_is_unlocked(&state, &headers, &share).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    if !share.is_directory || !share.permission.can_upload() {
        return Err(AppError(StatusCode::FORBIDDEN, "Upload not allowed"));
    }
    let required_csrf = share_unlock_csrf(&state, &headers, &share).await?;
    if share.password_hash.is_some() && required_csrf.is_none() {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    let csrf_header_valid = required_csrf.as_deref().is_some_and(|expected| {
        headers
            .get("x-vaultlink-upload-csrf")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| auth::constant_time_eq(expected, value))
    });

    let upload_permit = state
        .upload_admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            AppError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Too many concurrent uploads",
            )
        })?;
    let upload_peer_permit = try_acquire_client_activity(
        state.upload_peer_admission.clone(),
        current_client_limit_key(),
        crate::MAX_IN_FLIGHT_UPLOADS_PER_CLIENT,
    )
    .ok_or(AppError(
        StatusCode::SERVICE_UNAVAILABLE,
        "Too many concurrent uploads from this client",
    ))?;
    let share_scope = state
        .secure_root
        .bind_directory(&share.relative_path)
        .map_err(|_| AppError(StatusCode::NOT_FOUND, "Target folder unavailable"))?;
    // The descriptor remains bound to the revalidated directory after releasing
    // the mutation lock, so a long request body cannot block admin operations.
    drop(storage_guard);

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
                return Ok(public_upload_error(
                    &token,
                    "",
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Not enough free storage",
                ))
            }
            Err(_) => {
                return Ok(public_upload_error(
                    &token,
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
    };
    let upload = match form_phase.run(multipart).await {
        Ok(upload) => upload,
        Err(PublicUploadPhaseError::Response(response)) => return Ok(response),
        Err(PublicUploadPhaseError::App(error)) => return Err(error),
    };

    let audit_client_ip = current_audit_client_ip();
    let locale = i18n::current_locale();
    let return_to = i18n::current_return_to();
    let audit_context = AuditContext::new("public", enabled_audit_client_ip(&state));
    let finalizer = PublicUploadFinalizer {
        state,
        token,
        uri,
        upload,
        audit_context,
        admission: PublicUploadAdmission {
            _upload: upload_permit,
            _peer: upload_peer_permit,
        },
    };
    run_public_upload_finalizer(finalizer, audit_client_ip, locale, return_to).await
}
#[derive(Serialize)]
pub(super) struct UploadQueueSuccess {
    pub(super) file: String,
    pub(super) outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) warning: Option<&'static str>,
}

#[derive(Serialize)]
pub(super) struct UploadQueueErrorEnvelope {
    error: UploadQueueError,
}

#[derive(Serialize)]
pub(super) struct UploadQueueError {
    code: String,
    message: String,
}

pub(super) fn upload_queue_error_response(status: StatusCode, message: &str) -> Response {
    let code = match status {
        StatusCode::SERVICE_UNAVAILABLE
            if message == crate::http_auth::AUDIT_UNAVAILABLE_MESSAGE =>
        {
            "audit_unavailable"
        }
        StatusCode::BAD_REQUEST => "invalid_upload",
        StatusCode::UNAUTHORIZED => "share_locked",
        StatusCode::FORBIDDEN => "upload_forbidden",
        StatusCode::NOT_FOUND => "target_not_found",
        StatusCode::CONFLICT => "file_exists",
        StatusCode::PAYLOAD_TOO_LARGE => "upload_too_large",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "blocked_extension",
        StatusCode::INSUFFICIENT_STORAGE => "insufficient_storage",
        _ => "upload_failed",
    };
    let locale = i18n::current_locale();
    let message = if message == crate::http_auth::AUDIT_UNAVAILABLE_MESSAGE {
        std::borrow::Cow::Borrowed(i18n::text(locale, i18n::AUDIT_TEMPORARILY_UNAVAILABLE))
    } else if message == crate::http_auth::ARGON2_BUSY_MESSAGE {
        std::borrow::Cow::Borrowed(i18n::text(locale, i18n::PASSWORD_PROCESSING_UNAVAILABLE))
    } else {
        i18n::localized_text(locale, message)
    };
    (
        status,
        Json(UploadQueueErrorEnvelope {
            error: UploadQueueError {
                code: code.to_string(),
                message: message.into_owned(),
            },
        }),
    )
        .into_response()
}

pub(super) async fn upload_queue(
    state: State<AppState>,
    uri: OriginalUri,
    headers: HeaderMap,
    token: AxPath<String>,
    multipart: Multipart,
) -> Result<Response> {
    let response = match upload(state, uri, headers, token, multipart).await {
        Ok(response) => response,
        Err(AppError(status, message)) => {
            return Ok(upload_queue_error_response(status, message));
        }
    };
    if response.status().is_redirection() {
        let (file, outcome, audit_uncertain) = upload_success_metadata(&response);
        let status = if audit_uncertain {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        };
        return Ok((
            status,
            Json(UploadQueueSuccess {
                file,
                outcome,
                warning: audit_uncertain.then_some("audit_durability_uncertain"),
            }),
        )
            .into_response());
    }

    let status = response.status();
    Ok(upload_queue_error_response(
        status,
        status.canonical_reason().unwrap_or("Upload failed"),
    ))
}

/// Preserve the established redirect response for ordinary API uploads, but
/// surface a post-publication audit failure as an explicit non-retryable JSON
/// success. At this point the filesystem effect is already visible.
pub(crate) async fn upload_api(
    state: State<AppState>,
    uri: OriginalUri,
    headers: HeaderMap,
    token: AxPath<String>,
    multipart: Multipart,
) -> Result<Response> {
    let response = upload(state, uri, headers, token, multipart).await?;
    if !response.status().is_redirection() {
        return Ok(response);
    }
    let (file, outcome, audit_uncertain) = upload_success_metadata(&response);
    if !audit_uncertain {
        return Ok(response);
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(UploadQueueSuccess {
            file,
            outcome,
            warning: Some("audit_durability_uncertain"),
        }),
    )
        .into_response())
}

fn upload_success_metadata(response: &Response) -> (String, String, bool) {
    let file = response
        .headers()
        .get("x-vaultlink-upload-file")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            percent_encoding::percent_decode_str(value)
                .decode_utf8_lossy()
                .into_owned()
        })
        .unwrap_or_default();
    let outcome = response
        .headers()
        .get("x-vaultlink-upload-outcome")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("created")
        .to_string();
    let audit_uncertain = response
        .headers()
        .get("x-vaultlink-audit-durability")
        .is_some_and(|value| value == "uncertain");
    (file, outcome, audit_uncertain)
}
