use super::*;

type StorageMutationGuard = crate::storage_authority::StorageMutationGuard;

pub(super) struct PublicUploadFinalizer {
    pub(super) state: AppState,
    pub(super) token: String,
    pub(super) upload: PreparedUpload,
    pub(super) audit_context: AuditContext,
}

enum FinalizerStep<T> {
    Continue(T),
    Complete(PublicUploadOutcome),
}

struct StoragePreflight {
    current_base: SecureDirectory,
    current_destination: Option<SecureDirectory>,
    existed: bool,
}

struct PreflightUpload {
    upload: PreparedUpload,
    storage_guard: StorageMutationGuard,
    storage: StoragePreflight,
    upload_subdir: String,
    allow_replace: bool,
    replaced: bool,
}

struct CommittedContext {
    upload: CommittedUpload,
    current_base: SecureDirectory,
    current_destination: Option<SecureDirectory>,
    upload_subdir: String,
    audit_context: AuditContext,
}

struct PublicationReady {
    upload: CommittedUpload,
    destination: SecureDirectory,
    directory_durability_uncertain: bool,
    upload_subdir: String,
    audit_context: AuditContext,
}

impl PublicUploadFinalizer {
    pub(super) async fn run(self) -> Result<PublicUploadOutcome> {
        let upload = apply_test_finalizer_hooks(&self.state, &self.token, self.upload).await?;
        let preflight = match preflight_upload(&self.state, &self.token, upload).await? {
            FinalizerStep::Continue(context) => context,
            FinalizerStep::Complete(outcome) => return Ok(outcome),
        };
        let committed = match commit_upload(&self.state, self.audit_context, preflight).await? {
            FinalizerStep::Continue(context) => context,
            FinalizerStep::Complete(outcome) => return Ok(outcome),
        };
        let publication = match prepare_publication(&self.state, committed).await? {
            FinalizerStep::Continue(context) => context,
            FinalizerStep::Complete(outcome) => return Ok(outcome),
        };
        publish_and_audit(&self.state, publication).await
    }
}

#[cfg(test)]
async fn apply_test_finalizer_hooks(
    state: &AppState,
    token: &str,
    mut upload: PreparedUpload,
) -> Result<PreparedUpload> {
    upload_phase_test_checkpoint(token, PublicUploadTestPhase::Finalizer)
        .await
        .map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebPublicUploadTestCheckpoint,
                error,
            ))
        })?;
    if let Some(kind) = state.take_upload_directory_sync_failure_for_test() {
        upload.fail_next_directory_sync(kind);
    }
    Ok(upload)
}

#[cfg(not(test))]
async fn apply_test_finalizer_hooks(
    _state: &AppState,
    _token: &str,
    upload: PreparedUpload,
) -> Result<PreparedUpload> {
    Ok(upload)
}

async fn preflight_upload(
    state: &AppState,
    token: &str,
    upload: PreparedUpload,
) -> Result<FinalizerStep<PreflightUpload>> {
    let storage_guard = file_ops::acquire_storage_mutation(state)
        .await
        .map_err(storage_recovery_app_error)?;
    storage_locked_test_checkpoint(token).await?;
    let upload_subdir = upload.upload_subdir().to_string();
    let current_share = match get_share(state, token).await {
        Ok(share) => share,
        Err(error) => {
            storage_guard.finish_clean();
            upload.cancel().await?;
            return Err(error);
        }
    };
    if current_share.id != upload.share_id()
        || !current_share.is_directory
        || !current_share.permission.can_upload()
    {
        storage_guard.finish_clean();
        upload.cancel().await?;
        return Ok(FinalizerStep::Complete(rejected(
            &upload_subdir,
            StatusCode::GONE,
            "Share changed during upload",
        )));
    }
    let allow_replace = state.config().storage.replacements_allowed()
        && current_share.upload_conflict_strategy.can_overwrite()
        && upload.overwrite_requested();
    let storage =
        inspect_storage_target(state, &current_share.relative_path, storage_guard, upload).await?;
    finish_preflight(storage, allow_replace, upload_subdir).await
}

#[cfg(test)]
async fn storage_locked_test_checkpoint(token: &str) -> Result<()> {
    upload_phase_test_checkpoint(token, PublicUploadTestPhase::StorageLocked)
        .await
        .map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebPublicUploadTestCheckpoint,
                error,
            ))
        })
}

#[cfg(not(test))]
async fn storage_locked_test_checkpoint(_token: &str) -> Result<()> {
    Ok(())
}

async fn inspect_storage_target(
    state: &AppState,
    current_share_path: &str,
    storage_guard: StorageMutationGuard,
    upload: PreparedUpload,
) -> Result<(
    StorageMutationGuard,
    PreparedUpload,
    std::result::Result<StoragePreflight, PublicUploadStoragePreflightError>,
)> {
    let preflight_root = state.secure_root().clone();
    let current_share_path = current_share_path.to_string();
    let preflight_span = tracing::Span::current();
    tokio::task::spawn_blocking(move || {
        let _entered = preflight_span.enter();
        let preflight =
            inspect_storage_target_blocking(&preflight_root, &current_share_path, &upload);
        (storage_guard, upload, preflight)
    })
    .await
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebPublicUploadStageTaskJoin,
            error,
        ))
    })
}

fn inspect_storage_target_blocking(
    root: &crate::secure_fs::SecureRoot,
    share_path: &str,
    upload: &PreparedUpload,
) -> std::result::Result<StoragePreflight, PublicUploadStoragePreflightError> {
    let current_base = root
        .bind_directory(share_path)
        .and_then(|scope| scope.bind_directory(upload.upload_base()))
        .map_err(|_| PublicUploadStoragePreflightError::Changed)?;
    if !upload.upload_base_matches(&current_base).map_err(|error| {
        PublicUploadStoragePreflightError::Internal(AppError::from(report_internal(
            InternalOperation::WebPublicUploadBaseMatch,
            error,
        )))
    })? {
        return Err(PublicUploadStoragePreflightError::Changed);
    }
    let current_destination = bind_current_destination(upload, &current_base)?;
    if !upload
        .expected_destination_matches(current_destination.as_ref())
        .map_err(|error| {
            PublicUploadStoragePreflightError::Internal(AppError::from(report_internal(
                InternalOperation::WebPublicUploadDestinationMatch,
                error,
            )))
        })?
    {
        return Err(PublicUploadStoragePreflightError::Changed);
    }
    let existed = if let Some(destination) = current_destination.as_ref() {
        upload.destination_exists(destination).map_err(|error| {
            PublicUploadStoragePreflightError::Internal(AppError::from(report_internal(
                InternalOperation::WebPublicUploadDestinationExists,
                error,
            )))
        })?
    } else {
        false
    };
    Ok(StoragePreflight {
        current_base,
        current_destination,
        existed,
    })
}

fn bind_current_destination(
    upload: &PreparedUpload,
    current_base: &SecureDirectory,
) -> std::result::Result<Option<SecureDirectory>, PublicUploadStoragePreflightError> {
    if upload.folder_path().is_empty() {
        return Ok(Some(current_base.clone()));
    }
    match current_base.bind_directory(upload.folder_path()) {
        Ok(directory) => Ok(Some(directory)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(PublicUploadStoragePreflightError::Changed),
    }
}

async fn finish_preflight(
    (storage_guard, upload, preflight): (
        StorageMutationGuard,
        PreparedUpload,
        std::result::Result<StoragePreflight, PublicUploadStoragePreflightError>,
    ),
    allow_replace: bool,
    upload_subdir: String,
) -> Result<FinalizerStep<PreflightUpload>> {
    let storage = match preflight {
        Ok(preflight) => preflight,
        Err(PublicUploadStoragePreflightError::Changed) => {
            storage_guard.finish_clean();
            upload.cancel().await?;
            return Ok(FinalizerStep::Complete(rejected(
                &upload_subdir,
                StatusCode::CONFLICT,
                "Upload target changed during upload",
            )));
        }
        Err(PublicUploadStoragePreflightError::Internal(error)) => {
            storage_guard.finish_clean();
            upload.cancel().await?;
            return Err(error);
        }
    };
    if storage.existed && !allow_replace {
        storage_guard.finish_clean();
        upload.cancel().await?;
        return Ok(FinalizerStep::Complete(rejected(
            &upload_subdir,
            StatusCode::CONFLICT,
            "File already exists.",
        )));
    }
    let replaced = allow_replace && storage.existed;
    Ok(FinalizerStep::Continue(PreflightUpload {
        upload,
        storage_guard,
        storage,
        upload_subdir,
        allow_replace,
        replaced,
    }))
}

async fn commit_upload(
    state: &AppState,
    audit_context: AuditContext,
    context: PreflightUpload,
) -> Result<FinalizerStep<CommittedContext>> {
    let commit = context
        .upload
        .commit(
            state.db().clone(),
            audit_context.clone(),
            context.allow_replace,
            context.replaced,
            context.storage_guard,
        )
        .await?;
    let upload = match commit {
        PublicUploadCommit::Committed(upload) => *upload,
        PublicUploadCommit::ReservationExpired => {
            return Ok(FinalizerStep::Complete(rejected(
                &context.upload_subdir,
                StatusCode::REQUEST_TIMEOUT,
                "Upload reservation has expired",
            )));
        }
        PublicUploadCommit::ShareUnavailable => {
            return Ok(FinalizerStep::Complete(rejected(
                &context.upload_subdir,
                StatusCode::GONE,
                "Share was disabled during upload",
            )));
        }
    };
    Ok(FinalizerStep::Continue(CommittedContext {
        upload,
        current_base: context.storage.current_base,
        current_destination: context.storage.current_destination,
        upload_subdir: context.upload_subdir,
        audit_context,
    }))
}

async fn prepare_publication(
    state: &AppState,
    context: CommittedContext,
) -> Result<FinalizerStep<PublicationReady>> {
    let destination_was_missing = context.current_destination.is_none();
    let directory = match context.current_destination {
        Some(destination) => PublicUploadDirectoryOutcome {
            destination: Some(destination),
            created: Vec::new(),
            durability_uncertain: false,
            complete: true,
        },
        None => {
            ensure_public_upload_directory(context.current_base, &context.upload.target.folder_path)
                .await?
        }
    };
    let directory_audit_uncertain = audit_directory_outcome(
        state,
        &context.audit_context,
        context.upload.target.share_id,
        &context.upload_subdir,
        &directory,
    )
    .await;
    if !directory.complete {
        return Ok(FinalizerStep::Complete(PublicUploadOutcome::Success(
            PublicUploadSuccess::new(
                context.upload.target.file_name.clone(),
                context.upload_subdir,
                UploadDisposition::DirectoryUncertain,
                directory_audit_uncertain,
            ),
        )));
    }
    let destination = directory
        .destination
        .expect("complete directory creation has a destination capability");
    if destination_was_missing && !destination_is_absent(&context.upload, &destination)? {
        return Ok(FinalizerStep::Complete(rejected(
            &context.upload_subdir,
            StatusCode::CONFLICT,
            "File already exists.",
        )));
    }
    Ok(FinalizerStep::Continue(PublicationReady {
        upload: context.upload,
        destination,
        directory_durability_uncertain: directory.durability_uncertain,
        upload_subdir: context.upload_subdir,
        audit_context: context.audit_context,
    }))
}

async fn audit_directory_outcome(
    state: &AppState,
    audit_context: &AuditContext,
    share_id: i64,
    upload_subdir: &str,
    directory: &PublicUploadDirectoryOutcome,
) -> bool {
    let audit_uncertain = if directory.created.is_empty() {
        false
    } else if directory.complete {
        audit_observation(
            state,
            "public".into(),
            AuditAction::UploadDirectoriesCreated,
            Some(share_id.to_string()),
            Some(format!(
                "path={upload_subdir};created={}",
                directory.created.len()
            )),
        )
        .await;
        false
    } else {
        persist_required_file_audit(
            state,
            audit_context.clone(),
            AuditAction::UploadDirectoriesCreated,
            share_id.to_string(),
            format!(
                "path={upload_subdir};created={};complete=false;quota_committed=true",
                directory.created.len()
            ),
        )
        .await
    };
    if directory.durability_uncertain {
        audit_observation(
            state,
            "public".into(),
            AuditAction::UploadDurabilityUncertain,
            Some(share_id.to_string()),
            Some(format!(
                "path={upload_subdir};directory_publication=uncertain"
            )),
        )
        .await;
    }
    audit_uncertain
}

fn destination_is_absent(upload: &CommittedUpload, destination: &SecureDirectory) -> Result<bool> {
    match upload.target.destination_exists(destination) {
        Ok(exists) => Ok(!exists),
        Err(error) => Err(AppError::from(report_internal(
            InternalOperation::WebPublicUploadPostDirectoryDestinationExists,
            error,
        ))),
    }
}

async fn publish_and_audit(
    state: &AppState,
    context: PublicationReady,
) -> Result<PublicUploadOutcome> {
    let upload = context
        .upload
        .bind_destination(&context.destination)
        .map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebPublicUploadBindDestination,
                error,
            ))
        })?;
    let published = match upload.publish().await.map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebPublicUploadPublishTaskJoin,
            error,
        ))
    })? {
        Ok(upload) => upload,
        Err(error) => return publish_error(&context.upload_subdir, error),
    };
    record_publication(
        state,
        published,
        context.directory_durability_uncertain,
        context.audit_context,
    )
    .await
}

fn publish_error(upload_subdir: &str, error: std::io::Error) -> Result<PublicUploadOutcome> {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        return Ok(rejected(
            upload_subdir,
            StatusCode::CONFLICT,
            "File already exists.",
        ));
    }
    if storage_full_error(&error) {
        return Ok(rejected(
            upload_subdir,
            StatusCode::INSUFFICIENT_STORAGE,
            "Not enough free storage",
        ));
    }
    Err(AppError::from(report_internal(
        InternalOperation::WebPublicUploadPublishFailure,
        error,
    )))
}

async fn record_publication(
    state: &AppState,
    published: PublishedUpload,
    directory_durability_uncertain: bool,
    audit_context: AuditContext,
) -> Result<PublicUploadOutcome> {
    let (target, total, replaced, publish_outcome, _admission) = published.into_parts();
    let name = target.file_name;
    let durability_uncertain = directory_durability_uncertain || !publish_outcome.is_durable();
    let audit_detail = format!("file={name};bytes={total}");
    if let Some(error) = publish_outcome.uncertainty_error() {
        tracing::warn!(
            share_id = target.share_id,
            file = %EscapedLogPath::new(&name),
            error = %EscapedLogValue::new(error),
            "upload publication or directory durability is uncertain"
        );
        audit_observation(
            state,
            "public".into(),
            AuditAction::UploadDurabilityUncertain,
            Some(target.share_id.to_string()),
            Some(audit_detail.clone()),
        )
        .await;
    }
    let audit_durability_uncertain = persist_required_file_audit(
        state,
        audit_context,
        if replaced {
            AuditAction::UploadReplaced
        } else {
            AuditAction::Upload
        },
        target.share_id.to_string(),
        audit_detail,
    )
    .await;
    let disposition = match (replaced, durability_uncertain) {
        (true, true) => UploadDisposition::ReplacedUncertain,
        (false, true) => UploadDisposition::CreatedUncertain,
        (true, false) => UploadDisposition::Replaced,
        (false, false) => UploadDisposition::Created,
    };
    Ok(PublicUploadOutcome::Success(PublicUploadSuccess::new(
        name,
        target.upload_subdir,
        disposition,
        audit_durability_uncertain,
    )))
}

struct PublicUploadDirectoryOutcome {
    destination: Option<SecureDirectory>,
    created: Vec<String>,
    durability_uncertain: bool,
    complete: bool,
}

enum PublicUploadStoragePreflightError {
    Changed,
    Internal(AppError),
}

async fn ensure_public_upload_directory(
    base_scope: SecureDirectory,
    relative: &str,
) -> Result<PublicUploadDirectoryOutcome> {
    let relative = crate::path_security::validate_relative(relative)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "Invalid folder path"))?
        .to_string_lossy()
        .replace('\\', "/");
    if relative.is_empty() {
        return Ok(PublicUploadDirectoryOutcome {
            destination: Some(base_scope),
            created: Vec::new(),
            durability_uncertain: false,
            complete: true,
        });
    }
    tokio::task::spawn_blocking(move || {
        let outcome = base_scope.ensure_directory_tree_with_outcome(&relative)?;
        let created = outcome.created;
        if let Some(error) = outcome.terminal_error {
            if created.is_empty() {
                return Err(error);
            }
            tracing::error!(
                error = %EscapedLogValue::new(&error),
                created = created.len(),
                "public upload directory tree was only partially created after quota commit"
            );
            return Ok(PublicUploadDirectoryOutcome {
                destination: None,
                created,
                durability_uncertain: true,
                complete: false,
            });
        }
        let durability_uncertain = outcome.sync_error.is_some();
        match base_scope.bind_directory(&relative) {
            Ok(destination) => Ok(PublicUploadDirectoryOutcome {
                destination: Some(destination),
                created,
                durability_uncertain,
                complete: true,
            }),
            Err(error) if created.is_empty() => Err(error),
            Err(error) => {
                tracing::error!(
                    error = %EscapedLogValue::new(&error),
                    created = created.len(),
                    "public upload directory target became unavailable after partial creation"
                );
                Ok(PublicUploadDirectoryOutcome {
                    destination: None,
                    created,
                    durability_uncertain: true,
                    complete: false,
                })
            }
        }
    })
    .await
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebPublicUploadDirectoryTaskJoin,
            error,
        ))
    })?
    .map_err(|error| match error.kind() {
        std::io::ErrorKind::InvalidInput => {
            AppError::new(StatusCode::BAD_REQUEST, "Invalid folder path")
        }
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
            AppError::new(StatusCode::CONFLICT, "Upload folder could not be created")
        }
        _ => AppError::from(report_internal(
            InternalOperation::WebPublicUploadDirectoryFailure,
            error,
        )),
    })
}

pub(super) async fn run_public_upload_finalizer(
    finalizer: PublicUploadFinalizer,
    audit_client_ip: Option<std::net::IpAddr>,
    locale: i18n::Locale,
    return_to: String,
) -> Result<PublicUploadOutcome> {
    let task = tokio::spawn(
        with_audit_client_ip(
            audit_client_ip,
            i18n::scope(locale, return_to, finalizer.run()),
        )
        .instrument(tracing::Span::current()),
    );
    task.await.map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebPublicUploadFinalizerJoin,
            error,
        ))
    })?
}
