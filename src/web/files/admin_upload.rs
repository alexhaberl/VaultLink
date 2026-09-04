pub(super) struct AdminUploadSuccess {
    file: String,
    disposition: UploadDisposition,
    directory: String,
    audit_durability_uncertain: bool,
}

const ADMIN_UPLOAD_SESSION_REVOKED: &str = "session_revoked";

#[derive(Serialize)]
struct AdminUploadSessionRevoked {
    error: &'static str,
}

#[derive(Serialize)]
struct AdminUploadQueueSuccess {
    file: String,
    outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<&'static str>,
}

#[derive(Serialize)]
struct AdminUploadQueueErrorEnvelope {
    error: AdminUploadQueueError,
}

#[derive(Serialize)]
struct AdminUploadQueueError {
    code: String,
    message: String,
}

pub(super) async fn stage_admin_upload(
    state: &FileRouteState,
    directory: &str,
    field: axum::extract::multipart::Field<'_>,
    maximum: u64,
    blocked_extensions: &[String],
) -> Result<(PendingUpload, String, u64)> {
    let file_name = field
        .file_name()
        .ok_or(AppError(StatusCode::BAD_REQUEST, "File name missing"))?;
    let name = path_security::safe_admin_filename(file_name)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid file name"))?
        .to_string();
    if extension_is_blocked(&name, blocked_extensions) {
        return Err(AppError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "File type blocked",
        ));
    }

    let storage_guard = file_ops::acquire_storage_read(state)
        .await
        .map_err(storage_recovery_app_error)?;
    let secure_root = state.secure_root().clone();
    let upload_directory = directory.to_string();
    let pending_file = tokio::task::spawn_blocking(move || {
        let _storage_guard = storage_guard;
        let mut pending = secure_root
            .begin_upload(&upload_directory)
            .map_err(|_| PendingUploadFileError::Begin)?;
        let file = pending.take_file().map_err(PendingUploadFileError::Take)?;
        Ok::<_, PendingUploadFileError>((pending, file))
    })
    .await
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebAdminUploadStageTaskJoin,
            error,
        ))
    })?;
    let (pending, file) = match pending_file {
        Ok(value) => value,
        Err(PendingUploadFileError::Begin) => {
            return Err(AppError(StatusCode::NOT_FOUND, "Target folder unavailable"))
        }
        Err(PendingUploadFileError::Take(error)) => return Err(upload_io_error(error)),
    };

    let mut staged = StagedUploadFile::new(pending, file);
    let stream = field;
    tokio::pin!(stream);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| admin_multipart_read_error(&error, "Upload aborted"))?;
        staged
            .write_chunk(state, maximum, &chunk)
            .await
            .map_err(admin_staged_file_error)?;
    }
    staged.finish().await.map_err(admin_staged_file_error)?;
    let (pending, total) = staged.into_parts();
    Ok((pending, name, total))
}

fn admin_staged_file_error(error: StagedFileError) -> AppError {
    match error {
        StagedFileError::TooLarge => AppError(StatusCode::PAYLOAD_TOO_LARGE, "Upload is too large"),
        StagedFileError::CapacityUnavailable => AppError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Storage capacity could not be determined",
        ),
        StagedFileError::InsufficientStorage => {
            AppError(StatusCode::INSUFFICIENT_STORAGE, "Not enough free storage")
        }
        StagedFileError::Io(error) => upload_io_error(error),
    }
}

struct AdminUploadPermits {
    global: tokio::sync::OwnedSemaphorePermit,
    peer: ClientActivityPermit,
    proof: MfaSessionProof,
}
type AdminDirectoryStatus = (Vec<String>, bool, bool);
type AdminDirectoryOutcome = SessionBound<AdminDirectoryStatus>;
type AdminDirectoryAudit = (AdminDirectoryStatus, Vec<RequiredAuditEvent>);
type AdminDirectoryResult<T> = std::result::Result<T, file_ops::FileOperationError>;

struct AdminDirectoryCreation {
    state: FileRouteState,
    base: String,
    tree: String,
    target: String,
    audit_context: AuditContext,
    permits: AdminUploadPermits,
}

async fn ensure_admin_upload_directory(
    state: &FileRouteState,
    proof: MfaSessionProof,
    base: &str,
    relative: &str,
    actor: &str,
    upload_permit: tokio::sync::OwnedSemaphorePermit,
    upload_peer_permit: ClientActivityPermit,
) -> Result<(String, bool, AdminUploadPermits)> {
    let tree = path_security::validate_relative(relative)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid folder path"))?
        .to_string_lossy()
        .replace('\\', "/");
    let permits = AdminUploadPermits {
        global: upload_permit,
        peer: upload_peer_permit,
        proof,
    };
    if tree.is_empty() {
        return Ok((base.to_string(), false, permits));
    }
    let target = join_display(base, &tree);
    let guard = file_ops::acquire_storage_mutation(state)
        .await
        .map_err(storage_recovery_app_error)?;
    let database_permit = file_ops::acquire_database_permit(state.db())
        .await
        .map_err(file_operation_app_error)?;
    let creation = AdminDirectoryCreation {
        state: state.clone(),
        base: base.to_string(),
        tree,
        target: target.clone(),
        audit_context: AuditContext::new(actor, enabled_audit_client_ip(state)),
        permits,
    };
    let (outcome, permits) = tokio::task::spawn_blocking(move || {
        create_admin_upload_directory_blocking(creation, guard, database_permit)
    })
    .await
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebAdminUploadDirectoriesTaskJoin,
            error,
        ))
    })?
    .map_err(upload_directory_error)?;
    let (_created, durability_uncertain, complete) = match outcome {
        SessionBound::Authorized(outcome) => outcome,
        SessionBound::SessionUnavailable => {
            return Err(AppError(
                StatusCode::UNAUTHORIZED,
                ADMIN_UPLOAD_SESSION_REVOKED,
            ));
        }
    };
    if !complete {
        return Err(AppError(
            StatusCode::ACCEPTED,
            "Upload directory creation is uncertain",
        ));
    }
    Ok((target, durability_uncertain, permits))
}

fn create_admin_upload_directory_blocking(
    creation: AdminDirectoryCreation,
    guard: crate::storage_authority::StorageMutationGuard,
    database_permit: tokio::sync::OwnedSemaphorePermit,
) -> AdminDirectoryResult<(AdminDirectoryOutcome, AdminUploadPermits)> {
    let _database_permit = database_permit;
    let database = creation.state.db().clone();
    let proof = &creation.permits.proof;
    let mut created_snapshot = None;
    let outcome = match database.run_required_session_audit(|database| {
        database.required_transaction_for_mfa_session_audited(
            proof,
            &creation.audit_context,
            |_transaction| create_admin_directory_tree(&creation, &mut created_snapshot),
        )
    }) {
        Ok(outcome) => Ok(outcome),
        Err(file_ops::FileOperationError::Database(error))
            if created_snapshot
                .as_ref()
                .is_some_and(|(created, _)| !created.is_empty()) =>
        {
            let (created, complete) =
                created_snapshot.expect("created upload directories recorded");
            tracing::error!(
                error = %EscapedLogValue::new(&error),
                action = "upload_directories_created",
                path = %EscapedLogPath::new(&creation.target),
                "upload directories are visible but required audit durability is uncertain"
            );
            Ok(SessionBound::Authorized((created, true, complete)))
        }
        Err(error) => Err(error),
    }?;
    guard.finish_clean();
    Ok((outcome, creation.permits))
}

fn create_admin_directory_tree(
    creation: &AdminDirectoryCreation,
    created_snapshot: &mut Option<(Vec<String>, bool)>,
) -> AdminDirectoryResult<AdminDirectoryAudit> {
    wait_for_admin_directory_test_barrier(&creation.state);
    let tree_outcome = creation
        .state
        .secure_root()
        .bind_directory(&creation.base)
        .and_then(|directory| directory.ensure_directory_tree_with_outcome(&creation.tree))
        .map_err(file_ops::FileOperationError::Io)?;
    let created = tree_outcome.created;
    let complete = tree_outcome.terminal_error.is_none();
    *created_snapshot = Some((created.clone(), complete));
    let durability_uncertain = tree_outcome.sync_error.is_some() || !complete;
    if let Some(error) = tree_outcome.sync_error {
        tracing::error!(
            error = %EscapedLogValue::new(&error),
            action = "upload_directories_created",
            path = %EscapedLogPath::new(&creation.target),
            "upload directory is visible but parent-directory durability is uncertain"
        );
    }
    if let Some(error) = tree_outcome.terminal_error {
        tracing::error!(
            error = %EscapedLogValue::new(&error),
            action = "upload_directories_created",
            path = %EscapedLogPath::new(&creation.target),
            "upload directory tree was only partially created"
        );
    }
    let events = (!created.is_empty())
        .then(|| {
            RequiredAuditEvent::new(
                AuditAction::UploadDirectoriesCreated,
                Some(creation.target.clone()),
                Some(format!("created={};complete={complete}", created.len())),
            )
        })
        .into_iter()
        .collect();
    Ok(((created, durability_uncertain, complete), events))
}

#[cfg(test)]
fn wait_for_admin_directory_test_barrier(state: &FileRouteState) {
    state.wait_at_upload_directory_creation_barrier_for_test();
}

#[cfg(not(test))]
fn wait_for_admin_directory_test_barrier(_state: &FileRouteState) {}

fn upload_directory_error(error: file_ops::FileOperationError) -> AppError {
    match error {
        file_ops::FileOperationError::Io(error)
            if error.kind() == std::io::ErrorKind::InvalidInput =>
        {
            AppError(StatusCode::BAD_REQUEST, "Invalid folder path")
        }
        file_ops::FileOperationError::Io(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            AppError(StatusCode::CONFLICT, "Upload folder could not be created")
        }
        other => file_operation_app_error(other),
    }
}

pub(super) async fn admin_upload(
    State(state): State<FileRouteState>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Result<Response> {
    let success = match process_admin_upload(&state, &headers, multipart).await {
        Ok(success) => success,
        Err(AppError(StatusCode::UNAUTHORIZED, ADMIN_UPLOAD_SESSION_REVOKED)) => {
            return Err(AppError(StatusCode::UNAUTHORIZED, SESSION_REVOKED_MESSAGE));
        }
        Err(error) => return Err(error),
    };
    let mut response = Redirect::to(&browser_redirect(
        &success.directory,
        if success.audit_durability_uncertain {
            "audit_durability_uncertain"
        } else {
            "upload_ok"
        },
    ))
    .into_response();
    response.headers_mut().insert(
        "x-vaultlink-upload-file",
        HeaderValue::from_str(&encoded(&success.file)).map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebAdminUploadFileHeader,
                error,
            ))
        })?,
    );
    response.headers_mut().insert(
        "x-vaultlink-upload-outcome",
        HeaderValue::from_static(success.disposition.outcome()),
    );
    if success.audit_durability_uncertain {
        response.headers_mut().insert(
            "x-vaultlink-audit-durability",
            HeaderValue::from_static("uncertain"),
        );
    }
    Ok(response)
}

pub(super) async fn admin_upload_queue(
    State(state): State<FileRouteState>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Response {
    match process_admin_upload(&state, &headers, multipart).await {
        Ok(success) => {
            let status = if success.audit_durability_uncertain {
                StatusCode::ACCEPTED
            } else {
                StatusCode::OK
            };
            (
                status,
                Json(AdminUploadQueueSuccess {
                    file: success.file,
                    outcome: success.disposition.outcome().to_string(),
                    warning: success
                        .audit_durability_uncertain
                        .then_some("audit_durability_uncertain"),
                }),
            )
                .into_response()
        }
        Err(AppError(
            StatusCode::UNAUTHORIZED,
            ADMIN_UPLOAD_SESSION_REVOKED | SESSION_REVOKED_MESSAGE,
        )) => (
            StatusCode::UNAUTHORIZED,
            Json(AdminUploadSessionRevoked {
                error: ADMIN_UPLOAD_SESSION_REVOKED,
            }),
        )
            .into_response(),
        Err(AppError(status, message)) => admin_upload_queue_error_response(status, message),
    }
}

fn admin_upload_queue_error_response(status: StatusCode, message: &str) -> Response {
    let admission_rejected =
        status == StatusCode::SERVICE_UNAVAILABLE && message.starts_with("Too many concurrent ");
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
        StatusCode::REQUEST_TIMEOUT => "upload_timeout",
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
    let mut response = (
        status,
        Json(AdminUploadQueueErrorEnvelope {
            error: AdminUploadQueueError {
                code: code.to_string(),
                message: message.into_owned(),
            },
        }),
    )
        .into_response();
    if admission_rejected {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
    response
}
