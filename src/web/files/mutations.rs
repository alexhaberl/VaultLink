#[derive(Deserialize)]
pub(super) struct CreateDirectoryForm {
    csrf: String,
    parent: String,
    name: String,
}

#[derive(Deserialize)]
pub(super) struct RenameFileForm {
    csrf: String,
    path: String,
    name: String,
}

#[derive(Deserialize)]
pub(super) struct DeleteFileQuery {
    path: String,
}

#[derive(Deserialize)]
pub(super) struct DeleteFileForm {
    csrf: String,
    path: String,
    confirm_name: Option<String>,
}

pub(super) async fn create_directory_ui(
    State(state): State<FileRouteState>,
    headers: HeaderMap,
    Form(form): Form<CreateDirectoryForm>,
) -> Result<Redirect> {
    let admin = mfa_session(&state, &headers, MissingSession::RedirectToLogin).await?;
    csrf(&admin, &form.csrf)?;
    let file_service = state.file_service();
    let operation_parent = form.parent.clone();
    let operation_name = form.name;
    let audit_client_ip = current_audit_client_ip();
    let audit_client_ip_for_event = enabled_audit_client_ip(&state);
    let result = tokio::spawn(with_audit_client_ip(audit_client_ip, async move {
        file_service
            .create_directory(
                admin,
                &operation_parent,
                &operation_name,
                audit_client_ip_for_event,
            )
            .await
    }))
    .await
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebFilesCreateTaskJoin,
            error,
        ))
    })?;
    let result = resolve_file_mutation(result)?;
    let result = super::session_bound(result)?;
    Ok(Redirect::to(&browser_redirect(
        &form.parent,
        if result.audit_durability.is_uncertain() {
            "audit_durability_uncertain"
        } else {
            "directory_created"
        },
    )))
}

pub(super) async fn rename_file_ui(
    State(state): State<FileRouteState>,
    headers: HeaderMap,
    Form(form): Form<RenameFileForm>,
) -> Result<Redirect> {
    let admin = mfa_session(&state, &headers, MissingSession::RedirectToLogin).await?;
    csrf(&admin, &form.csrf)?;
    let parent = parent_path(&form.path).unwrap_or_default();
    let file_service = state.file_service();
    let operation_path = form.path;
    let operation_name = form.name;
    let audit_client_ip = current_audit_client_ip();
    let audit_client_ip_for_event = enabled_audit_client_ip(&state);
    let result = tokio::spawn(with_audit_client_ip(audit_client_ip, async move {
        file_service
            .rename(
                admin,
                &operation_path,
                &operation_name,
                audit_client_ip_for_event,
            )
            .await
    }))
    .await
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebFilesRenameTaskJoin,
            error,
        ))
    })?;
    let result = resolve_file_mutation(result)?;
    let result = super::session_bound(result)?;
    Ok(Redirect::to(&browser_redirect(
        &parent,
        if result.audit_durability.is_uncertain() {
            "audit_durability_uncertain"
        } else {
            "path_renamed"
        },
    )))
}

pub(super) async fn delete_file_confirmation(
    State(state): State<FileRouteState>,
    headers: HeaderMap,
    Query(query): Query<DeleteFileQuery>,
) -> Result<Html<String>> {
    let admin = mfa_session(&state, &headers, MissingSession::RedirectToLogin).await?;
    let inspection = state
        .file_service()
        .inspect_delete(&query.path)
        .await
        .map_err(file_service_app_error)?;
    let locale = i18n::current_locale();
    let kind = if inspection.status.kind == crate::secure_fs::EntryKind::Directory {
        i18n::text(locale, i18n::FOLDER)
    } else {
        i18n::text(locale, i18n::FILE)
    };
    let heading = match locale {
        Locale::De => format!("{kind} permanent löschen?"),
        Locale::En => format!("Delete {kind} permanently?"),
    };
    let body = DeleteFileConfirmTemplate {
        heading,
        path: inspection.path.clone(),
        name: inspection.name,
        affected_shares: inspection.affected_shares,
        csrf_token: admin.csrf_token.clone(),
        confirmation_required: inspection.status.directory_non_empty,
        parent_path: encoded(parent_path(&inspection.path).as_deref().unwrap_or("")),
    };
    Ok(Html(super::templates::admin_page(
        &state,
        PageId::DeleteConfirm,
        &body,
        false,
        &admin.csrf_token,
        true,
    )?))
}

pub(super) async fn delete_file_ui(
    State(state): State<FileRouteState>,
    headers: HeaderMap,
    Form(form): Form<DeleteFileForm>,
) -> Result<Redirect> {
    let admin = mfa_session(&state, &headers, MissingSession::RedirectToLogin).await?;
    csrf(&admin, &form.csrf)?;
    let parent = parent_path(&form.path).unwrap_or_default();
    let file_service = state.file_service();
    let operation_path = form.path;
    let confirm_name = form.confirm_name;
    let audit_client_ip = current_audit_client_ip();
    let audit_client_ip_for_event = enabled_audit_client_ip(&state);
    let result = tokio::spawn(with_audit_client_ip(audit_client_ip, async move {
        file_service
            .delete(
                admin,
                &operation_path,
                confirm_name.as_deref(),
                audit_client_ip_for_event,
            )
            .await
    }))
    .await
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebFilesDeleteTaskJoin,
            error,
        ))
    })?;
    let result = resolve_file_mutation(result)?;
    let result = super::session_bound(result)?;
    let notice = if result.audit_durability.is_uncertain() {
        "audit_durability_uncertain"
    } else if result.cleanup_pending {
        "path_delete_queued"
    } else {
        "path_deleted"
    };
    Ok(Redirect::to(&browser_redirect(&parent, notice)))
}

pub(super) fn browser_redirect(path: &str, notice: &str) -> String {
    format!("/admin?path={}&notice={notice}", encoded(path))
}

pub(super) fn file_operation_app_error(error: file_ops::FileOperationError) -> AppError {
    use file_ops::FileOperationError;
    match error {
        FileOperationError::InvalidPath => AppError(StatusCode::BAD_REQUEST, "Invalid path"),
        FileOperationError::InvalidName => AppError(StatusCode::BAD_REQUEST, "Invalid name"),
        FileOperationError::NotFound => AppError(StatusCode::NOT_FOUND, "Target not found"),
        FileOperationError::Conflict => {
            AppError(StatusCode::CONFLICT, "Target name already exists")
        }
        FileOperationError::ConfirmationRequired { .. } => AppError(
            StatusCode::CONFLICT,
            "The exact folder name must be confirmed",
        ),
        FileOperationError::Database(database_error) => {
            AppError::from(crate::http_auth::database_error(database_error))
        }
        FileOperationError::DatabaseCapacity => AppError(
            StatusCode::SERVICE_UNAVAILABLE,
            crate::http_auth::DATABASE_BUSY_MESSAGE,
        ),
        other @ (FileOperationError::Io(_) | FileOperationError::Join(_)) => AppError::from(
            report_internal(InternalOperation::WebFilesOperationFailure, other),
        ),
    }
}

fn file_service_app_error(error: FileServiceError) -> AppError {
    match error {
        ServiceError::Validation(FileValidationError::InvalidPath) => {
            AppError(StatusCode::BAD_REQUEST, "Invalid path")
        }
        ServiceError::Validation(FileValidationError::InvalidName) => {
            AppError(StatusCode::BAD_REQUEST, "Invalid name")
        }
        ServiceError::NotFound => AppError(StatusCode::NOT_FOUND, "Target not found"),
        ServiceError::Conflict(FileConflict::DestinationExists) => {
            AppError(StatusCode::CONFLICT, "Target name already exists")
        }
        ServiceError::Conflict(FileConflict::ConfirmationRequired { .. }) => AppError(
            StatusCode::CONFLICT,
            "The exact folder name must be confirmed",
        ),
        error @ (ServiceError::Capacity(_)
        | ServiceError::AuditUnavailable(_)
        | ServiceError::Internal(_)) => AppError::from(crate::http_auth::service_error(
            error,
            InternalOperation::WebFilesOperationFailure,
        )),
    }
}

fn resolve_file_mutation<T>(outcome: FileMutationResult<T>) -> Result<crate::db::SessionBound<T>> {
    match outcome {
        Ok(audited) => Ok(crate::db::release_session_audited(audited)),
        Err(FileMutationError::AuditUncertain(outcome)) => Ok(outcome),
        Err(FileMutationError::Service(error)) => Err(file_service_app_error(error)),
    }
}
