use axum::{
    extract::{Path as AxPath, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    auth,
    db::{
        AuditContext, Permission, RequiredAuditEvent, Share, ShareControlsUpdateOutcome,
        UploadConflictStrategy, MAX_SQLITE_UNSIGNED,
    },
    file_ops,
    http_auth::{
        csrf_header, current_audit_client_ip, database, hash_password_admitted, runtime_settings,
        session, MissingSession,
    },
    runtime::RuntimeSettings,
    sensitive::SecretString,
    services::share::{
        CreateShareCommand, ShareAuthorityMutation, SharePasswordInput, ShareService,
        ShareServiceError, ShareTarget,
    },
    AppState,
};

use super::{
    common::find_share_by_id, storage_recovery_api_error, ApiError, ApiResult, PasswordRequest,
    SimpleResponse,
};

#[derive(Serialize)]
pub(super) struct ShareResponse {
    id: i64,
    token: String,
    alias: Option<String>,
    url: String,
    path: String,
    is_directory: bool,
    permission: Permission,
    expires_at: Option<DateTime<Utc>>,
    max_downloads: Option<u64>,
    max_upload_size: Option<u64>,
    max_upload_total_size: Option<u64>,
    max_upload_files: Option<u64>,
    uploaded_bytes: u64,
    uploaded_files: u64,
    download_count: u64,
    active: bool,
    password_protected: bool,
    upload_conflict_strategy: UploadConflictStrategy,
}

fn share_response(settings: &RuntimeSettings, share: Share) -> ShareResponse {
    let public_path = share
        .alias
        .as_ref()
        .map(|alias| format!("s/{alias}"))
        .unwrap_or_else(|| format!("v/{}", share.token));
    ShareResponse {
        id: share.id,
        token: share.token,
        alias: share.alias,
        url: format!(
            "{}/{}",
            settings.public_base_url.trim_end_matches('/'),
            public_path
        ),
        path: share.relative_path,
        is_directory: share.is_directory,
        permission: share.permission,
        expires_at: share.expires_at,
        max_downloads: share.max_downloads,
        max_upload_size: share.max_upload_size,
        max_upload_total_size: share.max_upload_total_size,
        max_upload_files: share.max_upload_files,
        uploaded_bytes: share.uploaded_bytes,
        uploaded_files: share.uploaded_files,
        download_count: share.download_count,
        active: share.active,
        password_protected: share.password_hash.is_some(),
        upload_conflict_strategy: share.upload_conflict_strategy,
    }
}

pub(super) async fn list_shares(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<ShareResponse>>> {
    session(&state, &headers, true, MissingSession::Unauthorized).await?;
    let settings = runtime_settings(&state);
    let shares = database(state.db.clone(), |db| db.list_shares()).await?;
    Ok(Json(
        shares
            .into_iter()
            .map(|share| share_response(&settings, share))
            .collect(),
    ))
}

#[derive(Deserialize)]
pub(super) struct CreateShareRequest {
    path: String,
    permission: Permission,
    alias: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    max_downloads: Option<u64>,
    max_upload_size: Option<u64>,
    max_upload_total_size: Option<u64>,
    max_upload_files: Option<u64>,
    password: Option<SecretString>,
    overwrite_allowed: Option<bool>,
}

pub(super) async fn create_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateShareRequest>,
) -> ApiResult<Json<ShareResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    let settings = runtime_settings(&state);
    let service = ShareService::new(
        state.db.clone(),
        settings.clone(),
        state.config.storage.external_writers,
    );
    let rel = service
        .normalize_target_path(&request.path)
        .map_err(share_validation_error)?;
    let storage_guard = state.storage_mutation.clone().lock_owned().await;
    let storage_guard = file_ops::recover_pending_file_operations_with_guard(&state, storage_guard)
        .await
        .map_err(storage_recovery_api_error)?;
    let authority_mutation = ShareAuthorityMutation::from_guard(&state, storage_guard);
    let metadata = state
        .secure_root
        .metadata(&rel)
        .map_err(|_| ApiError::not_found("Ziel nicht gefunden"))?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(ApiError::bad_request(
            "Freigaben sind nur für reguläre Dateien oder Ordner erlaubt",
        ));
    }
    let target = if metadata.is_dir() {
        ShareTarget::Directory
    } else {
        ShareTarget::File
    };
    let token = auth::random_token(32);
    let password = request
        .password
        .map(SharePasswordInput::Direct)
        .unwrap_or(SharePasswordInput::None);
    let validated = service
        .prepare_create(CreateShareCommand {
            token: token.clone(),
            path: rel,
            target,
            permission: request.permission,
            alias: request.alias,
            expires_at: request.expires_at,
            max_downloads: request.max_downloads,
            max_upload_size: request.max_upload_size,
            max_upload_total_size: request.max_upload_total_size,
            max_upload_files: request.max_upload_files,
            password,
            overwrite_allowed: request.overwrite_allowed.unwrap_or(false),
            created_by: session_data.admin_id,
        })
        .map_err(share_validation_error)?;
    let (prepared, password) = validated.into_password_hash_input();
    let password_hash = match password {
        Some(password) => Some(hash_password_admitted(&state, password).await?),
        None => None,
    };
    let username = session_data.username;
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(username, audit_client_ip);
    authority_mutation
        .commit(move |_| {
            // The database task is not cancelled with the request. The authority
            // mutation retains the storage lock so rename/delete cannot interleave
            // after the target metadata check and create a share for a stale path.
            service
                .create(prepared, password_hash, &audit_context)
                .map(drop)
                .map_err(share_database_error)
        })
        .await?;
    let share = database(state.db.clone(), move |db| db.share_by_token(&token))
        .await?
        .ok_or_else(|| ApiError::internal(()))?;
    Ok(Json(share_response(&settings, share)))
}

#[derive(Deserialize)]
pub(super) struct UpdateShareRequest {
    active: Option<bool>,
    upload_conflict_strategy: Option<UploadConflictStrategy>,
    max_upload_total_size: Option<u64>,
    max_upload_files: Option<u64>,
}

pub(super) async fn update_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Json(request): Json<UpdateShareRequest>,
) -> ApiResult<Json<ShareResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    let no_changes = request.active.is_none()
        && request.upload_conflict_strategy.is_none()
        && request.max_upload_total_size.is_none()
        && request.max_upload_files.is_none();
    if no_changes {
        let current_share = find_share_by_id(&state, id).await?;
        return Ok(Json(share_response(
            &runtime_settings(&state),
            current_share,
        )));
    }
    let authority_mutation = ShareAuthorityMutation::acquire(&state).await;
    let current_share = find_share_by_id(&state, id).await?;
    if request
        .upload_conflict_strategy
        .as_ref()
        .is_some_and(|strategy| {
            strategy.can_overwrite()
                && (state.config.storage.external_writers
                    || !current_share.is_directory
                    || !current_share.permission.can_upload())
        })
    {
        return Err(ApiError::bad_request(
            "Überschreiben ist für diese Freigabe nicht erlaubt",
        ));
    }
    let upload_limits =
        if request.max_upload_total_size.is_some() || request.max_upload_files.is_some() {
            if !current_share.is_directory || !current_share.permission.can_upload() {
                return Err(ApiError::bad_request(
                    "Uploadlimits sind nur für Upload-Freigaben erlaubt",
                ));
            }
            let total = request
                .max_upload_total_size
                .or(current_share.max_upload_total_size)
                .ok_or_else(|| ApiError::internal(()))?;
            let files = request
                .max_upload_files
                .or(current_share.max_upload_files)
                .ok_or_else(|| ApiError::internal(()))?;
            let effective_single = current_share
                .max_upload_size
                .unwrap_or_else(|| runtime_settings(&state).max_upload_size)
                .min(crate::config::MAX_UPLOAD_SIZE);
            if total < effective_single
                || total < current_share.uploaded_bytes
                || total > MAX_SQLITE_UNSIGNED
                || files == 0
                || files < current_share.uploaded_files
                || files > MAX_SQLITE_UNSIGNED
            {
                return Err(ApiError::bad_request("Ungültige kumulative Uploadlimits"));
            }
            Some((total, files))
        } else {
            None
        };
    let active = request.active;
    let strategy = request.upload_conflict_strategy.clone();
    let strategy_for_db = strategy.clone();
    let username = session_data.username;
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(username, audit_client_ip);
    let object = id.to_string();
    let mut audit_events = Vec::new();
    if let Some(active) = active {
        audit_events.push(RequiredAuditEvent::new(
            if active {
                "share_activated"
            } else {
                "share_deactivated"
            },
            Some(object.clone()),
            None,
        ));
    }
    if strategy.is_some() {
        audit_events.push(RequiredAuditEvent::new(
            "share_upload_conflict_updated",
            Some(object.clone()),
            None,
        ));
    }
    if let Some((total, files)) = upload_limits {
        audit_events.push(RequiredAuditEvent::new(
            "share_upload_limits_updated",
            Some(object),
            Some(format!("bytes={total};files={files}")),
        ));
    }
    let outcome = authority_mutation
        .commit(move |db| {
            db.update_share_controls_and_audit(
                id,
                active,
                strategy_for_db.as_ref(),
                upload_limits,
                &audit_context,
                &audit_events,
            )
        })
        .await?;
    match outcome {
        ShareControlsUpdateOutcome::Updated => {}
        ShareControlsUpdateOutcome::NotFound => {
            return Err(ApiError::not_found("Freigabe nicht gefunden"));
        }
        ShareControlsUpdateOutcome::QuotaConflict => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "upload_quota_in_use",
                "Uploadlimit wird von laufenden Uploads belegt",
            ));
        }
    }
    let settings = runtime_settings(&state);
    let share = find_share_by_id(&state, id).await?;
    Ok(Json(share_response(&settings, share)))
}

pub(super) async fn activate_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<SimpleResponse>> {
    set_share_active_api(state, headers, id, true).await
}

pub(super) async fn deactivate_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<SimpleResponse>> {
    set_share_active_api(state, headers, id, false).await
}

async fn set_share_active_api(
    state: AppState,
    headers: HeaderMap,
    id: i64,
    active: bool,
) -> ApiResult<Json<SimpleResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    let username = session_data.username;
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(username, audit_client_ip);
    let authority_mutation = ShareAuthorityMutation::acquire(&state).await;
    let changed = authority_mutation
        .commit(move |db| {
            db.set_share_active_and_audit(
                id,
                active,
                &audit_context,
                if active {
                    "share_activated"
                } else {
                    "share_deactivated"
                },
            )
        })
        .await?;
    if !changed {
        return Err(ApiError::not_found("Freigabe nicht gefunden"));
    }
    Ok(Json(SimpleResponse { ok: true }))
}

pub(super) async fn delete_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<SimpleResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    let username = session_data.username;
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(username, audit_client_ip);
    let authority_mutation = ShareAuthorityMutation::acquire(&state).await;
    let deleted = authority_mutation
        .commit(move |db| db.delete_share_and_audit(id, &audit_context))
        .await?;
    if !deleted {
        return Err(ApiError::not_found("Freigabe nicht gefunden"));
    }
    Ok(Json(SimpleResponse { ok: true }))
}

pub(super) async fn set_share_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Json(request): Json<PasswordRequest>,
) -> ApiResult<Json<SimpleResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    let service = ShareService::new(
        state.db.clone(),
        runtime_settings(&state),
        state.config.storage.external_writers,
    );
    let password = service
        .prepare_password(SharePasswordInput::Direct(request.password))
        .map_err(share_validation_error)?
        .ok_or_else(|| ApiError::bad_request("Ungültiges Freigabepasswort"))?;
    let hash = hash_password_admitted(&state, password).await?;
    let username = session_data.username;
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(username, audit_client_ip);
    let authority_mutation = ShareAuthorityMutation::acquire(&state).await;
    let changed = authority_mutation
        .commit(move |db| {
            db.set_share_password_and_audit(id, Some(&hash), &audit_context, "share_password_set")
        })
        .await?;
    if !changed {
        return Err(ApiError::not_found("Freigabe nicht gefunden"));
    }
    Ok(Json(SimpleResponse { ok: true }))
}

fn share_validation_error(error: ShareServiceError) -> ApiError {
    match error {
        ShareServiceError::InvalidPath => ApiError::bad_request("Ungültiger Pfad"),
        ShareServiceError::InvalidAlias => ApiError::bad_request("Ungültiger Alias"),
        ShareServiceError::ExpirationNotFuture => {
            ApiError::bad_request("Ablaufzeit muss in der Zukunft liegen")
        }
        ShareServiceError::UploadPermissionRequiresDirectory => {
            ApiError::bad_request("Upload-Rechte sind für Datei-Freigaben nicht erlaubt")
        }
        ShareServiceError::InvalidDownloadLimit => {
            ApiError::bad_request("Ungültiges Übertragungslimit")
        }
        ShareServiceError::InvalidUploadLimit => ApiError::bad_request("Ungültiges Uploadlimit"),
        ShareServiceError::UploadLimitsRequireDirectoryUpload => {
            ApiError::bad_request("Uploadlimits sind nur für Upload-Freigaben erlaubt")
        }
        ShareServiceError::InvalidUploadTotalLimit
        | ShareServiceError::UploadTotalBelowSingleLimit => {
            ApiError::bad_request("Ungültiges kumulatives Uploadlimit")
        }
        ShareServiceError::InvalidUploadFileLimit => {
            ApiError::bad_request("Ungültiges Upload-Dateilimit")
        }
        ShareServiceError::OverwriteRequiresDirectoryUpload => {
            ApiError::bad_request("Überschreiben ist für diese Freigabe nicht erlaubt")
        }
        ShareServiceError::OverwriteDisabledForExternalWriters => {
            ApiError::bad_request("Überschreiben ist bei externen Storage-Schreibern deaktiviert")
        }
        ShareServiceError::PasswordConfirmationRequired
        | ShareServiceError::PasswordConfirmationMismatch
        | ShareServiceError::InvalidPasswordCharacterLength => {
            ApiError::bad_request("Ungültiges Freigabepasswort")
        }
        ShareServiceError::PasswordTooManyBytes => {
            ApiError::bad_request("Freigabepasswort ist zu lang")
        }
        ShareServiceError::PasswordHashStateMismatch => ApiError::internal(()),
        ShareServiceError::Database(error) => ApiError::internal(error),
    }
}

fn share_database_error(error: ShareServiceError) -> rusqlite::Error {
    error
        .into_database_error()
        .unwrap_or(rusqlite::Error::InvalidQuery)
}

pub(super) async fn remove_share_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<SimpleResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    let username = session_data.username;
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(username, audit_client_ip);
    let authority_mutation = ShareAuthorityMutation::acquire(&state).await;
    let changed = authority_mutation
        .commit(move |db| {
            db.set_share_password_and_audit(id, None, &audit_context, "share_password_removed")
        })
        .await?;
    if !changed {
        return Err(ApiError::not_found("Freigabe nicht gefunden"));
    }
    Ok(Json(SimpleResponse { ok: true }))
}
