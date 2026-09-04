use axum::{
    extract::{Path as AxPath, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    auth,
    db::{
        AuditAction, AuditContext, Permission, RequiredAuditEvent, Share,
        ShareControlsUpdateOutcome, ShareListOptions, ShareListSort, ShareListStatus,
        UploadConflictStrategy, MAX_SQLITE_UNSIGNED,
    },
    file_ops,
    http_auth::{
        csrf_header, current_audit_client_ip, database, hash_password_admitted, mfa_session,
        runtime_settings, session, MissingSession,
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
    common::find_share_by_id, session_bound, storage_recovery_api_error, ApiError, ApiResult,
    PasswordRequest, SimpleResponse,
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

#[derive(Default, Deserialize)]
pub(super) struct ShareListQuery {
    limit: Option<usize>,
    cursor: Option<i64>,
    q: Option<String>,
    status: Option<String>,
    sort: Option<String>,
}

#[derive(Serialize)]
pub(super) struct ShareListResponse {
    shares: Vec<ShareResponse>,
    next_cursor: Option<i64>,
}

pub(super) async fn list_shares(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ShareListQuery>,
) -> ApiResult<Json<ShareListResponse>> {
    session(&state, &headers, true, MissingSession::Unauthorized).await?;
    let limit = query.limit.unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(ApiError::bad_request(
            "Share list limit must be between 1 and 200",
        ));
    }
    if query.cursor.is_some_and(|cursor| cursor <= 0) {
        return Err(ApiError::bad_request("Share list cursor is invalid"));
    }
    let query_text = query
        .q
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if query_text
        .as_ref()
        .is_some_and(|value| value.len() > super::MAX_SEARCH_QUERY_BYTES)
    {
        return Err(ApiError::bad_request("Share search query is too long"));
    }
    let status = ShareListStatus::parse(query.status.as_deref().unwrap_or("all"))
        .ok_or_else(|| ApiError::bad_request("Share list status is invalid"))?;
    let sort = match query.sort.as_deref().unwrap_or("newest") {
        "newest" => ShareListSort::Newest,
        "oldest" => ShareListSort::Oldest,
        _ => return Err(ApiError::bad_request("Share list sort is invalid")),
    };
    let options = ShareListOptions {
        query: query_text,
        status,
        sort,
        cursor: query.cursor,
        limit,
        now: Utc::now(),
    };
    let settings = runtime_settings(&state);
    let page = database(state.db.clone(), move |db| db.list_share_page(&options)).await?;
    Ok(Json(ShareListResponse {
        shares: page
            .shares
            .into_iter()
            .map(|share| share_response(&settings, share))
            .collect(),
        next_cursor: page.next_cursor,
    }))
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
    let authenticated = mfa_session(&state, &headers, MissingSession::Unauthorized).await?;
    csrf_header(&authenticated, &headers)?;
    let settings = runtime_settings(&state);
    let service = ShareService::new(
        state.db.clone(),
        settings.clone(),
        !state.config.storage.replacements_allowed(),
    );
    let rel = service
        .normalize_target_path(&request.path)
        .map_err(share_validation_error)?;
    let secure_root = state.secure_root.clone();
    let metadata_path = rel.clone();
    let metadata = tokio::task::spawn_blocking(move || secure_root.metadata(&metadata_path))
        .await
        .map_err(ApiError::internal)?
        .map_err(|_| ApiError::not_found("Target not found"))?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(ApiError::bad_request(
            "Shares are allowed only for regular files or directories",
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
    let revalidation_path = rel.clone();
    let validated = service
        .prepare_create(CreateShareCommand {
            token,
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
            created_by: authenticated.admin_id,
        })
        .map_err(share_validation_error)?;
    let (prepared, password) = validated.into_password_hash_input();
    let password_hash = match password {
        Some(password) => Some(hash_password_admitted(&state, password).await?),
        None => None,
    };
    let storage_guard = state.storage_mutation.clone().lock_owned().await;
    let storage_guard = file_ops::recover_pending_file_operations_with_guard(&state, storage_guard)
        .await
        .map_err(storage_recovery_api_error)?;
    let secure_root = state.secure_root.clone();
    let metadata_path = revalidation_path;
    let current_metadata =
        tokio::task::spawn_blocking(move || secure_root.metadata(&metadata_path))
            .await
            .map_err(ApiError::internal)?
            .map_err(|_| ApiError::conflict("Target changed during processing"))?;
    let current_target = if current_metadata.is_dir() {
        ShareTarget::Directory
    } else if current_metadata.is_file() {
        ShareTarget::File
    } else {
        return Err(ApiError::conflict("Target changed during processing"));
    };
    if current_target != target {
        return Err(ApiError::conflict("Target changed during processing"));
    }
    let authority_mutation =
        ShareAuthorityMutation::from_guard(&state, storage_guard, authenticated.proof().clone());
    let username = authenticated.username.clone();
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(username, audit_client_ip);
    let (_created, share) = session_bound(
        authority_mutation
            .commit(move |_, proof| {
                // The database task is not cancelled with the request. The authority
                // mutation retains the storage lock so rename/delete cannot interleave
                // after the target metadata check and create a share for a stale path.
                service
                    .create_for_mfa_session(
                        &proof,
                        prepared,
                        password_hash.as_deref(),
                        &audit_context,
                    )
                    .map_err(share_database_error)
            })
            .await?,
    )?;
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
    let authenticated = mfa_session(&state, &headers, MissingSession::Unauthorized).await?;
    csrf_header(&authenticated, &headers)?;
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
    let authority_mutation =
        ShareAuthorityMutation::acquire(&state, authenticated.proof().clone()).await;
    let current_share = find_share_by_id(&state, id).await?;
    if request
        .upload_conflict_strategy
        .as_ref()
        .is_some_and(|strategy| {
            strategy.can_overwrite()
                && (!state.config.storage.replacements_allowed()
                    || !current_share.is_directory
                    || !current_share.permission.can_upload())
        })
    {
        return Err(ApiError::bad_request(
            "Overwriting is not allowed for this share",
        ));
    }
    let upload_limits =
        if request.max_upload_total_size.is_some() || request.max_upload_files.is_some() {
            if !current_share.is_directory || !current_share.permission.can_upload() {
                return Err(ApiError::bad_request(
                    "Upload limits are allowed only for upload shares",
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
                return Err(ApiError::bad_request("Invalid cumulative upload limits"));
            }
            Some((total, files))
        } else {
            None
        };
    let active = request.active;
    let strategy = request.upload_conflict_strategy.clone();
    let strategy_for_db = strategy.clone();
    let username = authenticated.username.clone();
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
                AuditAction::ShareActivated
            } else {
                AuditAction::ShareDeactivated
            },
            Some(object.clone()),
            None,
        ));
    }
    if strategy.is_some() {
        audit_events.push(RequiredAuditEvent::new(
            AuditAction::ShareUploadConflictUpdated,
            Some(object.clone()),
            None,
        ));
    }
    if let Some((total, files)) = upload_limits {
        audit_events.push(RequiredAuditEvent::new(
            AuditAction::ShareUploadLimitsUpdated,
            Some(object),
            Some(format!("bytes={total};files={files}")),
        ));
    }
    let (outcome, share) = session_bound(
        authority_mutation
            .commit(move |db, proof| {
                db.update_share_controls_for_mfa_session(
                    &proof,
                    id,
                    active,
                    strategy_for_db.as_ref(),
                    upload_limits,
                    &audit_context,
                    &audit_events,
                )
            })
            .await?,
    )?;
    match outcome {
        ShareControlsUpdateOutcome::Updated => {}
        ShareControlsUpdateOutcome::NotFound => {
            return Err(ApiError::not_found("Share not found"));
        }
        ShareControlsUpdateOutcome::QuotaConflict => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "upload_quota_in_use",
                "Upload limit is reserved by active uploads",
            ));
        }
    }
    let settings = runtime_settings(&state);
    let share = share.ok_or_else(|| ApiError::internal(()))?;
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
    let authenticated = mfa_session(&state, &headers, MissingSession::Unauthorized).await?;
    csrf_header(&authenticated, &headers)?;
    let username = authenticated.username.clone();
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(username, audit_client_ip);
    let authority_mutation =
        ShareAuthorityMutation::acquire(&state, authenticated.proof().clone()).await;
    let changed = session_bound(
        authority_mutation
            .commit(move |db, proof| {
                db.set_share_active_for_mfa_session(
                    &proof,
                    id,
                    active,
                    &audit_context,
                    if active {
                        AuditAction::ShareActivated
                    } else {
                        AuditAction::ShareDeactivated
                    },
                )
            })
            .await?,
    )?;
    if !changed {
        return Err(ApiError::not_found("Share not found"));
    }
    Ok(Json(SimpleResponse { ok: true }))
}

pub(super) async fn delete_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<SimpleResponse>> {
    let authenticated = mfa_session(&state, &headers, MissingSession::Unauthorized).await?;
    csrf_header(&authenticated, &headers)?;
    let username = authenticated.username.clone();
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(username, audit_client_ip);
    let authority_mutation =
        ShareAuthorityMutation::acquire(&state, authenticated.proof().clone()).await;
    let deleted = session_bound(
        authority_mutation
            .commit(move |db, proof| db.delete_share_for_mfa_session(&proof, id, &audit_context))
            .await?,
    )?;
    if !deleted {
        return Err(ApiError::not_found("Share not found"));
    }
    Ok(Json(SimpleResponse { ok: true }))
}

pub(super) async fn set_share_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Json(request): Json<PasswordRequest>,
) -> ApiResult<Json<SimpleResponse>> {
    let authenticated = mfa_session(&state, &headers, MissingSession::Unauthorized).await?;
    csrf_header(&authenticated, &headers)?;
    let service = ShareService::new(
        state.db.clone(),
        runtime_settings(&state),
        !state.config.storage.replacements_allowed(),
    );
    let password = service
        .prepare_password(SharePasswordInput::Direct(request.password))
        .map_err(share_validation_error)?
        .ok_or_else(|| ApiError::bad_request("Invalid share password"))?;
    let hash = hash_password_admitted(&state, password).await?;
    let username = authenticated.username.clone();
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(username, audit_client_ip);
    let authority_mutation =
        ShareAuthorityMutation::acquire(&state, authenticated.proof().clone()).await;
    let changed = session_bound(
        authority_mutation
            .commit(move |db, proof| {
                db.set_share_password_for_mfa_session(
                    &proof,
                    id,
                    Some(&hash),
                    &audit_context,
                    AuditAction::SharePasswordSet,
                )
            })
            .await?,
    )?;
    if !changed {
        return Err(ApiError::not_found("Share not found"));
    }
    Ok(Json(SimpleResponse { ok: true }))
}

fn share_validation_error(error: ShareServiceError) -> ApiError {
    match error {
        ShareServiceError::InvalidPath => ApiError::bad_request("Invalid path"),
        ShareServiceError::InvalidAlias => ApiError::bad_request("Invalid alias"),
        ShareServiceError::ExpirationNotFuture => {
            ApiError::bad_request("Expiration time must be in the future")
        }
        ShareServiceError::UploadPermissionRequiresDirectory => {
            ApiError::bad_request("Upload permission is not allowed for file shares")
        }
        ShareServiceError::InvalidDownloadLimit => ApiError::bad_request("Invalid transfer limit"),
        ShareServiceError::InvalidUploadLimit => ApiError::bad_request("Invalid upload limit"),
        ShareServiceError::UploadLimitsRequireDirectoryUpload => {
            ApiError::bad_request("Upload limits are allowed only for upload shares")
        }
        ShareServiceError::InvalidUploadTotalLimit
        | ShareServiceError::UploadTotalBelowSingleLimit => {
            ApiError::bad_request("Invalid cumulative upload limit")
        }
        ShareServiceError::InvalidUploadFileLimit => {
            ApiError::bad_request("Invalid upload file limit")
        }
        ShareServiceError::OverwriteRequiresDirectoryUpload => {
            ApiError::bad_request("Overwriting is not allowed for this share")
        }
        ShareServiceError::OverwriteDisabledForExternalWriters => {
            ApiError::bad_request("Overwriting is disabled with external storage writers")
        }
        ShareServiceError::PasswordConfirmationRequired
        | ShareServiceError::PasswordConfirmationMismatch
        | ShareServiceError::InvalidPasswordCharacterLength => {
            ApiError::bad_request("Invalid share password")
        }
        ShareServiceError::PasswordTooManyBytes => {
            ApiError::bad_request("Share password is too long")
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
    let authenticated = mfa_session(&state, &headers, MissingSession::Unauthorized).await?;
    csrf_header(&authenticated, &headers)?;
    let username = authenticated.username.clone();
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(username, audit_client_ip);
    let authority_mutation =
        ShareAuthorityMutation::acquire(&state, authenticated.proof().clone()).await;
    let changed = session_bound(
        authority_mutation
            .commit(move |db, proof| {
                db.set_share_password_for_mfa_session(
                    &proof,
                    id,
                    None,
                    &audit_context,
                    AuditAction::SharePasswordRemoved,
                )
            })
            .await?,
    )?;
    if !changed {
        return Err(ApiError::not_found("Share not found"));
    }
    Ok(Json(SimpleResponse { ok: true }))
}
