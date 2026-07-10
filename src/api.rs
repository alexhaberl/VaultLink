use std::{net::SocketAddr, path::Path};

use axum::{
    body::Body,
    extract::DefaultBodyLimit,
    extract::{ConnectInfo, Path as AxPath, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put},
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    auth,
    db::{
        AdminDeactivationOutcome, AdminSummary, AuditEvent, Permission, Share,
        UploadConflictStrategy,
    },
    file_ops,
    http_auth::{
        audit, clear_session_cookie, commit_runtime_settings, csrf_header, database,
        make_session_cookie, make_unlock_cookie, runtime_settings, session, share_is_unlocked,
        MissingSession, UnlockCookieScope,
    },
    path_security, proxy,
    runtime::RuntimeSettings,
    AppState,
};

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

type ApiResult<T> = std::result::Result<T, ApiError>;

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
        }
    }
    fn bad_request(message: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }
    fn not_found(message: &'static str) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }
    fn internal<T>(_: T) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Interner Fehler",
        )
    }
}

impl From<crate::http_auth::HttpAuthError> for ApiError {
    fn from(value: crate::http_auth::HttpAuthError) -> Self {
        let code = match value.status {
            StatusCode::UNAUTHORIZED => "unauthorized",
            StatusCode::FORBIDDEN => "forbidden",
            StatusCode::TOO_MANY_REQUESTS => "rate_limited",
            _ => "request_failed",
        };
        Self::new(value.status, code, value.message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct ErrorBody {
            error: ErrorObject,
        }
        #[derive(Serialize)]
        struct ErrorObject {
            code: &'static str,
            message: &'static str,
        }
        (
            self.status,
            Json(ErrorBody {
                error: ErrorObject {
                    code: self.code,
                    message: self.message,
                },
            }),
        )
            .into_response()
    }
}

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/session/login", post(login))
        .route("/session/mfa", post(mfa))
        .route("/session/logout", post(logout))
        .route("/session/me", get(me))
        .route(
            "/files",
            get(files)
                .patch(rename_file_entry)
                .delete(delete_file_entry),
        )
        .route("/files/directories", post(create_directory))
        .route("/shares", get(list_shares).post(create_share))
        .route("/shares/{id}", patch(update_share).delete(delete_share))
        .route("/shares/{id}/activate", post(activate_share))
        .route("/shares/{id}/deactivate", post(deactivate_share))
        .route(
            "/shares/{id}/password",
            put(set_share_password).delete(remove_share_password),
        )
        .route("/admins", get(list_admins).post(create_admin))
        .route("/admins/{id}/activate", post(activate_admin))
        .route("/admins/{id}/deactivate", post(deactivate_admin))
        .route("/admins/{id}/password", put(reset_admin_password))
        .route("/admins/{id}/totp/reset", post(reset_admin_totp))
        .route("/settings", get(get_settings).put(update_settings))
        .route("/audit", get(list_audit))
        .route("/audit/client-ips", delete(delete_audit_client_ips))
        .route("/public/shares/{token}", get(public_share))
        .route("/public/shares/{token}/unlock", post(unlock_share))
        .route(
            "/public/shares/{token}/download",
            get(crate::web::download).head(crate::web::download),
        )
        .route(
            "/public/shares/{token}/preview",
            get(crate::web::public_preview),
        )
        .route(
            "/public/shares/{token}/preview/raw",
            get(crate::web::public_preview_raw).head(crate::web::public_preview_raw),
        )
        .route(
            "/public/shares/{token}/download.zip",
            get(crate::web::download_zip),
        )
        .route(
            "/public/shares/{token}/upload",
            post(crate::web::upload)
                .layer(DefaultBodyLimit::max(
                    crate::web::HARD_MULTIPART_LIMIT.min(usize::MAX as u64) as usize,
                ))
                .layer(middleware::from_fn(crate::web::guard_multipart_upload)),
        )
        .layer(middleware::from_fn(normalize_api_errors))
        .with_state(state)
}

async fn normalize_api_errors(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    if !(response.status().is_client_error() || response.status().is_server_error()) {
        return response;
    }
    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    if is_json {
        return response;
    }
    let status = response.status();
    let code = status_code_name(status);
    let message = status.canonical_reason().unwrap_or("Request failed");
    let body = format!(r#"{{"error":{{"code":"{code}","message":"{message}"}}}}"#);
    let mut normalized = Response::new(Body::from(body));
    *normalized.status_mut() = status;
    normalized.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    normalized
}

fn status_code_name(status: StatusCode) -> &'static str {
    match status {
        StatusCode::BAD_REQUEST => "bad_request",
        StatusCode::UNAUTHORIZED => "unauthorized",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::CONFLICT => "conflict",
        StatusCode::GONE => "gone",
        StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "unsupported_media_type",
        StatusCode::TOO_MANY_REQUESTS => "rate_limited",
        StatusCode::RANGE_NOT_SATISFIABLE => "range_not_satisfiable",
        StatusCode::INSUFFICIENT_STORAGE => "insufficient_storage",
        _ if status.is_server_error() => "internal_error",
        _ => "request_failed",
    }
}

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
    version: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    mfa_required: bool,
    csrf_token: String,
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(form): Json<LoginRequest>,
) -> ApiResult<Response> {
    let ip = proxy::effective_client_ip(peer.ip(), &headers, &state.config);
    let key = format!("{}:{}", ip, form.username.to_lowercase());
    let ip_key = format!("ip:{ip}");
    if !state.limiter.allowed(&key) || !state.limiter.allowed(&ip_key) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Zu viele Anmeldeversuche",
        ));
    }
    let username = form.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username)).await?;
    let password_hash = admin.as_ref().map(|admin| admin.password_hash.clone());
    let password = form.password;
    let valid = tokio::task::spawn_blocking(move || match password_hash {
        Some(hash) => auth::verify_password(&hash, &password),
        None => {
            let _ = auth::hash_password(&password);
            false
        }
    })
    .await
    .map_err(ApiError::internal)?;
    if !valid {
        state.limiter.failure(&key);
        state.limiter.failure(&ip_key);
        audit(&state, form.username, "login_failed", None, None).await;
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Ungültige Zugangsdaten",
        ));
    }
    state.limiter.success(&key);
    state.limiter.success(&ip_key);
    let admin = admin.expect("valid password requires active admin");
    let token = auth::random_token(32);
    let csrf = auth::random_token(24);
    let expires = Utc::now() + Duration::hours(state.config.security.session_hours);
    let session_token = token.clone();
    let session_csrf = csrf.clone();
    let admin_id = admin.id;
    database(state.db.clone(), move |db| {
        db.create_session(&session_token, admin_id, &session_csrf, expires)
    })
    .await?;
    audit(&state, admin.username, "password_verified", None, None).await;
    let mut response = Json(LoginResponse {
        mfa_required: true,
        csrf_token: csrf,
    })
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&make_session_cookie(&state, &token)).map_err(ApiError::internal)?,
    );
    Ok(response)
}

#[derive(Deserialize)]
struct MfaRequest {
    code: String,
}

async fn mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(form): Json<MfaRequest>,
) -> ApiResult<Json<MeResponse>> {
    let (token, session_data) =
        session(&state, &headers, false, MissingSession::Unauthorized).await?;
    let key = format!("mfa:{}", session_data.username.to_lowercase());
    if !state.limiter.allowed(&key) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Zu viele MFA-Versuche",
        ));
    }
    let username = session_data.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username))
        .await?
        .ok_or_else(|| ApiError::internal(()))?;
    if !auth::verify_totp_now(&admin.totp_secret, &form.code) {
        state.limiter.failure(&key);
        audit(&state, session_data.username, "mfa_failed", None, None).await;
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_mfa",
            "Ungültiger MFA-Code",
        ));
    }
    state.limiter.success(&key);
    database(state.db.clone(), move |db| db.verify_mfa(&token)).await?;
    audit(
        &state,
        session_data.username.clone(),
        "login_success",
        None,
        None,
    )
    .await;
    Ok(Json(MeResponse {
        authenticated: true,
        admin_id: session_data.admin_id,
        username: session_data.username,
        mfa_verified: true,
        csrf_token: session_data.csrf_token,
    }))
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    let (token, session_data) =
        session(&state, &headers, false, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    database(state.db.clone(), move |db| db.delete_session(&token)).await?;
    audit(&state, session_data.username, "logout", None, None).await;
    let mut response = Json(SimpleResponse { ok: true }).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_session_cookie(&state)).map_err(ApiError::internal)?,
    );
    Ok(response)
}

#[derive(Serialize)]
struct MeResponse {
    authenticated: bool,
    admin_id: i64,
    username: String,
    mfa_verified: bool,
    csrf_token: String,
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<MeResponse>> {
    let (_, session_data) = session(&state, &headers, false, MissingSession::Unauthorized).await?;
    Ok(Json(MeResponse {
        authenticated: true,
        admin_id: session_data.admin_id,
        username: session_data.username,
        mfa_verified: session_data.mfa_verified,
        csrf_token: session_data.csrf_token,
    }))
}

#[derive(Serialize)]
struct SimpleResponse {
    ok: bool,
}

#[derive(Default, Deserialize)]
struct FilesQuery {
    path: Option<String>,
    page: Option<usize>,
    q: Option<String>,
}

#[derive(Serialize)]
struct FileEntryResponse {
    name: String,
    path: String,
    kind: &'static str,
    size: Option<u64>,
    modified: Option<String>,
    preview_allowed: bool,
}

#[derive(Serialize)]
struct FilesResponse {
    path: String,
    page: usize,
    has_next: bool,
    truncated: bool,
    entries: Vec<FileEntryResponse>,
}

fn list_file_page(
    secure_root: crate::secure_fs::SecureRoot,
    relative: &str,
    page: usize,
    query: Option<&str>,
    scan_limit: usize,
) -> std::io::Result<(Vec<crate::secure_fs::Entry>, bool)> {
    let needle = query.map(str::to_ascii_lowercase);
    let skip = page.saturating_mul(100);
    let mut matched = 0usize;
    let mut scanned = 0usize;
    let mut results = Vec::new();
    let mut truncated = false;
    let mut directory = secure_root.scan_directory(relative)?;
    while results.len() < 101 {
        let remaining = scan_limit.saturating_sub(scanned);
        if remaining == 0 {
            let sentinel = directory.run_batch(1)?;
            truncated = sentinel.scanned != 0 || !sentinel.complete;
            break;
        }
        let batch = directory.run_batch(remaining.min(100))?;
        scanned = scanned.saturating_add(batch.scanned);
        for entry in batch.entries {
            if needle
                .as_ref()
                .is_none_or(|needle| entry.name.to_ascii_lowercase().contains(needle))
            {
                if matched >= skip && results.len() < 101 {
                    results.push(entry);
                }
                matched = matched.saturating_add(1);
            }
        }
        if batch.complete {
            break;
        }
    }
    Ok((results, truncated))
}

async fn files(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<FilesQuery>,
) -> ApiResult<Json<FilesResponse>> {
    session(&state, &headers, true, MissingSession::Unauthorized).await?;
    let settings = runtime_settings(&state);
    let raw = query.path.unwrap_or_default();
    let rel = validate_rel(&raw)?;
    let page = query.page.unwrap_or(0).min(1_000_000);
    let search = query
        .q
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let secure_root = state.secure_root.clone();
    let scan_limit = settings.max_search_entries;
    let (entries, truncated) = tokio::task::spawn_blocking(move || {
        list_file_page(secure_root, &rel, page, search.as_deref(), scan_limit)
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(ApiError::internal)?;
    let mut entries = entries
        .into_iter()
        .map(|entry| {
            let path = if raw.is_empty() {
                entry.name.clone()
            } else {
                format!("{}/{}", raw.trim_matches('/'), entry.name)
            };
            FileEntryResponse {
                name: entry.name,
                path: path.clone(),
                kind: if entry.is_dir { "directory" } else { "file" },
                size: (!entry.is_dir).then_some(entry.len),
                modified: entry
                    .modified
                    .map(|time| DateTime::<Utc>::from(time).to_rfc3339()),
                preview_allowed: !entry.is_dir && preview_allowed(&path, &settings),
            }
        })
        .collect::<Vec<_>>();
    let has_next = entries.len() > 100;
    entries.truncate(100);
    Ok(Json(FilesResponse {
        path: raw,
        page,
        has_next,
        truncated,
        entries,
    }))
}

#[derive(Deserialize)]
struct CreateDirectoryRequest {
    #[serde(default)]
    parent: String,
    name: String,
}

#[derive(Deserialize)]
struct RenameFileRequest {
    path: String,
    name: String,
}

#[derive(Deserialize)]
struct DeleteFileRequest {
    path: String,
    confirm_name: Option<String>,
}

#[derive(Serialize)]
struct CreatedDirectoryResponse {
    ok: bool,
    path: String,
    kind: &'static str,
}

#[derive(Serialize)]
struct RenamedFileResponse {
    ok: bool,
    path: String,
    kind: &'static str,
    updated_shares: usize,
}

#[derive(Serialize)]
struct DeletedFileResponse {
    ok: bool,
    path: String,
    kind: &'static str,
    deactivated_shares: usize,
    cleanup_pending: bool,
}

async fn create_directory(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateDirectoryRequest>,
) -> ApiResult<Response> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    let result = file_ops::create_directory(&state, &request.parent, &request.name)
        .await
        .map_err(file_operation_error)?;
    audit(
        &state,
        session_data.username,
        "directory_created",
        Some(result.path.clone()),
        None,
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(CreatedDirectoryResponse {
            ok: true,
            path: result.path,
            kind: "directory",
        }),
    )
        .into_response())
}

async fn rename_file_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RenameFileRequest>,
) -> ApiResult<Json<RenamedFileResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    let old_path = request.path.clone();
    let result = file_ops::rename(&state, &request.path, &request.name)
        .await
        .map_err(file_operation_error)?;
    audit(
        &state,
        session_data.username,
        "path_renamed",
        Some(result.path.clone()),
        Some(format!(
            "old_path={old_path};updated_shares={}",
            result.updated_shares
        )),
    )
    .await;
    Ok(Json(RenamedFileResponse {
        ok: true,
        path: result.path,
        kind: file_ops::kind_name(result.kind),
        updated_shares: result.updated_shares,
    }))
}

async fn delete_file_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DeleteFileRequest>,
) -> ApiResult<Response> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    let result = file_ops::delete(&state, &request.path, request.confirm_name.as_deref())
        .await
        .map_err(file_operation_error)?;
    audit(
        &state,
        session_data.username,
        "path_deleted",
        Some(result.path.clone()),
        Some(format!(
            "kind={};deactivated_shares={};cleanup={}",
            file_ops::kind_name(result.kind),
            result.deactivated_shares,
            if result.cleanup_pending {
                "pending"
            } else {
                "complete"
            }
        )),
    )
    .await;
    let status = if result.cleanup_pending {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(DeletedFileResponse {
            ok: true,
            path: result.path,
            kind: file_ops::kind_name(result.kind),
            deactivated_shares: result.deactivated_shares,
            cleanup_pending: result.cleanup_pending,
        }),
    )
        .into_response())
}

fn file_operation_error(error: file_ops::FileOperationError) -> ApiError {
    use file_ops::FileOperationError;
    match error {
        FileOperationError::InvalidPath => {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_path", "Ungültiger Pfad")
        }
        FileOperationError::InvalidName => {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_name", "Ungültiger Name")
        }
        FileOperationError::NotFound => ApiError::not_found("Ziel nicht gefunden"),
        FileOperationError::Conflict => ApiError::new(
            StatusCode::CONFLICT,
            "conflict",
            "Zielname ist bereits vorhanden",
        ),
        FileOperationError::ConfirmationRequired { .. } => ApiError::new(
            StatusCode::CONFLICT,
            "confirmation_required",
            "Der exakte Ordnername muss bestätigt werden",
        ),
        FileOperationError::Database(_)
        | FileOperationError::Io(_)
        | FileOperationError::Join(_) => ApiError::internal(error),
    }
}

#[derive(Serialize)]
struct ShareResponse {
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
        url: format!("{}/{}", settings.public_base_url, public_path),
        path: share.relative_path,
        is_directory: share.is_directory,
        permission: share.permission,
        expires_at: share.expires_at,
        max_downloads: share.max_downloads,
        max_upload_size: share.max_upload_size,
        download_count: share.download_count,
        active: share.active,
        password_protected: share.password_hash.is_some(),
        upload_conflict_strategy: share.upload_conflict_strategy,
    }
}

async fn list_shares(
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
struct CreateShareRequest {
    path: String,
    permission: Permission,
    alias: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    max_downloads: Option<u64>,
    max_upload_size: Option<u64>,
    password: Option<String>,
    overwrite_allowed: Option<bool>,
}

async fn create_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateShareRequest>,
) -> ApiResult<Json<ShareResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    let _storage_guard = state.storage_mutation.lock().await;
    let settings = runtime_settings(&state);
    let rel = validate_rel(&request.path)?;
    let metadata = state
        .secure_root
        .metadata(&rel)
        .map_err(|_| ApiError::not_found("Ziel nicht gefunden"))?;
    if metadata.is_file() && request.permission.can_upload() {
        return Err(ApiError::bad_request(
            "Upload-Rechte sind für Datei-Freigaben nicht erlaubt",
        ));
    }
    if request.max_downloads == Some(0) {
        return Err(ApiError::bad_request(
            "Das Übertragungslimit muss mindestens 1 sein",
        ));
    }
    if request.max_upload_size == Some(0) {
        return Err(ApiError::bad_request(
            "Uploadlimit muss mindestens 1 Byte sein",
        ));
    }
    let alias = request
        .alias
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(validate_alias)
        .transpose()?;
    let password_hash = if let Some(password) = request
        .password
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        validate_share_password(&settings, password)?;
        Some(
            tokio::task::spawn_blocking({
                let password = password.to_string();
                move || auth::hash_password(&password)
            })
            .await
            .map_err(ApiError::internal)?
            .map_err(ApiError::internal)?,
        )
    } else {
        None
    };
    let strategy = if metadata.is_dir()
        && request.permission.can_upload()
        && request.overwrite_allowed.unwrap_or(false)
    {
        UploadConflictStrategy::OverwriteAllowed
    } else {
        UploadConflictStrategy::Reject
    };
    let audit_detail = format!(
        "path={rel};permission={};alias={};expires_at={};transfer_limit={};upload_limit={};password_protected={};overwrite_allowed={}",
        request.permission.as_str(),
        alias.as_deref().unwrap_or(""),
        request
            .expires_at
            .map(|value| value.to_rfc3339())
            .unwrap_or_default(),
        request
            .max_downloads
            .map(|value| value.to_string())
            .unwrap_or_default(),
        request
            .max_upload_size
            .map(|value| value.to_string())
            .unwrap_or_default(),
        password_hash.is_some(),
        strategy.can_overwrite(),
    );
    let token = auth::random_token(32);
    let token_for_db = token.clone();
    let rel_for_db = rel.clone();
    let permission = request.permission.clone();
    let expires_at = request.expires_at;
    let max_downloads = request.max_downloads;
    let max_upload_size = request.max_upload_size;
    let admin_id = session_data.admin_id;
    let password_hash_for_db = password_hash.clone();
    let strategy_for_db = strategy.clone();
    let share_id = database(state.db.clone(), move |db| {
        db.create_share(
            &token_for_db,
            alias.as_deref(),
            &rel_for_db,
            metadata.is_dir(),
            &permission,
            expires_at,
            max_downloads,
            max_upload_size,
            admin_id,
            password_hash_for_db.as_deref(),
            &strategy_for_db,
        )
    })
    .await?;
    audit(
        &state,
        session_data.username,
        "share_created",
        Some(share_id.to_string()),
        Some(audit_detail),
    )
    .await;
    let share = database(state.db.clone(), move |db| db.share_by_token(&token))
        .await?
        .ok_or_else(|| ApiError::internal(()))?;
    Ok(Json(share_response(&settings, share)))
}

#[derive(Deserialize)]
struct UpdateShareRequest {
    active: Option<bool>,
    upload_conflict_strategy: Option<UploadConflictStrategy>,
}

async fn update_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Json(request): Json<UpdateShareRequest>,
) -> ApiResult<Json<ShareResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    if let Some(active) = request.active {
        database(state.db.clone(), move |db| db.set_share_active(id, active)).await?;
        audit(
            &state,
            session_data.username.clone(),
            if active {
                "share_activated"
            } else {
                "share_deactivated"
            },
            Some(id.to_string()),
            None,
        )
        .await;
    }
    if let Some(strategy) = request.upload_conflict_strategy {
        let changed = database(state.db.clone(), move |db| {
            db.set_upload_conflict_strategy(id, &strategy)
        })
        .await?;
        if !changed {
            return Err(ApiError::not_found("Freigabe nicht gefunden"));
        }
        audit(
            &state,
            session_data.username,
            "share_upload_conflict_updated",
            Some(id.to_string()),
            None,
        )
        .await;
    }
    let settings = runtime_settings(&state);
    let share = find_share_by_id(&state, id).await?;
    Ok(Json(share_response(&settings, share)))
}

async fn activate_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<SimpleResponse>> {
    set_share_active_api(state, headers, id, true).await
}

async fn deactivate_share(
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
    database(state.db.clone(), move |db| db.set_share_active(id, active)).await?;
    audit(
        &state,
        session_data.username,
        if active {
            "share_activated"
        } else {
            "share_deactivated"
        },
        Some(id.to_string()),
        None,
    )
    .await;
    Ok(Json(SimpleResponse { ok: true }))
}

async fn delete_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<SimpleResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    database(state.db.clone(), move |db| db.delete_share(id)).await?;
    audit(
        &state,
        session_data.username,
        "share_deleted",
        Some(id.to_string()),
        None,
    )
    .await;
    Ok(Json(SimpleResponse { ok: true }))
}

#[derive(Deserialize)]
struct PasswordRequest {
    password: String,
}

async fn set_share_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Json(request): Json<PasswordRequest>,
) -> ApiResult<Json<SimpleResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    validate_share_password(&runtime_settings(&state), &request.password)?;
    let hash = tokio::task::spawn_blocking(move || auth::hash_password(&request.password))
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)?;
    let changed = database(state.db.clone(), move |db| {
        db.set_share_password(id, Some(&hash))
    })
    .await?;
    if !changed {
        return Err(ApiError::not_found("Freigabe nicht gefunden"));
    }
    audit(
        &state,
        session_data.username,
        "share_password_set",
        Some(id.to_string()),
        None,
    )
    .await;
    Ok(Json(SimpleResponse { ok: true }))
}

async fn remove_share_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<SimpleResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    let changed = database(state.db.clone(), move |db| db.set_share_password(id, None)).await?;
    if !changed {
        return Err(ApiError::not_found("Freigabe nicht gefunden"));
    }
    audit(
        &state,
        session_data.username,
        "share_password_removed",
        Some(id.to_string()),
        None,
    )
    .await;
    Ok(Json(SimpleResponse { ok: true }))
}

#[derive(Serialize)]
struct AdminResponse {
    id: i64,
    username: String,
    created_at: String,
    active: bool,
}

fn admin_response(admin: AdminSummary) -> AdminResponse {
    AdminResponse {
        id: admin.id,
        username: admin.username,
        created_at: admin.created_at,
        active: admin.active,
    }
}

async fn list_admins(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<AdminResponse>>> {
    session(&state, &headers, true, MissingSession::Unauthorized).await?;
    let admins = database(state.db.clone(), |db| db.list_admins()).await?;
    Ok(Json(admins.into_iter().map(admin_response).collect()))
}

#[derive(Deserialize)]
struct CreateAdminRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct CreatedAdminResponse {
    id: i64,
    username: String,
    totp_secret: String,
    otpauth_url: String,
}

async fn create_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateAdminRequest>,
) -> ApiResult<Json<CreatedAdminResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    validate_admin_username(&request.username)?;
    validate_admin_password(&request.password)?;
    let password_hash = tokio::task::spawn_blocking({
        let password = request.password.clone();
        move || auth::hash_password(&password)
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(ApiError::internal)?;
    let secret = auth::new_totp_secret();
    let username = request.username.clone();
    let secret_for_db = secret.clone();
    database(state.db.clone(), move |db| {
        db.create_admin(&username, &password_hash, &secret_for_db)
    })
    .await?;
    let admin = database(state.db.clone(), {
        let username = request.username.clone();
        move |db| db.admin(&username)
    })
    .await?
    .ok_or_else(|| ApiError::internal(()))?;
    audit(
        &state,
        session_data.username,
        "admin_created",
        Some(admin.id.to_string()),
        None,
    )
    .await;
    Ok(Json(CreatedAdminResponse {
        id: admin.id,
        username: admin.username.clone(),
        totp_secret: secret.clone(),
        otpauth_url: format!(
            "otpauth://totp/VaultLink:{}?secret={}&issuer=VaultLink",
            admin.username, secret
        ),
    }))
}

async fn activate_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<SimpleResponse>> {
    set_admin_active_api(state, headers, id, true).await
}

async fn deactivate_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<SimpleResponse>> {
    set_admin_active_api(state, headers, id, false).await
}

async fn set_admin_active_api(
    state: AppState,
    headers: HeaderMap,
    id: i64,
    active: bool,
) -> ApiResult<Json<SimpleResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    if !active && id == session_data.admin_id {
        return Err(ApiError::bad_request(
            "Eigener Admin kann nicht stillgelegt werden",
        ));
    }
    if active {
        if !database(state.db.clone(), move |db| db.activate_admin(id)).await? {
            return Err(ApiError::not_found("Admin nicht gefunden"));
        }
    } else {
        match database(state.db.clone(), move |db| db.deactivate_admin(id)).await? {
            AdminDeactivationOutcome::Deactivated | AdminDeactivationOutcome::AlreadyInactive => {}
            AdminDeactivationOutcome::LastActive => {
                return Err(ApiError::bad_request(
                    "Letzter aktiver Admin kann nicht stillgelegt werden",
                ));
            }
            AdminDeactivationOutcome::NotFound => {
                return Err(ApiError::not_found("Admin nicht gefunden"));
            }
        }
    }
    audit(
        &state,
        session_data.username,
        if active {
            "admin_activated"
        } else {
            "admin_deactivated"
        },
        Some(id.to_string()),
        None,
    )
    .await;
    Ok(Json(SimpleResponse { ok: true }))
}

async fn reset_admin_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Json(request): Json<PasswordRequest>,
) -> ApiResult<Json<SimpleResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    if id == session_data.admin_id {
        return Err(ApiError::bad_request(
            "Eigenes Passwort wird in 0.3 nicht über diese API geändert",
        ));
    }
    validate_admin_password(&request.password)?;
    let hash = tokio::task::spawn_blocking(move || auth::hash_password(&request.password))
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)?;
    let changed = database(state.db.clone(), move |db| {
        db.reset_admin_password(id, &hash)
    })
    .await?;
    if !changed {
        return Err(ApiError::not_found("Admin nicht gefunden"));
    }
    audit(
        &state,
        session_data.username,
        "admin_password_reset",
        Some(id.to_string()),
        None,
    )
    .await;
    Ok(Json(SimpleResponse { ok: true }))
}

async fn reset_admin_totp(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<CreatedAdminResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    if id == session_data.admin_id {
        return Err(ApiError::bad_request(
            "Eigene MFA wird in 0.3 nicht über diese API geändert",
        ));
    }
    let secret = auth::new_totp_secret();
    let secret_for_db = secret.clone();
    let username = database(state.db.clone(), move |db| {
        db.reset_admin_totp(id, &secret_for_db)
    })
    .await?
    .ok_or_else(|| ApiError::not_found("Admin nicht gefunden"))?;
    audit(
        &state,
        session_data.username,
        "admin_totp_reset",
        Some(id.to_string()),
        None,
    )
    .await;
    Ok(Json(CreatedAdminResponse {
        id,
        username: username.clone(),
        totp_secret: secret.clone(),
        otpauth_url: format!(
            "otpauth://totp/VaultLink:{}?secret={}&issuer=VaultLink",
            username, secret
        ),
    }))
}

#[derive(Serialize, Deserialize)]
struct SettingsBody {
    public_base_url: String,
    max_upload_size: u64,
    blocked_extensions: Vec<String>,
    share_password_min_length: usize,
    share_password_max_length: usize,
    share_unlock_minutes: i64,
    max_zip_size: u64,
    max_zip_files: usize,
    max_search_entries: usize,
    max_search_results: usize,
    max_preview_size: u64,
    preview_extensions: Vec<String>,
    image_preview_extensions: Vec<String>,
    pdf_preview_enabled: bool,
    max_media_preview_size: u64,
    #[serde(default)]
    audit_client_ip_enabled: Option<bool>,
}

fn settings_body(settings: RuntimeSettings) -> SettingsBody {
    SettingsBody {
        public_base_url: settings.public_base_url,
        max_upload_size: settings.max_upload_size,
        blocked_extensions: settings.blocked_extensions,
        share_password_min_length: settings.share_password_min_length,
        share_password_max_length: settings.share_password_max_length,
        share_unlock_minutes: settings.share_unlock_minutes,
        max_zip_size: settings.max_zip_size,
        max_zip_files: settings.max_zip_files,
        max_search_entries: settings.max_search_entries,
        max_search_results: settings.max_search_results,
        max_preview_size: settings.max_preview_size,
        preview_extensions: settings.preview_extensions,
        image_preview_extensions: settings.image_preview_extensions,
        pdf_preview_enabled: settings.pdf_preview_enabled,
        max_media_preview_size: settings.max_media_preview_size,
        audit_client_ip_enabled: Some(settings.audit_client_ip_enabled),
    }
}

async fn get_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<SettingsBody>> {
    session(&state, &headers, true, MissingSession::Unauthorized).await?;
    Ok(Json(settings_body(runtime_settings(&state))))
}

async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SettingsBody>,
) -> ApiResult<Json<SettingsBody>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    let current = runtime_settings(&state);
    let mut next = current.clone();
    let max_upload_size = body.max_upload_size.to_string();
    let blocked_extensions = body.blocked_extensions.join(",");
    let share_password_min_length = body.share_password_min_length.to_string();
    let share_password_max_length = body.share_password_max_length.to_string();
    let share_unlock_minutes = body.share_unlock_minutes.to_string();
    let max_zip_size = body.max_zip_size.to_string();
    let max_zip_files = body.max_zip_files.to_string();
    let max_search_entries = body.max_search_entries.to_string();
    let max_search_results = body.max_search_results.to_string();
    let max_preview_size = body.max_preview_size.to_string();
    let preview_extensions = body.preview_extensions.join(",");
    let image_preview_extensions = body.image_preview_extensions.join(",");
    let pdf_preview_enabled = body.pdf_preview_enabled.to_string();
    let max_media_preview_size = body.max_media_preview_size.to_string();
    let audit_client_ip_enabled = body
        .audit_client_ip_enabled
        .unwrap_or(next.audit_client_ip_enabled)
        .to_string();
    next.apply_many([
        ("public_base_url", body.public_base_url.as_str()),
        ("max_upload_size", max_upload_size.as_str()),
        ("blocked_extensions", blocked_extensions.as_str()),
        (
            "share_password_min_length",
            share_password_min_length.as_str(),
        ),
        (
            "share_password_max_length",
            share_password_max_length.as_str(),
        ),
        ("share_unlock_minutes", share_unlock_minutes.as_str()),
        ("max_zip_size", max_zip_size.as_str()),
        ("max_zip_files", max_zip_files.as_str()),
        ("max_search_entries", max_search_entries.as_str()),
        ("max_search_results", max_search_results.as_str()),
        ("max_preview_size", max_preview_size.as_str()),
        ("preview_extensions", preview_extensions.as_str()),
        (
            "image_preview_extensions",
            image_preview_extensions.as_str(),
        ),
        ("pdf_preview_enabled", pdf_preview_enabled.as_str()),
        ("max_media_preview_size", max_media_preview_size.as_str()),
        ("audit_client_ip_enabled", audit_client_ip_enabled.as_str()),
    ])
    .map_err(|_| ApiError::bad_request("Invalid runtime setting"))?;
    next.validate()
        .map_err(|_| ApiError::bad_request("Ungültige Einstellung"))?;
    let admin_id = session_data.admin_id;
    let changed_keys = current.changed_keys(&next).join(",");
    commit_runtime_settings(&state, next.clone(), admin_id).await?;
    audit(
        &state,
        session_data.username,
        "settings_updated",
        None,
        Some(format!("changed_keys={changed_keys}")),
    )
    .await;
    Ok(Json(settings_body(next)))
}

#[derive(Default, Deserialize)]
struct AuditQuery {
    page: Option<usize>,
    action: Option<String>,
}

#[derive(Serialize)]
struct AuditResponse {
    page: usize,
    has_next: bool,
    client_ip_enabled: bool,
    events: Vec<AuditEventResponse>,
}

#[derive(Serialize)]
struct AuditEventResponse {
    occurred_at: String,
    actor: String,
    action: String,
    object_id: Option<String>,
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_ip: Option<String>,
}

impl AuditEventResponse {
    fn from_event(value: AuditEvent, client_ip_enabled: bool) -> Self {
        Self {
            occurred_at: value.occurred_at,
            actor: value.actor,
            action: value.action,
            object_id: value.object_id,
            detail: value.detail,
            client_ip: if client_ip_enabled {
                value.client_ip
            } else {
                None
            },
        }
    }
}

async fn list_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<AuditResponse>> {
    session(&state, &headers, true, MissingSession::Unauthorized).await?;
    let page = query.page.unwrap_or(0).min(1_000_000);
    let action = query.action.filter(|value| !value.trim().is_empty());
    let runtime = state.runtime.clone();
    let (client_ip_enabled, events) = database(state.db.clone(), move |db| {
        let client_ip_enabled = runtime
            .read()
            .map(|settings| settings.audit_client_ip_enabled)
            .unwrap_or(false);
        let events = db.list_audit(action.as_deref(), 101, page * 100)?;
        Ok((client_ip_enabled, events))
    })
    .await?;
    let mut events = events
        .into_iter()
        .map(|event| AuditEventResponse::from_event(event, client_ip_enabled))
        .collect::<Vec<_>>();
    let has_next = events.len() > 100;
    events.truncate(100);
    Ok(Json(AuditResponse {
        page,
        has_next,
        client_ip_enabled,
        events,
    }))
}

enum AuditClientIpDeletion {
    LoggingEnabled,
    Deleted(usize),
}

#[derive(Serialize)]
struct DeletedAuditClientIpsResponse {
    deleted: usize,
}

#[derive(Deserialize)]
struct DeleteAuditClientIpsRequest {
    confirmation: String,
}

async fn delete_audit_client_ips(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DeleteAuditClientIpsRequest>,
) -> ApiResult<Json<DeletedAuditClientIpsResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    if request.confirmation != "IP-DATEN LÖSCHEN" {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "confirmation_required",
            "Exakte Bestätigung IP-DATEN LÖSCHEN erforderlich",
        ));
    }
    let runtime = state.runtime.clone();
    let outcome = database(state.db.clone(), move |db| {
        let logging_enabled = runtime
            .read()
            .map(|settings| settings.audit_client_ip_enabled)
            .unwrap_or(true);
        if logging_enabled {
            Ok(AuditClientIpDeletion::LoggingEnabled)
        } else {
            db.delete_audit_client_ips()
                .map(AuditClientIpDeletion::Deleted)
        }
    })
    .await?;
    let AuditClientIpDeletion::Deleted(deleted) = outcome else {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "client_ip_logging_enabled",
            "Client-IP-Logging muss vor dem Löschen deaktiviert werden",
        ));
    };
    audit(
        &state,
        session_data.username,
        "audit_client_ips_deleted",
        None,
        Some(format!("deleted={deleted}")),
    )
    .await;
    Ok(Json(DeletedAuditClientIpsResponse { deleted }))
}

#[derive(Default, Deserialize)]
struct PublicShareQuery {
    path: Option<String>,
}

#[derive(Serialize)]
struct PublicShareResponse {
    token: String,
    path: String,
    is_directory: bool,
    permission: Permission,
    locked: bool,
    active: bool,
    expires_at: Option<DateTime<Utc>>,
    download_count: u64,
    max_downloads: Option<u64>,
}

async fn public_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(query): Query<PublicShareQuery>,
) -> ApiResult<Json<PublicShareResponse>> {
    if let Some(path) = query.path.as_deref() {
        let _ = validate_rel(path)?;
    }
    let share = get_share(&state, &token).await?;
    let unlocked = share_is_unlocked(&state, &headers, &share).await?;
    let public_path = if share.permission == Permission::UploadOnly {
        String::new()
    } else {
        share.relative_path.clone()
    };
    Ok(Json(PublicShareResponse {
        token: share.token,
        path: public_path,
        is_directory: share.is_directory,
        permission: share.permission,
        locked: !unlocked,
        active: share.active,
        expires_at: share.expires_at,
        download_count: share.download_count,
        max_downloads: share.max_downloads,
    }))
}

#[derive(Deserialize)]
struct UnlockRequest {
    password: String,
}

async fn unlock_share(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Json(request): Json<UnlockRequest>,
) -> ApiResult<Response> {
    let share = get_share(&state, &token).await?;
    let ip = proxy::effective_client_ip(peer.ip(), &headers, &state.config);
    let key = format!("share:{}:{ip}", share.id);
    if !state.share_limiter.allowed(&key) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Zu viele Passwortversuche",
        ));
    }
    let Some(hash) = share.password_hash.clone() else {
        return Ok(Json(SimpleResponse { ok: true }).into_response());
    };
    let password = request.password;
    let valid = tokio::task::spawn_blocking(move || auth::verify_password(&hash, &password))
        .await
        .map_err(ApiError::internal)?;
    if !valid {
        state.share_limiter.failure(&key);
        audit(
            &state,
            "public".into(),
            "share_unlock_failed",
            Some(share.id.to_string()),
            None,
        )
        .await;
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_share_password",
            "Ungültiges Passwort",
        ));
    }
    state.share_limiter.success(&key);
    let unlock_token = auth::random_token(32);
    let share_id = share.id;
    let expires = Utc::now() + Duration::minutes(runtime_settings(&state).share_unlock_minutes);
    let token_for_db = unlock_token.clone();
    database(state.db.clone(), move |db| {
        db.create_unlock_session(&token_for_db, share_id, expires)
    })
    .await?;
    audit(
        &state,
        "public".into(),
        "share_unlocked",
        Some(share.id.to_string()),
        None,
    )
    .await;
    let mut response = Json(SimpleResponse { ok: true }).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&make_unlock_cookie(
            &state,
            &share,
            &unlock_token,
            UnlockCookieScope::Api,
        ))
        .map_err(ApiError::internal)?,
    );
    Ok(response)
}

async fn find_share_by_id(state: &AppState, id: i64) -> ApiResult<Share> {
    database(state.db.clone(), move |db| db.list_shares())
        .await?
        .into_iter()
        .find(|share| share.id == id)
        .ok_or_else(|| ApiError::not_found("Freigabe nicht gefunden"))
}

async fn get_share(state: &AppState, token: &str) -> ApiResult<Share> {
    let token = token.to_string();
    let share = database(state.db.clone(), move |db| db.share_by_token(&token))
        .await?
        .ok_or_else(|| ApiError::not_found("Freigabe nicht gefunden"))?;
    usable(&share)?;
    Ok(share)
}

fn usable(share: &Share) -> ApiResult<()> {
    if !share.active {
        return Err(ApiError::new(
            StatusCode::GONE,
            "share_inactive",
            "Freigabe ist deaktiviert",
        ));
    }
    if share.expires_at.is_some_and(|expires| expires < Utc::now()) {
        return Err(ApiError::new(
            StatusCode::GONE,
            "share_expired",
            "Freigabe ist abgelaufen",
        ));
    }
    Ok(())
}

fn validate_rel(value: &str) -> ApiResult<String> {
    path_security::validate_relative(value)
        .map_err(|_| ApiError::bad_request("Ungültiger Pfad"))
        .map(|path| path.to_string_lossy().replace('\\', "/"))
}

fn validate_alias(value: &str) -> ApiResult<String> {
    let value = value.trim();
    if (3..=32).contains(&value.len())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        Ok(value.to_string())
    } else {
        Err(ApiError::bad_request("Ungültiger Alias"))
    }
}

fn validate_share_password(settings: &RuntimeSettings, password: &str) -> ApiResult<()> {
    let chars = password.chars().count();
    if chars < settings.share_password_min_length || chars > settings.share_password_max_length {
        return Err(ApiError::bad_request("Ungültiges Freigabepasswort"));
    }
    if password.len() > 1024 {
        return Err(ApiError::bad_request("Freigabepasswort ist zu lang"));
    }
    Ok(())
}

fn validate_admin_username(username: &str) -> ApiResult<()> {
    if (3..=64).contains(&username.len())
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        Ok(())
    } else {
        Err(ApiError::bad_request("Ungültiger Benutzername"))
    }
}

fn validate_admin_password(password: &str) -> ApiResult<()> {
    if password.chars().count() >= 14 && password.len() <= 1024 {
        Ok(())
    } else {
        Err(ApiError::bad_request("Ungültiges Admin-Passwort"))
    }
}

fn preview_allowed(path: &str, settings: &RuntimeSettings) -> bool {
    let extension = Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    settings
        .preview_extensions
        .iter()
        .any(|value| value == &extension)
        || (settings.pdf_preview_enabled && extension == "pdf")
        || settings
            .image_preview_extensions
            .iter()
            .any(|value| value == &extension)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Config, Logging, ReverseProxy, Security, Server, ServerMode, Storage, Tls,
    };
    use axum::{
        body::{to_bytes, Body},
        http::{Method, Request},
    };
    use std::{
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tower::ServiceExt;

    fn test_state(root: &Path, data: &Path) -> AppState {
        AppState::new(Config {
            server: Server {
                mode: ServerMode::Development,
                listen_address: "127.0.0.1:8080".into(),
                public_base_url: "http://localhost:8080".into(),
                production_mode: false,
            },
            storage: Storage {
                root_mount_path: root.into(),
                data_directory: data.into(),
                max_upload_size: 1_000_000,
                max_zip_size: 1_000_000_000,
                max_zip_files: 100,
                max_search_entries: 1000,
                max_search_results: 100,
                max_preview_size: 1_000_000,
                preview_extensions: vec!["txt".into(), "md".into()],
                image_preview_extensions: vec!["jpg".into(), "png".into()],
                pdf_preview_enabled: true,
                max_media_preview_size: 100_000_000,
                blocked_extensions: vec!["exe".into()],
            },
            reverse_proxy: ReverseProxy::default(),
            tls: Tls::default(),
            security: Security {
                secure_cookie: false,
                ..Default::default()
            },
            logging: Logging::default(),
        })
        .unwrap()
    }

    fn json_request(method: Method, uri: &str, body: &str) -> Request<Body> {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
        ));
        request
    }

    fn multipart_request(uri: &str, name: &str, content: &[u8]) -> Request<Body> {
        let boundary = "vaultlink-api-test-boundary";
        let mut body = Vec::new();
        body.extend_from_slice(format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        ).as_bytes());
        body.extend_from_slice(content);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
        ));
        request
    }

    async fn response_text(response: Response) -> String {
        String::from_utf8(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap()
    }

    fn json_string_value(body: &str, key: &str) -> String {
        let marker = format!("\"{key}\":\"");
        let start = body.find(&marker).expect("json key") + marker.len();
        let end = body[start..].find('"').expect("json value end") + start;
        body[start..end].to_string()
    }

    fn json_i64_value(body: &str, key: &str) -> i64 {
        let marker = format!("\"{key}\":");
        let start = body.find(&marker).expect("json key") + marker.len();
        let end = body[start..]
            .find(|c: char| !c.is_ascii_digit())
            .map(|offset| start + offset)
            .unwrap_or(body.len());
        body[start..end].parse().unwrap()
    }

    fn cookie(response: &Response) -> String {
        response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    fn current_totp(secret: &str) -> String {
        let step = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 30;
        auth::totp_code(secret, step).unwrap()
    }

    async fn api_login(state: &AppState, secret: &str) -> (String, String) {
        let app = crate::web::router(state.clone());
        let login = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/api/v1/session/login",
                r#"{"username":"admin","password":"correct horse battery staple"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let session_cookie = cookie(&login);
        let login_body = response_text(login).await;
        let csrf = json_string_value(&login_body, "csrf_token");
        let mut mfa = json_request(
            Method::POST,
            "/api/v1/session/mfa",
            &format!(r#"{{"code":"{}"}}"#, current_totp(secret)),
        );
        mfa.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        let mfa = app.oneshot(mfa).await.unwrap();
        assert_eq!(mfa.status(), StatusCode::OK);
        (session_cookie, csrf)
    }

    #[tokio::test]
    async fn api_session_requires_mfa_and_csrf() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let secret = auth::new_totp_secret();
        let hash = auth::hash_password("correct horse battery staple").unwrap();
        state.db.create_admin("admin", &hash, &secret).unwrap();

        let (session_cookie, csrf) = api_login(&state, &secret).await;
        let app = crate::web::router(state.clone());
        let mut me = json_request(Method::GET, "/api/v1/session/me", "");
        me.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        let me = app.clone().oneshot(me).await.unwrap();
        assert_eq!(me.status(), StatusCode::OK);
        let body = response_text(me).await;
        assert!(body.contains(r#""username":"admin""#));
        assert!(body.contains(&csrf));

        let mut logout_without_csrf = json_request(Method::POST, "/api/v1/session/logout", "{}");
        logout_without_csrf.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        let response = app.oneshot(logout_without_csrf).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response_text(response).await;
        assert!(body.contains(r#""code":"forbidden""#));
        assert!(body.contains("CSRF"));
    }

    #[tokio::test]
    async fn api_creates_share_and_hides_secrets() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("docs")).unwrap();
        std::fs::write(root.path().join("docs/readme.txt"), "hello").unwrap();
        let state = test_state(root.path(), data.path());
        let secret = auth::new_totp_secret();
        let hash = auth::hash_password("correct horse battery staple").unwrap();
        state.db.create_admin("admin", &hash, &secret).unwrap();
        let (session_cookie, csrf) = api_login(&state, &secret).await;
        let app = crate::web::router(state.clone());

        let mut invalid_limit = json_request(
            Method::POST,
            "/api/v1/shares",
            r#"{"path":"docs","permission":"download_only","max_downloads":0}"#,
        );
        invalid_limit.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        invalid_limit
            .headers_mut()
            .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
        assert_eq!(
            app.clone().oneshot(invalid_limit).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );

        let mut create = json_request(
            Method::POST,
            "/api/v1/shares",
            r#"{"path":"docs","permission":"download_upload","alias":"docsapi","max_downloads":5,"password":"very strong share password","overwrite_allowed":true}"#,
        );
        create.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        create
            .headers_mut()
            .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
        let response = app.clone().oneshot(create).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_text(response).await;
        assert!(body.contains(r#""alias":"docsapi""#));
        assert!(body.contains(r#""url":"http://localhost:8080/s/docsapi""#));
        assert!(body.contains(r#""password_protected":true"#));
        assert!(body.contains(r#""upload_conflict_strategy":"overwrite_allowed""#));
        assert!(!body.contains("password_hash"));
        let audit_events = state.db.list_audit(Some("share_created"), 10, 0).unwrap();
        let detail = audit_events[0].detail.as_deref().unwrap();
        assert!(detail.contains("path=docs"));
        assert!(detail.contains("permission=download_upload"));
        assert!(detail.contains("alias=docsapi"));
        assert!(detail.contains("transfer_limit=5"));
        assert!(detail.contains("password_protected=true"));
        assert!(detail.contains("overwrite_allowed=true"));

        let mut list = json_request(Method::GET, "/api/v1/shares", "");
        list.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        let response = app.oneshot(list).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_text(response).await;
        assert!(body.contains("docsapi"));
        assert!(!body.contains("very strong share password"));
        assert!(!body.contains("password_hash"));
    }

    #[tokio::test]
    async fn api_admin_and_settings_flows_are_csrf_protected() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let secret = auth::new_totp_secret();
        let hash = auth::hash_password("correct horse battery staple").unwrap();
        state.db.create_admin("admin", &hash, &secret).unwrap();
        let (session_cookie, csrf) = api_login(&state, &secret).await;
        let app = crate::web::router(state.clone());

        let mut create_admin = json_request(
            Method::POST,
            "/api/v1/admins",
            r#"{"username":"ops","password":"another correct horse password"}"#,
        );
        create_admin.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        create_admin
            .headers_mut()
            .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
        let response = app.clone().oneshot(create_admin).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_text(response).await;
        assert!(body.contains(r#""username":"ops""#));
        assert!(body.contains("otpauth://totp/VaultLink:ops"));
        let ops_id = json_i64_value(&body, "id");

        let mut deactivate = json_request(
            Method::POST,
            &format!("/api/v1/admins/{ops_id}/deactivate"),
            "{}",
        );
        deactivate.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        let response = app.oneshot(deactivate).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response_text(response).await;
        assert!(body.contains("CSRF"));
    }

    #[tokio::test]
    async fn api_settings_are_canonical_and_restart_safe() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let config = state.config.as_ref().clone();
        let secret = auth::new_totp_secret();
        let hash = auth::hash_password("correct horse battery staple").unwrap();
        state.db.create_admin("admin", &hash, &secret).unwrap();
        let (session_cookie, csrf) = api_login(&state, &secret).await;
        let app = crate::web::router(state.clone());

        let mut invalid_body = settings_body(runtime_settings(&state));
        invalid_body.public_base_url.clear();
        let invalid_json = serde_json::to_string(&invalid_body).unwrap();
        let mut invalid = json_request(Method::PUT, "/api/v1/settings", &invalid_json);
        invalid.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        invalid
            .headers_mut()
            .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
        assert_eq!(
            app.clone().oneshot(invalid).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
        assert!(state.db.runtime_settings().unwrap().is_empty());

        let mut valid_body = settings_body(runtime_settings(&state));
        valid_body.public_base_url = "http://localhost:8080/".into();
        valid_body.blocked_extensions = vec!["EXE, .SH".into()];
        valid_body.audit_client_ip_enabled = Some(true);
        let valid_json = serde_json::to_string(&valid_body).unwrap();
        let mut valid = json_request(Method::PUT, "/api/v1/settings", &valid_json);
        valid.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        valid
            .headers_mut()
            .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
        let response = app.clone().oneshot(valid).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response_text(response)
            .await
            .contains(r#""audit_client_ip_enabled":true"#));
        let current = runtime_settings(&state);
        assert_eq!(current.public_base_url, "http://localhost:8080");
        assert_eq!(current.blocked_extensions, ["exe", "sh"]);
        assert!(current.audit_client_ip_enabled);

        let mut legacy_json = serde_json::to_value(settings_body(current)).unwrap();
        legacy_json
            .as_object_mut()
            .unwrap()
            .remove("audit_client_ip_enabled");
        let mut legacy_update = json_request(
            Method::PUT,
            "/api/v1/settings",
            &serde_json::to_string(&legacy_json).unwrap(),
        );
        legacy_update.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        legacy_update
            .headers_mut()
            .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
        assert_eq!(
            app.clone().oneshot(legacy_update).await.unwrap().status(),
            StatusCode::OK
        );
        assert!(runtime_settings(&state).audit_client_ip_enabled);

        drop(app);
        drop(state);
        let restarted = AppState::new(config).unwrap();
        let restarted = runtime_settings(&restarted);
        assert_eq!(restarted.public_base_url, "http://localhost:8080");
        assert_eq!(restarted.blocked_extensions, ["exe", "sh"]);
        assert!(restarted.audit_client_ip_enabled);
    }

    #[tokio::test]
    async fn api_audit_client_ips_are_opt_in_and_can_be_deleted_only_when_disabled() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let secret = auth::new_totp_secret();
        let hash = auth::hash_password("correct horse battery staple").unwrap();
        state.db.create_admin("admin", &hash, &secret).unwrap();
        let (session_cookie, csrf) = api_login(&state, &secret).await;
        state
            .db
            .audit_with_client_ip("admin", "client_ip_test", None, None, Some("203.0.113.10"))
            .unwrap();
        assert_eq!(state.db.count_audit_client_ips().unwrap(), 1);
        let app = crate::web::router(state.clone());

        let mut list_disabled = json_request(Method::GET, "/api/v1/audit", "");
        list_disabled.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        let response = app.clone().oneshot(list_disabled).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_text(response).await;
        assert!(body.contains(r#""client_ip_enabled":false"#));
        assert!(!body.contains(r#""client_ip":"#));
        assert!(!body.contains("203.0.113.10"));

        state.runtime.write().unwrap().audit_client_ip_enabled = true;
        let mut list_enabled = json_request(Method::GET, "/api/v1/audit", "");
        list_enabled.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        let response = app.clone().oneshot(list_enabled).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_text(response).await;
        assert!(body.contains(r#""client_ip_enabled":true"#));
        assert!(body.contains(r#""client_ip":"203.0.113.10""#));

        let mut wrong_confirmation = json_request(
            Method::DELETE,
            "/api/v1/audit/client-ips",
            r#"{"confirmation":"LÖSCHEN"}"#,
        );
        wrong_confirmation.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        wrong_confirmation
            .headers_mut()
            .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
        let response = app.clone().oneshot(wrong_confirmation).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response_text(response)
            .await
            .contains("confirmation_required"));
        assert_eq!(state.db.count_audit_client_ips().unwrap(), 1);

        let mut delete_enabled = json_request(
            Method::DELETE,
            "/api/v1/audit/client-ips",
            r#"{"confirmation":"IP-DATEN LÖSCHEN"}"#,
        );
        delete_enabled.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        delete_enabled
            .headers_mut()
            .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
        let response = app.clone().oneshot(delete_enabled).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(response_text(response)
            .await
            .contains("client_ip_logging_enabled"));
        assert_eq!(state.db.count_audit_client_ips().unwrap(), 1);

        state.runtime.write().unwrap().audit_client_ip_enabled = false;
        let mut delete_without_csrf = json_request(
            Method::DELETE,
            "/api/v1/audit/client-ips",
            r#"{"confirmation":"IP-DATEN LÖSCHEN"}"#,
        );
        delete_without_csrf.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        assert_eq!(
            app.clone()
                .oneshot(delete_without_csrf)
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(state.db.count_audit_client_ips().unwrap(), 1);

        let mut delete = json_request(
            Method::DELETE,
            "/api/v1/audit/client-ips",
            r#"{"confirmation":"IP-DATEN LÖSCHEN"}"#,
        );
        delete.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        delete
            .headers_mut()
            .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
        let response = app.oneshot(delete).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response_text(response).await.contains(r#""deleted":1"#));
        assert_eq!(state.db.count_audit_client_ips().unwrap(), 0);
    }

    #[tokio::test]
    async fn api_file_search_filters_before_pagination() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        for index in 0..180 {
            std::fs::write(root.path().join(format!("ordinary-{index:03}.txt")), "x").unwrap();
        }
        std::fs::write(root.path().join("only-late-match.txt"), "match").unwrap();
        let state = test_state(root.path(), data.path());
        let secret = auth::new_totp_secret();
        let hash = auth::hash_password("correct horse battery staple").unwrap();
        state.db.create_admin("admin", &hash, &secret).unwrap();
        let (session_cookie, _) = api_login(&state, &secret).await;
        let app = crate::web::router(state);
        let mut request = json_request(Method::GET, "/api/v1/files?path=&q=only-late-match", "");
        request.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_text(response).await;
        assert!(body.contains("only-late-match.txt"), "{body}");
        assert!(body.contains(r#""truncated":false"#));
        assert!(body.contains(r#""has_next":false"#));
    }

    #[test]
    fn api_file_pages_count_filtered_raw_directory_items() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        for _ in 0..2 {
            std::fs::write(
                root.path().join(crate::secure_fs::upload_fragment_name()),
                b"partial",
            )
            .unwrap();
        }
        let state = test_state(root.path(), data.path());
        let (entries, truncated) =
            list_file_page(state.secure_root.clone(), "", 0, None, 1).unwrap();
        assert!(entries.is_empty());
        assert!(truncated);
        let (entries, truncated) =
            list_file_page(state.secure_root, "", 0, Some("missing"), 1).unwrap();
        assert!(entries.is_empty());
        assert!(truncated);
    }

    #[tokio::test]
    async fn api_unlock_cookie_authorizes_followup_api_download() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("secret.txt"), "protected content").unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("admin", "hash", "secret").unwrap();
        let password_hash = auth::hash_password("very strong share password").unwrap();
        state
            .db
            .create_share(
                "protected-token",
                None,
                "secret.txt",
                false,
                &Permission::DownloadOnly,
                None,
                Some(1),
                None,
                1,
                Some(&password_hash),
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        let app = crate::web::router(state.clone());
        let unlock = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/api/v1/public/shares/protected-token/unlock",
                r#"{"password":"very strong share password"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(unlock.status(), StatusCode::OK);
        let set_cookie = unlock
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(set_cookie.contains("Path=/api/v1/public/shares/protected-token"));
        let unlock_cookie = set_cookie.split(';').next().unwrap().to_string();

        let mut download = json_request(
            Method::GET,
            "/api/v1/public/shares/protected-token/download",
            "",
        );
        download.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&unlock_cookie).unwrap(),
        );
        let download = app.clone().oneshot(download).await.unwrap();
        assert_eq!(download.status(), StatusCode::OK);
        assert!(download
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|value| value
                .to_str()
                .unwrap()
                .contains("Path=/api/v1/public/shares/protected-token")));
        assert_eq!(response_text(download).await, "protected content");
        for _ in 0..100 {
            if state
                .db
                .share_by_token("protected-token")
                .unwrap()
                .unwrap()
                .download_count
                == 1
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        let metadata = app
            .oneshot(json_request(
                Method::GET,
                "/api/v1/public/shares/protected-token",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(metadata.status(), StatusCode::OK);
        assert!(response_text(metadata)
            .await
            .contains(r#""download_count":1"#));
    }

    #[tokio::test]
    async fn api_media_preview_keeps_unlock_and_raw_routes_api_scoped() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("protected")).unwrap();
        std::fs::write(root.path().join("protected/image.png"), b"\x89PNG").unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("admin", "hash", "secret").unwrap();
        let password_hash = auth::hash_password("very strong share password").unwrap();
        state
            .db
            .create_share(
                "media-token",
                None,
                "protected",
                true,
                &Permission::DownloadOnly,
                None,
                Some(1),
                None,
                1,
                Some(&password_hash),
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        let app = crate::web::router(state.clone());
        let unlock = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/api/v1/public/shares/media-token/unlock",
                r#"{"password":"very strong share password"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(unlock.status(), StatusCode::OK);
        let unlock_cookie = unlock
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();

        let mut preview = json_request(
            Method::GET,
            "/api/v1/public/shares/media-token/preview?path=image.png",
            "",
        );
        preview.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&unlock_cookie).unwrap(),
        );
        let preview = app.clone().oneshot(preview).await.unwrap();
        assert_eq!(preview.status(), StatusCode::OK);
        let preview = response_text(preview).await;
        assert!(preview.contains("/api/v1/public/shares/media-token/preview/raw?path=image%2Epng"));
        assert!(preview.contains("href=\"/api/v1/public/shares/media-token\""));
        assert!(!preview.contains("/v/media-token/preview/raw"));
        assert!(!preview.contains("href=\"/v/media-token\""));
        let token_start = preview.find("preview_token=").unwrap() + "preview_token=".len();
        let preview_token = preview[token_start..]
            .chars()
            .take_while(|character| *character != '"' && *character != '&')
            .collect::<String>();

        let mut raw = json_request(
            Method::GET,
            &format!(
                "/api/v1/public/shares/media-token/preview/raw?path=image.png&preview_token={preview_token}"
            ),
            "",
        );
        raw.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&unlock_cookie).unwrap(),
        );
        let raw = app.oneshot(raw).await.unwrap();
        assert_eq!(raw.status(), StatusCode::OK);
        assert_eq!(
            axum::body::to_bytes(raw.into_body(), usize::MAX)
                .await
                .unwrap()
                .as_ref(),
            b"\x89PNG"
        );
        assert_eq!(
            state
                .db
                .share_by_token("media-token")
                .unwrap()
                .unwrap()
                .download_count,
            1
        );
    }

    #[tokio::test]
    async fn api_admin_file_mutations_update_shares_and_require_tree_confirmation() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("docs")).unwrap();
        std::fs::write(root.path().join("docs/file.txt"), b"content").unwrap();
        let state = test_state(root.path(), data.path());
        let secret = auth::new_totp_secret();
        let hash = auth::hash_password("correct horse battery staple").unwrap();
        state.db.create_admin("admin", &hash, &secret).unwrap();
        state
            .db
            .create_share(
                "file-token",
                None,
                "docs/file.txt",
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
        let (session_cookie, csrf) = api_login(&state, &secret).await;
        let app = crate::web::router(state.clone());

        let mut create = json_request(
            Method::POST,
            "/api/v1/files/directories",
            r#"{"parent":"","name":"tree"}"#,
        );
        authorize_mutation(&mut create, &session_cookie, &csrf);
        assert_eq!(
            app.clone().oneshot(create).await.unwrap().status(),
            StatusCode::CREATED
        );

        let mut rename = json_request(
            Method::PATCH,
            "/api/v1/files",
            r#"{"path":"docs/file.txt","name":"final.txt"}"#,
        );
        authorize_mutation(&mut rename, &session_cookie, &csrf);
        assert_eq!(
            app.clone().oneshot(rename).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            state
                .db
                .share_by_token("file-token")
                .unwrap()
                .unwrap()
                .relative_path,
            "docs/final.txt"
        );

        std::fs::write(root.path().join("tree/child.txt"), b"child").unwrap();
        state
            .db
            .create_share(
                "tree-token",
                None,
                "tree/child.txt",
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
        let mut unconfirmed = json_request(Method::DELETE, "/api/v1/files", r#"{"path":"tree"}"#);
        authorize_mutation(&mut unconfirmed, &session_cookie, &csrf);
        let unconfirmed = app.clone().oneshot(unconfirmed).await.unwrap();
        assert_eq!(unconfirmed.status(), StatusCode::CONFLICT);
        assert!(response_text(unconfirmed)
            .await
            .contains("confirmation_required"));
        assert!(root.path().join("tree").exists());

        let cleanup_guard = state.storage_cleanup.lock().await;
        let mut confirmed = json_request(
            Method::DELETE,
            "/api/v1/files",
            r#"{"path":"tree","confirm_name":"tree"}"#,
        );
        authorize_mutation(&mut confirmed, &session_cookie, &csrf);
        assert_eq!(
            app.oneshot(confirmed).await.unwrap().status(),
            StatusCode::ACCEPTED
        );
        assert!(!root.path().join("tree").exists());
        let tombstone_exists = || {
            std::fs::read_dir(root.path()).unwrap().any(|entry| {
                crate::secure_fs::is_deletion_tombstone_name(&entry.unwrap().file_name())
            })
        };
        assert!(tombstone_exists());
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(tombstone_exists());
        drop(cleanup_guard);
        for _ in 0..100 {
            if !tombstone_exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(!tombstone_exists());
        assert!(
            !state
                .db
                .share_by_token("tree-token")
                .unwrap()
                .unwrap()
                .active
        );
    }

    fn authorize_mutation(request: &mut Request<Body>, session_cookie: &str, csrf: &str) {
        request.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(session_cookie).unwrap(),
        );
        request
            .headers_mut()
            .insert("x-csrf-token", HeaderValue::from_str(csrf).unwrap());
    }

    #[tokio::test]
    async fn api_delegated_public_upload_errors_are_json() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("uploads")).unwrap();
        let state = test_state(root.path(), data.path());
        let hash = auth::hash_password("correct horse battery staple").unwrap();
        state
            .db
            .create_admin("admin", &hash, &auth::new_totp_secret())
            .unwrap();
        state
            .db
            .create_share(
                "upload-token",
                None,
                "uploads",
                true,
                &Permission::UploadOnly,
                None,
                None,
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        let app = crate::web::router(state);
        let response = app
            .oneshot(multipart_request(
                "/api/v1/public/shares/upload-token/upload",
                "blocked.exe",
                b"blocked",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert!(response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("application/json"));
        let body = response_text(response).await;
        assert!(body.contains(r#""code":"unsupported_media_type""#));
        assert!(!body.contains("<html"));
        assert!(!body.contains("Zurück zur Freigabe"));
    }
}
