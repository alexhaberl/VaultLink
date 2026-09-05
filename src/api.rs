#[cfg(test)]
use axum::routing::get;
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    Json, Router,
};
use serde::{Deserialize, Serialize};
#[cfg(panic = "unwind")]
use tower_http::catch_panic::CatchPanicLayer;

use crate::{
    internal_reporting::ReportedInternalError, sensitive::SecretString, state::ReadinessState,
    AppState,
};

mod admins;
mod auth;
mod common;
mod files;
mod monitoring;
mod public;
mod public_transfer;
mod public_upload;
mod service_tokens;
mod settings_audit;
mod shares;

use admins::{
    activate_admin, create_admin, deactivate_admin, list_admins, reset_admin_password,
    reset_admin_totp,
};
use auth::{login, logout, me, mfa};
use files::{create_directory, delete_file_entry, files, rename_file_entry};
use monitoring::{monitoring_share_page, monitoring_summary};
use public::{public_share, unlock_share};
use public_transfer::{download, download_zip, public_preview, public_preview_raw};
use public_upload::upload;
use service_tokens::{create_service_token, list_service_tokens, revoke_service_token};
use settings_audit::{delete_audit_client_ips, get_settings, list_audit, update_settings};
use shares::{
    activate_share, create_share, deactivate_share, delete_share, list_shares,
    remove_share_password, set_share_password, update_share,
};

#[cfg(test)]
use crate::db::{Permission, UploadConflictStrategy};
#[cfg(test)]
use crate::http_auth::runtime_settings;
#[cfg(test)]
use axum::extract::ConnectInfo;
#[cfg(test)]
use files::list_file_page;
#[cfg(test)]
use settings_audit::settings_body;
#[cfg(test)]
use std::net::SocketAddr;

use crate::http_contract::MAX_SEARCH_QUERY_BYTES;

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    retry_after_seconds: Option<u64>,
}

type ApiResult<T> = std::result::Result<T, ApiError>;

fn session_bound<T>(outcome: crate::db::SessionBound<T>) -> ApiResult<T> {
    match outcome {
        crate::db::SessionBound::Authorized(value) => Ok(value),
        crate::db::SessionBound::SessionUnavailable => Err(ApiError::session_revoked()),
    }
}

fn storage_recovery_api_error(error: crate::file_ops::FileOperationError) -> ApiError {
    match error {
        crate::file_ops::FileOperationError::DatabaseCapacity => {
            ApiError::from(crate::http_auth::HttpAuthError::with_kind(
                StatusCode::SERVICE_UNAVAILABLE,
                crate::http_auth::DATABASE_BUSY_MESSAGE,
                crate::http_auth::HttpAuthErrorKind::CapacityUnavailable,
            ))
        }
        crate::file_ops::FileOperationError::Database(database_error)
            if crate::db::is_audit_unavailable(&database_error)
                || crate::db::is_sqlite_busy_or_locked(&database_error) =>
        {
            ApiError::from(crate::http_auth::database_error(database_error))
        }
        _ => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_recovery",
            "Storage state is being recovered",
        ),
    }
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
            retry_after_seconds: None,
        }
    }
    fn storage_busy() -> Self {
        let mut error = Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_busy",
            "Storage temporarily busy",
        );
        error.retry_after_seconds = Some(1);
        error
    }
    fn bad_request(message: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }
    fn not_found(message: &'static str) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }
    fn conflict(message: &'static str) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }
    fn session_revoked() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "session_revoked",
            "Session is no longer authorized",
        )
    }
    fn rate_limited(message: &'static str, retry_after_seconds: u64) -> Self {
        let mut error = Self::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", message);
        error.retry_after_seconds = Some(retry_after_seconds);
        error
    }
}

impl From<ReportedInternalError> for ApiError {
    fn from(_: ReportedInternalError) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Internal error",
        )
    }
}

impl From<crate::http_auth::HttpAuthError> for ApiError {
    fn from(value: crate::http_auth::HttpAuthError) -> Self {
        let code = match value.kind {
            crate::http_auth::HttpAuthErrorKind::AuditUnavailable => "audit_unavailable",
            crate::http_auth::HttpAuthErrorKind::CapacityUnavailable => "request_failed",
            crate::http_auth::HttpAuthErrorKind::AmbiguousAuthentication => {
                "ambiguous_authentication"
            }
            crate::http_auth::HttpAuthErrorKind::InsufficientScope => "insufficient_scope",
            crate::http_auth::HttpAuthErrorKind::SessionRevoked => "session_revoked",
            crate::http_auth::HttpAuthErrorKind::Request => match value.status {
                StatusCode::UNAUTHORIZED => "unauthorized",
                StatusCode::FORBIDDEN => "forbidden",
                StatusCode::TOO_MANY_REQUESTS => "rate_limited",
                _ => "request_failed",
            },
        };
        let message = match value.kind {
            crate::http_auth::HttpAuthErrorKind::AuditUnavailable => {
                "Security audit temporarily unavailable"
            }
            crate::http_auth::HttpAuthErrorKind::CapacityUnavailable => {
                "Request processing capacity is temporarily unavailable"
            }
            crate::http_auth::HttpAuthErrorKind::AmbiguousAuthentication => {
                "Ambiguous authentication"
            }
            crate::http_auth::HttpAuthErrorKind::InsufficientScope => {
                "Service token scope is insufficient"
            }
            crate::http_auth::HttpAuthErrorKind::SessionRevoked => {
                "Session is no longer authorized"
            }
            crate::http_auth::HttpAuthErrorKind::Request => match value.status {
                StatusCode::BAD_REQUEST => "Invalid request",
                StatusCode::UNAUTHORIZED => "Authentication required",
                StatusCode::FORBIDDEN => "Request forbidden",
                StatusCode::NOT_FOUND => "Resource not found",
                StatusCode::CONFLICT => "Request conflict",
                StatusCode::TOO_MANY_REQUESTS => "Too many requests",
                StatusCode::SERVICE_UNAVAILABLE => "Service temporarily unavailable",
                StatusCode::INTERNAL_SERVER_ERROR => "Internal error",
                _ => "Request failed",
            },
        };
        let mut error = Self::new(value.status, code, message);
        if value.kind == crate::http_auth::HttpAuthErrorKind::CapacityUnavailable {
            error.retry_after_seconds = Some(1);
        }
        error
    }
}

impl From<crate::services::public_transfer::PublicTransferError> for ApiError {
    fn from(error: crate::services::public_transfer::PublicTransferError) -> Self {
        use crate::services::public_transfer::PublicTransferError as Error;
        let (status, code) = match error {
            Error::StorageBusy => return Self::storage_busy(),
            Error::NotFound | Error::FileUnavailable | Error::ShareTargetUnavailable => {
                (StatusCode::NOT_FOUND, "not_found")
            }
            Error::Inactive
            | Error::Expired
            | Error::Changed
            | Error::TransferLimitReached
            | Error::TransferShareUnavailable => (StatusCode::GONE, "gone"),
            Error::StorageUnavailable | Error::Capacity => {
                (StatusCode::SERVICE_UNAVAILABLE, "internal_error")
            }
            Error::AuditUnavailable => {
                return Self::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "audit_unavailable",
                    "Service Unavailable",
                )
            }
            Error::InvalidFilePath
            | Error::MissingFilePath
            | Error::InvalidZipPath
            | Error::NotFile => (StatusCode::BAD_REQUEST, "bad_request"),
            Error::PreviewLimitReached => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            Error::RangeNotSatisfiable(_) => {
                (StatusCode::RANGE_NOT_SATISFIABLE, "range_not_satisfiable")
            }
            Error::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Error::ConcurrentDownloads => {
                let mut response = Self::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "internal_error",
                    "Service Unavailable",
                );
                response.retry_after_seconds = Some(1);
                return response;
            }
            Error::Internal(reported) => return Self::from(reported),
        };
        let mut response = Self::new(
            status,
            code,
            status.canonical_reason().unwrap_or("Request failed"),
        );
        if matches!(error, Error::Capacity) {
            response.retry_after_seconds = Some(1);
        }
        response
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
        let mut response = (
            self.status,
            Json(ErrorBody {
                error: ErrorObject {
                    code: self.code,
                    message: self.message,
                },
            }),
        )
            .into_response();
        if let Some(seconds) = self.retry_after_seconds {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from_str(&seconds.to_string())
                    .expect("Retry-After seconds are a valid header value"),
            );
        }
        response
    }
}

crate::declare_routes! {
    pub static API_ROUTE_SPECS = ApiV2;
    fn add_api_routes(router: Router<AppState>) -> Router<AppState>;
    "/health" {
        GET => health, [Public, None, None, None, None, ReadOnly];
    }
    "/health/live" {
        GET => health, [Public, None, None, None, None, ReadOnly];
    }
    "/health/ready" {
        GET => readiness, [Public, None, None, None, None, ReadOnly];
    }
    "/session/login" {
        POST => login, [Public, None, None, Required, Json, Authentication];
    }
    "/session/mfa" {
        POST => mfa, [Session, None, Header, Required, Json, Authentication];
    }
    "/session/logout" {
        POST => logout, [Session, None, Header, Required, None, Authentication];
    }
    "/session/me" {
        GET => me, [Session, None, None, None, None, ReadOnly];
    }
    "/monitoring/summary" {
        GET => monitoring_summary, [MonitoringCredential, None, None, None, None, ReadOnly];
        HEAD => monitoring_method_not_allowed, [Public, None, None, None, None, ReadOnly];
    }
    "/monitoring/shares" {
        GET => monitoring_share_page, [MonitoringCredential, None, None, None, None, ReadOnly];
        HEAD => monitoring_method_not_allowed, [Public, None, None, None, None, ReadOnly];
    }
    "/files" {
        GET => files, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
        PATCH => rename_file_entry, [AdminSession, MutationContext, Header, Required, Json, Storage];
        DELETE => delete_file_entry, [AdminSession, MutationContext, Header, Required, Json, Storage];
    }
    "/files/directories" {
        POST => create_directory, [AdminSession, MutationContext, Header, Required, Json, Storage];
    }
    "/shares" {
        GET => list_shares, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
        POST => create_share, [AdminSession, MutationContext, Header, Required, Json, Privileged];
    }
    "/shares/{id}" {
        PATCH => update_share, [AdminSession, MutationContext, Header, Required, Json, Privileged];
        DELETE => delete_share, [AdminSession, MutationContext, Header, Required, None, Privileged];
    }
    "/shares/{id}/activate" {
        POST => activate_share, [AdminSession, MutationContext, Header, Required, None, Privileged];
    }
    "/shares/{id}/deactivate" {
        POST => deactivate_share, [AdminSession, MutationContext, Header, Required, None, Privileged];
    }
    "/shares/{id}/password" {
        PUT => set_share_password, [AdminSession, MutationContext, Header, Required, Json, Privileged];
        DELETE => remove_share_password, [AdminSession, MutationContext, Header, Required, None, Privileged];
    }
    "/admins" {
        GET => list_admins, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
        POST => create_admin, [AdminSession, MutationContext, Header, Required, Json, Privileged];
    }
    "/admins/{id}/activate" {
        POST => activate_admin, [AdminSession, MutationContext, Header, Required, None, Privileged];
    }
    "/admins/{id}/deactivate" {
        POST => deactivate_admin, [AdminSession, MutationContext, Header, Required, None, Privileged];
    }
    "/admins/{id}/password" {
        PUT => reset_admin_password, [AdminSession, MutationContext, Header, Required, Json, Privileged];
    }
    "/admins/{id}/totp/reset" {
        POST => reset_admin_totp, [AdminSession, MutationContext, Header, Required, None, Privileged];
    }
    "/settings" {
        GET => get_settings, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
        PUT => update_settings, [AdminSession, MutationContext, Header, Required, Json, Privileged];
    }
    "/audit" {
        GET => list_audit, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
    }
    "/audit/client-ips" {
        DELETE => delete_audit_client_ips, [AdminSession, MutationContext, Header, Required, Json, Privileged];
    }
    "/service-tokens" {
        GET => list_service_tokens, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
        POST => create_service_token, [AdminSession, MutationContext, Header, Required, Json, Privileged];
    }
    "/service-tokens/{id}" {
        DELETE => revoke_service_token, [AdminSession, MutationContext, Header, Required, None, Privileged];
    }
    "/public/shares/{token}" {
        GET => public_share, [ShareCapability, None, None, Observation, None, ReadOnly];
    }
    "/public/shares/{token}/unlock" {
        POST => unlock_share, [ShareCapability, None, None, Observation, Json, ShareUnlock];
    }
    "/public/shares/{token}/download" {
        GET => download, [ShareCapability, None, None, Required, None, ReadOnly];
        HEAD => download, [ShareCapability, None, None, Required, None, ReadOnly];
    }
    "/public/shares/{token}/preview" {
        GET => public_preview, [ShareCapability, None, None, Observation, None, ReadOnly];
    }
    "/public/shares/{token}/preview/raw" {
        GET => public_preview_raw, [ShareCapability, None, None, Observation, None, ReadOnly];
        HEAD => public_preview_raw, [ShareCapability, None, None, Observation, None, ReadOnly];
    }
    "/public/shares/{token}/download.zip" {
        GET => download_zip, [ShareCapability, None, None, Required, None, ReadOnly];
    }
    "/public/shares/{token}/upload" {
        POST => upload, [ShareCapability, None, None, Required, Multipart, Upload];
    }
    layers [
        DefaultBodyLimit::max(crate::http_contract::HARD_MULTIPART_LIMIT.min(usize::MAX as u64) as usize),
        middleware::from_fn(guard_api_multipart_upload),
    ];
}

pub fn router(state: AppState) -> Router<AppState> {
    crate::install_safe_panic_reporting();
    let router = add_api_routes(Router::new()).layer(middleware::from_fn(normalize_api_errors));
    #[cfg(panic = "unwind")]
    let router = router.layer(CatchPanicLayer::custom(api_panic_response));
    router.with_state(state)
}

#[cfg(panic = "unwind")]
fn api_panic_response(_panic: Box<dyn std::any::Any + Send + 'static>) -> Response {
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "Internal error",
    )
    .into_response()
}

async fn guard_api_multipart_upload(request: Request, next: Next) -> Response {
    match crate::multipart_guard::guard_multipart_request(request) {
        Ok(request) => next.run(request).await,
        Err(error) => {
            let status = error.status_code();
            ApiError::new(
                status,
                status_code_name(status),
                status.canonical_reason().unwrap_or("Request failed"),
            )
            .into_response()
        }
    }
}

async fn monitoring_method_not_allowed() -> StatusCode {
    // Axum normally lets HEAD fall back to GET. Monitoring authentication is
    // deliberately exposed on the two documented GET methods only.
    StatusCode::METHOD_NOT_ALLOWED
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
    let audit_unavailable = response
        .headers()
        .get(crate::http_contract::ERROR_CODE_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == "audit_unavailable");
    let (mut parts, _) = response.into_parts();
    let status = parts.status;
    let code = if audit_unavailable {
        "audit_unavailable"
    } else {
        status_code_name(status)
    };
    let message = status.canonical_reason().unwrap_or("Request failed");
    let body = format!(r#"{{"error":{{"code":"{code}","message":"{message}"}}}}"#);
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.remove(header::CONTENT_ENCODING);
    parts
        .headers
        .remove(crate::http_contract::ERROR_CODE_HEADER);
    parts.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    Response::from_parts(parts, Body::from(body))
}

fn status_code_name(status: StatusCode) -> &'static str {
    match status {
        StatusCode::BAD_REQUEST => "bad_request",
        StatusCode::UNAUTHORIZED => "unauthorized",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::CONFLICT => "conflict",
        StatusCode::GONE => "gone",
        StatusCode::REQUEST_TIMEOUT => "request_timeout",
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

async fn readiness(State(state): State<ReadinessState>) -> impl IntoResponse {
    let ready = state.check().await;
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(HealthResponse {
            ok: ready,
            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}

#[derive(Serialize)]
struct SimpleResponse {
    ok: bool,
}

#[derive(Deserialize)]
struct PasswordRequest {
    password: SecretString,
}

#[cfg(test)]
#[path = "api/tests.rs"]
mod tests;
