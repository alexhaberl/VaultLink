use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::{sensitive::SecretString, AppState};

mod admins;
mod auth;
mod common;
mod files;
mod public;
mod settings_audit;
mod shares;

use admins::{
    activate_admin, create_admin, deactivate_admin, list_admins, reset_admin_password,
    reset_admin_totp,
};
use auth::{login, logout, me, mfa};
use files::{create_directory, delete_file_entry, files, rename_file_entry};
use public::{public_share, unlock_share};
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

const MAX_SEARCH_QUERY_BYTES: usize = 256;

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    retry_after_seconds: Option<u64>,
}

type ApiResult<T> = std::result::Result<T, ApiError>;

fn storage_recovery_api_error(error: crate::file_ops::FileOperationError) -> ApiError {
    match error {
        crate::file_ops::FileOperationError::Database(database_error)
            if crate::db::is_audit_unavailable(&database_error) =>
        {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit_unavailable",
                "Security audit temporarily unavailable",
            )
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
    fn bad_request(message: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }
    fn not_found(message: &'static str) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }
    fn conflict(message: &'static str) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }
    fn internal<T>(_: T) -> Self {
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

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/health/live", get(health))
        .route("/health/ready", get(readiness))
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
            post(crate::web::upload_api)
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
    let audit_unavailable = response
        .headers()
        .get(crate::web::ERROR_CODE_HEADER)
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
    parts.headers.remove(crate::web::ERROR_CODE_HEADER);
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

async fn readiness(State(state): State<AppState>) -> impl IntoResponse {
    let ready = state
        .readiness
        .check(state.db.clone(), state.secure_root.clone())
        .await;
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
