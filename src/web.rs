use askama::Template;
use axum::{
    extract::{DefaultBodyLimit, MatchedPath, Request},
    http::{header, HeaderValue, StatusCode},
    middleware,
    response::{Html, IntoResponse, Redirect, Response},
    Router,
};
#[cfg(panic = "unwind")]
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::RequestBodyTimeoutLayer,
    trace::TraceLayer,
};

use crate::{i18n, AppState};

mod account;
mod admin;
mod admission;
mod auth_ui;
mod common;
mod files;
mod preview_zip;
mod public;
mod public_preview;
mod rendering;
mod service_tokens;
mod settings_audit;
mod shares;
pub(crate) mod templates;
mod transfer;
mod transfer_runtime;
#[path = "web/public_upload/mod.rs"]
mod upload;

use crate::http_contract::{
    DEFAULT_REQUEST_BODY_LIMIT, MAX_SEARCH_QUERY_BYTES, MAX_UPLOAD_OPTION_FIELD_BYTES,
    MAX_UPLOAD_PATH_FIELD_BYTES, STREAM_BUFFER_BYTES as BUFFERED_RESPONSE_CHUNK_BYTES,
};
use crate::http_contract::{ERROR_CODE_HEADER, HARD_MULTIPART_LIMIT};
pub(crate) use admission::guard_multipart_upload;
const BUFFERED_RESPONSE_MAX_LIFETIME: std::time::Duration = std::time::Duration::from_secs(5 * 60);
const REQUEST_ID_HEADER: header::HeaderName = header::HeaderName::from_static("x-request-id");

#[derive(Clone, Debug)]
struct ServerRequestId(String);

impl ServerRequestId {
    fn as_str(&self) -> &str {
        &self.0
    }
}

async fn discard_client_request_id(mut request: Request, next: middleware::Next) -> Response {
    request.headers_mut().remove(REQUEST_ID_HEADER);
    next.run(request).await
}

fn server_request_id(request: &Request) -> &str {
    request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("<missing>")
}

async fn attach_server_request_id(mut request: Request, next: middleware::Next) -> Response {
    let request_id = server_request_id(&request).to_owned();
    request.extensions_mut().insert(ServerRequestId(request_id));
    next.run(request).await
}
const REQUEST_BODY_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const DEFAULT_REQUEST_BODY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);
const TEXT_PREVIEW_RENDER_UNIT_BYTES: u64 = 1_000_000;
const MAX_RENDERED_TEXT_PREVIEW_BYTES: usize = crate::config::MAX_TEXT_PREVIEW_SIZE as usize;
const TEXT_PREVIEW_STREAM_MARKER: &str = "<!--VAULTLINK_ESCAPED_TEXT_PREVIEW_STREAM-->";
pub(crate) const SESSION_REVOKED_MESSAGE: &str = "Session was revoked before commit";
#[derive(Debug)]
pub struct AppError(StatusCode, &'static str);

impl From<crate::internal_reporting::ReportedInternalError> for AppError {
    fn from(_: crate::internal_reporting::ReportedInternalError) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    }
}

impl From<crate::services::public_transfer::PublicTransferError> for AppError {
    fn from(error: crate::services::public_transfer::PublicTransferError) -> Self {
        use crate::services::public_transfer::PublicTransferError as Error;
        match error {
            Error::NotFound => Self(StatusCode::NOT_FOUND, "Link not found"),
            Error::Inactive | Error::Expired => {
                Self(StatusCode::GONE, "This link is no longer active")
            }
            Error::Changed => Self(StatusCode::GONE, "Share changed in the meantime"),
            Error::StorageUnavailable => Self(
                StatusCode::SERVICE_UNAVAILABLE,
                "Storage state is being recovered",
            ),
            Error::Capacity => Self(
                StatusCode::SERVICE_UNAVAILABLE,
                crate::http_auth::DATABASE_BUSY_MESSAGE,
            ),
            Error::AuditUnavailable => Self(
                StatusCode::SERVICE_UNAVAILABLE,
                crate::http_auth::AUDIT_UNAVAILABLE_MESSAGE,
            ),
            Error::InvalidFilePath => Self(StatusCode::BAD_REQUEST, "Invalid file path"),
            Error::MissingFilePath => Self(StatusCode::BAD_REQUEST, "File path missing"),
            Error::InvalidZipPath => Self(StatusCode::BAD_REQUEST, "Invalid ZIP path"),
            Error::FileUnavailable => Self(StatusCode::NOT_FOUND, "File unavailable"),
            Error::ShareTargetUnavailable => {
                Self(StatusCode::NOT_FOUND, "Share target unavailable")
            }
            Error::NotFile => Self(StatusCode::BAD_REQUEST, "Not a file"),
            Error::PreviewLimitReached => {
                Self(StatusCode::PAYLOAD_TOO_LARGE, "Preview limit reached")
            }
            Error::RangeNotSatisfiable(_) => {
                Self(StatusCode::RANGE_NOT_SATISFIABLE, "Invalid byte range")
            }
            Error::TransferLimitReached => Self(StatusCode::GONE, "Transfer limit reached"),
            Error::TransferShareUnavailable => Self(StatusCode::GONE, "Share unavailable"),
            Error::RateLimited => Self(StatusCode::TOO_MANY_REQUESTS, "Too many public transfers"),
            Error::ConcurrentDownloads => Self(
                StatusCode::SERVICE_UNAVAILABLE,
                "Too many concurrent downloads for this share",
            ),
            Error::Internal(reported) => Self::from(reported),
        }
    }
}

#[derive(Template)]
#[template(path = "web/error.html")]
struct ErrorTemplate<'a> {
    message: &'a str,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if self.0 == StatusCode::UNAUTHORIZED && self.1 == SESSION_REVOKED_MESSAGE {
            let mut response = Redirect::to("/login").into_response();
            response.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_static(
                    "vaultlink_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
                ),
            );
            response.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_static(
                    "__Host-vaultlink_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Secure",
                ),
            );
            return response;
        }
        if self.0.is_redirection() {
            return Redirect::to(self.1).into_response();
        }
        let locale = i18n::current_locale();
        let message = if self.1 == crate::http_auth::AUDIT_UNAVAILABLE_MESSAGE {
            std::borrow::Cow::Borrowed(i18n::text(locale, i18n::AUDIT_TEMPORARILY_UNAVAILABLE))
        } else if self.1 == crate::http_auth::ARGON2_BUSY_MESSAGE {
            std::borrow::Cow::Borrowed(i18n::text(locale, i18n::PASSWORD_PROCESSING_UNAVAILABLE))
        } else if self.1 == crate::http_auth::DATABASE_BUSY_MESSAGE {
            std::borrow::Cow::Borrowed(i18n::text(locale, i18n::DATABASE_TEMPORARILY_UNAVAILABLE))
        } else {
            i18n::localized_text(locale, self.1)
        };
        let audit_unavailable = self.0 == StatusCode::SERVICE_UNAVAILABLE
            && self.1 == crate::http_auth::AUDIT_UNAVAILABLE_MESSAGE;
        let page = templates::public_page(i18n::ERROR, &ErrorTemplate { message: &message });
        let mut response = match page {
            Ok(page) => (self.0, Html(page)).into_response(),
            Err(_) => (self.0, message).into_response(),
        };
        if audit_unavailable {
            response.headers_mut().insert(
                ERROR_CODE_HEADER,
                HeaderValue::from_static("audit_unavailable"),
            );
        }
        if self.0 == StatusCode::SERVICE_UNAVAILABLE
            && (matches!(
                self.1,
                crate::http_auth::ARGON2_BUSY_MESSAGE | crate::http_auth::DATABASE_BUSY_MESSAGE
            ) || self.1.starts_with("Too many concurrent "))
        {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        response
    }
}
type Result<T> = std::result::Result<T, AppError>;

pub(crate) fn session_bound<T>(outcome: crate::db::SessionBound<T>) -> Result<T> {
    match outcome {
        crate::db::SessionBound::Authorized(value) => Ok(value),
        crate::db::SessionBound::SessionUnavailable => {
            Err(AppError(StatusCode::UNAUTHORIZED, SESSION_REVOKED_MESSAGE))
        }
    }
}

fn storage_recovery_app_error(error: crate::file_ops::FileOperationError) -> AppError {
    match error {
        crate::file_ops::FileOperationError::DatabaseCapacity => AppError(
            StatusCode::SERVICE_UNAVAILABLE,
            crate::http_auth::DATABASE_BUSY_MESSAGE,
        ),
        crate::file_ops::FileOperationError::Database(database_error)
            if crate::db::is_audit_unavailable(&database_error)
                || crate::db::is_sqlite_busy_or_locked(&database_error) =>
        {
            AppError::from(crate::http_auth::database_error(database_error))
        }
        _ => AppError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Storage state is being recovered",
        ),
    }
}

impl From<crate::http_auth::HttpAuthError> for AppError {
    fn from(value: crate::http_auth::HttpAuthError) -> Self {
        if value.kind == crate::http_auth::HttpAuthErrorKind::SessionRevoked {
            AppError(StatusCode::UNAUTHORIZED, SESSION_REVOKED_MESSAGE)
        } else if let Some(location) = value.redirect {
            AppError(StatusCode::SEE_OTHER, location)
        } else {
            AppError(value.status, value.message)
        }
    }
}

async fn root_redirect() -> Redirect {
    Redirect::to("/admin")
}

crate::declare_routes! {
    pub static WEB_ROUTE_SPECS = Web;
    fn add_web_routes(router: Router<AppState>) -> Router<AppState>;
    "/" {
        GET => root_redirect, [Public, None, None, None, None, ReadOnly];
    }
    "/login" {
        GET => auth_ui::login_page, [Public, None, None, None, None, ReadOnly];
        POST => auth_ui::login, [Public, None, None, Required, Form, Authentication];
    }
    "/mfa" {
        GET => auth_ui::mfa_page, [Session, None, None, None, None, ReadOnly];
        POST => auth_ui::mfa, [Session, None, FormField, Required, Form, Authentication];
    }
    "/mfa/security-key/start" {
        POST => auth_ui::start_security_key_authentication, [Session, None, JsonField, None, Json, Authentication];
    }
    "/mfa/security-key/finish" {
        POST => auth_ui::finish_security_key_authentication, [Session, None, JsonField, Required, Json, Authentication];
    }
    "/locale" {
        POST => rendering::set_locale, [Public, None, None, None, Form, Preference];
    }
    "/logout" {
        POST => auth_ui::logout, [Session, None, FormField, Required, Form, Authentication];
    }
    "/admin" {
        GET => files::admin_browser, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
    }
    "/admin/account" {
        GET => account::account_page, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
    }
    "/admin/account/password" {
        POST => account::change_account_password, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/account/totp" {
        POST => account::set_account_totp, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/account/mfa/start" {
        POST => account::start_account_mfa, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/account/mfa/confirm" {
        POST => account::confirm_account_mfa, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/account/security-keys/register/start" {
        POST => account::start_security_key_registration, [AdminSession, MutationContext, JsonField, None, Json, Authentication];
    }
    "/admin/account/security-keys/register/finish" {
        POST => account::finish_security_key_registration, [AdminSession, MutationContext, JsonField, Required, Json, Privileged];
    }
    "/admin/account/security-keys/{id}/delete" {
        POST => account::delete_security_key, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/files/directories" {
        POST => files::create_directory_ui, [AdminSession, MutationContext, FormField, Required, Form, Storage];
    }
    "/admin/files/upload" {
        POST => files::admin_upload, [AdminSession, MutationContext, FormField, Required, Multipart, Upload];
    }
    layers [
        DefaultBodyLimit::max(HARD_MULTIPART_LIMIT.min(usize::MAX as u64) as usize),
        middleware::from_fn(guard_multipart_upload),
    ];
    "/admin/files/upload/queue" {
        POST => files::admin_upload_queue, [AdminSession, MutationContext, FormField, Required, Multipart, Upload];
    }
    layers [
        DefaultBodyLimit::max(HARD_MULTIPART_LIMIT.min(usize::MAX as u64) as usize),
        middleware::from_fn(guard_multipart_upload),
    ];
    "/admin/files/rename" {
        POST => files::rename_file_ui, [AdminSession, MutationContext, FormField, Required, Form, Storage];
    }
    "/admin/files/download" {
        GET => files::admin_download, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
        HEAD => files::admin_download, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
    }
    "/admin/files/delete" {
        GET => files::delete_file_confirmation, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
        POST => files::delete_file_ui, [AdminSession, MutationContext, FormField, Required, Form, Storage];
    }
    "/admin/preview" {
        GET => files::admin_preview, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
    }
    "/admin/preview/raw" {
        GET => files::admin_preview_raw, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
        HEAD => files::admin_preview_raw, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
    }
    "/admin/shares" {
        GET => shares::share_index_page, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
        POST => shares::create_share, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/shares/new" {
        GET => shares::share_create_page, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
    }
    "/admin/shares/{id}/toggle" {
        POST => shares::toggle_share, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/shares/{id}/upload-conflict" {
        POST => shares::set_share_upload_conflict, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/shares/{id}/password" {
        POST => shares::set_share_password, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/shares/{id}/delete" {
        POST => shares::delete_share, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/admins" {
        GET => admin::admins_page, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
        POST => admin::create_admin_ui, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/admins/{id}/deactivate" {
        POST => admin::deactivate_admin, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/admins/{id}/activate" {
        POST => admin::activate_admin, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/admins/{id}/password" {
        POST => admin::reset_admin_password, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/admins/{id}/totp" {
        POST => admin::reset_admin_totp, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/service-tokens" {
        GET => service_tokens::service_tokens_page, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
        POST => service_tokens::create_service_token, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/service-tokens/{id}/revoke" {
        POST => service_tokens::revoke_service_token, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/settings" {
        GET => settings_audit::settings_page, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
        POST => settings_audit::update_settings, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/settings/audit-ips/delete" {
        GET => settings_audit::audit_ips_delete_confirmation, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
        POST => settings_audit::delete_audit_ips_ui, [AdminSession, MutationContext, FormField, Required, Form, Privileged];
    }
    "/admin/audit" {
        GET => settings_audit::audit_page, [AdminSession, VerifiedSession, None, None, None, ReadOnly];
    }
    "/v/{token}" {
        GET => public::public_page, [ShareCapability, None, None, Observation, None, ReadOnly];
    }
    "/v/{token}/preview" {
        GET => public_preview::public_preview, [ShareCapability, None, None, Observation, None, ReadOnly];
    }
    "/v/{token}/preview/raw" {
        GET => public_preview::public_preview_raw, [ShareCapability, None, None, Observation, None, ReadOnly];
        HEAD => public_preview::public_preview_raw, [ShareCapability, None, None, Observation, None, ReadOnly];
    }
    "/v/{token}/unlock" {
        POST => public::unlock_share, [ShareCapability, None, None, Observation, Form, ShareUnlock];
    }
    "/v/{token}/download" {
        GET => transfer::download, [ShareCapability, None, None, Required, None, ReadOnly];
        HEAD => transfer::download, [ShareCapability, None, None, Required, None, ReadOnly];
    }
    "/v/{token}/download.zip" {
        GET => transfer::download_zip, [ShareCapability, None, None, Required, None, ReadOnly];
    }
    "/v/{token}/upload" {
        POST => upload::upload, [ShareCapability, None, None, Required, Multipart, Upload];
    }
    layers [
        DefaultBodyLimit::max(HARD_MULTIPART_LIMIT.min(usize::MAX as u64) as usize),
        middleware::from_fn(guard_multipart_upload),
    ];
    "/v/{token}/upload/queue" {
        POST => upload::upload_queue, [ShareCapability, None, None, Required, Multipart, Upload];
    }
    layers [
        DefaultBodyLimit::max(HARD_MULTIPART_LIMIT.min(usize::MAX as u64) as usize),
        middleware::from_fn(guard_multipart_upload),
    ];
    "/s/{alias}" {
        GET => public::short_redirect, [Public, None, None, Observation, None, ReadOnly];
    }
    "/assets/vaultlink.css" {
        GET => rendering::stylesheet_asset, [Public, None, None, None, None, ReadOnly];
    }
    "/assets/app.js" {
        GET => rendering::app_js, [Public, None, None, None, None, ReadOnly];
    }
    "/assets/vaultlink-logo.svg" {
        GET => rendering::logo_svg, [Public, None, None, None, None, ReadOnly];
    }
    "/assets/favicon.svg" {
        GET => rendering::favicon_svg, [Public, None, None, None, None, ReadOnly];
    }
    "/assets/favicon-32.png" {
        GET => rendering::favicon_png, [Public, None, None, None, None, ReadOnly];
    }
    "/favicon.ico" {
        GET => rendering::favicon_png, [Public, None, None, None, None, ReadOnly];
    }
}

pub fn router(state: AppState) -> Router {
    crate::install_safe_panic_reporting();
    let router = add_web_routes(Router::new().nest("/api/v2", crate::api::router(state.clone())))
        .layer(DefaultBodyLimit::max(DEFAULT_REQUEST_BODY_LIMIT))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admission::absolute_request_body_deadline,
        ))
        .layer(RequestBodyTimeoutLayer::new(REQUEST_BODY_IDLE_TIMEOUT))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request| {
                let matched_path = request
                    .extensions()
                    .get::<MatchedPath>()
                    .map(MatchedPath::as_str)
                    .unwrap_or("<unmatched>");
                tracing::debug_span!(
                    "http_request",
                    method = %request.method(),
                    route = matched_path,
                    version = ?request.version(),
                    request_id = %request
                        .extensions()
                        .get::<ServerRequestId>()
                        .map(ServerRequestId::as_str)
                        .unwrap_or("<missing>")
                )
            }),
        )
        .layer(middleware::from_fn(attach_server_request_id))
        .layer(SetRequestIdLayer::new(REQUEST_ID_HEADER, MakeRequestUuid))
        .layer(middleware::from_fn(discard_client_request_id));
    #[cfg(panic = "unwind")]
    let router = router.layer(CatchPanicLayer::custom(web_panic_response));
    router
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admission::response_admission,
        ))
        .layer(middleware::from_fn(admission::locale_context))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admission::audit_client_ip_context,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admission::security_headers,
        ))
        .with_state(state)
}

#[cfg(panic = "unwind")]
fn web_panic_response(_panic: Box<dyn std::any::Any + Send + 'static>) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "Internal error",
    )
        .into_response()
}

#[cfg(test)]
mod internal_error_contract_tests {
    use super::*;

    #[test]
    fn reported_internal_error_keeps_the_generic_web_contract() {
        let reported = crate::internal_reporting::report_invariant(
            crate::internal_reporting::InternalOperation::WebSharePasswordHashStateInvariant,
        );
        let error = AppError::from(reported);

        assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.1, "Internal error");
    }

    #[cfg(panic = "unwind")]
    #[tokio::test]
    async fn panic_payload_is_not_returned_by_the_web_boundary() {
        let response = web_panic_response(Box::new("secret\r\nforged-log-line".to_owned()));
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("panic response body");
        assert_eq!(&body[..], b"Internal error");
    }
}

#[cfg(test)]
#[path = "web/tests.rs"]
mod tests;
