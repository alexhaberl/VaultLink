use askama::Template;
use axum::{
    extract::{DefaultBodyLimit, MatchedPath, Request},
    http::{header, HeaderValue, StatusCode},
    middleware,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
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
mod settings_audit;
mod shares;
pub(crate) mod templates;
mod transfer;
mod transfer_runtime;
mod upload;

pub(crate) use admission::guard_multipart_upload;
pub(crate) use public_preview::{public_preview, public_preview_raw};
pub(crate) use transfer::{download, download_zip};
pub(crate) use upload::upload_api;

pub(crate) const HARD_MULTIPART_LIMIT: u64 = crate::config::MAX_MULTIPART_BODY_SIZE;
pub(crate) const ERROR_CODE_HEADER: &str = "x-vaultlink-error-code";
const DEFAULT_REQUEST_BODY_LIMIT: usize = 1024 * 1024;
const MAX_UPLOAD_PATH_FIELD_BYTES: usize = 4 * 1024;
const MAX_UPLOAD_OPTION_FIELD_BYTES: usize = 16;
const MAX_UPLOAD_MULTIPART_FIELDS: usize = 5;
const MAX_SEARCH_QUERY_BYTES: usize = 256;
const BUFFERED_RESPONSE_CHUNK_BYTES: usize = 64 * 1024;
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
const UPLOAD_REQUEST_BODY_DEADLINE: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);
const UPLOAD_QUOTA_RESERVATION_STEP: u64 = 1024 * 1024;
const UPLOAD_QUOTA_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5 * 60);
const TEXT_PREVIEW_RENDER_UNIT_BYTES: u64 = 1_000_000;
const MAX_RENDERED_TEXT_PREVIEW_BYTES: usize = crate::config::MAX_TEXT_PREVIEW_SIZE as usize;
const TEXT_PREVIEW_STREAM_MARKER: &str = "<!--VAULTLINK_ESCAPED_TEXT_PREVIEW_STREAM-->";
#[derive(Debug)]
pub struct AppError(StatusCode, &'static str);

#[derive(Template)]
#[template(path = "web/error.html")]
struct ErrorTemplate<'a> {
    message: &'a str,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if self.0.is_redirection() {
            return Redirect::to(self.1).into_response();
        }
        let locale = i18n::current_locale();
        let message = if self.1 == crate::http_auth::AUDIT_UNAVAILABLE_MESSAGE {
            std::borrow::Cow::Borrowed(i18n::text(locale, i18n::AUDIT_TEMPORARILY_UNAVAILABLE))
        } else if self.1 == crate::http_auth::ARGON2_BUSY_MESSAGE {
            std::borrow::Cow::Borrowed(i18n::text(locale, i18n::PASSWORD_PROCESSING_UNAVAILABLE))
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
            && self.1 == crate::http_auth::ARGON2_BUSY_MESSAGE
        {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        response
    }
}
type Result<T> = std::result::Result<T, AppError>;

fn storage_recovery_app_error(error: crate::file_ops::FileOperationError) -> AppError {
    match error {
        crate::file_ops::FileOperationError::Database(database_error)
            if crate::db::is_audit_unavailable(&database_error) =>
        {
            AppError(
                StatusCode::SERVICE_UNAVAILABLE,
                crate::http_auth::AUDIT_UNAVAILABLE_MESSAGE,
            )
        }
        _ => AppError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Storage state is being recovered",
        ),
    }
}

impl From<crate::http_auth::HttpAuthError> for AppError {
    fn from(value: crate::http_auth::HttpAuthError) -> Self {
        if let Some(location) = value.redirect {
            AppError(StatusCode::SEE_OTHER, location)
        } else {
            AppError(value.status, value.message)
        }
    }
}

pub fn router(state: AppState) -> Router {
    let limit = HARD_MULTIPART_LIMIT.min(usize::MAX as u64) as usize;
    let router = Router::new()
        .nest("/api/v2", crate::api::router(state.clone()))
        .route("/", get(|| async { Redirect::to("/admin") }))
        .route("/login", get(auth_ui::login_page).post(auth_ui::login))
        .route("/mfa", get(auth_ui::mfa_page).post(auth_ui::mfa))
        .route(
            "/mfa/security-key/start",
            post(auth_ui::start_security_key_authentication),
        )
        .route(
            "/mfa/security-key/finish",
            post(auth_ui::finish_security_key_authentication),
        )
        .route("/locale", post(rendering::set_locale))
        .route("/logout", post(auth_ui::logout))
        .route("/admin", get(files::admin_browser))
        .route("/admin/account", get(account::account_page))
        .route(
            "/admin/account/password",
            post(account::change_account_password),
        )
        .route("/admin/account/totp", post(account::set_account_totp))
        .route("/admin/account/mfa/start", post(account::start_account_mfa))
        .route(
            "/admin/account/mfa/confirm",
            post(account::confirm_account_mfa),
        )
        .route(
            "/admin/account/security-keys/register/start",
            post(account::start_security_key_registration),
        )
        .route(
            "/admin/account/security-keys/register/finish",
            post(account::finish_security_key_registration),
        )
        .route(
            "/admin/account/security-keys/{id}/delete",
            post(account::delete_security_key),
        )
        .route("/admin/files/directories", post(files::create_directory_ui))
        .route(
            "/admin/files/upload",
            post(files::admin_upload)
                .layer(DefaultBodyLimit::max(limit))
                .layer(middleware::from_fn(guard_multipart_upload)),
        )
        .route(
            "/admin/files/upload/queue",
            post(files::admin_upload_queue)
                .layer(DefaultBodyLimit::max(limit))
                .layer(middleware::from_fn(guard_multipart_upload)),
        )
        .route("/admin/files/rename", post(files::rename_file_ui))
        .route(
            "/admin/files/download",
            get(files::admin_download).head(files::admin_download),
        )
        .route(
            "/admin/files/delete",
            get(files::delete_file_confirmation).post(files::delete_file_ui),
        )
        .route("/admin/preview", get(files::admin_preview))
        .route(
            "/admin/preview/raw",
            get(files::admin_preview_raw).head(files::admin_preview_raw),
        )
        .route(
            "/admin/shares",
            get(shares::share_index_page).post(shares::create_share),
        )
        .route("/admin/shares/new", get(shares::share_create_page))
        .route("/admin/shares/{id}/toggle", post(shares::toggle_share))
        .route(
            "/admin/shares/{id}/upload-conflict",
            post(shares::set_share_upload_conflict),
        )
        .route(
            "/admin/shares/{id}/password",
            post(shares::set_share_password),
        )
        .route("/admin/shares/{id}/delete", post(shares::delete_share))
        .route(
            "/admin/admins",
            get(admin::admins_page).post(admin::create_admin_ui),
        )
        .route(
            "/admin/admins/{id}/deactivate",
            post(admin::deactivate_admin),
        )
        .route("/admin/admins/{id}/activate", post(admin::activate_admin))
        .route(
            "/admin/admins/{id}/password",
            post(admin::reset_admin_password),
        )
        .route("/admin/admins/{id}/totp", post(admin::reset_admin_totp))
        .route(
            "/admin/settings",
            get(settings_audit::settings_page).post(settings_audit::update_settings),
        )
        .route(
            "/admin/settings/audit-ips/delete",
            get(settings_audit::audit_ips_delete_confirmation)
                .post(settings_audit::delete_audit_ips_ui),
        )
        .route("/admin/audit", get(settings_audit::audit_page))
        .route("/v/{token}", get(public::public_page))
        .route("/v/{token}/preview", get(public_preview::public_preview))
        .route(
            "/v/{token}/preview/raw",
            get(public_preview::public_preview_raw).head(public_preview::public_preview_raw),
        )
        .route("/v/{token}/unlock", post(public::unlock_share))
        .route(
            "/v/{token}/download",
            get(transfer::download).head(transfer::download),
        )
        .route("/v/{token}/download.zip", get(transfer::download_zip))
        .route(
            "/v/{token}/upload",
            post(upload::upload)
                .layer(DefaultBodyLimit::max(limit))
                .layer(middleware::from_fn(guard_multipart_upload)),
        )
        .route(
            "/v/{token}/upload/queue",
            post(upload::upload_queue)
                .layer(DefaultBodyLimit::max(limit))
                .layer(middleware::from_fn(guard_multipart_upload)),
        )
        .route("/s/{alias}", get(public::short_redirect))
        .route("/assets/vaultlink.css", get(rendering::stylesheet_asset))
        .route("/assets/app.js", get(rendering::app_js))
        .route("/assets/vaultlink-logo.svg", get(rendering::logo_svg))
        .route("/assets/favicon.svg", get(rendering::favicon_svg))
        .route("/assets/favicon-32.png", get(rendering::favicon_png))
        .route("/favicon.ico", get(rendering::favicon_png))
        .layer(DefaultBodyLimit::max(DEFAULT_REQUEST_BODY_LIMIT))
        .layer(middleware::from_fn(
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
    let router = router.layer(CatchPanicLayer::new());
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

#[cfg(test)]
#[path = "web/tests.rs"]
mod tests;
