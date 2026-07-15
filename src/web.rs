use axum::{
    extract::{DefaultBodyLimit, MatchedPath, Request},
    http::{header, HeaderValue, StatusCode},
    middleware,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::RequestBodyTimeoutLayer,
    trace::TraceLayer,
};

use crate::{i18n, AppState};

// The extracted test module intentionally keeps the namespace it had while it
// was inline. These imports are test-only and do not enlarge the production
// facade.
#[cfg(test)]
use crate::{
    auth,
    config::MAX_TEXT_PREVIEW_SIZE,
    db::{
        Permission, Session, Share, TransferLeaseBeginOutcome, UploadConflictStrategy,
        UploadReservationBeginOutcome,
    },
    http_auth::{csrf, runtime_settings, try_acquire_client_activity},
    i18n::Locale,
    proxy,
};
#[cfg(test)]
use axum::{
    body::{Body, Bytes},
    extract::ConnectInfo,
    http::{Method, Uri},
};
#[cfg(test)]
use chrono::{Duration, Utc};
#[cfg(test)]
use futures_util::StreamExt;
#[cfg(test)]
use std::{
    io::{self, Read},
    net::SocketAddr,
    path::Path,
    sync::{atomic::Ordering, Arc},
};

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
mod transfer;
mod transfer_runtime;
mod upload;

#[allow(unused_imports)]
use account::{
    account_page, change_account_password, confirm_account_mfa, delete_security_key,
    finish_security_key_registration, start_account_mfa, start_security_key_registration,
    AccountMfaConfirmForm, AccountMfaStartForm, AccountPasswordForm, DeleteSecurityKeyForm,
    SecurityKeyRegistrationFinish, SecurityKeyRegistrationStart,
};
#[allow(unused_imports)]
use admin::{
    activate_admin, admins_page, create_admin_ui, deactivate_admin, reset_admin_password,
    reset_admin_totp, AdminNoticeQuery, CreateAdminUiForm, ResetAdminPasswordForm,
};
pub(crate) use admission::guard_multipart_upload;
#[allow(unused_imports)]
use admission::{
    absolute_request_body_deadline, audit_client_ip_context, locale_context, locale_return_to,
    response_admission, security_headers, streaming_response_path, upload_request_path,
    AbsoluteDeadlineBody, BufferedAdmissionBody, PeerPermitBody, PermitBody, StreamAdmissionBody,
};
#[allow(unused_imports)]
use auth_ui::{
    finish_security_key_authentication, login, login_page, logout, mfa, mfa_page,
    start_security_key_authentication, LoginForm, MfaForm, SecurityKeyAuthenticationFinish,
};
pub(crate) use common::BrowseQuery;
#[allow(unused_imports)]
use common::{
    add_upload_bytes, breadcrumbs, decode_security_keys, display_limit_unit_ceil,
    display_limit_unit_floor, encoded, expiry_picker_html, extension_is_blocked, format_audit_time,
    format_file_time, format_public_date, format_unit_floor, format_utc_minute, human, internal,
    join_display, list_directory_page, otpauth_url, parent_path, parse_expiry, parse_unit_to_bytes,
    preview_allowed, preview_kind, public_breadcrumbs, public_preview_error, qr_svg, search_tree,
    upload_limit_label, CsrfForm, DirectoryAccess, SearchHit,
};
#[allow(unused_imports)]
use files::{
    admin_browser, admin_media_preview_body, admin_preview, admin_preview_raw, admin_upload,
    admin_upload_queue, browser_redirect, create_directory_ui, delete_file_confirmation,
    delete_file_ui, file_name_cell, file_operation_app_error, file_row_actions, media_viewer,
    persist_required_file_audit, preview_too_large_body, process_admin_upload, rename_file_ui,
    stage_admin_upload, AdminUploadSuccess, CreateDirectoryForm, DeleteFileForm, DeleteFileQuery,
    RenameFileForm,
};
#[allow(unused_imports)]
use preview_zip::{
    build_zip_temp, direct_zip_stream, estimate_zip_archive_size, plan_zip, raw_preview_response,
    raw_preview_secure_file_response, read_preview, read_preview_opened, read_preview_secure_file,
    write_streaming_central_entry, write_streaming_eocd, write_streaming_zip64_eocd,
    write_streaming_zip64_locator, write_zip_archive, zip_error, PreviewContent, ReservedZipStream,
    StreamingZipEntry, ZipBuildError, ZipFilePlan, ZipPlan, ZipTempReservation,
    ZIP64_CENTRAL_EXTRA_SIZE, ZIP64_EXTRA_PAYLOAD_SIZE, ZIP64_LOCAL_EXTRA_SIZE,
    ZIP64_SIZE_FIELDS_SIZE, ZIP64_VERSION, ZIP_EOCD_SIZE,
};
#[cfg(test)]
use preview_zip::{TextPreviewReadTestGuard, TextPreviewReadTestHook, TEXT_PREVIEW_READ_TEST_HOOK};
#[allow(unused_imports)]
use public::{
    get_share, get_storage_share, public_page, short_redirect, unlock_share, usable, UnlockForm,
};
#[allow(unused_imports)]
use public_preview::{add_public_preview_actions, public_back_link, text_preview_render_permits};
pub(crate) use public_preview::{public_preview, public_preview_raw};
#[allow(unused_imports)]
use rendering::{
    admin_page, admin_page_with_locale_switcher, admin_page_without_locale_switcher, app_js,
    disk_stats, disk_stats_linux, esc, escaped_html_len, favicon_png, favicon_svg, locale_switcher,
    logo_svg, plain_page, push_html_escaped, safe_internal_return_to, set_locale,
    storage_full_error, storage_has_room, stylesheet_asset, system_panel, DiskStats, LocaleForm,
    NavSection, PageId, UploadChunkReservation, GB, MB, STORAGE_RESERVE_BYTES,
    UPLOAD_BYTES_RESERVED,
};
#[allow(unused_imports)]
use settings_audit::{
    audit_ips_delete_confirmation, audit_page, delete_audit_ips_ui, settings_form, settings_page,
    update_settings, AuditQuery, DeleteAuditIpsForm, SettingsForm,
};
pub(crate) use shares::PreviewRawQuery;
#[allow(unused_imports)]
use shares::{
    create_share, delete_share, selected, set_share_password, set_share_upload_conflict,
    share_create_page, share_index_page, share_is_available, share_is_expired, share_limit_reached,
    share_list_url, share_permission_label, share_primary_status, share_public_url, toggle_share,
    CreateShare, SharePasswordForm, ShareQuery, UploadConflictForm,
};
pub(crate) use transfer::{download, download_zip};
#[allow(unused_imports)]
use transfer_runtime::{
    begin_public_transfer, begin_transfer_lease_cancellation_safe,
    begin_upload_reservation_cancellation_safe, check_public_transfer_availability,
    complete_transfer_without_body, escaped_text_page_stream, limited_multipart_text,
    public_share_route, public_upload_error, set_transfer_cookie, spawn_transfer_cancel,
    start_transfer_heartbeat, transfer_body, transfer_complete_future, transfer_scope,
    upload_io_error, EscapedTextPageStream, PendingReservationOwnership, PendingUploadFileError,
    PublicTransferLease, TransferBodyStream, UploadQuotaReservation,
};
pub(crate) use upload::{upload, upload_api};
#[allow(unused_imports)]
use upload::{
    upload_queue, upload_queue_error_response, UploadQueueError, UploadQueueErrorEnvelope,
    UploadQueueSuccess,
};

pub(crate) const HARD_MULTIPART_LIMIT: u64 = crate::config::MAX_MULTIPART_BODY_SIZE;
pub(crate) const ERROR_CODE_HEADER: &str = "x-vaultlink-error-code";
const DEFAULT_REQUEST_BODY_LIMIT: usize = 1024 * 1024;
const MAX_UPLOAD_PATH_FIELD_BYTES: usize = 4 * 1024;
const MAX_UPLOAD_OPTION_FIELD_BYTES: usize = 16;
const MAX_UPLOAD_MULTIPART_FIELDS: usize = 5;
const MAX_SEARCH_QUERY_BYTES: usize = 256;
const BUFFERED_RESPONSE_CHUNK_BYTES: usize = 64 * 1024;
const BUFFERED_RESPONSE_MAX_LIFETIME: std::time::Duration = std::time::Duration::from_secs(5 * 60);
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
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if self.0.is_redirection() {
            return Redirect::to(self.1).into_response();
        }
        let message = i18n::text_from_german(i18n::current_locale(), self.1);
        let audit_unavailable = self.0 == StatusCode::SERVICE_UNAVAILABLE
            && self.1 == crate::http_auth::AUDIT_UNAVAILABLE_MESSAGE;
        let mut response = (
            self.0,
            Html(plain_page(
                "Fehler",
                &format!(
                    r#"<section class="vl-panel"><h1><vl-i18n key="common.error"/></h1><p>{}</p></section>"#,
                    esc(&message)
                ),
            )),
        )
            .into_response();
        if audit_unavailable {
            response.headers_mut().insert(
                ERROR_CODE_HEADER,
                HeaderValue::from_static("audit_unavailable"),
            );
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
            "Speicherzustand wird wiederhergestellt",
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
    Router::new()
        .nest("/api/v1", crate::api::router(state.clone()))
        .route("/", get(|| async { Redirect::to("/admin") }))
        .route("/login", get(login_page).post(login))
        .route("/mfa", get(mfa_page).post(mfa))
        .route(
            "/mfa/security-key/start",
            post(start_security_key_authentication),
        )
        .route(
            "/mfa/security-key/finish",
            post(finish_security_key_authentication),
        )
        .route("/locale", post(set_locale))
        .route("/logout", post(logout))
        .route("/admin", get(admin_browser))
        .route("/admin/account", get(account_page))
        .route("/admin/account/password", post(change_account_password))
        .route("/admin/account/mfa/start", post(start_account_mfa))
        .route("/admin/account/mfa/confirm", post(confirm_account_mfa))
        .route(
            "/admin/account/security-keys/register/start",
            post(start_security_key_registration),
        )
        .route(
            "/admin/account/security-keys/register/finish",
            post(finish_security_key_registration),
        )
        .route(
            "/admin/account/security-keys/{id}/delete",
            post(delete_security_key),
        )
        .route("/admin/files/directories", post(create_directory_ui))
        .route(
            "/admin/files/upload",
            post(admin_upload)
                .layer(DefaultBodyLimit::max(limit))
                .layer(middleware::from_fn(guard_multipart_upload)),
        )
        .route(
            "/admin/files/upload/queue",
            post(admin_upload_queue)
                .layer(DefaultBodyLimit::max(limit))
                .layer(middleware::from_fn(guard_multipart_upload)),
        )
        .route("/admin/files/rename", post(rename_file_ui))
        .route(
            "/admin/files/delete",
            get(delete_file_confirmation).post(delete_file_ui),
        )
        .route("/admin/preview", get(admin_preview))
        .route(
            "/admin/preview/raw",
            get(admin_preview_raw).head(admin_preview_raw),
        )
        .route("/admin/shares", get(share_index_page).post(create_share))
        .route("/admin/shares/new", get(share_create_page))
        .route("/admin/shares/{id}/toggle", post(toggle_share))
        .route(
            "/admin/shares/{id}/upload-conflict",
            post(set_share_upload_conflict),
        )
        .route("/admin/shares/{id}/password", post(set_share_password))
        .route("/admin/shares/{id}/delete", post(delete_share))
        .route("/admin/admins", get(admins_page).post(create_admin_ui))
        .route("/admin/admins/{id}/deactivate", post(deactivate_admin))
        .route("/admin/admins/{id}/activate", post(activate_admin))
        .route("/admin/admins/{id}/password", post(reset_admin_password))
        .route("/admin/admins/{id}/totp", post(reset_admin_totp))
        .route("/admin/settings", get(settings_page).post(update_settings))
        .route(
            "/admin/settings/audit-ips/delete",
            get(audit_ips_delete_confirmation).post(delete_audit_ips_ui),
        )
        .route("/admin/audit", get(audit_page))
        .route("/v/{token}", get(public_page))
        .route("/v/{token}/preview", get(public_preview))
        .route(
            "/v/{token}/preview/raw",
            get(public_preview_raw).head(public_preview_raw),
        )
        .route("/v/{token}/unlock", post(unlock_share))
        .route("/v/{token}/download", get(download).head(download))
        .route("/v/{token}/download.zip", get(download_zip))
        .route(
            "/v/{token}/upload",
            post(upload)
                .layer(DefaultBodyLimit::max(limit))
                .layer(middleware::from_fn(guard_multipart_upload)),
        )
        .route(
            "/v/{token}/upload/queue",
            post(upload_queue)
                .layer(DefaultBodyLimit::max(limit))
                .layer(middleware::from_fn(guard_multipart_upload)),
        )
        .route("/s/{alias}", get(short_redirect))
        .route("/assets/vaultlink.css", get(stylesheet_asset))
        .route("/assets/app.js", get(app_js))
        .route("/assets/vaultlink-logo.svg", get(logo_svg))
        .route("/assets/favicon.svg", get(favicon_svg))
        .route("/assets/favicon-32.png", get(favicon_png))
        .route("/favicon.ico", get(favicon_png))
        .layer(DefaultBodyLimit::max(DEFAULT_REQUEST_BODY_LIMIT))
        .layer(middleware::from_fn(absolute_request_body_deadline))
        .layer(RequestBodyTimeoutLayer::new(REQUEST_BODY_IDLE_TIMEOUT))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::new(
            header::HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ))
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
                    version = ?request.version()
                )
            }),
        )
        .layer(CatchPanicLayer::new())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            audit_client_ip_context,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .layer(middleware::from_fn(locale_context))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            response_admission,
        ))
        .with_state(state)
}

#[cfg(test)]
#[path = "web/tests.rs"]
mod tests;
