use std::{
    collections::VecDeque,
    future::Future,
    io::{self, Read, Seek, Write},
    net::SocketAddr,
    path::Path,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    task::{Context, Poll},
};

use axum::{
    body::{Body, Bytes},
    extract::{
        ConnectInfo, DefaultBodyLimit, Form, Json, Multipart, OriginalUri, Path as AxPath, Query,
        Request, State,
    },
    http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use base64::Engine as _;
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use futures_util::{Stream, StreamExt};
use qrcode::{render::svg, QrCode};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::io::ReaderStream;
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};

use crate::{
    auth,
    db::{
        AdminDeactivationOutcome, AdminMfaEnrollmentActivationOutcome,
        AdminMfaEnrollmentStartOutcome, AdminPasswordChangeOutcome, Database,
        PasswordSessionCreationOutcome, Permission, Session, Share, TransferAvailabilityOutcome,
        TransferLeaseBeginOutcome, TransferLeaseCompleteOutcome, UploadConflictStrategy,
    },
    file_ops,
    http_auth::{
        audit, clear_session_cookie, commit_runtime_settings, csrf, current_audit_client_ip,
        database, make_session_cookie, make_transfer_cookie, make_unlock_cookie,
        redirect_with_cookie, runtime_settings, session, share_is_unlocked, transfer_cookie,
        with_audit_client_ip, MissingSession, TransferCookieScope, UnlockCookieScope,
    },
    i18n::{self, Locale, MessageKey},
    path_security, proxy,
    range::parse_byte_range,
    runtime,
    runtime::RuntimeSettings,
    secure_fs::{DirectoryScan, Entry, PendingUpload, SecureDirectory, SecureFile, SecureRoot},
    AppState,
};

pub(crate) const HARD_MULTIPART_LIMIT: u64 = 128 * 1024 * 1024 * 1024;
const DEFAULT_REQUEST_BODY_LIMIT: usize = 1024 * 1024;
const MAX_UPLOAD_PATH_FIELD_BYTES: usize = 4 * 1024;
const MAX_UPLOAD_OPTION_FIELD_BYTES: usize = 16;
const MAX_UPLOAD_MULTIPART_FIELDS: usize = 4;

#[derive(Debug)]
pub struct AppError(StatusCode, &'static str);
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if self.0.is_redirection() {
            return Redirect::to(self.1).into_response();
        }
        let message = i18n::text_from_german(i18n::current_locale(), self.1);
        (
            self.0,
            Html(plain_page(
                "Fehler",
                &format!(
                    r#"<section><h1><vl-i18n key="common.error"/></h1><p>{}</p></section>"#,
                    esc(&message)
                ),
            )),
        )
            .into_response()
    }
}
type Result<T> = std::result::Result<T, AppError>;

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
        .route("/admin/admins", get(admins_page_v3).post(create_admin_ui))
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
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::new(
            header::HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ))
        .layer(TraceLayer::new_for_http())
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
        .with_state(state)
}

async fn locale_context(req: Request, next: Next) -> Response {
    let locale = Locale::resolve(req.headers());
    let return_to = locale_return_to(req.method(), req.uri());
    i18n::scope(locale, return_to, async move {
        let mut response = next.run(req).await;
        let is_localized_content = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.starts_with("text/html") || value.starts_with("application/javascript")
            });
        if is_localized_content {
            response.headers_mut().insert(
                header::CONTENT_LANGUAGE,
                HeaderValue::from_static(locale.code()),
            );
        }
        response
    })
    .await
}

fn locale_return_to(method: &Method, uri: &Uri) -> String {
    let current = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    if matches!(*method, Method::GET | Method::HEAD) {
        return current.to_string();
    }

    match uri.path() {
        "/login"
        | "/mfa"
        | "/admin/shares"
        | "/admin/admins"
        | "/admin/settings"
        | "/admin/settings/audit-ips/delete" => current.to_string(),
        "/admin/files/delete" => "/admin".to_string(),
        "/logout" => "/login".to_string(),
        path if path.starts_with("/admin/account/") => "/admin/account".to_string(),
        path if path.starts_with("/admin/files/") => "/admin".to_string(),
        path if path.starts_with("/admin/shares/") => "/admin/shares".to_string(),
        path if path.starts_with("/admin/admins/") => "/admin/admins".to_string(),
        path if path.starts_with("/v/") => {
            let token = path
                .strip_prefix("/v/")
                .and_then(|value| value.split('/').next())
                .filter(|value| !value.is_empty());
            token
                .map(|token| format!("/v/{token}"))
                .unwrap_or_else(|| "/".to_string())
        }
        _ => "/".to_string(),
    }
}

async fn audit_client_ip_context(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let client_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| {
            proxy::effective_client_ip(peer.ip(), req.headers(), &state.config)
        });
    with_audit_client_ip(client_ip, next.run(req)).await
}

async fn security_headers(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let h = response.headers_mut();
    h.insert("content-security-policy",HeaderValue::from_static("default-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    if state.config.tls.hsts_enabled {
        h.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    response
}

pub(crate) async fn guard_multipart_upload(request: Request, next: Next) -> Response {
    match crate::multipart_guard::guard_multipart_request(request) {
        Ok(request) => next.run(request).await,
        Err(error) => AppError(error.status_code(), "Ungültiger Multipart-Upload").into_response(),
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn app_css() -> &'static str {
    r#"
:root{--bg:#070b16;--bg2:#0b1224;--panel:#111a2e;--panel2:#151f36;--line:#263553;--line2:#334565;--text:#f3f7ff;--muted:#9fb0d0;--soft:#c8d6f4;--accent:#5aa7ff;--accent2:#7c5cff;--good:#55d69a;--bad:#ff7b86;--shadow:0 22px 70px rgba(0,0,0,.36)}
*{box-sizing:border-box}html{min-height:100%}body{margin:0;min-height:100vh;background:radial-gradient(circle at 15% -10%,rgba(90,167,255,.22),transparent 30rem),radial-gradient(circle at 85% 5%,rgba(124,92,255,.18),transparent 28rem),linear-gradient(135deg,var(--bg),var(--bg2) 60%,#080d1b);color:var(--text);font:16px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}.app-shell{display:grid;grid-template-columns:260px minmax(0,1fr);min-height:100vh}.public-shell{min-height:100vh;padding:clamp(1rem,3vw,2.5rem);display:grid;align-items:start}.public-shell main{width:min(1120px,100%);margin:4vh auto 0}.sidebar{position:sticky;top:0;height:100vh;padding:1.25rem;border-right:1px solid rgba(255,255,255,.08);background:linear-gradient(180deg,rgba(14,22,40,.96),rgba(8,12,24,.92));backdrop-filter:blur(18px)}.brand,.public-brand{display:flex;align-items:center;gap:.75rem;margin-bottom:1.5rem;font-weight:800;letter-spacing:.01em}.brand img,.public-brand img{width:48px;height:48px;border-radius:15px;box-shadow:0 12px 30px rgba(90,167,255,.18)}.brand small,.public-brand small{display:block;color:var(--muted);font-weight:600}.nav-group{display:grid;gap:.35rem}.nav-link{display:flex;align-items:center;gap:.65rem;padding:.75rem .85rem;border-radius:12px;color:var(--soft);border:1px solid transparent}.nav-link:hover{text-decoration:none;background:rgba(90,167,255,.10);border-color:rgba(90,167,255,.18)}.sidebar-foot{position:absolute;left:1.25rem;right:1.25rem;bottom:1.25rem;padding:1rem;border:1px solid rgba(85,214,154,.18);border-radius:16px;background:rgba(85,214,154,.07);color:var(--muted);font-size:.9rem;overflow-wrap:anywhere}.content{min-width:0;padding:1.5rem 1.75rem 2.5rem}.topbar{display:flex;justify-content:space-between;align-items:center;gap:1rem;margin:0 auto 1.25rem;max-width:1500px}.topbar-title p{margin:0;color:var(--muted);font-size:.9rem}.topbar-title h1{margin:.15rem 0 0;font-size:clamp(1.45rem,2vw,2.1rem)}.topbar-actions{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center}.topbar-actions form{margin:0}main{max-width:1500px;margin:0 auto}
section,.panel{background:linear-gradient(180deg,rgba(21,31,54,.96),rgba(15,23,42,.96));border:1px solid rgba(255,255,255,.08);box-shadow:var(--shadow);padding:1.25rem;border-radius:22px;margin:1rem 0;overflow:auto}.hero{display:flex;justify-content:space-between;align-items:flex-end;gap:1rem;background:linear-gradient(135deg,rgba(90,167,255,.16),rgba(124,92,255,.10)),linear-gradient(180deg,rgba(26,39,66,.98),rgba(17,26,46,.98))}.hero h1,.panel h1,section h1{margin:.15rem 0 .65rem;font-size:clamp(1.8rem,3vw,3rem);line-height:1.08}.eyebrow{margin:0;color:#91c7ff;text-transform:uppercase;letter-spacing:.12em;font-size:.78rem;font-weight:800}.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:.8rem;margin:1rem 0}.stat-card{padding:1rem;border:1px solid rgba(255,255,255,.08);border-radius:18px;background:rgba(255,255,255,.045)}.stat-card strong{display:block;font-size:1.45rem}.stat-card span{color:var(--muted);font-size:.9rem}
input,select,button,textarea{font:inherit;padding:.72rem .8rem;border-radius:12px;border:1px solid var(--line2);background:#0b1326;color:var(--text);max-width:100%}input:focus,select:focus,textarea:focus{outline:2px solid rgba(90,167,255,.35);border-color:var(--accent)}button,.button{display:inline-flex;align-items:center;justify-content:center;gap:.4rem;cursor:pointer;padding:.78rem 1rem;border-radius:12px;background:linear-gradient(135deg,#2f67bd,#4e7de2);border:1px solid rgba(255,255,255,.1);color:white;box-shadow:0 10px 24px rgba(47,103,189,.22);font-weight:750;line-height:1.1;text-decoration:none;white-space:nowrap}button:hover,.button:hover{text-decoration:none;filter:brightness(1.08)}button:disabled{cursor:not-allowed;opacity:.5;filter:none}.button.secondary,button.secondary{background:rgba(90,167,255,.12);border-color:rgba(90,167,255,.35);box-shadow:none;color:#dbeafe}.button.danger,button.danger{background:rgba(255,123,134,.16);border-color:rgba(255,123,134,.34);box-shadow:none;color:#ffd6db}.button.small,button.small{padding:.55rem .75rem;border-radius:10px;font-size:.92rem}label{display:block;margin:.7rem 0;color:var(--soft);font-weight:650}label input,label select,label textarea{margin-top:.25rem;width:100%}.datetime-picker{position:relative;display:flex;gap:.45rem;align-items:center}.datetime-picker input{margin-top:.25rem}.datetime-picker .calendar-button{margin-top:.25rem;padding:.72rem .8rem}.datetime-popover{position:absolute;z-index:20;top:calc(100% + .45rem);left:0;min-width:min(360px,90vw);padding:.9rem;border:1px solid rgba(90,167,255,.28);border-radius:16px;background:linear-gradient(180deg,#121d34,#0c1428);box-shadow:0 24px 60px rgba(0,0,0,.48)}.datetime-popover[hidden]{display:none}.datetime-popover .picker-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.65rem}.datetime-popover label{margin:0}.datetime-popover .picker-actions{display:flex;gap:.5rem;justify-content:flex-end;margin-top:.8rem}table{width:100%;border-collapse:separate;border-spacing:0 .35rem}th{padding:.65rem .8rem;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;font-size:.78rem;text-align:left}td{padding:.85rem .8rem;border-top:1px solid rgba(255,255,255,.07);border-bottom:1px solid rgba(255,255,255,.07);background:rgba(11,19,38,.55);vertical-align:top}td:first-child{border-left:1px solid rgba(255,255,255,.07);border-radius:14px 0 0 14px}td:last-child{border-right:1px solid rgba(255,255,255,.07);border-radius:0 14px 14px 0}.row{display:flex;gap:.8rem;flex-wrap:wrap;align-items:end}.row label{min-width:220px;flex:1}.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:.8rem;align-items:end}.form-grid label{margin:0}.form-actions{display:flex;gap:.55rem;align-items:end}.muted{color:var(--muted)}.bad{color:var(--bad)}.good{color:var(--good)}.notice{padding:.85rem 1rem;border-radius:14px;background:rgba(85,214,154,.09);border:1px solid rgba(85,214,154,.2);color:#c8f8df}code,pre{overflow-wrap:anywhere}code{padding:.15rem .35rem;border:1px solid rgba(255,255,255,.08);border-radius:8px;background:rgba(0,0,0,.18);color:#dbe9ff}pre{white-space:pre-wrap;background:#0b1326;border:1px solid var(--line);border-radius:16px;padding:1rem}.crumbs,.actions,.button-group,.preview-actions{display:flex;gap:.55rem;flex-wrap:wrap;align-items:center}.crumbs{padding:.75rem .9rem;border-radius:14px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07)}.actions form,.button-group form{display:inline-flex;gap:.45rem;flex-wrap:wrap;margin:0}.pill{display:inline-flex;align-items:center;gap:.35rem;padding:.25rem .55rem;border-radius:999px;border:1px solid rgba(90,167,255,.22);color:#cfe5ff;background:rgba(90,167,255,.10)}.split{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:1rem;align-items:start}.side-panel{padding:1rem;border-radius:18px;border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.045)}.form-card,.share-card{padding:1rem;border:1px solid rgba(90,167,255,.16);border-radius:18px;background:rgba(90,167,255,.045);margin:.9rem 0}.form-card h2,.share-card h2{margin:0 0 .75rem;font-size:1rem;color:#cfe5ff}.share-card{display:grid;gap:.9rem}.share-main{display:grid;grid-template-columns:minmax(220px,1.3fr) minmax(150px,.6fr) minmax(150px,.7fr) minmax(120px,.45fr) minmax(280px,1fr);gap:1rem;align-items:start}.share-actions,.password-actions{display:flex;gap:.55rem;flex-wrap:wrap;align-items:center}.password-actions{padding-top:.75rem;margin-top:.75rem;border-top:1px solid rgba(255,255,255,.08)}.password-actions input{min-width:180px;flex:1}.overwrite-panel{padding:.85rem;border:1px solid rgba(255,255,255,.08);border-radius:16px;background:rgba(255,255,255,.035)}img{border-radius:16px}iframe{background:#0b1326}
.actions a,.preview-actions a,td:last-child>a,section>p>a[href="/admin"],section>p>a[href^="/admin?"],section>p>a[href^="/v/"]{display:inline-flex;align-items:center;justify-content:center;gap:.4rem;padding:.55rem .75rem;border-radius:10px;background:rgba(90,167,255,.12);border:1px solid rgba(90,167,255,.35);color:#dbeafe;text-decoration:none;font-weight:750;line-height:1.1}.actions a:hover,.preview-actions a:hover,td:last-child>a:hover,section>p>a:hover{text-decoration:none;filter:brightness(1.08)}.row>button{align-self:end;margin-bottom:.7rem}
.qr-card{display:inline-block;margin:.9rem 0;padding:1rem;border-radius:18px;background:#f8fbff;color:#081226;border:1px solid rgba(90,167,255,.28);box-shadow:0 18px 44px rgba(0,0,0,.20)}.qr-card svg{display:block;width:220px;height:220px;border-radius:10px}.secret-block{display:grid;gap:.45rem;max-width:860px}.secret-block code{display:block;padding:.55rem .7rem}
.admin-columns{display:grid;grid-template-columns:1fr;gap:1rem;align-items:start}.admin-column{padding:1rem;border:1px solid rgba(90,167,255,.16);border-radius:18px;background:rgba(90,167,255,.045)}.admin-column summary{cursor:pointer;font-size:1.1rem;font-weight:800;color:#dbeafe;margin-bottom:.7rem}.admin-column summary::marker{color:var(--accent)}.admin-column table{margin-top:.6rem}.admin-actions{display:grid;gap:.65rem;min-width:520px}.admin-actions .button-group{gap:.5rem}.admin-reset-form{display:grid;grid-template-columns:minmax(180px,1fr) minmax(180px,1fr) auto;gap:.55rem;align-items:end;padding-top:.65rem;border-top:1px solid rgba(255,255,255,.08)}.admin-reset-form label{margin:0}.admin-reset-form input{width:100%}
.toggle-card{display:flex;align-items:center;gap:.85rem;width:100%;min-width:260px;padding:.9rem 1rem;border:1px solid rgba(90,167,255,.22);border-radius:16px;background:rgba(90,167,255,.07);cursor:pointer}.toggle-card input{position:absolute;opacity:0;width:1px;height:1px}.toggle-card .switch-ui{flex:0 0 auto;width:54px;height:30px;border-radius:999px;background:#1f2b45;border:1px solid var(--line2);position:relative;box-shadow:inset 0 1px 4px rgba(0,0,0,.28)}.toggle-card .switch-ui::after{content:"";position:absolute;top:3px;left:3px;width:22px;height:22px;border-radius:999px;background:#dbeafe;transition:transform .18s ease,background .18s ease}.toggle-card input:checked+.switch-ui{background:linear-gradient(135deg,#2f67bd,#4e7de2);border-color:rgba(255,255,255,.18)}.toggle-card input:checked+.switch-ui::after{transform:translateX(24px);background:#fff}.toggle-card .switch-copy{display:grid;gap:.15rem;color:var(--text)}.toggle-card small{display:block;color:var(--muted);font-weight:600;line-height:1.35}.toggle-card:focus-within{outline:2px solid rgba(90,167,255,.35)}.toggle-card>input+span{position:relative;display:grid;gap:.15rem;padding-left:68px;color:var(--text)}.toggle-card>input+span::before{content:"";position:absolute;left:0;top:50%;transform:translateY(-50%);width:54px;height:30px;border-radius:999px;background:#1f2b45;border:1px solid var(--line2);box-shadow:inset 0 1px 4px rgba(0,0,0,.28)}.toggle-card>input+span::after{content:"";position:absolute;left:4px;top:50%;transform:translateY(-50%);width:22px;height:22px;border-radius:999px;background:#dbeafe;transition:transform .18s ease,background .18s ease}.toggle-card>input:checked+span::before{background:linear-gradient(135deg,#2f67bd,#4e7de2);border-color:rgba(255,255,255,.18)}.toggle-card>input:checked+span::after{transform:translate(24px,-50%);background:#fff}
@media(max-width:980px){.app-shell{display:block}.sidebar{position:relative;height:auto;border-right:0;border-bottom:1px solid rgba(255,255,255,.08)}.sidebar-foot{display:none}.nav-group{grid-template-columns:repeat(auto-fit,minmax(130px,1fr))}.content{padding:1rem}.split,.admin-columns{grid-template-columns:1fr}}@media(max-width:650px){th:nth-child(3),td:nth-child(3){display:none}.topbar{display:block}.hero{display:block}}
"#
}

async fn stylesheet_asset() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        format!(
            "@layer vl-legacy, vl-reset, vl-tokens, vl-base, vl-components, vl-layouts, vl-utilities;\n@layer vl-legacy {{{}}}\n{}",
            app_css(),
            crate::ui::APP_CSS
        ),
    )
}

async fn app_js() -> impl IntoResponse {
    let script = format!(
        "{}\n{}",
        r#"document.addEventListener('click',async e=>{const closer=e.target.closest('[data-details-close]');if(closer){closer.closest('details')?.removeAttribute('open');return;}const b=e.target.closest('[data-copy]');if(!b)return;try{await navigator.clipboard.writeText(b.dataset.copy);b.textContent='<vl-i18n key="common.copied"/>';}catch(_){b.textContent='<vl-i18n key="common.copy_failed"/>';}});
const pad=n=>String(n).padStart(2,'0');
function fillSelect(select,from,to,current){select.innerHTML='';for(let i=from;i<=to;i++){const o=document.createElement('option');o.value=String(i);o.textContent=String(i).padStart(select.dataset.pad||0,'0');if(i===current)o.selected=true;select.appendChild(o);}}
function daysInMonth(y,m){return new Date(y,m,0).getDate();}
function initDateTimePicker(picker){const input=picker.querySelector('[data-datetime-input]');const pop=picker.querySelector('[data-datetime-popover]');const toggle=picker.querySelector('[data-datetime-toggle]');const year=picker.querySelector('[data-dt-year]');const month=picker.querySelector('[data-dt-month]');const day=picker.querySelector('[data-dt-day]');const hour=picker.querySelector('[data-dt-hour]');const minute=picker.querySelector('[data-dt-minute]');const now=new Date();fillSelect(year,now.getFullYear(),now.getFullYear()+5,now.getFullYear());fillSelect(month,1,12,now.getMonth()+1);fillSelect(hour,0,23,23);fillSelect(minute,0,59,0);function syncDays(){const selected=Number(day.value)||now.getDate();fillSelect(day,1,daysInMonth(Number(year.value),Number(month.value)),Math.min(selected,daysInMonth(Number(year.value),Number(month.value))))}function setOpen(open){pop.hidden=!open;toggle.setAttribute('aria-expanded',String(open));if(open)year.focus();}syncDays();[year,month].forEach(s=>s.addEventListener('change',syncDays));toggle.addEventListener('click',()=>setOpen(pop.hidden));picker.addEventListener('keydown',e=>{if(e.key==='Escape'){setOpen(false);toggle.focus();}});picker.querySelector('[data-datetime-apply]').addEventListener('click',()=>{const date=document.documentElement.lang==='de'?`${pad(day.value)}.${pad(month.value)}.${year.value}`:`${year.value}-${pad(month.value)}-${pad(day.value)}`;input.value=`${date} ${pad(hour.value)}:${pad(minute.value)}`;setOpen(false);});picker.querySelector('[data-datetime-clear]').addEventListener('click',()=>{input.value='';setOpen(false);});}
function initDeleteConfirmation(form){const input=form.querySelector('[data-confirm-input]');const button=form.querySelector('[data-confirm-delete]');if(!input||!button)return;const sync=()=>{button.disabled=input.value!==form.dataset.requiredName;};input.addEventListener('input',sync);sync();input.focus();}
document.addEventListener('click',e=>{document.querySelectorAll('[data-datetime-picker]').forEach(p=>{if(!p.contains(e.target)){const pop=p.querySelector('[data-datetime-popover]');const toggle=p.querySelector('[data-datetime-toggle]');if(pop)pop.hidden=true;if(toggle)toggle.setAttribute('aria-expanded','false');}});});
function initFileSelection(){const bar=document.querySelector('[data-selection-bar]');const link=bar?.querySelector('[data-selection-share]');const name=bar?.querySelector('[data-selection-name]');if(!bar||!link||!name)return;document.querySelectorAll('[data-file-select]').forEach(input=>input.addEventListener('change',()=>{if(!input.checked)return;name.textContent=`${input.value||'/'} <vl-i18n key="files.selected"/>`;link.href=`/admin/shares/new?path=${encodeURIComponent(input.value)}`;bar.hidden=false;}));}
function initShareReview(){const form=document.querySelector('[data-share-create]');if(!form)return;const review=form.parentElement.querySelector('[data-share-review]');const passwordToggle=form.querySelector('[data-password-toggle]');const passwordFields=form.querySelector('[data-password-fields]');const uploadRules=form.querySelector('[data-upload-rules]');const permissionLabels={download_only:'<vl-i18n key="share.download_only"/>',upload_only:'<vl-i18n key="share.upload_only"/>',download_upload:'<vl-i18n key="share.download_upload"/>'};const sync=()=>{const permission=form.querySelector('[name="permission"]:checked')?.value||form.querySelector('[name="permission"]')?.value||'download_only';const alias=form.elements.alias?.value.trim();const maximum=form.elements.max_downloads?.value.trim();const protectedShare=Boolean(passwordToggle?.checked);if(review){review.querySelector('[data-review-permission]').textContent=permissionLabels[permission]||permission;review.querySelector('[data-review-password]').textContent=protectedShare?'<vl-i18n key="share.password_protected"/>':'<vl-i18n key="share.no_password"/>';review.querySelector('[data-review-limit]').textContent=maximum?`${maximum} <vl-i18n key="share.transfers"/>`:'<vl-i18n key="common.unlimited"/>';const url=review.querySelector('[data-review-url]');if(url){const base=url.textContent.split('/v/')[0].split('/s/')[0];url.textContent=alias?`${base}/s/${alias}`:`${base}/v/••••••••`;}}if(passwordFields){passwordFields.hidden=!protectedShare;passwordFields.querySelectorAll('input').forEach(input=>{input.disabled=!protectedShare;input.required=protectedShare;});}if(uploadRules)uploadRules.hidden=permission==='download_only';};form.addEventListener('input',sync);form.addEventListener('change',sync);sync();}
function webauthnBuffer(value){const padded=value.replace(/-/g,'+').replace(/_/g,'/')+'==='.slice((value.length+3)%4);const raw=atob(padded);return Uint8Array.from(raw,c=>c.charCodeAt(0));}
function webauthnBase64(value){const bytes=new Uint8Array(value);let raw='';bytes.forEach(byte=>raw+=String.fromCharCode(byte));return btoa(raw).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
function webauthnOptions(options){options.publicKey.challenge=webauthnBuffer(options.publicKey.challenge);if(options.publicKey.user)options.publicKey.user.id=webauthnBuffer(options.publicKey.user.id);for(const key of ['allowCredentials','excludeCredentials'])for(const item of options.publicKey[key]||[])item.id=webauthnBuffer(item.id);return options;}
function webauthnCredential(credential){const response={};for(const key of ['attestationObject','clientDataJSON','authenticatorData','signature','userHandle'])if(credential.response[key])response[key]=webauthnBase64(credential.response[key]);if(credential.response.getTransports)response.transports=credential.response.getTransports();return{id:credential.id,rawId:webauthnBase64(credential.rawId),type:credential.type,response,clientExtensionResults:credential.getClientExtensionResults(),authenticatorAttachment:credential.authenticatorAttachment};}
async function webauthnPost(url,body){const response=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});if(!response.ok)throw new Error(await response.text());return response.json();}
function initSecurityKeyLogin(){const button=document.querySelector('[data-security-key-login]');if(!button)return;const status=document.querySelector('[data-security-key-status]');button.addEventListener('click',async()=>{button.disabled=true;status.textContent='<vl-i18n key="auth.security_key_wait"/>';try{const options=webauthnOptions(await webauthnPost('/mfa/security-key/start'));const credential=await navigator.credentials.get(options);const result=await webauthnPost('/mfa/security-key/finish',{credential:webauthnCredential(credential)});location.assign(result.redirect);}catch(error){status.textContent='<vl-i18n key="auth.security_key_failed"/>';button.disabled=false;}});}
function initSecurityKeyRegistration(){const form=document.querySelector('[data-security-key-register]');if(!form)return;const status=form.querySelector('[data-security-key-status]');form.addEventListener('submit',async event=>{event.preventDefault();const button=form.querySelector('button');button.disabled=true;status.textContent='<vl-i18n key="auth.security_key_wait"/>';const label=form.elements.label.value.trim();try{const options=webauthnOptions(await webauthnPost('/admin/account/security-keys/register/start',{csrf:form.dataset.csrf,current_password:form.elements.current_password.value,label}));const credential=await navigator.credentials.create(options);const result=await webauthnPost('/admin/account/security-keys/register/finish',{csrf:form.dataset.csrf,label,credential:webauthnCredential(credential)});location.assign(result.redirect);}catch(error){status.textContent='<vl-i18n key="auth.security_key_failed"/>';button.disabled=false;}});}
document.addEventListener('DOMContentLoaded',()=>{document.querySelectorAll('[data-datetime-picker]').forEach(initDateTimePicker);document.querySelectorAll('[data-delete-confirmation]').forEach(initDeleteConfirmation);initFileSelection();initShareReview();initSecurityKeyLogin();initSecurityKeyRegistration();});
document.addEventListener('submit',e=>{e.target.querySelectorAll('[data-tz-offset]').forEach(i=>{i.value=String(new Date().getTimezoneOffset())})});"#,
        crate::ui::UPLOAD_QUEUE_JAVASCRIPT
    );
    let script = i18n::render_markers(i18n::current_locale(), &script);
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        script,
    )
}

const MB: u64 = 1_000_000;
const GB: u64 = 1_000_000_000;
const STORAGE_RESERVE_BYTES: u64 = 64 * MB;
const SHARE_PASSWORD_HARD_MAX_BYTES: usize = 1024;

async fn logo_svg() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "image/svg+xml; charset=utf-8")],
        LOGO_SVG,
    )
}

async fn favicon_svg() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "image/svg+xml; charset=utf-8")],
        LOGO_SVG,
    )
}

async fn favicon_png() -> impl IntoResponse {
    static PNG_1X1: &[u8] = &[
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6,
        0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 13, 73, 68, 65, 84, 120, 156, 99, 96, 248, 207, 192, 0,
        0, 4, 0, 1, 255, 166, 44, 203, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
    ];
    ([(header::CONTENT_TYPE, "image/png")], PNG_1X1)
}

const LOGO_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="VaultLink"><defs><linearGradient id="g" x1="9" y1="7" x2="55" y2="59" gradientUnits="userSpaceOnUse"><stop stop-color="#5aa7ff"/><stop offset="1" stop-color="#7c5cff"/></linearGradient><filter id="s" x="-20%" y="-20%" width="140%" height="140%"><feDropShadow dx="0" dy="6" stdDeviation="5" flood-color="#193b8f" flood-opacity=".35"/></filter></defs><rect width="64" height="64" rx="18" fill="#081226"/><path filter="url(#s)" d="M32 7 51 15v15c0 13-7.8 22.8-19 27-11.2-4.2-19-14-19-27V15L32 7Z" fill="url(#g)"/><path d="M24.4 36.7a7.5 7.5 0 0 1 0-10.6l4.1-4.1a7.5 7.5 0 0 1 10.6 0 2.8 2.8 0 0 1-4 4 1.9 1.9 0 0 0-2.7 0l-4.1 4.1a1.9 1.9 0 0 0 2.7 2.7 2.8 2.8 0 0 1 4 4 7.5 7.5 0 0 1-10.6-.1Z" fill="#f3f7ff"/><path d="M28.8 42a2.8 2.8 0 0 1 0-4 1.9 1.9 0 0 0 2.7 0l4.1-4.1a1.9 1.9 0 0 0-2.7-2.7 2.8 2.8 0 1 1-4-4 7.5 7.5 0 0 1 10.6 10.7L35.4 42a7.5 7.5 0 0 1-10.6 0Z" fill="#dbeafe" opacity=".95"/><path d="M27 32h10" stroke="#081226" stroke-width="4.2" stroke-linecap="round" opacity=".45"/></svg>"##;

#[derive(Deserialize)]
struct LocaleForm {
    locale: String,
    return_to: String,
}

fn safe_internal_return_to(value: &str) -> String {
    if !value.starts_with('/') || value.starts_with("//") || value.contains('\\') {
        return "/".to_string();
    }
    let Ok(uri) = value.parse::<Uri>() else {
        return "/".to_string();
    };
    if uri.scheme().is_some() || uri.authority().is_some() || uri.path() == "/locale" {
        return "/".to_string();
    }
    uri.path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string())
}

async fn set_locale(
    State(state): State<AppState>,
    Form(form): Form<LocaleForm>,
) -> Result<Response> {
    let locale = Locale::parse(&form.locale)
        .ok_or(AppError(StatusCode::BAD_REQUEST, "Ungültige Sprache"))?;
    let return_to = safe_internal_return_to(&form.return_to);
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000;{}",
        i18n::LOCALE_COOKIE,
        locale.code(),
        if state.config.security.secure_cookie {
            " Secure;"
        } else {
            ""
        }
    );
    let mut response = Redirect::to(&return_to).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(internal)?,
    );
    Ok(response)
}

fn locale_switcher() -> String {
    let locale = i18n::current_locale();
    let label = i18n::text(locale, i18n::LANGUAGE);
    let return_to = i18n::current_return_to();
    format!(
        r#"<form class="vl-locale-switch" method="post" action="/locale" aria-label="{}"><input type="hidden" name="return_to" value="{}"><button class="vl-locale-switch__option" name="locale" value="de" type="submit"{}>DE</button><span aria-hidden="true">/</span><button class="vl-locale-switch__option" name="locale" value="en" type="submit"{}>EN</button></form>"#,
        esc(label),
        esc(&return_to),
        if locale == Locale::De {
            r#" aria-current="true""#
        } else {
            ""
        },
        if locale == Locale::En {
            r#" aria-current="true""#
        } else {
            ""
        },
    )
}

fn plain_page(title: &str, body: &str) -> String {
    let locale = i18n::current_locale();
    let title = i18n::text_from_german(locale, title);
    let body = i18n::render_markers(locale, body);
    format!(
        r##"<!doctype html><html lang="{}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{} · VaultLink</title><link rel="icon" href="/assets/favicon.svg" type="image/svg+xml"><link rel="alternate icon" href="/assets/favicon-32.png" type="image/png"><link rel="stylesheet" href="/assets/vaultlink.css"><script src="/assets/app.js" defer></script></head><body class="vl-ui"><a class="vl-skip-link" href="#main-content">{}</a><div class="vl-public-shell"><header class="vl-public-header">{}{}</header><main id="main-content" class="vl-public-main">{}</main></div></body></html>"##,
        locale.code(),
        esc(&title),
        i18n::text(locale, i18n::SKIP_TO_CONTENT),
        crate::ui::brand_lockup(i18n::text(locale, i18n::BRAND_TAGLINE)),
        locale_switcher(),
        body
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NavSection {
    Files,
    Links,
    Admins,
    Settings,
    Audit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PageId {
    Account,
    Files,
    Preview,
    DeleteConfirm,
    Links,
    CreateLink,
    Admins,
    AdminCreated,
    MfaReset,
    Settings,
    AuditSecurity,
}

impl PageId {
    const fn title(self) -> MessageKey {
        match self {
            Self::Account => i18n::ACCOUNT,
            Self::Files => i18n::NAV_FILES,
            Self::Preview => i18n::TITLE_PREVIEW,
            Self::DeleteConfirm => i18n::TITLE_DELETE_CONFIRM,
            Self::Links => i18n::NAV_LINKS,
            Self::CreateLink => i18n::CREATE_LINK,
            Self::Admins => i18n::NAV_ADMINS,
            Self::AdminCreated => i18n::TITLE_ADMIN_CREATED,
            Self::MfaReset => i18n::TITLE_MFA_RESET,
            Self::Settings => i18n::NAV_SETTINGS,
            Self::AuditSecurity => i18n::TITLE_AUDIT_SECURITY,
        }
    }

    const fn nav(self) -> Option<NavSection> {
        match self {
            Self::Account => None,
            Self::Files | Self::Preview | Self::DeleteConfirm => Some(NavSection::Files),
            Self::Links | Self::CreateLink => Some(NavSection::Links),
            Self::Admins | Self::AdminCreated | Self::MfaReset => Some(NavSection::Admins),
            Self::Settings => Some(NavSection::Settings),
            Self::AuditSecurity => Some(NavSection::Audit),
        }
    }
}

fn admin_page(
    state: &AppState,
    page: PageId,
    body: &str,
    show_create_link: bool,
    csrf_token: &str,
) -> String {
    admin_page_with_locale_switcher(state, page, body, show_create_link, csrf_token, true)
}

fn admin_page_without_locale_switcher(
    state: &AppState,
    page: PageId,
    body: &str,
    show_create_link: bool,
    csrf_token: &str,
) -> String {
    admin_page_with_locale_switcher(state, page, body, show_create_link, csrf_token, false)
}

fn admin_page_with_locale_switcher(
    state: &AppState,
    page: PageId,
    body: &str,
    show_create_link: bool,
    csrf_token: &str,
    show_locale_switcher: bool,
) -> String {
    let locale = i18n::current_locale();
    let title = i18n::text(locale, page.title());
    let create_link = if show_create_link {
        format!(
            r#"<a class="vl-button" href="/admin/shares/new">{} {}</a>"#,
            crate::ui::icon(crate::ui::Icon::Link),
            i18n::text(locale, i18n::CREATE_LINK),
        )
    } else {
        String::new()
    };
    let active = page.nav();
    let nav = [
        crate::ui::nav_link(
            "/admin",
            i18n::text(locale, i18n::NAV_FILES),
            crate::ui::Icon::Folder,
            active == Some(NavSection::Files),
        ),
        crate::ui::nav_link(
            "/admin/shares",
            i18n::text(locale, i18n::NAV_LINKS),
            crate::ui::Icon::Link,
            active == Some(NavSection::Links),
        ),
        crate::ui::nav_link(
            "/admin/admins",
            i18n::text(locale, i18n::NAV_ADMINS),
            crate::ui::Icon::Users,
            active == Some(NavSection::Admins),
        ),
        crate::ui::nav_link(
            "/admin/settings",
            i18n::text(locale, i18n::NAV_SETTINGS),
            crate::ui::Icon::Settings,
            active == Some(NavSection::Settings),
        ),
        crate::ui::nav_link(
            "/admin/audit",
            i18n::text(locale, i18n::NAV_AUDIT),
            crate::ui::Icon::Audit,
            active == Some(NavSection::Audit),
        ),
    ]
    .join("");
    let body = i18n::render_markers(locale, body);
    let body = body.replacen("<h1>", "<h2>", usize::MAX);
    let body = body.replacen("</h1>", "</h2>", usize::MAX);
    let system_panel = i18n::render_markers(locale, &system_panel(state));
    let locale_switcher = if show_locale_switcher {
        locale_switcher()
    } else {
        String::new()
    };
    format!(
        r##"<!doctype html><html lang="{}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{} · VaultLink</title><link rel="icon" href="/assets/favicon.svg" type="image/svg+xml"><link rel="alternate icon" href="/assets/favicon-32.png" type="image/png"><link rel="stylesheet" href="/assets/vaultlink.css"><script src="/assets/app.js" defer></script></head><body class="vl-ui"><a class="vl-skip-link" href="#main-content">{}</a><div class="vl-app-shell"><aside class="vl-sidebar">{}<nav class="vl-nav" aria-label="{}">{}</nav><div class="vl-system-card"><strong><span aria-hidden="true">●</span> {}</strong><span>{}</span></div></aside><div class="vl-content"><header class="vl-topbar"><div><p class="vl-eyebrow">{}</p><h1>{}</h1></div><div class="vl-topbar-actions">{}{}<a class="vl-button vl-button--ghost" href="/admin/account">{} {}</a><form method="post" action="/logout"><input type="hidden" name="csrf" value="{}"><button class="vl-button vl-button--secondary">{} {}</button></form></div></header><main id="main-content" class="vl-main">{}</main></div></div></body></html>"##,
        locale.code(),
        esc(title),
        i18n::text(locale, i18n::SKIP_TO_CONTENT),
        crate::ui::brand_lockup(i18n::text(locale, i18n::BRAND_TAGLINE)),
        i18n::text(locale, i18n::MAIN_NAVIGATION),
        nav,
        i18n::text(locale, i18n::VAULTLINK_AVAILABLE),
        system_panel,
        i18n::text(locale, i18n::VAULTLINK_ADMIN),
        esc(title),
        create_link,
        locale_switcher,
        crate::ui::icon(crate::ui::Icon::User),
        i18n::text(locale, i18n::ACCOUNT_LINK),
        esc(csrf_token),
        crate::ui::icon(crate::ui::Icon::Logout),
        i18n::text(locale, i18n::LOG_OUT),
        body
    )
}

fn system_panel(state: &AppState) -> String {
    let disk = disk_stats(state.secure_root.display_root())
        .map(|d| {
            format!(
                r#"<vl-i18n key="audit.storage"/>: {} <vl-i18n key="common.free"/> / {}"#,
                human(d.free),
                human(d.total)
            )
        })
        .unwrap_or_else(|| r#"<vl-i18n key="audit.storage"/>: n/a"#.to_string());
    format!(
        "{}<br>URL: {}<br><vl-i18n key=\"audit.server_mode\"/>: {:?}",
        disk,
        esc(&runtime_settings(state).public_base_url),
        state.config.server.mode
    )
}

struct DiskStats {
    free: u64,
    total: u64,
}

fn disk_stats(path: &Path) -> Option<DiskStats> {
    #[cfg(unix)]
    {
        disk_stats_unix(path)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

#[cfg(unix)]
fn disk_stats_unix(path: &Path) -> Option<DiskStats> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let stat = rustix::fs::statvfs(&canonical).ok()?;
    let block_size = stat.f_bsize;
    Some(DiskStats {
        free: stat.f_bavail.saturating_mul(block_size),
        total: stat.f_blocks.saturating_mul(block_size),
    })
}

fn storage_has_room(path: &Path, needed: u64) -> bool {
    disk_stats(path).is_none_or(|stats| {
        stats
            .free
            .saturating_sub(STORAGE_RESERVE_BYTES)
            .saturating_sub(needed)
            > 0
    })
}

fn storage_full_error(error: &std::io::Error) -> bool {
    const ENOSPC: i32 = 28;
    const EDQUOT: i32 = 122;
    error.kind() == std::io::ErrorKind::StorageFull
        || matches!(error.raw_os_error(), Some(ENOSPC | EDQUOT | 112))
}

struct PublicTransferLease {
    lease_token: Option<String>,
    cookie: String,
    heartbeat_stop: Option<tokio::sync::oneshot::Sender<()>>,
    database: Database,
    client_ip: Option<String>,
}

impl PublicTransferLease {
    fn into_stream_parts(
        mut self,
    ) -> (
        String,
        Option<tokio::sync::oneshot::Sender<()>>,
        Option<String>,
    ) {
        let lease_token = self
            .lease_token
            .take()
            .expect("public transfer lease token");
        let heartbeat_stop = self.heartbeat_stop.take();
        let client_ip = self.client_ip.take();
        (lease_token, heartbeat_stop, client_ip)
    }
}

impl Drop for PublicTransferLease {
    fn drop(&mut self) {
        self.heartbeat_stop.take();
        if let Some(lease_token) = self.lease_token.take() {
            spawn_transfer_cancel(self.database.clone(), lease_token);
        }
    }
}

fn start_transfer_heartbeat(
    database: Database,
    lease_token: String,
) -> Option<tokio::sync::oneshot::Sender<()>> {
    let handle = tokio::runtime::Handle::try_current().ok()?;
    let (stop_sender, mut stop_receiver) = tokio::sync::oneshot::channel();
    handle.spawn(async move {
        let heartbeat_interval = std::time::Duration::from_secs(
            (crate::db::TRANSFER_SESSION_TTL_SECONDS / 3) as u64,
        );
        let mut ticker = tokio::time::interval(heartbeat_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = &mut stop_receiver => break,
                _ = ticker.tick() => {
                    let heartbeat_database = database.clone();
                    let heartbeat_token = lease_token.clone();
                    match tokio::task::spawn_blocking(move || {
                        heartbeat_database.heartbeat_transfer_lease(&heartbeat_token)
                    }).await {
                        Ok(Ok(crate::db::TransferLeaseHeartbeatOutcome::Extended)) => {}
                        Ok(Ok(crate::db::TransferLeaseHeartbeatOutcome::NotFound)) => {
                            tracing::warn!("public transfer lease disappeared while the response was active");
                            break;
                        }
                        Ok(Err(error)) => {
                            tracing::warn!(%error, "could not heartbeat public transfer lease");
                        }
                        Err(error) => {
                            tracing::warn!(%error, "public transfer heartbeat task failed");
                            break;
                        }
                    }
                }
            }
        }
    });
    Some(stop_sender)
}

fn transfer_scope(uri: &Uri) -> TransferCookieScope {
    if uri.path().starts_with("/api/v1/") {
        TransferCookieScope::Api
    } else {
        TransferCookieScope::Web
    }
}

fn public_share_route(uri: &Uri, token: &str) -> String {
    if uri.path().starts_with("/api/v1/") {
        format!("/api/v1/public/shares/{token}")
    } else {
        format!("/v/{token}")
    }
}

async fn begin_public_transfer(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    share: &Share,
    resource_key: String,
    action: &'static str,
) -> Result<PublicTransferLease> {
    let session_token = transfer_cookie(headers, share.id)
        .map(str::to_string)
        .unwrap_or_else(|| auth::random_token(32));
    let lease_token = auth::random_token(32);
    let session_for_db = session_token.clone();
    let lease_for_db = lease_token.clone();
    let share_id = share.id;
    let outcome = database(state.db.clone(), move |database| {
        database.begin_transfer_lease(
            &session_for_db,
            &lease_for_db,
            share_id,
            &resource_key,
            action,
        )
    })
    .await?;
    match outcome {
        TransferLeaseBeginOutcome::NewLease | TransferLeaseBeginOutcome::AlreadyCounted => {
            Ok(PublicTransferLease {
                heartbeat_stop: start_transfer_heartbeat(state.db.clone(), lease_token.clone()),
                lease_token: Some(lease_token),
                cookie: make_transfer_cookie(state, share, &session_token, transfer_scope(uri)),
                database: state.db.clone(),
                client_ip: runtime_settings(state)
                    .audit_client_ip_enabled
                    .then(current_audit_client_ip)
                    .flatten()
                    .map(|ip| ip.to_string()),
            })
        }
        TransferLeaseBeginOutcome::LimitReached => {
            Err(AppError(StatusCode::GONE, "Übertragungslimit erreicht"))
        }
        TransferLeaseBeginOutcome::ShareUnavailable => {
            Err(AppError(StatusCode::GONE, "Freigabe nicht verfügbar"))
        }
    }
}

async fn check_public_transfer_availability(
    state: &AppState,
    headers: &HeaderMap,
    share: &Share,
    resource_key: String,
    action: &'static str,
) -> Result<()> {
    let session_token = transfer_cookie(headers, share.id)
        .map(str::to_string)
        .unwrap_or_else(|| auth::random_token(32));
    let share_id = share.id;
    let outcome = database(state.db.clone(), move |database| {
        database.check_transfer_availability(&session_token, share_id, &resource_key, action)
    })
    .await?;
    match outcome {
        TransferAvailabilityOutcome::Available | TransferAvailabilityOutcome::AlreadyCounted => {
            Ok(())
        }
        TransferAvailabilityOutcome::LimitReached => {
            Err(AppError(StatusCode::GONE, "Übertragungslimit erreicht"))
        }
        TransferAvailabilityOutcome::ShareUnavailable => {
            Err(AppError(StatusCode::GONE, "Freigabe nicht verfügbar"))
        }
    }
}

fn transfer_complete_future(
    database: Database,
    runtime: Arc<RwLock<RuntimeSettings>>,
    lease_token: String,
    action: &'static str,
    share_id: i64,
    client_ip: Option<String>,
) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send>> {
    Box::pin(async move {
        let client_ip = runtime
            .read()
            .ok()
            .is_some_and(|settings| settings.audit_client_ip_enabled)
            .then_some(client_ip)
            .flatten();
        let result = tokio::task::spawn_blocking(move || {
            let outcome = database.complete_transfer_lease(&lease_token)?;
            let audit_failed = outcome == TransferLeaseCompleteOutcome::Counted
                && database
                    .audit_with_client_ip(
                        "public",
                        action,
                        Some(&share_id.to_string()),
                        Some("completed transfer session"),
                        client_ip.as_deref(),
                    )
                    .is_err();
            Ok::<_, rusqlite::Error>(audit_failed)
        })
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
        match result {
            Ok(true) => tracing::warn!(share_id, action, "could not audit completed transfer"),
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(share_id, action, %error, "could not finalize public transfer lease");
                return Err(io::Error::other(error.to_string()));
            }
        }
        Ok(())
    })
}

fn spawn_transfer_cancel(database: Database, lease_token: String) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn(async move {
        let _ =
            tokio::task::spawn_blocking(move || database.cancel_transfer_lease(&lease_token)).await;
    });
}

struct TransferBodyStream {
    inner: Pin<Box<dyn Stream<Item = io::Result<Bytes>> + Send>>,
    database: Database,
    runtime: Arc<RwLock<RuntimeSettings>>,
    lease_token: Option<String>,
    client_ip: Option<String>,
    action: &'static str,
    share_id: i64,
    heartbeat_stop: Option<tokio::sync::oneshot::Sender<()>>,
    finalize: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>,
    remaining_bytes: Option<u64>,
    pending_final_chunk: Option<Bytes>,
}

impl Stream for TransferBodyStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(finalize) = self.finalize.as_mut() {
                return match finalize.as_mut().poll(context) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Ok(())) => {
                        self.finalize.take();
                        match self.pending_final_chunk.take() {
                            Some(chunk) => Poll::Ready(Some(Ok(chunk))),
                            None => Poll::Ready(None),
                        }
                    }
                    Poll::Ready(Err(error)) => {
                        self.finalize.take();
                        Poll::Ready(Some(Err(error)))
                    }
                };
            }
            match self.inner.as_mut().poll_next(context) {
                Poll::Ready(None) => {
                    if self.remaining_bytes.is_some_and(|remaining| remaining > 0) {
                        self.heartbeat_stop.take();
                        if let Some(token) = self.lease_token.take() {
                            spawn_transfer_cancel(self.database.clone(), token);
                        }
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "transfer source ended before Content-Length",
                        ))));
                    }
                    self.heartbeat_stop.take();
                    if let Some(token) = self.lease_token.take() {
                        self.finalize = Some(transfer_complete_future(
                            self.database.clone(),
                            self.runtime.clone(),
                            token,
                            self.action,
                            self.share_id,
                            self.client_ip.take(),
                        ));
                        continue;
                    }
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Err(error))) => {
                    self.heartbeat_stop.take();
                    if let Some(token) = self.lease_token.take() {
                        spawn_transfer_cancel(self.database.clone(), token);
                    }
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(Some(Ok(chunk))) => {
                    if let Some(remaining) = self.remaining_bytes {
                        let chunk_length = chunk.len() as u64;
                        if chunk_length > remaining {
                            self.heartbeat_stop.take();
                            if let Some(token) = self.lease_token.take() {
                                spawn_transfer_cancel(self.database.clone(), token);
                            }
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "transfer source exceeded Content-Length",
                            ))));
                        }
                        let remaining = remaining - chunk_length;
                        self.remaining_bytes = Some(remaining);
                        if remaining == 0 {
                            self.heartbeat_stop.take();
                            if let Some(token) = self.lease_token.take() {
                                self.pending_final_chunk = Some(chunk);
                                self.finalize = Some(transfer_complete_future(
                                    self.database.clone(),
                                    self.runtime.clone(),
                                    token,
                                    self.action,
                                    self.share_id,
                                    self.client_ip.take(),
                                ));
                                continue;
                            }
                        }
                    }
                    return Poll::Ready(Some(Ok(chunk)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Drop for TransferBodyStream {
    fn drop(&mut self) {
        self.heartbeat_stop.take();
        if let Some(token) = self.lease_token.take() {
            spawn_transfer_cancel(self.database.clone(), token);
        }
    }
}

fn transfer_body<S>(
    stream: S,
    state: &AppState,
    transfer: PublicTransferLease,
    action: &'static str,
    share_id: i64,
    expected_bytes: Option<u64>,
) -> Body
where
    S: Stream<Item = io::Result<Bytes>> + Send + 'static,
{
    let (lease_token, heartbeat_stop, client_ip) = transfer.into_stream_parts();
    Body::from_stream(TransferBodyStream {
        inner: Box::pin(stream),
        database: state.db.clone(),
        runtime: state.runtime.clone(),
        lease_token: Some(lease_token),
        client_ip,
        action,
        share_id,
        heartbeat_stop,
        finalize: None,
        remaining_bytes: expected_bytes,
        pending_final_chunk: None,
    })
}

async fn complete_transfer_without_body(
    state: &AppState,
    transfer: PublicTransferLease,
    action: &'static str,
    share_id: i64,
) -> Result<()> {
    let (lease_token, heartbeat_stop, client_ip) = transfer.into_stream_parts();
    drop(heartbeat_stop);
    transfer_complete_future(
        state.db.clone(),
        state.runtime.clone(),
        lease_token,
        action,
        share_id,
        client_ip,
    )
    .await
    .map_err(internal)
}

fn set_transfer_cookie(response: &mut Response, cookie: &str) -> Result<()> {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(cookie).map_err(internal)?,
    );
    Ok(())
}

fn upload_io_error(error: std::io::Error) -> AppError {
    if storage_full_error(&error) {
        AppError(
            StatusCode::INSUFFICIENT_STORAGE,
            "Nicht genug freier Speicher",
        )
    } else {
        internal(error)
    }
}

enum PendingUploadFileError {
    Begin,
    Take(std::io::Error),
}

async fn limited_multipart_text(
    mut field: axum::extract::multipart::Field<'_>,
    maximum: usize,
) -> std::result::Result<String, ()> {
    let mut value = Vec::new();
    while let Some(chunk) = field.chunk().await.map_err(|_| ())? {
        if value
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > maximum)
        {
            return Err(());
        }
        value.extend_from_slice(&chunk);
    }
    String::from_utf8(value).map_err(|_| ())
}

fn public_upload_error(
    token: &str,
    upload_subdir: &str,
    status: StatusCode,
    message: &str,
) -> Response {
    let message = i18n::text_from_german(i18n::current_locale(), message);
    let back = if upload_subdir.is_empty() {
        format!("/v/{token}")
    } else {
        format!("/v/{token}?path={}", encoded(upload_subdir))
    };
    (
        status,
        Html(plain_page(
            "Fehler",
            &format!(
            r#"<section><h1><vl-i18n key="common.error"/></h1><p>{}</p><p><a class="button secondary" href="{}"><vl-i18n key="share.back"/></a></p></section>"#,
                esc(&message),
                esc(&back)
            ),
        )),
    )
        .into_response()
}

fn format_audit_time(value: &str) -> String {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| {
            let utc = dt.with_timezone(&Utc);
            match i18n::current_locale() {
                Locale::De => utc.format("%d.%m.%Y %H:%M:%S").to_string(),
                Locale::En => utc.format("%Y-%m-%d %H:%M:%S").to_string(),
            }
        })
        .unwrap_or_else(|_| value.to_string())
}

fn format_file_time(value: std::time::SystemTime) -> String {
    format_utc_minute(DateTime::<Utc>::from(value))
}

fn format_utc_minute(value: DateTime<Utc>) -> String {
    match i18n::current_locale() {
        Locale::De => value.format("%d.%m.%Y %H:%M UTC").to_string(),
        Locale::En => value.format("%Y-%m-%d %H:%M UTC").to_string(),
    }
}

fn format_public_date(value: DateTime<Utc>) -> String {
    match i18n::current_locale() {
        Locale::De => value.format("%d.%m.%Y").to_string(),
        Locale::En => value.format("%Y-%m-%d").to_string(),
    }
}

fn internal<T>(_: T) -> AppError {
    AppError(StatusCode::INTERNAL_SERVER_ERROR, "Interner Fehler")
}
async fn login_page() -> Html<String> {
    Html(plain_page(
        "Login",
        r#"<section><h1><vl-i18n key="auth.admin_login"/></h1><form method="post"><label><vl-i18n key="auth.username"/><br><input name="username" autocomplete="username" required></label><label><vl-i18n key="auth.password"/><br><input name="password" type="password" autocomplete="current-password" required></label><button><vl-i18n key="auth.sign_in"/></button></form></section>"#,
    ))
}
#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}
async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Result<Response> {
    let ip = proxy::effective_client_ip(peer.ip(), &headers, &state.config);
    let key = format!("{}:{}", ip, form.username.to_lowercase());
    let ip_key = format!("ip:{ip}");
    if !state.limiter.allowed(&key) || !state.limiter.allowed(&ip_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele Anmeldeversuche",
        ));
    }
    let username = form.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username)).await?;
    let expected_password_hash = admin.as_ref().map(|admin| admin.password_hash.clone());
    let verification_hash = expected_password_hash.clone();
    let password = form.password;
    let valid = tokio::task::spawn_blocking(move || match verification_hash {
        Some(hash) => auth::verify_password(&hash, &password),
        None => {
            let _ = auth::hash_password(&password);
            false
        }
    })
    .await
    .map_err(internal)?;
    if !valid {
        state.limiter.failure(&key);
        state.limiter.failure(&ip_key);
        audit(&state, form.username, "login_failed", None, None).await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    let a = admin.unwrap();
    let token = auth::random_token(32);
    let csrf = auth::random_token(24);
    let session_token = token.clone();
    let session_csrf = csrf.clone();
    let expires = Utc::now() + Duration::hours(state.config.security.session_hours);
    let admin_id = a.id;
    let expected_password_hash = expected_password_hash.expect("valid password requires a hash");
    let outcome = database(state.db.clone(), move |db| {
        db.create_session_for_verified_password(
            &session_token,
            admin_id,
            &expected_password_hash,
            &session_csrf,
            expires,
        )
    })
    .await?;
    if outcome != PasswordSessionCreationOutcome::Created {
        state.limiter.failure(&key);
        state.limiter.failure(&ip_key);
        audit(&state, form.username, "login_failed", None, None).await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    state.limiter.success(&key);
    state.limiter.success(&ip_key);
    audit(&state, a.username, "password_verified", None, None).await;
    Ok(redirect_with_cookie(
        "/mfa",
        make_session_cookie(&state, &token),
    )?)
}
async fn mfa_page(State(state): State<AppState>, headers: HeaderMap) -> Result<Html<String>> {
    let (_, current_session) =
        session(&state, &headers, false, MissingSession::RedirectToLogin).await?;
    let admin_id = current_session.admin_id;
    let security_key_count = database(state.db.clone(), move |db| {
        db.admin_webauthn_credentials(admin_id)
            .map(|credentials| credentials.len())
    })
    .await?;
    let security_key_button = if security_key_count >= 2 {
        r#"<hr><button type="button" data-security-key-login><vl-i18n key="auth.security_key_use"/></button><p class="vl-muted" data-security-key-status></p>"#
    } else {
        ""
    };
    Ok(Html(plain_page(
        "MFA",
        &format!(
            r#"<section><h1><vl-i18n key="auth.second_factor"/></h1><form method="post"><label><vl-i18n key="auth.six_digit_totp"/><br><input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{{6}}" required></label><button><vl-i18n key="auth.verify"/></button></form>{security_key_button}</section>"#
        ),
    )))
}
#[derive(Deserialize)]
struct MfaForm {
    code: String,
}
async fn mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<MfaForm>,
) -> Result<Redirect> {
    let (token, s) = session(&state, &headers, false, MissingSession::RedirectToLogin).await?;
    let key = format!("mfa:{}", s.username.to_lowercase());
    if !state.limiter.allowed(&key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele MFA-Versuche",
        ));
    }
    let username = s.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username))
        .await?
        .ok_or_else(|| internal(()))?;
    if !auth::verify_totp_now(&admin.totp_secret, &form.code) {
        state.limiter.failure(&key);
        audit(&state, s.username, "mfa_failed", None, None).await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültiger MFA-Code"));
    }
    state.limiter.success(&key);
    database(state.db.clone(), move |db| db.verify_mfa(&token)).await?;
    audit(&state, s.username, "login_success", None, None).await;
    Ok(Redirect::to("/admin"))
}

fn decode_security_keys(
    rows: &[crate::db::AdminWebauthnCredential],
) -> Result<Vec<webauthn_rs::prelude::SecurityKey>> {
    rows.iter()
        .map(|row| serde_json::from_str(&row.credential_json).map_err(internal))
        .collect()
}

async fn start_security_key_authentication(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<webauthn_rs::prelude::RequestChallengeResponse>> {
    let (token, session) =
        session(&state, &headers, false, MissingSession::RedirectToLogin).await?;
    if session.mfa_verified {
        return Err(AppError(
            StatusCode::CONFLICT,
            "MFA wurde bereits bestätigt",
        ));
    }
    let admin_id = session.admin_id;
    let rows = database(state.db.clone(), move |db| {
        db.admin_webauthn_credentials(admin_id)
    })
    .await?;
    if rows.len() < 2 {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Kein Sicherheitsschlüssel registriert",
        ));
    }
    let keys = decode_security_keys(&rows)?;
    let challenge = state
        .webauthn
        .start_authentication(&token, admin_id, &keys)
        .map_err(|_| {
            AppError(
                StatusCode::BAD_REQUEST,
                "Sicherheitsschlüssel konnte nicht gestartet werden",
            )
        })?;
    Ok(Json(challenge))
}

#[derive(Deserialize)]
struct SecurityKeyAuthenticationFinish {
    credential: webauthn_rs::prelude::PublicKeyCredential,
}

async fn finish_security_key_authentication(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SecurityKeyAuthenticationFinish>,
) -> Result<Json<serde_json::Value>> {
    let (token, session) =
        session(&state, &headers, false, MissingSession::RedirectToLogin).await?;
    if session.mfa_verified {
        return Err(AppError(
            StatusCode::CONFLICT,
            "MFA wurde bereits bestätigt",
        ));
    }
    let admin_id = session.admin_id;
    let rows = database(state.db.clone(), move |db| {
        db.admin_webauthn_credentials(admin_id)
    })
    .await?;
    let mut keys = decode_security_keys(&rows)?;
    let index = state
        .webauthn
        .finish_authentication(&token, admin_id, &body.credential, &mut keys)
        .map_err(|_| AppError(StatusCode::UNAUTHORIZED, "Ungültiger Sicherheitsschlüssel"))?;
    let row = rows.get(index).ok_or_else(|| internal(()))?;
    let credential_id = row.id;
    let expected_credential_json = row.credential_json.clone();
    let credential_json = serde_json::to_string(&keys[index]).map_err(internal)?;
    let completed = database(state.db.clone(), move |db| {
        db.complete_webauthn_mfa(
            &token,
            credential_id,
            admin_id,
            &expected_credential_json,
            &credential_json,
        )
    })
    .await?;
    if !completed {
        return Err(AppError(
            StatusCode::CONFLICT,
            "Sicherheitsschlüssel wurde gleichzeitig geändert",
        ));
    }
    audit(
        &state,
        session.username,
        "login_success_webauthn",
        None,
        None,
    )
    .await;
    Ok(Json(serde_json::json!({"redirect":"/admin"})))
}
#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
}
async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    let (token, s) = session(&state, &headers, false, MissingSession::RedirectToLogin).await?;
    csrf(&s, &form.csrf)?;
    database(state.db.clone(), move |db| db.delete_session(&token)).await?;
    audit(&state, s.username, "logout", None, None).await;
    Ok(redirect_with_cookie(
        "/login",
        clear_session_cookie(&state),
    )?)
}

#[derive(Default, Deserialize)]
pub(crate) struct BrowseQuery {
    path: Option<String>,
    page: Option<usize>,
    q: Option<String>,
    upload: Option<String>,
    notice: Option<String>,
}

#[derive(Deserialize)]
struct CreateDirectoryForm {
    csrf: String,
    parent: String,
    name: String,
}

#[derive(Deserialize)]
struct RenameFileForm {
    csrf: String,
    path: String,
    name: String,
}

#[derive(Deserialize)]
struct DeleteFileQuery {
    path: String,
}

#[derive(Deserialize)]
struct DeleteFileForm {
    csrf: String,
    path: String,
    confirm_name: Option<String>,
}

async fn create_directory_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateDirectoryForm>,
) -> Result<Redirect> {
    let (_, admin) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&admin, &form.csrf)?;
    let result = file_ops::create_directory(&state, &form.parent, &form.name)
        .await
        .map_err(file_operation_app_error)?;
    audit(
        &state,
        admin.username,
        "directory_created",
        Some(result.path),
        None,
    )
    .await;
    Ok(Redirect::to(&browser_redirect(
        &form.parent,
        "directory_created",
    )))
}

async fn rename_file_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RenameFileForm>,
) -> Result<Redirect> {
    let (_, admin) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&admin, &form.csrf)?;
    let old_path = form.path.clone();
    let parent = parent_path(&form.path).unwrap_or_default();
    let result = file_ops::rename(&state, &form.path, &form.name)
        .await
        .map_err(file_operation_app_error)?;
    audit(
        &state,
        admin.username,
        "path_renamed",
        Some(result.path),
        Some(format!(
            "old_path={old_path};updated_shares={}",
            result.updated_shares
        )),
    )
    .await;
    Ok(Redirect::to(&browser_redirect(&parent, "path_renamed")))
}

async fn delete_file_confirmation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DeleteFileQuery>,
) -> Result<Html<String>> {
    let (_, admin) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let inspection = file_ops::inspect_delete(&state, &query.path)
        .await
        .map_err(file_operation_app_error)?;
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
    let (confirmation, form_attributes, button_attributes) = if inspection
        .status
        .directory_non_empty
    {
        (
            format!(
                r#"<div class="form-card"><p class="bad"><strong><vl-i18n key="common.warning"/></strong> <vl-i18n key="files.folder_not_empty"/></p><label><vl-i18n key="files.confirm_folder_name"/> <code>{}</code> <vl-i18n key="files.enter"/><input name="confirm_name" autocomplete="off" data-confirm-input autofocus required></label></div>"#,
                esc(&inspection.name)
            ),
            format!(
                r#" data-delete-confirmation data-required-name="{}""#,
                esc(&inspection.name)
            ),
            " data-confirm-delete disabled",
        )
    } else {
        (String::new(), String::new(), "")
    };
    let body = format!(
        r#"<section><h1>{}</h1><p><code>/{}</code></p><p class="bad"><vl-i18n key="files.delete_irreversible"/></p><p><vl-i18n key="files.affected_shares"/> <strong>{}</strong></p><form method="post" action="/admin/files/delete"{form_attributes}><input type="hidden" name="csrf" value="{}"><input type="hidden" name="path" value="{}">{}<div class="actions"><button class="danger"{button_attributes}><vl-i18n key="files.permanent_delete"/></button><a class="button secondary" href="/admin?path={}"><vl-i18n key="common.cancel"/></a></div></form></section>"#,
        esc(&heading),
        esc(&inspection.path),
        inspection.affected_shares,
        esc(&admin.csrf_token),
        esc(&inspection.path),
        confirmation,
        encoded(parent_path(&inspection.path).as_deref().unwrap_or("")),
    );
    Ok(Html(admin_page(
        &state,
        PageId::DeleteConfirm,
        &body,
        false,
        &admin.csrf_token,
    )))
}

async fn delete_file_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeleteFileForm>,
) -> Result<Redirect> {
    let (_, admin) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&admin, &form.csrf)?;
    let parent = parent_path(&form.path).unwrap_or_default();
    let result = file_ops::delete(&state, &form.path, form.confirm_name.as_deref())
        .await
        .map_err(file_operation_app_error)?;
    let notice = if result.cleanup_pending {
        "path_delete_queued"
    } else {
        "path_deleted"
    };
    audit(
        &state,
        admin.username,
        "path_deleted",
        Some(result.path),
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
    Ok(Redirect::to(&browser_redirect(&parent, notice)))
}

struct AdminUploadSuccess {
    file: String,
    outcome: String,
    directory: String,
}

async fn stage_admin_upload(
    state: &AppState,
    directory: &str,
    field: axum::extract::multipart::Field<'_>,
    maximum: u64,
    blocked_extensions: &[String],
) -> Result<(PendingUpload, String, u64)> {
    let file_name = field
        .file_name()
        .ok_or(AppError(StatusCode::BAD_REQUEST, "Dateiname fehlt"))?;
    let name = path_security::safe_filename(file_name)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Dateiname"))?
        .to_string();
    if crate::secure_fs::is_upload_fragment_name(std::ffi::OsStr::new(&name)) {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Dateiname ist für interne Uploadfragmente reserviert",
        ));
    }
    if extension_is_blocked(&name, blocked_extensions) {
        return Err(AppError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Dateityp blockiert",
        ));
    }

    let secure_root = state.secure_root.clone();
    let upload_directory = directory.to_string();
    let pending_file = tokio::task::spawn_blocking(move || {
        let mut pending = secure_root
            .begin_upload(&upload_directory)
            .map_err(|_| PendingUploadFileError::Begin)?;
        let file = pending.take_file().map_err(PendingUploadFileError::Take)?;
        Ok::<_, PendingUploadFileError>((pending, file))
    })
    .await
    .map_err(internal)?;
    let (pending, file) = match pending_file {
        Ok(value) => value,
        Err(PendingUploadFileError::Begin) => {
            return Err(AppError(
                StatusCode::NOT_FOUND,
                "Zielordner nicht verfügbar",
            ))
        }
        Err(PendingUploadFileError::Take(error)) => return Err(upload_io_error(error)),
    };

    let mut output = tokio::fs::File::from_std(file);
    let mut total = 0u64;
    let stream = field;
    tokio::pin!(stream);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| AppError(StatusCode::BAD_REQUEST, "Upload abgebrochen"))?;
        let Some(new_total) = add_upload_bytes(total, chunk.len(), maximum) else {
            return Err(AppError(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Upload ist zu groß",
            ));
        };
        if !storage_has_room(state.secure_root.display_root(), chunk.len() as u64) {
            return Err(AppError(
                StatusCode::INSUFFICIENT_STORAGE,
                "Nicht genug freier Speicher",
            ));
        }
        total = new_total;
        output.write_all(&chunk).await.map_err(upload_io_error)?;
    }
    output.flush().await.map_err(upload_io_error)?;
    output.sync_all().await.map_err(upload_io_error)?;
    drop(output);
    Ok((pending, name, total))
}

async fn process_admin_upload(
    state: &AppState,
    headers: &HeaderMap,
    mut multipart: Multipart,
) -> Result<AdminUploadSuccess> {
    let (_, admin) = session(state, headers, true, MissingSession::RedirectToLogin).await?;
    let settings = runtime_settings(state);
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| !storage_has_room(state.secure_root.display_root(), length))
    {
        return Err(AppError(
            StatusCode::INSUFFICIENT_STORAGE,
            "Nicht genug freier Speicher",
        ));
    }

    let mut directory: Option<String> = None;
    let mut csrf_value: Option<String> = None;
    let mut overwrite_existing = false;
    let mut saw_overwrite = false;
    let mut staged: Option<(PendingUpload, String, u64)> = None;
    let mut fields_seen = 0usize;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Upload"))?
    {
        fields_seen += 1;
        if fields_seen > 5 {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "Zu viele Multipart-Felder",
            ));
        }
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "path" => {
                if directory.is_some() || staged.is_some() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "Uploadpfad wurde mehrfach oder zu spät übermittelt",
                    ));
                }
                let value = limited_multipart_text(field, MAX_UPLOAD_PATH_FIELD_BYTES)
                    .await
                    .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Uploadpfad"))?;
                let value = path_security::validate_relative(&value)
                    .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Uploadpfad"))?
                    .to_string_lossy()
                    .replace('\\', "/");
                directory = Some(value);
            }
            "csrf" => {
                if csrf_value.is_some() || staged.is_some() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "CSRF-Nachweis wurde mehrfach oder zu spät übermittelt",
                    ));
                }
                let value = limited_multipart_text(field, 512)
                    .await
                    .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger CSRF-Nachweis"))?;
                csrf(&admin, &value)?;
                csrf_value = Some(value);
            }
            "overwrite_existing" => {
                if std::mem::replace(&mut saw_overwrite, true) || staged.is_some() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "Uploadoption wurde mehrfach oder zu spät übermittelt",
                    ));
                }
                let value = limited_multipart_text(field, MAX_UPLOAD_OPTION_FIELD_BYTES)
                    .await
                    .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültige Uploadoption"))?;
                overwrite_existing = value == "1";
            }
            "file" => {
                if staged.is_some() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "Pro Request ist genau eine Datei erlaubt",
                    ));
                }
                let target = directory.as_deref().ok_or(AppError(
                    StatusCode::BAD_REQUEST,
                    "Uploadpfad muss vor der Datei übermittelt werden",
                ))?;
                if csrf_value.is_none() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "CSRF-Nachweis muss vor der Datei übermittelt werden",
                    ));
                }
                staged = Some(
                    stage_admin_upload(
                        state,
                        target,
                        field,
                        settings.max_upload_size,
                        &settings.blocked_extensions,
                    )
                    .await?,
                );
            }
            _ => {
                return Err(AppError(
                    StatusCode::BAD_REQUEST,
                    "Unbekanntes Multipart-Feld",
                ))
            }
        }
    }

    let directory = directory.ok_or(AppError(StatusCode::BAD_REQUEST, "Uploadpfad fehlt"))?;
    if csrf_value.is_none() {
        return Err(AppError(StatusCode::FORBIDDEN, "CSRF-Nachweis fehlt"));
    }
    let (mut pending, name, total) = staged.ok_or(AppError(
        StatusCode::BAD_REQUEST,
        "Pro Request ist genau eine Datei erforderlich",
    ))?;
    let destination = join_display(&directory, &name);
    let publish_name = name.clone();
    #[cfg(test)]
    if let Some(kind) = state
        .upload_directory_sync_failure
        .lock()
        .expect("upload sync fault lock")
        .take()
    {
        pending.fail_next_directory_sync(kind);
    }
    let _storage_guard = state.storage_mutation.lock().await;
    let existed = match state.secure_root.metadata(&destination) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(internal(error)),
    };
    let publish_result = tokio::task::spawn_blocking(move || {
        if overwrite_existing {
            pending.publish_replace(&publish_name)
        } else {
            pending.publish(&publish_name)
        }
    })
    .await
    .map_err(internal)?;
    let publish_outcome = match publish_result {
        Ok(outcome) => outcome,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(AppError(
                StatusCode::CONFLICT,
                "Datei existiert bereits; Ersetzen muss für diese Datei bestätigt werden",
            ))
        }
        Err(error) => return Err(upload_io_error(error)),
    };
    let replaced = overwrite_existing && existed;
    let durability_uncertain = !publish_outcome.is_durable();
    let detail = format!("file={name};bytes={total};path={destination}");
    if let Some(error) = publish_outcome.sync_error() {
        tracing::warn!(file = %name, %error, "admin upload published but directory fsync failed");
        audit(
            state,
            admin.username.clone(),
            "admin_upload_durability_uncertain",
            Some(destination.clone()),
            Some(detail.clone()),
        )
        .await;
    }
    audit(
        state,
        admin.username,
        if replaced {
            "admin_upload_replaced"
        } else {
            "admin_upload"
        },
        Some(destination),
        Some(detail),
    )
    .await;
    let outcome = match (replaced, durability_uncertain) {
        (true, true) => "replaced_uncertain",
        (false, true) => "created_uncertain",
        (true, false) => "replaced",
        (false, false) => "created",
    };
    Ok(AdminUploadSuccess {
        file: name,
        outcome: outcome.to_string(),
        directory,
    })
}

async fn admin_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Result<Response> {
    let success = process_admin_upload(&state, &headers, multipart).await?;
    let mut response =
        Redirect::to(&browser_redirect(&success.directory, "upload_ok")).into_response();
    response.headers_mut().insert(
        "x-vaultlink-upload-file",
        HeaderValue::from_str(&encoded(&success.file)).map_err(internal)?,
    );
    response.headers_mut().insert(
        "x-vaultlink-upload-outcome",
        HeaderValue::from_str(&success.outcome).map_err(internal)?,
    );
    Ok(response)
}

async fn admin_upload_queue(
    State(state): State<AppState>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Response {
    match process_admin_upload(&state, &headers, multipart).await {
        Ok(success) => Json(UploadQueueSuccess {
            file: success.file,
            outcome: success.outcome,
        })
        .into_response(),
        Err(AppError(status, message)) => upload_queue_error_response(status, message),
    }
}

fn browser_redirect(path: &str, notice: &str) -> String {
    format!("/admin?path={}&notice={notice}", encoded(path))
}

fn file_operation_app_error(error: file_ops::FileOperationError) -> AppError {
    use file_ops::FileOperationError;
    match error {
        FileOperationError::InvalidPath => AppError(StatusCode::BAD_REQUEST, "Ungültiger Pfad"),
        FileOperationError::InvalidName => AppError(StatusCode::BAD_REQUEST, "Ungültiger Name"),
        FileOperationError::NotFound => AppError(StatusCode::NOT_FOUND, "Ziel nicht gefunden"),
        FileOperationError::Conflict => {
            AppError(StatusCode::CONFLICT, "Zielname ist bereits vorhanden")
        }
        FileOperationError::ConfirmationRequired { .. } => AppError(
            StatusCode::CONFLICT,
            "Der exakte Ordnername muss bestätigt werden",
        ),
        FileOperationError::Database(_)
        | FileOperationError::Io(_)
        | FileOperationError::Join(_) => internal(error),
    }
}

fn file_row_actions(path: &str, name: &str, csrf_token: &str) -> String {
    format!(
        r#"<a class="vl-button vl-button--secondary vl-button--small" href="/admin/shares/new?path={}"><vl-i18n key="files.share_action"/></a><details class="vl-action-details"><summary class="vl-icon-button" aria-label="<vl-i18n key="share.more_aria"/>">{}</summary><div class="vl-action-panel"><form method="post" action="/admin/files/rename" class="vl-stack"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="path" value="{}"><label class="vl-field"><vl-i18n key="files.new_name"/><input name="name" value="{}" maxlength="255" required></label><button class="vl-button vl-button--small"><vl-i18n key="common.rename"/></button></form><a class="vl-button vl-button--danger vl-button--small" href="/admin/files/delete?path={}">{} <vl-i18n key="common.delete"/></a></div></details>"#,
        encoded(path),
        crate::ui::icon(crate::ui::Icon::More),
        esc(csrf_token),
        esc(path),
        esc(name),
        encoded(path),
        crate::ui::icon(crate::ui::Icon::Trash),
    )
}

fn file_name_cell(path: &str, display_name: &str, is_directory: bool) -> String {
    let target = encoded(path);
    let icon = crate::ui::icon(if is_directory {
        crate::ui::Icon::Folder
    } else {
        crate::ui::Icon::File
    });
    let label = if is_directory {
        format!(
            r#"<a href="/admin?path={target}">{}</a>"#,
            esc(display_name)
        )
    } else {
        esc(display_name)
    };
    format!(
        r#"<label class="vl-file-select"><input type="radio" name="selected_path" value="{}" data-file-select><span>{icon}{label}</span></label>"#,
        esc(path)
    )
}

async fn admin_browser(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<BrowseQuery>,
) -> Result<Html<String>> {
    let (_, s) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let settings = runtime_settings(&state);
    let disk = disk_stats(state.secure_root.display_root());
    let used_storage = disk
        .as_ref()
        .map(|stats| stats.total.saturating_sub(stats.free))
        .map(human)
        .unwrap_or_else(|| "n/v".into());
    let free_storage = disk
        .as_ref()
        .map(|stats| human(stats.free))
        .unwrap_or_else(|| "n/v".into());
    let active_links = database(state.db.clone(), |database| database.list_shares())
        .await?
        .into_iter()
        .filter(share_is_available)
        .count();
    let raw = q.path.unwrap_or_default();
    let page_number = q.page.unwrap_or(0).min(1_000_000);
    let search =
        q.q.map(|value| value.trim().to_string())
            .filter(|v| !v.is_empty());
    let rel = path_security::validate_relative(&raw)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Pfad"))?
        .to_string_lossy()
        .replace('\\', "/");
    let secure_root = state.secure_root.clone();
    let mut rows = String::new();
    let mut has_next = false;
    if let Some(search) = search.clone() {
        let base = rel.clone();
        let search_settings = settings.clone();
        let hits = tokio::task::spawn_blocking(move || {
            search_tree(secure_root, &base, &search, &search_settings)
        })
        .await
        .map_err(internal)?
        .map_err(internal)?;
        for hit in hits {
            let target = encoded(&hit.relative_path);
            let actions = file_row_actions(&hit.relative_path, &hit.entry.name, &s.csrf_token);
            let preview = if !hit.entry.is_dir && preview_allowed(&hit.relative_path, &settings) {
                format!(
                    r#"<a class="vl-button vl-button--secondary vl-button--small" href="/admin/preview?path={target}"><vl-i18n key="common.view"/></a> "#
                )
            } else {
                String::new()
            };
            let modified = hit
                .entry
                .modified
                .map(format_file_time)
                .unwrap_or_else(|| "—".into());
            rows += &format!(
                r#"<tr><td data-label="<vl-i18n key="common.name"/>">{}</td><td data-label="<vl-i18n key="common.type"/>">{}</td><td data-label="<vl-i18n key="common.size"/>">{}</td><td data-label="<vl-i18n key="common.changed"/>">{}</td><td data-label="<vl-i18n key="common.action"/>"><div class="vl-inline-actions">{}{}</div></td></tr>"#,
                file_name_cell(&hit.relative_path, &hit.relative_path, hit.entry.is_dir),
                i18n::text(
                    i18n::current_locale(),
                    if hit.entry.is_dir {
                        i18n::FOLDER
                    } else {
                        i18n::FILE
                    }
                ),
                if hit.entry.is_dir {
                    "—".into()
                } else {
                    human(hit.entry.len)
                },
                modified,
                preview,
                actions
            );
        }
    } else {
        let listing_path = rel.clone();
        let scan_limit = settings.max_search_entries;
        let (entries, truncated) = tokio::task::spawn_blocking(move || {
            list_directory_page(&secure_root, &listing_path, page_number, scan_limit)
        })
        .await
        .map_err(internal)?
        .map_err(internal)?;
        has_next = entries.len() > 100;
        for entry in entries.into_iter().take(100) {
            let name = entry.name;
            let is_dir = entry.is_dir;
            let size = entry.len;
            let modified = entry.modified;
            let child = join_display(&rel, &name);
            let target = encoded(&child);
            let actions = file_row_actions(&child, &name, &s.csrf_token);
            let display = file_name_cell(&child, &name, is_dir);
            let preview = if !is_dir && preview_allowed(&child, &settings) {
                format!(
                    r#"<a class="vl-button vl-button--secondary vl-button--small" href="/admin/preview?path={target}"><vl-i18n key="common.view"/></a> "#
                )
            } else {
                String::new()
            };
            let modified = modified.map(format_file_time).unwrap_or_else(|| "—".into());
            rows += &format!(
                r#"<tr><td data-label="<vl-i18n key="common.name"/>">{display}</td><td data-label="<vl-i18n key="common.type"/>">{}</td><td data-label="<vl-i18n key="common.size"/>">{}</td><td data-label="<vl-i18n key="common.changed"/>">{}</td><td data-label="<vl-i18n key="common.action"/>"><div class="vl-inline-actions">{}{}</div></td></tr>"#,
                i18n::text(
                    i18n::current_locale(),
                    if is_dir { i18n::FOLDER } else { i18n::FILE }
                ),
                if is_dir { "—".into() } else { human(size) },
                modified,
                preview,
                actions
            );
        }
        if truncated {
            rows +=
                r#"<tr><td colspan="5" class="muted"><vl-i18n key="files.scan_limit"/></td></tr>"#;
        }
    }
    let encoded_path = encoded(&rel);
    let current_folder_target = if raw.is_empty() {
        ".".to_string()
    } else {
        encoded_path.clone()
    };
    let search_value = search.as_deref().unwrap_or("");
    let search_param = if search_value.is_empty() {
        String::new()
    } else {
        format!("&q={}", encoded(search_value))
    };
    let previous = if page_number > 0 {
        format!(
            "<a href=\"/admin?path={encoded_path}&page={}{}\"><vl-i18n key=\"common.back\"/></a>",
            page_number - 1,
            search_param
        )
    } else {
        String::new()
    };
    let next = if has_next {
        format!(
            "<a href=\"/admin?path={encoded_path}&page={}{}\"><vl-i18n key=\"common.continue\"/></a>",
            page_number + 1,
            search_param
        )
    } else {
        String::new()
    };
    let up = parent_path(&rel)
        .map(|parent| {
            format!(
                r#"<a class="vl-button vl-button--ghost" href="/admin?path={}"><vl-i18n key="files.up"/></a>"#,
                encoded(&parent)
            )
        })
        .unwrap_or_default();
    let notice = match q.notice.as_deref() {
        Some("directory_created") => "<p class=\"vl-notice vl-notice--success\"><vl-i18n key=\"files.folder_created\"/></p>",
        Some("path_renamed") => "<p class=\"vl-notice vl-notice--success\"><vl-i18n key=\"files.entry_renamed\"/></p>",
        Some("path_deleted") => "<p class=\"vl-notice vl-notice--success\"><vl-i18n key=\"files.entry_deleted\"/></p>",
        Some("path_delete_queued") => {
            "<p class=\"vl-notice vl-notice--success\"><vl-i18n key=\"files.entry_removed_cleanup\"/></p>"
        }
        Some("upload_ok") => {
            "<p class=\"vl-notice vl-notice--success\"><vl-i18n key=\"files.uploaded\"/></p>"
        }
        _ => "",
    };
    let _legacy_listing = format!(
        r#"<section class="hero"><div><p class="eyebrow">VaultLink Admin</p><h1>Dateibrowser</h1>{}<p class=muted>Relativer Pfad: /{}</p></div><div class="side-panel"><strong>Schnellaktion</strong><p class="muted">Aktuellen Ordner sicher freigeben oder per Suche eingrenzen.</p><p><a class="button" href="/admin/shares?path={}">Aktuellen Ordner freigeben</a></p></div></section><section>{}<form method="get" class="row"><input type="hidden" name="path" value="{}"><label>Suche<br><input name="q" value="{}" placeholder="Dateiname"></label><button>Suchen</button></form><table><thead><tr><th>Name</th><th>Typ</th><th>Größe</th><th>Geändert</th><th></th></tr></thead><tbody>{}</tbody></table><p>{} {}</p><p class=muted>100 Einträge pro Seite. Suche ist limitiert und läuft innerhalb des aktuellen Ordners.</p></section>"#,
        breadcrumbs(&rel, "/admin"),
        esc(&rel),
        current_folder_target,
        up,
        esc(&rel),
        esc(search_value),
        rows,
        previous,
        next
    );
    let create_form = format!(
        r#"<details class="vl-create-folder"><summary class="vl-button vl-button--secondary"><vl-i18n key="files.new_folder"/></summary><form method="post" action="/admin/files/directories" class="vl-create-folder__form"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="parent" value="{}"><label class="vl-field vl-create-folder__field"><span><vl-i18n key="files.folder_name"/></span><input name="name" maxlength="255" required></label><button class="vl-button"><vl-i18n key="files.create_folder"/></button></form></details>"#,
        esc(&s.csrf_token),
        esc(&rel),
    );
    let upload_form = format!(
        r#"<details class="vl-create-folder vl-upload-dialog"><summary class="vl-button vl-button--secondary">{} <vl-i18n key="upload.files"/></summary><form method="post" enctype="multipart/form-data" action="/admin/files/upload" class="vl-stack" data-upload-queue data-queue-endpoint="/admin/files/upload/queue"><input type="hidden" name="path" value="{}"><input type="hidden" name="csrf" value="{}"><div class="vl-panel-head"><div><strong><vl-i18n key="upload.admin"/></strong><p class="vl-muted"><vl-i18n key="upload.sequential"/></p></div><button class="vl-button vl-button--ghost vl-button--small" type="button" data-details-close><vl-i18n key="common.close"/></button></div><label class="vl-switch"><input type="checkbox" name="overwrite_existing" value="1"><span><vl-i18n key="share.replace_conflict"/><small><vl-i18n key="share.after_conflict"/></small></span></label><label class="vl-upload-dropzone" data-upload-dropzone><strong><vl-i18n key="upload.drop_here"/></strong><span class="vl-muted"><vl-i18n key="upload.or_add"/></span><input class="vl-upload-input" type="file" name="file" required data-upload-input></label><div class="vl-upload-queue" data-upload-list aria-live="polite"></div><button class="vl-button" data-upload-submit><vl-i18n key="upload.start"/></button></form></details>"#,
        crate::ui::icon(crate::ui::Icon::Upload),
        esc(&rel),
        esc(&s.csrf_token),
    );
    let listing = format!(
        r#"<section class="vl-stat-strip" aria-label="<vl-i18n key="audit.storage_aria"/>"><div><strong>{}</strong><span><vl-i18n key="common.used"/></span></div><div><strong>{}</strong><span><vl-i18n key="common.free"/></span></div><div><strong>{}</strong><span><vl-i18n key="share.active_links"/></span></div></section><section class="vl-panel"><div class="vl-browser-head"><div>{}<p class="vl-muted"><vl-i18n key="files.relative_path"/>: /{}</p></div><div class="vl-inline-actions">{}{}{}<a class="vl-button" href="/admin/shares/new?path={}"><vl-i18n key="share.current_folder"/></a></div></div><form method="get" class="vl-toolbar"><input type="hidden" name="path" value="{}"><label class="vl-field vl-search"><span class="vl-sr-only"><vl-i18n key="files.browse"/></span><input name="q" value="{}" placeholder="<vl-i18n key="files.search_placeholder"/>"></label><button class="vl-button"><vl-i18n key="common.search"/></button></form><div class="vl-table-wrap"><table class="vl-data-table"><thead><tr><th><vl-i18n key="common.name"/></th><th><vl-i18n key="common.type"/></th><th><vl-i18n key="common.size"/></th><th><vl-i18n key="common.changed"/></th><th><vl-i18n key="common.action"/></th></tr></thead><tbody>{}</tbody></table></div><nav class="vl-pagination" aria-label="<vl-i18n key="files.pages_aria"/>">{} {}</nav><p class="vl-muted"><vl-i18n key="files.entries_page"/></p></section><div class="vl-selection-bar" data-selection-bar hidden><span data-selection-name><vl-i18n key="share.one_selected"/></span><a class="vl-button" data-selection-share href="/admin/shares/new"><vl-i18n key="share.selection"/></a></div>"#,
        esc(&used_storage),
        esc(&free_storage),
        active_links,
        breadcrumbs(&rel, "/admin"),
        esc(&rel),
        up,
        create_form,
        upload_form,
        current_folder_target,
        esc(&rel),
        esc(search_value),
        rows,
        previous,
        next,
    );
    let body = format!("{notice}{listing}");
    Ok(Html(admin_page(
        &state,
        PageId::Files,
        &body,
        false,
        &s.csrf_token,
    )))
}

async fn admin_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ShareQuery>,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let raw = q
        .path
        .ok_or(AppError(StatusCode::BAD_REQUEST, "Dateipfad fehlt"))?;
    let rel = path_security::validate_relative(&raw)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Pfad"))?
        .to_string_lossy()
        .replace('\\', "/");
    let settings = runtime_settings(&state);
    let secure_root = state.secure_root.clone();
    let preview_path = rel.clone();
    let content =
        tokio::task::spawn_blocking(move || read_preview(secure_root, &preview_path, &settings))
            .await
            .map_err(internal)?
            .map_err(|_| AppError(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Vorschau nicht erlaubt"))?;
    let preview_detail = match &content {
        PreviewContent::TooLarge { size } => format!("kind=too_large;bytes={size}"),
        PreviewContent::Text(text) => format!("kind=text;bytes={}", text.len()),
        PreviewContent::Media { kind, size } => format!("kind={kind:?};bytes={size}"),
    };
    audit(
        &state,
        session.username.clone(),
        "admin_preview",
        Some(rel.clone()),
        Some(preview_detail),
    )
    .await;
    let body = match content {
        PreviewContent::TooLarge { size } => {
            preview_too_large_body(&rel, size, "Datei ist größer als das Preview-Limit.", None)
        }
        PreviewContent::Text(text) => format!(
            r#"<section><p class="preview-actions"><a href="/admin?path={}"><vl-i18n key="files.back_to_folder"/></a></p><p><code>/{}</code></p><pre>{}</pre></section>"#,
            encoded(parent_path(&rel).as_deref().unwrap_or("")),
            esc(&rel),
            esc(&text)
        ),
        PreviewContent::Media { kind, size } => admin_media_preview_body(&rel, kind, size),
    };
    Ok(Html(admin_page(
        &state,
        PageId::Preview,
        &body,
        false,
        &session.csrf_token,
    )))
}

async fn admin_preview_raw(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
    Query(q): Query<ShareQuery>,
) -> Result<Response> {
    session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let raw = q
        .path
        .ok_or(AppError(StatusCode::BAD_REQUEST, "Dateipfad fehlt"))?;
    let rel = path_security::validate_relative(&raw)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Pfad"))?
        .to_string_lossy()
        .replace('\\', "/");
    let settings = runtime_settings(&state);
    let kind = preview_kind(&rel, &settings)
        .filter(|kind| kind.is_media())
        .ok_or(AppError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Vorschau nicht erlaubt",
        ))?;
    raw_preview_response(
        state.secure_root.clone(),
        method,
        headers,
        rel,
        kind,
        settings.max_media_preview_size,
    )
    .await
}

fn admin_media_preview_body(path: &str, kind: PreviewKind, size: u64) -> String {
    let raw = format!("/admin/preview/raw?path={}", encoded(path));
    let viewer = media_viewer(kind, &raw);
    format!(
        r#"<section><p class="preview-actions"><a href="/admin?path={}"><vl-i18n key="files.back_to_folder"/></a></p><p><code>/{}</code> <span class="muted">{}</span></p>{}</section>"#,
        encoded(parent_path(path).as_deref().unwrap_or("")),
        esc(path),
        human(size),
        viewer
    )
}

fn media_viewer(kind: PreviewKind, raw_url: &str) -> String {
    match kind {
        PreviewKind::Image(_) => format!(
            r#"<img class="vl-media-preview vl-media-preview--image" src="{}" alt="<vl-i18n key="files.preview_alt"/>">"#,
            esc(raw_url)
        ),
        PreviewKind::Pdf => format!(
            r#"<iframe class="vl-media-preview vl-media-preview--pdf" src="{}" title="<vl-i18n key="files.pdf_preview"/>"></iframe>"#,
            esc(raw_url)
        ),
        PreviewKind::Text => String::new(),
    }
}

fn preview_too_large_body(
    path: &str,
    size: u64,
    message: &str,
    download_link: Option<&str>,
) -> String {
    let message = i18n::text_from_german(i18n::current_locale(), message);
    let is_public = download_link.is_some();
    let back = if is_public {
        String::new()
    } else {
        format!(
            r#"<a href="/admin?path={}"><vl-i18n key="files.back_to_folder"/></a>"#,
            encoded(parent_path(path).as_deref().unwrap_or(""))
        )
    };
    let heading = if is_public {
        r#"<h1><vl-i18n key="files.preview"/></h1>"#
    } else {
        ""
    };
    format!(
        r#"<section>{}<p class="preview-actions">{}</p><p><code>/{}</code></p><p class="muted">{} <vl-i18n key="files.size_label"/>: {}.</p></section>"#,
        heading,
        back,
        esc(path),
        esc(&message),
        human(size)
    )
}

fn human(n: u64) -> String {
    let mut value = if n >= GB {
        format!("{:.1} GB", n as f64 / GB as f64)
    } else if n >= MB {
        format!("{:.1} MB", n as f64 / MB as f64)
    } else if n >= 1_000 {
        format!("{:.1} KB", n as f64 / 1_000.)
    } else {
        format!("{n} B")
    };
    if i18n::current_locale() == Locale::De {
        value = value.replace('.', ",");
    }
    value
}

fn upload_limit_label(bytes: u64) -> String {
    human(bytes)
}

fn display_limit_unit_floor(bytes: u64, unit: u64) -> String {
    format_unit_floor(bytes, unit)
}

fn expiry_picker_html() -> String {
    format!(
        r#"<label class="vl-field"><vl-i18n key="share.expires_optional"/><div class="vl-datetime-picker vl-input-action" data-datetime-picker><input name="expires_local" data-datetime-input placeholder="<vl-i18n key="date.placeholder"/>" autocomplete="off" inputmode="numeric"><button class="vl-button vl-button--secondary" type="button" data-datetime-toggle aria-label="<vl-i18n key="share.date_select"/>" aria-expanded="false">{}</button><div class="vl-datetime-popover" data-datetime-popover hidden><div class="vl-datetime-popover__grid"><label><vl-i18n key="date.year"/><select data-dt-year></select></label><label><vl-i18n key="date.month"/><select data-dt-month data-pad="2"></select></label><label><vl-i18n key="date.day"/><select data-dt-day data-pad="2"></select></label><label><vl-i18n key="date.hour"/><select data-dt-hour data-pad="2"></select></label><label><vl-i18n key="date.minute"/><select data-dt-minute data-pad="2"></select></label></div><div class="vl-datetime-popover__actions"><button class="vl-button vl-button--secondary vl-button--small" type="button" data-datetime-clear><vl-i18n key="common.delete"/></button><button class="vl-button vl-button--small" type="button" data-datetime-apply><vl-i18n key="common.apply"/></button></div></div></div><small><vl-i18n key="date.format"/></small></label>"#,
        crate::ui::icon(crate::ui::Icon::Calendar)
    )
}

fn format_unit_floor(bytes: u64, unit: u64) -> String {
    (bytes / unit).to_string()
}

fn parse_unit_to_bytes(value: &str, unit: u64, label: &'static str) -> Result<u64> {
    let parsed = value
        .trim()
        .replace(',', ".")
        .parse::<f64>()
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, label))?;
    if !parsed.is_finite() || parsed <= 0.0 {
        return Err(AppError(StatusCode::BAD_REQUEST, label));
    }
    let bytes = (parsed * unit as f64).round();
    if bytes < 1.0 || bytes > u64::MAX as f64 {
        return Err(AppError(StatusCode::BAD_REQUEST, label));
    }
    Ok(bytes as u64)
}

fn parse_expiry(
    local: Option<&str>,
    offset_minutes: Option<&str>,
) -> Result<Option<DateTime<Utc>>> {
    if let Some(value) = local.map(str::trim).filter(|value| !value.is_empty()) {
        let naive = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M")
            .or_else(|_| NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S"))
            .or_else(|_| NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M"))
            .or_else(|_| NaiveDateTime::parse_from_str(value, "%d.%m.%Y %H:%M"))
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiges Ablaufdatum"))?;
        let offset = offset_minutes
            .unwrap_or("0")
            .trim()
            .parse::<i64>()
            .unwrap_or(0);
        let utc_naive = naive + Duration::minutes(offset);
        return Ok(Some(DateTime::<Utc>::from_naive_utc_and_offset(
            utc_naive, Utc,
        )));
    }
    Ok(None)
}

fn extension_is_blocked(name: &str, blocked: &[String]) -> bool {
    runtime::extension_is_blocked(name, blocked)
}

fn add_upload_bytes(total: u64, chunk: usize, maximum: u64) -> Option<u64> {
    total
        .checked_add(chunk as u64)
        .filter(|new_total| *new_total <= maximum)
}

fn validate_share_password(settings: &RuntimeSettings, password: &str) -> Result<()> {
    let chars = password.chars().count();
    if chars < settings.share_password_min_length
        || chars > settings.share_password_max_length
        || password.len() > SHARE_PASSWORD_HARD_MAX_BYTES
    {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Freigabepasswort entspricht nicht der Richtlinie",
        ));
    }
    Ok(())
}

fn encoded(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

fn otpauth_url(username: &str, secret: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}",
        encoded("VaultLink"),
        encoded(username),
        encoded(secret),
        encoded("VaultLink")
    )
}

fn qr_svg(data: &str) -> Result<String> {
    let code = QrCode::new(data.as_bytes()).map_err(internal)?;
    Ok(code
        .render::<svg::Color<'_>>()
        .min_dimensions(220, 220)
        .dark_color(svg::Color("#081226"))
        .light_color(svg::Color("#f8fbff"))
        .build())
}

fn join_display(base: &str, child: &str) -> String {
    if base.is_empty() || base == "." {
        child.to_string()
    } else {
        format!("{base}/{child}")
    }
}

fn parent_path(path: &str) -> Option<String> {
    let clean = path.trim_matches('/');
    if clean.is_empty() {
        return None;
    }
    clean
        .rsplit_once('/')
        .map(|(parent, _)| parent.to_string())
        .or_else(|| Some(String::new()))
}

fn breadcrumbs(path: &str, base_url: &str) -> String {
    let clean = path.trim_matches('/');
    let mut html = String::from(r#"<p class="crumbs"><a href=""#);
    html.push_str(base_url);
    html.push_str(r#"">/</a>"#);
    if clean.is_empty() {
        html.push_str("</p>");
        return html;
    }
    let mut current = String::new();
    for part in clean.split('/') {
        current = join_display(&current, part);
        html.push_str(" / ");
        html.push_str(&format!(
            r#"<a href="{}?path={}">{}</a>"#,
            base_url,
            encoded(&current),
            esc(part)
        ));
    }
    html.push_str("</p>");
    html
}

fn public_breadcrumbs(token: &str, path: &str) -> String {
    breadcrumbs(path, &format!("/v/{token}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreviewKind {
    Text,
    Image(&'static str),
    Pdf,
}

impl PreviewKind {
    fn content_type(self) -> &'static str {
        match self {
            Self::Text => "text/plain; charset=utf-8",
            Self::Image(content_type) => content_type,
            Self::Pdf => "application/pdf",
        }
    }

    fn is_media(self) -> bool {
        matches!(self, Self::Image(_) | Self::Pdf)
    }
}

fn preview_kind(path: &str, settings: &RuntimeSettings) -> Option<PreviewKind> {
    let extension = Path::new(path)
        .extension()
        .and_then(|value| value.to_str())?
        .trim_start_matches('.')
        .to_ascii_lowercase();
    if settings
        .preview_extensions
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&extension))
    {
        return Some(PreviewKind::Text);
    }
    if settings.pdf_preview_enabled && extension == "pdf" {
        return Some(PreviewKind::Pdf);
    }
    if settings
        .image_preview_extensions
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&extension))
    {
        return image_content_type(&extension).map(PreviewKind::Image);
    }
    None
}

fn preview_allowed(path: &str, settings: &RuntimeSettings) -> bool {
    preview_kind(path, settings).is_some()
}

fn public_preview_error(error: io::Error) -> AppError {
    // Linux openat2 reports EXDEV/ELOOP when resolution would cross the
    // descriptor-bound share or follow a forbidden final symlink. Keep that
    // security boundary indistinguishable from a missing public file.
    if matches!(error.raw_os_error(), Some(18 | 40)) {
        return AppError(StatusCode::NOT_FOUND, "Datei nicht verfügbar");
    }
    match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied => {
            AppError(StatusCode::NOT_FOUND, "Datei nicht verfügbar")
        }
        _ => AppError(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Vorschau nicht erlaubt"),
    }
}

fn image_content_type(extension: &str) -> Option<&'static str> {
    match extension {
        "jpg" | "jpeg" => Some("image/jpeg"),
        "png" => Some("image/png"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        "bmp" => Some("image/bmp"),
        "avif" => Some("image/avif"),
        _ => None,
    }
}

#[derive(Debug)]
struct SearchHit {
    relative_path: String,
    entry: Entry,
}

trait DirectoryAccess: Clone + Send + 'static {
    fn scan_entries(&self, relative: &str) -> io::Result<DirectoryScan>;
    fn open_regular_file(&self, relative: &str) -> io::Result<std::fs::File>;
    fn entry_metadata(&self, relative: &str) -> io::Result<std::fs::Metadata>;
}

impl DirectoryAccess for SecureRoot {
    fn scan_entries(&self, relative: &str) -> io::Result<DirectoryScan> {
        self.scan_directory(relative)
    }

    fn open_regular_file(&self, relative: &str) -> io::Result<std::fs::File> {
        self.open_file(relative)
    }

    fn entry_metadata(&self, relative: &str) -> io::Result<std::fs::Metadata> {
        self.metadata(relative)
    }
}

impl DirectoryAccess for SecureDirectory {
    fn scan_entries(&self, relative: &str) -> io::Result<DirectoryScan> {
        self.scan_directory(relative)
    }

    fn open_regular_file(&self, relative: &str) -> io::Result<std::fs::File> {
        self.open_file(relative).map(SecureFile::into_file)
    }

    fn entry_metadata(&self, relative: &str) -> io::Result<std::fs::Metadata> {
        self.metadata(relative)
    }
}

fn list_directory_page<D: DirectoryAccess>(
    directory: &D,
    relative: &str,
    page: usize,
    scan_limit: usize,
) -> io::Result<(Vec<Entry>, bool)> {
    let skip = page.saturating_mul(100);
    let mut visible = 0usize;
    let mut scanned = 0usize;
    let mut entries = Vec::new();
    let mut scan = directory.scan_entries(relative)?;
    while entries.len() < 101 {
        let remaining = scan_limit.saturating_sub(scanned);
        if remaining == 0 {
            let sentinel = scan.run_batch(1)?;
            return Ok((entries, sentinel.scanned != 0 || !sentinel.complete));
        }
        let batch = scan.run_batch(remaining.min(100))?;
        scanned = scanned.saturating_add(batch.scanned);
        for entry in batch.entries {
            if visible >= skip && entries.len() < 101 {
                entries.push(entry);
            }
            visible = visible.saturating_add(1);
        }
        if batch.complete {
            break;
        }
    }
    Ok((entries, false))
}

fn search_tree<D: DirectoryAccess>(
    secure_root: D,
    base: &str,
    query: &str,
    settings: &RuntimeSettings,
) -> std::io::Result<Vec<SearchHit>> {
    let needle = query.to_ascii_lowercase();
    let mut scanned_entries = 0usize;
    let mut results = Vec::new();
    let mut queue = VecDeque::from([base.to_string()]);
    while let Some(directory) = queue.pop_front() {
        let mut scan = secure_root.scan_entries(&directory)?;
        loop {
            let remaining = settings.max_search_entries.saturating_sub(scanned_entries);
            if remaining == 0 {
                return Ok(results);
            }
            let batch = scan.run_batch(remaining.min(100))?;
            scanned_entries = scanned_entries.saturating_add(batch.scanned);
            for entry in batch.entries {
                let relative_path = join_display(&directory, &entry.name);
                if entry.name.to_ascii_lowercase().contains(&needle)
                    && results.len() < settings.max_search_results
                {
                    results.push(SearchHit {
                        relative_path: relative_path.clone(),
                        entry: Entry {
                            name: entry.name.clone(),
                            is_dir: entry.is_dir,
                            len: entry.len,
                            modified: entry.modified,
                        },
                    });
                }
                if entry.is_dir {
                    queue.push_back(relative_path);
                }
                if results.len() >= settings.max_search_results {
                    return Ok(results);
                }
            }
            if batch.complete {
                break;
            }
        }
    }
    Ok(results)
}

const ZIP_CHUNK_SIZE: usize = 64 * 1024;
const ZIP_CHANNEL_CHUNKS: usize = 8;
const ZIP_TEMP_MIN_RESERVE: u64 = 64 * 1024 * 1024;
const ZIP64_VERSION: u16 = 45;
const ZIP_LOCAL_HEADER_SIZE: u64 = 30;
const ZIP_CENTRAL_HEADER_SIZE: u64 = 46;
const ZIP64_DATA_DESCRIPTOR_SIZE: u64 = 24;
const ZIP64_LOCAL_EXTRA_SIZE: u64 = 20;
const ZIP64_CENTRAL_EXTRA_SIZE: u64 = 28;
const ZIP64_EXTRA_PAYLOAD_SIZE: u16 = 24;
const ZIP64_SIZE_FIELDS_SIZE: u16 = 16;
const ZIP_EOCD_SIZE: u64 = 22;
const ZIP64_END_RECORDS_SIZE: u64 = 76;
const ZIP64_ENTRY_FIXED_SIZE: u64 = ZIP_LOCAL_HEADER_SIZE
    + ZIP64_LOCAL_EXTRA_SIZE
    + ZIP64_DATA_DESCRIPTOR_SIZE
    + ZIP_CENTRAL_HEADER_SIZE
    + ZIP64_CENTRAL_EXTRA_SIZE;
const ZIP64_ARCHIVE_END_SIZE: u64 = ZIP_EOCD_SIZE + ZIP64_END_RECORDS_SIZE;
static ZIP_TEMP_RESERVED: AtomicU64 = AtomicU64::new(0);

struct ZipTempReservation {
    bytes: u64,
}

impl ZipTempReservation {
    fn acquire(estimated_bytes: u64) -> Option<Self> {
        let safety = ZIP_TEMP_MIN_RESERVE.max(estimated_bytes / 10);
        let required = estimated_bytes.checked_add(safety)?;
        let available = disk_stats(&std::env::temp_dir()).map(|stats| stats.free);
        loop {
            let reserved = ZIP_TEMP_RESERVED.load(Ordering::Acquire);
            if available.is_some_and(|free| free.saturating_sub(reserved) < required) {
                return None;
            }
            if ZIP_TEMP_RESERVED
                .compare_exchange_weak(
                    reserved,
                    reserved.checked_add(estimated_bytes)?,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Some(Self {
                    bytes: estimated_bytes,
                });
            }
        }
    }
}

impl Drop for ZipTempReservation {
    fn drop(&mut self) {
        ZIP_TEMP_RESERVED.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

#[derive(Debug)]
enum ZipBuildError {
    Limit(&'static str),
    Source(io::Error),
    Output(io::Error),
}

impl ZipBuildError {
    fn into_io(self) -> io::Error {
        match self {
            Self::Limit(message) => io::Error::new(io::ErrorKind::InvalidData, message),
            Self::Source(error) | Self::Output(error) => error,
        }
    }

    fn is_output_capacity_error(&self) -> bool {
        matches!(self, Self::Output(error) if storage_full_error(error))
    }
}

#[derive(Clone)]
struct ZipFilePlan {
    source_path: String,
    archive_name: String,
    scanned_len: u64,
}

#[derive(Clone)]
struct ZipPlan {
    files: Vec<ZipFilePlan>,
    max_data_size: u64,
    estimated_archive_size: u64,
}

fn estimate_zip_archive_size(files: &[ZipFilePlan]) -> std::result::Result<u64, ZipBuildError> {
    let mut archive_size = ZIP64_ARCHIVE_END_SIZE;
    for file in files {
        let name_len = u64::try_from(file.archive_name.len())
            .map_err(|_| ZipBuildError::Limit("zip entry name is too long"))?;
        let names_size = name_len
            .checked_mul(2)
            .ok_or(ZipBuildError::Limit("zip archive size overflow"))?;
        archive_size = archive_size
            .checked_add(file.scanned_len)
            .and_then(|size| size.checked_add(ZIP64_ENTRY_FIXED_SIZE))
            .and_then(|size| size.checked_add(names_size))
            .ok_or(ZipBuildError::Limit("zip archive size overflow"))?;
    }
    Ok(archive_size)
}

fn plan_zip<D: DirectoryAccess>(
    directory: &D,
    root_path: &str,
    settings: &RuntimeSettings,
) -> std::result::Result<ZipPlan, ZipBuildError> {
    let mut queue = VecDeque::from([(root_path.to_string(), String::new())]);
    let mut files = Vec::new();
    let mut scanned_entries = 0usize;
    let mut total_data = 0u64;
    while let Some((current_directory, archive_prefix)) = queue.pop_front() {
        let mut scan = directory
            .scan_entries(&current_directory)
            .map_err(ZipBuildError::Source)?;
        loop {
            let remaining = settings.max_search_entries.saturating_sub(scanned_entries);
            if remaining == 0 {
                let sentinel = scan.run_batch(1).map_err(ZipBuildError::Source)?;
                if sentinel.scanned == 0 && sentinel.complete {
                    break;
                }
                return Err(ZipBuildError::Limit("zip scan entry limit exceeded"));
            }
            let batch = scan
                .run_batch(remaining.min(100))
                .map_err(ZipBuildError::Source)?;
            scanned_entries = scanned_entries.saturating_add(batch.scanned);
            for entry in batch.entries {
                let source_path = join_display(&current_directory, &entry.name);
                let archive_name = join_display(&archive_prefix, &entry.name);
                if entry.is_dir {
                    queue.push_back((source_path, archive_name));
                    continue;
                }
                if archive_name.len() > u16::MAX as usize {
                    return Err(ZipBuildError::Limit("zip entry name is too long"));
                }
                files.push(ZipFilePlan {
                    source_path,
                    archive_name: archive_name.clone(),
                    scanned_len: entry.len,
                });
                if settings.max_zip_files != 0 && files.len() > settings.max_zip_files {
                    return Err(ZipBuildError::Limit("zip file count limit exceeded"));
                }
                total_data = total_data
                    .checked_add(entry.len)
                    .ok_or(ZipBuildError::Limit("zip size overflow"))?;
                if settings.max_zip_size != 0 && total_data > settings.max_zip_size {
                    return Err(ZipBuildError::Limit("zip size limit exceeded"));
                }
            }
            if batch.complete {
                break;
            }
        }
    }
    let estimated_archive_size = estimate_zip_archive_size(&files)?;
    Ok(ZipPlan {
        files,
        max_data_size: settings.max_zip_size,
        estimated_archive_size,
    })
}

struct CountingWriter<W> {
    inner: W,
    written: u64,
}

impl<W> CountingWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner, written: 0 }
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.written = self
            .written
            .checked_add(written as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "zip size overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct StreamingZipEntry {
    name: String,
    crc: u32,
    size: u64,
    local_offset: u64,
}

fn write_zip_u16(writer: &mut impl Write, value: u16) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn write_zip_u32(writer: &mut impl Write, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn write_zip_u64(writer: &mut impl Write, value: u64) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn write_streaming_local_header(writer: &mut impl Write, name: &[u8]) -> io::Result<()> {
    write_zip_u32(writer, 0x0403_4b50)?;
    write_zip_u16(writer, ZIP64_VERSION)?;
    write_zip_u16(writer, 0x0808)?;
    write_zip_u16(writer, 0)?;
    write_zip_u16(writer, 0)?;
    write_zip_u16(writer, 33)?;
    write_zip_u32(writer, 0)?;
    write_zip_u32(writer, u32::MAX)?;
    write_zip_u32(writer, u32::MAX)?;
    write_zip_u16(writer, name.len() as u16)?;
    write_zip_u16(writer, ZIP64_LOCAL_EXTRA_SIZE as u16)?;
    writer.write_all(name)?;
    // Bit 3 makes the descriptor authoritative; zero placeholders announce its 64-bit width.
    write_zip_u16(writer, 0x0001)?;
    write_zip_u16(writer, ZIP64_SIZE_FIELDS_SIZE)?;
    write_zip_u64(writer, 0)?;
    write_zip_u64(writer, 0)?;
    Ok(())
}

fn write_streaming_descriptor(writer: &mut impl Write, crc: u32, size: u64) -> io::Result<()> {
    write_zip_u32(writer, 0x0807_4b50)?;
    write_zip_u32(writer, crc)?;
    write_zip_u64(writer, size)?;
    write_zip_u64(writer, size)
}

fn write_streaming_central_entry(
    writer: &mut impl Write,
    entry: &StreamingZipEntry,
) -> io::Result<()> {
    let name = entry.name.as_bytes();
    write_zip_u32(writer, 0x0201_4b50)?;
    write_zip_u16(writer, ZIP64_VERSION)?;
    write_zip_u16(writer, ZIP64_VERSION)?;
    write_zip_u16(writer, 0x0808)?;
    write_zip_u16(writer, 0)?;
    write_zip_u16(writer, 0)?;
    write_zip_u16(writer, 33)?;
    write_zip_u32(writer, entry.crc)?;
    write_zip_u32(writer, u32::MAX)?;
    write_zip_u32(writer, u32::MAX)?;
    write_zip_u16(writer, name.len() as u16)?;
    write_zip_u16(writer, ZIP64_CENTRAL_EXTRA_SIZE as u16)?;
    write_zip_u16(writer, 0)?;
    write_zip_u16(writer, 0)?;
    write_zip_u16(writer, 0)?;
    write_zip_u32(writer, 0)?;
    write_zip_u32(writer, u32::MAX)?;
    writer.write_all(name)?;
    write_zip_u16(writer, 0x0001)?;
    write_zip_u16(writer, ZIP64_EXTRA_PAYLOAD_SIZE)?;
    write_zip_u64(writer, entry.size)?;
    write_zip_u64(writer, entry.size)?;
    write_zip_u64(writer, entry.local_offset)?;
    Ok(())
}

fn write_streaming_eocd(writer: &mut impl Write) -> io::Result<()> {
    write_zip_u32(writer, 0x0605_4b50)?;
    write_zip_u16(writer, 0)?;
    write_zip_u16(writer, 0)?;
    write_zip_u16(writer, u16::MAX)?;
    write_zip_u16(writer, u16::MAX)?;
    write_zip_u32(writer, u32::MAX)?;
    write_zip_u32(writer, u32::MAX)?;
    write_zip_u16(writer, 0)
}

fn write_streaming_zip64_eocd(
    writer: &mut impl Write,
    entries: u64,
    central_size: u64,
    central_offset: u64,
) -> io::Result<()> {
    write_zip_u32(writer, 0x0606_4b50)?;
    write_zip_u64(writer, 44)?;
    write_zip_u16(writer, ZIP64_VERSION)?;
    write_zip_u16(writer, ZIP64_VERSION)?;
    write_zip_u32(writer, 0)?;
    write_zip_u32(writer, 0)?;
    write_zip_u64(writer, entries)?;
    write_zip_u64(writer, entries)?;
    write_zip_u64(writer, central_size)?;
    write_zip_u64(writer, central_offset)
}

fn write_streaming_zip64_locator(
    writer: &mut impl Write,
    zip64_eocd_offset: u64,
) -> io::Result<()> {
    write_zip_u32(writer, 0x0706_4b50)?;
    write_zip_u32(writer, 0)?;
    write_zip_u64(writer, zip64_eocd_offset)?;
    write_zip_u32(writer, 1)
}

fn update_crc32(mut crc: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    crc
}

fn write_zip_archive<D: DirectoryAccess, W: Write>(
    directory: &D,
    plan: &ZipPlan,
    output: W,
) -> std::result::Result<W, ZipBuildError> {
    let mut writer = CountingWriter::new(output);
    let mut central_entries = Vec::with_capacity(plan.files.len());
    let mut total_data = 0u64;
    let mut buffer = vec![0u8; ZIP_CHUNK_SIZE];
    for planned in &plan.files {
        let local_offset = writer.written;
        write_streaming_local_header(&mut writer, planned.archive_name.as_bytes())
            .map_err(ZipBuildError::Output)?;
        let mut source = directory
            .open_regular_file(&planned.source_path)
            .map_err(ZipBuildError::Source)?;
        let mut remaining = planned.scanned_len;
        let mut size = 0u64;
        let mut crc = 0xffff_ffffu32;
        while remaining > 0 {
            let wanted = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();
            let read = source
                .read(&mut buffer[..wanted])
                .map_err(ZipBuildError::Source)?;
            if read == 0 {
                break;
            }
            remaining -= read as u64;
            size = size
                .checked_add(read as u64)
                .ok_or(ZipBuildError::Limit("zip size overflow"))?;
            total_data = total_data
                .checked_add(read as u64)
                .ok_or(ZipBuildError::Limit("zip size overflow"))?;
            if plan.max_data_size != 0 && total_data > plan.max_data_size {
                return Err(ZipBuildError::Limit("zip size limit exceeded"));
            }
            crc = update_crc32(crc, &buffer[..read]);
            writer
                .write_all(&buffer[..read])
                .map_err(ZipBuildError::Output)?;
        }
        let crc = !crc;
        write_streaming_descriptor(&mut writer, crc, size).map_err(ZipBuildError::Output)?;
        central_entries.push(StreamingZipEntry {
            name: planned.archive_name.clone(),
            crc,
            size,
            local_offset,
        });
    }
    let central_offset = writer.written;
    for entry in &central_entries {
        write_streaming_central_entry(&mut writer, entry).map_err(ZipBuildError::Output)?;
    }
    let central_end = writer.written;
    let central_size = central_end
        .checked_sub(central_offset)
        .ok_or(ZipBuildError::Limit("zip central directory overflow"))?;
    let entries = u64::try_from(central_entries.len())
        .map_err(|_| ZipBuildError::Limit("zip file count overflow"))?;
    let zip64_eocd_offset = writer.written;
    write_streaming_zip64_eocd(&mut writer, entries, central_size, central_offset)
        .map_err(ZipBuildError::Output)?;
    write_streaming_zip64_locator(&mut writer, zip64_eocd_offset).map_err(ZipBuildError::Output)?;
    write_streaming_eocd(&mut writer).map_err(ZipBuildError::Output)?;
    writer.flush().map_err(ZipBuildError::Output)?;
    Ok(writer.into_inner())
}

fn build_zip_temp<D: DirectoryAccess>(
    directory: &D,
    plan: &ZipPlan,
) -> std::result::Result<std::fs::File, ZipBuildError> {
    let file = tempfile::tempfile().map_err(ZipBuildError::Output)?;
    let mut file = write_zip_archive(directory, plan, file)?;
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(ZipBuildError::Output)?;
    Ok(file)
}

struct ZipChannelWriter {
    sender: tokio::sync::mpsc::Sender<io::Result<Bytes>>,
    buffer: Vec<u8>,
}

impl ZipChannelWriter {
    fn new(sender: tokio::sync::mpsc::Sender<io::Result<Bytes>>) -> Self {
        Self {
            sender,
            buffer: Vec::with_capacity(ZIP_CHUNK_SIZE),
        }
    }

    fn send_buffer(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let bytes = Bytes::from(std::mem::replace(
            &mut self.buffer,
            Vec::with_capacity(ZIP_CHUNK_SIZE),
        ));
        self.sender
            .blocking_send(Ok(bytes))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "zip client disconnected"))
    }
}

impl Write for ZipChannelWriter {
    fn write(&mut self, mut input: &[u8]) -> io::Result<usize> {
        let original_len = input.len();
        while !input.is_empty() {
            let remaining = ZIP_CHUNK_SIZE - self.buffer.len();
            let take = remaining.min(input.len());
            self.buffer.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.buffer.len() == ZIP_CHUNK_SIZE {
                self.send_buffer()?;
            }
        }
        Ok(original_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_buffer()
    }
}

fn direct_zip_stream<D: DirectoryAccess>(
    directory: D,
    plan: ZipPlan,
) -> impl Stream<Item = io::Result<Bytes>> + Send {
    let (sender, receiver) = tokio::sync::mpsc::channel(ZIP_CHANNEL_CHUNKS);
    let error_sender = sender.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(error) = write_zip_archive(&directory, &plan, ZipChannelWriter::new(sender)) {
            let _ = error_sender.blocking_send(Err(error.into_io()));
        }
    });
    futures_util::stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|item| (item, receiver))
    })
}

struct ReservedZipStream {
    inner: ReaderStream<tokio::fs::File>,
    _reservation: ZipTempReservation,
}

impl Stream for ReservedZipStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(context)
    }
}

fn zip_error(error: ZipBuildError) -> AppError {
    match error {
        ZipBuildError::Limit(_) => AppError(StatusCode::PAYLOAD_TOO_LARGE, "ZIP-Limit erreicht"),
        ZipBuildError::Source(_) => AppError(StatusCode::NOT_FOUND, "ZIP-Quelle nicht verfügbar"),
        ZipBuildError::Output(_) => AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ZIP-Erstellung fehlgeschlagen",
        ),
    }
}

enum PreviewContent {
    TooLarge { size: u64 },
    Text(String),
    Media { kind: PreviewKind, size: u64 },
}

fn read_preview<D: DirectoryAccess>(
    secure_root: D,
    path: &str,
    settings: &RuntimeSettings,
) -> std::io::Result<PreviewContent> {
    let metadata = secure_root.entry_metadata(path)?;
    let file = secure_root.open_regular_file(path)?;
    read_preview_opened(file, metadata, path, settings)
}

fn read_preview_secure_file(
    file: SecureFile,
    path: &str,
    settings: &RuntimeSettings,
) -> std::io::Result<PreviewContent> {
    let metadata = file.metadata()?;
    read_preview_opened(file.into_file(), metadata, path, settings)
}

fn read_preview_opened(
    file: std::fs::File,
    metadata: std::fs::Metadata,
    path: &str,
    settings: &RuntimeSettings,
) -> std::io::Result<PreviewContent> {
    let kind = preview_kind(path, settings).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "preview extension is not allowed",
        )
    })?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "preview target is not a file",
        ));
    }
    if kind.is_media() {
        if metadata.len() > settings.max_media_preview_size {
            return Ok(PreviewContent::TooLarge {
                size: metadata.len(),
            });
        }
        return Ok(PreviewContent::Media {
            kind,
            size: metadata.len(),
        });
    }
    if metadata.len() > settings.max_preview_size {
        return Ok(PreviewContent::TooLarge {
            size: metadata.len(),
        });
    }
    let mut bytes = Vec::new();
    file.take(settings.max_preview_size + 1)
        .read_to_end(&mut bytes)?;
    if bytes.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "binary content is not previewed",
        ));
    }
    Ok(PreviewContent::Text(
        String::from_utf8_lossy(&bytes).into_owned(),
    ))
}

async fn raw_preview_response<D: DirectoryAccess>(
    secure_root: D,
    method: Method,
    headers: HeaderMap,
    relative_file: String,
    kind: PreviewKind,
    max_size: u64,
) -> Result<Response> {
    let open_path = relative_file.clone();
    let file = tokio::task::spawn_blocking(move || secure_root.open_regular_file(&open_path))
        .await
        .map_err(internal)?
        .map_err(|_| AppError(StatusCode::NOT_FOUND, "Datei nicht verfügbar"))?;
    raw_preview_opened_response(file, method, headers, relative_file, kind, max_size).await
}

async fn raw_preview_secure_file_response(
    file: SecureFile,
    method: Method,
    headers: HeaderMap,
    relative_file: String,
    kind: PreviewKind,
    max_size: u64,
) -> Result<Response> {
    raw_preview_opened_response(
        file.into_file(),
        method,
        headers,
        relative_file,
        kind,
        max_size,
    )
    .await
}

async fn raw_preview_opened_response(
    file: std::fs::File,
    method: Method,
    headers: HeaderMap,
    relative_file: String,
    kind: PreviewKind,
    max_size: u64,
) -> Result<Response> {
    if !file.metadata().map_err(internal)?.is_file() {
        return Err(AppError(StatusCode::BAD_REQUEST, "Keine Datei"));
    }
    let mut f = tokio::fs::File::from_std(file);
    let length = f.metadata().await.map_err(internal)?.len();
    if length > max_size {
        return Err(AppError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Vorschau-Limit erreicht",
        ));
    }
    let range = match headers.get(header::RANGE) {
        Some(value) => match value
            .to_str()
            .ok()
            .and_then(|value| parse_byte_range(value, length).ok())
        {
            Some(range) => Some(range),
            None => {
                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                response
                    .headers_mut()
                    .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
                response.headers_mut().insert(
                    header::CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes */{length}")).map_err(internal)?,
                );
                return Ok(response);
            }
        },
        None => None,
    };
    let (start, end) = range.unwrap_or((0, length.saturating_sub(1)));
    let response_length = if length == 0 { 0 } else { end - start + 1 };
    if start > 0 {
        f.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(internal)?;
    }
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from_stream(ReaderStream::new(f.take(response_length)))
    };
    let mut r = Response::new(body);
    if range.is_some() {
        *r.status_mut() = StatusCode::PARTIAL_CONTENT;
        r.headers_mut().insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {start}-{end}/{length}")).map_err(internal)?,
        );
    }
    let name = Path::new(&relative_file)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("preview");
    let filename = percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC);
    r.headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    r.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&response_length.to_string()).map_err(internal)?,
    );
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(kind.content_type()),
    );
    r.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("inline; filename*=UTF-8''{filename}")).map_err(internal)?,
    );
    r.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    Ok(r)
}

#[derive(Default, Deserialize)]
struct ShareQuery {
    path: Option<String>,
    q: Option<String>,
    status: Option<String>,
    sort: Option<String>,
    page: Option<usize>,
}

#[derive(Default, Deserialize)]
pub(crate) struct PreviewRawQuery {
    path: Option<String>,
    preview_token: Option<String>,
}

fn share_permission_label(permission: &Permission) -> &'static str {
    let locale = i18n::current_locale();
    match permission {
        Permission::DownloadOnly => i18n::text(locale, i18n::DOWNLOAD_ONLY),
        Permission::UploadOnly => i18n::text(locale, i18n::UPLOAD_ONLY),
        Permission::DownloadUpload => i18n::text(locale, i18n::DOWNLOAD_UPLOAD),
    }
}

fn share_is_expired(share: &Share) -> bool {
    share
        .expires_at
        .is_some_and(|expires_at| expires_at <= Utc::now())
}

fn share_limit_reached(share: &Share) -> bool {
    share
        .max_downloads
        .is_some_and(|maximum| share.download_count >= maximum)
}

fn share_is_available(share: &Share) -> bool {
    share.active && !share_is_expired(share) && !share_limit_reached(share)
}

fn share_primary_status(share: &Share) -> (&'static str, &'static str) {
    let locale = i18n::current_locale();
    if !share.active {
        (i18n::text(locale, i18n::INACTIVE), "neutral")
    } else if share_is_expired(share) {
        (i18n::text(locale, i18n::EXPIRED), "warning")
    } else if share_limit_reached(share) {
        (i18n::text(locale, i18n::LIMIT_REACHED), "warning")
    } else {
        (i18n::text(locale, i18n::ACTIVE), "success")
    }
}

fn share_public_url(settings: &RuntimeSettings, share: &Share) -> String {
    let base = settings.public_base_url.trim_end_matches('/');
    match share.alias.as_deref() {
        Some(alias) => format!("{base}/s/{alias}"),
        None => format!("{base}/v/{}", share.token),
    }
}

fn selected(current: &str, value: &str) -> &'static str {
    if current == value {
        "selected"
    } else {
        ""
    }
}

fn share_list_url(query: &str, status: &str, sort: &str, page: usize) -> String {
    format!(
        "/admin/shares?q={}&status={}&sort={}&page={page}",
        encoded(query),
        encoded(status),
        encoded(sort)
    )
}

async fn share_index_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ShareQuery>,
) -> Result<Response> {
    let (_, session_data) =
        session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    if let Some(path) = q.path.as_deref().filter(|path| !path.is_empty()) {
        return Ok(
            Redirect::to(&format!("/admin/shares/new?path={}", encoded(path))).into_response(),
        );
    }
    let settings = runtime_settings(&state);
    let all_shares = database(state.db.clone(), |database| database.list_shares()).await?;
    let monthly = database(state.db.clone(), |database| {
        database.current_transfer_monthly_counts()
    })
    .await?;
    let statistics_started_at = database(state.db.clone(), |database| {
        database.transfer_statistics_started_at()
    })
    .await?;
    let statistics_started_label = DateTime::parse_from_rfc3339(&statistics_started_at)
        .map(|value| format_utc_minute(value.with_timezone(&Utc)))
        .unwrap_or(statistics_started_at);
    let active_count = all_shares
        .iter()
        .filter(|share| share_is_available(share))
        .count();
    let protected_count = all_shares
        .iter()
        .filter(|share| share.password_hash.is_some())
        .count();
    let query = q.q.as_deref().unwrap_or("").trim().to_string();
    let query_lower = query.to_lowercase();
    let status = match q.status.as_deref().unwrap_or("all") {
        value @ ("active" | "protected" | "expired" | "limit" | "inactive") => value,
        _ => "all",
    };
    let sort = if q.sort.as_deref() == Some("oldest") {
        "oldest"
    } else {
        "newest"
    };
    let mut shares = all_shares
        .into_iter()
        .filter(|share| {
            let matches_query = query_lower.is_empty()
                || share.relative_path.to_lowercase().contains(&query_lower)
                || share
                    .alias
                    .as_deref()
                    .is_some_and(|alias| alias.to_lowercase().contains(&query_lower));
            let matches_status = match status {
                "active" => share_is_available(share),
                "protected" => share.password_hash.is_some(),
                "expired" => share_is_expired(share),
                "limit" => share_limit_reached(share),
                "inactive" => !share.active,
                _ => true,
            };
            matches_query && matches_status
        })
        .collect::<Vec<_>>();
    if sort == "oldest" {
        shares.reverse();
    }
    const PAGE_SIZE: usize = 50;
    let total = shares.len();
    let total_pages = total.div_ceil(PAGE_SIZE).max(1);
    let page = q
        .page
        .unwrap_or(0)
        .min(1_000_000)
        .min(total_pages.saturating_sub(1));
    let start = page.saturating_mul(PAGE_SIZE).min(total);
    let end = start.saturating_add(PAGE_SIZE).min(total);
    let mut share_rows = String::new();
    for share in &shares[start..end] {
        let url = share_public_url(&settings, share);
        let display_name = share
            .alias
            .as_deref()
            .or_else(|| share.relative_path.rsplit('/').next())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| i18n::text(i18n::current_locale(), i18n::DEFAULT_SHARE_NAME));
        let (status_label, status_tone) = share_primary_status(share);
        let password_badge = if share.password_hash.is_some() {
            r#"<span class="vl-badge vl-badge--neutral"><vl-i18n key="auth.password"/></span>"#
        } else {
            ""
        };
        let maximum = share
            .max_downloads
            .map(|value| value.to_string())
            .unwrap_or_else(|| "∞".into());
        let progress = share
            .max_downloads
            .map(|maximum| {
                let value = share
                    .download_count
                    .saturating_mul(100)
                    .saturating_div(maximum.max(1))
                    .min(100);
                format!(r#"<progress max="100" value="{value}">{value}%</progress>"#)
            })
            .unwrap_or_default();
        let upload_settings = if share.is_directory && share.permission.can_upload() {
            let checked = if share.upload_conflict_strategy.can_overwrite() {
                "checked"
            } else {
                ""
            };
            format!(
                r#"<details><summary><vl-i18n key="share.upload_rules"/></summary><form method="post" action="/admin/shares/{}/upload-conflict" class="vl-stack"><input type="hidden" name="csrf" value="{}"><label class="vl-switch"><input type="checkbox" name="overwrite_allowed" value="1" {}><span><vl-i18n key="share.allow_overwrite"/><small><vl-i18n key="share.uploader_confirm_each"/></small></span></label><button class="vl-button vl-button--secondary"><vl-i18n key="common.apply"/></button></form></details>"#,
                share.id,
                esc(&session_data.csrf_token),
                checked
            )
        } else {
            String::new()
        };
        let upload_limit = share
            .max_upload_size
            .map(upload_limit_label)
            .unwrap_or_else(|| format!("global {}", human(settings.max_upload_size)));
        share_rows += &format!(
            r#"<article class="vl-share-row"><div class="vl-share-identity"><span class="vl-file-kind" aria-hidden="true"></span><div><strong>{}</strong><span class="vl-muted">/{}</span></div></div><div class="vl-share-url"><code>{}</code><button class="vl-button vl-button--secondary vl-button--small vl-copy-button" type="button" data-copy="{}" aria-label="<vl-i18n key="share.copy_aria"/>"><vl-i18n key="common.copy"/></button></div><div class="vl-share-badges"><span class="vl-badge vl-badge--accent">{}</span><span class="vl-badge vl-badge--{}">{}</span>{}</div><div class="vl-share-quota"><span>{} / {} <vl-i18n key="share.counted_transfers"/></span>{}<small class="vl-muted"><vl-i18n key="share.upload_limit_label"/>: {}</small></div><details class="vl-action-details"><summary class="vl-icon-button"><vl-i18n key="common.actions"/></summary><div class="vl-action-panel"><a class="vl-button vl-button--ghost" href="{}"><vl-i18n key="common.open"/></a><form method="post" action="/admin/shares/{}/toggle"><input type="hidden" name="csrf" value="{}"><button class="vl-button vl-button--ghost">{}</button></form><details><summary><vl-i18n key="account.change_password"/></summary><form method="post" action="/admin/shares/{}/password" class="vl-stack"><input type="hidden" name="csrf" value="{}"><label class="vl-field"><vl-i18n key="account.new_password"/><input type="password" name="password" minlength="{}" maxlength="{}"></label><label class="vl-field"><vl-i18n key="common.confirm"/><input type="password" name="password_confirm"></label><div class="vl-inline-actions"><button class="vl-button"><vl-i18n key="common.set"/></button><button class="vl-button vl-button--secondary" name="remove" value="1"><vl-i18n key="common.remove"/></button></div></form></details>{}<form method="post" action="/admin/shares/{}/delete"><input type="hidden" name="csrf" value="{}"><button class="vl-button vl-button--danger"><vl-i18n key="common.delete"/></button></form></div></details></article>"#,
            esc(display_name),
            esc(&share.relative_path),
            esc(&url),
            esc(&url),
            esc(share_permission_label(&share.permission)),
            status_tone,
            status_label,
            password_badge,
            share.download_count,
            maximum,
            progress,
            esc(&upload_limit),
            esc(&url),
            share.id,
            esc(&session_data.csrf_token),
            if share.active {
                i18n::text(i18n::current_locale(), i18n::DEACTIVATE_COMMON)
            } else {
                i18n::text(i18n::current_locale(), i18n::ACTIVATE)
            },
            share.id,
            esc(&session_data.csrf_token),
            settings.share_password_min_length,
            settings.share_password_max_length,
            upload_settings,
            share.id,
            esc(&session_data.csrf_token),
        );
    }
    if share_rows.is_empty() {
        share_rows = r#"<div class="vl-empty"><strong><vl-i18n key="share.no_links"/></strong><p class="vl-muted"><vl-i18n key="share.adjust_filters"/></p></div>"#.into();
    }
    let previous = (page > 0).then(|| share_list_url(&query, status, sort, page - 1));
    let next = (page + 1 < total_pages).then(|| share_list_url(&query, status, sort, page + 1));
    let body = format!(
        r#"<section class="vl-stat-strip" aria-label="<vl-i18n key="share.overview_aria"/>"><div><strong>{active_count}</strong><span><vl-i18n key="share.active_links"/></span></div><div><strong>{protected_count}</strong><span><vl-i18n key="share.password_protected_lower"/></span></div><div><strong>{}</strong><span><vl-i18n key="files.file"/> · {}</span></div><div><strong>{}</strong><span>ZIP · {}</span></div><div><strong>{}</strong><span><vl-i18n key="files.preview"/> · {}</span></div></section><p class="vl-muted"><vl-i18n key="share.monthly_values"/> {}.</p><section class="vl-panel"><form method="get" class="vl-toolbar"><label class="vl-field vl-search"><span class="vl-sr-only"><vl-i18n key="share.search_links"/></span><input name="q" value="{}" placeholder="<vl-i18n key="share.search_links"/>"></label><label class="vl-field"><span class="vl-sr-only"><vl-i18n key="common.status"/></span><select name="status"><option value="all" {}><vl-i18n key="common.all"/></option><option value="active" {}><vl-i18n key="common.active"/></option><option value="protected" {}><vl-i18n key="common.protected"/></option><option value="expired" {}><vl-i18n key="common.expired"/></option><option value="limit" {}><vl-i18n key="share.limit_reached"/></option><option value="inactive" {}><vl-i18n key="common.inactive"/></option></select></label><label class="vl-field"><span class="vl-sr-only"><vl-i18n key="files.sorting"/></span><select name="sort"><option value="newest" {}><vl-i18n key="files.newest_first"/></option><option value="oldest" {}><vl-i18n key="files.oldest_first"/></option></select></label><button class="vl-button"><vl-i18n key="common.filter"/></button></form><div class="vl-share-list">{share_rows}</div><nav class="vl-pagination" aria-label="<vl-i18n key="common.page_navigation"/>">{}<span><vl-i18n key="common.page_of"/> {} <vl-i18n key="common.of"/> {}</span>{}</nav></section>"#,
        monthly.download,
        esc(&monthly.month),
        monthly.zip_download,
        esc(&monthly.month),
        monthly.preview,
        esc(&monthly.month),
        esc(&statistics_started_label),
        esc(&query),
        selected(status, "all"),
        selected(status, "active"),
        selected(status, "protected"),
        selected(status, "expired"),
        selected(status, "limit"),
        selected(status, "inactive"),
        selected(sort, "newest"),
        selected(sort, "oldest"),
        previous
            .map(|url| format!(
                r#"<a class="vl-button vl-button--ghost" href="{}"><vl-i18n key="common.back"/></a>"#,
                esc(&url)
            ))
            .unwrap_or_default(),
        page + 1,
        total_pages,
        next.map(|url| format!(
            r#"<a class="vl-button vl-button--ghost" href="{}"><vl-i18n key="common.continue"/></a>"#,
            esc(&url)
        ))
        .unwrap_or_default(),
    );
    Ok(Html(admin_page(
        &state,
        PageId::Links,
        &body,
        false,
        &session_data.csrf_token,
    ))
    .into_response())
}

async fn share_create_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ShareQuery>,
) -> Result<Html<String>> {
    let (_, session_data) =
        session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let settings = runtime_settings(&state);
    let Some(raw_path) = query.path.as_deref().filter(|path| !path.is_empty()) else {
        let body = r#"<section class="vl-panel vl-empty"><strong><vl-i18n key="share.select_target"/></strong><p class="vl-muted"><vl-i18n key="share.open_browser"/></p><a class="vl-button" href="/admin"><vl-i18n key="share.to_browser"/></a></section>"#;
        return Ok(Html(admin_page(
            &state,
            PageId::CreateLink,
            body,
            false,
            &session_data.csrf_token,
        )));
    };
    let relative_path = path_security::validate_relative(raw_path)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Zielpfad"))?
        .to_string_lossy()
        .replace('\\', "/");
    let secure_root = state.secure_root.clone();
    let metadata_path = relative_path.clone();
    let metadata = tokio::task::spawn_blocking(move || secure_root.metadata(&metadata_path))
        .await
        .map_err(internal)?
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Zielpfad"))?;
    let is_directory = metadata.is_dir();
    let permission_fields = if is_directory {
        r#"<div class="vl-segmented" role="radiogroup" aria-label="<vl-i18n key="share.permission_aria"/>"><label><input type="radio" name="permission" value="download_only" checked><span><vl-i18n key="share.download_only"/></span></label><label><input type="radio" name="permission" value="upload_only"><span><vl-i18n key="share.upload_only"/></span></label><label><input type="radio" name="permission" value="download_upload"><span><vl-i18n key="share.download_upload"/></span></label></div>"#
    } else {
        r#"<input type="hidden" name="permission" value="download_only"><span class="vl-badge vl-badge--accent"><vl-i18n key="share.download_only"/></span><p class="vl-muted"><vl-i18n key="share.upload_folder_only"/></p>"#
    };
    let upload_rules = if is_directory {
        format!(
            r#"<section class="vl-form-section" data-upload-rules><h2><vl-i18n key="share.step_upload"/></h2><div class="vl-form-grid"><label class="vl-field"><vl-i18n key="share.max_file"/><input name="max_upload_size_gb" type="number" min="1" step="1" placeholder="Global: {} GB"><small><vl-i18n key="share.empty_global"/></small></label><label class="vl-switch"><input type="checkbox" name="overwrite_allowed" value="1"><span><vl-i18n key="share.existing_replace"/><small><vl-i18n key="share.uploader_confirm"/></small></span></label></div></section>"#,
            display_limit_unit_floor(settings.max_upload_size, GB)
        )
    } else {
        String::new()
    };
    let url_preview = format!(
        "{}/v/••••••••",
        settings.public_base_url.trim_end_matches('/')
    );
    let body = format!(
        r#"<div class="vl-create-layout"><form method="post" action="/admin/shares" class="vl-panel vl-stack" data-share-create><input type="hidden" name="csrf" value="{}"><input type="hidden" name="path" value="{}"><input type="hidden" name="expires_tz_offset_minutes" data-tz-offset value="0"><section class="vl-target-card"><div><span class="vl-eyebrow"><vl-i18n key="share.selected_target"/></span><strong>/{}</strong><small class="vl-muted">{}</small></div><a class="vl-button vl-button--ghost" href="/admin"><vl-i18n key="share.change_target"/></a></section><section class="vl-form-section"><h2><vl-i18n key="share.step_permission"/></h2>{permission_fields}</section><section class="vl-form-section"><h2><vl-i18n key="share.step_link"/></h2><div class="vl-form-grid"><label class="vl-field"><vl-i18n key="share.short_alias"/><input name="alias" pattern="[A-Za-z0-9_-]{{3,32}}" data-share-alias><small><vl-i18n key="share.alias_help"/></small></label>{}<label class="vl-field"><vl-i18n key="share.max_transfers"/><input name="max_downloads" type="number" min="1"><small><vl-i18n key="share.empty_unlimited"/></small></label></div></section><section class="vl-form-section"><h2><vl-i18n key="share.step_protection"/></h2><label class="vl-switch"><input type="checkbox" data-password-toggle><span><vl-i18n key="share.password_protection"/><small><vl-i18n key="share.password_enable"/></small></span></label><div class="vl-form-grid" data-password-fields><label class="vl-field"><vl-i18n key="auth.password"/><input name="password" type="password" minlength="{}" maxlength="{}" autocomplete="new-password"></label><label class="vl-field"><vl-i18n key="account.confirm_password"/><input name="password_confirm" type="password" autocomplete="new-password"></label></div></section>{upload_rules}<button class="vl-button vl-button--primary" type="submit"><vl-i18n key="share.create_secure"/></button></form><aside class="vl-panel vl-review-card" data-share-review><h2><vl-i18n key="share.review"/></h2><dl class="vl-review-list"><div><dt><vl-i18n key="common.target"/></dt><dd>/{}</dd></div><div><dt><vl-i18n key="share.permission"/></dt><dd data-review-permission><vl-i18n key="share.download_only"/></dd></div><div><dt><vl-i18n key="auth.password"/></dt><dd data-review-password><vl-i18n key="share.no_password"/></dd></div><div><dt><vl-i18n key="share.limit"/></dt><dd data-review-limit><vl-i18n key="common.unlimited"/></dd></div></dl><div class="vl-field"><span><vl-i18n key="share.url_preview"/></span><code data-review-url>{}</code></div><p class="vl-muted"><vl-i18n key="share.audit_help"/></p></aside></div>"#,
        esc(&session_data.csrf_token),
        esc(&relative_path),
        esc(&relative_path),
        i18n::text(
            i18n::current_locale(),
            if is_directory {
                i18n::FOLDER
            } else {
                i18n::FILE
            }
        ),
        expiry_picker_html(),
        settings.share_password_min_length,
        settings.share_password_max_length,
        esc(&relative_path),
        esc(&url_preview),
    );
    let body = body.replacen(
        r#"type="checkbox" data-password-toggle"#,
        r#"type="checkbox" name="password_enabled" value="1" data-password-toggle"#,
        1,
    );
    Ok(Html(admin_page(
        &state,
        PageId::CreateLink,
        &body,
        false,
        &session_data.csrf_token,
    )))
}

#[allow(dead_code)]
async fn share_create_page_legacy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ShareQuery>,
) -> Result<Html<String>> {
    let (_, s) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let settings = runtime_settings(&state);
    let mut rows = String::new();
    let shares = database(state.db.clone(), |db| db.list_shares()).await?;
    for sh in shares {
        let url = format!(
            "{}/v/{}",
            settings.public_base_url.trim_end_matches('/'),
            sh.token
        );
        let upload_limit = sh
            .max_upload_size
            .map(upload_limit_label)
            .unwrap_or_else(|| format!("global ({})", human(settings.max_upload_size)));
        let upload_conflict = match sh.upload_conflict_strategy {
            UploadConflictStrategy::Reject => "Konflikt: ablehnen",
            UploadConflictStrategy::OverwriteAllowed => "Konflikt: Überschreiben erlaubt",
        };
        let upload_conflict_form = if sh.is_directory && sh.permission.can_upload() {
            let checked = if sh.upload_conflict_strategy.can_overwrite() {
                "checked"
            } else {
                ""
            };
            format!(
                r#"<div class="overwrite-panel"><form method="post" action="/admin/shares/{}/upload-conflict" class="button-group"><input type="hidden" name="csrf" value="{}"><label class="toggle-card"><input type="checkbox" name="overwrite_allowed" value="1" {}><span>Überschreiben erlauben<small>Kann jederzeit wieder deaktiviert werden.</small></span></label><button class="secondary">Übernehmen</button></form></div>"#,
                sh.id,
                esc(&s.csrf_token),
                checked
            )
        } else {
            String::new()
        };
        let upload_limit = format!("{upload_limit}; {upload_conflict}");
        rows += &format!(
            r#"<div class="share-card"><div class="share-main"><div><small class="muted">Pfad</small><br><code>{}</code><br><small>{}</small></div><div><small class="muted">Recht</small><br>{}</div><div><small class="muted">Status</small><br>{}<br>{}<br><small>Uploadlimit: {}</small></div><div><small class="muted">Downloads</small><br>{}/{}</div><div><small class="muted">Aktionen</small><div class="share-actions"><a class="button secondary" href="{}">Öffnen</a><button type="button" data-copy="{}">Kopieren</button><form method="post" action="/admin/shares/{}/toggle"><input type="hidden" name="csrf" value="{}"><button>{}</button></form><form method="post" action="/admin/shares/{}/delete"><input type="hidden" name="csrf" value="{}"><button class="danger">Löschen</button></form></div><form method="post" action="/admin/shares/{}/password" class="password-actions"><input type="hidden" name="csrf" value="{}"><input type="password" name="password" minlength="{}" maxlength="{}" placeholder="Passwort ersetzen"><input type="password" name="password_confirm" placeholder="Bestätigen"><button>Setzen</button><button class="secondary" name="remove" value="1">Entfernen</button></form></div></div>{}</div>"#,
            esc(&sh.relative_path),
            esc(&url),
            esc(sh.permission.as_str()),
            if sh.active { "aktiv" } else { "inaktiv" },
            if sh.password_hash.is_some() {
                "passwortgeschützt"
            } else {
                "ohne Passwort"
            },
            esc(&upload_limit),
            sh.download_count,
            sh.max_downloads
                .map(|v| v.to_string())
                .unwrap_or_else(|| "∞".into()),
            esc(&url),
            esc(&url),
            sh.id,
            esc(&s.csrf_token),
            if sh.active {
                "Deaktivieren"
            } else {
                "Aktivieren"
            },
            sh.id,
            esc(&s.csrf_token),
            sh.id,
            esc(&s.csrf_token),
            settings.share_password_min_length,
            settings.share_password_max_length,
            upload_conflict_form,
        );
    }
    let selected_raw = q.path.unwrap_or_default();
    let selected = if selected_raw.is_empty() {
        None
    } else {
        let rel = path_security::validate_relative(&selected_raw)
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Zielpfad"))?
            .to_string_lossy()
            .replace('\\', "/");
        let secure_root = state.secure_root.clone();
        let metadata_path = rel.clone();
        let metadata = tokio::task::spawn_blocking(move || secure_root.metadata(&metadata_path))
            .await
            .map_err(internal)?
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Zielpfad"))?;
        Some((rel, metadata.is_dir()))
    };
    let create_section = if let Some((selected, is_dir)) = selected {
        let permissions = if is_dir {
            r#"<option value="download_only">Download only</option><option value="upload_only">Upload only</option><option value="download_upload">Download + Upload</option>"#
        } else {
            r#"<option value="download_only">Download only</option>"#
        };
        let upload_hint = if is_dir {
            String::new()
        } else {
            r#"<p class="muted">Upload-Rechte sind nur für Ordnerlinks verfügbar. Für Uploads bitte im Dateibrowser einen Zielordner auswählen.</p>"#.into()
        };
        format!(
            r#"<section><h1>Link erstellen</h1><div class="form-card"><h2>Ziel</h2><p>Ausgewähltes Ziel: <code>/{}</code> <span class="muted">({})</span></p>{}<p><a class="button secondary" href="/admin">Anderen Pfad im Dateibrowser auswählen</a></p></div><form method="post"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="path" value="{}"><input type="hidden" name="expires_tz_offset_minutes" data-tz-offset value="0"><div class="form-card"><h2>Freigabeoptionen</h2><div class="form-grid"><label>Berechtigung<br><select name="permission">{}</select></label><label class="toggle-card"><input type="checkbox" name="overwrite_allowed" value="1"><span>Überschreiben für Uploads erlauben<small>Uploader müssen das Ersetzen pro Upload zusätzlich bestätigen.</small></span></label></div></div><div class="form-card"><h2>Limits und Schutz</h2><div class="form-grid"><label>Alias (optional)<br><input name="alias" pattern="[A-Za-z0-9_-]{{3,32}}"></label>{}<label>Max. Downloads<br><input name="max_downloads" type="number" min="1"></label><label>Uploadlimit GB (optional)<br><input name="max_upload_size_gb" type="number" min="1" step="1" placeholder="global: {}"></label><label>Passwort (optional)<br><input name="password" type="password" minlength="{}" maxlength="{}"></label><label>Passwort bestätigen<br><input name="password_confirm" type="password"></label></div></div><button>Erstellen</button></form></section>"#,
            esc(&selected),
            if is_dir { "Ordner" } else { "Datei" },
            upload_hint,
            esc(&s.csrf_token),
            esc(&selected),
            permissions,
            expiry_picker_html(),
            display_limit_unit_floor(settings.max_upload_size, GB),
            settings.share_password_min_length,
            settings.share_password_max_length,
        )
    } else {
        r#"<section><h1>Link erstellen</h1><p>Bitte zuerst im Dateibrowser eine Datei oder einen Ordner auswählen.</p><p><a class="button secondary" href="/admin">Pfad im Dateibrowser auswählen</a></p></section>"#.into()
    };
    let body = format!(
        r#"{create_section}<section><h1>Freigaben</h1>{}</section>"#,
        rows
    );
    Ok(Html(admin_page(
        &state,
        PageId::Links,
        &body,
        false,
        &s.csrf_token,
    )))
}
#[derive(Deserialize)]
struct CreateShare {
    csrf: String,
    path: String,
    permission: String,
    alias: Option<String>,
    expires_local: Option<String>,
    expires_tz_offset_minutes: Option<String>,
    max_downloads: Option<String>,
    max_upload_size: Option<String>,
    max_upload_size_gb: Option<String>,
    password: Option<String>,
    password_confirm: Option<String>,
    password_enabled: Option<String>,
    overwrite_allowed: Option<String>,
}
async fn create_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<CreateShare>,
) -> Result<Redirect> {
    let (_, s) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&s, &f.csrf)?;
    let _storage_guard = state.storage_mutation.lock().await;
    let rel = path_security::validate_relative(&f.path)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Zielpfad"))?
        .to_string_lossy()
        .replace('\\', "/");
    let secure_root = state.secure_root.clone();
    let metadata_path = rel.clone();
    let target_metadata = tokio::task::spawn_blocking(move || secure_root.metadata(&metadata_path))
        .await
        .map_err(internal)?
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Zielpfad"))?;
    let permission = Permission::parse(&f.permission)
        .ok_or(AppError(StatusCode::BAD_REQUEST, "Ungültige Berechtigung"))?;
    if target_metadata.is_file() && permission.can_upload() {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Uploads sind im MVP nur für Ordnerlinks erlaubt",
        ));
    }
    let alias = f.alias.filter(|a| !a.is_empty());
    if alias.as_ref().is_some_and(|a| {
        a.len() < 3
            || a.len() > 32
            || !a
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    }) {
        return Err(AppError(StatusCode::BAD_REQUEST, "Ungültiger Alias"));
    }
    let exp = parse_expiry(
        f.expires_local.as_deref(),
        f.expires_tz_offset_minutes.as_deref(),
    )?;
    if exp.is_some_and(|e| e <= Utc::now()) {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Ablaufdatum liegt in der Vergangenheit",
        ));
    }
    let settings = runtime_settings(&state);
    let token = auth::random_token(24);
    let password = f.password.filter(|value| !value.is_empty());
    let password_confirm = f.password_confirm.filter(|value| !value.is_empty());
    let password_requested = f.password_enabled.as_deref() == Some("1")
        || password.is_some()
        || password_confirm.is_some();
    if password_requested && (password.is_none() || password_confirm.is_none()) {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Passwort und Bestätigung sind für den Passwortschutz verpflichtend",
        ));
    }
    if password != password_confirm {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Passwörter stimmen nicht überein",
        ));
    }
    let password_protected = password.is_some();
    let password_hash = if let Some(password) = password {
        validate_share_password(&settings, &password)?;
        Some(
            tokio::task::spawn_blocking(move || auth::hash_password(&password))
                .await
                .map_err(internal)?
                .map_err(internal)?,
        )
    } else {
        None
    };
    let permission_detail = permission.as_str().to_string();
    let is_directory = target_metadata.is_dir();
    let max_downloads = f
        .max_downloads
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiges Übertragungslimit"))?;
    if max_downloads == Some(0) {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Das Übertragungslimit muss mindestens 1 sein",
        ));
    }
    let max_upload_size = if let Some(value) = f
        .max_upload_size_gb
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(parse_unit_to_bytes(value, GB, "Ungültiges Uploadlimit")?)
    } else {
        let parsed = f
            .max_upload_size
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.parse::<u64>())
            .transpose()
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiges Uploadlimit"))?;
        parsed
    };
    if max_upload_size == Some(0) {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Uploadlimit muss mindestens 1 Byte sein",
        ));
    }
    let upload_conflict_strategy =
        if f.overwrite_allowed.as_deref() == Some("1") && is_directory && permission.can_upload() {
            UploadConflictStrategy::OverwriteAllowed
        } else {
            UploadConflictStrategy::Reject
        };
    let audit_detail = format!(
        "path={rel};permission={permission_detail};alias={};expires_at={};transfer_limit={};upload_limit={};password_protected={password_protected};overwrite_allowed={}",
        alias.as_deref().unwrap_or(""),
        exp.map(|value| value.to_rfc3339()).unwrap_or_default(),
        max_downloads.map(|value| value.to_string()).unwrap_or_default(),
        max_upload_size.map(|value| value.to_string()).unwrap_or_default(),
        upload_conflict_strategy.can_overwrite(),
    );
    let admin_id = s.admin_id;
    let id = database(state.db.clone(), move |db| {
        db.create_share(
            &token,
            alias.as_deref(),
            &rel,
            is_directory,
            &permission,
            exp,
            max_downloads,
            max_upload_size,
            admin_id,
            password_hash.as_deref(),
            &upload_conflict_strategy,
        )
    })
    .await
    .map_err(|_| AppError(StatusCode::CONFLICT, "Token oder Alias bereits vorhanden"))?;
    audit(
        &state,
        s.username,
        "share_created",
        Some(id.to_string()),
        Some(audit_detail),
    )
    .await;
    Ok(Redirect::to("/admin/shares"))
}
async fn toggle_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Redirect> {
    let (_, s) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&s, &f.csrf)?;
    let sh = database(state.db.clone(), |db| db.list_shares())
        .await?
        .into_iter()
        .find(|v| v.id == id)
        .ok_or(AppError(StatusCode::NOT_FOUND, "Link nicht gefunden"))?;
    database(state.db.clone(), move |db| {
        db.set_share_active(id, !sh.active)
    })
    .await?;
    audit(
        &state,
        s.username,
        "share_toggled",
        Some(id.to_string()),
        None,
    )
    .await;
    Ok(Redirect::to("/admin/shares"))
}

#[derive(Deserialize)]
struct UploadConflictForm {
    csrf: String,
    strategy: Option<String>,
    overwrite_allowed: Option<String>,
}

async fn set_share_upload_conflict(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(form): Form<UploadConflictForm>,
) -> Result<Redirect> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    let strategy = if let Some(strategy) = form.strategy.as_deref() {
        UploadConflictStrategy::parse(strategy).ok_or(AppError(
            StatusCode::BAD_REQUEST,
            "Ungültige Upload-Konfliktstrategie",
        ))?
    } else if form.overwrite_allowed.as_deref() == Some("1") {
        UploadConflictStrategy::OverwriteAllowed
    } else {
        UploadConflictStrategy::Reject
    };
    let share = database(state.db.clone(), |db| db.list_shares())
        .await?
        .into_iter()
        .find(|share| share.id == id)
        .ok_or(AppError(StatusCode::NOT_FOUND, "Link nicht gefunden"))?;
    if !share.is_directory || !share.permission.can_upload() {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Überschreiben ist nur für Ordnerlinks mit Uploadrecht erlaubt",
        ));
    }
    let stored_strategy = strategy.clone();
    let changed = database(state.db.clone(), move |db| {
        db.set_upload_conflict_strategy(id, &stored_strategy)
    })
    .await?;
    if !changed {
        return Err(AppError(StatusCode::NOT_FOUND, "Link nicht gefunden"));
    }
    audit(
        &state,
        session.username,
        "share_upload_conflict_updated",
        Some(id.to_string()),
        Some(strategy.as_str().to_string()),
    )
    .await;
    Ok(Redirect::to("/admin/shares"))
}

#[derive(Deserialize)]
struct SharePasswordForm {
    csrf: String,
    password: Option<String>,
    password_confirm: Option<String>,
    remove: Option<String>,
}

async fn set_share_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(form): Form<SharePasswordForm>,
) -> Result<Redirect> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    if !database(state.db.clone(), |db| db.list_shares())
        .await?
        .iter()
        .any(|share| share.id == id)
    {
        return Err(AppError(StatusCode::NOT_FOUND, "Link nicht gefunden"));
    }
    let remove = form.remove.as_deref() == Some("1");
    let password_hash = if remove {
        None
    } else {
        let password = form.password.unwrap_or_default();
        if password != form.password_confirm.unwrap_or_default() {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "Passwörter stimmen nicht überein",
            ));
        }
        let settings = runtime_settings(&state);
        validate_share_password(&settings, &password)?;
        Some(
            tokio::task::spawn_blocking(move || auth::hash_password(&password))
                .await
                .map_err(internal)?
                .map_err(internal)?,
        )
    };
    let changed = database(state.db.clone(), move |db| {
        db.set_share_password(id, password_hash.as_deref())
    })
    .await?;
    if !changed {
        return Err(AppError(StatusCode::NOT_FOUND, "Link nicht gefunden"));
    }
    let action = if remove {
        "share_password_removed"
    } else {
        "share_password_set"
    };
    audit(&state, session.username, action, Some(id.to_string()), None).await;
    Ok(Redirect::to("/admin/shares"))
}

async fn delete_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Redirect> {
    let (_, s) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&s, &f.csrf)?;
    database(state.db.clone(), move |db| db.delete_share(id)).await?;
    audit(
        &state,
        s.username,
        "share_deleted",
        Some(id.to_string()),
        None,
    )
    .await;
    Ok(Redirect::to("/admin/shares"))
}

#[derive(Deserialize)]
struct SecurityKeyRegistrationStart {
    csrf: String,
    current_password: String,
    label: String,
}

async fn start_security_key_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SecurityKeyRegistrationStart>,
) -> Result<Json<webauthn_rs::prelude::CreationChallengeResponse>> {
    let (token, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &body.csrf)?;
    let label = body.label.trim();
    if label.is_empty() || label.chars().count() > 80 {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Ungültiger Schlüsselname",
        ));
    }
    let username = session.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username))
        .await?
        .ok_or(AppError(StatusCode::UNAUTHORIZED, "Anmeldung erforderlich"))?;
    let password_hash = admin.password_hash;
    let current_password = body.current_password;
    let password_valid = tokio::task::spawn_blocking(move || {
        auth::verify_password(&password_hash, &current_password)
    })
    .await
    .map_err(internal)?;
    if !password_valid {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    let admin_id = session.admin_id;
    let rows = database(state.db.clone(), move |db| {
        db.admin_webauthn_credentials(admin_id)
    })
    .await?;
    let existing = decode_security_keys(&rows)?;
    let challenge = state
        .webauthn
        .start_registration(&token, admin_id, &session.username, &existing)
        .map_err(|_| {
            AppError(
                StatusCode::BAD_REQUEST,
                "Sicherheitsschlüssel konnte nicht gestartet werden",
            )
        })?;
    Ok(Json(challenge))
}

#[derive(Deserialize)]
struct SecurityKeyRegistrationFinish {
    csrf: String,
    label: String,
    credential: webauthn_rs::prelude::RegisterPublicKeyCredential,
}

async fn finish_security_key_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SecurityKeyRegistrationFinish>,
) -> Result<Json<serde_json::Value>> {
    let (token, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &body.csrf)?;
    let label = body.label.trim().to_string();
    if label.is_empty() || label.chars().count() > 80 {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Ungültiger Schlüsselname",
        ));
    }
    let key = state
        .webauthn
        .finish_registration(&token, session.admin_id, &body.credential)
        .map_err(|_| {
            AppError(
                StatusCode::BAD_REQUEST,
                "Ungültige Sicherheitsschlüssel-Antwort",
            )
        })?;
    let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.cred_id());
    let credential_json = serde_json::to_string(&key).map_err(internal)?;
    let admin_id = session.admin_id;
    database(state.db.clone(), move |db| {
        db.add_admin_webauthn_credential(admin_id, &label, &credential_id, &credential_json)
    })
    .await
    .map_err(|_| {
        AppError(
            StatusCode::CONFLICT,
            "Sicherheitsschlüssel ist bereits registriert",
        )
    })?;
    audit(
        &state,
        session.username,
        "webauthn_credential_added",
        None,
        None,
    )
    .await;
    Ok(Json(serde_json::json!({"redirect":"/admin/account"})))
}

#[derive(Deserialize)]
struct DeleteSecurityKeyForm {
    csrf: String,
    current_password: String,
    current_code: String,
}

async fn delete_security_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(form): Form<DeleteSecurityKeyForm>,
) -> Result<Redirect> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    let username = session.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username))
        .await?
        .ok_or(AppError(StatusCode::UNAUTHORIZED, "Anmeldung erforderlich"))?;
    let password_hash = admin.password_hash;
    let password = form.current_password;
    let password_valid =
        tokio::task::spawn_blocking(move || auth::verify_password(&password_hash, &password))
            .await
            .map_err(internal)?;
    if !password_valid || !auth::verify_totp_now(&admin.totp_secret, &form.current_code) {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    let admin_id = session.admin_id;
    let deleted = database(state.db.clone(), move |db| {
        db.delete_admin_webauthn_credential(id, admin_id)
    })
    .await?;
    if !deleted {
        return Err(AppError(
            StatusCode::CONFLICT,
            "Sicherheitsschlüssel nicht gefunden",
        ));
    }
    audit(
        &state,
        session.username,
        "webauthn_credential_deleted",
        Some(id.to_string()),
        None,
    )
    .await;
    Ok(Redirect::to("/admin/account"))
}

async fn account_page(State(state): State<AppState>, headers: HeaderMap) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let admin_id = session.admin_id;
    let security_keys = database(state.db.clone(), move |db| {
        db.admin_webauthn_credentials(admin_id)
    })
    .await?;
    let security_key_rows = if security_keys.is_empty() {
        r#"<p class="vl-muted"><vl-i18n key="account.security_keys_empty"/></p>"#.to_string()
    } else {
        security_keys
            .iter()
            .map(|key| format!(
                r#"<article class="vl-share-row"><div><strong>{}</strong><small class="vl-muted">{}</small></div><form method="post" action="/admin/account/security-keys/{}/delete" class="vl-stack"><input type="hidden" name="csrf" value="{}"><input name="current_password" type="password" autocomplete="current-password" placeholder="Passwort" required><input name="current_code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{{6}}" placeholder="TOTP" required><button class="vl-button vl-button--danger"><vl-i18n key="common.delete"/></button></form></article>"#,
                esc(&key.label),
                esc(&key.created_at),
                key.id,
                esc(&session.csrf_token),
            ))
            .collect::<String>()
    };
    let body = format!(
        r#"<div class="vl-create-layout"><section class="vl-panel vl-stack"><div><p class="vl-eyebrow"><vl-i18n key="account.current_user"/></p><h2>{username}</h2></div><form method="post" action="/admin/account/password" class="vl-stack"><input type="hidden" name="csrf" value="{csrf}"><h2><vl-i18n key="account.change_password"/></h2><label class="vl-field"><vl-i18n key="account.current_password"/><input name="current_password" type="password" autocomplete="current-password" required></label><label class="vl-field"><vl-i18n key="account.new_password"/><input name="new_password" type="password" minlength="14" autocomplete="new-password" required><small><vl-i18n key="error.password_min"/></small></label><label class="vl-field"><vl-i18n key="account.confirm_password"/><input name="password_confirm" type="password" minlength="14" autocomplete="new-password" required></label><button class="vl-button" type="submit"><vl-i18n key="account.change_password"/></button></form></section><aside class="vl-panel vl-stack"><h2><vl-i18n key="account.change_mfa"/></h2><p class="vl-muted"><vl-i18n key="account.old_mfa_valid"/></p><form method="post" action="/admin/account/mfa/start" class="vl-stack"><input type="hidden" name="csrf" value="{csrf}"><label class="vl-field"><vl-i18n key="account.current_password"/><input name="current_password" type="password" autocomplete="current-password" required></label><label class="vl-field"><vl-i18n key="account.current_mfa_code"/><input name="current_code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{{6}}" required></label><button class="vl-button" type="submit"><vl-i18n key="common.continue"/></button></form></aside></div><section class="vl-panel vl-stack"><h2><vl-i18n key="account.security_keys"/></h2><p class="vl-muted"><vl-i18n key="account.security_keys_help"/></p>{security_key_rows}<form class="vl-stack" data-security-key-register data-csrf="{csrf}"><label class="vl-field"><vl-i18n key="account.security_key_label"/><input name="label" maxlength="80" required></label><label class="vl-field"><vl-i18n key="account.current_password"/><input name="current_password" type="password" autocomplete="current-password" required></label><button class="vl-button" type="submit"><vl-i18n key="account.security_key_add"/></button><p class="vl-muted" data-security-key-status></p></form></section>"#,
        username = esc(&session.username),
        csrf = esc(&session.csrf_token),
        security_key_rows = security_key_rows,
    );
    Ok(Html(admin_page(
        &state,
        PageId::Account,
        &body,
        false,
        &session.csrf_token,
    )))
}

#[derive(Deserialize)]
struct AccountPasswordForm {
    csrf: String,
    current_password: String,
    new_password: String,
    password_confirm: String,
}

async fn change_account_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AccountPasswordForm>,
) -> Result<Response> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    let limiter_key = format!("account-password:{}", session.admin_id);
    if !state.limiter.allowed(&limiter_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele Passwortversuche",
        ));
    }

    let username = session.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username))
        .await?
        .ok_or(AppError(StatusCode::UNAUTHORIZED, "Anmeldung erforderlich"))?;
    let expected_hash = admin.password_hash.clone();
    let verification_hash = expected_hash.clone();
    let current_password = form.current_password;
    let current_password_valid = tokio::task::spawn_blocking(move || {
        auth::verify_password(&verification_hash, &current_password)
    })
    .await
    .map_err(internal)?;
    if !current_password_valid {
        state.limiter.failure(&limiter_key);
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    state.limiter.success(&limiter_key);

    if form.new_password != form.password_confirm {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Passwörter stimmen nicht überein",
        ));
    }
    if form.new_password.chars().count() < 14 {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Passwort muss mindestens 14 Zeichen enthalten",
        ));
    }
    let new_password = form.new_password;
    let new_hash = tokio::task::spawn_blocking(move || auth::hash_password(&new_password))
        .await
        .map_err(internal)?
        .map_err(internal)?;
    let admin_id = session.admin_id;
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let outcome = database(state.db.clone(), move |db| {
        db.change_admin_password_cas(
            admin_id,
            &expected_hash,
            &new_hash,
            audit_client_ip.as_deref(),
        )
    })
    .await?;
    match outcome {
        AdminPasswordChangeOutcome::Changed => Ok(redirect_with_cookie(
            "/login",
            clear_session_cookie(&state),
        )?),
        AdminPasswordChangeOutcome::StalePassword => Err(AppError(
            StatusCode::CONFLICT,
            "Kontoänderung fehlgeschlagen.",
        )),
        AdminPasswordChangeOutcome::Inactive | AdminPasswordChangeOutcome::NotFound => {
            Err(AppError(StatusCode::UNAUTHORIZED, "Anmeldung erforderlich"))
        }
    }
}

#[derive(Deserialize)]
struct AccountMfaStartForm {
    csrf: String,
    current_password: String,
    current_code: String,
}

async fn start_account_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AccountMfaStartForm>,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    let limiter_key = format!("account-mfa-start:{}", session.admin_id);
    if !state.limiter.allowed(&limiter_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele MFA-Versuche",
        ));
    }

    let username = session.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username))
        .await?
        .ok_or(AppError(StatusCode::UNAUTHORIZED, "Anmeldung erforderlich"))?;
    let verification_hash = admin.password_hash;
    let current_password = form.current_password;
    let current_password_valid = tokio::task::spawn_blocking(move || {
        auth::verify_password(&verification_hash, &current_password)
    })
    .await
    .map_err(internal)?;
    let current_mfa_valid = auth::verify_totp_now(&admin.totp_secret, &form.current_code);
    if !current_password_valid || !current_mfa_valid {
        state.limiter.failure(&limiter_key);
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    state.limiter.success(&limiter_key);

    let enrollment_token = auth::random_token(32);
    let new_secret = auth::new_totp_secret();
    let admin_id = session.admin_id;
    let token_for_db = enrollment_token.clone();
    let secret_for_db = new_secret.clone();
    let outcome = database(state.db.clone(), move |db| {
        db.start_admin_mfa_enrollment(admin_id, &token_for_db, &secret_for_db)
    })
    .await?;
    let expires_at = match outcome {
        AdminMfaEnrollmentStartOutcome::Started { expires_at } => expires_at,
        AdminMfaEnrollmentStartOutcome::AdminInactive
        | AdminMfaEnrollmentStartOutcome::AdminNotFound => {
            return Err(AppError(StatusCode::UNAUTHORIZED, "Anmeldung erforderlich"));
        }
    };
    let expires_at = DateTime::parse_from_rfc3339(&expires_at)
        .map(|value| format_utc_minute(value.with_timezone(&Utc)))
        .unwrap_or(expires_at);
    let otpauth = otpauth_url(&session.username, &new_secret);
    let qr = qr_svg(&otpauth)?;
    let body = format!(
        r#"<section class="vl-panel vl-stack"><div><p class="vl-eyebrow"><vl-i18n key="account.change_mfa"/></p><h2><vl-i18n key="account.mfa_enrollment_flow"/></h2></div><p class="vl-muted"><vl-i18n key="account.old_mfa_valid"/></p><div class="qr-card" aria-label="TOTP QR-Code">{qr}</div><div class="secret-block"><code>{secret}</code><code>{otpauth}</code></div><p class="vl-muted"><vl-i18n key="public.valid_until"/>: {expires_at}</p><form method="post" action="/admin/account/mfa/confirm" class="vl-stack"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="enrollment_token" value="{token}"><label class="vl-field"><vl-i18n key="account.new_mfa_test_code"/><input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{{6}}" required></label><div class="vl-inline-actions"><button class="vl-button" type="submit"><vl-i18n key="common.confirm"/></button><a class="vl-button vl-button--secondary" href="/admin/account"><vl-i18n key="common.cancel"/></a></div></form></section>"#,
        qr = qr,
        secret = esc(&new_secret),
        otpauth = esc(&otpauth),
        expires_at = esc(&expires_at),
        csrf = esc(&session.csrf_token),
        token = esc(&enrollment_token),
    );
    Ok(Html(admin_page_without_locale_switcher(
        &state,
        PageId::Account,
        &body,
        false,
        &session.csrf_token,
    )))
}

#[derive(Deserialize)]
struct AccountMfaConfirmForm {
    csrf: String,
    enrollment_token: String,
    code: String,
}

async fn confirm_account_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AccountMfaConfirmForm>,
) -> Result<Response> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    if form.enrollment_token.is_empty() || form.enrollment_token.len() > 256 {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Kontoänderung fehlgeschlagen.",
        ));
    }
    let limiter_key = format!("account-mfa-confirm:{}", session.admin_id);
    if !state.limiter.allowed(&limiter_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele MFA-Versuche",
        ));
    }
    let admin_id = session.admin_id;
    let lookup_token = form.enrollment_token.clone();
    let enrollment = database(state.db.clone(), move |db| {
        db.admin_mfa_enrollment(admin_id, &lookup_token)
    })
    .await?
    .ok_or(AppError(
        StatusCode::CONFLICT,
        "Kontoänderung fehlgeschlagen.",
    ))?;
    if !auth::verify_totp_now(&enrollment.totp_secret, &form.code) {
        state.limiter.failure(&limiter_key);
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültiger MFA-Code"));
    }
    state.limiter.success(&limiter_key);
    let activation_token = form.enrollment_token;
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let outcome = database(state.db.clone(), move |db| {
        db.activate_admin_mfa_enrollment(admin_id, &activation_token, audit_client_ip.as_deref())
    })
    .await?;
    match outcome {
        AdminMfaEnrollmentActivationOutcome::Activated => Ok(redirect_with_cookie(
            "/login",
            clear_session_cookie(&state),
        )?),
        AdminMfaEnrollmentActivationOutcome::NotFoundOrExpired => Err(AppError(
            StatusCode::CONFLICT,
            "Kontoänderung fehlgeschlagen.",
        )),
    }
}

fn valid_username(username: &str) -> bool {
    username.len() >= 3
        && username.len() <= 64
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

async fn admins_page_v3(
    State(state): State<AppState>,
    Query(query): Query<AdminNoticeQuery>,
    headers: HeaderMap,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let admins = database(state.db.clone(), |db| db.list_admins()).await?;
    let mut active_rows = String::new();
    let mut inactive_rows = String::new();
    for admin in admins {
        let action = if admin.id == session.admin_id {
            r#"<div class="admin-actions"><span class="pill"><vl-i18n key="admins.current"/></span></div>"#
                .to_string()
        } else {
            let status_action = if admin.active {
                format!(
                    r#"<form method="post" action="/admin/admins/{}/deactivate"><input type="hidden" name="csrf" value="{}"><button class="secondary"><vl-i18n key="admins.deactivate"/></button></form>"#,
                    admin.id,
                    esc(&session.csrf_token)
                )
            } else {
                format!(
                    r#"<form method="post" action="/admin/admins/{}/activate"><input type="hidden" name="csrf" value="{}"><button><vl-i18n key="admins.activate"/></button></form>"#,
                    admin.id,
                    esc(&session.csrf_token)
                )
            };
            format!(
                r#"<div class="admin-actions"><div class="button-group">{}<form method="post" action="/admin/admins/{}/totp"><input type="hidden" name="csrf" value="{}"><button class="secondary"><vl-i18n key="admins.reset_mfa"/></button></form></div><form method="post" action="/admin/admins/{}/password" class="admin-reset-form"><input type="hidden" name="csrf" value="{}"><label><vl-i18n key="account.new_password"/><input name="password" type="password" minlength="14" required></label><label><vl-i18n key="common.confirm"/><input name="password_confirm" type="password" minlength="14" required></label><button><vl-i18n key="admins.set_password"/></button></form></div>"#,
                status_action,
                admin.id,
                esc(&session.csrf_token),
                admin.id,
                esc(&session.csrf_token)
            )
        };
        let row = format!(
            r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
            admin.id,
            esc(&admin.username),
            esc(&format_audit_time(&admin.created_at)),
            action
        );
        if admin.active {
            active_rows.push_str(&row);
        } else {
            inactive_rows.push_str(&row);
        }
    }
    if active_rows.is_empty() {
        active_rows.push_str(
            r#"<tr><td colspan="4" class="muted"><vl-i18n key="admins.no_active"/></td></tr>"#,
        );
    }
    if inactive_rows.is_empty() {
        inactive_rows.push_str(
            r#"<tr><td colspan="4" class="muted"><vl-i18n key="admins.no_inactive"/></td></tr>"#,
        );
    }
    let notice = match query.notice.as_deref() {
        Some("password_reset") => r#"<p class="notice"><vl-i18n key="admins.password_set"/></p>"#,
        _ => "",
    };
    let body = format!(
        r#"<section><h1><vl-i18n key="nav.admins"/></h1>{notice}<div class="admin-columns"><details class="admin-column" open><summary><vl-i18n key="admins.active"/></summary><table><tr><th>ID</th><th><vl-i18n key="auth.username"/></th><th><vl-i18n key="common.created"/></th><th><vl-i18n key="common.action"/></th></tr>{active_rows}</table></details><details class="admin-column" open><summary><vl-i18n key="admins.inactive"/></summary><table><tr><th>ID</th><th><vl-i18n key="auth.username"/></th><th><vl-i18n key="common.created"/></th><th><vl-i18n key="common.action"/></th></tr>{inactive_rows}</table></details></div></section><section><h2><vl-i18n key="admins.create"/></h2><form method="post" class="vl-admin-create-form"><input type="hidden" name="csrf" value="{}"><label class="vl-field"><vl-i18n key="auth.username"/><input name="username" pattern="[A-Za-z0-9_-]{{3,64}}" required></label><label class="vl-field"><vl-i18n key="auth.password"/><input name="password" type="password" minlength="14" required></label><label class="vl-field"><vl-i18n key="account.confirm_password"/><input name="password_confirm" type="password" required></label><button class="vl-button"><vl-i18n key="common.create"/></button></form></section>"#,
        esc(&session.csrf_token)
    );
    Ok(Html(admin_page(
        &state,
        PageId::Admins,
        &body,
        false,
        &session.csrf_token,
    )))
}

#[derive(Deserialize)]
struct CreateAdminUiForm {
    csrf: String,
    username: String,
    password: String,
    password_confirm: String,
}

#[derive(Deserialize)]
struct ResetAdminPasswordForm {
    csrf: String,
    password: String,
    password_confirm: String,
}

#[derive(Deserialize, Default)]
struct AdminNoticeQuery {
    notice: Option<String>,
}

async fn create_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateAdminUiForm>,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    if !valid_username(&form.username) {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Benutzername muss 3-64 sichere ASCII-Zeichen enthalten",
        ));
    }
    if form.password != form.password_confirm {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Passwörter stimmen nicht überein",
        ));
    }
    if form.password.chars().count() < 14 {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Passwort muss mindestens 14 Zeichen enthalten",
        ));
    }
    let username = form.username.clone();
    let secret = auth::new_totp_secret();
    let password = form.password;
    let hash = tokio::task::spawn_blocking(move || auth::hash_password(&password))
        .await
        .map_err(internal)?
        .map_err(internal)?;
    let created_username = username.clone();
    let created_secret = secret.clone();
    database(state.db.clone(), move |db| {
        db.create_admin(&created_username, &hash, &created_secret)
    })
    .await
    .map_err(|_| AppError(StatusCode::CONFLICT, "Benutzername existiert bereits"))?;
    audit(
        &state,
        session.username,
        "admin_created",
        Some(username.clone()),
        None,
    )
    .await;
    let otpauth = otpauth_url(&username, &secret);
    let qr = qr_svg(&otpauth)?;
    let body = format!(
        r#"<section><h1><vl-i18n key="title.admin_created"/></h1><p><vl-i18n key="admins.secret_once"/></p><p><strong>{}</strong></p><div class="qr-card" aria-label="TOTP QR-Code">{}</div><div class="secret-block"><code>{}</code><code>{}</code></div><p><a class="button secondary" href="/admin/admins"><vl-i18n key="admins.to_list"/></a></p></section>"#,
        esc(&username),
        qr,
        esc(&secret),
        esc(&otpauth)
    );
    Ok(Html(admin_page_without_locale_switcher(
        &state,
        PageId::AdminCreated,
        &body,
        false,
        &session.csrf_token,
    )))
}

async fn reset_admin_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(form): Form<ResetAdminPasswordForm>,
) -> Result<Redirect> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    if id == session.admin_id {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Eigenes Passwort kann hier nicht zurückgesetzt werden",
        ));
    }
    if form.password != form.password_confirm {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Passwörter stimmen nicht überein",
        ));
    }
    if form.password.chars().count() < 14 {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Passwort muss mindestens 14 Zeichen enthalten",
        ));
    }
    let password = form.password;
    let hash = tokio::task::spawn_blocking(move || auth::hash_password(&password))
        .await
        .map_err(internal)?
        .map_err(internal)?;
    let changed = database(state.db.clone(), move |db| {
        db.reset_admin_password(id, &hash)
    })
    .await?;
    if !changed {
        return Err(AppError(StatusCode::NOT_FOUND, "Admin nicht gefunden"));
    }
    audit(
        &state,
        session.username,
        "admin_password_reset",
        Some(id.to_string()),
        None,
    )
    .await;
    Ok(Redirect::to("/admin/admins?notice=password_reset"))
}

async fn reset_admin_totp(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    if id == session.admin_id {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Eigene MFA kann hier nicht zurückgesetzt werden",
        ));
    }
    let secret = auth::new_totp_secret();
    let reset_secret = secret.clone();
    let username = database(state.db.clone(), move |db| {
        db.reset_admin_totp(id, &reset_secret)
    })
    .await?
    .ok_or(AppError(StatusCode::NOT_FOUND, "Admin nicht gefunden"))?;
    audit(
        &state,
        session.username,
        "admin_totp_reset",
        Some(id.to_string()),
        None,
    )
    .await;
    let otpauth = otpauth_url(&username, &secret);
    let qr = qr_svg(&otpauth)?;
    let body = format!(
        r#"<section><h1><vl-i18n key="title.mfa_reset"/></h1><p><vl-i18n key="admins.new_secret_once"/></p><p><strong>{}</strong></p><div class="qr-card" aria-label="TOTP QR-Code">{}</div><div class="secret-block"><code>{}</code><code>{}</code></div><p><a class="button secondary" href="/admin/admins"><vl-i18n key="admins.to_list"/></a></p></section>"#,
        esc(&username),
        qr,
        esc(&secret),
        esc(&otpauth)
    );
    Ok(Html(admin_page_without_locale_switcher(
        &state,
        PageId::MfaReset,
        &body,
        false,
        &session.csrf_token,
    )))
}

async fn deactivate_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Redirect> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    if id == session.admin_id {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Eigener Admin kann nicht stillgelegt werden",
        ));
    }
    match database(state.db.clone(), move |db| db.deactivate_admin(id)).await? {
        AdminDeactivationOutcome::Deactivated | AdminDeactivationOutcome::AlreadyInactive => {}
        AdminDeactivationOutcome::LastActive => {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "Letzter aktiver Admin kann nicht stillgelegt werden",
            ));
        }
        AdminDeactivationOutcome::NotFound => {
            return Err(AppError(StatusCode::NOT_FOUND, "Admin nicht gefunden"));
        }
    }
    audit(
        &state,
        session.username,
        "admin_deactivated",
        Some(id.to_string()),
        None,
    )
    .await;
    Ok(Redirect::to("/admin/admins"))
}

async fn activate_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Redirect> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    let changed = database(state.db.clone(), move |db| db.activate_admin(id)).await?;
    if !changed {
        return Err(AppError(StatusCode::NOT_FOUND, "Admin nicht gefunden"));
    }
    audit(
        &state,
        session.username,
        "admin_activated",
        Some(id.to_string()),
        None,
    )
    .await;
    Ok(Redirect::to("/admin/admins"))
}

#[derive(Deserialize)]
struct SettingsForm {
    csrf: String,
    public_base_url: String,
    max_upload_size_gb: Option<String>,
    max_upload_size: Option<String>,
    blocked_extensions: String,
    share_password_min_length: String,
    share_password_max_length: Option<String>,
    share_password_max_bytes: Option<String>,
    share_unlock_minutes: String,
    max_zip_size_gb: Option<String>,
    max_zip_size: Option<String>,
    max_zip_files: String,
    max_search_entries: String,
    max_search_results: String,
    max_preview_size_mb: Option<String>,
    max_preview_size: Option<String>,
    preview_extensions: String,
    image_preview_extensions: String,
    pdf_preview_enabled: Option<String>,
    max_media_preview_size_mb: Option<String>,
    max_media_preview_size_gb: Option<String>,
    max_media_preview_size: Option<String>,
    audit_client_ip_enabled: Option<String>,
}

async fn settings_page(State(state): State<AppState>, headers: HeaderMap) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let settings = runtime_settings(&state);
    let ip_count = database(state.db.clone(), |db| db.count_audit_client_ips()).await?;
    let body = settings_form(&session, &settings, ip_count, "");
    Ok(Html(admin_page(
        &state,
        PageId::Settings,
        &body,
        false,
        &session.csrf_token,
    )))
}

fn settings_form(
    session: &Session,
    settings: &RuntimeSettings,
    audit_ip_count: u64,
    message: &str,
) -> String {
    let message = if message.is_empty() {
        String::new()
    } else {
        format!(
            r#"<p class="muted">{}</p>"#,
            esc(&i18n::text_from_german(i18n::current_locale(), message))
        )
    };
    let purge_link = if !settings.audit_client_ip_enabled && audit_ip_count > 0 {
        format!(
            r#"<p><a class="vl-button vl-button--danger" href="/admin/settings/audit-ips/delete">{} <vl-i18n key="settings.delete_ips"/></a></p>"#,
            audit_ip_count
        )
    } else {
        String::new()
    };
    format!(
        r#"<section class="vl-panel"><h2><vl-i18n key="settings.runtime"/></h2>{message}<p class="vl-muted"><vl-i18n key="settings.runtime_help"/></p><form method="post" class="row"><input type="hidden" name="csrf" value="{}"><label>Public Base URL<br><input name="public_base_url" value="{}" required></label><label><vl-i18n key="settings.upload_limit"/><br><input name="max_upload_size_gb" type="number" min="1" step="1" value="{}" required></label><label><vl-i18n key="settings.blocked"/><br><input name="blocked_extensions" value="{}"></label><label><vl-i18n key="settings.password_min"/><br><input name="share_password_min_length" type="number" min="8" value="{}" required></label><label><vl-i18n key="settings.password_max"/><br><input name="share_password_max_length" type="number" min="8" value="{}" required></label><label><vl-i18n key="settings.unlock_minutes"/><br><input name="share_unlock_minutes" type="number" min="1" value="{}" required></label><label><vl-i18n key="settings.zip_gb"/><br><input name="max_zip_size_gb" type="number" min="0" step="1" value="{}" required></label><label><vl-i18n key="settings.zip_files"/><br><input name="max_zip_files" type="number" min="0" value="{}" required></label><label><vl-i18n key="settings.search_entries"/><br><input name="max_search_entries" type="number" min="1" value="{}" required></label><label><vl-i18n key="settings.search_results"/><br><input name="max_search_results" type="number" min="1" value="{}" required></label><label><vl-i18n key="settings.text_preview"/><br><input name="max_preview_size_mb" type="number" min="1" step="1" value="{}" required></label><label><vl-i18n key="settings.text_extensions"/><br><input name="preview_extensions" value="{}" required></label><label><vl-i18n key="settings.media_preview"/><br><input name="max_media_preview_size_mb" type="number" min="1" step="1" value="{}" required></label><label><vl-i18n key="settings.image_extensions"/><br><input name="image_preview_extensions" value="{}"></label><label class="toggle-card"><input type="checkbox" name="pdf_preview_enabled" {}><span><vl-i18n key="settings.pdf_active"/><small><vl-i18n key="settings.pdf_help"/></small></span></label><label class="toggle-card"><input type="checkbox" name="audit_client_ip_enabled" {}><span><vl-i18n key="settings.audit_ip"/><small><vl-i18n key="settings.audit_ip_help"/></small></span></label><button><vl-i18n key="common.save"/></button></form>{purge_link}</section>"#,
        esc(&session.csrf_token),
        esc(&settings.public_base_url),
        display_limit_unit_floor(settings.max_upload_size, GB),
        esc(&settings.blocked_extensions.join(",")),
        settings.share_password_min_length,
        settings.share_password_max_length,
        settings.share_unlock_minutes,
        display_limit_unit_floor(settings.max_zip_size, GB),
        settings.max_zip_files,
        settings.max_search_entries,
        settings.max_search_results,
        display_limit_unit_floor(settings.max_preview_size, MB),
        esc(&settings.preview_extensions.join(",")),
        display_limit_unit_floor(settings.max_media_preview_size, MB),
        esc(&settings.image_preview_extensions.join(",")),
        if settings.pdf_preview_enabled {
            "checked"
        } else {
            ""
        },
        if settings.audit_client_ip_enabled {
            "checked"
        } else {
            ""
        },
    )
}

async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SettingsForm>,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    let mut next = runtime_settings(&state);
    let max_upload_size = if let Some(value) = form.max_upload_size_gb.as_deref() {
        parse_unit_to_bytes(value, GB, "Ungültiges Uploadlimit")?.to_string()
    } else {
        form.max_upload_size.unwrap_or_default()
    };
    let max_zip_size = if let Some(value) = form.max_zip_size_gb.as_deref() {
        if value.trim() == "0" {
            "0".to_string()
        } else {
            parse_unit_to_bytes(value, GB, "Ungültiges ZIP-Limit")?.to_string()
        }
    } else {
        form.max_zip_size.unwrap_or_default()
    };
    let max_preview_size = if let Some(value) = form.max_preview_size_mb.as_deref() {
        parse_unit_to_bytes(value, MB, "Ungültiges Preview-Limit")?.to_string()
    } else {
        form.max_preview_size.unwrap_or_default()
    };
    let max_media_preview_size = if let Some(value) = form.max_media_preview_size_mb.as_deref() {
        parse_unit_to_bytes(value, MB, "Ungültiges Media-Preview-Limit")?.to_string()
    } else if let Some(value) = form.max_media_preview_size_gb.as_deref() {
        parse_unit_to_bytes(value, GB, "Ungültiges Media-Preview-Limit")?.to_string()
    } else {
        form.max_media_preview_size.unwrap_or_default()
    };
    let share_password_max_length = form
        .share_password_max_length
        .or(form.share_password_max_bytes)
        .unwrap_or_default();
    let entries = [
        ("public_base_url", form.public_base_url.as_str()),
        ("max_upload_size", max_upload_size.as_str()),
        ("blocked_extensions", form.blocked_extensions.as_str()),
        (
            "share_password_min_length",
            form.share_password_min_length.as_str(),
        ),
        (
            "share_password_max_length",
            share_password_max_length.as_str(),
        ),
        ("share_unlock_minutes", form.share_unlock_minutes.as_str()),
        ("max_zip_size", max_zip_size.as_str()),
        ("max_zip_files", form.max_zip_files.as_str()),
        ("max_search_entries", form.max_search_entries.as_str()),
        ("max_search_results", form.max_search_results.as_str()),
        ("max_preview_size", max_preview_size.as_str()),
        ("preview_extensions", form.preview_extensions.as_str()),
        (
            "image_preview_extensions",
            form.image_preview_extensions.as_str(),
        ),
        (
            "pdf_preview_enabled",
            if form.pdf_preview_enabled.is_some() {
                "true"
            } else {
                "false"
            },
        ),
        ("max_media_preview_size", max_media_preview_size.as_str()),
        (
            "audit_client_ip_enabled",
            if form.audit_client_ip_enabled.is_some() {
                "true"
            } else {
                "false"
            },
        ),
    ];
    next.apply_many(entries)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültige Einstellung"))?;
    if state.config.server.production_mode
        && url::Url::parse(&next.public_base_url)
            .ok()
            .is_none_or(|url| url.scheme() != "https")
    {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Production public_base_url muss HTTPS verwenden",
        ));
    }
    let admin_id = session.admin_id;
    let previous = runtime_settings(&state);
    commit_runtime_settings(&state, next.clone(), admin_id).await?;
    let actor = session.username.clone();
    let changed = previous.changed_keys(&next);
    audit(
        &state,
        actor,
        "settings_updated",
        None,
        Some(format!("changed_keys={}", changed.join(","))),
    )
    .await;
    let ip_count = database(state.db.clone(), |db| db.count_audit_client_ips()).await?;
    Ok(Html(admin_page(
        &state,
        PageId::Settings,
        &settings_form(&session, &next, ip_count, "Einstellungen gespeichert."),
        false,
        &session.csrf_token,
    )))
}

#[derive(Deserialize)]
struct DeleteAuditIpsForm {
    csrf: String,
    confirmation: String,
}

async fn audit_ips_delete_confirmation(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    if runtime_settings(&state).audit_client_ip_enabled {
        return Err(AppError(
            StatusCode::CONFLICT,
            "IP-Erfassung muss vor dem Löschen deaktiviert werden",
        ));
    }
    let count = database(state.db.clone(), |db| db.count_audit_client_ips()).await?;
    let body = format!(
        r#"<section class="vl-panel vl-confirm-card"><h2><vl-i18n key="settings.delete_ip_data"/></h2><p><vl-i18n key="settings.values_prefix"/> <strong>{count}</strong> <vl-i18n key="settings.delete_ip_values"/></p><form method="post" action="/admin/settings/audit-ips/delete" class="vl-stack"><input type="hidden" name="csrf" value="{}"><label class="vl-field"><vl-i18n key="settings.enter_confirm"/> <code>IP-DATEN LÖSCHEN</code><input name="confirmation" autocomplete="off" required></label><div class="vl-inline-actions"><button class="vl-button vl-button--danger"><vl-i18n key="settings.delete_ip_action"/></button><a class="vl-button vl-button--secondary" href="/admin/settings"><vl-i18n key="common.cancel"/></a></div></form></section>"#,
        esc(&session.csrf_token),
    );
    Ok(Html(admin_page(
        &state,
        PageId::Settings,
        &body,
        false,
        &session.csrf_token,
    )))
}

async fn delete_audit_ips_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeleteAuditIpsForm>,
) -> Result<Redirect> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    if form.confirmation != "IP-DATEN LÖSCHEN" {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Exakte Bestätigung IP-DATEN LÖSCHEN erforderlich",
        ));
    }
    if runtime_settings(&state).audit_client_ip_enabled {
        return Err(AppError(
            StatusCode::CONFLICT,
            "IP-Erfassung muss vor dem Löschen deaktiviert werden",
        ));
    }
    let deleted = database(state.db.clone(), |db| db.delete_audit_client_ips()).await?;
    audit(
        &state,
        session.username,
        "audit_client_ips_deleted",
        None,
        Some(format!("deleted={deleted}")),
    )
    .await;
    Ok(Redirect::to("/admin/settings"))
}

#[derive(Default, Deserialize)]
struct AuditQuery {
    page: Option<usize>,
    action: Option<String>,
}

async fn audit_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let settings = runtime_settings(&state);
    let client_ip_enabled = settings.audit_client_ip_enabled;
    let requested_page = query.page.unwrap_or(0).min(1_000_000);
    let action = query
        .action
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_string());
    let action_for_db = action.clone();
    let (events, total, page_number) = database(state.db.clone(), move |db| {
        let total = db.count_audit(action_for_db.as_deref())?;
        let total_pages = total.div_ceil(100).max(1);
        let page_number = requested_page.min(total_pages - 1);
        let events = db.list_audit(action_for_db.as_deref(), 100, page_number * 100)?;
        Ok((events, total, page_number))
    })
    .await?;
    let total_pages = total.div_ceil(100).max(1);
    let has_next = page_number + 1 < total_pages;
    let mut rows = String::new();
    for event in events {
        let client_ip = if client_ip_enabled {
            format!(
                r#"<td class="vl-audit-ip" data-label="Client IP">{}</td>"#,
                event.client_ip.as_deref().map(esc).unwrap_or_default()
            )
        } else {
            String::new()
        };
        rows += &format!(
            r#"<tr><td class="vl-audit-time" data-label="<vl-i18n key="common.time"/>">{}</td><td class="vl-audit-user" data-label="User">{}</td><td class="vl-audit-action" data-label="<vl-i18n key="common.action"/>"><code>{}</code></td><td class="vl-audit-object" data-label="<vl-i18n key="common.object"/>">{}</td><td class="vl-audit-detail" data-label="<vl-i18n key="common.detail"/>">{}</td>{client_ip}</tr>"#,
            esc(&format_audit_time(&event.occurred_at)),
            esc(&event.actor),
            esc(&event.action),
            event.object_id.as_deref().map(esc).unwrap_or_default(),
            event.detail.as_deref().map(esc).unwrap_or_default()
        );
    }
    let filter_value = action.as_deref().unwrap_or("");
    let encoded_filter =
        percent_encoding::utf8_percent_encode(filter_value, percent_encoding::NON_ALPHANUMERIC);
    let previous = if page_number > 0 {
        format!(
            r#"<a class="vl-button vl-button--ghost" href="/admin/audit?action={encoded_filter}&page={}"><vl-i18n key="common.back"/></a>"#,
            page_number - 1
        )
    } else {
        String::new()
    };
    let next = if has_next {
        format!(
            r#"<a class="vl-button vl-button--ghost" href="/admin/audit?action={encoded_filter}&page={}"><vl-i18n key="common.continue"/></a>"#,
            page_number + 1
        )
    } else {
        String::new()
    };
    let ip_header = if client_ip_enabled {
        "<th class=\"vl-audit-ip\">Client-IP</th>"
    } else {
        ""
    };
    let url_scheme = url::Url::parse(&settings.public_base_url)
        .ok()
        .map(|url| url.scheme().to_uppercase())
        .unwrap_or_else(|| i18n::text(i18n::current_locale(), i18n::UNKNOWN).into());
    let trusted_proxy_count = state.config.reverse_proxy.trusted_proxies.len();
    let body = format!(
        r#"<div class="vl-audit-layout"><section class="vl-panel"><div class="vl-panel-head"><div><p class="vl-eyebrow"><vl-i18n key="audit.traceability"/></p><h2><vl-i18n key="audit.events"/></h2></div><form method="get" class="vl-inline-actions"><label class="vl-field"><span class="vl-sr-only"><vl-i18n key="audit.action_filter"/></span><input name="action" value="{}" placeholder="<vl-i18n key="audit.filter_action"/>"></label><button class="vl-button"><vl-i18n key="common.filter"/></button></form></div><div class="vl-table-wrap"><table class="vl-data-table vl-audit-table"><thead><tr><th class="vl-audit-time"><vl-i18n key="common.time"/></th><th class="vl-audit-user">User</th><th class="vl-audit-action"><vl-i18n key="common.action"/></th><th class="vl-audit-object"><vl-i18n key="common.object"/></th><th class="vl-audit-detail"><vl-i18n key="common.detail"/></th>{ip_header}</tr></thead><tbody>{rows}</tbody></table></div><nav class="vl-pagination" aria-label="<vl-i18n key="audit.pages"/>">{previous}<span><vl-i18n key="common.page_of"/> {} <vl-i18n key="common.of"/> {}</span>{next}</nav></section><aside class="vl-panel vl-security-facts"><p class="vl-eyebrow"><vl-i18n key="audit.security_status"/></p><h2><vl-i18n key="audit.proven_config"/></h2><dl><div><dt>MFA</dt><dd><vl-i18n key="audit.mfa_required"/></dd></div><div><dt><vl-i18n key="audit.server_mode"/></dt><dd>{:?}</dd></div><div><dt><vl-i18n key="audit.url_scheme"/></dt><dd>{}</dd></div><div><dt>Trusted Proxies</dt><dd>{}</dd></div><div><dt><vl-i18n key="audit.ip_capture"/></dt><dd>{}</dd></div><div><dt><vl-i18n key="audit.logging"/></dt><dd><vl-i18n key="audit.structured"/></dd></div></dl></aside></div>"#,
        esc(filter_value),
        page_number + 1,
        total_pages,
        state.config.server.mode,
        esc(&url_scheme),
        trusted_proxy_count,
        if client_ip_enabled {
            i18n::text(i18n::current_locale(), i18n::ENABLED)
        } else {
            i18n::text(i18n::current_locale(), i18n::DISABLED)
        },
    );
    Ok(Html(admin_page(
        &state,
        PageId::AuditSecurity,
        &body,
        false,
        &session.csrf_token,
    )))
}

fn usable(sh: &Share) -> Result<()> {
    if !sh.active || sh.expires_at.is_some_and(|e| e <= Utc::now()) {
        Err(AppError(
            StatusCode::GONE,
            "Dieser Link ist nicht mehr aktiv",
        ))
    } else {
        Ok(())
    }
}
async fn get_share(state: &AppState, token: &str) -> Result<Share> {
    let token = token.to_string();
    let sh = database(state.db.clone(), move |db| db.share_by_token(&token))
        .await?
        .ok_or(AppError(StatusCode::NOT_FOUND, "Link nicht gefunden"))?;
    usable(&sh)?;
    Ok(sh)
}

#[derive(Deserialize)]
struct UnlockForm {
    password: String,
}

async fn unlock_share(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Form(form): Form<UnlockForm>,
) -> Result<Response> {
    let share = get_share(&state, &token).await?;
    let Some(password_hash) = share.password_hash.clone() else {
        return Ok(Redirect::to(&format!("/v/{token}")).into_response());
    };
    let ip = proxy::effective_client_ip(peer.ip(), &headers, &state.config);
    let key = format!("share:{}:{ip}", share.id);
    if !state.share_limiter.allowed(&key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele Passwortversuche",
        ));
    }
    let password = form.password;
    let valid =
        tokio::task::spawn_blocking(move || auth::verify_password(&password_hash, &password))
            .await
            .map_err(internal)?;
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
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültiges Passwort"));
    }
    state.share_limiter.success(&key);
    let unlock_token = auth::random_token(32);
    let stored_unlock_token = unlock_token.clone();
    let share_id = share.id;
    let expires = Utc::now() + Duration::minutes(runtime_settings(&state).share_unlock_minutes);
    database(state.db.clone(), move |db| {
        db.create_unlock_session(&stored_unlock_token, share_id, expires)
    })
    .await?;
    audit(
        &state,
        "public".into(),
        "share_unlock_success",
        Some(share.id.to_string()),
        None,
    )
    .await;
    Ok(redirect_with_cookie(
        &format!("/v/{token}"),
        make_unlock_cookie(&state, &share, &unlock_token, UnlockCookieScope::Web),
    )?)
}

async fn public_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(q): Query<BrowseQuery>,
) -> Result<Html<String>> {
    let sh = get_share(&state, &token).await?;
    let settings = runtime_settings(&state);
    if !share_is_unlocked(&state, &headers, &sh).await? {
        let body = format!(
            r#"<section class="vl-panel vl-auth-card"><p class="vl-eyebrow"><vl-i18n key="share.secure"/></p><h1><vl-i18n key="public.protected_title"/></h1><p class="vl-muted"><vl-i18n key="public.enter_share_password"/></p><form method="post" action="/v/{0}/unlock" class="vl-stack"><label class="vl-field"><vl-i18n key="auth.password"/><input type="password" name="password" autocomplete="current-password" required></label><button class="vl-button">{1} <vl-i18n key="public.unlock"/></button></form></section>"#,
            esc(&token),
            crate::ui::icon(crate::ui::Icon::Lock),
        );
        return Ok(Html(plain_page("Geschützte Freigabe", &body)));
    }
    let display_name = if sh.permission == Permission::UploadOnly {
        i18n::text(i18n::current_locale(), i18n::UPLOAD_FILE).to_string()
    } else {
        sh.relative_path
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| i18n::text(i18n::current_locale(), i18n::DEFAULT_SHARE_NAME))
            .to_string()
    };
    let secure_transport = url::Url::parse(&settings.public_base_url)
        .ok()
        .is_some_and(|url| url.scheme() == "https");
    let expiry_badge = sh
        .expires_at
        .map(|expires_at| {
            format!(
                r#"<span class="vl-badge"><vl-i18n key="public.valid_until"/> {}</span>"#,
                format_public_date(expires_at)
            )
        })
        .unwrap_or_else(|| {
            r#"<span class="vl-badge"><vl-i18n key="share.no_expiry"/></span>"#.into()
        });
    let password_badge = if sh.password_hash.is_some() {
        r#"<span class="vl-badge vl-badge--neutral"><vl-i18n key="share.password_protected"/></span>"#
    } else {
        ""
    };
    let quota = sh.max_downloads.map(|maximum| {
        let value = sh
            .download_count
            .saturating_mul(100)
            .saturating_div(maximum.max(1))
            .min(100);
        format!(r#"<div class="vl-public-quota"><span>{} <vl-i18n key="public.transfers_used_prefix"/> {} <vl-i18n key="public.transfers_used_suffix"/></span><progress class="vl-public-progress" max="100" value="{value}">{value}%</progress></div>"#, sh.download_count, maximum)
    }).unwrap_or_default();
    let mut body = format!(
        r#"<section class="vl-panel vl-public-hero"><div><p class="vl-eyebrow"><vl-i18n key="share.secure"/></p><h1>{}</h1><p class="vl-muted"><vl-i18n key="public.provided_by"/> {}</p><div class="vl-share-badges"><span class="vl-badge vl-badge--accent">{}</span>{password_badge}{expiry_badge}</div></div><div>{}<p class="vl-muted">{}</p></div></section>"#,
        esc(&display_name),
        esc(&settings.public_base_url),
        esc(share_permission_label(&sh.permission)),
        quota,
        if secure_transport {
            i18n::text(i18n::current_locale(), i18n::HTTPS_SECURE)
        } else {
            i18n::text(i18n::current_locale(), i18n::LOCAL_HTTP)
        },
    );
    if let Some(upload_status) = q.upload.as_deref() {
        let message = match upload_status {
            "replaced" => i18n::text(i18n::current_locale(), i18n::FILE_REPLACED_SUCCESS),
            "ok" => i18n::text(i18n::current_locale(), i18n::UPLOAD_COMPLETED),
            "uncertain" => i18n::text(i18n::current_locale(), i18n::UPLOAD_STORAGE_UNCONFIRMED),
            "replaced_uncertain" => {
                i18n::text(i18n::current_locale(), i18n::REPLACE_STORAGE_UNCONFIRMED)
            }
            _ => "",
        };
        if !message.is_empty() {
            body += &format!(r#"<p class="vl-notice vl-notice--success">{message}</p>"#);
        }
    }
    let split_layout =
        sh.is_directory && sh.permission.can_download() && sh.permission.can_upload();
    if split_layout {
        body += r#"<div class="vl-public-share-layout"><section class="vl-panel">"#;
    } else if sh.is_directory && sh.permission.can_download() {
        body += r#"<section class="vl-panel">"#;
    }
    if sh.is_directory && sh.permission.can_download() {
        let sub = q.path.clone().unwrap_or_default();
        let page_number = q.page.unwrap_or(0).min(1_000_000);
        let search =
            q.q.map(|value| value.trim().to_string())
                .filter(|v| !v.is_empty());
        let clean_sub = path_security::validate_relative(&sub)
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Pfad"))?
            .to_string_lossy()
            .replace('\\', "/");
        let relative_dir = clean_sub.clone();
        let share_scope = state
            .secure_root
            .bind_directory(&sh.relative_path)
            .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabeziel nicht verfügbar"))?;
        body += &public_breadcrumbs(&token, &clean_sub);
        if let Some(parent) = parent_path(&clean_sub) {
            body += &format!(
                r#"<p><a href="/v/{token}?path={}"><vl-i18n key="files.up"/></a></p>"#,
                encoded(&parent)
            );
        }
        body += &format!(
            r#"<form method="get" class="vl-toolbar"><input type="hidden" name="path" value="{}"><label class="vl-field vl-search"><span class="vl-sr-only"><vl-i18n key="files.browse"/></span><input name="q" value="{}" placeholder="<vl-i18n key="files.search_placeholder"/>"></label><button class="vl-button"><vl-i18n key="common.search"/></button><a class="vl-button vl-button--secondary" href="/v/{token}/download.zip?path={}"><vl-i18n key="files.folder_zip"/></a></form>"#,
            esc(&clean_sub),
            esc(search.as_deref().unwrap_or("")),
            encoded(&clean_sub)
        );
        let secure_root = share_scope;
        let mut rows = String::new();
        let mut has_next = false;
        if let Some(search) = search.clone() {
            let search_settings = settings.clone();
            let hits = tokio::task::spawn_blocking(move || {
                search_tree(secure_root, &relative_dir, &search, &search_settings)
            })
            .await
            .map_err(internal)?
            .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabeziel nicht verfügbar"))?;
            for hit in hits {
                let share_rel = hit.relative_path.clone();
                let target = encoded(&share_rel);
                let preview = if !hit.entry.is_dir && preview_allowed(&hit.relative_path, &settings)
                {
                    format!(
                        r#"<a class="vl-button vl-button--ghost vl-button--small" href="/v/{token}/preview?path={target}"><vl-i18n key="common.view"/></a> "#
                    )
                } else {
                    String::new()
                };
                let modified = hit
                    .entry
                    .modified
                    .map(format_file_time)
                    .unwrap_or_else(|| "—".into());
                let name = if hit.entry.is_dir {
                    format!(
                        r#"{} <a href="/v/{token}?path={target}">{}</a>"#,
                        crate::ui::icon(crate::ui::Icon::Folder),
                        esc(&share_rel)
                    )
                } else {
                    format!(
                        "{} {}",
                        crate::ui::icon(crate::ui::Icon::File),
                        esc(&share_rel)
                    )
                };
                rows += &format!(
                    r#"<tr><td data-label="<vl-i18n key="common.name"/>">{name}</td><td data-label="<vl-i18n key="common.size"/>">{}</td><td data-label="<vl-i18n key="common.changed"/>">{modified}</td><td data-label="<vl-i18n key="common.action"/>" class="vl-inline-actions">{}{preview}</td></tr>"#,
                    if hit.entry.is_dir {
                        "—".into()
                    } else {
                        human(hit.entry.len)
                    },
                    if hit.entry.is_dir {
                        format!(
                            r#"<a class="vl-button vl-button--ghost vl-button--small" href="/v/{token}?path={target}"><vl-i18n key="common.open"/></a>"#
                        )
                    } else {
                        format!(
                            r#"<a class="vl-button vl-button--secondary vl-button--small" href="/v/{token}/download?path={target}"><vl-i18n key="common.download"/></a>"#
                        )
                    },
                );
            }
        } else {
            let scan_limit = settings.max_search_entries;
            let (entries, truncated) = tokio::task::spawn_blocking(move || {
                list_directory_page(&secure_root, &relative_dir, page_number, scan_limit)
            })
            .await
            .map_err(internal)?
            .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabeziel nicht verfügbar"))?;
            has_next = entries.len() > 100;
            for entry in entries.into_iter().take(100) {
                let rel = joined_relative(&clean_sub, &entry.name)?;
                let name = esc(&entry.name);
                let target = encoded(&rel);
                if entry.is_dir {
                    rows += &format!(
                        r#"<tr><td data-label="<vl-i18n key="common.name"/>">{} <a href="/v/{token}?path={target}">{name}</a></td><td data-label="<vl-i18n key="common.size"/>">—</td><td data-label="<vl-i18n key="common.changed"/>">{}</td><td data-label="<vl-i18n key="common.action"/>"><a class="vl-button vl-button--ghost vl-button--small" href="/v/{token}?path={target}"><vl-i18n key="common.open"/></a></td></tr>"#,
                        crate::ui::icon(crate::ui::Icon::Folder),
                        entry
                            .modified
                            .map(format_file_time)
                            .unwrap_or_else(|| "—".into())
                    );
                } else {
                    let preview = if preview_allowed(&rel, &settings) {
                        format!(
                            r#"<a class="vl-button vl-button--ghost vl-button--small" href="/v/{token}/preview?path={target}"><vl-i18n key="common.view"/></a> "#
                        )
                    } else {
                        String::new()
                    };
                    rows += &format!(
                        r#"<tr><td data-label="<vl-i18n key="common.name"/>">{} {name}</td><td data-label="<vl-i18n key="common.size"/>">{}</td><td data-label="<vl-i18n key="common.changed"/>">{}</td><td data-label="<vl-i18n key="common.action"/>" class="vl-inline-actions">{}<a class="vl-button vl-button--secondary vl-button--small" href="/v/{token}/download?path={target}"><vl-i18n key="common.download"/></a></td></tr>"#,
                        crate::ui::icon(crate::ui::Icon::File),
                        human(entry.len),
                        entry
                            .modified
                            .map(format_file_time)
                            .unwrap_or_else(|| "—".into()),
                        preview,
                    );
                }
            }
            if truncated {
                rows += r#"<tr><td colspan="4" class="vl-muted"><vl-i18n key="files.scan_limit"/></td></tr>"#;
            }
        }
        body += "<div class=\"vl-table-wrap\"><table class=\"vl-data-table\"><thead><tr><th><vl-i18n key=\"common.name\"/></th><th><vl-i18n key=\"common.size\"/></th><th><vl-i18n key=\"common.changed\"/></th><th><vl-i18n key=\"common.action\"/></th></tr></thead><tbody>";
        body += &rows;
        body += "</tbody></table></div>";
        let encoded_sub = encoded(&clean_sub);
        let search_param = search
            .as_deref()
            .map(|value| format!("&q={}", encoded(value)))
            .unwrap_or_default();
        if page_number > 0 {
            body += &format!(
                " <a href=\"/v/{token}?path={encoded_sub}&page={}{}\"><vl-i18n key=\"common.back\"/></a>",
                page_number - 1,
                search_param
            );
        }
        if has_next {
            body += &format!(
                " <a href=\"/v/{token}?path={encoded_sub}&page={}{}\"><vl-i18n key=\"common.continue\"/></a>",
                page_number + 1,
                search_param
            );
        }
        body += "</section>";
    } else if !sh.is_directory && sh.permission.can_download() {
        let secure_root = state.secure_root.clone();
        let metadata_path = sh.relative_path.clone();
        let metadata = tokio::task::spawn_blocking(move || secure_root.metadata(&metadata_path))
            .await
            .map_err(internal)?
            .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabedatei nicht verfügbar"))?;
        let preview = if preview_allowed(&sh.relative_path, &settings) {
            format!(
                r#"<a class="vl-button vl-button--secondary" href="/v/{token}/preview"><vl-i18n key="files.view_browser"/></a> "#
            )
        } else {
            String::new()
        };
        body += &format!(
            r#"<section class="vl-panel"><p class="vl-muted">{} · <vl-i18n key="files.modified_label"/> {}</p><div class="vl-inline-actions">{}<a class="vl-button" href="/v/{token}/download"><vl-i18n key="files.download_file"/></a></div></section>"#,
            human(metadata.len()),
            metadata
                .modified()
                .map(format_file_time)
                .unwrap_or_else(|_| "—".into()),
            preview,
        );
    }
    if sh.is_directory && sh.permission.can_upload() {
        let upload_path = if sh.permission.can_download() {
            path_security::validate_relative(q.path.as_deref().unwrap_or_default())
                .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Pfad"))?
                .to_string_lossy()
                .replace('\\', "/")
        } else {
            String::new()
        };
        let overwrite_checkbox = if sh.upload_conflict_strategy.can_overwrite() {
            r#"<label class="vl-switch"><input type="checkbox" name="overwrite_existing" value="1"><span><vl-i18n key="share.replace_existing_file"/><small><vl-i18n key="share.replace_concrete"/></small></span></label>"#
        } else {
            ""
        };
        let target_hint = if sh.permission == Permission::UploadOnly {
            r#"<p class="vl-notice"><strong><vl-i18n key="share.existing_hidden"/></strong></p>"#
                .to_string()
        } else {
            format!(
                r#"<p class="vl-muted"><vl-i18n key="public.target_folder"/>: /{}</p>"#,
                esc(&upload_path)
            )
        };
        let panel_tag = if split_layout { "aside" } else { "section" };
        body += &format!(
            r#"<{panel_tag} class="vl-panel vl-upload-panel"><h2>{}</h2>{target_hint}<form method="post" enctype="multipart/form-data" action="/v/{token}/upload" class="vl-stack" data-upload-queue data-queue-endpoint="/v/{token}/upload/queue"><input type="hidden" name="path" value="{}"><label class="vl-upload-dropzone" data-upload-dropzone>{}<strong><vl-i18n key="upload.drop_here"/></strong><span class="vl-muted"><vl-i18n key="upload.or_choose"/></span><input class="vl-upload-input" type="file" name="file" required data-upload-input></label>{}<div class="vl-upload-queue" data-upload-list aria-live="polite"></div><button class="vl-button" data-upload-submit>{} <vl-i18n key="upload.securely"/></button><p class="vl-muted"><vl-i18n key="share.no_replace_help"/></p></form></{panel_tag}>"#,
            if sh.permission == Permission::UploadOnly {
                i18n::text(i18n::current_locale(), i18n::UPLOAD_FILE)
            } else {
                i18n::text(i18n::current_locale(), i18n::UPLOAD_FILES_PUBLIC)
            },
            esc(&upload_path),
            crate::ui::icon(crate::ui::Icon::Upload),
            overwrite_checkbox,
            crate::ui::icon(crate::ui::Icon::Upload),
        );
    }
    if split_layout {
        body += "</div>";
    }
    Ok(Html(plain_page("Freigabe", &body)))
}
fn joined_relative(base: &str, child: &str) -> Result<String> {
    let mut path = path_security::validate_relative(base)
        .map_err(|_| AppError(StatusCode::FORBIDDEN, "Ungültiger Pfad"))?;
    path.push(
        path_security::validate_relative(child)
            .map_err(|_| AppError(StatusCode::FORBIDDEN, "Ungültiger Pfad"))?,
    );
    Ok(path.to_string_lossy().replace('\\', "/"))
}

fn public_back_link(
    public_route: &str,
    share_relative_file: &str,
    is_directory_share: bool,
) -> String {
    if !is_directory_share {
        return public_route.to_string();
    }
    let parent = parent_path(share_relative_file).unwrap_or_default();
    if parent.is_empty() {
        public_route.to_string()
    } else {
        format!("{public_route}?path={}", encoded(&parent))
    }
}

fn add_public_preview_actions(
    body: String,
    back_link: &str,
    download_link: Option<&str>,
) -> String {
    let download = download_link
        .map(|link| {
            format!(
                r#"<a href="{}"><vl-i18n key="common.download"/></a>"#,
                esc(link)
            )
        })
        .unwrap_or_default();
    let action = format!(
        r#"<h1><vl-i18n key="files.preview"/></h1><p class="preview-actions"><a href="{}"><vl-i18n key="share.back"/></a>{}</p>"#,
        esc(back_link),
        download
    );
    body.replacen(r#"<h1><vl-i18n key="files.preview"/></h1>"#, &action, 1)
}

pub(crate) async fn public_preview(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response> {
    let sh = get_share(&state, &token).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Freigabe ist gesperrt"));
    }
    if !sh.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "Vorschau nicht erlaubt"));
    }
    let requested_path = q.path.clone().unwrap_or_default();
    let relative_file = if sh.is_directory {
        if requested_path.is_empty() {
            return Err(AppError(StatusCode::BAD_REQUEST, "Dateipfad fehlt"));
        }
        requested_path.clone()
    } else {
        sh.relative_path.clone()
    };
    let settings = runtime_settings(&state);
    let preview_path = relative_file.clone();
    let content = if sh.is_directory {
        let scope = state
            .secure_root
            .bind_directory(&sh.relative_path)
            .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabeziel nicht verfügbar"))?;
        let requested = requested_path.clone();
        tokio::task::spawn_blocking(move || read_preview(scope, &requested, &settings)).await
    } else {
        let file = state
            .secure_root
            .bind_file(&sh.relative_path)
            .map_err(|_| AppError(StatusCode::NOT_FOUND, "Datei nicht verfügbar"))?;
        tokio::task::spawn_blocking(move || {
            read_preview_secure_file(file, &preview_path, &settings)
        })
        .await
    }
    .map_err(internal)?
    .map_err(public_preview_error)?;
    let share_rel = if sh.is_directory {
        requested_path
    } else {
        String::new()
    };
    let public_route = public_share_route(&uri, &token);
    let download_link = if sh.is_directory {
        format!(r#"{public_route}/download?path={}"#, encoded(&share_rel))
    } else {
        format!("{public_route}/download")
    };
    if let PreviewContent::TooLarge { size } = &content {
        let body = preview_too_large_body(
            &share_rel,
            *size,
            "Datei ist größer als das Preview-Limit.",
            Some(&download_link),
        );
        let body = add_public_preview_actions(
            body,
            &public_back_link(&public_route, &share_rel, sh.is_directory),
            Some(&download_link),
        );
        return Ok(Html(plain_page("Vorschau", &body)).into_response());
    }
    let count_html_preview = matches!(&content, PreviewContent::Text(_));
    let body = match content {
        PreviewContent::TooLarge { size } => preview_too_large_body(
            &share_rel,
            size,
            "Datei ist größer als das Preview-Limit.",
            Some(&download_link),
        ),
        PreviewContent::Text(text) => format!(
            r#"<section><h1><vl-i18n key="files.preview"/></h1><pre>{}</pre></section>"#,
            esc(&text)
        ),
        PreviewContent::Media { kind, size } => {
            let preview_token = auth::random_token(32);
            let stored_preview_token = preview_token.clone();
            let share_id = sh.id;
            let token_path = if sh.is_directory {
                share_rel.clone()
            } else {
                String::new()
            };
            let expires = Utc::now() + Duration::minutes(5);
            database(state.db.clone(), move |db| {
                db.create_preview_session(&stored_preview_token, share_id, &token_path, expires)
            })
            .await?;
            let raw_url = if sh.is_directory {
                format!(
                    "{public_route}/preview/raw?path={}&preview_token={}",
                    encoded(&share_rel),
                    encoded(&preview_token)
                )
            } else {
                format!(
                    "{public_route}/preview/raw?preview_token={}",
                    encoded(&preview_token)
                )
            };
            let viewer = media_viewer(kind, &raw_url);
            format!(
                r#"<section><h1><vl-i18n key="files.preview"/></h1><p class="muted">{} - <vl-i18n key="files.raw_token"/></p>{}</section>"#,
                human(size),
                viewer
            )
        }
    };
    let body = add_public_preview_actions(
        body,
        &public_back_link(&public_route, &share_rel, sh.is_directory),
        Some(&download_link),
    );
    let page = plain_page("Vorschau", &body);
    let mut response = if count_html_preview {
        let resource_key = if sh.is_directory {
            share_rel.clone()
        } else {
            sh.relative_path.clone()
        };
        let transfer =
            begin_public_transfer(&state, &headers, &uri, &sh, resource_key, "preview").await?;
        let transfer_cookie_value = transfer.cookie.clone();
        let page_length = page.len() as u64;
        let stream = futures_util::stream::once(async move { Ok(Bytes::from(page)) });
        let mut response = Response::new(transfer_body(
            stream,
            &state,
            transfer,
            "preview",
            sh.id,
            Some(page_length),
        ));
        set_transfer_cookie(&mut response, &transfer_cookie_value)?;
        response
    } else {
        Response::new(Body::from(page))
    };
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    Ok(response)
}

pub(crate) async fn public_preview_raw(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(q): Query<PreviewRawQuery>,
) -> Result<Response> {
    let sh = get_share(&state, &token).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Freigabe ist gesperrt"));
    }
    if !sh.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "Vorschau nicht erlaubt"));
    }
    let requested_path = q.path.clone().unwrap_or_default();
    let relative_file = if sh.is_directory {
        if requested_path.is_empty() {
            return Err(AppError(StatusCode::BAD_REQUEST, "Dateipfad fehlt"));
        }
        requested_path.clone()
    } else {
        sh.relative_path.clone()
    };
    let preview_token = q
        .preview_token
        .ok_or(AppError(StatusCode::FORBIDDEN, "Preview-Token fehlt"))?;
    let share_id = sh.id;
    let token_path = if sh.is_directory {
        requested_path.clone()
    } else {
        String::new()
    };
    let token_valid = database(state.db.clone(), move |db| {
        db.preview_session(&preview_token, share_id, &token_path)
    })
    .await?;
    if !token_valid {
        return Err(AppError(
            StatusCode::FORBIDDEN,
            "Preview-Token ungueltig oder abgelaufen",
        ));
    }
    let settings = runtime_settings(&state);
    let kind = preview_kind(&relative_file, &settings)
        .filter(|kind| kind.is_media())
        .ok_or(AppError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Vorschau nicht erlaubt",
        ))?;
    let mut response = if sh.is_directory {
        let scope = state
            .secure_root
            .bind_directory(&sh.relative_path)
            .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabeziel nicht verfügbar"))?;
        raw_preview_response(
            scope,
            method.clone(),
            headers.clone(),
            relative_file.clone(),
            kind,
            settings.max_media_preview_size,
        )
        .await?
    } else {
        let file = state
            .secure_root
            .bind_file(&sh.relative_path)
            .map_err(|_| AppError(StatusCode::NOT_FOUND, "Datei nicht verfügbar"))?;
        raw_preview_secure_file_response(
            file,
            method.clone(),
            headers.clone(),
            relative_file.clone(),
            kind,
            settings.max_media_preview_size,
        )
        .await?
    };
    if method == Method::GET && response.status().is_success() {
        let resource_key = if sh.is_directory {
            relative_file
        } else {
            sh.relative_path.clone()
        };
        let transfer =
            begin_public_transfer(&state, &headers, &uri, &sh, resource_key, "preview").await?;
        let transfer_cookie_value = transfer.cookie.clone();
        let expected_bytes = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if expected_bytes == Some(0) {
            complete_transfer_without_body(&state, transfer, "preview", sh.id).await?;
        } else {
            let body = std::mem::replace(response.body_mut(), Body::empty());
            let stream = body
                .into_data_stream()
                .map(|item| item.map_err(io::Error::other));
            *response.body_mut() =
                transfer_body(stream, &state, transfer, "preview", sh.id, expected_bytes);
        }
        set_transfer_cookie(&mut response, &transfer_cookie_value)?;
    }
    Ok(response)
}

pub(crate) async fn download_zip(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response> {
    let sh = get_share(&state, &token).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Freigabe ist gesperrt"));
    }
    if !sh.is_directory || !sh.permission.can_download() {
        return Err(AppError(
            StatusCode::FORBIDDEN,
            "ZIP-Download nicht erlaubt",
        ));
    }
    let sub = path_security::validate_relative(q.path.as_deref().unwrap_or_default())
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger ZIP-Pfad"))?
        .to_string_lossy()
        .replace('\\', "/");
    let settings = runtime_settings(&state);
    let secure_root = state
        .secure_root
        .bind_directory(&sh.relative_path)
        .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabeziel nicht verfügbar"))?;
    let resource_key = if sub.is_empty() {
        ".".to_string()
    } else {
        sub.clone()
    };
    let transfer =
        begin_public_transfer(&state, &headers, &uri, &sh, resource_key, "zip_download").await?;
    let transfer_cookie_value = transfer.cookie.clone();
    let mut transfer = Some(transfer);
    let plan_scope = secure_root.clone();
    let plan_path = sub.clone();
    let plan_settings = settings.clone();
    let plan =
        tokio::task::spawn_blocking(move || plan_zip(&plan_scope, &plan_path, &plan_settings))
            .await
            .map_err(internal)?
            .map_err(zip_error)?;
    let mut content_length = None;
    let body = if let Some(reservation) = ZipTempReservation::acquire(plan.estimated_archive_size) {
        let temp_scope = secure_root.clone();
        let temp_plan = plan.clone();
        match tokio::task::spawn_blocking(move || build_zip_temp(&temp_scope, &temp_plan))
            .await
            .map_err(internal)?
        {
            Ok(file) => {
                content_length = file.metadata().ok().map(|metadata| metadata.len());
                let stream = ReservedZipStream {
                    inner: ReaderStream::new(tokio::fs::File::from_std(file)),
                    _reservation: reservation,
                };
                transfer_body(
                    stream,
                    &state,
                    transfer.take().expect("ZIP transfer lease"),
                    "zip_download",
                    sh.id,
                    content_length,
                )
            }
            Err(error) if error.is_output_capacity_error() => {
                drop(reservation);
                transfer_body(
                    direct_zip_stream(secure_root, plan),
                    &state,
                    transfer.take().expect("ZIP transfer lease"),
                    "zip_download",
                    sh.id,
                    None,
                )
            }
            Err(error) => {
                let lease = transfer
                    .as_ref()
                    .expect("ZIP transfer lease")
                    .lease_token
                    .as_ref()
                    .expect("ZIP transfer lease token")
                    .clone();
                let _ = database(state.db.clone(), move |database| {
                    database.cancel_transfer_lease(&lease).map(|_| ())
                })
                .await;
                return Err(zip_error(error));
            }
        }
    } else {
        transfer_body(
            direct_zip_stream(secure_root, plan),
            &state,
            transfer.take().expect("ZIP transfer lease"),
            "zip_download",
            sh.id,
            None,
        )
    };
    let name = Path::new(&sh.relative_path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("vaultlink");
    let filename = encoded(&format!("{name}.zip"));
    let mut response = Response::new(body);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{filename}"))
            .map_err(internal)?,
    );
    if let Some(length) = content_length {
        response.headers_mut().insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&length.to_string()).map_err(internal)?,
        );
    }
    set_transfer_cookie(&mut response, &transfer_cookie_value)?;
    Ok(response)
}

pub(crate) async fn download(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response> {
    let sh = get_share(&state, &token).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Freigabe ist gesperrt"));
    }
    if !sh.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "Download nicht erlaubt"));
    }
    let relative_file = if sh.is_directory {
        let rel = q
            .path
            .ok_or(AppError(StatusCode::BAD_REQUEST, "Dateipfad fehlt"))?;
        path_security::validate_relative(&rel)
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Dateipfad"))?
            .to_string_lossy()
            .replace('\\', "/")
    } else {
        sh.relative_path.clone()
    };
    if method == Method::HEAD {
        check_public_transfer_availability(
            &state,
            &headers,
            &sh,
            relative_file.clone(),
            "download",
        )
        .await?;
    }
    let secure_root = state.secure_root.clone();
    let open_path = relative_file.clone();
    let share_path = sh.relative_path.clone();
    let directory_share = sh.is_directory;
    let file = tokio::task::spawn_blocking(move || {
        if directory_share {
            secure_root
                .bind_directory(&share_path)?
                .open_file(&open_path)
                .map(SecureFile::into_file)
        } else {
            secure_root
                .bind_file(&share_path)
                .map(SecureFile::into_file)
        }
    })
    .await
    .map_err(internal)?
    .map_err(|_| AppError(StatusCode::NOT_FOUND, "Datei nicht verfügbar"))?;
    if !file.metadata().map_err(internal)?.is_file() {
        return Err(AppError(StatusCode::BAD_REQUEST, "Keine Datei"));
    }
    let mut f = tokio::fs::File::from_std(file);
    let length = f.metadata().await.map_err(internal)?.len();
    let range = match headers.get(header::RANGE) {
        Some(value) => match value
            .to_str()
            .ok()
            .and_then(|value| parse_byte_range(value, length).ok())
        {
            Some(range) => Some(range),
            None => {
                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                response.headers_mut().insert(
                    header::CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes */{length}")).map_err(internal)?,
                );
                return Ok(response);
            }
        },
        None => None,
    };
    let transfer = if method == Method::GET {
        Some(
            begin_public_transfer(
                &state,
                &headers,
                &uri,
                &sh,
                relative_file.clone(),
                "download",
            )
            .await?,
        )
    } else {
        None
    };
    let (start, end) = range.unwrap_or((0, length.saturating_sub(1)));
    let response_length = if length == 0 { 0 } else { end - start + 1 };
    if start > 0 {
        f.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(internal)?;
    }
    let name = Path::new(&relative_file)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("download");
    let encoded = percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC);
    let (body, transfer_cookie_value) = if let Some(transfer) = transfer {
        let cookie = transfer.cookie.clone();
        let body = if response_length == 0 {
            complete_transfer_without_body(&state, transfer, "download", sh.id).await?;
            Body::empty()
        } else {
            transfer_body(
                ReaderStream::new(f.take(response_length)),
                &state,
                transfer,
                "download",
                sh.id,
                Some(response_length),
            )
        };
        (body, Some(cookie))
    } else {
        (Body::empty(), None)
    };
    let mut r = Response::new(body);
    if range.is_some() {
        *r.status_mut() = StatusCode::PARTIAL_CONTENT;
        r.headers_mut().insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {start}-{end}/{length}")).map_err(internal)?,
        );
    }
    r.headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    r.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&response_length.to_string()).map_err(internal)?,
    );
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(
            mime_guess::from_path(&relative_file)
                .first_or_octet_stream()
                .as_ref(),
        )
        .unwrap(),
    );
    r.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{encoded}"))
            .map_err(internal)?,
    );
    if let Some(cookie) = transfer_cookie_value {
        set_transfer_cookie(&mut r, &cookie)?;
    }
    Ok(r)
}
pub(crate) async fn upload(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    mut multipart: Multipart,
) -> Result<Response> {
    let sh = get_share(&state, &token).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Freigabe ist gesperrt"));
    }
    if !sh.is_directory || !sh.permission.can_upload() {
        return Err(AppError(StatusCode::FORBIDDEN, "Upload nicht erlaubt"));
    }
    let share_scope = state
        .secure_root
        .bind_directory(&sh.relative_path)
        .map_err(|_| AppError(StatusCode::NOT_FOUND, "Zielordner nicht verfügbar"))?;
    let settings = runtime_settings(&state);
    let maximum = sh.max_upload_size.unwrap_or(settings.max_upload_size);
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| !storage_has_room(state.secure_root.display_root(), length))
    {
        return Ok(public_upload_error(
            &token,
            "",
            StatusCode::INSUFFICIENT_STORAGE,
            "Nicht genug freier Speicher",
        ));
    }
    let mut upload_subdir = String::new();
    let mut overwrite_existing = false;
    let mut fields_seen = 0usize;
    let mut saw_path = false;
    let mut saw_overwrite = false;
    let mut prepared_upload: Option<(PendingUpload, String, u64)> = None;
    while let Some(field) = match multipart.next_field().await {
        Ok(field) => field,
        Err(_) => {
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::BAD_REQUEST,
                "Ungültiger Upload",
            ))
        }
    } {
        fields_seen += 1;
        if fields_seen > MAX_UPLOAD_MULTIPART_FIELDS {
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::BAD_REQUEST,
                "Zu viele Multipart-Felder",
            ));
        }
        let field_name = field.name().unwrap_or("").to_string();
        if field_name == "path" {
            if std::mem::replace(&mut saw_path, true) || prepared_upload.is_some() {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::BAD_REQUEST,
                    "Uploadpfad wurde mehrfach oder zu spät übermittelt",
                ));
            }
            let value = match limited_multipart_text(field, MAX_UPLOAD_PATH_FIELD_BYTES).await {
                Ok(value) => value,
                Err(_) => {
                    return Ok(public_upload_error(
                        &token,
                        &upload_subdir,
                        StatusCode::BAD_REQUEST,
                        "Ungültiger Uploadpfad",
                    ))
                }
            };
            if sh.permission == Permission::DownloadUpload {
                upload_subdir = match path_security::validate_relative(&value) {
                    Ok(path) => path.to_string_lossy().replace('\\', "/"),
                    Err(_) => {
                        return Ok(public_upload_error(
                            &token,
                            &upload_subdir,
                            StatusCode::BAD_REQUEST,
                            "Ungültiger Uploadpfad",
                        ))
                    }
                };
            }
            continue;
        }
        if field_name == "overwrite_existing" {
            if std::mem::replace(&mut saw_overwrite, true) {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::BAD_REQUEST,
                    "Uploadoption wurde mehrfach übermittelt",
                ));
            }
            let value = match limited_multipart_text(field, MAX_UPLOAD_OPTION_FIELD_BYTES).await {
                Ok(value) => value,
                Err(_) => {
                    return Ok(public_upload_error(
                        &token,
                        &upload_subdir,
                        StatusCode::BAD_REQUEST,
                        "Ungültiger Upload",
                    ))
                }
            };
            overwrite_existing = value == "1";
            continue;
        }
        if field_name != "file" {
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::BAD_REQUEST,
                "Unbekanntes Multipart-Feld",
            ));
        }
        if prepared_upload.is_some() {
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::BAD_REQUEST,
                "Pro Request ist genau eine Datei erlaubt",
            ));
        }
        let Some(file_name) = field.file_name() else {
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::BAD_REQUEST,
                "Dateiname fehlt",
            ));
        };
        let name = match path_security::safe_filename(file_name) {
            Ok(name) => name.to_string(),
            Err(_) => {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::BAD_REQUEST,
                    "Ungültiger Dateiname",
                ))
            }
        };
        if crate::secure_fs::is_upload_fragment_name(std::ffi::OsStr::new(&name)) {
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::BAD_REQUEST,
                "Dateiname ist für interne Uploadfragmente reserviert",
            ));
        }
        if extension_is_blocked(&name, &settings.blocked_extensions) {
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Dateityp blockiert",
            ));
        }
        let secure_root = share_scope.clone();
        let upload_directory = upload_subdir.clone();
        let pending_file = tokio::task::spawn_blocking(move || {
            let mut pending = secure_root
                .begin_upload(&upload_directory)
                .map_err(|_| PendingUploadFileError::Begin)?;
            let file = pending.take_file().map_err(PendingUploadFileError::Take)?;
            Ok::<_, PendingUploadFileError>((pending, file))
        })
        .await
        .map_err(internal)?;
        let (pending, file) = match pending_file {
            Ok(value) => value,
            Err(PendingUploadFileError::Begin) => {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::NOT_FOUND,
                    "Zielordner nicht verfügbar",
                ))
            }
            Err(PendingUploadFileError::Take(error)) => return Err(upload_io_error(error)),
        };
        let mut output = tokio::fs::File::from_std(file);
        let mut total = 0u64;
        let stream = field;
        tokio::pin!(stream);
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(_) => {
                    return Ok(public_upload_error(
                        &token,
                        &upload_subdir,
                        StatusCode::BAD_REQUEST,
                        "Upload abgebrochen",
                    ))
                }
            };
            let Some(new_total) = add_upload_bytes(total, chunk.len(), maximum) else {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Upload ist zu groß",
                ));
            };
            if !storage_has_room(state.secure_root.display_root(), chunk.len() as u64) {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Nicht genug freier Speicher",
                ));
            }
            total = new_total;
            if let Err(e) = output.write_all(&chunk).await {
                return if storage_full_error(&e) {
                    Ok(public_upload_error(
                        &token,
                        &upload_subdir,
                        StatusCode::INSUFFICIENT_STORAGE,
                        "Nicht genug freier Speicher",
                    ))
                } else {
                    Err(upload_io_error(e))
                };
            }
        }
        if let Err(e) = output.flush().await {
            return if storage_full_error(&e) {
                Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Nicht genug freier Speicher",
                ))
            } else {
                Err(upload_io_error(e))
            };
        }
        if let Err(e) = output.sync_all().await {
            return if storage_full_error(&e) {
                Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Nicht genug freier Speicher",
                ))
            } else {
                Err(upload_io_error(e))
            };
        }
        drop(output);
        prepared_upload = Some((pending, name, total));
    }
    let Some((mut pending, name, total)) = prepared_upload else {
        return Ok(public_upload_error(
            &token,
            &upload_subdir,
            StatusCode::BAD_REQUEST,
            "Datei fehlt",
        ));
    };
    let publish_name = name.clone();
    let allow_replace = sh.upload_conflict_strategy.can_overwrite() && overwrite_existing;
    #[cfg(test)]
    if let Some(kind) = state
        .upload_directory_sync_failure
        .lock()
        .expect("upload sync fault lock")
        .take()
    {
        pending.fail_next_directory_sync(kind);
    }
    let _storage_guard = state.storage_mutation.lock().await;
    let destination = join_display(&upload_subdir, &name);
    let existed = match share_scope.metadata(&destination) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(internal(error)),
    };
    let replaced = allow_replace && existed;
    let publish_result = tokio::task::spawn_blocking(move || {
        if allow_replace {
            pending.publish_replace(&publish_name)
        } else {
            pending.publish(&publish_name)
        }
    })
    .await
    .map_err(internal)?;
    let publish_outcome = match publish_result {
        Ok(outcome) => outcome,
        Err(error) => {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::CONFLICT,
                    "Datei existiert bereits.",
                ));
            }
            return if storage_full_error(&error) {
                Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Nicht genug freier Speicher",
                ))
            } else {
                Err(internal(error))
            };
        }
    };
    let durability_uncertain = !publish_outcome.is_durable();
    let audit_detail = format!("file={name};bytes={total}");
    if let Some(error) = publish_outcome.sync_error() {
        tracing::warn!(share_id = sh.id, file = %name, %error, "upload published but directory fsync failed");
        audit(
            &state,
            "public".into(),
            "upload_durability_uncertain",
            Some(sh.id.to_string()),
            Some(audit_detail.clone()),
        )
        .await;
    }
    audit(
        &state,
        "public".into(),
        if replaced {
            "upload_replaced"
        } else {
            "upload"
        },
        Some(sh.id.to_string()),
        Some(audit_detail),
    )
    .await;
    let upload_status = match (replaced, durability_uncertain) {
        (true, true) => "replaced_uncertain",
        (false, true) => "uncertain",
        (true, false) => "replaced",
        (false, false) => "ok",
    };
    let public_route = public_share_route(&uri, &token);
    let target = if upload_subdir.is_empty() {
        format!("{public_route}?upload={upload_status}")
    } else {
        format!(
            "{public_route}?path={}&upload={upload_status}",
            encoded(&upload_subdir)
        )
    };
    let outcome = match upload_status {
        "replaced_uncertain" => "replaced_uncertain",
        "uncertain" => "created_uncertain",
        "replaced" => "replaced",
        _ => "created",
    };
    let mut response = Redirect::to(&target).into_response();
    response.headers_mut().insert(
        "x-vaultlink-upload-file",
        HeaderValue::from_str(&encoded(&name)).map_err(internal)?,
    );
    response.headers_mut().insert(
        "x-vaultlink-upload-outcome",
        HeaderValue::from_static(outcome),
    );
    if durability_uncertain {
        response.headers_mut().insert(
            "x-vaultlink-durability",
            HeaderValue::from_static("uncertain"),
        );
    }
    Ok(response)
}

#[derive(Serialize)]
struct UploadQueueSuccess {
    file: String,
    outcome: String,
}

#[derive(Serialize)]
struct UploadQueueErrorEnvelope {
    error: UploadQueueError,
}

#[derive(Serialize)]
struct UploadQueueError {
    code: String,
    message: String,
}

fn upload_queue_error_response(status: StatusCode, message: &str) -> Response {
    let message = i18n::text_from_german(i18n::current_locale(), message);
    let code = match status {
        StatusCode::BAD_REQUEST => "invalid_upload",
        StatusCode::UNAUTHORIZED => "share_locked",
        StatusCode::FORBIDDEN => "upload_forbidden",
        StatusCode::NOT_FOUND => "target_not_found",
        StatusCode::CONFLICT => "file_exists",
        StatusCode::PAYLOAD_TOO_LARGE => "upload_too_large",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "blocked_extension",
        StatusCode::INSUFFICIENT_STORAGE => "insufficient_storage",
        _ => "upload_failed",
    };
    (
        status,
        Json(UploadQueueErrorEnvelope {
            error: UploadQueueError {
                code: code.to_string(),
                message,
            },
        }),
    )
        .into_response()
}

async fn upload_queue(
    state: State<AppState>,
    uri: OriginalUri,
    headers: HeaderMap,
    token: AxPath<String>,
    multipart: Multipart,
) -> Result<Response> {
    let response = match upload(state, uri, headers, token, multipart).await {
        Ok(response) => response,
        Err(AppError(status, message)) => {
            return Ok(upload_queue_error_response(status, message));
        }
    };
    if response.status().is_redirection() {
        let file = response
            .headers()
            .get("x-vaultlink-upload-file")
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                percent_encoding::percent_decode_str(value)
                    .decode_utf8_lossy()
                    .into_owned()
            })
            .unwrap_or_default();
        let outcome = response
            .headers()
            .get("x-vaultlink-upload-outcome")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("created")
            .to_string();
        return Ok(Json(UploadQueueSuccess { file, outcome }).into_response());
    }

    let status = response.status();
    Ok(upload_queue_error_response(
        status,
        status.canonical_reason().unwrap_or("Upload fehlgeschlagen"),
    ))
}
async fn short_redirect(
    State(state): State<AppState>,
    AxPath(alias): AxPath<String>,
) -> Result<Redirect> {
    if alias.len() > 32
        || !alias
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(AppError(StatusCode::NOT_FOUND, "Alias nicht gefunden"));
    }
    let sh = database(state.db.clone(), move |db| db.share_by_alias(&alias))
        .await?
        .ok_or(AppError(StatusCode::NOT_FOUND, "Alias nicht gefunden"))?;
    usable(&sh)?;
    Ok(Redirect::to(&format!("/v/{}", sh.token)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Config, Logging, ReverseProxy, Security, Server, ServerMode, Storage, Tls,
    };
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;

    fn test_state(root: &Path, data: &Path) -> AppState {
        test_state_with_limit(root, data, 1024 * 1024)
    }

    fn test_state_with_limit(root: &Path, data: &Path, max_upload_size: u64) -> AppState {
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
                max_upload_size,
                max_zip_size: 1024 * 1024,
                max_zip_files: 100,
                max_search_entries: 1000,
                max_search_results: 100,
                max_preview_size: 1024,
                preview_extensions: vec!["txt".into(), "log".into(), "md".into()],
                image_preview_extensions: vec![
                    "jpg".into(),
                    "jpeg".into(),
                    "png".into(),
                    "gif".into(),
                    "webp".into(),
                    "bmp".into(),
                    "avif".into(),
                ],
                pdf_preview_enabled: true,
                max_media_preview_size: 1024 * 1024,
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

    fn request(method: Method, uri: &str, body: &str) -> Request {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT_LANGUAGE, "de")
            .body(Body::from(body.to_string()))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
        ));
        request
    }

    fn zip_u16(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
    }

    fn zip_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    fn zip_u64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    #[test]
    fn public_preview_back_link_returns_share_parent() {
        assert_eq!(public_back_link("/v/tok", "file.txt", false), "/v/tok");
        assert_eq!(public_back_link("/v/tok", "file.txt", true), "/v/tok");
        assert_eq!(
            public_back_link("/v/tok", "folder/file.txt", true),
            "/v/tok?path=folder"
        );
        assert_eq!(
            public_back_link("/api/v1/public/shares/tok", "folder/file.txt", true),
            "/api/v1/public/shares/tok?path=folder"
        );
    }

    #[test]
    fn storage_full_error_maps_linux_quota_and_space_errors() {
        assert!(storage_full_error(&std::io::Error::from_raw_os_error(28)));
        assert!(storage_full_error(&std::io::Error::from_raw_os_error(122)));
        assert!(!storage_full_error(&std::io::Error::from_raw_os_error(13)));
    }

    #[test]
    fn every_zip_archive_uses_full_zip64_records() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("docs")).unwrap();
        std::fs::write(root.path().join("docs/tiny.bin"), b"abc").unwrap();
        let state = test_state(root.path(), data.path());
        let scope = state.secure_root.bind_directory("docs").unwrap();
        let files = vec![ZipFilePlan {
            source_path: "tiny.bin".into(),
            archive_name: "tiny.bin".into(),
            scanned_len: 3,
        }];
        let plan = ZipPlan {
            estimated_archive_size: estimate_zip_archive_size(&files).unwrap(),
            files,
            max_data_size: 3,
        };

        let archive = write_zip_archive(&scope, &plan, Vec::new()).unwrap();
        assert_eq!(archive.len() as u64, plan.estimated_archive_size);
        assert_eq!(archive.len(), 265);

        assert_eq!(zip_u32(&archive, 0), 0x0403_4b50);
        assert_eq!(zip_u16(&archive, 4), ZIP64_VERSION);
        assert_eq!(zip_u16(&archive, 6), 0x0808);
        assert_eq!(zip_u32(&archive, 18), u32::MAX);
        assert_eq!(zip_u32(&archive, 22), u32::MAX);
        assert_eq!(zip_u16(&archive, 26), 8);
        assert_eq!(zip_u16(&archive, 28), ZIP64_LOCAL_EXTRA_SIZE as u16);
        assert_eq!(&archive[30..38], b"tiny.bin");
        assert_eq!(zip_u16(&archive, 38), 0x0001);
        assert_eq!(zip_u16(&archive, 40), ZIP64_SIZE_FIELDS_SIZE);
        assert_eq!(zip_u64(&archive, 42), 0);
        assert_eq!(zip_u64(&archive, 50), 0);
        assert_eq!(&archive[58..61], b"abc");

        assert_eq!(zip_u32(&archive, 61), 0x0807_4b50);
        assert_eq!(zip_u32(&archive, 65), 0x3524_41c2);
        assert_eq!(zip_u64(&archive, 69), 3);
        assert_eq!(zip_u64(&archive, 77), 3);

        assert_eq!(zip_u32(&archive, 85), 0x0201_4b50);
        assert_eq!(zip_u16(&archive, 89), ZIP64_VERSION);
        assert_eq!(zip_u16(&archive, 91), ZIP64_VERSION);
        assert_eq!(zip_u32(&archive, 105), u32::MAX);
        assert_eq!(zip_u32(&archive, 109), u32::MAX);
        assert_eq!(zip_u16(&archive, 115), ZIP64_CENTRAL_EXTRA_SIZE as u16);
        assert_eq!(zip_u32(&archive, 127), u32::MAX);
        assert_eq!(&archive[131..139], b"tiny.bin");
        assert_eq!(zip_u16(&archive, 139), 0x0001);
        assert_eq!(zip_u16(&archive, 141), ZIP64_EXTRA_PAYLOAD_SIZE);
        assert_eq!(zip_u64(&archive, 143), 3);
        assert_eq!(zip_u64(&archive, 151), 3);
        assert_eq!(zip_u64(&archive, 159), 0);

        assert_eq!(zip_u32(&archive, 167), 0x0606_4b50);
        assert_eq!(zip_u64(&archive, 171), 44);
        assert_eq!(zip_u16(&archive, 179), ZIP64_VERSION);
        assert_eq!(zip_u16(&archive, 181), ZIP64_VERSION);
        assert_eq!(zip_u64(&archive, 191), 1);
        assert_eq!(zip_u64(&archive, 199), 1);
        assert_eq!(zip_u64(&archive, 207), 82);
        assert_eq!(zip_u64(&archive, 215), 85);
        assert_eq!(zip_u32(&archive, 223), 0x0706_4b50);
        assert_eq!(zip_u64(&archive, 231), 167);
        assert_eq!(zip_u32(&archive, 239), 1);
        assert_eq!(zip_u32(&archive, 243), 0x0605_4b50);
        assert_eq!(zip_u16(&archive, 251), u16::MAX);
        assert_eq!(zip_u16(&archive, 253), u16::MAX);
        assert_eq!(zip_u32(&archive, 255), u32::MAX);
        assert_eq!(zip_u32(&archive, 259), u32::MAX);

        let empty_files = Vec::<ZipFilePlan>::new();
        let empty_plan = ZipPlan {
            estimated_archive_size: estimate_zip_archive_size(&empty_files).unwrap(),
            files: empty_files,
            max_data_size: 0,
        };
        let empty_archive = write_zip_archive(&scope, &empty_plan, Vec::new()).unwrap();
        assert_eq!(empty_archive.len(), 98);
        assert_eq!(zip_u32(&empty_archive, 0), 0x0606_4b50);
        assert_eq!(zip_u64(&empty_archive, 24), 0);
        assert_eq!(zip_u32(&empty_archive, 56), 0x0706_4b50);
        assert_eq!(zip_u32(&empty_archive, 76), 0x0605_4b50);
    }

    #[test]
    fn every_central_entry_uses_zip64_sizes_and_offset() {
        let mut central = Vec::new();
        write_streaming_central_entry(
            &mut central,
            &StreamingZipEntry {
                name: "x".into(),
                crc: 7,
                size: 9,
                local_offset: 11,
            },
        )
        .unwrap();
        assert_eq!(central.len(), 75);
        assert_eq!(zip_u16(&central, 4), ZIP64_VERSION);
        assert_eq!(zip_u32(&central, 20), u32::MAX);
        assert_eq!(zip_u32(&central, 24), u32::MAX);
        assert_eq!(zip_u16(&central, 30), ZIP64_CENTRAL_EXTRA_SIZE as u16);
        assert_eq!(zip_u32(&central, 42), u32::MAX);
        assert_eq!(&central[46..47], b"x");
        assert_eq!(zip_u16(&central, 47), 0x0001);
        assert_eq!(zip_u16(&central, 49), ZIP64_EXTRA_PAYLOAD_SIZE);
        assert_eq!(zip_u64(&central, 51), 9);
        assert_eq!(zip_u64(&central, 59), 9);
        assert_eq!(zip_u64(&central, 67), 11);
    }

    #[test]
    fn zip64_end_records_preserve_64_bit_directory_values() {
        let entries = u16::MAX as u64;
        let central_size = u32::MAX as u64 + 3;
        let central_offset = u32::MAX as u64 + 9;
        let zip64_eocd_offset = 0x2_0000_0042;
        let mut records = Vec::new();
        write_streaming_zip64_eocd(&mut records, entries, central_size, central_offset).unwrap();
        write_streaming_zip64_locator(&mut records, zip64_eocd_offset).unwrap();
        write_streaming_eocd(&mut records).unwrap();

        assert_eq!(records.len(), 98);
        assert_eq!(zip_u32(&records, 0), 0x0606_4b50);
        assert_eq!(zip_u64(&records, 4), 44);
        assert_eq!(zip_u16(&records, 12), ZIP64_VERSION);
        assert_eq!(zip_u16(&records, 14), ZIP64_VERSION);
        assert_eq!(zip_u64(&records, 24), entries);
        assert_eq!(zip_u64(&records, 32), entries);
        assert_eq!(zip_u64(&records, 40), central_size);
        assert_eq!(zip_u64(&records, 48), central_offset);
        assert_eq!(zip_u32(&records, 56), 0x0706_4b50);
        assert_eq!(zip_u64(&records, 64), zip64_eocd_offset);
        assert_eq!(zip_u32(&records, 72), 1);
        assert_eq!(zip_u32(&records, 76), 0x0605_4b50);
        assert_eq!(zip_u16(&records, 84), u16::MAX);
        assert_eq!(zip_u16(&records, 86), u16::MAX);
        assert_eq!(zip_u32(&records, 88), u32::MAX);
        assert_eq!(zip_u32(&records, 92), u32::MAX);
    }

    #[test]
    fn always_zip64_estimate_is_fixed_and_rejects_u64_overflow() {
        assert_eq!(estimate_zip_archive_size(&[]).unwrap(), 98);

        let tiny_file = ZipFilePlan {
            source_path: "tiny.bin".into(),
            archive_name: "tiny.bin".into(),
            scanned_len: 3,
        };
        assert_eq!(estimate_zip_archive_size(&[tiny_file]).unwrap(), 265);

        let multiple_files = [
            ZipFilePlan {
                source_path: "first".into(),
                archive_name: "x".into(),
                scanned_len: 0,
            },
            ZipFilePlan {
                source_path: "second".into(),
                archive_name: "long".into(),
                scanned_len: 10,
            },
        ];
        assert_eq!(estimate_zip_archive_size(&multiple_files).unwrap(), 414);

        let overflowing_file = ZipFilePlan {
            source_path: "overflow.bin".into(),
            archive_name: "overflow.bin".into(),
            scanned_len: u64::MAX,
        };
        assert!(matches!(
            estimate_zip_archive_size(&[overflowing_file]),
            Err(ZipBuildError::Limit("zip archive size overflow"))
        ));
    }

    #[tokio::test]
    async fn non_upload_routes_reject_large_buffered_bodies() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let app = router(state);
        let oversized = format!(
            "username={}&password=x",
            "a".repeat(DEFAULT_REQUEST_BODY_LIMIT)
        );
        assert_eq!(
            app.oneshot(request(Method::POST, "/login", &oversized))
                .await
                .unwrap()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn upload_routes_reject_multipart_headers_before_the_parser_can_buffer_them() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("uploads")).unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("admin", "hash", "secret").unwrap();
        state
            .db
            .create_share(
                "guarded-upload",
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
        let app = router(state);
        let boundary = "guard-boundary";
        let body = format!(
            "--{boundary}\r\nX-Long: {}\r\n\r\nvalue\r\n--{boundary}--\r\n",
            "x".repeat(crate::multipart_guard::DEFAULT_MAX_HEADER_BYTES + 1)
        );
        let mut malformed = Request::builder()
            .method(Method::POST)
            .uri("/v/guarded-upload/upload")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap();
        malformed.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
        ));
        assert_eq!(
            app.clone().oneshot(malformed).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );

        let mut missing_content_type = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/public/shares/missing/upload")
            .body(Body::empty())
            .unwrap();
        missing_content_type.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
        ));
        let response = app.oneshot(missing_content_type).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert!(response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("application/json"));
    }

    #[tokio::test]
    async fn zip_temp_and_direct_paths_cap_files_at_the_scanned_size() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("docs")).unwrap();
        let file_path = root.path().join("docs/file.txt");
        std::fs::write(&file_path, b"small").unwrap();
        let state = test_state(root.path(), data.path());
        let scope = state.secure_root.bind_directory("docs").unwrap();
        let settings = runtime_settings(&state);
        let plan = plan_zip(&scope, "", &settings).unwrap();
        let estimated_archive_size = plan.estimated_archive_size;

        const GROWN_MARKER: &[u8] = b"-must-not-enter-the-archive";
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&file_path)
            .unwrap()
            .write_all(GROWN_MARKER)
            .unwrap();

        let mut temp_file = build_zip_temp(&scope, &plan).unwrap();
        let mut temp_bytes = Vec::new();
        temp_file.read_to_end(&mut temp_bytes).unwrap();

        let mut direct_bytes = Vec::new();
        let mut stream = Box::pin(direct_zip_stream(scope, plan));
        while let Some(chunk) = stream.next().await {
            direct_bytes.extend_from_slice(&chunk.unwrap());
        }

        assert_eq!(direct_bytes, temp_bytes);
        assert_eq!(temp_bytes.len() as u64, estimated_archive_size);
        assert!(temp_bytes.starts_with(b"PK\x03\x04"));
        let eocd = temp_bytes.len() - ZIP_EOCD_SIZE as usize;
        assert_eq!(zip_u32(&temp_bytes, eocd), 0x0605_4b50);
        assert_eq!(zip_u16(&temp_bytes, eocd + 8), u16::MAX);
        assert_eq!(zip_u16(&temp_bytes, eocd + 10), u16::MAX);
        assert_eq!(zip_u32(&temp_bytes, eocd + 12), u32::MAX);
        assert_eq!(zip_u32(&temp_bytes, eocd + 16), u32::MAX);
        assert!(!temp_bytes
            .windows(GROWN_MARKER.len())
            .any(|window| window == GROWN_MARKER));
    }

    #[test]
    fn zero_disables_zip_size_and_file_count_limits() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("docs")).unwrap();
        std::fs::write(root.path().join("docs/one.txt"), b"one").unwrap();
        std::fs::write(root.path().join("docs/two.txt"), b"two").unwrap();
        let state = test_state(root.path(), data.path());
        let scope = state.secure_root.bind_directory("docs").unwrap();
        let mut settings = runtime_settings(&state);
        settings.max_zip_size = 0;
        settings.max_zip_files = 0;

        let plan = plan_zip(&scope, "", &settings).unwrap();
        assert_eq!(plan.files.len(), 2);
        assert_eq!(plan.max_data_size, 0);
        write_zip_archive(&scope, &plan, Vec::new()).unwrap();
    }

    #[test]
    fn zip_planning_bounds_empty_directory_scans() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("docs")).unwrap();
        std::fs::create_dir(root.path().join("docs/one")).unwrap();
        std::fs::create_dir(root.path().join("docs/two")).unwrap();
        std::fs::create_dir(root.path().join("single")).unwrap();
        std::fs::write(root.path().join("single/only.txt"), b"one").unwrap();
        let state = test_state(root.path(), data.path());
        let scope = state.secure_root.bind_directory("docs").unwrap();
        let mut settings = runtime_settings(&state);
        settings.max_search_entries = 1;
        assert!(matches!(
            plan_zip(&scope, "", &settings),
            Err(ZipBuildError::Limit("zip scan entry limit exceeded"))
        ));
        let single = state.secure_root.bind_directory("single").unwrap();
        assert_eq!(plan_zip(&single, "", &settings).unwrap().files.len(), 1);
    }

    #[test]
    fn filtered_directory_items_consume_listing_search_and_zip_budgets() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("docs")).unwrap();
        for _ in 0..2 {
            std::fs::write(
                root.path()
                    .join("docs")
                    .join(crate::secure_fs::upload_fragment_name()),
                b"partial",
            )
            .unwrap();
        }
        let state = test_state(root.path(), data.path());
        let scope = state.secure_root.bind_directory("docs").unwrap();
        let mut settings = runtime_settings(&state);
        settings.max_search_entries = 1;

        let (entries, truncated) = list_directory_page(&scope, "", 0, 1).unwrap();
        assert!(entries.is_empty());
        assert!(truncated);
        assert!(search_tree(scope.clone(), "", "missing", &settings)
            .unwrap()
            .is_empty());
        assert!(matches!(
            plan_zip(&scope, "", &settings),
            Err(ZipBuildError::Limit("zip scan entry limit exceeded"))
        ));
    }

    fn multipart_request(uri: &str, name: &str, content: &[u8]) -> Request {
        multipart_request_with_path(uri, name, content, None)
    }

    fn multipart_request_with_path(
        uri: &str,
        name: &str,
        content: &[u8],
        path: Option<&str>,
    ) -> Request {
        multipart_request_with_options(uri, name, content, path, false)
    }

    fn multipart_request_with_options(
        uri: &str,
        name: &str,
        content: &[u8],
        path: Option<&str>,
        overwrite_existing: bool,
    ) -> Request {
        let boundary = "vaultlink-test-boundary";
        let mut body = Vec::new();
        if let Some(path) = path {
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n{path}\r\n"
                )
                .as_bytes(),
            );
        }
        if overwrite_existing {
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"overwrite_existing\"\r\n\r\n1\r\n"
                )
                .as_bytes(),
            );
        }
        body.extend_from_slice(format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        ).as_bytes());
        body.extend_from_slice(content);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::ACCEPT_LANGUAGE, "de")
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

    fn admin_multipart_request(
        uri: &str,
        path: &str,
        csrf: &str,
        name: &str,
        content: &[u8],
        overwrite_existing: bool,
    ) -> Request {
        let boundary = "vaultlink-admin-upload-boundary";
        let mut body = Vec::new();
        for (field, value) in [("path", path), ("csrf", csrf)] {
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{value}\r\n"
                )
                .as_bytes(),
            );
        }
        if overwrite_existing {
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"overwrite_existing\"\r\n\r\n1\r\n"
                )
                .as_bytes(),
            );
        }
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(content);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::ACCEPT_LANGUAGE, "de")
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
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn windows_1252_byte(ch: char) -> Option<u8> {
        match ch {
            '\u{0000}'..='\u{009f}' | '\u{00a0}'..='\u{00ff}' => Some(ch as u32 as u8),
            '\u{20ac}' => Some(0x80),
            '\u{201a}' => Some(0x82),
            '\u{0192}' => Some(0x83),
            '\u{201e}' => Some(0x84),
            '\u{2026}' => Some(0x85),
            '\u{2020}' => Some(0x86),
            '\u{2021}' => Some(0x87),
            '\u{02c6}' => Some(0x88),
            '\u{2030}' => Some(0x89),
            '\u{0160}' => Some(0x8a),
            '\u{2039}' => Some(0x8b),
            '\u{0152}' => Some(0x8c),
            '\u{017d}' => Some(0x8e),
            '\u{2018}' => Some(0x91),
            '\u{2019}' => Some(0x92),
            '\u{201c}' => Some(0x93),
            '\u{201d}' => Some(0x94),
            '\u{2022}' => Some(0x95),
            '\u{2013}' => Some(0x96),
            '\u{2014}' => Some(0x97),
            '\u{02dc}' => Some(0x98),
            '\u{2122}' => Some(0x99),
            '\u{0161}' => Some(0x9a),
            '\u{203a}' => Some(0x9b),
            '\u{0153}' => Some(0x9c),
            '\u{017e}' => Some(0x9e),
            '\u{0178}' => Some(0x9f),
            _ => None,
        }
    }

    fn assert_no_mojibake(label: &str, text: &str) {
        if let Some((offset, _)) = text.char_indices().find(|(_, ch)| *ch == '\u{fffd}') {
            panic!("{label} contains the Unicode replacement character at byte {offset}");
        }

        let chars = text.char_indices().collect::<Vec<_>>();
        for start in 0..chars.len() {
            for len in 2..=4 {
                let end = start + len;
                if end > chars.len() {
                    continue;
                }
                let Some(bytes) = chars[start..end]
                    .iter()
                    .map(|(_, ch)| windows_1252_byte(*ch))
                    .collect::<Option<Vec<_>>>()
                else {
                    continue;
                };
                let expected_len = match bytes[0] {
                    0xc2..=0xdf => 2,
                    0xe0..=0xef => 3,
                    0xf0..=0xf4 => 4,
                    _ => continue,
                };
                if len != expected_len
                    || !bytes[1..].iter().all(|byte| (0x80..=0xbf).contains(byte))
                {
                    continue;
                }
                let Ok(decoded) = std::str::from_utf8(&bytes) else {
                    continue;
                };
                let start_offset = chars[start].0;
                let end_offset = chars.get(end).map_or(text.len(), |(offset, _)| *offset);
                let suspect = &text[start_offset..end_offset];
                panic!(
                    "{label} contains likely Windows-1252/UTF-8 mojibake at byte {start_offset}: {suspect:?} should be {decoded:?}"
                );
            }
        }
    }

    fn preview_token_from(html: &str) -> String {
        let marker = "preview_token=";
        let start = html.find(marker).expect("preview token in html") + marker.len();
        let encoded = html[start..]
            .chars()
            .take_while(|c| *c != '"' && *c != '&')
            .collect::<String>();
        percent_encoding::percent_decode_str(&encoded)
            .decode_utf8()
            .unwrap()
            .into_owned()
    }

    fn range_request(method: Method, uri: &str, range: Option<&str>) -> Request {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(range) = range {
            builder = builder.header(header::RANGE, range);
        }
        let mut request = builder.body(Body::empty()).unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
        ));
        request
    }
    #[test]
    fn html_is_escaped() {
        assert_eq!(esc("<script>&\""), "&lt;script&gt;&amp;&quot;");
    }

    #[test]
    fn missing_session_error_redirects_to_login() {
        let response = AppError(StatusCode::SEE_OTHER, "/login").into_response();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/login");
    }

    #[test]
    fn invalid_credentials_remain_an_error() {
        let response = AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten").into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(header::LOCATION).is_none());
    }

    #[test]
    fn post_locale_return_targets_are_get_safe() {
        let uri = |value: &str| value.parse::<Uri>().unwrap();
        assert_eq!(
            locale_return_to(&Method::POST, &uri("/admin/account/password")),
            "/admin/account"
        );
        assert_eq!(
            locale_return_to(&Method::POST, &uri("/admin/admins/42/totp")),
            "/admin/admins"
        );
        assert_eq!(
            locale_return_to(&Method::POST, &uri("/admin/files/delete")),
            "/admin"
        );
        assert_eq!(
            locale_return_to(&Method::POST, &uri("/v/share-token/upload/queue")),
            "/v/share-token"
        );
        assert_eq!(
            locale_return_to(&Method::GET, &uri("/admin?path=folder")),
            "/admin?path=folder"
        );
    }
    #[test]
    fn permissions() {
        assert!(!Permission::DownloadOnly.can_upload());
        assert!(!Permission::UploadOnly.can_download());
        assert!(Permission::DownloadUpload.can_download());
    }

    #[test]
    fn csrf_rejects_mismatch() {
        let session = Session {
            admin_id: 1,
            username: "admin".into(),
            csrf_token: "expected".into(),
            mfa_verified: true,
        };
        assert!(csrf(&session, "expected").is_ok());
        assert!(csrf(&session, "wrong").is_err());
    }

    #[test]
    fn inactive_and_expired_shares_are_unusable() {
        let share = |active, expires_at| Share {
            id: 1,
            token: "token".into(),
            alias: None,
            relative_path: "file".into(),
            is_directory: false,
            permission: Permission::DownloadOnly,
            expires_at,
            max_downloads: None,
            max_upload_size: None,
            download_count: 0,
            active,
            password_hash: None,
            upload_conflict_strategy: UploadConflictStrategy::Reject,
            created_at: Utc::now().to_rfc3339(),
        };
        assert!(usable(&share(false, None)).is_err());
        assert!(usable(&share(true, Some(Utc::now() - Duration::seconds(1)))).is_err());
        assert!(usable(&share(true, Some(Utc::now() + Duration::hours(1)))).is_ok());
    }

    #[test]
    fn upload_policy_helpers() {
        let blocked = vec!["exe".to_string(), ".SH".to_string()];
        assert!(extension_is_blocked("payload.ExE", &blocked));
        assert!(extension_is_blocked("script.sh", &blocked));
        assert!(!extension_is_blocked("report.pdf", &blocked));
        assert_eq!(add_upload_bytes(5, 5, 10), Some(10));
        assert_eq!(add_upload_bytes(5, 6, 10), None);
        assert_eq!(add_upload_bytes(u64::MAX, 1, u64::MAX), None);
        assert_eq!(human(1_500_000_000), "1.5 GB");
        assert_eq!(format_unit_floor(53_687_091_200, GB), "53");
        assert_eq!(display_limit_unit_floor(1_073_741_824, GB), "1");
        assert_eq!(
            parse_unit_to_bytes("1.5", GB, "bad").unwrap(),
            1_500_000_000
        );
        assert_eq!(
            parse_expiry(Some("2026-07-07T20:32"), Some("-120"))
                .unwrap()
                .unwrap()
                .to_rfc3339(),
            "2026-07-07T18:32:00+00:00"
        );
        assert_eq!(
            parse_expiry(Some("07.07.2026 20:32"), Some("-120"))
                .unwrap()
                .unwrap()
                .to_rfc3339(),
            "2026-07-07T18:32:00+00:00"
        );
    }

    #[tokio::test]
    async fn admin_shell_renders_nav_icons_and_system_panel() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let html = i18n::scope(Locale::De, "/admin".into(), async {
            admin_page(&state, PageId::Files, "<section></section>", true, "csrf")
        })
        .await;
        assert!(html.contains("<title>Dateien · VaultLink</title>"));
        for label in ["Dateien", "Links", "Admins", "Einstellungen", "Audit"] {
            assert!(html.contains(&format!("<span>{label}</span>")));
        }
        assert!(html.contains("vl-icon"));
        assert_eq!(html.matches(r#"aria-current="page""#).count(), 1);
        assert!(!html.contains('📁'));
        assert!(html.contains("VaultLink erreichbar"));
        assert_no_mojibake("admin shell", &html);
        assert!(!html.contains("Secure Mode"));
    }

    #[tokio::test]
    async fn locale_route_sets_hardened_cookie_and_rejects_external_return_targets() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let app = router(test_state(root.path(), data.path()));

        let response = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/locale",
                "locale=en&return_to=%2Flogin%3Ffrom%3Dswitch",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/login?from=switch"
        );
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cookie.starts_with("vaultlink_locale=en;"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));
        assert!(!cookie.contains(" Secure;"));

        let response = app
            .oneshot(request(
                Method::POST,
                "/locale",
                "locale=de&return_to=https%3A%2F%2Fevil.example",
            ))
            .await
            .unwrap();
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/");

        let mut secure_state = test_state(root.path(), data.path());
        Arc::make_mut(&mut secure_state.config)
            .security
            .secure_cookie = true;
        let secure_response = router(secure_state)
            .oneshot(request(
                Method::POST,
                "/locale",
                "locale=en&return_to=%2Flogin",
            ))
            .await
            .unwrap();
        assert!(secure_response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains(" Secure;"));
    }

    #[tokio::test]
    async fn http_locale_resolution_uses_accept_language_then_english_fallback() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let app = router(test_state(root.path(), data.path()));

        let request_without_language = Request::builder()
            .uri("/login")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request_without_language).await.unwrap();
        assert_eq!(
            response.headers().get(header::CONTENT_LANGUAGE).unwrap(),
            "en"
        );
        assert!(response_text(response).await.contains("Admin sign in"));

        let mut german = request(Method::GET, "/login", "");
        german.headers_mut().insert(
            header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("de-AT,de;q=0.9"),
        );
        let response = app.clone().oneshot(german).await.unwrap();
        assert_eq!(
            response.headers().get(header::CONTENT_LANGUAGE).unwrap(),
            "de"
        );
        assert!(response_text(response).await.contains("Admin Login"));

        let mut cookie_override = request(Method::GET, "/login", "");
        cookie_override.headers_mut().insert(
            header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        cookie_override.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_static("vaultlink_locale=de"),
        );
        let response = app.oneshot(cookie_override).await.unwrap();
        assert_eq!(
            response.headers().get(header::CONTENT_LANGUAGE).unwrap(),
            "de"
        );
    }

    #[tokio::test]
    async fn queue_errors_localize_message_without_changing_machine_code() {
        let response = i18n::scope(Locale::En, "/v/token".into(), async {
            upload_queue_error_response(
                StatusCode::CONFLICT,
                "Datei existiert bereits; Ersetzen muss für diese Datei bestätigt werden",
            )
        })
        .await;
        let body = response_text(response).await;
        assert!(body.contains(r#""code":"file_exists""#));
        assert!(body.contains("File already exists"));
        assert!(!body.contains("Datei existiert"));
    }

    #[tokio::test]
    async fn english_locale_covers_main_routes_without_touching_user_values() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("Dateien"), b"public").unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("Abmelden", "hash", "secret").unwrap();
        state
            .db
            .create_session(
                "locale-session",
                1,
                "locale-csrf",
                Utc::now() + Duration::hours(1),
            )
            .unwrap();
        state.db.verify_mfa("locale-session").unwrap();
        state
            .db
            .create_share(
                "locale-public",
                None,
                "Dateien",
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
        let app = router(state);
        let routes = [
            ("/login", false),
            ("/admin", true),
            ("/admin/account", true),
            ("/admin/shares", true),
            ("/admin/admins", true),
            ("/admin/settings", true),
            ("/admin/audit", true),
            ("/v/locale-public", false),
        ];
        let forbidden_static_german = [
            "Zum Inhalt springen",
            "Dateibrowser",
            "Dateien durchsuchen",
            "Aktuellen Ordner freigeben",
            "Einstellungen",
            "Nachvollziehbarkeit",
            "Sichere Freigabe",
            "Benutzername",
            "Speichern",
            ">Abmelden</button>",
            ">Zurück<",
            ">Weiter<",
            ">Suchen<",
            ">Löschen<",
            ">Ansehen<",
            ">Erstellen<",
            ">Aktiv<",
            ">Abgelaufen<",
            ">Geschützt<",
            ">Passwort<",
            ">Größe<",
            ">Geändert<",
            ">Aktion<",
            ">Vorschau<",
        ];

        for (uri, authenticated) in routes {
            let mut request = request(Method::GET, uri, "");
            let cookie = if authenticated {
                "vaultlink_locale=en; vaultlink_session=locale-session"
            } else {
                "vaultlink_locale=en"
            };
            request
                .headers_mut()
                .insert(header::COOKIE, HeaderValue::from_static(cookie));
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "route {uri}");
            assert_eq!(
                response.headers().get(header::CONTENT_LANGUAGE).unwrap(),
                "en",
                "route {uri}"
            );
            let html = response_text(response).await;
            assert!(html.contains(r#"<html lang="en">"#), "route {uri}");
            assert!(!html.contains("<vl-i18n"), "unresolved marker on {uri}");
            for fragment in forbidden_static_german {
                assert!(
                    !html.contains(fragment),
                    "route {uri} still contains German UI fragment {fragment:?}"
                );
            }
            assert!(
                !html
                    .chars()
                    .any(|ch| matches!(ch, 'ä' | 'ö' | 'ü' | 'Ä' | 'Ö' | 'Ü' | 'ß')),
                "route {uri} still contains a German-specific character"
            );
            if uri == "/admin" || uri == "/v/locale-public" {
                assert!(html.contains("Dateien"), "user file name changed on {uri}");
            }
            if uri == "/admin/admins" {
                assert!(html.contains("Abmelden"), "user name was translated");
                assert!(html.contains("Log out"), "logout action was not translated");
            }
        }
    }

    #[tokio::test]
    async fn login_page_serves_correct_utf8() {
        let response = i18n::scope(Locale::De, "/login".into(), login_page())
            .await
            .into_response();
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        let html = response_text(response).await;
        assert!(html.contains("<meta charset=\"utf-8\">"));
        assert!(html.contains("<title>Login · VaultLink</title>"));
        assert_no_mojibake("login page", &html);
    }

    #[tokio::test]
    async fn csp_requires_self_hosted_styles_and_pages_have_no_inline_styles() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let response = router(test_state(root.path(), data.path()))
            .oneshot(request(Method::GET, "/login", ""))
            .await
            .unwrap();
        let csp = response
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("style-src 'self'"));
        assert!(!csp.contains("unsafe-inline"));
        assert!(!include_str!("web.rs").contains(concat!("style", "=")));
        assert!(!include_str!("setup.rs").contains(concat!("style", "=")));
    }

    #[test]
    fn user_facing_sources_do_not_contain_mojibake() {
        assert_no_mojibake("src/web.rs", include_str!("web.rs"));
        assert_no_mojibake("src/setup.rs", include_str!("setup.rs"));
    }

    #[test]
    #[should_panic(expected = "likely Windows-1252/UTF-8 mojibake")]
    fn mojibake_guard_rejects_redecoded_utf8_bytes() {
        let broken_folder = ['\u{00f0}', '\u{0178}', '\u{201c}', '\u{0081}']
            .into_iter()
            .collect::<String>();
        assert_no_mojibake("broken folder icon", &broken_folder);
    }

    #[tokio::test]
    async fn settings_form_uses_decimal_whole_preview_defaults() {
        let session = Session {
            admin_id: 1,
            username: "admin".into(),
            csrf_token: "csrf".into(),
            mfa_verified: true,
        };
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let mut settings = runtime_settings(&state);
        settings.max_upload_size = 53_687_091_200;
        settings.max_zip_size = 1_000_000_000;
        settings.max_preview_size = 1_000_000;
        settings.max_media_preview_size = 100_000_000;

        let html = i18n::scope(Locale::De, "/admin/settings".into(), async {
            i18n::render_markers(Locale::De, &settings_form(&session, &settings, 0, ""))
        })
        .await;
        assert!(
            html.contains(r#"name="max_upload_size_gb" type="number" min="1" step="1" value="53""#)
        );
        assert!(html.contains(r#"name="max_zip_size_gb" type="number" min="0" step="1" value="1""#));
        assert!(
            html.contains(r#"name="max_preview_size_mb" type="number" min="1" step="1" value="1""#)
        );
        assert!(html.contains(
            r#"name="max_media_preview_size_mb" type="number" min="1" step="1" value="100""#
        ));
        assert!(html.contains("Suche Max. Einträge"));
        assert_no_mojibake("settings form", &html);
        assert!(!html.contains("Media-Preview Max. GB"));
    }

    #[test]
    fn custom_datetime_picker_replaces_native_browser_picker() {
        let css = app_css();
        let picker = i18n::render_markers(Locale::De, &expiry_picker_html());
        assert!(css.contains(".datetime-popover"));
        assert!(!css.contains(r#"datetime-local"]::-webkit-calendar-picker-indicator"#));
        assert!(picker.contains("data-datetime-picker"));
        assert!(picker.contains(r#"name="expires_local""#));
        assert!(picker.contains("TT.MM.JJJJ HH:MM"));
        assert!(!picker.contains(r#"type="datetime-local""#));
    }

    #[tokio::test]
    async fn file_time_uses_locale_date_order() {
        let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(60 * 60 * 20 + 32 * 60);
        let de = i18n::scope(Locale::De, "/".into(), async { format_file_time(time) }).await;
        let en = i18n::scope(Locale::En, "/".into(), async { format_file_time(time) }).await;
        assert_eq!(de, "01.01.1970 20:32 UTC");
        assert_eq!(en, "1970-01-01 20:32 UTC");
    }

    #[tokio::test]
    async fn byte_sizes_use_locale_decimal_separator() {
        let de = i18n::scope(Locale::De, "/".into(), async { human(1_500_000_000) }).await;
        let en = i18n::scope(Locale::En, "/".into(), async { human(1_500_000_000) }).await;
        assert_eq!(de, "1,5 GB");
        assert_eq!(en, "1.5 GB");
    }

    #[test]
    fn removed_setup_form_and_browser_rewrite_stay_removed() {
        assert!(!include_str!("setup.rs").contains(concat!("setup_form_", "legacy")));
        assert!(!include_str!("web.rs").contains(concat!("body.", "replace(")));
    }

    #[test]
    fn public_preview_actions_are_rendered_above_content() {
        let body =
            r#"<section><h1><vl-i18n key="files.preview"/></h1><pre>long text</pre></section>"#
                .to_string();
        let html = i18n::render_markers(
            Locale::De,
            &add_public_preview_actions(body, "/v/token", Some("/v/token/download")),
        );
        let actions = html.find("Zurück zur Freigabe").unwrap();
        let content = html.find("<pre>long text</pre>").unwrap();
        assert!(actions < content);
        assert!(html.contains("Herunterladen"));
    }

    #[cfg(unix)]
    #[test]
    fn disk_stats_uses_target_path() {
        let root = tempfile::tempdir().unwrap();
        let stats = disk_stats(root.path()).expect("statvfs must work for tempdir");
        assert!(stats.total > 0);
        assert!(stats.free > 0);
    }

    #[tokio::test]
    async fn create_new_prevents_upload_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("existing.txt");
        tokio::fs::write(&path, b"original").await.unwrap();
        let result = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await;
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"original");
    }

    #[tokio::test]
    async fn http_login_mfa_csrf_session_and_logout() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let secret = auth::new_totp_secret();
        state
            .db
            .create_admin(
                "admin",
                &auth::hash_password("a sufficiently long password").unwrap(),
                &secret,
            )
            .unwrap();
        let app = router(state.clone());

        let invalid = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/login",
                "username=admin&password=wrong",
            ))
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);

        let login = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/login",
                "username=admin&password=a%20sufficiently%20long%20password",
            ))
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::SEE_OTHER);
        let cookie = login
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let session_token = cookie.split_once('=').unwrap().1.to_string();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code = auth::totp_code(&secret, now / 30).unwrap();
        let mut mfa_request = request(Method::POST, "/mfa", &format!("code={code}"));
        mfa_request
            .headers_mut()
            .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
        let mfa = app.clone().oneshot(mfa_request).await.unwrap();
        assert_eq!(mfa.status(), StatusCode::SEE_OTHER);

        let mut admin_request = request(Method::GET, "/admin", "");
        admin_request
            .headers_mut()
            .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
        let admin = app.clone().oneshot(admin_request).await.unwrap();
        assert_eq!(admin.status(), StatusCode::OK);
        assert_eq!(
            admin.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );

        let mut bad_csrf = request(Method::POST, "/logout", "csrf=wrong");
        bad_csrf
            .headers_mut()
            .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
        assert_eq!(
            app.clone().oneshot(bad_csrf).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let csrf = state
            .db
            .session(&session_token)
            .unwrap()
            .unwrap()
            .csrf_token;
        let mut logout_request = request(Method::POST, "/logout", &format!("csrf={csrf}"));
        logout_request
            .headers_mut()
            .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
        assert_eq!(
            app.clone().oneshot(logout_request).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );
        assert!(state.db.session(&session_token).unwrap().is_none());
    }

    #[tokio::test]
    async fn share_creation_page_uses_browser_selected_path() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("file.txt"), b"file").unwrap();
        std::fs::create_dir(root.path().join("uploads")).unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("admin", "hash", "secret").unwrap();
        state
            .db
            .create_session(
                "session-token",
                1,
                "csrf-token",
                Utc::now() + Duration::hours(1),
            )
            .unwrap();
        state.db.verify_mfa("session-token").unwrap();
        let app = router(state.clone());
        let cookie = HeaderValue::from_static("vaultlink_session=session-token");

        let javascript = response_text(
            app.clone()
                .oneshot(request(Method::GET, "/assets/app.js", ""))
                .await
                .unwrap(),
        )
        .await;
        assert!(javascript.contains("initDeleteConfirmation"));
        assert!(javascript.contains("input.value!==form.dataset.requiredName"));

        let mut browser_root = request(Method::GET, "/admin", "");
        browser_root
            .headers_mut()
            .insert(header::COOKIE, cookie.clone());
        let browser_root = response_text(app.clone().oneshot(browser_root).await.unwrap()).await;
        assert!(browser_root.contains("Aktuellen Ordner freigeben"));
        assert!(browser_root.contains(r#"/admin/shares/new?path=."#));
        assert!(browser_root.contains(r#"action="/admin/files/directories""#));
        assert!(browser_root.contains(r#"action="/admin/files/rename""#));
        assert!(browser_root.contains(r#"/admin/files/delete?path=file%2Etxt"#));

        let mut create_folder = request(
            Method::POST,
            "/admin/files/directories",
            "csrf=csrf-token&parent=&name=Neu",
        );
        create_folder
            .headers_mut()
            .insert(header::COOKIE, cookie.clone());
        assert_eq!(
            app.clone().oneshot(create_folder).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );
        assert!(root.path().join("Neu").is_dir());

        std::fs::create_dir(root.path().join("tree")).unwrap();
        std::fs::write(root.path().join("tree/child.txt"), b"child").unwrap();
        let mut delete_confirmation = request(Method::GET, "/admin/files/delete?path=tree", "");
        delete_confirmation
            .headers_mut()
            .insert(header::COOKIE, cookie.clone());
        let delete_confirmation =
            response_text(app.clone().oneshot(delete_confirmation).await.unwrap()).await;
        assert!(delete_confirmation.contains(r#"name="confirm_name""#));
        assert!(delete_confirmation.contains("data-confirm-input autofocus"));
        assert!(
            delete_confirmation.contains(r#"data-delete-confirmation data-required-name="tree""#)
        );
        assert!(delete_confirmation.contains(r#"data-confirm-delete disabled"#));
        assert!(delete_confirmation.contains("tree"));

        let mut browser_folder = request(Method::GET, "/admin?path=uploads", "");
        browser_folder
            .headers_mut()
            .insert(header::COOKIE, cookie.clone());
        let browser_folder =
            response_text(app.clone().oneshot(browser_folder).await.unwrap()).await;
        assert!(browser_folder.contains(r#"/admin/shares/new?path=uploads"#));

        let mut folder_request = request(Method::GET, "/admin/shares/new?path=uploads", "");
        folder_request
            .headers_mut()
            .insert(header::COOKIE, cookie.clone());
        let folder = response_text(app.clone().oneshot(folder_request).await.unwrap()).await;
        assert!(folder.contains(r#"<strong>/uploads</strong>"#));
        assert!(folder.contains(r#"<input type="hidden" name="path" value="uploads">"#));
        assert!(folder.contains(r#"value="upload_only""#));

        let mut file_request = request(Method::GET, "/admin/shares/new?path=file.txt", "");
        file_request.headers_mut().insert(header::COOKIE, cookie);
        let file = response_text(app.clone().oneshot(file_request).await.unwrap()).await;
        assert!(file.contains(r#"<strong>/file.txt</strong>"#));
        assert!(file.contains(r#"<input type="hidden" name="path" value="file.txt">"#));
        assert!(file.contains(r#"value="download_only""#));
        assert!(!file.contains(r#"value="upload_only""#));
        assert!(!file.contains("data-upload-rules"));

        let mut missing_password = request(
            Method::POST,
            "/admin/shares",
            "csrf=csrf-token&path=uploads&permission=upload_only&alias=&max_downloads=&password_enabled=1&password=&password_confirm=",
        );
        missing_password.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_static("vaultlink_session=session-token"),
        );
        assert_eq!(
            app.clone()
                .oneshot(missing_password)
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );

        let mut create_request = request(
            Method::POST,
            "/admin/shares",
            "csrf=csrf-token&path=uploads&permission=upload_only&alias=&max_downloads=&password=&password_confirm=",
        );
        create_request.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_static("vaultlink_session=session-token"),
        );
        assert_eq!(
            app.clone().oneshot(create_request).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );

        let mut rejected_zero = request(
            Method::POST,
            "/admin/shares",
            "csrf=csrf-token&path=uploads&permission=upload_only&alias=&max_downloads=&max_upload_size=0&password=&password_confirm=",
        );
        rejected_zero.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_static("vaultlink_session=session-token"),
        );
        assert_eq!(
            app.clone().oneshot(rejected_zero).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );

        let mut legacy_limit = request(
            Method::POST,
            "/admin/shares",
            "csrf=csrf-token&path=uploads&permission=upload_only&alias=&max_downloads=&max_upload_size=1234&password=&password_confirm=",
        );
        legacy_limit.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_static("vaultlink_session=session-token"),
        );
        assert_eq!(
            app.oneshot(legacy_limit).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );
        let shares = state.db.list_shares().unwrap();
        assert_eq!(shares.len(), 2);
        assert!(shares.iter().all(|share| share.relative_path == "uploads"));
        assert!(shares.iter().all(|share| share.max_downloads.is_none()));
        assert_eq!(
            shares
                .iter()
                .filter(|share| share.max_upload_size == Some(1234))
                .count(),
            1
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn public_share_scope_blocks_sibling_symlink_http_flows() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("share-a/real")).unwrap();
        std::fs::create_dir_all(root.path().join("share-b/uploads")).unwrap();
        std::fs::write(root.path().join("share-a/real/allowed.txt"), "allowed").unwrap();
        std::fs::write(root.path().join("share-b/secret.txt"), "secret").unwrap();
        symlink("real", root.path().join("share-a/inside")).unwrap();
        symlink("../share-b", root.path().join("share-a/outside")).unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("admin", "hash", "secret").unwrap();
        state
            .db
            .create_share(
                "scope",
                None,
                "share-a",
                true,
                &Permission::DownloadUpload,
                None,
                None,
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        let app = router(state.clone());

        let allowed = app
            .clone()
            .oneshot(request(
                Method::GET,
                "/v/scope/download?path=inside/allowed.txt",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        assert_eq!(response_text(allowed).await, "allowed");

        for uri in [
            "/v/scope?path=outside",
            "/v/scope/download?path=outside/secret.txt",
            "/v/scope/preview?path=outside/secret.txt",
            "/v/scope/download.zip?path=outside",
        ] {
            assert_eq!(
                app.clone()
                    .oneshot(request(Method::GET, uri, ""))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND,
                "{uri} crossed the share boundary"
            );
        }
        let upload = app
            .oneshot(multipart_request_with_path(
                "/v/scope/upload",
                "created.txt",
                b"blocked",
                Some("outside/uploads"),
            ))
            .await
            .unwrap();
        assert_eq!(upload.status(), StatusCode::NOT_FOUND);
        assert!(!root.path().join("share-b/uploads/created.txt").exists());
    }

    #[tokio::test]
    async fn transfer_session_counts_range_resume_once_and_abort_not_at_all() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("file.txt"), b"abcdef").unwrap();
        std::fs::create_dir(root.path().join("zipdocs")).unwrap();
        std::fs::write(root.path().join("zipdocs/one.txt"), b"one").unwrap();
        std::fs::write(root.path().join("zipdocs/two.txt"), b"two").unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("admin", "hash", "secret").unwrap();
        let _share_id = state
            .db
            .create_share(
                "limited",
                None,
                "file.txt",
                false,
                &Permission::DownloadOnly,
                None,
                Some(1),
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        let aborted_id = state
            .db
            .create_share(
                "aborted",
                None,
                "file.txt",
                false,
                &Permission::DownloadOnly,
                None,
                Some(1),
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        state
            .db
            .create_share(
                "known-length",
                None,
                "file.txt",
                false,
                &Permission::DownloadOnly,
                None,
                Some(1),
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        std::fs::write(root.path().join("empty.txt"), b"").unwrap();
        state
            .db
            .create_share(
                "empty",
                None,
                "empty.txt",
                false,
                &Permission::DownloadOnly,
                None,
                Some(1),
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        let exhausted_zip_id = state
            .db
            .create_share(
                "zip-exhausted",
                None,
                "zipdocs",
                true,
                &Permission::DownloadOnly,
                None,
                Some(1),
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        let failing_zip_id = state
            .db
            .create_share(
                "zip-failing",
                None,
                "zipdocs",
                true,
                &Permission::DownloadOnly,
                None,
                Some(1),
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        assert!(state.db.count_download(exhausted_zip_id).unwrap());
        state.runtime.write().unwrap().max_search_entries = 1;
        let app = router(state.clone());

        assert_eq!(
            app.clone()
                .oneshot(request(Method::GET, "/v/zip-exhausted/download.zip", "",))
                .await
                .unwrap()
                .status(),
            StatusCode::GONE
        );
        assert_eq!(
            app.clone()
                .oneshot(request(Method::GET, "/v/zip-failing/download.zip", ""))
                .await
                .unwrap()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        for _ in 0..100 {
            if state
                .db
                .active_transfer_reservations(failing_zip_id)
                .unwrap()
                == 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        assert_eq!(
            state
                .db
                .active_transfer_reservations(failing_zip_id)
                .unwrap(),
            0
        );
        assert_eq!(
            state
                .db
                .share_by_token("zip-failing")
                .unwrap()
                .unwrap()
                .download_count,
            0
        );

        let available_head = app
            .clone()
            .oneshot(request(Method::HEAD, "/v/limited/download", ""))
            .await
            .unwrap();
        assert_eq!(available_head.status(), StatusCode::OK);
        assert_eq!(available_head.headers()[header::CONTENT_LENGTH], "6");
        assert_eq!(
            state
                .db
                .share_by_token("limited")
                .unwrap()
                .unwrap()
                .download_count,
            0
        );

        let first = app
            .clone()
            .oneshot(range_request(
                Method::GET,
                "/v/limited/download",
                Some("bytes=0-2"),
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::PARTIAL_CONTENT);
        let transfer_cookie = first
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        assert_eq!(
            app.clone()
                .oneshot(request(Method::HEAD, "/v/limited/download", ""))
                .await
                .unwrap()
                .status(),
            StatusCode::GONE
        );
        assert_eq!(response_text(first).await, "abc");
        for _ in 0..100 {
            if state
                .db
                .share_by_token("limited")
                .unwrap()
                .unwrap()
                .download_count
                == 1
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        assert_eq!(
            state
                .db
                .share_by_token("limited")
                .unwrap()
                .unwrap()
                .download_count,
            1
        );
        assert_eq!(
            app.clone()
                .oneshot(request(Method::HEAD, "/v/limited/download", ""))
                .await
                .unwrap()
                .status(),
            StatusCode::GONE
        );
        let mut counted_session_head = request(Method::HEAD, "/v/limited/download", "");
        counted_session_head.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&transfer_cookie).unwrap(),
        );
        assert_eq!(
            app.clone()
                .oneshot(counted_session_head)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );

        // HTTP/1 stops polling a response body after exactly Content-Length bytes.
        // The final chunk therefore must not become visible until the lease is counted.
        let known_length = app
            .clone()
            .oneshot(request(Method::GET, "/v/known-length/download", ""))
            .await
            .unwrap();
        assert_eq!(known_length.headers()[header::CONTENT_LENGTH], "6");
        let mut body = known_length.into_body().into_data_stream();
        assert_eq!(body.next().await.unwrap().unwrap().as_ref(), b"abcdef");
        drop(body); // deliberately never poll the stream to EOF
        assert_eq!(
            state
                .db
                .share_by_token("known-length")
                .unwrap()
                .unwrap()
                .download_count,
            1
        );

        let empty = app
            .clone()
            .oneshot(request(Method::GET, "/v/empty/download", ""))
            .await
            .unwrap();
        assert_eq!(empty.headers()[header::CONTENT_LENGTH], "0");
        drop(empty);
        assert_eq!(
            state
                .db
                .share_by_token("empty")
                .unwrap()
                .unwrap()
                .download_count,
            1
        );

        let mut resumed = range_request(Method::GET, "/v/limited/download", Some("bytes=3-5"));
        resumed.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&transfer_cookie).unwrap(),
        );
        let resumed = app.clone().oneshot(resumed).await.unwrap();
        assert_eq!(resumed.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(response_text(resumed).await, "def");
        assert_eq!(
            app.clone()
                .oneshot(request(Method::GET, "/v/limited/download", ""))
                .await
                .unwrap()
                .status(),
            StatusCode::GONE
        );

        let aborted = app
            .clone()
            .oneshot(request(Method::GET, "/v/aborted/download", ""))
            .await
            .unwrap();
        assert_eq!(aborted.status(), StatusCode::OK);
        drop(aborted);
        for _ in 0..100 {
            if state.db.active_transfer_reservations(aborted_id).unwrap() == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        assert_eq!(
            state.db.active_transfer_reservations(aborted_id).unwrap(),
            0
        );
        assert_eq!(
            state
                .db
                .share_by_token("aborted")
                .unwrap()
                .unwrap()
                .download_count,
            0
        );
    }

    #[tokio::test]
    async fn http_share_permissions_password_unlock_and_range() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("file.txt"), b"0123456789").unwrap();
        std::fs::create_dir(root.path().join("uploads")).unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("admin", "hash", "secret").unwrap();
        state
            .db
            .create_share(
                "download",
                None,
                "file.txt",
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
        state
            .db
            .create_share(
                "upload",
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
        let password_hash = auth::hash_password("share password 123").unwrap();
        state
            .db
            .create_share(
                "protected",
                None,
                "file.txt",
                false,
                &Permission::DownloadOnly,
                None,
                None,
                None,
                1,
                Some(password_hash.as_str()),
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        let app = router(state.clone());

        let mut range_request = request(Method::GET, "/v/download/download", "");
        range_request
            .headers_mut()
            .insert(header::RANGE, HeaderValue::from_static("bytes=2-5"));
        let range = app.clone().oneshot(range_request).await.unwrap();
        assert_eq!(range.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            range.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes 2-5/10"
        );
        assert_eq!(
            app.clone()
                .oneshot(request(Method::HEAD, "/v/download/download", ""))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone()
                .oneshot(request(Method::GET, "/v/upload/download", ""))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            app.clone()
                .oneshot(request(Method::GET, "/v/protected/download", ""))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );

        let wrong = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/v/protected/unlock",
                "password=wrong",
            ))
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        let unlocked = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/v/protected/unlock",
                "password=share%20password%20123",
            ))
            .await
            .unwrap();
        assert_eq!(unlocked.status(), StatusCode::SEE_OTHER);
        let cookie = unlocked
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let mut protected_download = request(Method::GET, "/v/protected/download", "");
        protected_download
            .headers_mut()
            .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
        assert_eq!(
            app.oneshot(protected_download).await.unwrap().status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn account_ui_changes_password_and_confirms_new_mfa_before_activation() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let current_password = "current-admin-password";
        let replacement_password = "replacement-admin-password";
        let password_hash = auth::hash_password(current_password).unwrap();
        let old_secret = auth::new_totp_secret();
        state.runtime.write().unwrap().audit_client_ip_enabled = true;
        state
            .db
            .create_admin("admin", &password_hash, &old_secret)
            .unwrap();
        state
            .db
            .create_session(
                "account-session",
                1,
                "account-csrf",
                Utc::now() + Duration::hours(1),
            )
            .unwrap();
        state.db.verify_mfa("account-session").unwrap();
        let app = router(state.clone());
        let account_cookie = HeaderValue::from_static("vaultlink_session=account-session");

        let mut account_request = request(Method::GET, "/admin/account", "");
        account_request
            .headers_mut()
            .insert(header::COOKIE, account_cookie.clone());
        let account_html = response_text(app.clone().oneshot(account_request).await.unwrap()).await;
        assert!(account_html.contains("Mein Konto"));
        assert!(account_html.contains("Aktueller Benutzer"));
        assert!(account_html.contains(">admin<"));
        assert!(account_html.contains(r#"action="/admin/account/password""#));
        assert!(account_html.contains(r#"action="/admin/account/mfa/start""#));
        assert!(account_html.contains(r#"action="/locale""#));

        let mut wrong_password = request(
            Method::POST,
            "/admin/account/password",
            "csrf=account-csrf&current_password=wrong-password&new_password=replacement-admin-password&password_confirm=replacement-admin-password",
        );
        wrong_password
            .headers_mut()
            .insert(header::COOKIE, account_cookie.clone());
        assert_eq!(
            app.clone().oneshot(wrong_password).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(state.db.session("account-session").unwrap().is_some());
        assert!(auth::verify_password(
            &state.db.admin("admin").unwrap().unwrap().password_hash,
            current_password
        ));

        let mut change_password = request(
            Method::POST,
            "/admin/account/password",
            "csrf=account-csrf&current_password=current-admin-password&new_password=replacement-admin-password&password_confirm=replacement-admin-password",
        );
        change_password
            .headers_mut()
            .insert(header::COOKIE, account_cookie);
        let changed = app.clone().oneshot(change_password).await.unwrap();
        assert_eq!(changed.status(), StatusCode::SEE_OTHER);
        assert_eq!(changed.headers().get(header::LOCATION).unwrap(), "/login");
        assert!(changed
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("Max-Age=0"));
        assert!(state.db.session("account-session").unwrap().is_none());
        assert!(auth::verify_password(
            &state.db.admin("admin").unwrap().unwrap().password_hash,
            replacement_password
        ));

        state
            .db
            .create_session(
                "account-mfa-session",
                1,
                "account-mfa-csrf",
                Utc::now() + Duration::hours(1),
            )
            .unwrap();
        state.db.verify_mfa("account-mfa-session").unwrap();
        let mfa_cookie = HeaderValue::from_static("vaultlink_session=account-mfa-session");

        let mut rejected_start = request(
            Method::POST,
            "/admin/account/mfa/start",
            "csrf=account-mfa-csrf&current_password=replacement-admin-password&current_code=abcdef",
        );
        rejected_start
            .headers_mut()
            .insert(header::COOKIE, mfa_cookie.clone());
        assert_eq!(
            app.clone().oneshot(rejected_start).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            state.db.admin("admin").unwrap().unwrap().totp_secret,
            old_secret
        );
        assert!(state.db.session("account-mfa-session").unwrap().is_some());

        let current_step = Utc::now().timestamp() as u64 / 30;
        let current_code = auth::totp_code(&old_secret, current_step).unwrap();
        let mut start_mfa = request(
            Method::POST,
            "/admin/account/mfa/start",
            &format!("csrf=account-mfa-csrf&current_password=replacement-admin-password&current_code={current_code}"),
        );
        start_mfa
            .headers_mut()
            .insert(header::COOKIE, mfa_cookie.clone());
        let start_response = app.clone().oneshot(start_mfa).await.unwrap();
        assert_eq!(start_response.status(), StatusCode::OK);
        let start_html = response_text(start_response).await;
        assert!(start_html.contains("Die bisherige MFA bleibt"));
        assert!(!start_html.contains(r#"action="/locale""#));
        let token_marker = r#"name="enrollment_token" value=""#;
        let token_start = start_html.find(token_marker).unwrap() + token_marker.len();
        let enrollment_token = start_html[token_start..]
            .split('"')
            .next()
            .unwrap()
            .to_string();
        let secret_marker = "otpauth://totp/VaultLink:admin?secret=";
        let secret_start = start_html.find(secret_marker).unwrap() + secret_marker.len();
        let new_secret = start_html[secret_start..]
            .split('&')
            .next()
            .unwrap()
            .to_string();
        assert_ne!(new_secret, old_secret);
        assert_eq!(
            state.db.admin("admin").unwrap().unwrap().totp_secret,
            old_secret
        );

        let mut wrong_confirmation = request(
            Method::POST,
            "/admin/account/mfa/confirm",
            &format!("csrf=account-mfa-csrf&enrollment_token={enrollment_token}&code=abcdef"),
        );
        wrong_confirmation
            .headers_mut()
            .insert(header::COOKIE, mfa_cookie.clone());
        assert_eq!(
            app.clone()
                .oneshot(wrong_confirmation)
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            state.db.admin("admin").unwrap().unwrap().totp_secret,
            old_secret
        );
        assert!(state.db.session("account-mfa-session").unwrap().is_some());

        let new_code = auth::totp_code(&new_secret, Utc::now().timestamp() as u64 / 30).unwrap();
        let mut confirm_mfa = request(
            Method::POST,
            "/admin/account/mfa/confirm",
            &format!("csrf=account-mfa-csrf&enrollment_token={enrollment_token}&code={new_code}"),
        );
        confirm_mfa.headers_mut().insert(header::COOKIE, mfa_cookie);
        let confirmed = app.clone().oneshot(confirm_mfa).await.unwrap();
        assert_eq!(confirmed.status(), StatusCode::SEE_OTHER);
        assert_eq!(confirmed.headers().get(header::LOCATION).unwrap(), "/login");
        assert!(confirmed
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("Max-Age=0"));
        assert_eq!(
            state.db.admin("admin").unwrap().unwrap().totp_secret,
            new_secret
        );
        assert!(state.db.session("account-mfa-session").unwrap().is_none());
        assert_eq!(
            state
                .db
                .count_audit(Some("account_password_changed"))
                .unwrap(),
            1
        );
        assert_eq!(
            state.db.count_audit(Some("account_mfa_changed")).unwrap(),
            1
        );
        for action in ["account_password_changed", "account_mfa_changed"] {
            let events = state.db.list_audit(Some(action), 10, 0).unwrap();
            assert_eq!(events[0].client_ip.as_deref(), Some("127.0.0.1"));
        }
    }

    #[tokio::test]
    async fn admin_ui_creates_admin_and_updates_runtime_settings() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("admin", "hash", "secret").unwrap();
        state
            .db
            .create_session(
                "session-token",
                1,
                "csrf-token",
                Utc::now() + Duration::hours(1),
            )
            .unwrap();
        state.db.verify_mfa("session-token").unwrap();
        let app = router(state.clone());
        let cookie = HeaderValue::from_static("vaultlink_session=session-token");

        let login_page = response_text(
            app.clone()
                .oneshot(request(Method::GET, "/login", ""))
                .await
                .unwrap(),
        )
        .await;
        assert!(!login_page.contains("Hauptnavigation"));
        assert!(!login_page.contains("Link erstellen"));
        assert!(login_page.contains("vl-brand"));
        assert!(login_page.contains("<svg"));

        let mut create_admin = request(
            Method::POST,
            "/admin/admins",
            "csrf=csrf-token&username=ops&password=another%20long%20password&password_confirm=another%20long%20password",
        );
        create_admin
            .headers_mut()
            .insert(header::COOKIE, cookie.clone());
        let response = app.clone().oneshot(create_admin).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let created_admin_page = response_text(response).await;
        assert!(created_admin_page.contains("TOTP QR-Code"));
        assert!(created_admin_page.contains("<svg"));
        assert!(created_admin_page.contains("otpauth://totp/VaultLink:ops"));
        assert!(!created_admin_page.contains(r#"action="/locale""#));
        assert!(created_admin_page.contains(r#"class="button secondary" href="/admin/admins""#));
        assert!(state.db.admin("ops").unwrap().is_some());

        let mut deactivate = request(
            Method::POST,
            "/admin/admins/2/deactivate",
            "csrf=csrf-token",
        );
        deactivate
            .headers_mut()
            .insert(header::COOKIE, cookie.clone());
        assert_eq!(
            app.clone().oneshot(deactivate).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );
        assert!(state.db.admin("ops").unwrap().is_none());
        let login_disabled = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/login",
                "username=ops&password=another%20long%20password",
            ))
            .await
            .unwrap();
        assert_eq!(login_disabled.status(), StatusCode::UNAUTHORIZED);
        let mut self_deactivate = request(
            Method::POST,
            "/admin/admins/1/deactivate",
            "csrf=csrf-token",
        );
        self_deactivate
            .headers_mut()
            .insert(header::COOKIE, cookie.clone());
        assert_eq!(
            app.clone().oneshot(self_deactivate).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
        state.db.create_admin("later", "hash", "secret").unwrap();
        let mut admin_list = request(Method::GET, "/admin/admins", "");
        admin_list
            .headers_mut()
            .insert(header::COOKIE, cookie.clone());
        let admin_list_html = response_text(app.clone().oneshot(admin_list).await.unwrap()).await;
        assert!(admin_list_html.contains("Aktive Admins"));
        assert!(admin_list_html.contains("Stillgelegte Admins"));
        assert!(!admin_list_html.contains("Admin-Löschen ist bewusst nicht enthalten"));
        assert!(admin_list_html.contains("Aktueller Admin"));
        assert!(!admin_list_html.contains("Eigene Passwort- und MFA-Änderungen"));
        assert_eq!(admin_list_html.matches("Passwort setzen").count(), 2);
        assert!(
            admin_list_html.find("<td>1</td>").unwrap()
                < admin_list_html.find("<td>3</td>").unwrap()
        );
        assert!(
            admin_list_html.find("Aktive Admins").unwrap()
                < admin_list_html.find("Stillgelegte Admins").unwrap()
        );
        assert!(admin_list_html.contains("MFA zurücksetzen"));
        assert!(admin_list_html.contains("Passwort setzen"));
        state
            .db
            .create_session(
                "later-session",
                3,
                "later-csrf",
                Utc::now() + Duration::hours(1),
            )
            .unwrap();
        state.db.verify_mfa("later-session").unwrap();
        let mut reset_password = request(
            Method::POST,
            "/admin/admins/3/password",
            "csrf=csrf-token&password=new%20long%20password&password_confirm=new%20long%20password",
        );
        reset_password
            .headers_mut()
            .insert(header::COOKIE, cookie.clone());
        let reset_password_response = app.clone().oneshot(reset_password).await.unwrap();
        assert_eq!(reset_password_response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            reset_password_response
                .headers()
                .get(header::LOCATION)
                .unwrap(),
            "/admin/admins?notice=password_reset"
        );
        let mut notice_page = request(Method::GET, "/admin/admins?notice=password_reset", "");
        notice_page
            .headers_mut()
            .insert(header::COOKIE, cookie.clone());
        let notice_html = response_text(app.clone().oneshot(notice_page).await.unwrap()).await;
        assert!(notice_html.contains("Passwort wurde gesetzt"));
        assert!(state.db.session("later-session").unwrap().is_none());
        let login_with_new_password = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/login",
                "username=later&password=new%20long%20password",
            ))
            .await
            .unwrap();
        assert_eq!(login_with_new_password.status(), StatusCode::SEE_OTHER);
        let mut self_password_reset = request(
            Method::POST,
            "/admin/admins/1/password",
            "csrf=csrf-token&password=new%20long%20password&password_confirm=new%20long%20password",
        );
        self_password_reset
            .headers_mut()
            .insert(header::COOKIE, cookie.clone());
        assert_eq!(
            app.clone()
                .oneshot(self_password_reset)
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        let mut reset_totp = request(Method::POST, "/admin/admins/3/totp", "csrf=csrf-token");
        reset_totp
            .headers_mut()
            .insert(header::COOKIE, cookie.clone());
        let reset_totp_response = app.clone().oneshot(reset_totp).await.unwrap();
        assert_eq!(reset_totp_response.status(), StatusCode::OK);
        let reset_totp_html = response_text(reset_totp_response).await;
        assert!(reset_totp_html.contains("MFA zurückgesetzt"));
        assert!(reset_totp_html.contains("TOTP QR-Code"));
        assert!(reset_totp_html.contains("otpauth://totp/VaultLink:later"));
        assert!(!reset_totp_html.contains(r#"action="/locale""#));

        let mut settings_request = request(
            Method::POST,
            "/admin/settings",
            "csrf=csrf-token&public_base_url=http%3A%2F%2Flocalhost%3A9999&max_upload_size=16&blocked_extensions=exe%2Cbat&share_password_min_length=12&share_password_max_bytes=128&share_unlock_minutes=30&max_zip_size=2048&max_zip_files=20&max_search_entries=200&max_search_results=20&max_preview_size=64&preview_extensions=txt%2Clog&image_preview_extensions=jpg%2Cpng&pdf_preview_enabled=on&max_media_preview_size=4096",
        );
        settings_request
            .headers_mut()
            .insert(header::COOKIE, cookie);
        let response = app.clone().oneshot(settings_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let runtime = state.runtime.read().unwrap().clone();
        assert_eq!(runtime.public_base_url, "http://localhost:9999");
        assert_eq!(runtime.max_upload_size, 16);
        assert_eq!(runtime.blocked_extensions, ["exe", "bat"]);
        assert!(state
            .db
            .runtime_settings()
            .unwrap()
            .iter()
            .any(|(key, value)| key == "max_preview_size" && value == "64"));
    }

    #[tokio::test]
    async fn upload_only_never_exposes_target_paths_or_existing_content() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("private-drop")).unwrap();
        std::fs::write(
            root.path().join("private-drop/hidden-secret.txt"),
            b"secret",
        )
        .unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("admin", "hash", "secret").unwrap();
        state
            .db
            .create_share(
                "drop-token",
                None,
                "private-drop",
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
        let app = router(state);

        let html = response_text(
            app.clone()
                .oneshot(request(Method::GET, "/v/drop-token", ""))
                .await
                .unwrap(),
        )
        .await;
        assert!(html.contains("Datei hochladen"));
        assert!(html.contains("Vorhandene Dateien und Ordner bleiben verborgen"));
        assert!(html.contains("Erfolgreiche Uploads werden protokolliert"));
        assert!(!html.contains("private-drop"));
        assert!(!html.contains("hidden-secret.txt"));
        assert!(!html.contains("Dateien durchsuchen"));
        assert!(!html.contains("Datei herunterladen"));

        let api_body = response_text(
            app.oneshot(request(Method::GET, "/api/v1/public/shares/drop-token", ""))
                .await
                .unwrap(),
        )
        .await;
        assert!(api_body.contains(r#""path":"""#));
        assert!(!api_body.contains("private-drop"));
        assert!(!api_body.contains("hidden-secret.txt"));
    }

    #[tokio::test]
    async fn admin_upload_is_csrf_protected_atomic_and_queue_compatible() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("uploads")).unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("admin", "hash", "secret").unwrap();
        state
            .db
            .create_session(
                "session-token",
                1,
                "csrf-token",
                Utc::now() + Duration::hours(1),
            )
            .unwrap();
        state.db.verify_mfa("session-token").unwrap();
        let app = router(state);
        let cookie = HeaderValue::from_static("vaultlink_session=session-token");

        let mut wrong_csrf = admin_multipart_request(
            "/admin/files/upload",
            "uploads",
            "wrong",
            "blocked.txt",
            b"content",
            false,
        );
        wrong_csrf
            .headers_mut()
            .insert(header::COOKIE, cookie.clone());
        assert_eq!(
            app.clone().oneshot(wrong_csrf).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        assert!(!root.path().join("uploads/blocked.txt").exists());

        let mut first = admin_multipart_request(
            "/admin/files/upload",
            "uploads",
            "csrf-token",
            "grüße.txt",
            b"first",
            false,
        );
        first.headers_mut().insert(header::COOKIE, cookie.clone());
        assert_eq!(
            app.clone().oneshot(first).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );
        assert_eq!(
            std::fs::read(root.path().join("uploads/grüße.txt")).unwrap(),
            b"first"
        );

        let mut conflict = admin_multipart_request(
            "/admin/files/upload/queue",
            "uploads",
            "csrf-token",
            "grüße.txt",
            b"second",
            false,
        );
        conflict
            .headers_mut()
            .insert(header::COOKIE, cookie.clone());
        let conflict = app.clone().oneshot(conflict).await.unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert!(response_text(conflict).await.contains("file_exists"));

        let mut replace = admin_multipart_request(
            "/admin/files/upload/queue",
            "uploads",
            "csrf-token",
            "grüße.txt",
            b"second",
            true,
        );
        replace.headers_mut().insert(header::COOKIE, cookie.clone());
        let replace = app.clone().oneshot(replace).await.unwrap();
        assert_eq!(replace.status(), StatusCode::OK);
        let replace_body = response_text(replace).await;
        assert!(replace_body.contains(r#""file":"grüße.txt""#));
        assert!(replace_body.contains(r#""outcome":"replaced"#));
        assert_eq!(
            std::fs::read(root.path().join("uploads/grüße.txt")).unwrap(),
            b"second"
        );

        let mut blocked = admin_multipart_request(
            "/admin/files/upload/queue",
            "uploads",
            "csrf-token",
            "payload.exe",
            b"x",
            false,
        );
        blocked.headers_mut().insert(header::COOKIE, cookie);
        assert_eq!(
            app.clone().oneshot(blocked).await.unwrap().status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        let javascript = response_text(
            app.oneshot(request(Method::GET, "/assets/app.js", ""))
                .await
                .unwrap(),
        )
        .await;
        assert!(javascript.contains("input.multiple = true"));
        assert!(javascript.contains("await uploadItem(item)"));
        assert!(javascript.contains("Erneut versuchen"));
        assert!(!javascript.contains("Promise.all"));
    }

    #[tokio::test]
    async fn public_folder_preview_zip_search_and_subfolder_upload() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("docs/sub")).unwrap();
        std::fs::write(root.path().join("docs/note.txt"), b"<b>hello</b>").unwrap();
        std::fs::write(root.path().join("docs/bad.html"), b"<script>x</script>").unwrap();
        std::fs::write(
            root.path().join("docs/image.png"),
            b"\x89PNG\r\n\x1a\npreview",
        )
        .unwrap();
        std::fs::write(root.path().join("docs/file.pdf"), b"%PDF-1.7\npreview").unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("admin", "hash", "secret").unwrap();
        let du_id = state
            .db
            .create_share(
                "du",
                None,
                "docs",
                true,
                &Permission::DownloadUpload,
                None,
                None,
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        state
            .db
            .create_share(
                "uo",
                None,
                "docs",
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
        let media_id = state
            .db
            .create_share(
                "media",
                None,
                "docs",
                true,
                &Permission::DownloadOnly,
                None,
                Some(1),
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        let app = router(state.clone());

        let listing = response_text(
            app.clone()
                .oneshot(request(Method::GET, "/v/du?q=note", ""))
                .await
                .unwrap(),
        )
        .await;
        assert!(listing.contains("note.txt"));
        assert!(listing.contains("download.zip"));
        assert!(!listing.contains("Hauptnavigation"));
        assert!(!listing.contains("Secure Mode"));
        assert!(!listing.contains("/admin/settings"));

        let preview = response_text(
            app.clone()
                .oneshot(request(Method::GET, "/v/du/preview?path=note.txt", ""))
                .await
                .unwrap(),
        )
        .await;
        assert!(preview.contains("&lt;b&gt;hello&lt;/b&gt;"));
        assert_eq!(
            app.clone()
                .oneshot(request(Method::GET, "/v/du/preview?path=bad.html", ""))
                .await
                .unwrap()
                .status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        let image_preview = response_text(
            app.clone()
                .oneshot(request(Method::GET, "/v/media/preview?path=image.png", ""))
                .await
                .unwrap(),
        )
        .await;
        assert!(image_preview.contains("<img"));
        let image_token = preview_token_from(&image_preview);
        assert!(!image_token.is_empty());
        assert!(state
            .db
            .preview_session(&image_token, media_id, "image.png")
            .unwrap());
        let raw_image_uri =
            format!("/v/media/preview/raw?path=image.png&preview_token={image_token}");
        let raw_image = app
            .clone()
            .oneshot(range_request(
                Method::GET,
                &raw_image_uri,
                Some("bytes=0-3"),
            ))
            .await
            .unwrap();
        assert_eq!(raw_image.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            raw_image.headers().get(header::CONTENT_TYPE).unwrap(),
            "image/png"
        );
        assert_eq!(
            raw_image
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .unwrap(),
            "inline; filename*=UTF-8''image%2Epng"
        );
        assert_eq!(
            raw_image.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
        let raw_image_bytes = axum::body::to_bytes(raw_image.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(raw_image_bytes.as_ref(), b"\x89PNG");
        for _ in 0..100 {
            if state
                .db
                .share_by_token("media")
                .unwrap()
                .unwrap()
                .download_count
                == 1
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        let head_image = app
            .clone()
            .oneshot(range_request(Method::HEAD, &raw_image_uri, None))
            .await
            .unwrap();
        assert_eq!(head_image.status(), StatusCode::OK);
        let bad_range = app
            .clone()
            .oneshot(range_request(
                Method::GET,
                &raw_image_uri,
                Some("bytes=999-1000"),
            ))
            .await
            .unwrap();
        assert_eq!(bad_range.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            app.clone()
                .oneshot(request(Method::GET, "/v/media/preview?path=image.png", ""))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone()
                .oneshot(request(Method::GET, &raw_image_uri, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::GONE
        );

        let pdf_preview = response_text(
            app.clone()
                .oneshot(request(Method::GET, "/v/du/preview?path=file.pdf", ""))
                .await
                .unwrap(),
        )
        .await;
        assert!(pdf_preview.contains("<iframe"));
        let pdf_token = preview_token_from(&pdf_preview);
        assert!(state
            .db
            .preview_session(&pdf_token, du_id, "file.pdf")
            .unwrap());
        let raw_pdf = app
            .clone()
            .oneshot(range_request(
                Method::GET,
                &format!("/v/du/preview/raw?path=file.pdf&preview_token={pdf_token}"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(raw_pdf.status(), StatusCode::OK);
        assert_eq!(
            raw_pdf.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/pdf"
        );
        assert_eq!(
            app.clone()
                .oneshot(request(
                    Method::GET,
                    "/v/du/preview/raw?path=image.png&preview_token=wrong",
                    "",
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );

        let zip = app
            .clone()
            .oneshot(request(Method::GET, "/v/du/download.zip", ""))
            .await
            .unwrap();
        if zip.status() != StatusCode::OK {
            let status = zip.status();
            let body = response_text(zip).await;
            panic!("ZIP failed with {status}: {body}");
        }
        assert_eq!(
            zip.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/zip"
        );

        let uploaded = app
            .clone()
            .oneshot(multipart_request_with_path(
                "/v/du/upload",
                "new.txt",
                b"new",
                Some("sub"),
            ))
            .await
            .unwrap();
        assert_eq!(uploaded.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            std::fs::read(root.path().join("docs/sub/new.txt")).unwrap(),
            b"new"
        );

        let upload_only_page = response_text(
            app.clone()
                .oneshot(request(Method::GET, "/v/uo", ""))
                .await
                .unwrap(),
        )
        .await;
        assert!(!upload_only_page.contains("note.txt"));
        assert_eq!(
            app.oneshot(request(Method::GET, "/v/uo/preview?path=note.txt", ""))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn http_upload_enforces_limit_extension_conflict_and_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("uploads")).unwrap();
        let state = test_state_with_limit(root.path(), data.path(), 8);
        state.db.create_admin("admin", "hash", "secret").unwrap();
        state
            .db
            .create_share(
                "upload",
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
        state
            .db
            .create_share(
                "replace",
                None,
                "uploads",
                true,
                &Permission::UploadOnly,
                None,
                None,
                None,
                1,
                None,
                &UploadConflictStrategy::OverwriteAllowed,
            )
            .unwrap();
        state
            .db
            .create_share(
                "roundtrip",
                None,
                "uploads",
                true,
                &Permission::DownloadUpload,
                None,
                None,
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        let app = router(state.clone());

        let replace_page = response_text(
            app.clone()
                .oneshot(request(Method::GET, "/v/replace", ""))
                .await
                .unwrap(),
        )
        .await;
        assert!(replace_page.contains("Bestehende Datei ersetzen"));
        let upload_page = response_text(
            app.clone()
                .oneshot(request(Method::GET, "/v/upload", ""))
                .await
                .unwrap(),
        )
        .await;
        assert!(!upload_page.contains("Bestehende Datei ersetzen"));

        let uploaded = app
            .clone()
            .oneshot(multipart_request("/v/upload/upload", "ok.txt", b"content"))
            .await
            .unwrap();
        assert_eq!(uploaded.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            std::fs::read(root.path().join("uploads/ok.txt")).unwrap(),
            b"content"
        );
        let queued = app
            .clone()
            .oneshot(multipart_request(
                "/v/upload/upload/queue",
                "grüße.txt",
                b"queued",
            ))
            .await
            .unwrap();
        assert_eq!(queued.status(), StatusCode::OK);
        let queued_body = response_text(queued).await;
        assert!(queued_body.contains(r#""file":"grüße.txt""#));
        assert!(queued_body.contains(r#""outcome":"created"#));
        assert_eq!(
            std::fs::read(root.path().join("uploads/grüße.txt")).unwrap(),
            b"queued"
        );
        *state
            .upload_directory_sync_failure
            .lock()
            .expect("upload sync fault lock") = Some(std::io::ErrorKind::Other);
        let uncertain = app
            .clone()
            .oneshot(multipart_request("/v/upload/upload", "uncertain.txt", b"x"))
            .await
            .unwrap();
        assert_eq!(uncertain.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            uncertain.headers().get("x-vaultlink-durability").unwrap(),
            "uncertain"
        );
        assert!(uncertain
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("upload=uncertain"));
        assert_eq!(
            std::fs::read(root.path().join("uploads/uncertain.txt")).unwrap(),
            b"x"
        );
        let percent_name = app
            .clone()
            .oneshot(multipart_request(
                "/v/roundtrip/upload",
                "100%.txt",
                b"percent",
            ))
            .await
            .unwrap();
        assert_eq!(percent_name.status(), StatusCode::SEE_OTHER);
        let percent_download = app
            .clone()
            .oneshot(request(
                Method::GET,
                "/v/roundtrip/download?path=100%25.txt",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(percent_download.status(), StatusCode::OK);
        assert_eq!(response_text(percent_download).await, "percent");
        for unsafe_name in ["C:escape.txt", "CON.txt"] {
            assert_eq!(
                app.clone()
                    .oneshot(multipart_request("/v/upload/upload", unsafe_name, b"x"))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::BAD_REQUEST,
                "unsafe upload name was accepted: {unsafe_name}"
            );
        }
        let huge_path = "a".repeat(MAX_UPLOAD_PATH_FIELD_BYTES + 1);
        assert_eq!(
            app.clone()
                .oneshot(multipart_request_with_path(
                    "/v/roundtrip/upload",
                    "never.txt",
                    b"x",
                    Some(&huge_path),
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert!(!root.path().join("uploads/never.txt").exists());
        let conflict = app
            .clone()
            .oneshot(multipart_request("/v/upload/upload", "ok.txt", b"new"))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        let conflict_body = response_text(conflict).await;
        assert!(conflict_body.contains("Datei existiert bereits"));
        assert!(conflict_body.contains("Zurück zur Freigabe"));
        assert!(conflict_body.contains(r#"href="/v/upload""#));
        let replace_without_checkbox = app
            .clone()
            .oneshot(multipart_request("/v/replace/upload", "ok.txt", b"new"))
            .await
            .unwrap();
        assert_eq!(replace_without_checkbox.status(), StatusCode::CONFLICT);
        let replace_without_checkbox_body = response_text(replace_without_checkbox).await;
        assert!(replace_without_checkbox_body.contains("Zurück zur Freigabe"));
        let replaced = app
            .clone()
            .oneshot(multipart_request_with_options(
                "/v/replace/upload",
                "ok.txt",
                b"new",
                None,
                true,
            ))
            .await
            .unwrap();
        assert_eq!(replaced.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            std::fs::read(root.path().join("uploads/ok.txt")).unwrap(),
            b"new"
        );
        let blocked = app
            .clone()
            .oneshot(multipart_request("/v/upload/upload", "bad.exe", b"x"))
            .await
            .unwrap();
        assert_eq!(blocked.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let blocked_body = response_text(blocked).await;
        assert!(blocked_body.contains("Dateityp blockiert"));
        assert!(blocked_body.contains("Zurück zur Freigabe"));

        let blocked_with_overwrite = app
            .clone()
            .oneshot(multipart_request_with_options(
                "/v/replace/upload",
                "bad.exe",
                b"x",
                None,
                true,
            ))
            .await
            .unwrap();
        assert_eq!(
            blocked_with_overwrite.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        let blocked_with_overwrite_body = response_text(blocked_with_overwrite).await;
        assert!(blocked_with_overwrite_body.contains("Dateityp blockiert"));
        assert!(blocked_with_overwrite_body.contains("Zurück zur Freigabe"));

        let too_large = app
            .oneshot(multipart_request(
                "/v/upload/upload",
                "large.txt",
                b"123456789",
            ))
            .await
            .unwrap();
        assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let too_large_body = response_text(too_large).await;
        assert!(too_large_body.contains("Upload ist zu groß"));
        assert!(too_large_body.contains("Zurück zur Freigabe"));
        let remaining_parts = std::fs::read_dir(root.path().join("uploads"))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".part"))
            .count();
        assert_eq!(remaining_parts, 0);
    }

    #[tokio::test]
    async fn api_upload_route_can_stream_beyond_the_buffered_body_limit() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("uploads")).unwrap();
        let state = test_state_with_limit(root.path(), data.path(), 2_000_000);
        state.db.create_admin("admin", "hash", "secret").unwrap();
        state
            .db
            .create_share(
                "large-upload",
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
        let app = router(state);
        let content = vec![b'x'; DEFAULT_REQUEST_BODY_LIMIT + 64 * 1024];
        let response = app
            .oneshot(multipart_request(
                "/api/v1/public/shares/large-upload/upload",
                "large.bin",
                &content,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("/api/v1/public/shares/large-upload"));
        assert_eq!(
            std::fs::metadata(root.path().join("uploads/large.bin"))
                .unwrap()
                .len(),
            content.len() as u64
        );
    }
}
