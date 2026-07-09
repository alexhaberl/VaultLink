use std::{collections::VecDeque, io::Read, net::SocketAddr, path::Path};

use axum::{
    body::Body,
    extract::{
        ConnectInfo, DefaultBodyLimit, Form, Multipart, Path as AxPath, Query, Request, State,
    },
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use futures_util::StreamExt;
use qrcode::{render::svg, QrCode};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::io::ReaderStream;
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};

use crate::{
    auth,
    db::{Permission, Session, Share, UploadConflictStrategy},
    http_auth::{
        audit, clear_session_cookie, csrf, database, make_session_cookie, make_unlock_cookie,
        redirect_with_cookie, runtime_settings, session, share_is_unlocked, MissingSession,
    },
    path_security, proxy,
    range::parse_byte_range,
    runtime,
    runtime::RuntimeSettings,
    secure_fs::Entry,
    AppState,
};

const HARD_MULTIPART_LIMIT: u64 = 128 * 1024 * 1024 * 1024;

#[derive(Debug)]
pub struct AppError(StatusCode, &'static str);
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if self.0.is_redirection() {
            return Redirect::to(self.1).into_response();
        }
        (
            self.0,
            Html(plain_page(
                "Fehler",
                &format!("<section><h1>Fehler</h1><p>{}</p></section>", esc(self.1)),
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
        .route("/logout", post(logout))
        .route("/admin", get(admin_browser))
        .route("/admin/preview", get(admin_preview))
        .route(
            "/admin/preview/raw",
            get(admin_preview_raw).head(admin_preview_raw),
        )
        .route("/admin/shares", get(shares_page).post(create_share))
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
        .route("/v/{token}/upload", post(upload))
        .route("/s/{alias}", get(short_redirect))
        .route("/assets/app.js", get(app_js))
        .route("/assets/vaultlink-logo.svg", get(logo_svg))
        .route("/assets/favicon.svg", get(favicon_svg))
        .route("/assets/favicon-32.png", get(favicon_png))
        .route("/favicon.ico", get(favicon_png))
        .layer(DefaultBodyLimit::max(limit))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::new(
            header::HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(CatchPanicLayer::new())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .with_state(state)
}

async fn security_headers(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let h = response.headers_mut();
    h.insert("content-security-policy",HeaderValue::from_static("default-src 'self'; style-src 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"));
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
input,select,button,textarea{font:inherit;padding:.72rem .8rem;border-radius:12px;border:1px solid var(--line2);background:#0b1326;color:var(--text);max-width:100%}input:focus,select:focus,textarea:focus{outline:2px solid rgba(90,167,255,.35);border-color:var(--accent)}button,.button{display:inline-flex;align-items:center;justify-content:center;gap:.4rem;cursor:pointer;padding:.78rem 1rem;border-radius:12px;background:linear-gradient(135deg,#2f67bd,#4e7de2);border:1px solid rgba(255,255,255,.1);color:white;box-shadow:0 10px 24px rgba(47,103,189,.22);font-weight:750;line-height:1.1;text-decoration:none;white-space:nowrap}button:hover,.button:hover{text-decoration:none;filter:brightness(1.08)}.button.secondary,button.secondary{background:rgba(90,167,255,.12);border-color:rgba(90,167,255,.35);box-shadow:none;color:#dbeafe}.button.danger,button.danger{background:rgba(255,123,134,.16);border-color:rgba(255,123,134,.34);box-shadow:none;color:#ffd6db}.button.small,button.small{padding:.55rem .75rem;border-radius:10px;font-size:.92rem}label{display:block;margin:.7rem 0;color:var(--soft);font-weight:650}label input,label select,label textarea{margin-top:.25rem;width:100%}.datetime-picker{position:relative;display:flex;gap:.45rem;align-items:center}.datetime-picker input{margin-top:.25rem}.datetime-picker .calendar-button{margin-top:.25rem;padding:.72rem .8rem}.datetime-popover{position:absolute;z-index:20;top:calc(100% + .45rem);left:0;min-width:min(360px,90vw);padding:.9rem;border:1px solid rgba(90,167,255,.28);border-radius:16px;background:linear-gradient(180deg,#121d34,#0c1428);box-shadow:0 24px 60px rgba(0,0,0,.48)}.datetime-popover[hidden]{display:none}.datetime-popover .picker-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.65rem}.datetime-popover label{margin:0}.datetime-popover .picker-actions{display:flex;gap:.5rem;justify-content:flex-end;margin-top:.8rem}table{width:100%;border-collapse:separate;border-spacing:0 .35rem}th{padding:.65rem .8rem;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;font-size:.78rem;text-align:left}td{padding:.85rem .8rem;border-top:1px solid rgba(255,255,255,.07);border-bottom:1px solid rgba(255,255,255,.07);background:rgba(11,19,38,.55);vertical-align:top}td:first-child{border-left:1px solid rgba(255,255,255,.07);border-radius:14px 0 0 14px}td:last-child{border-right:1px solid rgba(255,255,255,.07);border-radius:0 14px 14px 0}.row{display:flex;gap:.8rem;flex-wrap:wrap;align-items:end}.row label{min-width:220px;flex:1}.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:.8rem;align-items:end}.form-grid label{margin:0}.form-actions{display:flex;gap:.55rem;align-items:end}.muted{color:var(--muted)}.bad{color:var(--bad)}.good{color:var(--good)}.notice{padding:.85rem 1rem;border-radius:14px;background:rgba(85,214,154,.09);border:1px solid rgba(85,214,154,.2);color:#c8f8df}code,pre{overflow-wrap:anywhere}code{padding:.15rem .35rem;border:1px solid rgba(255,255,255,.08);border-radius:8px;background:rgba(0,0,0,.18);color:#dbe9ff}pre{white-space:pre-wrap;background:#0b1326;border:1px solid var(--line);border-radius:16px;padding:1rem}.crumbs,.actions,.button-group,.preview-actions{display:flex;gap:.55rem;flex-wrap:wrap;align-items:center}.crumbs{padding:.75rem .9rem;border-radius:14px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07)}.actions form,.button-group form{display:inline-flex;gap:.45rem;flex-wrap:wrap;margin:0}.pill{display:inline-flex;align-items:center;gap:.35rem;padding:.25rem .55rem;border-radius:999px;border:1px solid rgba(90,167,255,.22);color:#cfe5ff;background:rgba(90,167,255,.10)}.split{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:1rem;align-items:start}.side-panel{padding:1rem;border-radius:18px;border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.045)}.form-card,.share-card{padding:1rem;border:1px solid rgba(90,167,255,.16);border-radius:18px;background:rgba(90,167,255,.045);margin:.9rem 0}.form-card h2,.share-card h2{margin:0 0 .75rem;font-size:1rem;color:#cfe5ff}.share-card{display:grid;gap:.9rem}.share-main{display:grid;grid-template-columns:minmax(220px,1.3fr) minmax(150px,.6fr) minmax(150px,.7fr) minmax(120px,.45fr) minmax(280px,1fr);gap:1rem;align-items:start}.share-actions,.password-actions{display:flex;gap:.55rem;flex-wrap:wrap;align-items:center}.password-actions{padding-top:.75rem;margin-top:.75rem;border-top:1px solid rgba(255,255,255,.08)}.password-actions input{min-width:180px;flex:1}.overwrite-panel{padding:.85rem;border:1px solid rgba(255,255,255,.08);border-radius:16px;background:rgba(255,255,255,.035)}img{border-radius:16px}iframe{background:#0b1326}
.actions a,.preview-actions a,td:last-child>a,section>p>a[href="/admin"],section>p>a[href^="/admin?"],section>p>a[href^="/v/"]{display:inline-flex;align-items:center;justify-content:center;gap:.4rem;padding:.55rem .75rem;border-radius:10px;background:rgba(90,167,255,.12);border:1px solid rgba(90,167,255,.35);color:#dbeafe;text-decoration:none;font-weight:750;line-height:1.1}.actions a:hover,.preview-actions a:hover,td:last-child>a:hover,section>p>a:hover{text-decoration:none;filter:brightness(1.08)}.row>button{align-self:end;margin-bottom:.7rem}
.qr-card{display:inline-block;margin:.9rem 0;padding:1rem;border-radius:18px;background:#f8fbff;color:#081226;border:1px solid rgba(90,167,255,.28);box-shadow:0 18px 44px rgba(0,0,0,.20)}.qr-card svg{display:block;width:220px;height:220px;border-radius:10px}.secret-block{display:grid;gap:.45rem;max-width:860px}.secret-block code{display:block;padding:.55rem .7rem}
.admin-columns{display:grid;grid-template-columns:1fr;gap:1rem;align-items:start}.admin-column{padding:1rem;border:1px solid rgba(90,167,255,.16);border-radius:18px;background:rgba(90,167,255,.045)}.admin-column summary{cursor:pointer;font-size:1.1rem;font-weight:800;color:#dbeafe;margin-bottom:.7rem}.admin-column summary::marker{color:var(--accent)}.admin-column table{margin-top:.6rem}.admin-actions{display:grid;gap:.65rem;min-width:520px}.admin-actions .button-group{gap:.5rem}.admin-reset-form{display:grid;grid-template-columns:minmax(180px,1fr) minmax(180px,1fr) auto;gap:.55rem;align-items:end;padding-top:.65rem;border-top:1px solid rgba(255,255,255,.08)}.admin-reset-form label{margin:0}.admin-reset-form input{width:100%}
.toggle-card{display:flex;align-items:center;gap:.85rem;width:100%;min-width:260px;padding:.9rem 1rem;border:1px solid rgba(90,167,255,.22);border-radius:16px;background:rgba(90,167,255,.07);cursor:pointer}.toggle-card input{position:absolute;opacity:0;width:1px;height:1px}.toggle-card .switch-ui{flex:0 0 auto;width:54px;height:30px;border-radius:999px;background:#1f2b45;border:1px solid var(--line2);position:relative;box-shadow:inset 0 1px 4px rgba(0,0,0,.28)}.toggle-card .switch-ui::after{content:"";position:absolute;top:3px;left:3px;width:22px;height:22px;border-radius:999px;background:#dbeafe;transition:transform .18s ease,background .18s ease}.toggle-card input:checked+.switch-ui{background:linear-gradient(135deg,#2f67bd,#4e7de2);border-color:rgba(255,255,255,.18)}.toggle-card input:checked+.switch-ui::after{transform:translateX(24px);background:#fff}.toggle-card .switch-copy{display:grid;gap:.15rem;color:var(--text)}.toggle-card small{display:block;color:var(--muted);font-weight:600;line-height:1.35}.toggle-card:focus-within{outline:2px solid rgba(90,167,255,.35)}.toggle-card>input+span{position:relative;display:grid;gap:.15rem;padding-left:68px;color:var(--text)}.toggle-card>input+span::before{content:"";position:absolute;left:0;top:50%;transform:translateY(-50%);width:54px;height:30px;border-radius:999px;background:#1f2b45;border:1px solid var(--line2);box-shadow:inset 0 1px 4px rgba(0,0,0,.28)}.toggle-card>input+span::after{content:"";position:absolute;left:4px;top:50%;transform:translateY(-50%);width:22px;height:22px;border-radius:999px;background:#dbeafe;transition:transform .18s ease,background .18s ease}.toggle-card>input:checked+span::before{background:linear-gradient(135deg,#2f67bd,#4e7de2);border-color:rgba(255,255,255,.18)}.toggle-card>input:checked+span::after{transform:translate(24px,-50%);background:#fff}
@media(max-width:980px){.app-shell{display:block}.sidebar{position:relative;height:auto;border-right:0;border-bottom:1px solid rgba(255,255,255,.08)}.sidebar-foot{display:none}.nav-group{grid-template-columns:repeat(auto-fit,minmax(130px,1fr))}.content{padding:1rem}.split,.admin-columns{grid-template-columns:1fr}}@media(max-width:650px){th:nth-child(3),td:nth-child(3){display:none}.topbar{display:block}.hero{display:block}}
"#
}

async fn app_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        r#"document.addEventListener('click',async e=>{const b=e.target.closest('[data-copy]');if(!b)return;try{await navigator.clipboard.writeText(b.dataset.copy);b.textContent='Kopiert';}catch(_){b.textContent='Kopieren fehlgeschlagen';}});
const pad=n=>String(n).padStart(2,'0');
function fillSelect(select,from,to,current){select.innerHTML='';for(let i=from;i<=to;i++){const o=document.createElement('option');o.value=String(i);o.textContent=String(i).padStart(select.dataset.pad||0,'0');if(i===current)o.selected=true;select.appendChild(o);}}
function daysInMonth(y,m){return new Date(y,m,0).getDate();}
function initDateTimePicker(picker){const input=picker.querySelector('[data-datetime-input]');const pop=picker.querySelector('[data-datetime-popover]');const year=picker.querySelector('[data-dt-year]');const month=picker.querySelector('[data-dt-month]');const day=picker.querySelector('[data-dt-day]');const hour=picker.querySelector('[data-dt-hour]');const minute=picker.querySelector('[data-dt-minute]');const now=new Date();fillSelect(year,now.getFullYear(),now.getFullYear()+5,now.getFullYear());fillSelect(month,1,12,now.getMonth()+1);fillSelect(hour,0,23,23);fillSelect(minute,0,59,0);function syncDays(){const selected=Number(day.value)||now.getDate();fillSelect(day,1,daysInMonth(Number(year.value),Number(month.value)),Math.min(selected,daysInMonth(Number(year.value),Number(month.value))))}syncDays();[year,month].forEach(s=>s.addEventListener('change',syncDays));picker.querySelector('[data-datetime-toggle]').addEventListener('click',()=>{pop.hidden=!pop.hidden;});picker.querySelector('[data-datetime-apply]').addEventListener('click',()=>{input.value=`${pad(day.value)}.${pad(month.value)}.${year.value} ${pad(hour.value)}:${pad(minute.value)}`;pop.hidden=true;});picker.querySelector('[data-datetime-clear]').addEventListener('click',()=>{input.value='';pop.hidden=true;});}
document.addEventListener('DOMContentLoaded',()=>{document.querySelectorAll('[data-datetime-picker]').forEach(initDateTimePicker);});
document.addEventListener('click',e=>{document.querySelectorAll('[data-datetime-picker]').forEach(p=>{if(!p.contains(e.target)){const pop=p.querySelector('[data-datetime-popover]');if(pop)pop.hidden=true;}});});
document.addEventListener('submit',e=>{e.target.querySelectorAll('[data-tz-offset]').forEach(i=>{i.value=String(new Date().getTimezoneOffset())})});"#,
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

fn plain_page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{} Â· VaultLink</title><link rel="icon" href="/assets/favicon.svg" type="image/svg+xml"><link rel="alternate icon" href="/assets/favicon-32.png" type="image/png"><style>{}</style><script src="/assets/app.js" defer></script></head><body><div class="public-shell"><main><div class="public-brand"><img src="/assets/vaultlink-logo.svg" alt="VaultLink Logo"><div>VaultLink<small>Secure file links</small></div></div>{}</main></div></body></html>"#,
        esc(title),
        app_css(),
        body
    )
}

fn admin_page(
    state: &AppState,
    title: &str,
    body: &str,
    show_create_link: bool,
    csrf_token: &str,
) -> String {
    let create_link = if show_create_link {
        r#"<a class="button" href="/admin/shares">Link erstellen</a>"#
    } else {
        ""
    };
    format!(
        r#"<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{} Â· VaultLink</title><link rel="icon" href="/assets/favicon.svg" type="image/svg+xml"><link rel="alternate icon" href="/assets/favicon-32.png" type="image/png"><style>{}</style><script src="/assets/app.js" defer></script></head><body><div class="app-shell"><aside class="sidebar"><div class="brand"><img src="/assets/vaultlink-logo.svg" alt="VaultLink Logo"><div>VaultLink<small>Secure file links</small></div></div><nav class="nav-group" aria-label="Hauptnavigation"><a class="nav-link" href="/admin">ðŸ“ Dateien</a><a class="nav-link" href="/admin/shares">ðŸ”— Links</a><a class="nav-link" href="/admin/admins">ðŸ‘¥ Admins</a><a class="nav-link" href="/admin/settings">âš™ï¸ Einstellungen</a><a class="nav-link" href="/admin/audit">ðŸ›¡ï¸ Audit</a></nav><div class="sidebar-foot"><strong class="good">â— System</strong><br><span>{}</span></div></aside><div class="content"><header class="topbar"><div class="topbar-title"><p>VaultLink Admin</p><h1>{}</h1></div><div class="topbar-actions">{}<form method="post" action="/logout"><input type="hidden" name="csrf" value="{}"><button class="secondary">Abmelden</button></form></div></header><main>{}</main></div></div></body></html>"#,
        esc(title),
        app_css(),
        system_panel(state),
        esc(title),
        create_link,
        esc(csrf_token),
        body
    )
}

fn system_panel(state: &AppState) -> String {
    let disk = disk_stats(state.secure_root.display_root())
        .map(|d| format!("Speicher: {} frei / {}", human(d.free), human(d.total)))
        .unwrap_or_else(|| "Speicher: n/v".into());
    format!(
        "{}<br>URL: {}<br>Modus: {:?}",
        esc(&disk),
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
    matches!(error.raw_os_error(), Some(ENOSPC | EDQUOT))
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

fn public_upload_error(
    token: &str,
    upload_subdir: &str,
    status: StatusCode,
    message: &str,
) -> Response {
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
                r#"<section><h1>Fehler</h1><p>{}</p><p><a class="button secondary" href="{}">ZurÃ¼ck zur Freigabe</a></p></section>"#,
                esc(message),
                esc(&back)
            ),
        )),
    )
        .into_response()
}

fn format_audit_time(value: &str) -> String {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| {
            dt.with_timezone(&Utc)
                .format("%d.%m.%Y %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|_| value.to_string())
}

fn format_file_time(value: std::time::SystemTime) -> String {
    DateTime::<Utc>::from(value)
        .format("%d.%m.%Y %H:%M UTC")
        .to_string()
}

fn internal<T>(_: T) -> AppError {
    AppError(StatusCode::INTERNAL_SERVER_ERROR, "Interner Fehler")
}
async fn login_page() -> Html<String> {
    Html(plain_page(
        "Login",
        r#"<section><h1>Admin Login</h1><form method="post"><label>Benutzername<br><input name="username" autocomplete="username" required></label><label>Passwort<br><input name="password" type="password" autocomplete="current-password" required></label><button>Anmelden</button></form></section>"#,
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
    .map_err(internal)?;
    if !valid {
        state.limiter.failure(&key);
        state.limiter.failure(&ip_key);
        audit(&state, form.username, "login_failed", None, None).await;
        return Err(AppError(
            StatusCode::UNAUTHORIZED,
            "UngÃ¼ltige Zugangsdaten",
        ));
    }
    state.limiter.success(&key);
    state.limiter.success(&ip_key);
    let a = admin.unwrap();
    let token = auth::random_token(32);
    let csrf = auth::random_token(24);
    let session_token = token.clone();
    let session_csrf = csrf.clone();
    let expires = Utc::now() + Duration::hours(state.config.security.session_hours);
    let admin_id = a.id;
    database(state.db.clone(), move |db| {
        db.create_session(&session_token, admin_id, &session_csrf, expires)
    })
    .await?;
    audit(&state, a.username, "password_verified", None, None).await;
    Ok(redirect_with_cookie(
        "/mfa",
        make_session_cookie(&state, &token),
    ))
}
async fn mfa_page(State(state): State<AppState>, headers: HeaderMap) -> Result<Html<String>> {
    session(&state, &headers, false, MissingSession::RedirectToLogin).await?;
    Ok(Html(plain_page(
        "MFA",
        r#"<section><h1>Zweiter Faktor</h1><form method="post"><label>6-stelliger TOTP-Code<br><input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required></label><button>Verifizieren</button></form></section>"#,
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
        return Err(AppError(StatusCode::UNAUTHORIZED, "UngÃ¼ltiger MFA-Code"));
    }
    state.limiter.success(&key);
    database(state.db.clone(), move |db| db.verify_mfa(&token)).await?;
    audit(&state, s.username, "login_success", None, None).await;
    Ok(Redirect::to("/admin"))
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
    Ok(redirect_with_cookie("/login", clear_session_cookie(&state)))
}

#[derive(Default, Deserialize)]
pub(crate) struct BrowseQuery {
    path: Option<String>,
    page: Option<usize>,
    q: Option<String>,
    upload: Option<String>,
}
async fn admin_browser(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<BrowseQuery>,
) -> Result<Html<String>> {
    let (_, s) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let settings = runtime_settings(&state);
    let raw = q.path.unwrap_or_default();
    let page_number = q.page.unwrap_or(0).min(1_000_000);
    let search =
        q.q.map(|value| value.trim().to_string())
            .filter(|v| !v.is_empty());
    let rel = path_security::validate_relative(&raw)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "UngÃ¼ltiger Pfad"))?
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
            let name = esc(&hit.relative_path);
            let preview = if !hit.entry.is_dir && preview_allowed(&hit.relative_path, &settings) {
                format!(
                    r#"<a class="button secondary small" href="/admin/preview?path={target}">Ansehen</a> "#
                )
            } else {
                String::new()
            };
            let modified = hit
                .entry
                .modified
                .map(format_file_time)
                .unwrap_or_else(|| "â€”".into());
            rows += &format!(
                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class="actions">{}<a class="button secondary small" href="/admin/shares?path={}">Freigeben</a></td></tr>"#,
                if hit.entry.is_dir {
                    format!(r#"ðŸ“ <a href="/admin?path={target}">{name}</a>"#)
                } else {
                    format!("ðŸ“„ {name}")
                },
                if hit.entry.is_dir { "Ordner" } else { "Datei" },
                if hit.entry.is_dir {
                    "â€”".into()
                } else {
                    human(hit.entry.len)
                },
                modified,
                preview,
                target
            );
        }
    } else {
        let listing_path = rel.clone();
        let entries = tokio::task::spawn_blocking(move || {
            secure_root.list(&listing_path, page_number.saturating_mul(100), 101)
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
            let display = if is_dir {
                format!("ðŸ“ <a href=\"/admin?path={target}\">{}</a>", esc(&name))
            } else {
                format!("ðŸ“„ {}", esc(&name))
            };
            let preview = if !is_dir && preview_allowed(&child, &settings) {
                format!(
                    r#"<a class="button secondary small" href="/admin/preview?path={target}">Ansehen</a> "#
                )
            } else {
                String::new()
            };
            let modified = modified
                .map(format_file_time)
                .unwrap_or_else(|| "â€”".into());
            rows += &format!(
                r#"<tr><td>{display}</td><td>{}</td><td>{}</td><td>{}</td><td class="actions">{}<a class="button secondary small" href="/admin/shares?path={}">Freigeben</a></td></tr>"#,
                if is_dir { "Ordner" } else { "Datei" },
                if is_dir {
                    "â€”".into()
                } else {
                    human(size)
                },
                modified,
                preview,
                target
            );
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
            "<a href=\"/admin?path={encoded_path}&page={}{}\">ZurÃ¼ck</a>",
            page_number - 1,
            search_param
        )
    } else {
        String::new()
    };
    let next = if has_next {
        format!(
            "<a href=\"/admin?path={encoded_path}&page={}{}\">Weiter</a>",
            page_number + 1,
            search_param
        )
    } else {
        String::new()
    };
    let up = parent_path(&rel)
        .map(|parent| {
            format!(
                r#"<p><a class="button secondary" href="/admin?path={}">Hoch</a></p>"#,
                encoded(&parent)
            )
        })
        .unwrap_or_default();
    let body = format!(
        r#"<section class="hero"><div><p class="eyebrow">VaultLink Admin</p><h1>Dateibrowser</h1>{}<p class=muted>Relativer Pfad: /{}</p></div><div class="side-panel"><strong>Schnellaktion</strong><p class="muted">Aktuellen Ordner sicher freigeben oder per Suche eingrenzen.</p><p><a class="button" href="/admin/shares?path={}">Aktuellen Ordner freigeben</a></p></div></section><section>{}<form method="get" class="row"><input type="hidden" name="path" value="{}"><label>Suche<br><input name="q" value="{}" placeholder="Dateiname"></label><button>Suchen</button></form><table><thead><tr><th>Name</th><th>Typ</th><th>GrÃ¶ÃŸe</th><th>GeÃ¤ndert</th><th></th></tr></thead><tbody>{}</tbody></table><p>{} {}</p><p class=muted>100 EintrÃ¤ge pro Seite. Suche ist limitiert und lÃ¤uft innerhalb des aktuellen Ordners.</p></section>"#,
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
    Ok(Html(admin_page(
        &state,
        "Dateien",
        &body,
        true,
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
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "UngÃ¼ltiger Pfad"))?
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
    let body = match content {
        PreviewContent::TooLarge { size } => preview_too_large_body(
            &rel,
            size,
            "Datei ist grÃ¶ÃŸer als das Preview-Limit.",
            None,
        ),
        PreviewContent::Text(text) => format!(
            r#"<section><h1>Vorschau</h1><p class="preview-actions"><a href="/admin?path={}">ZurÃ¼ck zum Ordner</a></p><p><code>/{}</code></p><pre>{}</pre></section>"#,
            encoded(parent_path(&rel).as_deref().unwrap_or("")),
            esc(&rel),
            esc(&text)
        ),
        PreviewContent::Media { kind, size } => admin_media_preview_body(&rel, kind, size),
    };
    Ok(Html(admin_page(
        &state,
        "Vorschau",
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
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "UngÃ¼ltiger Pfad"))?
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
        r#"<section><h1>Vorschau</h1><p class="preview-actions"><a href="/admin?path={}">ZurÃ¼ck zum Ordner</a></p><p><code>/{}</code> <span class="muted">{}</span></p>{}</section>"#,
        encoded(parent_path(path).as_deref().unwrap_or("")),
        esc(path),
        human(size),
        viewer
    )
}

fn media_viewer(kind: PreviewKind, raw_url: &str) -> String {
    match kind {
        PreviewKind::Image(_) => format!(
            r#"<img src="{}" alt="Vorschau" style="max-width:100%;height:auto">"#,
            esc(raw_url)
        ),
        PreviewKind::Pdf => format!(
            r#"<iframe src="{}" title="PDF-Vorschau" style="width:100%;height:75vh;border:1px solid #303a55;border-radius:10px"></iframe>"#,
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
    let is_public = download_link.is_some();
    let back = if is_public {
        String::new()
    } else {
        format!(
            r#"<a href="/admin?path={}">ZurÃ¼ck zum Ordner</a>"#,
            encoded(parent_path(path).as_deref().unwrap_or(""))
        )
    };
    format!(
        r#"<section><h1>Vorschau</h1><p class="preview-actions">{}</p><p><code>/{}</code></p><p class="muted">{} GrÃ¶ÃŸe: {}.</p></section>"#,
        back,
        esc(path),
        esc(message),
        human(size)
    )
}

fn human(n: u64) -> String {
    if n >= GB {
        format!("{:.1} GB", n as f64 / GB as f64)
    } else if n >= MB {
        format!("{:.1} MB", n as f64 / MB as f64)
    } else if n >= 1_000 {
        format!("{:.1} KB", n as f64 / 1_000.)
    } else {
        format!("{n} B")
    }
}

fn upload_limit_label(bytes: u64) -> String {
    format!("{} GB", display_limit_unit_floor(bytes, GB))
}

fn display_limit_unit_floor(bytes: u64, unit: u64) -> String {
    format_unit_floor(bytes, unit)
}

fn expiry_picker_html() -> &'static str {
    r#"<label>Ablauf (optional)<br><div class="datetime-picker" data-datetime-picker><input name="expires_local" data-datetime-input placeholder="TT.MM.JJJJ HH:MM" autocomplete="off" inputmode="numeric"><button class="secondary calendar-button" type="button" data-datetime-toggle aria-label="Kalender Ã¶ffnen">ðŸ“…</button><div class="datetime-popover" data-datetime-popover hidden><div class="picker-grid"><label>Jahr<br><select data-dt-year></select></label><label>Monat<br><select data-dt-month data-pad="2"></select></label><label>Tag<br><select data-dt-day data-pad="2"></select></label><label>Stunde<br><select data-dt-hour data-pad="2"></select></label><label>Minute<br><select data-dt-minute data-pad="2"></select></label></div><div class="picker-actions"><button class="secondary small" type="button" data-datetime-clear>LÃ¶schen</button><button class="small" type="button" data-datetime-apply>Ãœbernehmen</button></div></div></div><small class="muted">Format: TT.MM.JJJJ HH:MM</small></label>"#
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
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "UngÃ¼ltiges Ablaufdatum"))?;
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

fn search_tree(
    secure_root: crate::secure_fs::SecureRoot,
    base: &str,
    query: &str,
    settings: &RuntimeSettings,
) -> std::io::Result<Vec<SearchHit>> {
    let needle = query.to_ascii_lowercase();
    let mut visited = 0usize;
    let mut results = Vec::new();
    let mut queue = VecDeque::from([base.to_string()]);
    while let Some(directory) = queue.pop_front() {
        let mut offset = 0usize;
        loop {
            let entries = secure_root.list(&directory, offset, 100)?;
            if entries.is_empty() {
                break;
            }
            offset += entries.len();
            for entry in entries {
                visited += 1;
                if visited > settings.max_search_entries {
                    return Ok(results);
                }
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
            if offset == 0 || !offset.is_multiple_of(100) {
                break;
            }
        }
    }
    Ok(results)
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

struct ZipEntry {
    name: String,
    crc: u32,
    size: u32,
    local_offset: u32,
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_zip_file(out: &mut Vec<u8>, entries: &mut Vec<ZipEntry>, name: &str, bytes: &[u8]) {
    let crc = crc32(bytes);
    let local_offset = out.len() as u32;
    let name_bytes = name.as_bytes();
    write_u32(out, 0x0403_4b50);
    write_u16(out, 20);
    write_u16(out, 0x0800);
    write_u16(out, 0);
    write_u16(out, 0);
    write_u16(out, 33);
    write_u32(out, crc);
    write_u32(out, bytes.len() as u32);
    write_u32(out, bytes.len() as u32);
    write_u16(out, name_bytes.len() as u16);
    write_u16(out, 0);
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(bytes);
    entries.push(ZipEntry {
        name: name.to_string(),
        crc,
        size: bytes.len() as u32,
        local_offset,
    });
}

fn finish_zip(mut out: Vec<u8>, entries: &[ZipEntry]) -> Vec<u8> {
    let central_offset = out.len() as u32;
    for entry in entries {
        let name_bytes = entry.name.as_bytes();
        write_u32(&mut out, 0x0201_4b50);
        write_u16(&mut out, 20);
        write_u16(&mut out, 20);
        write_u16(&mut out, 0x0800);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u16(&mut out, 33);
        write_u32(&mut out, entry.crc);
        write_u32(&mut out, entry.size);
        write_u32(&mut out, entry.size);
        write_u16(&mut out, name_bytes.len() as u16);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u32(&mut out, 0);
        write_u32(&mut out, entry.local_offset);
        out.extend_from_slice(name_bytes);
    }
    let central_size = out.len() as u32 - central_offset;
    write_u32(&mut out, 0x0605_4b50);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, entries.len() as u16);
    write_u16(&mut out, entries.len() as u16);
    write_u32(&mut out, central_size);
    write_u32(&mut out, central_offset);
    write_u16(&mut out, 0);
    out
}

fn build_zip(
    secure_root: crate::secure_fs::SecureRoot,
    root_path: &str,
    settings: RuntimeSettings,
) -> std::io::Result<Vec<u8>> {
    let mut queue = VecDeque::from([(root_path.to_string(), String::new())]);
    let mut files = Vec::new();
    let mut total = 0u64;
    while let Some((directory, zip_prefix)) = queue.pop_front() {
        let mut offset = 0usize;
        loop {
            let entries = secure_root.list(&directory, offset, 100)?;
            if entries.is_empty() {
                break;
            }
            offset += entries.len();
            for entry in entries {
                let fs_path = join_display(&directory, &entry.name);
                let zip_name = join_display(&zip_prefix, &entry.name);
                if entry.is_dir {
                    queue.push_back((fs_path, zip_name));
                    continue;
                }
                files.push((fs_path, zip_name, entry.len));
                if files.len() > settings.max_zip_files {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "zip file count limit exceeded",
                    ));
                }
                total = total.checked_add(entry.len).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "zip size overflow")
                })?;
                if total > settings.max_zip_size {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "zip size limit exceeded",
                    ));
                }
            }
            if offset == 0 || !offset.is_multiple_of(100) {
                break;
            }
        }
    }
    let mut out = Vec::with_capacity(total.min(settings.max_zip_size) as usize);
    let mut zip_entries = Vec::new();
    for (fs_path, zip_name, _) in files {
        let mut file = secure_root.open_file(&fs_path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        push_zip_file(&mut out, &mut zip_entries, &zip_name, &bytes);
    }
    Ok(finish_zip(out, &zip_entries))
}

enum PreviewContent {
    TooLarge { size: u64 },
    Text(String),
    Media { kind: PreviewKind, size: u64 },
}

fn read_preview(
    secure_root: crate::secure_fs::SecureRoot,
    path: &str,
    settings: &RuntimeSettings,
) -> std::io::Result<PreviewContent> {
    let kind = preview_kind(path, settings).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "preview extension is not allowed",
        )
    })?;
    let metadata = secure_root.metadata(path)?;
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
    let file = secure_root.open_file(path)?;
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

async fn raw_preview_response(
    secure_root: crate::secure_fs::SecureRoot,
    method: Method,
    headers: HeaderMap,
    relative_file: String,
    kind: PreviewKind,
    max_size: u64,
) -> Result<Response> {
    let open_path = relative_file.clone();
    let file = tokio::task::spawn_blocking(move || secure_root.open_file(&open_path))
        .await
        .map_err(internal)?
        .map_err(|_| AppError(StatusCode::NOT_FOUND, "Datei nicht verfuegbar"))?;
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
}

#[derive(Default, Deserialize)]
pub(crate) struct PreviewRawQuery {
    path: Option<String>,
    preview_token: Option<String>,
}
async fn shares_page(
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
            .unwrap_or_else(|| {
                format!(
                    "global ({} GB)",
                    display_limit_unit_floor(settings.max_upload_size, GB)
                )
            });
        let upload_conflict = match sh.upload_conflict_strategy {
            UploadConflictStrategy::Reject => "Konflikt: ablehnen",
            UploadConflictStrategy::OverwriteAllowed => "Konflikt: Ãœberschreiben erlaubt",
        };
        let upload_conflict_form = if sh.is_directory && sh.permission.can_upload() {
            let checked = if sh.upload_conflict_strategy.can_overwrite() {
                "checked"
            } else {
                ""
            };
            format!(
                r#"<div class="overwrite-panel"><form method="post" action="/admin/shares/{}/upload-conflict" class="button-group"><input type="hidden" name="csrf" value="{}"><label class="toggle-card"><input type="checkbox" name="overwrite_allowed" value="1" {}><span>Ãœberschreiben erlauben<small>Kann jederzeit wieder deaktiviert werden.</small></span></label><button class="secondary">Ãœbernehmen</button></form></div>"#,
                sh.id,
                esc(&s.csrf_token),
                checked
            )
        } else {
            String::new()
        };
        let upload_limit = format!("{upload_limit}; {upload_conflict}");
        rows += &format!(
            r#"<div class="share-card"><div class="share-main"><div><small class="muted">Pfad</small><br><code>{}</code><br><small>{}</small></div><div><small class="muted">Recht</small><br>{}</div><div><small class="muted">Status</small><br>{}<br>{}<br><small>Uploadlimit: {}</small></div><div><small class="muted">Downloads</small><br>{}/{}</div><div><small class="muted">Aktionen</small><div class="share-actions"><a class="button secondary" href="{}">Ã–ffnen</a><button type="button" data-copy="{}">Kopieren</button><form method="post" action="/admin/shares/{}/toggle"><input type="hidden" name="csrf" value="{}"><button>{}</button></form><form method="post" action="/admin/shares/{}/delete"><input type="hidden" name="csrf" value="{}"><button class="danger">LÃ¶schen</button></form></div><form method="post" action="/admin/shares/{}/password" class="password-actions"><input type="hidden" name="csrf" value="{}"><input type="password" name="password" minlength="{}" maxlength="{}" placeholder="Passwort ersetzen"><input type="password" name="password_confirm" placeholder="BestÃ¤tigen"><button>Setzen</button><button class="secondary" name="remove" value="1">Entfernen</button></form></div></div>{}</div>"#,
            esc(&sh.relative_path),
            esc(&url),
            esc(sh.permission.as_str()),
            if sh.active { "aktiv" } else { "inaktiv" },
            if sh.password_hash.is_some() {
                "passwortgeschÃ¼tzt"
            } else {
                "ohne Passwort"
            },
            esc(&upload_limit),
            sh.download_count,
            sh.max_downloads
                .map(|v| v.to_string())
                .unwrap_or_else(|| "âˆž".into()),
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
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "UngÃ¼ltiger Zielpfad"))?
            .to_string_lossy()
            .replace('\\', "/");
        let secure_root = state.secure_root.clone();
        let metadata_path = rel.clone();
        let metadata = tokio::task::spawn_blocking(move || secure_root.metadata(&metadata_path))
            .await
            .map_err(internal)?
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "UngÃ¼ltiger Zielpfad"))?;
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
            r#"<p class="muted">Upload-Rechte sind nur fÃ¼r Ordnerlinks verfÃ¼gbar. FÃ¼r Uploads bitte im Dateibrowser einen Zielordner auswÃ¤hlen.</p>"#.into()
        };
        format!(
            r#"<section><h1>Link erstellen</h1><div class="form-card"><h2>Ziel</h2><p>AusgewÃ¤hltes Ziel: <code>/{}</code> <span class="muted">({})</span></p>{}<p><a class="button secondary" href="/admin">Anderen Pfad im Dateibrowser auswÃ¤hlen</a></p></div><form method="post"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="path" value="{}"><input type="hidden" name="expires_tz_offset_minutes" data-tz-offset value="0"><div class="form-card"><h2>Freigabeoptionen</h2><div class="form-grid"><label>Berechtigung<br><select name="permission">{}</select></label><label class="toggle-card"><input type="checkbox" name="overwrite_allowed" value="1"><span>Ãœberschreiben fÃ¼r Uploads erlauben<small>Uploader mÃ¼ssen das Ersetzen pro Upload zusÃ¤tzlich bestÃ¤tigen.</small></span></label></div></div><div class="form-card"><h2>Limits und Schutz</h2><div class="form-grid"><label>Alias (optional)<br><input name="alias" pattern="[A-Za-z0-9_-]{{3,32}}"></label>{}<label>Max. Downloads<br><input name="max_downloads" type="number" min="1"></label><label>Uploadlimit GB (optional)<br><input name="max_upload_size_gb" type="number" min="1" step="1" placeholder="global: {}"></label><label>Passwort (optional)<br><input name="password" type="password" minlength="{}" maxlength="{}"></label><label>Passwort bestÃ¤tigen<br><input name="password_confirm" type="password"></label></div></div><button>Erstellen</button></form></section>"#,
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
        r#"<section><h1>Link erstellen</h1><p>Bitte zuerst im Dateibrowser eine Datei oder einen Ordner auswÃ¤hlen.</p><p><a class="button secondary" href="/admin">Pfad im Dateibrowser auswÃ¤hlen</a></p></section>"#.into()
    };
    let body = format!(
        r#"{create_section}<section><h1>Freigaben</h1>{}</section>"#,
        rows
    );
    Ok(Html(admin_page(
        &state,
        "Links",
        &body,
        true,
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
    overwrite_allowed: Option<String>,
}
async fn create_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<CreateShare>,
) -> Result<Redirect> {
    let (_, s) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&s, &f.csrf)?;
    let rel = path_security::validate_relative(&f.path)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "UngÃ¼ltiger Zielpfad"))?
        .to_string_lossy()
        .replace('\\', "/");
    let secure_root = state.secure_root.clone();
    let metadata_path = rel.clone();
    let target_metadata = tokio::task::spawn_blocking(move || secure_root.metadata(&metadata_path))
        .await
        .map_err(internal)?
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "UngÃ¼ltiger Zielpfad"))?;
    let permission = Permission::parse(&f.permission)
        .ok_or(AppError(StatusCode::BAD_REQUEST, "UngÃ¼ltige Berechtigung"))?;
    if target_metadata.is_file() && permission.can_upload() {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Uploads sind im MVP nur fÃ¼r Ordnerlinks erlaubt",
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
        return Err(AppError(StatusCode::BAD_REQUEST, "UngÃ¼ltiger Alias"));
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
    if password.as_deref()
        != f.password_confirm
            .as_deref()
            .filter(|value| !value.is_empty())
    {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "PasswÃ¶rter stimmen nicht Ã¼berein",
        ));
    }
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
        .map_err(|_| {
            AppError(
                StatusCode::BAD_REQUEST,
                "UngÃ¼ltige maximale Downloadanzahl",
            )
        })?;
    if max_downloads == Some(0) {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Maximale Downloadanzahl muss mindestens 1 sein",
        ));
    }
    let max_upload_size = if let Some(value) = f
        .max_upload_size_gb
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(parse_unit_to_bytes(value, GB, "UngÃ¼ltiges Uploadlimit")?)
    } else {
        f.max_upload_size
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.parse::<u64>())
            .transpose()
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "UngÃ¼ltiges Uploadlimit"))?;
        None
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
        Some(permission_detail),
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
            "UngÃ¼ltige Upload-Konfliktstrategie",
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
            "Ãœberschreiben ist nur fÃ¼r Ordnerlinks mit Uploadrecht erlaubt",
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
                "PasswÃ¶rter stimmen nicht Ã¼berein",
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
            r#"<div class="admin-actions"><span class="pill">Aktueller Admin</span><small class="muted">Eigene Passwort- und MFA-Ã„nderungen erfolgen spÃ¤ter Ã¼ber â€žMein Kontoâ€œ.</small></div>"#
                .to_string()
        } else {
            let status_action = if admin.active {
                format!(
                    r#"<form method="post" action="/admin/admins/{}/deactivate"><input type="hidden" name="csrf" value="{}"><button class="secondary">Stilllegen</button></form>"#,
                    admin.id,
                    esc(&session.csrf_token)
                )
            } else {
                format!(
                    r#"<form method="post" action="/admin/admins/{}/activate"><input type="hidden" name="csrf" value="{}"><button>Aktivieren</button></form>"#,
                    admin.id,
                    esc(&session.csrf_token)
                )
            };
            format!(
                r#"<div class="admin-actions"><div class="button-group">{}<form method="post" action="/admin/admins/{}/totp"><input type="hidden" name="csrf" value="{}"><button class="secondary">MFA zurÃ¼cksetzen</button></form></div><form method="post" action="/admin/admins/{}/password" class="admin-reset-form"><input type="hidden" name="csrf" value="{}"><label>Neues Passwort<input name="password" type="password" minlength="14" required></label><label>BestÃ¤tigen<input name="password_confirm" type="password" minlength="14" required></label><button>Passwort setzen</button></form></div>"#,
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
        active_rows
            .push_str(r#"<tr><td colspan="4" class="muted">Keine aktiven Admins.</td></tr>"#);
    }
    if inactive_rows.is_empty() {
        inactive_rows
            .push_str(r#"<tr><td colspan="4" class="muted">Keine stillgelegten Admins.</td></tr>"#);
    }
    let notice = match query.notice.as_deref() {
        Some("password_reset") => {
            r#"<p class="notice">Passwort wurde gesetzt. Bestehende Sessions dieses Admins wurden beendet.</p>"#
        }
        _ => "",
    };
    let body = format!(
        r#"<section><h1>Admins</h1>{notice}<div class="admin-columns"><details class="admin-column" open><summary>Aktive Admins</summary><table><tr><th>ID</th><th>Benutzername</th><th>Erstellt</th><th>Aktion</th></tr>{active_rows}</table></details><details class="admin-column" open><summary>Stillgelegte Admins</summary><table><tr><th>ID</th><th>Benutzername</th><th>Erstellt</th><th>Aktion</th></tr>{inactive_rows}</table></details></div><p class="muted">Admin-LÃ¶schen ist bewusst nicht enthalten, damit Audit-/Share-BezÃ¼ge stabil bleiben.</p></section><section><h2>Admin erstellen</h2><form method="post" class="row"><input type="hidden" name="csrf" value="{}"><label>Benutzername<br><input name="username" pattern="[A-Za-z0-9_-]{{3,64}}" required></label><label>Passwort<br><input name="password" type="password" minlength="14" required></label><label>Passwort bestÃ¤tigen<br><input name="password_confirm" type="password" required></label><button>Erstellen</button></form></section>"#,
        esc(&session.csrf_token)
    );
    Ok(Html(admin_page(
        &state,
        "Admins",
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
            "PasswÃ¶rter stimmen nicht Ã¼berein",
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
        r#"<section><h1>Admin erstellt</h1><p>Dieses TOTP-Secret wird nur jetzt angezeigt. QR-Code mit der Authenticator-App scannen oder Secret manuell eintragen.</p><p><strong>{}</strong></p><div class="qr-card" aria-label="TOTP QR-Code">{}</div><div class="secret-block"><code>{}</code><code>{}</code></div><p><a class="button secondary" href="/admin/admins">Zur Adminliste</a></p></section>"#,
        esc(&username),
        qr,
        esc(&secret),
        esc(&otpauth)
    );
    Ok(Html(admin_page(
        &state,
        "Admin erstellt",
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
            "Eigenes Passwort kann hier nicht zurÃ¼ckgesetzt werden",
        ));
    }
    if form.password != form.password_confirm {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "PasswÃ¶rter stimmen nicht Ã¼berein",
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
            "Eigene MFA kann hier nicht zurÃ¼ckgesetzt werden",
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
        r#"<section><h1>MFA zurÃ¼ckgesetzt</h1><p>Dieses neue TOTP-Secret wird nur jetzt angezeigt. QR-Code mit der Authenticator-App scannen oder Secret manuell eintragen.</p><p><strong>{}</strong></p><div class="qr-card" aria-label="TOTP QR-Code">{}</div><div class="secret-block"><code>{}</code><code>{}</code></div><p><a class="button secondary" href="/admin/admins">Zur Adminliste</a></p></section>"#,
        esc(&username),
        qr,
        esc(&secret),
        esc(&otpauth)
    );
    Ok(Html(admin_page(
        &state,
        "MFA zurÃ¼ckgesetzt",
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
    let active_count = database(state.db.clone(), |db| db.active_admin_count()).await?;
    if active_count <= 1 {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Letzter aktiver Admin kann nicht stillgelegt werden",
        ));
    }
    let changed = database(state.db.clone(), move |db| db.set_admin_active(id, false)).await?;
    if !changed {
        return Err(AppError(StatusCode::NOT_FOUND, "Admin nicht gefunden"));
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
    let changed = database(state.db.clone(), move |db| db.set_admin_active(id, true)).await?;
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
}

async fn settings_page(State(state): State<AppState>, headers: HeaderMap) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let settings = runtime_settings(&state);
    let body = settings_form(&session, &settings, "");
    Ok(Html(admin_page(
        &state,
        "Einstellungen",
        &body,
        false,
        &session.csrf_token,
    )))
}

fn settings_form(session: &Session, settings: &RuntimeSettings, message: &str) -> String {
    let message = if message.is_empty() {
        String::new()
    } else {
        format!(r#"<p class="muted">{}</p>"#, esc(message))
    };
    format!(
        r#"<section><h1>Einstellungen</h1>{message}<p class="muted">Runtime-Policy wird in SQLite gespeichert. Servermodus, Bind-Adresse, TLS-Dateien, Trusted Proxies, Root-Mount und Data-Dir bleiben file-/restart-basiert.</p><form method="post" class="row"><input type="hidden" name="csrf" value="{}"><label>Public Base URL<br><input name="public_base_url" value="{}" required></label><label>Globales Uploadlimit GB<br><input name="max_upload_size_gb" type="number" min="1" step="1" value="{}" required></label><label>Blockierte Endungen<br><input name="blocked_extensions" value="{}"></label><label>Share-Passwort Min. Zeichen<br><input name="share_password_min_length" type="number" min="8" value="{}" required></label><label>Share-Passwort Max. Zeichen<br><input name="share_password_max_length" type="number" min="8" value="{}" required></label><label>Unlock Minuten<br><input name="share_unlock_minutes" type="number" min="1" value="{}" required></label><label>ZIP Max. GB<br><input name="max_zip_size_gb" type="number" min="1" step="1" value="{}" required></label><label>ZIP Max. Dateien<br><input name="max_zip_files" type="number" min="1" value="{}" required></label><label>Suche Max. EintrÃ¤ge<br><input name="max_search_entries" type="number" min="1" value="{}" required></label><label>Suche Max. Treffer<br><input name="max_search_results" type="number" min="1" value="{}" required></label><label>Text-Preview Max. MB<br><input name="max_preview_size_mb" type="number" min="1" step="1" value="{}" required></label><label>Text-Preview-Endungen<br><input name="preview_extensions" value="{}" required></label><label>Media-Preview Max. MB<br><input name="max_media_preview_size_mb" type="number" min="1" step="1" value="{}" required></label><label>Bild-Preview-Endungen<br><input name="image_preview_extensions" value="{}"></label><label class="toggle-card"><input type="checkbox" name="pdf_preview_enabled" {}><span>PDF-Preview aktiv<small>PDFs werden inline mit sicheren Headern angezeigt.</small></span></label><button>Speichern</button></form></section>"#,
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
        parse_unit_to_bytes(value, GB, "UngÃ¼ltiges Uploadlimit")?.to_string()
    } else {
        form.max_upload_size.unwrap_or_default()
    };
    let max_zip_size = if let Some(value) = form.max_zip_size_gb.as_deref() {
        parse_unit_to_bytes(value, GB, "UngÃ¼ltiges ZIP-Limit")?.to_string()
    } else {
        form.max_zip_size.unwrap_or_default()
    };
    let max_preview_size = if let Some(value) = form.max_preview_size_mb.as_deref() {
        parse_unit_to_bytes(value, MB, "UngÃ¼ltiges Preview-Limit")?.to_string()
    } else {
        form.max_preview_size.unwrap_or_default()
    };
    let max_media_preview_size = if let Some(value) = form.max_media_preview_size_mb.as_deref() {
        parse_unit_to_bytes(value, MB, "UngÃ¼ltiges Media-Preview-Limit")?.to_string()
    } else if let Some(value) = form.max_media_preview_size_gb.as_deref() {
        parse_unit_to_bytes(value, GB, "UngÃ¼ltiges Media-Preview-Limit")?.to_string()
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
    ];
    next.apply_many(entries)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "UngÃ¼ltige Einstellung"))?;
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
    let pairs = next.pairs();
    let admin_id = session.admin_id;
    database(state.db.clone(), move |db| {
        for (key, value) in pairs {
            db.set_runtime_setting(key, &value, admin_id)?;
        }
        Ok(())
    })
    .await?;
    {
        let mut current = state
            .runtime
            .write()
            .expect("runtime settings lock poisoned");
        *current = next.clone();
    }
    let actor = session.username.clone();
    audit(&state, actor, "settings_updated", None, None).await;
    Ok(Html(admin_page(
        &state,
        "Einstellungen",
        &settings_form(&session, &next, "Einstellungen gespeichert."),
        false,
        &session.csrf_token,
    )))
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
    let page_number = query.page.unwrap_or(0).min(1_000_000);
    let action = query
        .action
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_string());
    let action_for_db = action.clone();
    let events = database(state.db.clone(), move |db| {
        db.list_audit(action_for_db.as_deref(), 101, page_number * 100)
    })
    .await?;
    let has_next = events.len() > 100;
    let mut rows = String::new();
    for event in events.into_iter().take(100) {
        rows += &format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
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
            r#"<a href="/admin/audit?action={encoded_filter}&page={}">ZurÃ¼ck</a>"#,
            page_number - 1
        )
    } else {
        String::new()
    };
    let next = if has_next {
        format!(
            r#"<a href="/admin/audit?action={encoded_filter}&page={}">Weiter</a>"#,
            page_number + 1
        )
    } else {
        String::new()
    };
    let body = format!(
        r#"<section><h1>Audit</h1><form method="get" class="row"><label>Action-Filter<br><input name="action" value="{}"></label><button>Filtern</button></form><table><tr><th>Zeit</th><th>Actor</th><th>Aktion</th><th>Objekt</th><th>Detail</th></tr>{rows}</table><p>{previous} {next}</p></section>"#,
        esc(filter_value)
    );
    Ok(Html(admin_page(
        &state,
        "Audit",
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
        return Err(AppError(StatusCode::UNAUTHORIZED, "UngÃ¼ltiges Passwort"));
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
        make_unlock_cookie(&state, &share, &unlock_token),
    ))
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
            r#"<section><h1>GeschÃ¼tzte Freigabe</h1><form method="post" action="/v/{}/unlock"><label>Passwort<br><input type="password" name="password" autocomplete="current-password" required></label><button>Entsperren</button></form></section>"#,
            esc(&token)
        );
        return Ok(Html(plain_page("GeschÃ¼tzte Freigabe", &body)));
    }
    let mut body = format!(
        "<section><h1>Ã–ffentliche Freigabe</h1><p>Berechtigung: <strong>{}</strong></p>",
        esc(sh.permission.as_str())
    );
    if let Some(upload_status) = q.upload.as_deref() {
        let message = match upload_status {
            "replaced" => "Datei erfolgreich ersetzt.",
            "ok" => "Upload erfolgreich abgeschlossen.",
            _ => "",
        };
        if !message.is_empty() {
            body += &format!(r#"<p class="notice">{message}</p>"#);
        }
    }
    if sh.is_directory && sh.permission.can_download() {
        let sub = q.path.clone().unwrap_or_default();
        let page_number = q.page.unwrap_or(0).min(1_000_000);
        let search =
            q.q.map(|value| value.trim().to_string())
                .filter(|v| !v.is_empty());
        let clean_sub = path_security::validate_relative(&sub)
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "UngÃ¼ltiger Pfad"))?
            .to_string_lossy()
            .replace('\\', "/");
        let relative_dir = joined_relative(&sh.relative_path, &clean_sub)?;
        body += &public_breadcrumbs(&token, &clean_sub);
        if let Some(parent) = parent_path(&clean_sub) {
            body += &format!(
                r#"<p><a href="/v/{token}?path={}">Hoch</a></p>"#,
                encoded(&parent)
            );
        }
        body += &format!(
            r#"<form method="get" class="row"><input type="hidden" name="path" value="{}"><label>Suche<br><input name="q" value="{}" placeholder="Dateiname"></label><button>Suchen</button></form><p class="actions"><a class="button" href="/v/{token}/download.zip?path={}">Ordner als ZIP herunterladen</a></p>"#,
            esc(&clean_sub),
            esc(search.as_deref().unwrap_or("")),
            encoded(&clean_sub)
        );
        let secure_root = state.secure_root.clone();
        let mut rows = String::new();
        let mut has_next = false;
        if let Some(search) = search.clone() {
            let search_settings = settings.clone();
            let hits = tokio::task::spawn_blocking(move || {
                search_tree(secure_root, &relative_dir, &search, &search_settings)
            })
            .await
            .map_err(internal)?
            .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabeziel nicht verfÃ¼gbar"))?;
            for hit in hits {
                let share_rel = hit
                    .relative_path
                    .strip_prefix(&sh.relative_path)
                    .unwrap_or(&hit.relative_path)
                    .trim_start_matches('/')
                    .to_string();
                let target = encoded(&share_rel);
                let preview = if !hit.entry.is_dir && preview_allowed(&hit.relative_path, &settings)
                {
                    format!(r#"<a href="/v/{token}/preview?path={target}">Ansehen</a> "#)
                } else {
                    String::new()
                };
                rows += &format!(
                    r#"<tr><td>{}</td><td class="actions">{}{}</td></tr>"#,
                    if hit.entry.is_dir {
                        format!(
                            r#"ðŸ“ <a href="/v/{token}?path={target}">{}</a>"#,
                            esc(&share_rel)
                        )
                    } else {
                        format!("ðŸ“„ {}", esc(&share_rel))
                    },
                    if hit.entry.is_dir {
                        String::new()
                    } else {
                        format!(r#"<a href="/v/{token}/download?path={target}">Download</a> "#)
                    },
                    preview
                );
            }
        } else {
            let entries = tokio::task::spawn_blocking(move || {
                secure_root.list(&relative_dir, page_number.saturating_mul(100), 101)
            })
            .await
            .map_err(internal)?
            .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabeziel nicht verfÃ¼gbar"))?;
            has_next = entries.len() > 100;
            for entry in entries.into_iter().take(100) {
                let rel = joined_relative(&clean_sub, &entry.name)?;
                let name = esc(&entry.name);
                let target = encoded(&rel);
                if entry.is_dir {
                    rows += &format!(
                        r#"<tr><td>ðŸ“ <a href="/v/{token}?path={target}">{name}</a></td><td class="actions"><a href="/v/{token}?path={target}">Ã–ffnen</a></td></tr>"#
                    );
                } else {
                    let preview =
                        if preview_allowed(&joined_relative(&sh.relative_path, &rel)?, &settings) {
                            format!(r#"<a href="/v/{token}/preview?path={target}">Ansehen</a> "#)
                        } else {
                            String::new()
                        };
                    rows += &format!(
                        r#"<tr><td>ðŸ“„ {name}</td><td class="actions">{}<a href="/v/{token}/download?path={target}">Download</a></td></tr>"#,
                        preview
                    );
                }
            }
        }
        body += "<table><tr><th>Name</th><th>Aktion</th></tr>";
        body += &rows;
        body += "</table>";
        let encoded_sub = encoded(&clean_sub);
        let search_param = search
            .as_deref()
            .map(|value| format!("&q={}", encoded(value)))
            .unwrap_or_default();
        if page_number > 0 {
            body += &format!(
                " <a href=\"/v/{token}?path={encoded_sub}&page={}{}\">ZurÃ¼ck</a>",
                page_number - 1,
                search_param
            );
        }
        if has_next {
            body += &format!(
                " <a href=\"/v/{token}?path={encoded_sub}&page={}{}\">Weiter</a>",
                page_number + 1,
                search_param
            );
        }
    } else if !sh.is_directory && sh.permission.can_download() {
        let preview = if preview_allowed(&sh.relative_path, &settings) {
            format!(r#"<a href="/v/{token}/preview">Im Browser ansehen</a> "#)
        } else {
            String::new()
        };
        body += &format!(
            r#"<p class="actions">{}<a href="/v/{token}/download">Datei herunterladen</a></p>"#,
            preview
        );
    }
    if sh.is_directory && sh.permission.can_upload() {
        let upload_path = if sh.permission.can_download() {
            path_security::validate_relative(q.path.as_deref().unwrap_or_default())
                .map_err(|_| AppError(StatusCode::BAD_REQUEST, "UngÃ¼ltiger Pfad"))?
                .to_string_lossy()
                .replace('\\', "/")
        } else {
            String::new()
        };
        let overwrite_checkbox = if sh.upload_conflict_strategy.can_overwrite() {
            r#"<label class="toggle-card"><input type="checkbox" name="overwrite_existing" value="1"><span>Bestehende Datei mit gleichem Namen ersetzen<small>Nur aktivieren, wenn die vorhandene Datei bewusst ersetzt werden soll.</small></span></label>"#
        } else {
            ""
        };
        body += &format!(
            r#"<h2>Upload</h2><p class="muted">Zielordner: /{}</p><form method="post" enctype="multipart/form-data" action="/v/{token}/upload"><input type="hidden" name="path" value="{}">{}<input type="file" name="file" required><button>Hochladen</button></form>"#,
            esc(&upload_path),
            esc(&upload_path),
            overwrite_checkbox
        );
    } else if sh.is_directory && sh.permission == Permission::UploadOnly {
        body += "<p class=\"muted\">Upload-only-Freigaben listen keine Ordnerinhalte.</p>";
    }
    body += "</section>";
    Ok(Html(plain_page("Freigabe", &body)))
}
fn joined_relative(base: &str, child: &str) -> Result<String> {
    let mut path = path_security::validate_relative(base)
        .map_err(|_| AppError(StatusCode::FORBIDDEN, "UngÃ¼ltiger Pfad"))?;
    path.push(
        path_security::validate_relative(child)
            .map_err(|_| AppError(StatusCode::FORBIDDEN, "UngÃ¼ltiger Pfad"))?,
    );
    Ok(path.to_string_lossy().replace('\\', "/"))
}

fn public_back_link(token: &str, share_relative_file: &str, is_directory_share: bool) -> String {
    if !is_directory_share {
        return format!("/v/{token}");
    }
    let parent = parent_path(share_relative_file).unwrap_or_default();
    if parent.is_empty() {
        format!("/v/{token}")
    } else {
        format!("/v/{token}?path={}", encoded(&parent))
    }
}

fn add_public_preview_actions(
    body: String,
    back_link: &str,
    download_link: Option<&str>,
) -> String {
    let download = download_link
        .map(|link| format!(r#"<a href="{}">Herunterladen</a>"#, esc(link)))
        .unwrap_or_default();
    let action = format!(
        r#"<h1>Vorschau</h1><p class="preview-actions"><a href="{}">ZurÃ¼ck zur Freigabe</a>{}</p>"#,
        esc(back_link),
        download
    );
    body.replacen("<h1>Vorschau</h1>", &action, 1)
}

pub(crate) async fn public_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(q): Query<BrowseQuery>,
) -> Result<Html<String>> {
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
        joined_relative(&sh.relative_path, &requested_path)?
    } else {
        sh.relative_path.clone()
    };
    let settings = runtime_settings(&state);
    let secure_root = state.secure_root.clone();
    let preview_path = relative_file.clone();
    let content =
        tokio::task::spawn_blocking(move || read_preview(secure_root, &preview_path, &settings))
            .await
            .map_err(internal)?
            .map_err(|_| AppError(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Vorschau nicht erlaubt"))?;
    let share_id = sh.id;
    if !database(state.db.clone(), move |db| db.count_download(share_id)).await? {
        return Err(AppError(StatusCode::GONE, "Downloadlimit erreicht"));
    }
    audit(
        &state,
        "public".into(),
        "preview",
        Some(sh.id.to_string()),
        None,
    )
    .await;
    let share_rel = if sh.is_directory {
        requested_path
    } else {
        String::new()
    };
    let download_link = if sh.is_directory {
        format!(r#"/v/{token}/download?path={}"#, encoded(&share_rel))
    } else {
        format!("/v/{token}/download")
    };
    let body = match content {
        PreviewContent::TooLarge { size } => preview_too_large_body(
            &share_rel,
            size,
            "Datei ist grÃ¶ÃŸer als das Preview-Limit.",
            Some(&download_link),
        ),
        PreviewContent::Text(text) => format!(
            r#"<section><h1>Vorschau</h1><pre>{}</pre></section>"#,
            esc(&text)
        ),
        PreviewContent::Media { kind, size } => {
            let preview_token = auth::random_token(32);
            let stored_preview_token = preview_token.clone();
            let share_id = sh.id;
            let token_path = relative_file.clone();
            let expires = Utc::now() + Duration::minutes(5);
            database(state.db.clone(), move |db| {
                db.create_preview_session(&stored_preview_token, share_id, &token_path, expires)
            })
            .await?;
            let raw_url = if sh.is_directory {
                format!(
                    "/v/{token}/preview/raw?path={}&preview_token={}",
                    encoded(&share_rel),
                    encoded(&preview_token)
                )
            } else {
                format!(
                    "/v/{token}/preview/raw?preview_token={}",
                    encoded(&preview_token)
                )
            };
            let viewer = media_viewer(kind, &raw_url);
            format!(
                r#"<section><h1>Vorschau</h1><p class="muted">{} - Raw-Token lÃ¤uft nach wenigen Minuten ab.</p>{}</section>"#,
                human(size),
                viewer
            )
        }
    };
    let body = add_public_preview_actions(
        body,
        &public_back_link(&token, &share_rel, sh.is_directory),
        Some(&download_link),
    );
    Ok(Html(plain_page("Vorschau", &body)))
}

pub(crate) async fn public_preview_raw(
    State(state): State<AppState>,
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
        joined_relative(&sh.relative_path, &requested_path)?
    } else {
        sh.relative_path.clone()
    };
    let preview_token = q
        .preview_token
        .ok_or(AppError(StatusCode::FORBIDDEN, "Preview-Token fehlt"))?;
    let share_id = sh.id;
    let token_path = relative_file.clone();
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
    raw_preview_response(
        state.secure_root.clone(),
        method,
        headers,
        relative_file,
        kind,
        settings.max_media_preview_size,
    )
    .await
}

pub(crate) async fn download_zip(
    State(state): State<AppState>,
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
    let sub = q.path.unwrap_or_default();
    let relative_dir = joined_relative(&sh.relative_path, &sub)?;
    let settings = runtime_settings(&state);
    let secure_root = state.secure_root.clone();
    let zip = tokio::task::spawn_blocking(move || build_zip(secure_root, &relative_dir, settings))
        .await
        .map_err(internal)?
        .map_err(|_| AppError(StatusCode::PAYLOAD_TOO_LARGE, "ZIP-Limit erreicht"))?;
    let share_id = sh.id;
    if !database(state.db.clone(), move |db| db.count_download(share_id)).await? {
        return Err(AppError(StatusCode::GONE, "Downloadlimit erreicht"));
    }
    audit(
        &state,
        "public".into(),
        "zip_download",
        Some(sh.id.to_string()),
        None,
    )
    .await;
    let name = Path::new(&sh.relative_path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("vaultlink");
    let filename = encoded(&format!("{name}.zip"));
    let mut response = Response::new(Body::from(zip));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{filename}"))
            .map_err(internal)?,
    );
    Ok(response)
}

pub(crate) async fn download(
    State(state): State<AppState>,
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
        joined_relative(&sh.relative_path, &rel)?
    } else {
        sh.relative_path.clone()
    };
    let secure_root = state.secure_root.clone();
    let open_path = relative_file.clone();
    let file = tokio::task::spawn_blocking(move || secure_root.open_file(&open_path))
        .await
        .map_err(internal)?
        .map_err(|_| AppError(StatusCode::NOT_FOUND, "Datei nicht verfÃ¼gbar"))?;
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
    let share_id = sh.id;
    if method == Method::GET
        && !database(state.db.clone(), move |db| db.count_download(share_id)).await?
    {
        return Err(AppError(StatusCode::GONE, "Downloadlimit erreicht"));
    }
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
    if method == Method::GET {
        audit(
            &state,
            "public".into(),
            "download",
            Some(sh.id.to_string()),
            None,
        )
        .await;
    }
    Ok(r)
}
pub(crate) async fn upload(
    State(state): State<AppState>,
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
    while let Some(field) = match multipart.next_field().await {
        Ok(field) => field,
        Err(_) => {
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::BAD_REQUEST,
                "UngÃ¼ltiger Upload",
            ))
        }
    } {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name == "path" {
            let value = match field.text().await {
                Ok(value) => value,
                Err(_) => {
                    return Ok(public_upload_error(
                        &token,
                        &upload_subdir,
                        StatusCode::BAD_REQUEST,
                        "UngÃ¼ltiger Uploadpfad",
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
                            "UngÃ¼ltiger Uploadpfad",
                        ))
                    }
                };
            }
            continue;
        }
        if field_name == "overwrite_existing" {
            let value = match field.text().await {
                Ok(value) => value,
                Err(_) => {
                    return Ok(public_upload_error(
                        &token,
                        &upload_subdir,
                        StatusCode::BAD_REQUEST,
                        "UngÃ¼ltiger Upload",
                    ))
                }
            };
            overwrite_existing = value == "1";
            continue;
        }
        if field_name != "file" {
            continue;
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
                    "UngÃ¼ltiger Dateiname",
                ))
            }
        };
        if extension_is_blocked(&name, &settings.blocked_extensions) {
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Dateityp blockiert",
            ));
        }
        let secure_root = state.secure_root.clone();
        let upload_directory = if upload_subdir.is_empty() {
            sh.relative_path.clone()
        } else {
            joined_relative(&sh.relative_path, &upload_subdir)?
        };
        let mut pending =
            match tokio::task::spawn_blocking(move || secure_root.begin_upload(&upload_directory))
                .await
                .map_err(internal)?
            {
                Ok(pending) => pending,
                Err(_) => {
                    return Ok(public_upload_error(
                        &token,
                        &upload_subdir,
                        StatusCode::NOT_FOUND,
                        "Zielordner nicht verfÃ¼gbar",
                    ))
                }
            };
        let mut output = tokio::fs::File::from_std(pending.take_file());
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
                    "Upload ist zu groÃŸ",
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
        let publish_name = name.clone();
        let allow_replace = sh.upload_conflict_strategy.can_overwrite() && overwrite_existing;
        let replaced = allow_replace;
        let publish_result = tokio::task::spawn_blocking(move || {
            if allow_replace {
                pending.publish_replace(&publish_name)
            } else {
                pending.publish(&publish_name)
            }
        })
        .await
        .map_err(internal)?;
        if let Err(error) = publish_result {
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
        audit(
            &state,
            "public".into(),
            if replaced {
                "upload_replaced"
            } else {
                "upload"
            },
            Some(sh.id.to_string()),
            Some(name),
        )
        .await;
        let upload_status = if replaced { "replaced" } else { "ok" };
        let target = if upload_subdir.is_empty() {
            format!("/v/{token}?upload={upload_status}")
        } else {
            format!(
                "/v/{token}?path={}&upload={upload_status}",
                encoded(&upload_subdir)
            )
        };
        return Ok(Redirect::to(&target).into_response());
    }
    Ok(public_upload_error(
        &token,
        &upload_subdir,
        StatusCode::BAD_REQUEST,
        "Datei fehlt",
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
            .body(Body::from(body.to_string()))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
        ));
        request
    }

    #[test]
    fn public_preview_back_link_returns_share_parent() {
        assert_eq!(public_back_link("tok", "file.txt", false), "/v/tok");
        assert_eq!(public_back_link("tok", "file.txt", true), "/v/tok");
        assert_eq!(
            public_back_link("tok", "folder/file.txt", true),
            "/v/tok?path=folder"
        );
    }

    #[test]
    fn storage_full_error_maps_linux_quota_and_space_errors() {
        assert!(storage_full_error(&std::io::Error::from_raw_os_error(28)));
        assert!(storage_full_error(&std::io::Error::from_raw_os_error(122)));
        assert!(!storage_full_error(&std::io::Error::from_raw_os_error(13)));
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
        let response =
            AppError(StatusCode::UNAUTHORIZED, "UngÃ¼ltige Zugangsdaten").into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(header::LOCATION).is_none());
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

    #[test]
    fn admin_shell_renders_nav_icons_and_system_panel() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let html = admin_page(&state, "Dateien", "<section></section>", true, "csrf");
        assert!(html.contains("ðŸ“ Dateien"));
        assert!(html.contains("ðŸ”— Links"));
        assert!(html.contains("ðŸ‘¥ Admins"));
        assert!(html.contains("âš™ï¸ Einstellungen"));
        assert!(html.contains("ðŸ›¡ï¸ Audit"));
        assert!(html.contains("â— System"));
        assert!(!html.contains("Secure Mode"));
    }

    #[test]
    fn settings_form_uses_decimal_whole_preview_defaults() {
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

        let html = settings_form(&session, &settings, "");
        assert!(
            html.contains(r#"name="max_upload_size_gb" type="number" min="1" step="1" value="53""#)
        );
        assert!(html.contains(r#"name="max_zip_size_gb" type="number" min="1" step="1" value="1""#));
        assert!(
            html.contains(r#"name="max_preview_size_mb" type="number" min="1" step="1" value="1""#)
        );
        assert!(html.contains(
            r#"name="max_media_preview_size_mb" type="number" min="1" step="1" value="100""#
        ));
        assert!(html.contains("Suche Max. EintrÃ¤ge"));
        for broken in ["Ãƒ", "Ã‚", "Ã¢", "Ã°Å¸", "ï¿½"] {
            assert!(
                !html.contains(broken),
                "settings form contains broken UTF-8 marker {broken:?}"
            );
        }
        assert!(!html.contains("Media-Preview Max. GB"));
    }

    #[test]
    fn custom_datetime_picker_replaces_native_browser_picker() {
        let css = app_css();
        assert!(css.contains(".datetime-popover"));
        assert!(!css.contains(r#"datetime-local"]::-webkit-calendar-picker-indicator"#));
        assert!(expiry_picker_html().contains("data-datetime-picker"));
        assert!(expiry_picker_html().contains(r#"name="expires_local""#));
        assert!(expiry_picker_html().contains("TT.MM.JJJJ HH:MM"));
        assert!(!expiry_picker_html().contains(r#"type="datetime-local""#));
    }

    #[test]
    fn file_time_uses_german_date_order() {
        let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(60 * 60 * 20 + 32 * 60);
        assert_eq!(format_file_time(time), "01.01.1970 20:32 UTC");
    }

    #[test]
    fn removed_setup_form_and_browser_rewrite_stay_removed() {
        assert!(!include_str!("setup.rs").contains(concat!("setup_form_", "legacy")));
        assert!(!include_str!("web.rs").contains(concat!("body.", "replace(")));
    }

    #[test]
    fn public_preview_actions_are_rendered_above_content() {
        let body = r#"<section><h1>Vorschau</h1><pre>long text</pre></section>"#.to_string();
        let html = add_public_preview_actions(body, "/v/token", Some("/v/token/download"));
        let actions = html.find("ZurÃ¼ck zur Freigabe").unwrap();
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

        let mut browser_root = request(Method::GET, "/admin", "");
        browser_root
            .headers_mut()
            .insert(header::COOKIE, cookie.clone());
        let browser_root = response_text(app.clone().oneshot(browser_root).await.unwrap()).await;
        assert!(browser_root.contains("Aktuellen Ordner freigeben"));
        assert!(browser_root.contains(r#"/admin/shares?path=."#));

        let mut browser_folder = request(Method::GET, "/admin?path=uploads", "");
        browser_folder
            .headers_mut()
            .insert(header::COOKIE, cookie.clone());
        let browser_folder =
            response_text(app.clone().oneshot(browser_folder).await.unwrap()).await;
        assert!(browser_folder.contains(r#"/admin/shares?path=uploads"#));

        let mut folder_request = request(Method::GET, "/admin/shares?path=uploads", "");
        folder_request
            .headers_mut()
            .insert(header::COOKIE, cookie.clone());
        let folder = response_text(app.clone().oneshot(folder_request).await.unwrap()).await;
        assert!(folder.contains(r#"AusgewÃ¤hltes Ziel: <code>/uploads</code>"#));
        assert!(folder.contains(r#"<input type="hidden" name="path" value="uploads">"#));
        assert!(folder.contains(r#"<option value="upload_only">Upload only</option>"#));

        let mut file_request = request(Method::GET, "/admin/shares?path=file.txt", "");
        file_request.headers_mut().insert(header::COOKIE, cookie);
        let file = response_text(app.clone().oneshot(file_request).await.unwrap()).await;
        assert!(file.contains(r#"AusgewÃ¤hltes Ziel: <code>/file.txt</code>"#));
        assert!(file.contains(r#"<input type="hidden" name="path" value="file.txt">"#));
        assert!(file.contains(r#"<option value="download_only">Download only</option>"#));
        assert!(!file.contains(r#"<option value="upload_only">Upload only</option>"#));
        assert!(file.contains("Upload-Rechte sind nur"));

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
            app.oneshot(create_request).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );
        let shares = state.db.list_shares().unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].relative_path, "uploads");
        assert_eq!(shares[0].max_downloads, None);
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
        assert!(login_page.contains("vaultlink-logo.svg"));

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
        assert!(admin_list_html.contains("Admin-LÃ¶schen ist bewusst nicht enthalten"));
        assert!(admin_list_html.contains("Aktueller Admin"));
        assert_eq!(admin_list_html.matches("Passwort setzen").count(), 2);
        assert!(
            admin_list_html.find("<td>1</td>").unwrap()
                < admin_list_html.find("<td>3</td>").unwrap()
        );
        assert!(
            admin_list_html.find("Aktive Admins").unwrap()
                < admin_list_html.find("Stillgelegte Admins").unwrap()
        );
        assert!(admin_list_html.contains("MFA zurÃ¼cksetzen"));
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
        assert!(reset_totp_html.contains("MFA zurÃ¼ckgesetzt"));
        assert!(reset_totp_html.contains("TOTP QR-Code"));
        assert!(reset_totp_html.contains("otpauth://totp/VaultLink:later"));

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
            .preview_session(&image_token, media_id, "docs/image.png")
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
            .preview_session(&pdf_token, du_id, "docs/file.pdf")
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
        assert_eq!(zip.status(), StatusCode::OK);
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
        let app = router(state);

        let replace_page = response_text(
            app.clone()
                .oneshot(request(Method::GET, "/v/replace", ""))
                .await
                .unwrap(),
        )
        .await;
        assert!(replace_page.contains("Bestehende Datei mit gleichem Namen ersetzen"));
        let upload_page = response_text(
            app.clone()
                .oneshot(request(Method::GET, "/v/upload", ""))
                .await
                .unwrap(),
        )
        .await;
        assert!(!upload_page.contains("Bestehende Datei mit gleichem Namen ersetzen"));

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
        let conflict = app
            .clone()
            .oneshot(multipart_request("/v/upload/upload", "ok.txt", b"new"))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        let conflict_body = response_text(conflict).await;
        assert!(conflict_body.contains("Datei existiert bereits"));
        assert!(conflict_body.contains("ZurÃ¼ck zur Freigabe"));
        assert!(conflict_body.contains(r#"href="/v/upload""#));
        let replace_without_checkbox = app
            .clone()
            .oneshot(multipart_request("/v/replace/upload", "ok.txt", b"new"))
            .await
            .unwrap();
        assert_eq!(replace_without_checkbox.status(), StatusCode::CONFLICT);
        let replace_without_checkbox_body = response_text(replace_without_checkbox).await;
        assert!(replace_without_checkbox_body.contains("ZurÃ¼ck zur Freigabe"));
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
        assert!(blocked_body.contains("ZurÃ¼ck zur Freigabe"));

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
        assert!(blocked_with_overwrite_body.contains("ZurÃ¼ck zur Freigabe"));

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
        assert!(too_large_body.contains("Upload ist zu groÃŸ"));
        assert!(too_large_body.contains("ZurÃ¼ck zur Freigabe"));
        let remaining_parts = std::fs::read_dir(root.path().join("uploads"))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".part"))
            .count();
        assert_eq!(remaining_parts, 0);
    }
}
