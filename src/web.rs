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
use chrono::{DateTime, Duration, Utc};
use futures_util::StreamExt;
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
    db::{Database, Permission, Session, Share, UploadConflictStrategy},
    path_security, proxy,
    range::parse_byte_range,
    runtime::RuntimeSettings,
    secure_fs::Entry,
    AppState,
};

const COOKIE: &str = "vaultlink_session";
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
            Html(page(
                "Fehler",
                &format!("<section><h1>Fehler</h1><p>{}</p></section>", esc(self.1)),
            )),
        )
            .into_response()
    }
}
type Result<T> = std::result::Result<T, AppError>;

pub fn router(state: AppState) -> Router {
    let limit = HARD_MULTIPART_LIMIT.min(usize::MAX as u64) as usize;
    Router::new()
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
        .route("/admin/admins", get(admins_page).post(create_admin_ui))
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
fn page(title: &str, body: &str) -> String {
    let css = r#"
:root{--bg:#070b16;--bg2:#0b1224;--panel:#111a2e;--panel2:#151f36;--line:#263553;--line2:#334565;--text:#f3f7ff;--muted:#9fb0d0;--soft:#c8d6f4;--accent:#5aa7ff;--accent2:#7c5cff;--good:#55d69a;--bad:#ff7b86;--shadow:0 22px 70px rgba(0,0,0,.36)}
*{box-sizing:border-box}html{min-height:100%}body{margin:0;min-height:100vh;background:radial-gradient(circle at 15% -10%,rgba(90,167,255,.22),transparent 30rem),radial-gradient(circle at 85% 5%,rgba(124,92,255,.18),transparent 28rem),linear-gradient(135deg,var(--bg),var(--bg2) 60%,#080d1b);color:var(--text);font:16px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}.app-shell{display:grid;grid-template-columns:260px minmax(0,1fr);min-height:100vh}.sidebar{position:sticky;top:0;height:100vh;padding:1.25rem;border-right:1px solid rgba(255,255,255,.08);background:linear-gradient(180deg,rgba(14,22,40,.96),rgba(8,12,24,.92));backdrop-filter:blur(18px)}.brand{display:flex;align-items:center;gap:.75rem;margin-bottom:1.5rem;font-weight:800;letter-spacing:.01em}.brand-mark{width:42px;height:42px;border-radius:14px;display:grid;place-items:center;background:linear-gradient(135deg,var(--accent),var(--accent2));box-shadow:0 12px 30px rgba(90,167,255,.25)}.brand small{display:block;color:var(--muted);font-weight:600}.nav-group{display:grid;gap:.35rem}.nav-link{display:flex;align-items:center;gap:.65rem;padding:.75rem .85rem;border-radius:12px;color:var(--soft);border:1px solid transparent}.nav-link:hover{text-decoration:none;background:rgba(90,167,255,.10);border-color:rgba(90,167,255,.18)}.sidebar-foot{position:absolute;left:1.25rem;right:1.25rem;bottom:1.25rem;padding:1rem;border:1px solid rgba(85,214,154,.18);border-radius:16px;background:rgba(85,214,154,.07);color:var(--muted);font-size:.9rem}.content{min-width:0;padding:1.5rem 1.75rem 2.5rem}.topbar{display:flex;justify-content:space-between;align-items:center;gap:1rem;margin:0 auto 1.25rem;max-width:1500px}.topbar-title p{margin:0;color:var(--muted);font-size:.9rem}.topbar-title h1{margin:.15rem 0 0;font-size:clamp(1.45rem,2vw,2.1rem)}.topbar-actions{display:flex;gap:.6rem;flex-wrap:wrap}main{max-width:1500px;margin:0 auto}
section,.panel{background:linear-gradient(180deg,rgba(21,31,54,.96),rgba(15,23,42,.96));border:1px solid rgba(255,255,255,.08);box-shadow:var(--shadow);padding:1.25rem;border-radius:22px;margin:1rem 0;overflow:auto}.hero{display:flex;justify-content:space-between;align-items:flex-end;gap:1rem;background:linear-gradient(135deg,rgba(90,167,255,.16),rgba(124,92,255,.10)),linear-gradient(180deg,rgba(26,39,66,.98),rgba(17,26,46,.98))}.hero h1,.panel h1,section h1{margin:.15rem 0 .65rem;font-size:clamp(1.8rem,3vw,3rem);line-height:1.08}.eyebrow{margin:0;color:#91c7ff;text-transform:uppercase;letter-spacing:.12em;font-size:.78rem;font-weight:800}.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:.8rem;margin:1rem 0}.stat-card{padding:1rem;border:1px solid rgba(255,255,255,.08);border-radius:18px;background:rgba(255,255,255,.045)}.stat-card strong{display:block;font-size:1.45rem}.stat-card span{color:var(--muted);font-size:.9rem}
input,select,button,textarea{font:inherit;padding:.72rem .8rem;border-radius:12px;border:1px solid var(--line2);background:#0b1326;color:var(--text);max-width:100%}input:focus,select:focus,textarea:focus{outline:2px solid rgba(90,167,255,.35);border-color:var(--accent)}button,.button{cursor:pointer;background:linear-gradient(135deg,#2f67bd,#4e7de2);border-color:rgba(255,255,255,.1);color:white;box-shadow:0 10px 24px rgba(47,103,189,.22)}button:hover,.button:hover{text-decoration:none;filter:brightness(1.08)}label{display:block;margin:.7rem 0;color:var(--soft);font-weight:650}label input,label select,label textarea{margin-top:.25rem;width:100%}table{width:100%;border-collapse:separate;border-spacing:0 .35rem}th{padding:.65rem .8rem;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;font-size:.78rem;text-align:left}td{padding:.85rem .8rem;border-top:1px solid rgba(255,255,255,.07);border-bottom:1px solid rgba(255,255,255,.07);background:rgba(11,19,38,.55);vertical-align:top}td:first-child{border-left:1px solid rgba(255,255,255,.07);border-radius:14px 0 0 14px}td:last-child{border-right:1px solid rgba(255,255,255,.07);border-radius:0 14px 14px 0}.row{display:flex;gap:.8rem;flex-wrap:wrap;align-items:end}.row label{min-width:220px;flex:1}.muted{color:var(--muted)}.bad{color:var(--bad)}.good{color:var(--good)}code,pre{overflow-wrap:anywhere}code{padding:.15rem .35rem;border:1px solid rgba(255,255,255,.08);border-radius:8px;background:rgba(0,0,0,.18);color:#dbe9ff}pre{white-space:pre-wrap;background:#0b1326;border:1px solid var(--line);border-radius:16px;padding:1rem}.crumbs,.actions{display:flex;gap:.55rem;flex-wrap:wrap;align-items:center}.crumbs{padding:.75rem .9rem;border-radius:14px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07)}.actions form{display:inline-flex;gap:.45rem;flex-wrap:wrap}.pill{display:inline-flex;align-items:center;gap:.35rem;padding:.25rem .55rem;border-radius:999px;border:1px solid rgba(90,167,255,.22);color:#cfe5ff;background:rgba(90,167,255,.10)}.split{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:1rem;align-items:start}.side-panel{padding:1rem;border-radius:18px;border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.045)}img{border-radius:16px}iframe{background:#0b1326}
@media(max-width:980px){.app-shell{display:block}.sidebar{position:relative;height:auto;border-right:0;border-bottom:1px solid rgba(255,255,255,.08)}.sidebar-foot{display:none}.nav-group{grid-template-columns:repeat(auto-fit,minmax(130px,1fr))}.content{padding:1rem}.split{grid-template-columns:1fr}}@media(max-width:650px){th:nth-child(3),td:nth-child(3){display:none}.topbar{display:block}.hero{display:block}}
"#;
    format!(
        r#"<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{} · VaultLink</title><style>{}</style><script src="/assets/app.js" defer></script></head><body><div class="app-shell"><aside class="sidebar"><div class="brand"><div class="brand-mark">VL</div><div>VaultLink<small>Secure file links</small></div></div><nav class="nav-group" aria-label="Hauptnavigation"><a class="nav-link" href="/admin">📁 Dateien</a><a class="nav-link" href="/admin/shares">🔗 Links</a><a class="nav-link" href="/admin/admins">👥 Admins</a><a class="nav-link" href="/admin/settings">⚙️ Einstellungen</a><a class="nav-link" href="/admin/audit">🛡️ Audit</a></nav><div class="sidebar-foot"><strong class="good">● Secure Mode</strong><br><span>Keine absoluten Serverpfade in der UI.</span></div></aside><div class="content"><header class="topbar"><div class="topbar-title"><p>VaultLink Admin</p><h1>{}</h1></div><div class="topbar-actions"><a class="button" href="/admin/shares">Link erstellen</a></div></header><main>{}</main></div></div></body></html>"#,
        esc(title),
        css,
        esc(title),
        body
    )
}

async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        "document.addEventListener('click',async e=>{const b=e.target.closest('[data-copy]');if(!b)return;try{await navigator.clipboard.writeText(b.dataset.copy);b.textContent='Kopiert';}catch(_){b.textContent='Kopieren fehlgeschlagen';}});",
    )
}
fn cookie(headers: &HeaderMap) -> Option<&str> {
    named_cookie(headers, COOKIE)
}
fn named_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|p| {
            let (k, v) = p.trim().split_once('=')?;
            (k == name).then_some(v)
        })
}
fn unlock_cookie_name(share_id: i64) -> String {
    format!("vaultlink_unlock_{share_id}")
}
async fn database<T, F>(database: Database, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(Database) -> rusqlite::Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || operation(database))
        .await
        .map_err(internal)?
        .map_err(internal)
}

async fn audit(
    state: &AppState,
    actor: String,
    action: &'static str,
    object: Option<String>,
    detail: Option<String>,
) {
    let _ = database(state.db.clone(), move |db| {
        db.audit(&actor, action, object.as_deref(), detail.as_deref())
    })
    .await;
}

fn runtime_settings(state: &AppState) -> RuntimeSettings {
    state
        .runtime
        .read()
        .expect("runtime settings lock poisoned")
        .clone()
}

async fn share_is_unlocked(state: &AppState, headers: &HeaderMap, share: &Share) -> Result<bool> {
    if share.password_hash.is_none() {
        return Ok(true);
    }
    let name = unlock_cookie_name(share.id);
    let Some(token) = named_cookie(headers, &name) else {
        return Ok(false);
    };
    let token = token.to_string();
    let share_id = share.id;
    database(state.db.clone(), move |db| {
        db.unlock_session(&token, share_id)
    })
    .await
}
fn make_unlock_cookie(state: &AppState, share: &Share, token: &str) -> String {
    let settings = runtime_settings(state);
    format!(
        "{}={}; Path=/v/{}; HttpOnly; SameSite=Strict; Max-Age={};{}",
        unlock_cookie_name(share.id),
        token,
        share.token,
        settings.share_unlock_minutes * 60,
        if state.config.security.secure_cookie {
            " Secure"
        } else {
            ""
        }
    )
}
async fn session(state: &AppState, headers: &HeaderMap, mfa: bool) -> Result<(String, Session)> {
    let token = cookie(headers).ok_or(AppError(StatusCode::SEE_OTHER, "/login"))?;
    let session_token = token.to_string();
    let s = database(state.db.clone(), move |db| db.session(&session_token))
        .await?
        .ok_or(AppError(StatusCode::SEE_OTHER, "/login"))?;
    if mfa && !s.mfa_verified {
        return Err(AppError(
            StatusCode::FORBIDDEN,
            "MFA-Verifikation erforderlich",
        ));
    }
    Ok((token.to_string(), s))
}
fn csrf(s: &Session, value: &str) -> Result<()> {
    if s.csrf_token.as_bytes() != value.as_bytes() {
        return Err(AppError(StatusCode::FORBIDDEN, "Ungültiges CSRF-Token"));
    }
    Ok(())
}
fn internal<T>(_: T) -> AppError {
    AppError(StatusCode::INTERNAL_SERVER_ERROR, "Interner Fehler")
}
fn make_cookie(state: &AppState, token: &str) -> String {
    format!(
        "{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={};{}",
        state.config.security.session_hours * 3600,
        if state.config.security.secure_cookie {
            " Secure"
        } else {
            ""
        }
    )
}
fn clear_cookie(state: &AppState) -> String {
    format!(
        "{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0;{}",
        if state.config.security.secure_cookie {
            " Secure"
        } else {
            ""
        }
    )
}
fn redirect_cookie(to: &str, value: String) -> Response {
    let mut r = Redirect::to(to).into_response();
    r.headers_mut()
        .insert(header::SET_COOKIE, HeaderValue::from_str(&value).unwrap());
    r
}

async fn login_page() -> Html<String> {
    Html(page(
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
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
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
    Ok(redirect_cookie("/mfa", make_cookie(&state, &token)))
}
async fn mfa_page(State(state): State<AppState>, headers: HeaderMap) -> Result<Html<String>> {
    session(&state, &headers, false).await?;
    Ok(Html(page(
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
    let (token, s) = session(&state, &headers, false).await?;
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
#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
}
async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    let (token, s) = session(&state, &headers, false).await?;
    csrf(&s, &form.csrf)?;
    database(state.db.clone(), move |db| db.delete_session(&token)).await?;
    audit(&state, s.username, "logout", None, None).await;
    Ok(redirect_cookie("/login", clear_cookie(&state)))
}

#[derive(Default, Deserialize)]
struct BrowseQuery {
    path: Option<String>,
    page: Option<usize>,
    q: Option<String>,
}
async fn admin_browser(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<BrowseQuery>,
) -> Result<Html<String>> {
    let (_, s) = session(&state, &headers, true).await?;
    let settings = runtime_settings(&state);
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
            let name = esc(&hit.relative_path);
            let preview = if !hit.entry.is_dir && preview_allowed(&hit.relative_path, &settings) {
                format!(r#"<a href="/admin/preview?path={target}">Ansehen</a> "#)
            } else {
                String::new()
            };
            let modified = hit
                .entry
                .modified
                .map(DateTime::<Utc>::from)
                .map(|v| v.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_else(|| "—".into());
            rows += &format!(
                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class="actions">{}<a href="/admin/shares?path={}">Freigeben</a></td></tr>"#,
                if hit.entry.is_dir {
                    format!(r#"📁 <a href="/admin?path={target}">{name}</a>"#)
                } else {
                    format!("📄 {name}")
                },
                if hit.entry.is_dir { "Ordner" } else { "Datei" },
                if hit.entry.is_dir {
                    "—".into()
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
                format!("📁 <a href=\"/admin?path={target}\">{}</a>", esc(&name))
            } else {
                format!("📄 {}", esc(&name))
            };
            let preview = if !is_dir && preview_allowed(&child, &settings) {
                format!(r#"<a href="/admin/preview?path={target}">Ansehen</a> "#)
            } else {
                String::new()
            };
            let modified = modified
                .map(DateTime::<Utc>::from)
                .map(|v| v.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_else(|| "—".into());
            rows += &format!(
                r#"<tr><td>{display}</td><td>{}</td><td>{}</td><td>{}</td><td class="actions">{}<a href="/admin/shares?path={}">Freigeben</a></td></tr>"#,
                if is_dir { "Ordner" } else { "Datei" },
                if is_dir { "—".into() } else { human(size) },
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
            "<a href=\"/admin?path={encoded_path}&page={}{}\">Zurück</a>",
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
                r#"<p><a href="/admin?path={}">Hoch</a></p>"#,
                encoded(&parent)
            )
        })
        .unwrap_or_default();
    let body = format!(
        r#"<section class="hero"><div><p class="eyebrow">VaultLink Admin</p><h1>Dateibrowser</h1>{}<p class=muted>Relativer Pfad: /{}</p></div><div class="side-panel"><strong>Schnellaktion</strong><p class="muted">Aktuellen Ordner sicher freigeben oder per Suche eingrenzen.</p><p><a class="button" href="/admin/shares?path={}">Aktuellen Ordner freigeben</a></p></div></section><section>{}<form method="get" class="row"><input type="hidden" name="path" value="{}"><label>Suche<br><input name="q" value="{}" placeholder="Dateiname"></label><button>Suchen</button></form><table><thead><tr><th>Name</th><th>Typ</th><th>Größe</th><th>Geändert</th><th></th></tr></thead><tbody>{}</tbody></table><p>{} {}</p><p class=muted>100 Einträge pro Seite. Suche ist limitiert und läuft innerhalb des aktuellen Ordners.</p></section><section><form method=post action=/logout><input type=hidden name=csrf value="{}"><button>Abmelden</button></form></section>"#,
        breadcrumbs(&rel, "/admin"),
        esc(&rel),
        current_folder_target,
        up,
        esc(&rel),
        esc(search_value),
        rows,
        previous,
        next,
        esc(&s.csrf_token)
    );
    Ok(Html(page("Dateien", &body)))
}

#[allow(dead_code)]
async fn admin_preview_legacy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ShareQuery>,
) -> Result<Html<String>> {
    session(&state, &headers, true).await?;
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
    let body = match content {
        PreviewContent::TooLarge { size } => format!(
            r#"<section><h1>Vorschau</h1><p><code>/{}</code></p><p class="muted">Datei ist mit {} größer als das Preview-Limit. Bitte über eine Freigabe herunterladen oder Limit anpassen.</p><p><a href="/admin?path={}">Zurück zum Ordner</a></p></section>"#,
            esc(&rel),
            human(size),
            encoded(parent_path(&rel).as_deref().unwrap_or(""))
        ),
        PreviewContent::Text(text) => format!(
            r#"<section><h1>Vorschau</h1><p><code>/{}</code></p><pre>{}</pre><p><a href="/admin?path={}">Zurück zum Ordner</a></p></section>"#,
            esc(&rel),
            esc(&text),
            encoded(parent_path(&rel).as_deref().unwrap_or(""))
        ),
        PreviewContent::Media { .. } => String::new(),
    };
    Ok(Html(page("Vorschau", &body)))
}

async fn admin_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ShareQuery>,
) -> Result<Html<String>> {
    session(&state, &headers, true).await?;
    let raw = q
        .path
        .ok_or(AppError(StatusCode::BAD_REQUEST, "Dateipfad fehlt"))?;
    let rel = path_security::validate_relative(&raw)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungueltiger Pfad"))?
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
            "Datei ist groesser als das Preview-Limit.",
            None,
        ),
        PreviewContent::Text(text) => format!(
            r#"<section><h1>Vorschau</h1><p><code>/{}</code></p><pre>{}</pre><p><a href="/admin?path={}">Zurueck zum Ordner</a></p></section>"#,
            esc(&rel),
            esc(&text),
            encoded(parent_path(&rel).as_deref().unwrap_or(""))
        ),
        PreviewContent::Media { kind, size } => admin_media_preview_body(&rel, kind, size),
    };
    Ok(Html(page("Vorschau", &body)))
}

async fn admin_preview_raw(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
    Query(q): Query<ShareQuery>,
) -> Result<Response> {
    session(&state, &headers, true).await?;
    let raw = q
        .path
        .ok_or(AppError(StatusCode::BAD_REQUEST, "Dateipfad fehlt"))?;
    let rel = path_security::validate_relative(&raw)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungueltiger Pfad"))?
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
        r#"<section><h1>Vorschau</h1><p><code>/{}</code> <span class="muted">{}</span></p>{}<p><a href="/admin?path={}">Zurueck zum Ordner</a></p></section>"#,
        esc(path),
        human(size),
        viewer,
        encoded(parent_path(path).as_deref().unwrap_or(""))
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
    let download = download_link
        .map(|link| format!(r#"<p><a href="{}">Herunterladen</a></p>"#, esc(link)))
        .unwrap_or_default();
    let back = if is_public {
        String::new()
    } else {
        format!(
            r#"<p><a href="/admin?path={}">Zurueck</a></p>"#,
            encoded(parent_path(path).as_deref().unwrap_or(""))
        )
    };
    format!(
        r#"<section><h1>Vorschau</h1><p><code>/{}</code></p><p class="muted">{} Groesse: {}.</p>{}{}</section>"#,
        esc(path),
        esc(message),
        human(size),
        download,
        back
    )
}

fn human(n: u64) -> String {
    if n >= 1_073_741_824 {
        format!("{:.1} GiB", n as f64 / 1_073_741_824.)
    } else if n >= 1_048_576 {
        format!("{:.1} MiB", n as f64 / 1_048_576.)
    } else if n >= 1024 {
        format!("{:.1} KiB", n as f64 / 1024.)
    } else {
        format!("{n} B")
    }
}

fn extension_is_blocked(name: &str, blocked: &[String]) -> bool {
    let extension = Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    blocked.iter().any(|value| {
        value
            .trim_start_matches('.')
            .eq_ignore_ascii_case(extension)
    })
}

fn add_upload_bytes(total: u64, chunk: usize, maximum: u64) -> Option<u64> {
    total
        .checked_add(chunk as u64)
        .filter(|new_total| *new_total <= maximum)
}

fn validate_share_password(settings: &RuntimeSettings, password: &str) -> Result<()> {
    if password.chars().count() < settings.share_password_min_length
        || password.len() > settings.share_password_max_bytes
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
struct PreviewRawQuery {
    path: Option<String>,
    preview_token: Option<String>,
}
async fn shares_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ShareQuery>,
) -> Result<Html<String>> {
    let (_, s) = session(&state, &headers, true).await?;
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
            .map(human)
            .unwrap_or_else(|| format!("global ({})", human(settings.max_upload_size)));
        let upload_conflict = match sh.upload_conflict_strategy {
            UploadConflictStrategy::Reject => "Konflikt: ablehnen",
            UploadConflictStrategy::OverwriteAllowed => "Konflikt: Ueberschreiben erlaubt",
        };
        let upload_conflict_form = if sh.is_directory && sh.permission.can_upload() {
            let (next, label) = if sh.upload_conflict_strategy.can_overwrite() {
                ("reject", "Ueberschreiben deaktivieren")
            } else {
                ("overwrite_allowed", "Ueberschreiben erlauben")
            };
            format!(
                r#"<form method="post" action="/admin/shares/{}/upload-conflict" style="display:inline"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="strategy" value="{}"><button>{}</button></form>"#,
                sh.id,
                esc(&s.csrf_token),
                next,
                label
            )
        } else {
            String::new()
        };
        let upload_limit = format!("{upload_limit}; {upload_conflict}");
        rows += &format!(
            r#"<tr><td><code>{}</code><br><small>{}</small></td><td>{}</td><td>{}<br>{}<br><small>Uploadlimit: {}</small></td><td>{}/{}</td><td><a href="{}">Öffnen</a> <button type="button" data-copy="{}">Kopieren</button><form method="post" action="/admin/shares/{}/toggle" style="display:inline"><input type="hidden" name="csrf" value="{}"><button>{}</button></form><form method="post" action="/admin/shares/{}/delete" style="display:inline"><input type="hidden" name="csrf" value="{}"><button>Löschen</button></form><form method="post" action="/admin/shares/{}/password" class="row"><input type="hidden" name="csrf" value="{}"><input type="password" name="password" minlength="{}" maxlength="{}" placeholder="Passwort ersetzen"><input type="password" name="password_confirm" placeholder="Bestätigen"><button>Setzen</button><button name="remove" value="1">Entfernen</button></form></td></tr>"#,
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
            settings.share_password_max_bytes,
        );
        if !upload_conflict_form.is_empty() {
            rows += &format!(
                r#"<tr><td colspan="5"><span class="muted">{}</span> {}</td></tr>"#,
                upload_conflict, upload_conflict_form
            );
        }
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
            r#"<section><h1>Link erstellen</h1><p>Ausgewähltes Ziel: <code>/{}</code> <span class="muted">({})</span></p>{}<p><a href="/admin">Anderen Pfad im Dateibrowser auswählen</a></p><form method="post" class="row"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="path" value="{}"><label>Berechtigung<br><select name="permission">{}</select></label><label>Alias (optional)<br><input name="alias" pattern="[A-Za-z0-9_-]{{3,32}}"></label><label>Ablauf RFC3339 (optional)<br><input name="expires_at" placeholder="2027-01-01T00:00:00Z"></label><label>Max. Downloads<br><input name="max_downloads" type="number" min="1"></label><label>Uploadlimit Bytes (optional)<br><input name="max_upload_size" type="number" min="1" placeholder="global: {}"></label><label><input type="checkbox" name="overwrite_allowed" value="1"> Überschreiben für Uploads erlauben</label><label>Passwort (optional)<br><input name="password" type="password" minlength="{}" maxlength="{}"></label><label>Passwort bestätigen<br><input name="password_confirm" type="password"></label><button>Erstellen</button></form></section>"#,
            esc(&selected),
            if is_dir { "Ordner" } else { "Datei" },
            upload_hint,
            esc(&s.csrf_token),
            esc(&selected),
            permissions,
            settings.max_upload_size,
            settings.share_password_min_length,
            settings.share_password_max_bytes,
        )
    } else {
        r#"<section><h1>Link erstellen</h1><p>Bitte zuerst im Dateibrowser eine Datei oder einen Ordner auswählen.</p><p><a href="/admin">Pfad im Dateibrowser auswählen</a></p></section>"#.into()
    };
    let body = format!(
        r#"{create_section}<section><h1>Freigaben</h1><table><tr><th>Pfad</th><th>Recht</th><th>Status</th><th>Downloads</th><th>Aktionen</th></tr>{}</table></section>"#,
        rows
    );
    Ok(Html(page("Links", &body)))
}
#[derive(Deserialize)]
struct CreateShare {
    csrf: String,
    path: String,
    permission: String,
    alias: Option<String>,
    expires_at: Option<String>,
    max_downloads: Option<String>,
    max_upload_size: Option<String>,
    password: Option<String>,
    password_confirm: Option<String>,
    overwrite_allowed: Option<String>,
}
async fn create_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<CreateShare>,
) -> Result<Redirect> {
    let (_, s) = session(&state, &headers, true).await?;
    csrf(&s, &f.csrf)?;
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
    let exp = f
        .expires_at
        .filter(|v| !v.is_empty())
        .map(|v| DateTime::parse_from_rfc3339(&v).map(|d| d.with_timezone(&Utc)))
        .transpose()
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiges Ablaufdatum"))?;
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
            "Passwörter stimmen nicht überein",
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
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültige maximale Downloadanzahl"))?;
    if max_downloads == Some(0) {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Maximale Downloadanzahl muss mindestens 1 sein",
        ));
    }
    let max_upload_size = f
        .max_upload_size
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiges Uploadlimit"))?;
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
    let (_, s) = session(&state, &headers, true).await?;
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
    strategy: String,
}

async fn set_share_upload_conflict(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(form): Form<UploadConflictForm>,
) -> Result<Redirect> {
    let (_, session) = session(&state, &headers, true).await?;
    csrf(&session, &form.csrf)?;
    let strategy = UploadConflictStrategy::parse(&form.strategy).ok_or(AppError(
        StatusCode::BAD_REQUEST,
        "Ungueltige Upload-Konfliktstrategie",
    ))?;
    let share = database(state.db.clone(), |db| db.list_shares())
        .await?
        .into_iter()
        .find(|share| share.id == id)
        .ok_or(AppError(StatusCode::NOT_FOUND, "Link nicht gefunden"))?;
    if !share.is_directory || !share.permission.can_upload() {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Ueberschreiben ist nur fuer Ordnerlinks mit Uploadrecht erlaubt",
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
    let (_, session) = session(&state, &headers, true).await?;
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
    let (_, s) = session(&state, &headers, true).await?;
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

async fn admins_page(State(state): State<AppState>, headers: HeaderMap) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true).await?;
    let admins = database(state.db.clone(), |db| db.list_admins()).await?;
    let mut rows = String::new();
    for admin in admins {
        rows += &format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            admin.id,
            esc(&admin.username),
            esc(&admin.created_at)
        );
    }
    let body = format!(
        r#"<section><h1>Admins</h1><table><tr><th>ID</th><th>Benutzername</th><th>Erstellt</th></tr>{rows}</table><p class="muted">Admin-Löschen ist in beta1 bewusst nicht enthalten, damit Audit-/Share-Bezüge stabil bleiben.</p></section><section><h2>Admin erstellen</h2><form method="post" class="row"><input type="hidden" name="csrf" value="{}"><label>Benutzername<br><input name="username" pattern="[A-Za-z0-9_-]{{3,64}}" required></label><label>Passwort<br><input name="password" type="password" minlength="14" required></label><label>Passwort bestätigen<br><input name="password_confirm" type="password" required></label><button>Erstellen</button></form></section>"#,
        esc(&session.csrf_token)
    );
    Ok(Html(page("Admins", &body)))
}

#[derive(Deserialize)]
struct CreateAdminUiForm {
    csrf: String,
    username: String,
    password: String,
    password_confirm: String,
}

async fn create_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateAdminUiForm>,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true).await?;
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
    let otpauth = format!(
        "otpauth://totp/VaultLink:{}?secret={}&issuer=VaultLink",
        username, secret
    );
    let body = format!(
        r#"<section><h1>Admin erstellt</h1><p>Dieses TOTP-Secret wird nur jetzt angezeigt.</p><p><strong>{}</strong></p><p><code>{}</code></p><p><code>{}</code></p><p><a href="/admin/admins">Zur Adminliste</a></p></section>"#,
        esc(&username),
        esc(&secret),
        esc(&otpauth)
    );
    Ok(Html(page("Admin erstellt", &body)))
}

#[derive(Deserialize)]
struct SettingsForm {
    csrf: String,
    public_base_url: String,
    max_upload_size: String,
    blocked_extensions: String,
    share_password_min_length: String,
    share_password_max_bytes: String,
    share_unlock_minutes: String,
    max_zip_size: String,
    max_zip_files: String,
    max_search_entries: String,
    max_search_results: String,
    max_preview_size: String,
    preview_extensions: String,
    image_preview_extensions: String,
    pdf_preview_enabled: Option<String>,
    max_media_preview_size: String,
}

async fn settings_page(State(state): State<AppState>, headers: HeaderMap) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true).await?;
    let settings = runtime_settings(&state);
    let body = settings_form(&session, &settings, "");
    Ok(Html(page("Einstellungen", &body)))
}

#[allow(dead_code)]
fn settings_form_legacy(session: &Session, settings: &RuntimeSettings, message: &str) -> String {
    let message = if message.is_empty() {
        String::new()
    } else {
        format!(r#"<p class="muted">{}</p>"#, esc(message))
    };
    format!(
        r#"<section><h1>Einstellungen</h1>{message}<p class="muted">Runtime-Policy wird in SQLite gespeichert. Servermodus, Bind-Adresse, TLS-Dateien, Trusted Proxies, Root-Mount und Data-Dir bleiben file-/restart-basiert.</p><form method="post" class="row"><input type="hidden" name="csrf" value="{}"><label>Public Base URL<br><input name="public_base_url" value="{}" required></label><label>Globales Uploadlimit Bytes<br><input name="max_upload_size" type="number" min="1" value="{}" required></label><label>Blockierte Endungen<br><input name="blocked_extensions" value="{}"></label><label>Share-Passwort Min.-Länge<br><input name="share_password_min_length" type="number" min="8" value="{}" required></label><label>Share-Passwort Max. Bytes<br><input name="share_password_max_bytes" type="number" min="8" value="{}" required></label><label>Unlock Minuten<br><input name="share_unlock_minutes" type="number" min="1" value="{}" required></label><label>ZIP Max. Bytes<br><input name="max_zip_size" type="number" min="1" value="{}" required></label><label>ZIP Max. Dateien<br><input name="max_zip_files" type="number" min="1" value="{}" required></label><label>Suche Max. Einträge<br><input name="max_search_entries" type="number" min="1" value="{}" required></label><label>Suche Max. Treffer<br><input name="max_search_results" type="number" min="1" value="{}" required></label><label>Preview Max. Bytes<br><input name="max_preview_size" type="number" min="1" value="{}" required></label><label>Preview-Endungen<br><input name="preview_extensions" value="{}" required></label><button>Speichern</button></form></section>"#,
        esc(&session.csrf_token),
        esc(&settings.public_base_url),
        settings.max_upload_size,
        esc(&settings.blocked_extensions.join(",")),
        settings.share_password_min_length,
        settings.share_password_max_bytes,
        settings.share_unlock_minutes,
        settings.max_zip_size,
        settings.max_zip_files,
        settings.max_search_entries,
        settings.max_search_results,
        settings.max_preview_size,
        esc(&settings.preview_extensions.join(",")),
    )
}

fn settings_form(session: &Session, settings: &RuntimeSettings, message: &str) -> String {
    let message = if message.is_empty() {
        String::new()
    } else {
        format!(r#"<p class="muted">{}</p>"#, esc(message))
    };
    format!(
        r#"<section><h1>Einstellungen</h1>{message}<p class="muted">Runtime-Policy wird in SQLite gespeichert. Servermodus, Bind-Adresse, TLS-Dateien, Trusted Proxies, Root-Mount und Data-Dir bleiben file-/restart-basiert.</p><form method="post" class="row"><input type="hidden" name="csrf" value="{}"><label>Public Base URL<br><input name="public_base_url" value="{}" required></label><label>Globales Uploadlimit Bytes<br><input name="max_upload_size" type="number" min="1" value="{}" required></label><label>Blockierte Endungen<br><input name="blocked_extensions" value="{}"></label><label>Share-Passwort Min.-Laenge<br><input name="share_password_min_length" type="number" min="8" value="{}" required></label><label>Share-Passwort Max. Bytes<br><input name="share_password_max_bytes" type="number" min="8" value="{}" required></label><label>Unlock Minuten<br><input name="share_unlock_minutes" type="number" min="1" value="{}" required></label><label>ZIP Max. Bytes<br><input name="max_zip_size" type="number" min="1" value="{}" required></label><label>ZIP Max. Dateien<br><input name="max_zip_files" type="number" min="1" value="{}" required></label><label>Suche Max. Eintraege<br><input name="max_search_entries" type="number" min="1" value="{}" required></label><label>Suche Max. Treffer<br><input name="max_search_results" type="number" min="1" value="{}" required></label><label>Text-Preview Max. Bytes<br><input name="max_preview_size" type="number" min="1" value="{}" required></label><label>Text-Preview-Endungen<br><input name="preview_extensions" value="{}" required></label><label>Media-Preview Max. Bytes<br><input name="max_media_preview_size" type="number" min="1" value="{}" required></label><label>Bild-Preview-Endungen<br><input name="image_preview_extensions" value="{}"></label><label><input type="checkbox" name="pdf_preview_enabled" {}> PDF-Preview aktiv</label><button>Speichern</button></form></section>"#,
        esc(&session.csrf_token),
        esc(&settings.public_base_url),
        settings.max_upload_size,
        esc(&settings.blocked_extensions.join(",")),
        settings.share_password_min_length,
        settings.share_password_max_bytes,
        settings.share_unlock_minutes,
        settings.max_zip_size,
        settings.max_zip_files,
        settings.max_search_entries,
        settings.max_search_results,
        settings.max_preview_size,
        esc(&settings.preview_extensions.join(",")),
        settings.max_media_preview_size,
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
    let (_, session) = session(&state, &headers, true).await?;
    csrf(&session, &form.csrf)?;
    let mut next = runtime_settings(&state);
    let entries = [
        ("public_base_url", form.public_base_url.as_str()),
        ("max_upload_size", form.max_upload_size.as_str()),
        ("blocked_extensions", form.blocked_extensions.as_str()),
        (
            "share_password_min_length",
            form.share_password_min_length.as_str(),
        ),
        (
            "share_password_max_bytes",
            form.share_password_max_bytes.as_str(),
        ),
        ("share_unlock_minutes", form.share_unlock_minutes.as_str()),
        ("max_zip_size", form.max_zip_size.as_str()),
        ("max_zip_files", form.max_zip_files.as_str()),
        ("max_search_entries", form.max_search_entries.as_str()),
        ("max_search_results", form.max_search_results.as_str()),
        ("max_preview_size", form.max_preview_size.as_str()),
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
        (
            "max_media_preview_size",
            form.max_media_preview_size.as_str(),
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
    Ok(Html(page(
        "Einstellungen",
        &settings_form(&session, &next, "Einstellungen gespeichert."),
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
    session(&state, &headers, true).await?;
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
            esc(&event.occurred_at),
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
            r#"<a href="/admin/audit?action={encoded_filter}&page={}">Zurück</a>"#,
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
    Ok(Html(page("Audit", &body)))
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
    Ok(redirect_cookie(
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
            r#"<section><h1>Geschützte Freigabe</h1><form method="post" action="/v/{}/unlock"><label>Passwort<br><input type="password" name="password" autocomplete="current-password" required></label><button>Entsperren</button></form></section>"#,
            esc(&token)
        );
        return Ok(Html(page("Geschützte Freigabe", &body)));
    }
    let mut body = format!(
        "<section><h1>Öffentliche Freigabe</h1><p>Berechtigung: <strong>{}</strong></p>",
        esc(sh.permission.as_str())
    );
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
        let relative_dir = joined_relative(&sh.relative_path, &clean_sub)?;
        body += &public_breadcrumbs(&token, &clean_sub);
        if let Some(parent) = parent_path(&clean_sub) {
            body += &format!(
                r#"<p><a href="/v/{token}?path={}">Hoch</a></p>"#,
                encoded(&parent)
            );
        }
        body += &format!(
            r#"<form method="get" class="row"><input type="hidden" name="path" value="{}"><label>Suche<br><input name="q" value="{}" placeholder="Dateiname"></label><button>Suchen</button></form><p class="actions"><a href="/v/{token}/download.zip?path={}">Ordner als ZIP herunterladen</a></p>"#,
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
            .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabeziel nicht verfügbar"))?;
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
                            r#"📁 <a href="/v/{token}?path={target}">{}</a>"#,
                            esc(&share_rel)
                        )
                    } else {
                        format!("📄 {}", esc(&share_rel))
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
            .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabeziel nicht verfügbar"))?;
            has_next = entries.len() > 100;
            for entry in entries.into_iter().take(100) {
                let rel = joined_relative(&clean_sub, &entry.name)?;
                let name = esc(&entry.name);
                let target = encoded(&rel);
                if entry.is_dir {
                    rows += &format!(
                        r#"<tr><td>📁 <a href="/v/{token}?path={target}">{name}</a></td><td class="actions"><a href="/v/{token}?path={target}">Öffnen</a></td></tr>"#
                    );
                } else {
                    let preview =
                        if preview_allowed(&joined_relative(&sh.relative_path, &rel)?, &settings) {
                            format!(r#"<a href="/v/{token}/preview?path={target}">Ansehen</a> "#)
                        } else {
                            String::new()
                        };
                    rows += &format!(
                        r#"<tr><td>📄 {name}</td><td class="actions">{}<a href="/v/{token}/download?path={target}">Download</a></td></tr>"#,
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
                " <a href=\"/v/{token}?path={encoded_sub}&page={}{}\">Zurück</a>",
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
                .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Pfad"))?
                .to_string_lossy()
                .replace('\\', "/")
        } else {
            String::new()
        };
        let overwrite_checkbox = if sh.upload_conflict_strategy.can_overwrite() {
            r#"<label><input type="checkbox" name="overwrite_existing" value="1"> Bestehende Datei mit gleichem Namen ersetzen</label>"#
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
    Ok(Html(page("Freigabe", &body)))
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

#[allow(dead_code)]
async fn public_preview_legacy(
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
        PreviewContent::TooLarge { size } => format!(
            r#"<section><h1>Vorschau</h1><p class="muted">Datei ist mit {} größer als das Preview-Limit.</p><p><a href="{}">Herunterladen</a></p></section>"#,
            human(size),
            esc(&download_link)
        ),
        PreviewContent::Text(text) => format!(
            r#"<section><h1>Vorschau</h1><pre>{}</pre><p><a href="{}">Herunterladen</a></p></section>"#,
            esc(&text),
            esc(&download_link)
        ),
        PreviewContent::Media { .. } => String::new(),
    };
    Ok(Html(page("Vorschau", &body)))
}

async fn public_preview(
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
            "Datei ist groesser als das Preview-Limit.",
            Some(&download_link),
        ),
        PreviewContent::Text(text) => format!(
            r#"<section><h1>Vorschau</h1><pre>{}</pre><p><a href="{}">Herunterladen</a></p></section>"#,
            esc(&text),
            esc(&download_link)
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
                r#"<section><h1>Vorschau</h1><p class="muted">{} - Raw-Token laeuft nach wenigen Minuten ab.</p>{}<p><a href="{}">Herunterladen</a></p></section>"#,
                human(size),
                viewer,
                esc(&download_link)
            )
        }
    };
    Ok(Html(page("Vorschau", &body)))
}

async fn public_preview_raw(
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

async fn download_zip(
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

async fn download(
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
async fn upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    mut multipart: Multipart,
) -> Result<Redirect> {
    let sh = get_share(&state, &token).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Freigabe ist gesperrt"));
    }
    if !sh.is_directory || !sh.permission.can_upload() {
        return Err(AppError(StatusCode::FORBIDDEN, "Upload nicht erlaubt"));
    }
    let settings = runtime_settings(&state);
    let maximum = sh.max_upload_size.unwrap_or(settings.max_upload_size);
    let mut upload_subdir = String::new();
    let mut overwrite_existing = false;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Upload"))?
    {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name == "path" {
            let value = field
                .text()
                .await
                .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Uploadpfad"))?;
            if sh.permission == Permission::DownloadUpload {
                upload_subdir = path_security::validate_relative(&value)
                    .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Uploadpfad"))?
                    .to_string_lossy()
                    .replace('\\', "/");
            }
            continue;
        }
        if field_name == "overwrite_existing" {
            let value = field
                .text()
                .await
                .map_err(|_| AppError(StatusCode::BAD_REQUEST, "UngÃ¼ltiger Upload"))?;
            overwrite_existing = value == "1";
            continue;
        }
        if field_name != "file" {
            continue;
        }
        let name = path_security::safe_filename(
            field
                .file_name()
                .ok_or(AppError(StatusCode::BAD_REQUEST, "Dateiname fehlt"))?,
        )
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Dateiname"))?
        .to_string();
        if extension_is_blocked(&name, &settings.blocked_extensions) {
            return Err(AppError(
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
            tokio::task::spawn_blocking(move || secure_root.begin_upload(&upload_directory))
                .await
                .map_err(internal)?
                .map_err(|_| AppError(StatusCode::NOT_FOUND, "Zielordner nicht verfügbar"))?;
        let mut output = tokio::fs::File::from_std(pending.take_file());
        let mut total = 0u64;
        let stream = field;
        tokio::pin!(stream);
        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.map_err(|_| AppError(StatusCode::BAD_REQUEST, "Upload abgebrochen"))?;
            let Some(new_total) = add_upload_bytes(total, chunk.len(), maximum) else {
                return Err(AppError(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Upload ist zu groß",
                ));
            };
            total = new_total;
            if let Err(e) = output.write_all(&chunk).await {
                return Err(internal(e));
            }
        }
        output.flush().await.map_err(internal)?;
        output.sync_all().await.map_err(internal)?;
        drop(output);
        let publish_name = name.clone();
        let allow_replace = sh.upload_conflict_strategy.can_overwrite() && overwrite_existing;
        let replaced = allow_replace;
        tokio::task::spawn_blocking(move || {
            if allow_replace {
                pending.publish_replace(&publish_name)
            } else {
                pending.publish(&publish_name)
            }
        })
        .await
        .map_err(internal)?
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                AppError(StatusCode::CONFLICT, "Datei existiert bereits")
            } else {
                internal(error)
            }
        })?;
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
        let target = if upload_subdir.is_empty() {
            format!("/v/{token}")
        } else {
            format!("/v/{token}?path={}", encoded(&upload_subdir))
        };
        return Ok(Redirect::to(&target));
    }
    Err(AppError(StatusCode::BAD_REQUEST, "Datei fehlt"))
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
        let response = AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten").into_response();
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
        assert!(folder.contains(r#"Ausgewähltes Ziel: <code>/uploads</code>"#));
        assert!(folder.contains(r#"<input type="hidden" name="path" value="uploads">"#));
        assert!(folder.contains(r#"<option value="upload_only">Upload only</option>"#));

        let mut file_request = request(Method::GET, "/admin/shares?path=file.txt", "");
        file_request.headers_mut().insert(header::COOKIE, cookie);
        let file = response_text(app.clone().oneshot(file_request).await.unwrap()).await;
        assert!(file.contains(r#"Ausgewähltes Ziel: <code>/file.txt</code>"#));
        assert!(file.contains(r#"<input type="hidden" name="path" value="file.txt">"#));
        assert!(file.contains(r#"<option value="download_only">Download only</option>"#));
        assert!(!file.contains(r#"<option value="upload_only">Upload only</option>"#));
        assert!(file.contains("Upload-Rechte sind nur"));

        let mut create_request = request(
            Method::POST,
            "/admin/shares",
            "csrf=csrf-token&path=uploads&permission=upload_only&alias=&expires_at=&max_downloads=&password=&password_confirm=",
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
        assert!(state.db.admin("ops").unwrap().is_some());

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
        assert_eq!(
            app.clone()
                .oneshot(multipart_request("/v/upload/upload", "ok.txt", b"new"))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            app.clone()
                .oneshot(multipart_request("/v/replace/upload", "ok.txt", b"new"))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
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
        assert_eq!(
            app.clone()
                .oneshot(multipart_request("/v/upload/upload", "bad.exe", b"x"))
                .await
                .unwrap()
                .status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            app.oneshot(multipart_request(
                "/v/upload/upload",
                "large.txt",
                b"123456789"
            ))
            .await
            .unwrap()
            .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let remaining_parts = std::fs::read_dir(root.path().join("uploads"))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".part"))
            .count();
        assert_eq!(remaining_parts, 0);
    }
}
