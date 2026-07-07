use std::{net::SocketAddr, path::Path};

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
    db::{Database, Permission, Session, Share},
    path_security, proxy,
    range::parse_byte_range,
    AppState,
};

const COOKIE: &str = "vaultlink_session";

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
    let limit = (state
        .config
        .storage
        .max_upload_size
        .saturating_add(1024 * 1024))
    .min(usize::MAX as u64) as usize;
    Router::new()
        .route("/", get(|| async { Redirect::to("/admin") }))
        .route("/login", get(login_page).post(login))
        .route("/mfa", get(mfa_page).post(mfa))
        .route("/logout", post(logout))
        .route("/admin", get(admin_browser))
        .route("/admin/shares", get(shares_page).post(create_share))
        .route("/admin/shares/{id}/toggle", post(toggle_share))
        .route("/admin/shares/{id}/password", post(set_share_password))
        .route("/admin/shares/{id}/delete", post(delete_share))
        .route("/v/{token}", get(public_page))
        .route("/v/{token}/unlock", post(unlock_share))
        .route("/v/{token}/download", get(download).head(download))
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
    format!(
        r#"<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{} · VaultLink</title><style>:root{{--bg:#0b1020;--card:#151c31;--text:#edf2ff;--muted:#9eabc7;--accent:#6ea8fe;--bad:#ff7b86}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:16px system-ui,sans-serif}}nav,main{{max-width:1100px;margin:auto;padding:1rem}}nav{{display:flex;justify-content:space-between}}a{{color:var(--accent)}}section{{background:var(--card);padding:1.25rem;border-radius:12px;margin:1rem 0;overflow:auto}}input,select,button{{font:inherit;padding:.65rem;border-radius:7px;border:1px solid #46516d;background:#0e1528;color:var(--text)}}button{{cursor:pointer;background:#264f94}}label{{display:block;margin:.7rem 0}}table{{width:100%;border-collapse:collapse}}th,td{{padding:.65rem;border-bottom:1px solid #303a55;text-align:left}}.row{{display:flex;gap:.7rem;flex-wrap:wrap;align-items:end}}.muted{{color:var(--muted)}}.bad{{color:var(--bad)}}code{{overflow-wrap:anywhere}}@media(max-width:650px){{th:nth-child(3),td:nth-child(3){{display:none}}}}</style><script src="/assets/app.js" defer></script></head><body><nav><strong>VaultLink</strong><span><a href="/admin">Dateien</a> · <a href="/admin/shares">Links</a></span></nav><main>{}</main></body></html>"#,
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
    format!(
        "{}={}; Path=/v/{}; HttpOnly; SameSite=Strict; Max-Age={};{}",
        unlock_cookie_name(share.id),
        token,
        share.token,
        state.config.security.share_unlock_minutes * 60,
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
}
async fn admin_browser(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<BrowseQuery>,
) -> Result<Html<String>> {
    let (_, s) = session(&state, &headers, true).await?;
    let raw = q.path.unwrap_or_default();
    let page_number = q.page.unwrap_or(0).min(1_000_000);
    let rel = path_security::validate_relative(&raw)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Pfad"))?
        .to_string_lossy()
        .replace('\\', "/");
    let secure_root = state.secure_root.clone();
    let listing_path = raw.clone();
    let entries = tokio::task::spawn_blocking(move || {
        secure_root.list(&listing_path, page_number.saturating_mul(100), 101)
    })
    .await
    .map_err(internal)?
    .map_err(internal)?;
    let has_next = entries.len() > 100;
    let mut rows = String::new();
    for entry in entries.into_iter().take(100) {
        let name = entry.name;
        let is_dir = entry.is_dir;
        let size = entry.len;
        let modified = entry.modified;
        let child = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
        let target =
            percent_encoding::utf8_percent_encode(&child, percent_encoding::NON_ALPHANUMERIC);
        let display = if is_dir {
            format!("📁 <a href=\"/admin?path={target}\">{}</a>", esc(&name))
        } else {
            format!("📄 {}", esc(&name))
        };
        let modified = modified
            .map(DateTime::<Utc>::from)
            .map(|v| v.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| "—".into());
        rows+=&format!("<tr><td>{display}</td><td>{}</td><td>{}</td><td>{}</td><td><a href=\"/admin/shares?path={}\">Freigeben</a></td></tr>",if is_dir{"Ordner"}else{"Datei"},if is_dir{"—".into()}else{human(size)},modified,target);
    }
    let encoded_path =
        percent_encoding::utf8_percent_encode(&raw, percent_encoding::NON_ALPHANUMERIC);
    let previous = if page_number > 0 {
        format!(
            "<a href=\"/admin?path={encoded_path}&page={}\">Zurück</a>",
            page_number - 1
        )
    } else {
        String::new()
    };
    let next = if has_next {
        format!(
            "<a href=\"/admin?path={encoded_path}&page={}\">Weiter</a>",
            page_number + 1
        )
    } else {
        String::new()
    };
    let body=format!("<section><h1>Dateibrowser</h1><p class=muted>Relativer Pfad: /{}</p><table><thead><tr><th>Name</th><th>Typ</th><th>Größe</th><th>Geändert</th><th></th></tr></thead><tbody>{}</tbody></table><p>{} {}</p><p class=muted>100 Einträge pro Seite.</p></section><section><form method=post action=/logout><input type=hidden name=csrf value=\"{}\"><button>Abmelden</button></form></section>",esc(&rel),rows,previous,next,esc(&s.csrf_token));
    Ok(Html(page("Dateien", &body)))
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

fn validate_share_password(config: &crate::config::Security, password: &str) -> Result<()> {
    if password.chars().count() < config.share_password_min_length
        || password.len() > config.share_password_max_bytes
    {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Freigabepasswort entspricht nicht der Richtlinie",
        ));
    }
    Ok(())
}

#[derive(Default, Deserialize)]
struct ShareQuery {
    path: Option<String>,
}
async fn shares_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ShareQuery>,
) -> Result<Html<String>> {
    let (_, s) = session(&state, &headers, true).await?;
    let mut rows = String::new();
    let shares = database(state.db.clone(), |db| db.list_shares()).await?;
    for sh in shares {
        let url = format!(
            "{}/v/{}",
            state.config.server.public_base_url.trim_end_matches('/'),
            sh.token
        );
        rows += &format!(
            r#"<tr><td><code>{}</code><br><small>{}</small></td><td>{}</td><td>{}<br>{}</td><td>{}/{}</td><td><a href="{}">Öffnen</a> <button type="button" data-copy="{}">Kopieren</button><form method="post" action="/admin/shares/{}/toggle" style="display:inline"><input type="hidden" name="csrf" value="{}"><button>{}</button></form><form method="post" action="/admin/shares/{}/delete" style="display:inline"><input type="hidden" name="csrf" value="{}"><button>Löschen</button></form><form method="post" action="/admin/shares/{}/password" class="row"><input type="hidden" name="csrf" value="{}"><input type="password" name="password" minlength="{}" maxlength="{}" placeholder="Passwort ersetzen"><input type="password" name="password_confirm" placeholder="Bestätigen"><button>Setzen</button><button name="remove" value="1">Entfernen</button></form></td></tr>"#,
            esc(&sh.relative_path),
            esc(&url),
            esc(sh.permission.as_str()),
            if sh.active { "aktiv" } else { "inaktiv" },
            if sh.password_hash.is_some() {
                "passwortgeschützt"
            } else {
                "ohne Passwort"
            },
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
            state.config.security.share_password_min_length,
            state.config.security.share_password_max_bytes,
        );
    }
    let selected = q.path.unwrap_or_default();
    let body = format!(
        r#"<section><h1>Link erstellen</h1><form method="post" class="row"><input type="hidden" name="csrf" value="{}"><label>Relativer Pfad<br><input name="path" value="{}" required></label><label>Berechtigung<br><select name="permission"><option value="download_only">Download only</option><option value="upload_only">Upload only</option><option value="download_upload">Download + Upload</option></select></label><label>Alias (optional)<br><input name="alias" pattern="[A-Za-z0-9_-]{{3,32}}"></label><label>Ablauf RFC3339 (optional)<br><input name="expires_at" placeholder="2027-01-01T00:00:00Z"></label><label>Max. Downloads<br><input name="max_downloads" type="number" min="1"></label><label>Passwort (optional)<br><input name="password" type="password" minlength="{}" maxlength="{}"></label><label>Passwort bestätigen<br><input name="password_confirm" type="password"></label><button>Erstellen</button></form></section><section><h1>Freigaben</h1><table><tr><th>Pfad</th><th>Recht</th><th>Status</th><th>Downloads</th><th>Aktionen</th></tr>{}</table></section>"#,
        esc(&s.csrf_token),
        esc(&selected),
        state.config.security.share_password_min_length,
        state.config.security.share_password_max_bytes,
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
    max_downloads: Option<u64>,
    password: Option<String>,
    password_confirm: Option<String>,
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
        validate_share_password(&state.config.security, &password)?;
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
    let max_downloads = f.max_downloads;
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
            admin_id,
            password_hash.as_deref(),
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
        validate_share_password(&state.config.security, &password)?;
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
    let expires = Utc::now() + Duration::minutes(state.config.security.share_unlock_minutes);
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
        let sub = q.path.unwrap_or_default();
        let page_number = q.page.unwrap_or(0).min(1_000_000);
        let relative_dir = joined_relative(&sh.relative_path, &sub)?;
        let secure_root = state.secure_root.clone();
        let entries = tokio::task::spawn_blocking(move || {
            secure_root.list(&relative_dir, page_number.saturating_mul(100), 101)
        })
        .await
        .map_err(internal)?
        .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabeziel nicht verfügbar"))?;
        let has_next = entries.len() > 100;
        body += "<table><tr><th>Name</th><th>Aktion</th></tr>";
        for entry in entries.into_iter().take(100) {
            let rel = joined_relative(&sub, &entry.name)?;
            let name = esc(&entry.name);
            if entry.is_dir {
                body += &format!(
                    "<tr><td>📁 {name}</td><td><a href=\"/v/{token}?path={}\">Öffnen</a></td></tr>",
                    percent_encoding::utf8_percent_encode(&rel, percent_encoding::NON_ALPHANUMERIC)
                );
            } else {
                body+=&format!("<tr><td>📄 {name}</td><td><a href=\"/v/{token}/download?path={}\">Download</a></td></tr>",percent_encoding::utf8_percent_encode(&rel,percent_encoding::NON_ALPHANUMERIC));
            }
        }
        body += "</table>";
        let encoded_sub =
            percent_encoding::utf8_percent_encode(&sub, percent_encoding::NON_ALPHANUMERIC);
        if page_number > 0 {
            body += &format!(
                " <a href=\"/v/{token}?path={encoded_sub}&page={}\">Zurück</a>",
                page_number - 1
            );
        }
        if has_next {
            body += &format!(
                " <a href=\"/v/{token}?path={encoded_sub}&page={}\">Weiter</a>",
                page_number + 1
            );
        }
    } else if !sh.is_directory && sh.permission.can_download() {
        body += &format!("<p><a href=\"/v/{token}/download\">Datei herunterladen</a></p>");
    }
    if sh.is_directory && sh.permission.can_upload() {
        body += &format!(
            r#"<h2>Upload</h2><form method="post" enctype="multipart/form-data" action="/v/{token}/upload"><input type="file" name="file" required><button>Hochladen</button></form>"#
        );
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
    let field = multipart
        .next_field()
        .await
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Upload"))?
        .ok_or(AppError(StatusCode::BAD_REQUEST, "Datei fehlt"))?;
    let name = path_security::safe_filename(
        field
            .file_name()
            .ok_or(AppError(StatusCode::BAD_REQUEST, "Dateiname fehlt"))?,
    )
    .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Dateiname"))?
    .to_string();
    if extension_is_blocked(&name, &state.config.storage.blocked_extensions) {
        return Err(AppError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Dateityp blockiert",
        ));
    }
    let secure_root = state.secure_root.clone();
    let upload_directory = sh.relative_path.clone();
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
        let chunk = chunk.map_err(|_| AppError(StatusCode::BAD_REQUEST, "Upload abgebrochen"))?;
        let Some(new_total) =
            add_upload_bytes(total, chunk.len(), state.config.storage.max_upload_size)
        else {
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
    tokio::task::spawn_blocking(move || pending.publish(&publish_name))
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
        "upload",
        Some(sh.id.to_string()),
        Some(name),
    )
    .await;
    Ok(Redirect::to(&format!("/v/{token}")))
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
        let boundary = "vaultlink-test-boundary";
        let mut body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .into_bytes();
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
            download_count: 0,
            active,
            password_hash: None,
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
                1,
                None,
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
                1,
                None,
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
                1,
                Some(&password_hash),
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
                1,
                None,
            )
            .unwrap();
        let app = router(state);

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
