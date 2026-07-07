use std::{net::SocketAddr, path::Path};

use axum::{
    body::Body,
    extract::{
        ConnectInfo, DefaultBodyLimit, Form, Multipart, Path as AxPath, Query, Request, State,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Duration, Utc};
use futures_util::StreamExt;
use serde::Deserialize;
use tokio::{fs::OpenOptions, io::AsyncWriteExt};
use tokio_util::io::ReaderStream;
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};

use crate::{
    auth,
    db::{Permission, Session, Share},
    path_security, proxy, AppState,
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
        .route("/admin/shares/{id}/delete", post(delete_share))
        .route("/v/{token}", get(public_page))
        .route("/v/{token}/download", get(download))
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
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|p| {
            let (k, v) = p.trim().split_once('=')?;
            (k == COOKIE).then_some(v)
        })
}
fn session(state: &AppState, headers: &HeaderMap, mfa: bool) -> Result<(String, Session)> {
    let token = cookie(headers).ok_or(AppError(StatusCode::SEE_OTHER, "/login"))?;
    let s = state
        .db
        .session(token)
        .map_err(internal)?
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
    let admin = state.db.admin(&form.username).map_err(internal)?;
    let valid = admin
        .as_ref()
        .map(|a| auth::verify_password(&a.password_hash, &form.password))
        .unwrap_or_else(|| {
            let _ = auth::hash_password(&form.password);
            false
        });
    if !valid {
        state.limiter.failure(&key);
        state.limiter.failure(&ip_key);
        let _ = state.db.audit(&form.username, "login_failed", None, None);
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    state.limiter.success(&key);
    state.limiter.success(&ip_key);
    let a = admin.unwrap();
    let token = auth::random_token(32);
    let csrf = auth::random_token(24);
    state
        .db
        .create_session(
            &token,
            a.id,
            &csrf,
            Utc::now() + Duration::hours(state.config.security.session_hours),
        )
        .map_err(internal)?;
    let _ = state.db.audit(&a.username, "password_verified", None, None);
    Ok(redirect_cookie("/mfa", make_cookie(&state, &token)))
}
async fn mfa_page(State(state): State<AppState>, headers: HeaderMap) -> Result<Html<String>> {
    session(&state, &headers, false)?;
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
    let (token, s) = session(&state, &headers, false)?;
    let key = format!("mfa:{}", s.username.to_lowercase());
    if !state.limiter.allowed(&key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele MFA-Versuche",
        ));
    }
    let admin = state
        .db
        .admin(&s.username)
        .map_err(internal)?
        .ok_or_else(|| internal(()))?;
    if !auth::verify_totp_now(&admin.totp_secret, &form.code) {
        state.limiter.failure(&key);
        let _ = state.db.audit(&s.username, "mfa_failed", None, None);
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültiger MFA-Code"));
    }
    state.limiter.success(&key);
    state.db.verify_mfa(&token).map_err(internal)?;
    let _ = state.db.audit(&s.username, "login_success", None, None);
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
    let (token, s) = session(&state, &headers, false)?;
    csrf(&s, &form.csrf)?;
    state.db.delete_session(&token).map_err(internal)?;
    let _ = state.db.audit(&s.username, "logout", None, None);
    Ok(redirect_cookie("/login", clear_cookie(&state)))
}

#[derive(Default, Deserialize)]
struct BrowseQuery {
    path: Option<String>,
}
async fn admin_browser(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<BrowseQuery>,
) -> Result<Html<String>> {
    let (_, s) = session(&state, &headers, true)?;
    let raw = q.path.unwrap_or_default();
    let dir = path_security::resolve_existing(&state.root, &raw)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Pfad"))?;
    if !dir.is_dir() {
        return Err(AppError(StatusCode::BAD_REQUEST, "Kein Ordner"));
    }
    let rel = path_security::display_relative(&state.root, &dir).map_err(internal)?;
    let mut entries = std::fs::read_dir(&dir)
        .map_err(internal)?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let p = e.path().canonicalize().ok()?;
            if !p.starts_with(state.root.as_path()) {
                return None;
            }
            let m = p.metadata().ok()?;
            Some((
                e.file_name().to_string_lossy().into_owned(),
                m.is_dir(),
                m.len(),
                m.modified().ok(),
            ))
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|e| (!e.1, e.0.to_lowercase()));
    let mut rows = String::new();
    for (name, is_dir, size, modified) in entries.into_iter().take(1000) {
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
    let body=format!("<section><h1>Dateibrowser</h1><p class=muted>Relativer Pfad: /{}</p><table><thead><tr><th>Name</th><th>Typ</th><th>Größe</th><th>Geändert</th><th></th></tr></thead><tbody>{}</tbody></table><p class=muted>Maximal 1000 Einträge pro Ansicht.</p></section><section><form method=post action=/logout><input type=hidden name=csrf value=\"{}\"><button>Abmelden</button></form></section>",esc(&rel),rows,esc(&s.csrf_token));
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

#[derive(Default, Deserialize)]
struct ShareQuery {
    path: Option<String>,
}
async fn shares_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ShareQuery>,
) -> Result<Html<String>> {
    let (_, s) = session(&state, &headers, true)?;
    let mut rows = String::new();
    for sh in state.db.list_shares().map_err(internal)? {
        let url = format!(
            "{}/v/{}",
            state.config.server.public_base_url.trim_end_matches('/'),
            sh.token
        );
        rows+=&format!("<tr><td><code>{}</code><br><small>{}</small></td><td>{}</td><td>{}</td><td>{}/{}</td><td><a href=\"{}\">Öffnen</a> <button type=button data-copy=\"{}\">Kopieren</button><form method=post action=\"/admin/shares/{}/toggle\" style=\"display:inline\"><input type=hidden name=csrf value=\"{}\"><button>{}</button></form><form method=post action=\"/admin/shares/{}/delete\" style=\"display:inline\"><input type=hidden name=csrf value=\"{}\"><button>Löschen</button></form></td></tr>",esc(&sh.relative_path),esc(&url),esc(sh.permission.as_str()),if sh.active{"aktiv"}else{"inaktiv"},sh.download_count,sh.max_downloads.map(|v|v.to_string()).unwrap_or_else(||"∞".into()),esc(&url),esc(&url),sh.id,esc(&s.csrf_token),if sh.active{"Deaktivieren"}else{"Aktivieren"},sh.id,esc(&s.csrf_token));
    }
    let selected = q.path.unwrap_or_default();
    let body = format!(
        r#"<section><h1>Link erstellen</h1><form method="post" class="row"><input type="hidden" name="csrf" value="{}"><label>Relativer Pfad<br><input name="path" value="{}" required></label><label>Berechtigung<br><select name="permission"><option value="download_only">Download only</option><option value="upload_only">Upload only</option><option value="download_upload">Download + Upload</option></select></label><label>Alias (optional)<br><input name="alias" pattern="[A-Za-z0-9_-]{{3,32}}"></label><label>Ablauf RFC3339 (optional)<br><input name="expires_at" placeholder="2027-01-01T00:00:00Z"></label><label>Max. Downloads<br><input name="max_downloads" type="number" min="1"></label><button>Erstellen</button></form></section><section><h1>Freigaben</h1><table><tr><th>Pfad</th><th>Recht</th><th>Status</th><th>Downloads</th><th>Aktionen</th></tr>{}</table></section>"#,
        esc(&s.csrf_token),
        esc(&selected),
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
}
async fn create_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<CreateShare>,
) -> Result<Redirect> {
    let (_, s) = session(&state, &headers, true)?;
    csrf(&s, &f.csrf)?;
    let target = path_security::resolve_existing(&state.root, &f.path)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Zielpfad"))?;
    let rel = path_security::display_relative(&state.root, &target).map_err(internal)?;
    let permission = Permission::parse(&f.permission)
        .ok_or(AppError(StatusCode::BAD_REQUEST, "Ungültige Berechtigung"))?;
    if target.is_file() && permission.can_upload() {
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
    let id = state
        .db
        .create_share(
            &token,
            alias.as_deref(),
            &rel,
            target.is_dir(),
            &permission,
            exp,
            f.max_downloads,
            s.admin_id,
        )
        .map_err(|_| AppError(StatusCode::CONFLICT, "Token oder Alias bereits vorhanden"))?;
    let _ = state.db.audit(
        &s.username,
        "share_created",
        Some(&id.to_string()),
        Some(permission.as_str()),
    );
    Ok(Redirect::to("/admin/shares"))
}
async fn toggle_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Redirect> {
    let (_, s) = session(&state, &headers, true)?;
    csrf(&s, &f.csrf)?;
    let sh = state
        .db
        .list_shares()
        .map_err(internal)?
        .into_iter()
        .find(|v| v.id == id)
        .ok_or(AppError(StatusCode::NOT_FOUND, "Link nicht gefunden"))?;
    state
        .db
        .set_share_active(id, !sh.active)
        .map_err(internal)?;
    let _ = state
        .db
        .audit(&s.username, "share_toggled", Some(&id.to_string()), None);
    Ok(Redirect::to("/admin/shares"))
}
async fn delete_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Redirect> {
    let (_, s) = session(&state, &headers, true)?;
    csrf(&s, &f.csrf)?;
    state.db.delete_share(id).map_err(internal)?;
    let _ = state
        .db
        .audit(&s.username, "share_deleted", Some(&id.to_string()), None);
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
fn get_share(state: &AppState, token: &str) -> Result<Share> {
    let sh = state
        .db
        .share_by_token(token)
        .map_err(internal)?
        .ok_or(AppError(StatusCode::NOT_FOUND, "Link nicht gefunden"))?;
    usable(&sh)?;
    Ok(sh)
}
async fn public_page(
    State(state): State<AppState>,
    AxPath(token): AxPath<String>,
    Query(q): Query<BrowseQuery>,
) -> Result<Html<String>> {
    let sh = get_share(&state, &token)?;
    let target = path_security::resolve_existing(&state.root, &sh.relative_path)
        .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabeziel nicht verfügbar"))?;
    let mut body = format!(
        "<section><h1>Öffentliche Freigabe</h1><p>Berechtigung: <strong>{}</strong></p>",
        esc(sh.permission.as_str())
    );
    if sh.is_directory && sh.permission.can_download() {
        let sub = q.path.unwrap_or_default();
        let base = if sub.is_empty() {
            target.clone()
        } else {
            let rel = path_security::validate_relative(&sub)
                .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Pfad"))?;
            path_security::resolve_existing(&target, &rel.to_string_lossy())
                .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Pfad"))?
        };
        if !base.starts_with(&target) || !base.is_dir() {
            return Err(AppError(StatusCode::FORBIDDEN, "Zugriff verweigert"));
        }
        body += "<table><tr><th>Name</th><th>Aktion</th></tr>";
        for e in std::fs::read_dir(&base)
            .map_err(internal)?
            .filter_map(|e| e.ok())
            .take(1000)
        {
            let p = match e.path().canonicalize() {
                Ok(v) if v.starts_with(&target) => v,
                _ => continue,
            };
            let rel = path_security::display_relative(&target, &p).map_err(internal)?;
            let name = esc(&e.file_name().to_string_lossy());
            if p.is_dir() {
                body += &format!(
                    "<tr><td>📁 {name}</td><td><a href=\"/v/{token}?path={}\">Öffnen</a></td></tr>",
                    percent_encoding::utf8_percent_encode(&rel, percent_encoding::NON_ALPHANUMERIC)
                );
            } else {
                body+=&format!("<tr><td>📄 {name}</td><td><a href=\"/v/{token}/download?path={}\">Download</a></td></tr>",percent_encoding::utf8_percent_encode(&rel,percent_encoding::NON_ALPHANUMERIC));
            }
        }
        body += "</table>";
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
async fn download(
    State(state): State<AppState>,
    AxPath(token): AxPath<String>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response> {
    let sh = get_share(&state, &token)?;
    if !sh.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "Download nicht erlaubt"));
    }
    let base = path_security::resolve_existing(&state.root, &sh.relative_path)
        .map_err(|_| AppError(StatusCode::NOT_FOUND, "Datei nicht verfügbar"))?;
    let file = if sh.is_directory {
        let rel = q
            .path
            .ok_or(AppError(StatusCode::BAD_REQUEST, "Dateipfad fehlt"))?;
        let p = path_security::resolve_existing(&base, &rel)
            .map_err(|_| AppError(StatusCode::FORBIDDEN, "Ungültiger Pfad"))?;
        if !p.starts_with(&base) {
            return Err(AppError(StatusCode::FORBIDDEN, "Zugriff verweigert"));
        }
        p
    } else {
        base
    };
    if !file.is_file() {
        return Err(AppError(StatusCode::BAD_REQUEST, "Keine Datei"));
    }
    if !state.db.count_download(sh.id).map_err(internal)? {
        return Err(AppError(StatusCode::GONE, "Downloadlimit erreicht"));
    }
    let f = tokio::fs::File::open(&file).await.map_err(internal)?;
    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("download");
    let encoded = percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC);
    let mut r = Response::new(Body::from_stream(ReaderStream::new(f)));
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(
            mime_guess::from_path(&file)
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
    let _ = state
        .db
        .audit("public", "download", Some(&sh.id.to_string()), None);
    Ok(r)
}
async fn upload(
    State(state): State<AppState>,
    AxPath(token): AxPath<String>,
    mut multipart: Multipart,
) -> Result<Redirect> {
    let sh = get_share(&state, &token)?;
    if !sh.is_directory || !sh.permission.can_upload() {
        return Err(AppError(StatusCode::FORBIDDEN, "Upload nicht erlaubt"));
    }
    let dir = path_security::resolve_existing(&state.root, &sh.relative_path)
        .map_err(|_| AppError(StatusCode::NOT_FOUND, "Zielordner nicht verfügbar"))?;
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
    let destination = dir.join(&name);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                AppError(StatusCode::CONFLICT, "Datei existiert bereits")
            } else {
                internal(e)
            }
        })?;
    let mut total = 0u64;
    let stream = field;
    tokio::pin!(stream);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| AppError(StatusCode::BAD_REQUEST, "Upload abgebrochen"))?;
        let Some(new_total) =
            add_upload_bytes(total, chunk.len(), state.config.storage.max_upload_size)
        else {
            drop(output);
            let _ = tokio::fs::remove_file(&destination).await;
            return Err(AppError(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Upload ist zu groß",
            ));
        };
        total = new_total;
        if let Err(e) = output.write_all(&chunk).await {
            drop(output);
            let _ = tokio::fs::remove_file(&destination).await;
            return Err(internal(e));
        }
    }
    output.flush().await.map_err(internal)?;
    let _ = state
        .db
        .audit("public", "upload", Some(&sh.id.to_string()), Some(&name));
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
    let sh = state
        .db
        .share_by_alias(&alias)
        .map_err(internal)?
        .ok_or(AppError(StatusCode::NOT_FOUND, "Alias nicht gefunden"))?;
    usable(&sh)?;
    Ok(Redirect::to(&format!("/v/{}", sh.token)))
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let result = OpenOptions::new()
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
}
