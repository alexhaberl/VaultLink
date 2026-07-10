use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use std::{future::Future, net::IpAddr};

use axum::response::{IntoResponse, Redirect, Response};

use crate::{
    db::{Database, Session, Share},
    runtime::RuntimeSettings,
    AppState,
};

pub const SESSION_COOKIE: &str = "vaultlink_session";
const TRANSFER_COOKIE_MAX_AGE_SECONDS: i64 = 24 * 60 * 60;

tokio::task_local! {
    static REQUEST_AUDIT_CLIENT_IP: Option<IpAddr>;
}

pub async fn with_audit_client_ip<F>(client_ip: Option<IpAddr>, future: F) -> F::Output
where
    F: Future,
{
    REQUEST_AUDIT_CLIENT_IP.scope(client_ip, future).await
}

pub fn current_audit_client_ip() -> Option<IpAddr> {
    REQUEST_AUDIT_CLIENT_IP
        .try_with(|client_ip| *client_ip)
        .ok()
        .flatten()
}

#[derive(Debug, Clone, Copy)]
pub enum MissingSession {
    RedirectToLogin,
    Unauthorized,
}

#[derive(Debug)]
pub struct HttpAuthError {
    pub status: StatusCode,
    pub message: &'static str,
    pub redirect: Option<&'static str>,
}

impl HttpAuthError {
    pub fn status(status: StatusCode, message: &'static str) -> Self {
        Self {
            status,
            message,
            redirect: None,
        }
    }

    pub fn redirect(location: &'static str) -> Self {
        Self {
            status: StatusCode::SEE_OTHER,
            message: location,
            redirect: Some(location),
        }
    }
}

pub type Result<T> = std::result::Result<T, HttpAuthError>;

pub fn internal<T>(_: T) -> HttpAuthError {
    HttpAuthError::status(StatusCode::INTERNAL_SERVER_ERROR, "Interner Fehler")
}

pub async fn database<T, F>(database: Database, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(Database) -> rusqlite::Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || operation(database))
        .await
        .map_err(internal)?
        .map_err(internal)
}

pub async fn audit(
    state: &AppState,
    actor: String,
    action: &'static str,
    object: Option<String>,
    detail: Option<String>,
) {
    let client_ip = runtime_settings(state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let _ = database(state.db.clone(), move |db| {
        db.audit_with_client_ip(
            &actor,
            action,
            object.as_deref(),
            detail.as_deref(),
            client_ip.as_deref(),
        )
    })
    .await;
}

pub fn runtime_settings(state: &AppState) -> RuntimeSettings {
    state
        .runtime
        .read()
        .expect("runtime settings lock poisoned")
        .clone()
}

pub async fn commit_runtime_settings(
    state: &AppState,
    next: RuntimeSettings,
    admin_id: i64,
) -> Result<()> {
    next.validate_for_config(&state.config)
        .map_err(|_| HttpAuthError::status(StatusCode::BAD_REQUEST, "Ungültige Einstellung"))?;
    let runtime = state.runtime.clone();
    database(state.db.clone(), move |database| {
        // Settings commits always acquire locks in Runtime -> Database order. Readers
        // therefore see the old snapshot until SQLite has committed the replacement.
        let mut current = runtime.write().expect("runtime settings lock poisoned");
        let pairs = next.pairs();
        database.replace_runtime_settings(&pairs, admin_id)?;
        *current = next;
        Ok(())
    })
    .await
}

pub fn named_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
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

pub fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    named_cookie(headers, SESSION_COOKIE)
}

pub async fn session(
    state: &AppState,
    headers: &HeaderMap,
    require_mfa: bool,
    missing: MissingSession,
) -> Result<(String, Session)> {
    let token = session_cookie(headers).ok_or_else(|| match missing {
        MissingSession::RedirectToLogin => HttpAuthError::redirect("/login"),
        MissingSession::Unauthorized => {
            HttpAuthError::status(StatusCode::UNAUTHORIZED, "Anmeldung erforderlich")
        }
    })?;
    let session_token = token.to_string();
    let session = database(state.db.clone(), move |db| db.session(&session_token))
        .await?
        .ok_or_else(|| match missing {
            MissingSession::RedirectToLogin => HttpAuthError::redirect("/login"),
            MissingSession::Unauthorized => {
                HttpAuthError::status(StatusCode::UNAUTHORIZED, "Anmeldung erforderlich")
            }
        })?;
    if require_mfa && !session.mfa_verified {
        return Err(HttpAuthError::status(
            StatusCode::FORBIDDEN,
            "MFA-Verifikation erforderlich",
        ));
    }
    Ok((token.to_string(), session))
}

pub fn csrf(session: &Session, value: &str) -> Result<()> {
    if session.csrf_token.as_bytes() != value.as_bytes() {
        return Err(HttpAuthError::status(
            StatusCode::FORBIDDEN,
            "Ungültiges CSRF-Token",
        ));
    }
    Ok(())
}

pub fn csrf_header(session: &Session, headers: &HeaderMap) -> Result<()> {
    let value = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| HttpAuthError::status(StatusCode::FORBIDDEN, "CSRF-Token fehlt"))?;
    csrf(session, value)
}

pub fn make_session_cookie(state: &AppState, token: &str) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={};{}",
        state.config.security.session_hours * 3600,
        if state.config.security.secure_cookie {
            " Secure"
        } else {
            ""
        }
    )
}

pub fn clear_session_cookie(state: &AppState) -> String {
    format!(
        "{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0;{}",
        if state.config.security.secure_cookie {
            " Secure"
        } else {
            ""
        }
    )
}

pub fn redirect_with_cookie(to: &str, value: String) -> Result<Response> {
    let mut response = Redirect::to(to).into_response();
    let value = HeaderValue::from_str(&value).map_err(internal)?;
    response.headers_mut().insert(header::SET_COOKIE, value);
    Ok(response)
}

pub fn unlock_cookie_name(share_id: i64) -> String {
    format!("vaultlink_unlock_{share_id}")
}

pub async fn share_is_unlocked(
    state: &AppState,
    headers: &HeaderMap,
    share: &Share,
) -> Result<bool> {
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

#[derive(Clone, Copy)]
pub enum UnlockCookieScope {
    Web,
    Api,
}

#[derive(Clone, Copy)]
pub enum TransferCookieScope {
    Web,
    Api,
}

pub fn transfer_cookie_name(share_id: i64) -> String {
    format!("vaultlink_transfer_{share_id}")
}

pub fn transfer_cookie(headers: &HeaderMap, share_id: i64) -> Option<&str> {
    named_cookie(headers, &transfer_cookie_name(share_id))
}

pub fn make_transfer_cookie(
    state: &AppState,
    share: &Share,
    token: &str,
    scope: TransferCookieScope,
) -> String {
    let path = match scope {
        TransferCookieScope::Web => format!("/v/{}", share.token),
        TransferCookieScope::Api => format!("/api/v1/public/shares/{}", share.token),
    };
    format!(
        "{}={}; Path={}; HttpOnly; SameSite=Strict; Max-Age={};{}",
        transfer_cookie_name(share.id),
        token,
        path,
        TRANSFER_COOKIE_MAX_AGE_SECONDS,
        if state.config.security.secure_cookie {
            " Secure"
        } else {
            ""
        }
    )
}

pub fn make_unlock_cookie(
    state: &AppState,
    share: &Share,
    token: &str,
    scope: UnlockCookieScope,
) -> String {
    let settings = runtime_settings(state);
    let path = match scope {
        UnlockCookieScope::Web => format!("/v/{}", share.token),
        UnlockCookieScope::Api => format!("/api/v1/public/shares/{}", share.token),
    };
    format!(
        "{}={}; Path={}; HttpOnly; SameSite=Strict; Max-Age={};{}",
        unlock_cookie_name(share.id),
        token,
        path,
        settings.share_unlock_minutes * 60,
        if state.config.security.secure_cookie {
            " Secure"
        } else {
            ""
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_response_cookie_is_reported_without_panicking() {
        let error = redirect_with_cookie("/", "cookie=value\r\nbad=value".to_string())
            .expect_err("invalid cookie header must be rejected");
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}
