use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex, RwLockWriteGuard},
};

use axum::response::{IntoResponse, Redirect, Response};

use crate::{
    auth,
    db::{
        AuditAction, AuditContext, AuthenticatedMfaSession, Database, MfaSessionProof, Session,
        SessionBound, Share,
    },
    runtime::RuntimeSettings,
    AppState,
};

pub const SESSION_COOKIE: &str = "vaultlink_session";
pub const SECURE_SESSION_COOKIE: &str = "__Host-vaultlink_session";
pub(crate) const AUDIT_UNAVAILABLE_MESSAGE: &str = "Security audit log temporarily unavailable";
pub(crate) const ARGON2_BUSY_MESSAGE: &str = "Password processing temporarily unavailable";
pub(crate) const SERVICE_TOKEN_PREFIX: &str = "vlk_st_v1_";
pub(crate) const DATABASE_BUSY_MESSAGE: &str = "Database temporarily unavailable";
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

pub fn enabled_audit_client_ip(state: &AppState) -> Option<String> {
    runtime_settings(state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string())
}

pub fn current_client_limit_key() -> IpAddr {
    crate::proxy::client_limit_key(
        current_audit_client_ip().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
    )
}

/// Shared web/API admission for administrator password login.
pub fn admin_login_attempt_admitted(state: &AppState, username: &str) -> bool {
    state
        .admin_login_limiter
        .check_and_record_attempt(username, current_client_limit_key())
}

pub(crate) struct ClientActivityPermit {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    peer: IpAddr,
    maximum: usize,
}

impl Drop for ClientActivityPermit {
    fn drop(&mut self) {
        let mut counts = client_activity_counts(&self.counts, self.maximum);
        if let Some(count) = counts.get_mut(&self.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.peer);
            }
        }
    }
}

fn client_activity_counts(
    counts: &Mutex<HashMap<IpAddr, usize>>,
    maximum: usize,
) -> std::sync::MutexGuard<'_, HashMap<IpAddr, usize>> {
    match counts.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            tracing::error!("recovering poisoned client activity admission map");
            let mut guard = poisoned.into_inner();
            // Counts are conservative admission state, not authority. Remove
            // impossible zero entries and cap damaged values at the route's
            // configured ceiling so one poison event cannot lock a peer out
            // forever while still avoiding an under-count.
            guard.retain(|_, count| {
                *count = (*count).min(maximum);
                *count > 0
            });
            counts.clear_poison();
            guard
        }
    }
}

pub(crate) fn try_acquire_client_activity(
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    peer: IpAddr,
    maximum: usize,
) -> Option<ClientActivityPermit> {
    let mut active = client_activity_counts(&counts, maximum);
    let count = active.entry(peer).or_default();
    if *count >= maximum {
        return None;
    }
    *count += 1;
    drop(active);
    Some(ClientActivityPermit {
        counts,
        peer,
        maximum,
    })
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
    pub kind: HttpAuthErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpAuthErrorKind {
    Request,
    SessionRevoked,
    AuditUnavailable,
    CapacityUnavailable,
    AmbiguousAuthentication,
    InsufficientScope,
}

impl HttpAuthError {
    pub fn status(status: StatusCode, message: &'static str) -> Self {
        Self {
            status,
            message,
            redirect: None,
            kind: HttpAuthErrorKind::Request,
        }
    }

    pub(crate) fn with_kind(
        status: StatusCode,
        message: &'static str,
        kind: HttpAuthErrorKind,
    ) -> Self {
        Self {
            status,
            message,
            redirect: None,
            kind,
        }
    }

    pub fn redirect(location: &'static str) -> Self {
        Self {
            status: StatusCode::SEE_OTHER,
            message: location,
            redirect: Some(location),
            kind: HttpAuthErrorKind::Request,
        }
    }
}

pub type Result<T> = std::result::Result<T, HttpAuthError>;

pub fn internal<T>(_: T) -> HttpAuthError {
    HttpAuthError::status(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
}

fn argon2_busy<T>(_: T) -> HttpAuthError {
    HttpAuthError::with_kind(
        StatusCode::SERVICE_UNAVAILABLE,
        ARGON2_BUSY_MESSAGE,
        HttpAuthErrorKind::CapacityUnavailable,
    )
}

pub(crate) async fn hash_password_admitted(
    state: &AppState,
    password: crate::sensitive::SecretString,
) -> Result<String> {
    let permit = state
        .argon2_admission
        .clone()
        .try_acquire_owned()
        .map_err(argon2_busy)?;
    tokio::task::spawn_blocking(move || {
        // Keep the owned permit in the blocking task so cancelling the request
        // cannot release capacity while Argon2 is still consuming CPU and RAM.
        let _permit = permit;
        crate::auth::hash_secret_password(&password)
    })
    .await
    .map_err(internal)?
    .map_err(internal)
}

pub(crate) async fn verify_password_admitted(
    state: &AppState,
    password_hash: Option<String>,
    password: crate::sensitive::SecretString,
) -> Result<bool> {
    let permit = state
        .argon2_admission
        .clone()
        .try_acquire_owned()
        .map_err(argon2_busy)?;
    tokio::task::spawn_blocking(move || {
        // Acquire before branching so known and unknown users receive the same
        // overload response and both paths consume one admitted Argon2 job.
        let _permit = permit;
        match password_hash {
            Some(hash) => crate::auth::verify_secret_password(&hash, &password),
            None => {
                let _ = crate::auth::hash_secret_password(&password);
                false
            }
        }
    })
    .await
    .map_err(internal)
}

pub(crate) async fn password_login_admitted(
    state: &AppState,
    command: crate::services::auth::PasswordLoginCommand,
) -> Result<crate::services::auth::PasswordLoginOutcome> {
    let permit = state
        .argon2_admission
        .clone()
        .try_acquire_owned()
        .map_err(argon2_busy)?;
    let service = crate::services::auth::AuthService::new(state.db.clone());
    tokio::task::spawn_blocking(move || {
        // The complete service operation owns the admitted Argon2 job. Unknown
        // and known accounts therefore share capacity and overload behavior.
        let _permit = permit;
        service.login_with_password(command)
    })
    .await
    .map_err(internal)?
    .map_err(database_error)
}

pub async fn database<T, F>(database: Database, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(Database) -> rusqlite::Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || operation(database))
        .await
        .map_err(internal)?
        .map_err(database_error)
}

pub async fn required_database<T, F>(database: Database, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(Database) -> rusqlite::Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || operation(database))
        .await
        .map_err(internal)?
        .map_err(database_error)
}

pub(crate) fn database_error(error: rusqlite::Error) -> HttpAuthError {
    if crate::db::is_audit_unavailable(&error) {
        tracing::error!(
            error = %error,
            "required audit transaction rolled back"
        );
        HttpAuthError::with_kind(
            StatusCode::SERVICE_UNAVAILABLE,
            AUDIT_UNAVAILABLE_MESSAGE,
            HttpAuthErrorKind::AuditUnavailable,
        )
    } else if crate::db::is_sqlite_busy_or_locked(&error) {
        tracing::warn!(error = %error, "database operation timed out waiting for SQLite capacity");
        HttpAuthError::with_kind(
            StatusCode::SERVICE_UNAVAILABLE,
            DATABASE_BUSY_MESSAGE,
            HttpAuthErrorKind::CapacityUnavailable,
        )
    } else {
        internal(error)
    }
}

/// Persists a non-transactional observation. Successful security mutations
/// must use a required audit transaction instead.
pub(crate) async fn audit_observation(
    state: &AppState,
    actor: String,
    action: AuditAction,
    object: Option<String>,
    detail: Option<String>,
) {
    let client_ip = enabled_audit_client_ip(state);
    let result = database(state.db.clone(), move |db| {
        db.audit_action_with_client_ip(
            action,
            &actor,
            object.as_deref(),
            detail.as_deref(),
            client_ip.as_deref(),
        )
    })
    .await;
    if let Err(error) = result {
        tracing::error!(
            ?error,
            action = action.as_str(),
            "could not persist audit event"
        );
    }
}

pub fn runtime_settings(state: &AppState) -> RuntimeSettings {
    match state.runtime.read() {
        Ok(settings) => settings.clone(),
        Err(poisoned) => {
            tracing::error!("recovering poisoned runtime settings snapshot");
            let settings = poisoned.into_inner();
            if settings.validate_for_config(&state.config).is_ok() {
                let recovered = settings.clone();
                state.runtime.clear_poison();
                return recovered;
            }
            drop(settings);

            let mut settings = match state.runtime.write() {
                Ok(settings) => return settings.clone(),
                Err(poisoned) => poisoned.into_inner(),
            };
            // Another request may have repaired the snapshot while this one
            // transitioned from a read to a write guard.
            if settings.validate_for_config(&state.config).is_err() {
                let replacement = match state.db.runtime_settings() {
                    Ok(persisted) => {
                        match crate::runtime_settings_from_persisted(&state.config, &persisted) {
                            Ok(replacement) => replacement,
                            Err(error) => {
                                tracing::error!(%error, "persisted runtime settings were invalid during poison recovery; using validated static defaults");
                                RuntimeSettings::from_config(&state.config)
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(%error, "could not reload runtime settings during poison recovery; using validated static defaults");
                        RuntimeSettings::from_config(&state.config)
                    }
                };
                *settings = replacement;
            }
            let recovered = settings.clone();
            state.runtime.clear_poison();
            recovered
        }
    }
}

pub fn webauthn_service(state: &AppState) -> Result<crate::webauthn::WebAuthnService> {
    match state.webauthn.read() {
        Ok(service) => Ok(service.clone()),
        Err(poisoned) => {
            tracing::error!("recovering poisoned WebAuthn service snapshot");
            drop(poisoned.into_inner());
            let public_base_url = runtime_settings(state).public_base_url;
            let replacement =
                crate::webauthn::WebAuthnService::from_public_base_url(&public_base_url)
                    .map_err(internal)?;
            let mut service = match state.webauthn.write() {
                Ok(service) => return Ok(service.clone()),
                Err(poisoned) => poisoned.into_inner(),
            };
            // Pending ceremonies cannot be validated after an unwind. Replace
            // the complete service and discard every in-flight challenge.
            *service = replacement;
            let recovered = service.clone();
            state.webauthn.clear_poison();
            Ok(recovered)
        }
    }
}

/// Keeps the previous in-memory settings snapshots available until SQLite's
/// required-audit transaction has committed. If audit insertion or COMMIT
/// fails, `Drop` restores both snapshots before the transaction releases its
/// writer fence, so a waiting revocation can never observe a later publication.
struct RuntimeSettingsPublication<'a> {
    runtime: RwLockWriteGuard<'a, RuntimeSettings>,
    previous_runtime: Option<RuntimeSettings>,
    webauthn: Option<RwLockWriteGuard<'a, crate::webauthn::WebAuthnService>>,
    previous_webauthn: Option<crate::webauthn::WebAuthnService>,
}

impl<'a> RuntimeSettingsPublication<'a> {
    fn publish(
        mut runtime: RwLockWriteGuard<'a, RuntimeSettings>,
        next: RuntimeSettings,
        mut webauthn: Option<RwLockWriteGuard<'a, crate::webauthn::WebAuthnService>>,
        replacement_webauthn: Option<crate::webauthn::WebAuthnService>,
    ) -> Self {
        let previous_runtime = Some(std::mem::replace(&mut *runtime, next));
        let previous_webauthn = match (webauthn.as_mut(), replacement_webauthn) {
            (Some(current), Some(replacement)) => {
                Some(std::mem::replace(&mut **current, replacement))
            }
            (None, None) => None,
            _ => unreachable!("WebAuthn snapshot lock and replacement must agree"),
        };
        Self {
            runtime,
            previous_runtime,
            webauthn,
            previous_webauthn,
        }
    }
}

impl crate::db::CommitPublication for RuntimeSettingsPublication<'_> {
    fn accept_commit(&mut self) {
        self.previous_runtime = None;
        self.previous_webauthn = None;
    }
}

impl Drop for RuntimeSettingsPublication<'_> {
    fn drop(&mut self) {
        if let (Some(current), Some(previous)) =
            (self.webauthn.as_mut(), self.previous_webauthn.take())
        {
            **current = previous;
        }
        if let Some(previous) = self.previous_runtime.take() {
            *self.runtime = previous;
        }
    }
}

pub(crate) async fn commit_runtime_settings(
    state: &AppState,
    proof: MfaSessionProof,
    next: RuntimeSettings,
    audit_actor: String,
    audit_detail: String,
) -> Result<SessionBound<()>> {
    let security_settings_guard = state.security_settings_mutation.clone().lock_owned().await;
    next.validate_for_config(&state.config)
        .map_err(|_| HttpAuthError::status(StatusCode::BAD_REQUEST, "Invalid setting"))?;
    let public_url_changed = runtime_settings(state).public_base_url != next.public_base_url;
    let replacement_webauthn = if public_url_changed {
        Some(
            crate::webauthn::WebAuthnService::from_public_base_url(&next.public_base_url).map_err(
                |_| {
                    HttpAuthError::status(StatusCode::BAD_REQUEST, "Invalid WebAuthn configuration")
                },
            )?,
        )
    } else {
        None
    };
    if public_url_changed {
        let credential_count = database(state.db.clone(), |database| {
            database.webauthn_credential_count()
        })
        .await?;
        if credential_count > 0 {
            return Err(HttpAuthError::status(
                StatusCode::CONFLICT,
                "Public base URL cannot be changed while security keys are registered",
            ));
        }
    }
    let runtime = state.runtime.clone();
    let webauthn = state.webauthn.clone();
    let replace_webauthn = replacement_webauthn.is_some();
    #[cfg(test)]
    let settings_publication_barrier = state.settings_publication_barrier.clone();
    // Match the previous post-commit audit semantics: an update that enables
    // client-IP auditing may record this request, while a disabling update may
    // not. The database still re-checks the persisted setting at insert time.
    let audit_client_ip = next
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(audit_actor, audit_client_ip);
    required_database(state.db.clone(), move |database| {
        // A cancelled request drops only the JoinHandle; the blocking database
        // operation keeps this owned guard until the runtime/WebAuthn snapshot
        // and SQLite commit have advanced together.
        let _security_settings_guard = security_settings_guard;
        // Settings commits always acquire locks in Runtime -> WebAuthn -> Database
        // order. The publication guard rolls both snapshots back on any required-
        // audit or COMMIT failure before SQLite admits a waiting revocation.
        let current = match runtime.write() {
            Ok(current) => current,
            Err(poisoned) => {
                tracing::error!("replacing poisoned runtime settings snapshot");
                poisoned.into_inner()
            }
        };
        let current_webauthn = if replacement_webauthn.is_some() {
            Some(match webauthn.write() {
                Ok(service) => service,
                Err(poisoned) => {
                    tracing::error!("replacing poisoned WebAuthn service snapshot");
                    poisoned.into_inner()
                }
            })
        } else {
            None
        };
        let pairs = next.pairs();
        let outcome = database.replace_runtime_settings_for_mfa_session(
            &proof,
            &pairs,
            &audit_context,
            audit_detail,
            || {
                #[cfg(test)]
                {
                    let mut barrier = match settings_publication_barrier.lock() {
                        Ok(barrier) => barrier,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    if let Some((entered, release)) = barrier.take() {
                        let _ = entered.send(());
                        let _ = release.recv();
                    }
                }
                RuntimeSettingsPublication::publish(
                    current,
                    next,
                    current_webauthn,
                    replacement_webauthn,
                )
            },
        )?;
        match outcome {
            SessionBound::Authorized(publication) => {
                runtime.clear_poison();
                if replace_webauthn {
                    webauthn.clear_poison();
                }
                drop(publication);
                Ok(SessionBound::Authorized(()))
            }
            SessionBound::SessionUnavailable => Ok(SessionBound::SessionUnavailable),
        }
    })
    .await
}

pub fn named_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut found = None;
    for header_value in headers.get_all(header::COOKIE) {
        let value = header_value.to_str().ok()?;
        for pair in value.split(';') {
            let Some((key, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if key != name {
                continue;
            }
            // Ambiguous cookies are rejected instead of relying on ordering that
            // differs between browsers and can be influenced by sibling domains.
            if found.is_some() {
                return None;
            }
            found = Some(value);
        }
    }
    found
}

fn session_cookie_name(state: &AppState) -> &'static str {
    if state.config.security.secure_cookie {
        SECURE_SESSION_COOKIE
    } else {
        SESSION_COOKIE
    }
}

enum ExactHeader<'a> {
    Missing,
    One(&'a str),
    Malformed,
    Ambiguous,
}

fn exact_session_cookie<'a>(state: &AppState, headers: &'a HeaderMap) -> ExactHeader<'a> {
    let name = session_cookie_name(state);
    let mut found = None;
    for header_value in headers.get_all(header::COOKIE) {
        let Ok(value) = header_value.to_str() else {
            return ExactHeader::Malformed;
        };
        for pair in value.split(';') {
            let Some((key, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if key != name {
                continue;
            }
            if found.is_some() {
                return ExactHeader::Ambiguous;
            }
            found = Some(value);
        }
    }
    found.map_or(ExactHeader::Missing, ExactHeader::One)
}

fn exact_authorization(headers: &HeaderMap) -> ExactHeader<'_> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return ExactHeader::Missing;
    };
    if values.next().is_some() {
        return ExactHeader::Ambiguous;
    }
    let Ok(value) = value.to_str() else {
        return ExactHeader::Malformed;
    };
    if value.contains(',') {
        return ExactHeader::Ambiguous;
    }
    ExactHeader::One(value)
}

fn strict_service_token(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    if bytes.len() < 7 || !bytes[..6].eq_ignore_ascii_case(b"Bearer") || bytes[6] != b' ' {
        return None;
    }
    let token = &value[7..];
    let encoded = token.strip_prefix(SERVICE_TOKEN_PREFIX)?;
    if encoded.len() != 43
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return None;
    }
    let decoded = zeroize::Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded.as_bytes()).ok()?);
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded.as_slice()) != encoded {
        return None;
    }
    Some(token)
}

/// Authorizes the deliberately narrow monitoring API with exactly one
/// authentication mechanism. All other administrator routes remain cookie-only.
pub(crate) async fn authorize_monitoring(state: &AppState, headers: &HeaderMap) -> Result<()> {
    let cookie = exact_session_cookie(state, headers);
    let authorization = exact_authorization(headers);
    match (cookie, authorization) {
        (ExactHeader::One(_), ExactHeader::One(_) | ExactHeader::Malformed)
        | (ExactHeader::One(_), ExactHeader::Ambiguous)
        | (ExactHeader::Ambiguous, _)
        | (_, ExactHeader::Ambiguous) => Err(HttpAuthError::with_kind(
            StatusCode::BAD_REQUEST,
            "Ambiguous authentication",
            HttpAuthErrorKind::AmbiguousAuthentication,
        )),
        (ExactHeader::Malformed, _) | (_, ExactHeader::Malformed) => Err(HttpAuthError::status(
            StatusCode::UNAUTHORIZED,
            "Invalid authentication",
        )),
        (ExactHeader::One(_), ExactHeader::Missing) => {
            session(state, headers, true, MissingSession::Unauthorized)
                .await
                .map(drop)
        }
        (ExactHeader::Missing, ExactHeader::One(value)) => {
            let token = zeroize::Zeroizing::new(
                strict_service_token(value)
                    .ok_or_else(|| {
                        HttpAuthError::status(StatusCode::UNAUTHORIZED, "Invalid authentication")
                    })?
                    .to_owned(),
            );
            let outcome = database(state.db.clone(), move |database| {
                database.authorize_service_token(
                    token.as_str(),
                    crate::db::SERVICE_TOKEN_SCOPE_MONITORING_READ,
                )
            })
            .await?;
            match outcome {
                crate::db::ServiceTokenAuthorizationOutcome::Authorized { .. } => Ok(()),
                crate::db::ServiceTokenAuthorizationOutcome::Unauthorized => Err(
                    HttpAuthError::status(StatusCode::UNAUTHORIZED, "Invalid authentication"),
                ),
                crate::db::ServiceTokenAuthorizationOutcome::InsufficientScope => {
                    Err(HttpAuthError::with_kind(
                        StatusCode::FORBIDDEN,
                        "Insufficient token scope",
                        HttpAuthErrorKind::InsufficientScope,
                    ))
                }
            }
        }
        (ExactHeader::Missing, ExactHeader::Missing) => Err(HttpAuthError::status(
            StatusCode::UNAUTHORIZED,
            "Authentication required",
        )),
    }
}

pub fn session_cookie<'a>(state: &AppState, headers: &'a HeaderMap) -> Option<&'a str> {
    named_cookie(headers, session_cookie_name(state))
}

pub async fn session(
    state: &AppState,
    headers: &HeaderMap,
    require_mfa: bool,
    missing: MissingSession,
) -> Result<(String, Session)> {
    let token = session_cookie(state, headers).ok_or_else(|| match missing {
        MissingSession::RedirectToLogin => HttpAuthError::redirect("/login"),
        MissingSession::Unauthorized => {
            HttpAuthError::status(StatusCode::UNAUTHORIZED, "Sign-in required")
        }
    })?;
    let session_token = token.to_string();
    let session = database(state.db.clone(), move |db| db.session(&session_token))
        .await?
        .ok_or_else(|| {
            HttpAuthError::with_kind(
                StatusCode::UNAUTHORIZED,
                "Session is no longer authorized",
                HttpAuthErrorKind::SessionRevoked,
            )
        })?;
    if require_mfa && !session.mfa_verified {
        return Err(HttpAuthError::status(
            StatusCode::FORBIDDEN,
            "MFA verification required",
        ));
    }
    Ok((token.to_string(), session))
}

/// Performs the request-bound MFA check and retains only an opaque hash proof
/// of the exact session for the later commit-time revalidation.
pub(crate) async fn mfa_session(
    state: &AppState,
    headers: &HeaderMap,
    missing: MissingSession,
) -> Result<AuthenticatedMfaSession> {
    let token = session_cookie(state, headers).ok_or_else(|| match missing {
        MissingSession::RedirectToLogin => HttpAuthError::redirect("/login"),
        MissingSession::Unauthorized => {
            HttpAuthError::status(StatusCode::UNAUTHORIZED, "Sign-in required")
        }
    })?;
    let session_token = token.to_string();
    let authenticated = database(state.db.clone(), move |database| {
        database.authenticated_mfa_session(&session_token)
    })
    .await?
    .ok_or_else(|| {
        HttpAuthError::with_kind(
            StatusCode::UNAUTHORIZED,
            "Session is no longer authorized",
            HttpAuthErrorKind::SessionRevoked,
        )
    })?;
    match authenticated {
        crate::db::MfaSessionAuthentication::Authenticated(authenticated) => Ok(authenticated),
        crate::db::MfaSessionAuthentication::MfaRequired => Err(HttpAuthError::status(
            StatusCode::FORBIDDEN,
            "MFA verification required",
        )),
    }
}

pub fn csrf(session: &Session, value: &str) -> Result<()> {
    if !auth::constant_time_eq(&session.csrf_token, value) {
        return Err(HttpAuthError::status(
            StatusCode::FORBIDDEN,
            "Invalid CSRF token",
        ));
    }
    Ok(())
}

pub fn csrf_header(session: &Session, headers: &HeaderMap) -> Result<()> {
    let value = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| HttpAuthError::status(StatusCode::FORBIDDEN, "CSRF token missing"))?;
    csrf(session, value)
}

pub fn make_session_cookie(state: &AppState, token: &str) -> String {
    let name = session_cookie_name(state);
    format!(
        "{name}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={};{}",
        state.config.security.session_hours * 3600,
        if state.config.security.secure_cookie {
            " Secure"
        } else {
            ""
        }
    )
}

pub fn clear_session_cookie(state: &AppState) -> String {
    let name = session_cookie_name(state);
    format!(
        "{name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0;{}",
        if state.config.security.secure_cookie {
            " Secure"
        } else {
            ""
        }
    )
}

pub fn redirect_with_cookie(to: &str, value: &str) -> Result<Response> {
    let mut response = Redirect::to(to).into_response();
    let value = HeaderValue::from_str(value).map_err(internal)?;
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

/// Returns the CSRF token bound to the current password-unlock cookie. Passwordless
/// capability URLs do not use ambient cookie authority and therefore return `None`.
pub async fn share_unlock_csrf(
    state: &AppState,
    headers: &HeaderMap,
    share: &Share,
) -> Result<Option<String>> {
    if share.password_hash.is_none() {
        return Ok(None);
    }
    let name = unlock_cookie_name(share.id);
    let Some(token) = named_cookie(headers, &name) else {
        return Ok(None);
    };
    let token = token.to_string();
    let share_id = share.id;
    database(state.db.clone(), move |db| {
        db.unlock_session_csrf(&token, share_id)
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
        TransferCookieScope::Api => format!("/api/v2/public/shares/{}", share.token),
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
        UnlockCookieScope::Api => format!("/api/v2/public/shares/{}", share.token),
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
    fn client_activity_map_is_normalized_after_poisoning() {
        let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let zero_peer = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let counts = Arc::new(Mutex::new(HashMap::from([
            (peer, usize::MAX),
            (zero_peer, 0usize),
        ])));
        let poisoned = counts.clone();
        assert!(std::panic::catch_unwind(move || {
            let _guard = poisoned.lock().unwrap();
            panic!("inject client activity map poisoning");
        })
        .is_err());

        let recovered = client_activity_counts(&counts, 4);
        assert_eq!(recovered.get(&peer), Some(&4));
        assert!(!recovered.contains_key(&zero_peer));
        drop(recovered);
        assert!(!counts.is_poisoned());
    }

    #[test]
    fn invalid_response_cookie_is_reported_without_panicking() {
        let error = redirect_with_cookie("/", "cookie=value\r\nbad=value")
            .expect_err("invalid cookie header must be rejected");
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn duplicate_named_cookies_are_rejected_across_cookie_headers() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("other=x; session=one"),
        );
        headers.append(header::COOKIE, HeaderValue::from_static("session=two"));
        assert_eq!(named_cookie(&headers, "session"), None);

        let mut single = HeaderMap::new();
        single.insert(
            header::COOKIE,
            HeaderValue::from_static("session=one; other=x"),
        );
        assert_eq!(named_cookie(&single, "session"), Some("one"));
    }

    #[test]
    fn service_token_authorization_parser_is_exact_and_canonical() {
        let encoded = URL_SAFE_NO_PAD.encode([7u8; 32]);
        let token = format!("{SERVICE_TOKEN_PREFIX}{encoded}");
        let authorization = format!("Bearer {token}");
        assert_eq!(strict_service_token(&authorization), Some(token.as_str()));
        assert_eq!(
            strict_service_token(&format!("bEaReR {token}")),
            Some(token.as_str())
        );

        for invalid in [
            format!("Bearer  {token}"),
            format!("Bearer {token}="),
            format!("Bearer {SERVICE_TOKEN_PREFIX}{}", &encoded[..42]),
            format!("Bearer {SERVICE_TOKEN_PREFIX}{}!", &encoded[..42]),
        ] {
            assert_eq!(strict_service_token(&invalid), None, "{invalid}");
        }
    }

    #[test]
    fn duplicate_authorization_headers_are_invalid() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer one"),
        );
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer two"),
        );
        assert!(matches!(
            exact_authorization(&headers),
            ExactHeader::Ambiguous
        ));

        let mut joined = HeaderMap::new();
        joined.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer one, Bearer two"),
        );
        assert!(matches!(
            exact_authorization(&joined),
            ExactHeader::Ambiguous
        ));
    }

    #[tokio::test]
    async fn ordinary_database_busy_and_locked_errors_are_retryable_capacity_failures() {
        fn sqlite_capacity_error(code: i32) -> rusqlite::Error {
            rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None)
        }

        for code in [
            rusqlite::ffi::SQLITE_BUSY,
            rusqlite::ffi::SQLITE_BUSY_TIMEOUT,
            rusqlite::ffi::SQLITE_LOCKED,
            rusqlite::ffi::SQLITE_LOCKED_SHAREDCACHE,
        ] {
            assert!(crate::db::is_sqlite_busy_or_locked(&sqlite_capacity_error(
                code
            )));
            let mapped = database(Database::open(":memory:").unwrap(), move |_| {
                Err::<(), _>(sqlite_capacity_error(code))
            })
            .await
            .unwrap_err();
            assert_eq!(mapped.status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(mapped.kind, HttpAuthErrorKind::CapacityUnavailable);
            assert_eq!(mapped.message, DATABASE_BUSY_MESSAGE);

            let response = crate::web::AppError::from(mapped).into_response();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "1");

            let required_mapped =
                required_database(Database::open(":memory:").unwrap(), move |_| {
                    Err::<(), _>(sqlite_capacity_error(code))
                })
                .await
                .unwrap_err();
            assert_eq!(required_mapped.status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(required_mapped.kind, HttpAuthErrorKind::CapacityUnavailable);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn security_mutation_inline_audit_survives_cancelled_database_await() {
        let db = Database::open(":memory:").unwrap();
        db.create_admin("admin", "old-hash", "secret").unwrap();
        let operation_database = db.clone();
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let (finished_sender, finished_receiver) = tokio::sync::oneshot::channel();

        let request = tokio::spawn(async move {
            required_database(operation_database, move |database| {
                let _ = started_sender.send(());
                release_receiver.recv().unwrap();
                assert!(database.reset_admin_password_and_audit(
                    1,
                    "new-hash",
                    &AuditContext::new("admin", None),
                )?);
                let _ = finished_sender.send(());
                Ok(())
            })
            .await
        });

        started_receiver.await.unwrap();
        request.abort();
        release_sender.send(()).unwrap();
        finished_receiver.await.unwrap();
        let _ = request.await;

        assert_eq!(
            db.admin("admin").unwrap().unwrap().password_hash,
            "new-hash"
        );
        assert_eq!(db.count_audit(Some("admin_password_reset")).unwrap(), 1);
    }
}
