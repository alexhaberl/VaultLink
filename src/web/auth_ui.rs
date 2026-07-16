use std::net::SocketAddr;

use askama::Template;
use axum::{
    extract::{ConnectInfo, Form, Json, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
};
use chrono::{Duration, Utc};
use serde::Deserialize;

use super::{
    common::{decode_security_keys, internal, webauthn_start_response, CsrfForm},
    templates::public_page,
    AppError, Result,
};
use crate::{
    auth,
    db::AuditContext,
    http_auth::{
        audit_observation, clear_session_cookie, csrf, database, enabled_audit_client_ip,
        make_session_cookie, password_login_admitted, redirect_with_cookie, required_database,
        session, MissingSession,
    },
    proxy,
    services::auth::{
        AuthService, PasswordLoginCommand, PasswordLoginOutcome, TotpLoginCommand, TotpLoginOutcome,
    },
    AppState,
};

#[derive(Template)]
#[template(path = "web/auth/login.html")]
struct LoginTemplate;

#[derive(Template)]
#[template(path = "web/auth/mfa.html")]
struct MfaTemplate<'a> {
    csrf: &'a str,
    security_key_enabled: bool,
    totp_enabled: bool,
}

pub(super) async fn login_page() -> Result<Html<String>> {
    Ok(Html(public_page("Login", &LoginTemplate)?))
}

#[derive(Deserialize)]
pub(super) struct LoginForm {
    username: String,
    password: crate::sensitive::SecretString,
}

pub(super) async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Result<Response> {
    let ip = proxy::client_limit_key(proxy::effective_client_ip(
        peer.ip(),
        &headers,
        &state.config,
    ));
    let ip_key = format!("ip:{ip}");
    if !auth::valid_admin_username(&form.username) {
        if !state.limiter.check_and_record_attempt(&ip_key) {
            return Err(AppError(
                StatusCode::TOO_MANY_REQUESTS,
                "Zu viele Anmeldeversuche",
            ));
        }
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    let key = format!("{}:{}", ip, form.username.to_lowercase());
    if !state.limiter.check_and_record_attempts(&[&key, &ip_key]) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele Anmeldeversuche",
        ));
    }
    if form.password.expose_secret().len() > auth::MAX_PASSWORD_BYTES {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    let attempted_username = form.username.clone();
    let token = auth::random_token(32);
    let csrf = auth::random_token(24);
    let expires = Utc::now() + Duration::hours(state.config.security.session_hours);
    let outcome = password_login_admitted(
        &state,
        PasswordLoginCommand {
            username: form.username,
            password: form.password,
            session_token: token.clone(),
            csrf_token: csrf,
            expires_at: expires,
            audit_client_ip: enabled_audit_client_ip(&state),
        },
    )
    .await?;
    if outcome == PasswordLoginOutcome::InvalidCredentials {
        audit_observation(&state, attempted_username, "login_failed", None, None).await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    // Successful password verifications remain in the fixed window as well. This
    // bounds Argon2 work, pre-MFA session creation and audit growth for valid but
    // compromised credentials.
    Ok(redirect_with_cookie(
        "/mfa",
        make_session_cookie(&state, &token),
    )?)
}

pub(super) async fn mfa_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Html<String>> {
    let (_, current_session) =
        session(&state, &headers, false, MissingSession::RedirectToLogin).await?;
    let admin_id = current_session.admin_id;
    let username = current_session.username.clone();
    let (security_key_count, totp_enabled) = database(state.db.clone(), move |db| {
        let security_key_count = db.admin_webauthn_credentials(admin_id)?.len();
        let admin = db
            .admin(&username)?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        Ok((security_key_count, admin.totp_enabled))
    })
    .await?;
    Ok(Html(public_page(
        "MFA",
        &MfaTemplate {
            csrf: &current_session.csrf_token,
            security_key_enabled: security_key_count >= 2,
            totp_enabled,
        },
    )?))
}

#[derive(Deserialize)]
pub(super) struct MfaForm {
    csrf: String,
    code: crate::sensitive::SecretString,
}

pub(super) async fn mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<MfaForm>,
) -> Result<Response> {
    let (token, s) = session(&state, &headers, false, MissingSession::RedirectToLogin).await?;
    csrf(&s, &form.csrf)?;
    let key = format!("mfa:{}", s.username.to_lowercase());
    if !state.limiter.check_and_record_attempt(&key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele MFA-Versuche",
        ));
    }
    let new_token = auth::random_token(32);
    let new_csrf = auth::random_token(24);
    let command = TotpLoginCommand {
        username: s.username.clone(),
        admin_id: s.admin_id,
        current_session_token: token,
        code: form.code,
        rotated_session_token: new_token.clone(),
        rotated_csrf_token: new_csrf,
        audit_client_ip: enabled_audit_client_ip(&state),
    };
    let outcome = required_database(state.db.clone(), move |db| {
        AuthService::new(db).login_with_totp(command)
    })
    .await?;
    match outcome {
        TotpLoginOutcome::Created => {}
        TotpLoginOutcome::InvalidCode => {
            audit_observation(&state, s.username, "mfa_failed", None, None).await;
            return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültiger MFA-Code"));
        }
        TotpLoginOutcome::ReplayedOrStale => {
            audit_observation(&state, s.username, "mfa_replayed", None, None).await;
            return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültiger MFA-Code"));
        }
    }
    state.limiter.success(&key);
    Ok(redirect_with_cookie(
        "/admin",
        make_session_cookie(&state, &new_token),
    )?)
}

pub(super) async fn start_security_key_authentication(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CsrfForm>,
) -> Result<Response> {
    let (token, session) =
        session(&state, &headers, false, MissingSession::RedirectToLogin).await?;
    if session.mfa_verified {
        return Err(AppError(
            StatusCode::CONFLICT,
            "MFA wurde bereits bestätigt",
        ));
    }
    csrf(&session, &body.csrf)?;
    let start_key = format!("mfa-webauthn-start:{}", session.username.to_lowercase());
    if !state.limiter.check_and_record_attempt(&start_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele Sicherheitsschluessel-Anfragen",
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
    let webauthn = crate::http_auth::webauthn_service(&state)?;
    webauthn_start_response(webauthn.start_authentication(&token, admin_id, &keys))
}

#[derive(Deserialize)]
pub(super) struct SecurityKeyAuthenticationFinish {
    csrf: String,
    credential: webauthn_rs::prelude::PublicKeyCredential,
}

pub(super) async fn finish_security_key_authentication(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SecurityKeyAuthenticationFinish>,
) -> Result<Response> {
    let (token, session) =
        session(&state, &headers, false, MissingSession::RedirectToLogin).await?;
    if session.mfa_verified {
        return Err(AppError(
            StatusCode::CONFLICT,
            "MFA wurde bereits bestätigt",
        ));
    }
    csrf(&session, &body.csrf)?;
    let attempt_key = format!("mfa:{}", session.username.to_lowercase());
    if !state.limiter.check_and_record_attempt(&attempt_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele MFA-Versuche",
        ));
    }
    let admin_id = session.admin_id;
    let rows = database(state.db.clone(), move |db| {
        db.admin_webauthn_credentials(admin_id)
    })
    .await?;
    let mut keys = decode_security_keys(&rows)?;
    let webauthn = crate::http_auth::webauthn_service(&state)?;
    let index = webauthn
        .finish_authentication(&token, admin_id, &body.credential, &mut keys)
        .map_err(|_| AppError(StatusCode::UNAUTHORIZED, "Ungültiger Sicherheitsschlüssel"))?;
    let row = rows.get(index).ok_or_else(|| internal(()))?;
    let credential_id = row.id;
    let expected_credential_json = row.credential_json.clone();
    let credential_json = serde_json::to_string(&keys[index]).map_err(internal)?;
    let new_token = auth::random_token(32);
    let new_csrf = auth::random_token(24);
    let rotated_token = new_token.clone();
    let rotated_csrf = new_csrf.clone();
    let audit_context =
        AuditContext::new(session.username.clone(), enabled_audit_client_ip(&state));
    let completed = required_database(state.db.clone(), move |db| {
        db.complete_webauthn_mfa_and_audit(
            &token,
            &rotated_token,
            &rotated_csrf,
            credential_id,
            admin_id,
            &expected_credential_json,
            &credential_json,
            &audit_context,
        )
    })
    .await?;
    if !completed {
        return Err(AppError(
            StatusCode::CONFLICT,
            "Sicherheitsschlüssel wurde gleichzeitig geändert",
        ));
    }
    state.limiter.success(&attempt_key);
    let mut response = Json(serde_json::json!({"redirect":"/admin"})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&make_session_cookie(&state, &new_token)).map_err(internal)?,
    );
    Ok(response)
}

pub(super) async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    let (token, s) = session(&state, &headers, false, MissingSession::RedirectToLogin).await?;
    csrf(&s, &form.csrf)?;
    let actor = s.username;
    let client_ip = enabled_audit_client_ip(&state);
    required_database(state.db.clone(), move |db| {
        AuthService::new(db).logout(&token, actor, client_ip)
    })
    .await?;
    Ok(redirect_with_cookie(
        "/login",
        clear_session_cookie(&state),
    )?)
}
