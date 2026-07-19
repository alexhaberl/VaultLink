use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    auth,
    http_auth::{
        admin_login_attempt_admitted, audit_security_observation as audit_observation,
        clear_session_cookie, csrf_header, enabled_audit_client_ip, make_session_cookie,
        password_login_admitted, required_database, session, MissingSession,
    },
    sensitive::SecretString,
    services::auth::{
        AuthService, PasswordLoginCommand, PasswordLoginOutcome, TotpLoginCommand, TotpLoginOutcome,
    },
    AppState,
};

use super::{ApiError, ApiResult, SimpleResponse};

#[cfg(test)]
pub(super) use crate::auth::{hash_password, new_totp_secret, totp_code};

#[derive(Deserialize)]
pub(super) struct LoginRequest {
    username: String,
    password: SecretString,
}

#[derive(Serialize)]
struct LoginResponse {
    mfa_required: bool,
    csrf_token: String,
}

pub(super) async fn login(
    State(state): State<AppState>,
    ConnectInfo(_peer): ConnectInfo<SocketAddr>,
    _headers: HeaderMap,
    Json(form): Json<LoginRequest>,
) -> ApiResult<Response> {
    if !admin_login_attempt_admitted(&state, &form.username) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Too many sign-in attempts",
        ));
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
            csrf_token: csrf.clone(),
            expires_at: expires,
            audit_client_ip: enabled_audit_client_ip(&state),
        },
    )
    .await?;
    if outcome == PasswordLoginOutcome::InvalidCredentials {
        audit_observation(&state, attempted_username, "login_failed", None, None).await;
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Invalid credentials",
        ));
    }
    // Successful password checks consume the same fixed-window budget so valid
    // compromised credentials cannot create unbounded sessions/audit traffic.
    let mut response = Json(LoginResponse {
        mfa_required: true,
        csrf_token: csrf,
    })
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&make_session_cookie(&state, &token)).map_err(ApiError::internal)?,
    );
    Ok(response)
}

#[derive(Deserialize)]
pub(super) struct MfaRequest {
    code: SecretString,
}

pub(super) async fn mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(form): Json<MfaRequest>,
) -> ApiResult<Response> {
    let (token, session_data) =
        session(&state, &headers, false, MissingSession::Unauthorized).await?;
    if session_data.mfa_verified {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "mfa_already_verified",
            "MFA has already been verified",
        ));
    }
    csrf_header(&session_data, &headers)?;
    let key = format!("mfa:{}", session_data.username.to_lowercase());
    if !state.limiter.check_and_record_attempt(&key) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Too many MFA attempts",
        ));
    }
    let new_token = auth::random_token(32);
    let new_csrf = auth::random_token(24);
    let command = TotpLoginCommand {
        username: session_data.username.clone(),
        admin_id: session_data.admin_id,
        current_session_token: token,
        code: form.code,
        rotated_session_token: new_token.clone(),
        rotated_csrf_token: new_csrf.clone(),
        audit_client_ip: enabled_audit_client_ip(&state),
    };
    let outcome = required_database(state.db.clone(), move |db| {
        AuthService::new(db).login_with_totp(command)
    })
    .await?;
    match outcome {
        TotpLoginOutcome::Created => {}
        TotpLoginOutcome::InvalidCode => {
            audit_observation(&state, session_data.username, "mfa_failed", None, None).await;
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "invalid_mfa",
                "Invalid MFA code",
            ));
        }
        TotpLoginOutcome::ReplayedOrStale => {
            audit_observation(&state, session_data.username, "mfa_replayed", None, None).await;
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "invalid_mfa",
                "Invalid MFA code",
            ));
        }
    }
    state.limiter.success(&key);
    let mut response = Json(MeResponse {
        authenticated: true,
        admin_id: session_data.admin_id,
        username: session_data.username,
        mfa_verified: true,
        csrf_token: new_csrf,
    })
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&make_session_cookie(&state, &new_token))
            .map_err(ApiError::internal)?,
    );
    Ok(response)
}

pub(super) async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let (token, session_data) =
        session(&state, &headers, false, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    let audit_actor = session_data.username;
    let audit_client_ip = enabled_audit_client_ip(&state);
    required_database(state.db.clone(), move |db| {
        AuthService::new(db).logout(&token, audit_actor, audit_client_ip)
    })
    .await?;
    let mut response = Json(SimpleResponse { ok: true }).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_session_cookie(&state)).map_err(ApiError::internal)?,
    );
    Ok(response)
}

#[derive(Serialize)]
pub(super) struct MeResponse {
    authenticated: bool,
    admin_id: i64,
    username: String,
    mfa_verified: bool,
    csrf_token: String,
}

pub(super) async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<MeResponse>> {
    let (_, session_data) = session(&state, &headers, false, MissingSession::Unauthorized).await?;
    Ok(Json(MeResponse {
        authenticated: true,
        admin_id: session_data.admin_id,
        username: session_data.username,
        mfa_verified: session_data.mfa_verified,
        csrf_token: session_data.csrf_token,
    }))
}
