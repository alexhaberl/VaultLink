use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Path as AxPath, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    auth,
    db::{AuditAction, AuditContext, Permission},
    http_auth::{
        audit_observation, current_client_limit_key, enabled_audit_client_ip, make_unlock_cookie,
        required_database, runtime_settings, share_is_unlocked, verify_password_admitted,
        UnlockCookieScope,
    },
    sensitive::SecretString,
    AppState,
};

use super::{common::get_share, ApiError, ApiResult};

#[derive(Serialize)]
pub(super) struct PublicShareResponse {
    locked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_directory: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    permission: Option<Permission>,
    #[serde(skip_serializing_if = "Option::is_none")]
    active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<Option<DateTime<Utc>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    download_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_downloads: Option<Option<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_upload_size: Option<Option<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_upload_total_size: Option<Option<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_upload_files: Option<Option<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uploaded_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uploaded_files: Option<u64>,
}

pub(super) async fn public_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
) -> ApiResult<Json<PublicShareResponse>> {
    let share = get_share(&state, &token).await?;
    let unlocked = share_is_unlocked(&state, &headers, &share).await?;
    if !unlocked {
        return Ok(Json(PublicShareResponse {
            locked: true,
            token: None,
            path: None,
            is_directory: None,
            permission: None,
            active: None,
            expires_at: None,
            download_count: None,
            max_downloads: None,
            max_upload_size: None,
            max_upload_total_size: None,
            max_upload_files: None,
            uploaded_bytes: None,
            uploaded_files: None,
        }));
    }
    let public_path = if share.permission == Permission::UploadOnly {
        String::new()
    } else {
        share.relative_path.clone()
    };
    Ok(Json(PublicShareResponse {
        locked: false,
        token: Some(share.token),
        path: Some(public_path),
        is_directory: Some(share.is_directory),
        permission: Some(share.permission),
        active: Some(share.active),
        expires_at: Some(share.expires_at),
        download_count: Some(share.download_count),
        max_downloads: Some(share.max_downloads),
        max_upload_size: Some(share.max_upload_size),
        max_upload_total_size: Some(share.max_upload_total_size),
        max_upload_files: Some(share.max_upload_files),
        uploaded_bytes: Some(share.uploaded_bytes),
        uploaded_files: Some(share.uploaded_files),
    }))
}

#[derive(Deserialize)]
pub(super) struct UnlockRequest {
    password: SecretString,
}

#[derive(Serialize)]
struct UnlockResponse {
    ok: bool,
    csrf_token: Option<String>,
}

pub(super) async fn unlock_share(
    State(state): State<AppState>,
    ConnectInfo(_peer): ConnectInfo<SocketAddr>,
    _headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Json(request): Json<UnlockRequest>,
) -> ApiResult<Response> {
    let share = get_share(&state, &token).await?;
    let Some(hash) = share.password_hash.clone() else {
        return Ok(Json(UnlockResponse {
            ok: true,
            csrf_token: None,
        })
        .into_response());
    };
    let expected_password_hash = hash.clone();
    let expected_upload_policy_epoch = share.upload_policy_epoch;
    let ip = current_client_limit_key();
    let global_key = format!("share-unlock-ip:{ip}");
    let share_key = format!("share-unlock:{}:{ip}", share.id);
    if !state
        .share_limiter
        .check_and_record_attempts(&[&global_key, &share_key])
    {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Too many password attempts",
        ));
    }
    let password = request.password;
    if password.expose_secret().len() > auth::MAX_PASSWORD_BYTES {
        audit_observation(
            &state,
            "public".into(),
            AuditAction::ShareUnlockFailed,
            Some(share.id.to_string()),
            None,
        )
        .await;
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_share_password",
            "Invalid password",
        ));
    }
    let valid = verify_password_admitted(&state, Some(hash), password).await?;
    if !valid {
        audit_observation(
            &state,
            "public".into(),
            AuditAction::ShareUnlockFailed,
            Some(share.id.to_string()),
            None,
        )
        .await;
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_share_password",
            "Invalid password",
        ));
    }
    // Successful unlocks stay inside the fixed-window budget as well.
    let unlock_token = auth::random_token(32);
    let unlock_csrf = auth::random_token(24);
    let share_id = share.id;
    let expires = Utc::now() + Duration::minutes(runtime_settings(&state).share_unlock_minutes);
    let token_for_db = unlock_token.clone();
    let csrf_for_db = unlock_csrf.clone();
    let audit_client_ip = enabled_audit_client_ip(&state);
    let audit_context = AuditContext::new("public", audit_client_ip);
    let created = required_database(state.db.clone(), move |db| {
        db.create_unlock_session_for_verified_password_and_audit(
            &token_for_db,
            share_id,
            &expected_password_hash,
            expected_upload_policy_epoch,
            &csrf_for_db,
            expires,
            &audit_context,
        )
    })
    .await?;
    if !created {
        audit_observation(
            &state,
            "public".into(),
            AuditAction::ShareUnlockFailed,
            Some(share.id.to_string()),
            None,
        )
        .await;
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_share_password",
            "Invalid password",
        ));
    }
    let mut response = Json(UnlockResponse {
        ok: true,
        csrf_token: Some(unlock_csrf),
    })
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&make_unlock_cookie(
            &state,
            &share,
            &unlock_token,
            UnlockCookieScope::Api,
        ))
        .map_err(ApiError::internal)?,
    );
    Ok(response)
}
