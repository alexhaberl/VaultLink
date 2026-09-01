use axum::{
    extract::{Path as AxPath, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    auth,
    db::{valid_service_token_name, AuditContext, ServiceToken, ServiceTokenCreationOutcome},
    http_auth::{
        csrf_header, database, enabled_audit_client_ip, required_database, session,
        verify_password_admitted, MissingSession, SERVICE_TOKEN_PREFIX,
    },
    sensitive::SecretString,
    AppState,
};

use super::{ApiError, ApiResult};

const SERVICE_TOKEN_SCOPE: &str = "monitoring:read";

#[derive(Serialize)]
struct ServiceTokenResponse {
    id: i64,
    name: String,
    created_by: String,
    scope: &'static str,
    created_at: String,
    expires_at: Option<String>,
    last_used_at: Option<String>,
    status: &'static str,
}

impl ServiceTokenResponse {
    fn from_database(token: ServiceToken, now: DateTime<Utc>) -> ApiResult<Self> {
        let expired = token
            .expires_at
            .as_deref()
            .map(DateTime::parse_from_rfc3339)
            .transpose()
            .map_err(ApiError::internal)?
            .is_some_and(|expires_at| expires_at <= now);
        Ok(Self {
            id: token.id,
            name: token.name,
            created_by: token.created_by_username,
            scope: SERVICE_TOKEN_SCOPE,
            created_at: token.created_at,
            expires_at: token.expires_at,
            last_used_at: token.last_used_at,
            status: if expired { "expired" } else { "active" },
        })
    }
}

#[derive(Serialize)]
pub(super) struct ServiceTokenListResponse {
    service_tokens: Vec<ServiceTokenResponse>,
}

pub(super) async fn list_service_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ServiceTokenListResponse>> {
    session(&state, &headers, true, MissingSession::Unauthorized).await?;
    let tokens = database(state.db.clone(), |database| database.list_service_tokens()).await?;
    let now = Utc::now();
    let service_tokens = tokens
        .into_iter()
        .map(|token| ServiceTokenResponse::from_database(token, now))
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(Json(ServiceTokenListResponse { service_tokens }))
}

#[derive(Deserialize)]
pub(super) struct CreateServiceTokenRequest {
    name: String,
    expires_at: Option<DateTime<Utc>>,
    current_password: SecretString,
}

#[derive(Serialize)]
struct CreatedServiceTokenResponse {
    #[serde(flatten)]
    metadata: ServiceTokenResponse,
    token: String,
}

pub(super) async fn create_service_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateServiceTokenRequest>,
) -> ApiResult<Response> {
    let (session_token, session_data) =
        session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;

    let CreateServiceTokenRequest {
        name,
        expires_at,
        current_password,
    } = request;
    if !valid_service_token_name(&name)
        || expires_at.is_some_and(|expires_at| expires_at <= Utc::now())
    {
        return Err(ApiError::bad_request("Invalid service token settings"));
    }

    let limiter_key = format!("service-token-create:{}", session_data.admin_id);
    if !state.limiter.check_and_record_attempt(&limiter_key) {
        return Err(ApiError::rate_limited("Too many password attempts", 60));
    }

    let username = session_data.username.clone();
    let admin = database(state.db.clone(), move |database| database.admin(&username))
        .await?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Invalid credentials",
            )
        })?;
    let expected_password_hash = admin.password_hash;
    if current_password.expose_secret().len() > auth::MAX_PASSWORD_BYTES
        || !verify_password_admitted(
            &state,
            Some(expected_password_hash.clone()),
            current_password,
        )
        .await?
    {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Invalid credentials",
        ));
    }

    let generated = SecretString::from(format!("{SERVICE_TOKEN_PREFIX}{}", auth::random_token(32)));
    let response_token = generated.duplicate_for_one_time_response();
    let admin_id = session_data.admin_id;
    let audit_context = AuditContext::new(
        session_data.username.clone(),
        enabled_audit_client_ip(&state),
    );
    let outcome = required_database(state.db.clone(), move |database| {
        database.create_service_token_for_verified_admin_and_audit(
            &session_token,
            admin_id,
            &expected_password_hash,
            &name,
            generated.expose_secret(),
            expires_at,
            &audit_context,
        )
    })
    .await?;
    let created = match outcome {
        ServiceTokenCreationOutcome::Created(token) => token,
        ServiceTokenCreationOutcome::ReauthenticationRejected => {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Invalid credentials",
            ));
        }
        ServiceTokenCreationOutcome::CapacityReached => {
            return Err(ApiError::conflict("Service token limit reached"));
        }
        ServiceTokenCreationOutcome::NameConflict => {
            return Err(ApiError::conflict("Service token name already exists"));
        }
    };

    let response = CreatedServiceTokenResponse {
        metadata: ServiceTokenResponse::from_database(created, Utc::now())?,
        token: response_token.into_one_time_response(),
    };
    let mut response = (StatusCode::CREATED, Json(response)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

pub(super) async fn revoke_service_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
) -> ApiResult<StatusCode> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    if id <= 0 {
        return Err(ApiError::not_found("Service token not found"));
    }
    let audit_context = AuditContext::new(session_data.username, enabled_audit_client_ip(&state));
    let revoked = required_database(state.db.clone(), move |database| {
        database.revoke_service_token_and_audit(id, &audit_context)
    })
    .await?;
    if !revoked {
        return Err(ApiError::not_found("Service token not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}
