use axum::{
    extract::{Path as AxPath, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    db::{AdminDeactivationOutcome, AdminSummary, AuditContext},
    http_auth::{
        csrf_header, database, enabled_audit_client_ip, hash_password_admitted, mfa_session,
        required_database, session, MissingSession,
    },
    sensitive::SecretString,
    services::admin::{AdminActivationResult, AdminService, AdminServiceError, CreateAdminCommand},
    AppState,
};

use super::{session_bound, ApiError, ApiResult, PasswordRequest, SimpleResponse};

#[derive(Serialize)]
pub(super) struct AdminResponse {
    id: i64,
    username: String,
    created_at: String,
    active: bool,
}

fn admin_response(admin: AdminSummary) -> AdminResponse {
    AdminResponse {
        id: admin.id,
        username: admin.username,
        created_at: admin.created_at,
        active: admin.active,
    }
}

pub(super) async fn list_admins(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<AdminResponse>>> {
    session(&state, &headers, true, MissingSession::Unauthorized).await?;
    let admins = database(state.db.clone(), |db| db.list_admins()).await?;
    Ok(Json(admins.into_iter().map(admin_response).collect()))
}

#[derive(Deserialize)]
pub(super) struct CreateAdminRequest {
    username: String,
    password: SecretString,
}

#[derive(Serialize)]
pub(super) struct CreatedAdminResponse {
    id: i64,
    username: String,
    totp_secret: String,
    otpauth_url: String,
}

pub(super) async fn create_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateAdminRequest>,
) -> ApiResult<Json<CreatedAdminResponse>> {
    let authenticated = mfa_session(&state, &headers, MissingSession::Unauthorized).await?;
    csrf_header(&authenticated, &headers)?;
    let service = AdminService::new(state.db.clone());
    let validated = service
        .prepare_create(CreateAdminCommand {
            username: request.username,
            password: request.password,
            confirmation: None,
        })
        .map_err(admin_validation_error)?;
    let (prepared, password) = validated.into_hash_input();
    let password_hash = hash_password_admitted(&state, password).await?;
    let proof = authenticated.proof().clone();
    let audit_actor = authenticated.username.clone();
    let audit_client_ip = enabled_audit_client_ip(&state);
    let audit_context = AuditContext::new(audit_actor, audit_client_ip);
    let login_limiter = state.admin_login_limiter.clone();
    let created = session_bound(
        required_database(state.db.clone(), move |_| {
            let outcome = service
                .create_for_mfa_session(
                    &proof,
                    &prepared,
                    &password_hash,
                    &audit_context,
                    |active_admins| login_limiter.publish_active_admins(active_admins),
                )
                .map_err(admin_database_error)?;
            match outcome {
                crate::db::SessionBound::Authorized((created, publication)) => {
                    drop(publication);
                    Ok(crate::db::SessionBound::Authorized(created))
                }
                crate::db::SessionBound::SessionUnavailable => {
                    Ok(crate::db::SessionBound::SessionUnavailable)
                }
            }
        })
        .await?,
    )?;
    let response_secret = created.totp_secret.into_one_time_response();
    let otpauth_url = format!(
        "otpauth://totp/VaultLink:{}?secret={}&issuer=VaultLink",
        created.summary.username, response_secret
    );
    Ok(Json(CreatedAdminResponse {
        id: created.summary.id,
        username: created.summary.username,
        totp_secret: response_secret,
        otpauth_url,
    }))
}

pub(super) async fn activate_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<SimpleResponse>> {
    set_admin_active_api(state, headers, id, true).await
}

pub(super) async fn deactivate_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<SimpleResponse>> {
    set_admin_active_api(state, headers, id, false).await
}

async fn set_admin_active_api(
    state: AppState,
    headers: HeaderMap,
    id: i64,
    active: bool,
) -> ApiResult<Json<SimpleResponse>> {
    let authenticated = mfa_session(&state, &headers, MissingSession::Unauthorized).await?;
    csrf_header(&authenticated, &headers)?;
    if !active && id == authenticated.admin_id {
        return Err(ApiError::bad_request(
            "You cannot deactivate your own administrator account",
        ));
    }
    let audit_actor = authenticated.username.clone();
    let audit_client_ip = enabled_audit_client_ip(&state);
    let audit_context = AuditContext::new(audit_actor, audit_client_ip);
    let service = AdminService::new(state.db.clone());
    let proof = authenticated.proof().clone();
    let login_limiter = state.admin_login_limiter.clone();
    let outcome = session_bound(
        required_database(state.db.clone(), move |_| {
            let outcome = service
                .set_active_for_mfa_session(&proof, id, active, &audit_context, |active_admins| {
                    login_limiter.publish_active_admins(active_admins)
                })
                .map_err(admin_database_error)?;
            match outcome {
                crate::db::SessionBound::Authorized((outcome, publication)) => {
                    drop(publication);
                    Ok(crate::db::SessionBound::Authorized(outcome))
                }
                crate::db::SessionBound::SessionUnavailable => {
                    Ok(crate::db::SessionBound::SessionUnavailable)
                }
            }
        })
        .await?,
    )?;
    match outcome {
        AdminActivationResult::Changed => {}
        AdminActivationResult::NotFound => {
            return Err(ApiError::not_found("Administrator not found"));
        }
        AdminActivationResult::Deactivation(outcome) => match outcome {
            AdminDeactivationOutcome::Deactivated | AdminDeactivationOutcome::AlreadyInactive => {}
            AdminDeactivationOutcome::LastActive => {
                return Err(ApiError::bad_request(
                    "The last active administrator cannot be deactivated",
                ));
            }
            AdminDeactivationOutcome::NotFound => {
                return Err(ApiError::not_found("Administrator not found"));
            }
        },
    }
    Ok(Json(SimpleResponse { ok: true }))
}

pub(super) async fn reset_admin_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Json(request): Json<PasswordRequest>,
) -> ApiResult<Json<SimpleResponse>> {
    let authenticated = mfa_session(&state, &headers, MissingSession::Unauthorized).await?;
    csrf_header(&authenticated, &headers)?;
    if id == authenticated.admin_id {
        return Err(ApiError::bad_request(
            "Change your own password through My account",
        ));
    }
    let service = AdminService::new(state.db.clone());
    let password = service
        .prepare_password(request.password, None)
        .map_err(admin_validation_error)?;
    let hash = hash_password_admitted(&state, password).await?;
    let audit_actor = authenticated.username.clone();
    let audit_client_ip = enabled_audit_client_ip(&state);
    let audit_context = AuditContext::new(audit_actor, audit_client_ip);
    let proof = authenticated.proof().clone();
    let changed = session_bound(
        required_database(state.db.clone(), move |_| {
            service
                .reset_password_for_mfa_session(&proof, id, &hash, &audit_context)
                .map_err(admin_database_error)
        })
        .await?,
    )?;
    if !changed {
        return Err(ApiError::not_found("Administrator not found"));
    }
    Ok(Json(SimpleResponse { ok: true }))
}

pub(super) async fn reset_admin_totp(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<CreatedAdminResponse>> {
    let authenticated = mfa_session(&state, &headers, MissingSession::Unauthorized).await?;
    csrf_header(&authenticated, &headers)?;
    if id == authenticated.admin_id {
        return Err(ApiError::bad_request(
            "Change your own MFA through My account",
        ));
    }
    let audit_actor = authenticated.username.clone();
    let audit_client_ip = enabled_audit_client_ip(&state);
    let audit_context = AuditContext::new(audit_actor, audit_client_ip);
    let service = AdminService::new(state.db.clone());
    let proof = authenticated.proof().clone();
    let security_settings_guard = state.security_settings_mutation.clone().lock_owned().await;
    let reset = session_bound(
        required_database(state.db.clone(), move |_| {
            // A TOTP reset removes every WebAuthn credential. Keep that
            // credential-count change ordered with runtime/settings updates.
            let _security_settings_guard = security_settings_guard;
            service
                .reset_totp_for_mfa_session(&proof, id, &audit_context)
                .map_err(admin_database_error)
        })
        .await?,
    )?
    .ok_or_else(|| ApiError::not_found("Administrator not found"))?;
    let username = reset.username;
    let response_secret = reset.totp_secret.into_one_time_response();
    let otpauth_url =
        format!("otpauth://totp/VaultLink:{username}?secret={response_secret}&issuer=VaultLink");
    Ok(Json(CreatedAdminResponse {
        id,
        username,
        totp_secret: response_secret,
        otpauth_url,
    }))
}

fn admin_validation_error(error: AdminServiceError) -> ApiError {
    match error {
        AdminServiceError::InvalidUsername => {
            ApiError::bad_request("Invalid administrator username")
        }
        AdminServiceError::InvalidPassword => {
            ApiError::bad_request("Invalid administrator password")
        }
        AdminServiceError::PasswordConfirmationMismatch => {
            ApiError::bad_request("Passwords do not match")
        }
        AdminServiceError::Database(error) => ApiError::internal(error),
    }
}

fn admin_database_error(error: AdminServiceError) -> rusqlite::Error {
    error
        .into_database_error()
        .unwrap_or(rusqlite::Error::InvalidQuery)
}
