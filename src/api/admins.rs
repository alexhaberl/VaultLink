use axum::{
    extract::{Path as AxPath, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    db::{AdminDeactivationOutcome, AdminSummary, AuditContext},
    http_auth::{
        csrf_header, database, enabled_audit_client_ip, hash_password_admitted, required_database,
        session, MissingSession,
    },
    sensitive::SecretString,
    services::admin::{AdminActivationResult, AdminService, AdminServiceError, CreateAdminCommand},
    AppState,
};

use super::{ApiError, ApiResult, PasswordRequest, SimpleResponse};

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
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
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
    let audit_actor = session_data.username;
    let audit_client_ip = enabled_audit_client_ip(&state);
    let audit_context = AuditContext::new(audit_actor, audit_client_ip);
    let created = required_database(state.db.clone(), move |_| {
        service
            .create(prepared, password_hash, &audit_context)
            .map_err(admin_database_error)
    })
    .await?;
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
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    if !active && id == session_data.admin_id {
        return Err(ApiError::bad_request(
            "Eigener Admin kann nicht stillgelegt werden",
        ));
    }
    let audit_actor = session_data.username;
    let audit_client_ip = enabled_audit_client_ip(&state);
    let audit_context = AuditContext::new(audit_actor, audit_client_ip);
    let service = AdminService::new(state.db.clone());
    let outcome = required_database(state.db.clone(), move |_| {
        service
            .set_active(id, active, &audit_context)
            .map_err(admin_database_error)
    })
    .await?;
    match outcome {
        AdminActivationResult::Changed => {}
        AdminActivationResult::NotFound => {
            return Err(ApiError::not_found("Admin nicht gefunden"));
        }
        AdminActivationResult::Deactivation(outcome) => match outcome {
            AdminDeactivationOutcome::Deactivated | AdminDeactivationOutcome::AlreadyInactive => {}
            AdminDeactivationOutcome::LastActive => {
                return Err(ApiError::bad_request(
                    "Letzter aktiver Admin kann nicht stillgelegt werden",
                ));
            }
            AdminDeactivationOutcome::NotFound => {
                return Err(ApiError::not_found("Admin nicht gefunden"));
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
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    if id == session_data.admin_id {
        return Err(ApiError::bad_request(
            "Das eigene Passwort wird über „Mein Konto“ geändert",
        ));
    }
    let service = AdminService::new(state.db.clone());
    let password = service
        .prepare_password(request.password, None)
        .map_err(admin_validation_error)?;
    let hash = hash_password_admitted(&state, password).await?;
    let audit_actor = session_data.username;
    let audit_client_ip = enabled_audit_client_ip(&state);
    let audit_context = AuditContext::new(audit_actor, audit_client_ip);
    let changed = required_database(state.db.clone(), move |_| {
        service
            .reset_password(id, &hash, &audit_context)
            .map_err(admin_database_error)
    })
    .await?;
    if !changed {
        return Err(ApiError::not_found("Admin nicht gefunden"));
    }
    Ok(Json(SimpleResponse { ok: true }))
}

pub(super) async fn reset_admin_totp(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<CreatedAdminResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    if id == session_data.admin_id {
        return Err(ApiError::bad_request(
            "Die eigene MFA wird über „Mein Konto“ geändert",
        ));
    }
    let audit_actor = session_data.username;
    let audit_client_ip = enabled_audit_client_ip(&state);
    let audit_context = AuditContext::new(audit_actor, audit_client_ip);
    let service = AdminService::new(state.db.clone());
    let reset = required_database(state.db.clone(), move |_| {
        service
            .reset_totp(id, &audit_context)
            .map_err(admin_database_error)
    })
    .await?
    .ok_or_else(|| ApiError::not_found("Admin nicht gefunden"))?;
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
        AdminServiceError::InvalidUsername => ApiError::bad_request("Ungültiger Benutzername"),
        AdminServiceError::InvalidPassword => ApiError::bad_request("Ungültiges Admin-Passwort"),
        AdminServiceError::PasswordConfirmationMismatch => {
            ApiError::bad_request("Passwörter stimmen nicht überein")
        }
        AdminServiceError::Database(error) => ApiError::internal(error),
    }
}

fn admin_database_error(error: AdminServiceError) -> rusqlite::Error {
    error
        .into_database_error()
        .unwrap_or(rusqlite::Error::InvalidQuery)
}
