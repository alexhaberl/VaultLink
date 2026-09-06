use super::{AppError, Result};
use crate::{
    db::AuditContext,
    http_auth::{
        csrf, enabled_audit_client_ip, mfa_session, required_mfa_audit_database, session,
        MissingSession,
    },
    updates::{self, Operation, Request, Status},
    SettingsRouteState,
};
use axum::{
    extract::{Form, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;

pub(super) async fn status(
    State(state): State<SettingsRouteState>,
    headers: HeaderMap,
) -> Result<Json<Status>> {
    session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    Ok(Json(
        updates::exchange(&Request::Status {})
            .await
            .unwrap_or_else(|_| Status::disconnected()),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UpdateForm {
    csrf: String,
    operation: String,
    version: Option<String>,
    enabled: Option<bool>,
}

pub(super) async fn submit(
    State(state): State<SettingsRouteState>,
    headers: HeaderMap,
    Form(form): Form<UpdateForm>,
) -> Result<Json<Status>> {
    let authorization = mfa_session(&state, &headers, MissingSession::RedirectToLogin).await?;
    csrf(&authorization, &form.csrf)?;
    let action = match (form.operation.as_str(), form.version, form.enabled) {
        ("check", None, None) => Operation::Check {},
        ("install", Some(version), None) => Operation::Install { version },
        ("automatic", None, Some(enabled)) => Operation::Automatic { enabled },
        _ => {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "Invalid update operation",
            ))
        }
    };
    if !action.valid() {
        return Err(AppError(StatusCode::BAD_REQUEST, "Invalid update version"));
    }
    let request_id = crate::auth::random_token(24);
    let detail = format!(
        "request_id={request_id} operation={}",
        serde_json::to_string(&action)
            .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "Update request failed"))?
    );
    let audit_ip = enabled_audit_client_ip(&state);
    let authorized = required_mfa_audit_database(
        state.db().clone(),
        authorization,
        move |db, session, proof| {
            db.authorize_software_update(
                &proof,
                &AuditContext::new(session.username, audit_ip),
                detail,
            )
        },
    )
    .await?;
    super::session_bound(authorized)?;
    let result = updates::exchange(&Request::Submit { request_id, action })
        .await
        .map_err(|_| {
            AppError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Update controller unavailable; refresh status before retrying",
            )
        })?;
    Ok(Json(result))
}
