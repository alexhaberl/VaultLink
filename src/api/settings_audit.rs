use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    db::{AuditClientIpDeletionOutcome, AuditContext, AuditEvent},
    http_auth::{
        commit_runtime_settings, csrf_header, database, enabled_audit_client_ip, required_database,
        runtime_settings, session, MissingSession,
    },
    runtime::RuntimeSettings,
    AppState,
};

use super::{ApiError, ApiResult};

#[derive(Serialize, Deserialize)]
pub(super) struct SettingsBody {
    pub(super) public_base_url: String,
    pub(super) max_upload_size: u64,
    pub(super) blocked_extensions: Vec<String>,
    pub(super) share_password_min_length: usize,
    pub(super) share_password_max_length: usize,
    pub(super) share_unlock_minutes: i64,
    pub(super) max_zip_size: u64,
    pub(super) max_zip_files: usize,
    pub(super) max_search_entries: usize,
    pub(super) max_search_results: usize,
    pub(super) max_preview_size: u64,
    pub(super) preview_extensions: Vec<String>,
    pub(super) image_preview_extensions: Vec<String>,
    pub(super) pdf_preview_enabled: bool,
    pub(super) max_media_preview_size: u64,
    #[serde(default)]
    pub(super) audit_client_ip_enabled: Option<bool>,
}

pub(super) fn settings_body(settings: RuntimeSettings) -> SettingsBody {
    SettingsBody {
        public_base_url: settings.public_base_url,
        max_upload_size: settings.max_upload_size,
        blocked_extensions: settings.blocked_extensions,
        share_password_min_length: settings.share_password_min_length,
        share_password_max_length: settings.share_password_max_length,
        share_unlock_minutes: settings.share_unlock_minutes,
        max_zip_size: settings.max_zip_size,
        max_zip_files: settings.max_zip_files,
        max_search_entries: settings.max_search_entries,
        max_search_results: settings.max_search_results,
        max_preview_size: settings.max_preview_size,
        preview_extensions: settings.preview_extensions,
        image_preview_extensions: settings.image_preview_extensions,
        pdf_preview_enabled: settings.pdf_preview_enabled,
        max_media_preview_size: settings.max_media_preview_size,
        audit_client_ip_enabled: Some(settings.audit_client_ip_enabled),
    }
}

pub(super) async fn get_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<SettingsBody>> {
    session(&state, &headers, true, MissingSession::Unauthorized).await?;
    Ok(Json(settings_body(runtime_settings(&state))))
}

pub(super) async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SettingsBody>,
) -> ApiResult<Json<SettingsBody>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    let current = runtime_settings(&state);
    let mut next = current.clone();
    let max_upload_size = body.max_upload_size.to_string();
    let blocked_extensions = body.blocked_extensions.join(",");
    let share_password_min_length = body.share_password_min_length.to_string();
    let share_password_max_length = body.share_password_max_length.to_string();
    let share_unlock_minutes = body.share_unlock_minutes.to_string();
    let max_zip_size = body.max_zip_size.to_string();
    let max_zip_files = body.max_zip_files.to_string();
    let max_search_entries = body.max_search_entries.to_string();
    let max_search_results = body.max_search_results.to_string();
    let max_preview_size = body.max_preview_size.to_string();
    let preview_extensions = body.preview_extensions.join(",");
    let image_preview_extensions = body.image_preview_extensions.join(",");
    let pdf_preview_enabled = body.pdf_preview_enabled.to_string();
    let max_media_preview_size = body.max_media_preview_size.to_string();
    let audit_client_ip_enabled = body
        .audit_client_ip_enabled
        .unwrap_or(next.audit_client_ip_enabled)
        .to_string();
    next.apply_many([
        ("public_base_url", body.public_base_url.as_str()),
        ("max_upload_size", max_upload_size.as_str()),
        ("blocked_extensions", blocked_extensions.as_str()),
        (
            "share_password_min_length",
            share_password_min_length.as_str(),
        ),
        (
            "share_password_max_length",
            share_password_max_length.as_str(),
        ),
        ("share_unlock_minutes", share_unlock_minutes.as_str()),
        ("max_zip_size", max_zip_size.as_str()),
        ("max_zip_files", max_zip_files.as_str()),
        ("max_search_entries", max_search_entries.as_str()),
        ("max_search_results", max_search_results.as_str()),
        ("max_preview_size", max_preview_size.as_str()),
        ("preview_extensions", preview_extensions.as_str()),
        (
            "image_preview_extensions",
            image_preview_extensions.as_str(),
        ),
        ("pdf_preview_enabled", pdf_preview_enabled.as_str()),
        ("max_media_preview_size", max_media_preview_size.as_str()),
        ("audit_client_ip_enabled", audit_client_ip_enabled.as_str()),
    ])
    .map_err(|_| ApiError::bad_request("Invalid runtime setting"))?;
    next.validate()
        .map_err(|_| ApiError::bad_request("Invalid setting"))?;
    let admin_id = session_data.admin_id;
    let changed_keys = current.changed_keys(&next).join(",");
    commit_runtime_settings(
        &state,
        next.clone(),
        admin_id,
        session_data.username,
        format!("changed_keys={changed_keys}"),
    )
    .await?;
    Ok(Json(settings_body(next)))
}

#[derive(Default, Deserialize)]
pub(super) struct AuditQuery {
    page: Option<usize>,
    action: Option<String>,
}

#[derive(Serialize)]
pub(super) struct AuditResponse {
    page: usize,
    has_next: bool,
    client_ip_enabled: bool,
    events: Vec<AuditEventResponse>,
}

#[derive(Serialize)]
struct AuditEventResponse {
    occurred_at: String,
    actor: String,
    action: String,
    object_id: Option<String>,
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_ip: Option<String>,
}

impl AuditEventResponse {
    fn from_event(value: AuditEvent, client_ip_enabled: bool) -> Self {
        Self {
            occurred_at: value.occurred_at,
            actor: value.actor,
            action: value.action,
            object_id: value.object_id,
            detail: value.detail,
            client_ip: if client_ip_enabled {
                value.client_ip
            } else {
                None
            },
        }
    }
}

pub(super) async fn list_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<AuditResponse>> {
    session(&state, &headers, true, MissingSession::Unauthorized).await?;
    let page = query.page.unwrap_or(0).min(1_000_000);
    let action = query.action.filter(|value| !value.trim().is_empty());
    let client_ip_enabled = runtime_settings(&state).audit_client_ip_enabled;
    let (client_ip_enabled, events) = database(state.db.clone(), move |db| {
        let events = db.list_audit(action.as_deref(), 101, page * 100)?;
        Ok((client_ip_enabled, events))
    })
    .await?;
    let mut events = events
        .into_iter()
        .map(|event| AuditEventResponse::from_event(event, client_ip_enabled))
        .collect::<Vec<_>>();
    let has_next = events.len() > 100;
    events.truncate(100);
    Ok(Json(AuditResponse {
        page,
        has_next,
        client_ip_enabled,
        events,
    }))
}

#[derive(Serialize)]
pub(super) struct DeletedAuditClientIpsResponse {
    deleted: usize,
}

#[derive(Deserialize)]
pub(super) struct DeleteAuditClientIpsRequest {
    confirmation: String,
}

pub(super) async fn delete_audit_client_ips(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DeleteAuditClientIpsRequest>,
) -> ApiResult<Json<DeletedAuditClientIpsResponse>> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    if request.confirmation != "IP-DATEN LÖSCHEN" {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "confirmation_required",
            "Exact confirmation IP-DATEN LÖSCHEN is required",
        ));
    }
    let fallback_logging_enabled = runtime_settings(&state).audit_client_ip_enabled;
    let audit_actor = session_data.username;
    let audit_client_ip = enabled_audit_client_ip(&state);
    let audit_context = AuditContext::new(audit_actor, audit_client_ip);
    let outcome = required_database(state.db.clone(), move |db| {
        db.delete_audit_client_ips_if_disabled_and_audit(fallback_logging_enabled, &audit_context)
    })
    .await?;
    let AuditClientIpDeletionOutcome::Deleted(deleted) = outcome else {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "client_ip_logging_enabled",
            "Client IP logging must be disabled before deletion",
        ));
    };
    Ok(Json(DeletedAuditClientIpsResponse { deleted }))
}
