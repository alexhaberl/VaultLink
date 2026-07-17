use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    db::AuditContext,
    file_ops,
    http_auth::{
        csrf_header, current_audit_client_ip, current_client_limit_key, enabled_audit_client_ip,
        runtime_settings, session, try_acquire_client_activity, with_audit_client_ip,
        MissingSession,
    },
    services::file::FileService,
    AppState,
};

use super::{
    common::{preview_allowed, validate_rel},
    ApiError, ApiResult, MAX_SEARCH_QUERY_BYTES,
};

#[derive(Default, Deserialize)]
pub(super) struct FilesQuery {
    path: Option<String>,
    page: Option<usize>,
    q: Option<String>,
}

#[derive(Serialize)]
struct FileEntryResponse {
    name: String,
    path: String,
    kind: &'static str,
    size: Option<u64>,
    modified: Option<String>,
    preview_allowed: bool,
}

#[derive(Serialize)]
pub(super) struct FilesResponse {
    path: String,
    page: usize,
    has_next: bool,
    truncated: bool,
    entries: Vec<FileEntryResponse>,
}

pub(super) fn list_file_page(
    secure_root: &crate::secure_fs::SecureRoot,
    relative: &str,
    page: usize,
    query: Option<&str>,
    scan_limit: usize,
) -> std::io::Result<(Vec<crate::secure_fs::Entry>, bool)> {
    let needle = query.map(str::to_ascii_lowercase);
    let skip = page.saturating_mul(100);
    let mut matched = 0usize;
    let mut scanned = 0usize;
    let mut results = Vec::new();
    let mut truncated = false;
    let mut directory = secure_root.scan_directory(relative)?;
    while results.len() < 101 {
        let remaining = scan_limit.saturating_sub(scanned);
        if remaining == 0 {
            let sentinel = directory.run_batch(1)?;
            truncated = sentinel.scanned != 0 || !sentinel.complete;
            break;
        }
        let batch = directory.run_batch(remaining.min(100))?;
        scanned = scanned.saturating_add(batch.scanned);
        for entry in batch.entries {
            if needle
                .as_ref()
                .is_none_or(|needle| entry.name.to_ascii_lowercase().contains(needle))
            {
                if matched >= skip && results.len() < 101 {
                    results.push(entry);
                }
                matched = matched.saturating_add(1);
            }
        }
        if batch.complete {
            break;
        }
    }
    Ok((results, truncated))
}

pub(super) async fn files(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<FilesQuery>,
) -> ApiResult<Json<FilesResponse>> {
    session(&state, &headers, true, MissingSession::Unauthorized).await?;
    let settings = runtime_settings(&state);
    let raw = query.path.unwrap_or_default();
    let rel = validate_rel(&raw)?;
    let page = query.page.unwrap_or(0).min(1_000_000);
    let search = query
        .q
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if search
        .as_ref()
        .is_some_and(|value| value.len() > MAX_SEARCH_QUERY_BYTES)
    {
        return Err(ApiError::bad_request("Search query is too long"));
    }
    let (scan_peer_permit, scan_permit) = if search.is_some() {
        let peer = try_acquire_client_activity(
            state.expensive_peer_admission.clone(),
            current_client_limit_key(),
            crate::MAX_EXPENSIVE_OPERATIONS_PER_CLIENT,
        )
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "search_busy",
                "Too many concurrent file searches from this client",
            )
        })?;
        let global = state
            .search_admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "search_busy",
                    "Too many concurrent file searches",
                )
            })?;
        (Some(peer), Some(global))
    } else {
        (None, None)
    };
    let secure_root = state.secure_root.clone();
    let scan_limit = settings.max_search_entries;
    let (entries, truncated) = tokio::task::spawn_blocking(move || {
        // Blocking filesystem scans are not cancelled when the request future is
        // dropped. Keep both permits in this closure so disconnects cannot
        // create unbounded detached search work.
        let _scan_peer_permit = scan_peer_permit;
        let _scan_permit = scan_permit;
        list_file_page(&secure_root, &rel, page, search.as_deref(), scan_limit)
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(ApiError::internal)?;
    let mut entries = entries
        .into_iter()
        .map(|entry| {
            let path = if raw.is_empty() {
                entry.name.clone()
            } else {
                format!("{}/{}", raw.trim_matches('/'), entry.name)
            };
            FileEntryResponse {
                name: entry.name,
                path: path.clone(),
                kind: if entry.is_dir { "directory" } else { "file" },
                size: (!entry.is_dir).then_some(entry.len),
                modified: entry
                    .modified
                    .map(|time| DateTime::<Utc>::from(time).to_rfc3339()),
                preview_allowed: !entry.is_dir && preview_allowed(&path, &settings),
            }
        })
        .collect::<Vec<_>>();
    let has_next = entries.len() > 100;
    entries.truncate(100);
    Ok(Json(FilesResponse {
        path: raw,
        page,
        has_next,
        truncated,
        entries,
    }))
}

#[derive(Deserialize)]
pub(super) struct CreateDirectoryRequest {
    #[serde(default)]
    parent: String,
    name: String,
}

#[derive(Deserialize)]
pub(super) struct RenameFileRequest {
    path: String,
    name: String,
}

#[derive(Deserialize)]
pub(super) struct DeleteFileRequest {
    path: String,
    confirm_name: Option<String>,
}

#[derive(Serialize)]
struct CreatedDirectoryResponse {
    ok: bool,
    path: String,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<&'static str>,
}

#[derive(Serialize)]
struct RenamedFileResponse {
    ok: bool,
    path: String,
    kind: &'static str,
    updated_shares: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<&'static str>,
}

#[derive(Serialize)]
struct DeletedFileResponse {
    ok: bool,
    path: String,
    kind: &'static str,
    deactivated_shares: usize,
    cleanup_pending: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<&'static str>,
}

pub(super) async fn create_directory(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateDirectoryRequest>,
) -> ApiResult<Response> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    let service = FileService::new(state.clone());
    let audit_client_ip = current_audit_client_ip();
    let audit_context = AuditContext::new(session_data.username, enabled_audit_client_ip(&state));
    let result = tokio::spawn(with_audit_client_ip(audit_client_ip, async move {
        service
            .create_directory(&request.parent, &request.name, audit_context)
            .await
    }))
    .await
    .map_err(ApiError::internal)?
    .map_err(file_operation_error)?;
    let audit_uncertain = result.audit_durability.is_uncertain();
    Ok((
        if audit_uncertain {
            StatusCode::ACCEPTED
        } else {
            StatusCode::CREATED
        },
        Json(CreatedDirectoryResponse {
            ok: true,
            path: result.path,
            kind: "directory",
            warning: audit_uncertain.then_some("audit_durability_uncertain"),
        }),
    )
        .into_response())
}

pub(super) async fn rename_file_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RenameFileRequest>,
) -> ApiResult<Response> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    let service = FileService::new(state.clone());
    let audit_client_ip = current_audit_client_ip();
    let audit_context = AuditContext::new(session_data.username, enabled_audit_client_ip(&state));
    let result = tokio::spawn(with_audit_client_ip(audit_client_ip, async move {
        service
            .rename(&request.path, &request.name, audit_context)
            .await
    }))
    .await
    .map_err(ApiError::internal)?
    .map_err(file_operation_error)?;
    let audit_uncertain = result.audit_durability.is_uncertain();
    Ok((
        if audit_uncertain {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        },
        Json(RenamedFileResponse {
            ok: true,
            path: result.path,
            kind: file_ops::kind_name(result.kind),
            updated_shares: result.updated_shares,
            warning: audit_uncertain.then_some("audit_durability_uncertain"),
        }),
    )
        .into_response())
}

pub(super) async fn delete_file_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DeleteFileRequest>,
) -> ApiResult<Response> {
    let (_, session_data) = session(&state, &headers, true, MissingSession::Unauthorized).await?;
    csrf_header(&session_data, &headers)?;
    let service = FileService::new(state.clone());
    let audit_client_ip = current_audit_client_ip();
    let audit_context = AuditContext::new(session_data.username, enabled_audit_client_ip(&state));
    let result = tokio::spawn(with_audit_client_ip(audit_client_ip, async move {
        service
            .delete(
                &request.path,
                request.confirm_name.as_deref(),
                audit_context,
            )
            .await
    }))
    .await
    .map_err(ApiError::internal)?
    .map_err(file_operation_error)?;
    let audit_uncertain = result.audit_durability.is_uncertain();
    let status = if result.cleanup_pending || audit_uncertain {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(DeletedFileResponse {
            ok: true,
            path: result.path,
            kind: file_ops::kind_name(result.kind),
            deactivated_shares: result.deactivated_shares,
            cleanup_pending: result.cleanup_pending,
            warning: audit_uncertain.then_some("audit_durability_uncertain"),
        }),
    )
        .into_response())
}

pub(super) fn file_operation_error(error: file_ops::FileOperationError) -> ApiError {
    use file_ops::FileOperationError;
    match error {
        FileOperationError::InvalidPath => {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_path", "Invalid path")
        }
        FileOperationError::InvalidName => {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_name", "Invalid name")
        }
        FileOperationError::NotFound => ApiError::not_found("Target not found"),
        FileOperationError::Conflict => ApiError::new(
            StatusCode::CONFLICT,
            "conflict",
            "Target name already exists",
        ),
        FileOperationError::ConfirmationRequired { .. } => ApiError::new(
            StatusCode::CONFLICT,
            "confirmation_required",
            "The exact directory name must be confirmed",
        ),
        FileOperationError::Database(database_error)
            if crate::db::is_audit_unavailable(&database_error) =>
        {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit_unavailable",
                "Security audit temporarily unavailable",
            )
        }
        other @ (FileOperationError::Database(_)
        | FileOperationError::Io(_)
        | FileOperationError::Join(_)) => ApiError::internal(other),
    }
}
