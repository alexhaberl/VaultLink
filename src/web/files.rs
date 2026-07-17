use askama::Template;
use axum::{
    body::Body,
    extract::{Form, Json, Multipart, Query, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::{DateTime, SecondsFormat, Utc};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;

use super::{
    admission::PermitBody,
    common::{
        add_upload_bytes, encoded, extension_is_blocked, file_sort_column, file_sort_column_value,
        file_sort_direction, file_sort_direction_value, human, internal, join_display,
        list_directory_cursor_page, parent_path, preview_allowed, preview_kind, search_tree,
        sort_search_hits, BrowseQuery,
    },
    preview_zip::{raw_preview_response, read_preview, PreviewContent},
    public_preview::text_preview_render_permits,
    rendering::{
        escaped_html_len, storage_has_room, PageId, StorageReservationError, UploadChunkReservation,
    },
    shares::ShareQuery,
    storage_recovery_app_error,
    transfer_runtime::{
        escaped_text_page_stream, limited_multipart_text, upload_io_error, PendingUploadFileError,
    },
    upload::{upload_queue_error_response, UploadQueueSuccess},
    AppError, Result, MAX_RENDERED_TEXT_PREVIEW_BYTES, MAX_SEARCH_QUERY_BYTES,
    MAX_UPLOAD_OPTION_FIELD_BYTES, MAX_UPLOAD_PATH_FIELD_BYTES,
};

#[derive(Template)]
#[template(path = "web/files/text_preview.html")]
struct AdminTextPreviewTemplate<'a> {
    parent_path: &'a str,
    relative_path: &'a str,
}

#[derive(Template)]
#[template(path = "web/files/delete_confirm.html")]
struct DeleteFileConfirmTemplate {
    heading: String,
    path: String,
    name: String,
    affected_shares: usize,
    csrf_token: String,
    confirmation_required: bool,
    parent_path: String,
}

struct AdminBreadcrumbView {
    label: String,
    url: String,
}

struct AdminSortHeaderView {
    label_key: &'static str,
    aria_sort: &'static str,
    indicator: &'static str,
    sort: &'static str,
    direction: &'static str,
}

struct AdminFileRowView {
    path: String,
    name: String,
    icon: super::templates::TrustedMarkup,
    is_directory: bool,
    type_label: &'static str,
    size: String,
    modified_datetime: Option<String>,
    modified_label: String,
    open_url: Option<String>,
    preview_url: Option<String>,
    share_url: String,
    download_url: Option<String>,
    delete_url: String,
}

#[derive(Template)]
#[template(path = "web/files/browser.html")]
struct AdminBrowserTemplate {
    notice_key: Option<&'static str>,
    notice_success: bool,
    used_storage: String,
    free_storage: String,
    active_links: usize,
    breadcrumbs: Vec<AdminBreadcrumbView>,
    path: String,
    path_encoded: String,
    up_url: Option<String>,
    csrf_token: String,
    replacements_allowed: bool,
    upload_icon: super::templates::TrustedMarkup,
    folder_icon: super::templates::TrustedMarkup,
    more_icon: super::templates::TrustedMarkup,
    trash_icon: super::templates::TrustedMarkup,
    current_folder_target: String,
    sort: &'static str,
    direction: &'static str,
    search: String,
    search_encoded: Option<String>,
    headers: Vec<AdminSortHeaderView>,
    rows: Vec<AdminFileRowView>,
    truncated: bool,
    previous_cursor: Option<String>,
    next_cursor: Option<String>,
}

#[derive(Template)]
#[template(path = "web/files/preview_too_large.html")]
struct AdminPreviewTooLargeTemplate {
    parent_path: String,
    path: String,
    message: String,
    size: String,
}

#[derive(Template)]
#[template(path = "web/files/media_preview.html")]
struct AdminMediaPreviewTemplate {
    parent_path: String,
    path: String,
    size: String,
    raw_url: String,
    image: bool,
}

fn admin_file_time(value: std::time::SystemTime) -> (String, String) {
    let utc = DateTime::<Utc>::from(value);
    (
        utc.to_rfc3339_opts(SecondsFormat::Secs, true),
        super::common::format_utc_minute(utc),
    )
}

fn admin_breadcrumb_views(path: &str) -> Vec<AdminBreadcrumbView> {
    let mut current = String::new();
    path.trim_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .map(|part| {
            current = join_display(&current, part);
            AdminBreadcrumbView {
                label: part.to_string(),
                url: format!("/admin?path={}", encoded(&current)),
            }
        })
        .collect()
}

fn admin_sort_header_view(
    label_key: &'static str,
    column: super::common::FileSortColumn,
    current_column: super::common::FileSortColumn,
    current_direction: super::common::FileSortDirection,
) -> AdminSortHeaderView {
    use super::common::FileSortDirection;
    let active = column == current_column;
    let next_direction = if active && current_direction == FileSortDirection::Ascending {
        FileSortDirection::Descending
    } else {
        FileSortDirection::Ascending
    };
    AdminSortHeaderView {
        label_key,
        aria_sort: if active {
            match current_direction {
                FileSortDirection::Ascending => "ascending",
                FileSortDirection::Descending => "descending",
            }
        } else {
            "none"
        },
        indicator: if active {
            match current_direction {
                FileSortDirection::Ascending => "↑",
                FileSortDirection::Descending => "↓",
            }
        } else {
            ""
        },
        sort: file_sort_column_value(column),
        direction: file_sort_direction_value(next_direction),
    }
}

fn admin_file_row_view(
    path: &str,
    name: String,
    is_directory: bool,
    size: u64,
    modified: Option<std::time::SystemTime>,
    settings: &crate::runtime::RuntimeSettings,
) -> AdminFileRowView {
    let target = encoded(path);
    let modified = modified.map(admin_file_time);
    let (modified_datetime, modified_label) = if let Some((datetime, label)) = modified {
        (Some(datetime), label)
    } else {
        (None, "—".into())
    };
    AdminFileRowView {
        path: path.to_string(),
        name,
        icon: super::templates::TrustedMarkup::static_icon(if is_directory {
            crate::ui::Icon::Folder
        } else {
            crate::ui::Icon::File
        }),
        is_directory,
        type_label: i18n::text(
            i18n::current_locale(),
            if is_directory {
                i18n::FOLDER
            } else {
                i18n::FILE
            },
        ),
        size: if is_directory {
            "—".into()
        } else {
            human(size)
        },
        modified_datetime,
        modified_label,
        open_url: is_directory.then(|| format!("/admin?path={target}")),
        preview_url: (!is_directory && preview_allowed(path, settings))
            .then(|| format!("/admin/preview?path={target}")),
        share_url: format!("/admin/shares/new?path={target}"),
        download_url: (!is_directory).then(|| format!("/admin/files/download?path={target}")),
        delete_url: format!("/admin/files/delete?path={target}"),
    }
}
use crate::{
    db::AuditContext,
    file_ops,
    http_auth::{
        audit_observation, clear_session_cookie, csrf, current_audit_client_ip,
        current_client_limit_key, database, enabled_audit_client_ip, runtime_settings, session,
        try_acquire_client_activity, with_audit_client_ip, MissingSession,
    },
    i18n::{self, Locale},
    path_security,
    policy::PreviewKind,
    secure_fs::PendingUpload,
    services::file::FileService,
    AppState,
};

#[derive(Deserialize)]
pub(super) struct CreateDirectoryForm {
    csrf: String,
    parent: String,
    name: String,
}

#[derive(Deserialize)]
pub(super) struct RenameFileForm {
    csrf: String,
    path: String,
    name: String,
}

#[derive(Deserialize)]
pub(super) struct DeleteFileQuery {
    path: String,
}

#[derive(Deserialize)]
pub(super) struct DeleteFileForm {
    csrf: String,
    path: String,
    confirm_name: Option<String>,
}

pub(super) async fn create_directory_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateDirectoryForm>,
) -> Result<Redirect> {
    let (_, admin) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&admin, &form.csrf)?;
    let file_service = FileService::new(state.clone());
    let operation_parent = form.parent.clone();
    let operation_name = form.name;
    let audit_client_ip = current_audit_client_ip();
    let audit_context = AuditContext::new(admin.username, enabled_audit_client_ip(&state));
    let result = tokio::spawn(with_audit_client_ip(audit_client_ip, async move {
        file_service
            .create_directory(&operation_parent, &operation_name, audit_context)
            .await
    }))
    .await
    .map_err(internal)?
    .map_err(file_operation_app_error)?;
    Ok(Redirect::to(&browser_redirect(
        &form.parent,
        if result.audit_durability.is_uncertain() {
            "audit_durability_uncertain"
        } else {
            "directory_created"
        },
    )))
}

pub(super) async fn rename_file_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RenameFileForm>,
) -> Result<Redirect> {
    let (_, admin) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&admin, &form.csrf)?;
    let parent = parent_path(&form.path).unwrap_or_default();
    let file_service = FileService::new(state.clone());
    let operation_path = form.path;
    let operation_name = form.name;
    let audit_client_ip = current_audit_client_ip();
    let audit_context = AuditContext::new(admin.username, enabled_audit_client_ip(&state));
    let result = tokio::spawn(with_audit_client_ip(audit_client_ip, async move {
        file_service
            .rename(&operation_path, &operation_name, audit_context)
            .await
    }))
    .await
    .map_err(internal)?
    .map_err(file_operation_app_error)?;
    Ok(Redirect::to(&browser_redirect(
        &parent,
        if result.audit_durability.is_uncertain() {
            "audit_durability_uncertain"
        } else {
            "path_renamed"
        },
    )))
}

pub(super) async fn delete_file_confirmation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DeleteFileQuery>,
) -> Result<Html<String>> {
    let (_, admin) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let inspection = FileService::new(state.clone())
        .inspect_delete(&query.path)
        .await
        .map_err(file_operation_app_error)?;
    let locale = i18n::current_locale();
    let kind = if inspection.status.kind == crate::secure_fs::EntryKind::Directory {
        i18n::text(locale, i18n::FOLDER)
    } else {
        i18n::text(locale, i18n::FILE)
    };
    let heading = match locale {
        Locale::De => format!("{kind} permanent löschen?"),
        Locale::En => format!("Delete {kind} permanently?"),
    };
    let body = DeleteFileConfirmTemplate {
        heading,
        path: inspection.path.clone(),
        name: inspection.name,
        affected_shares: inspection.affected_shares,
        csrf_token: admin.csrf_token.clone(),
        confirmation_required: inspection.status.directory_non_empty,
        parent_path: encoded(parent_path(&inspection.path).as_deref().unwrap_or("")),
    };
    Ok(Html(super::templates::admin_page(
        &state,
        PageId::DeleteConfirm,
        &body,
        false,
        &admin.csrf_token,
        true,
    )?))
}

pub(super) async fn delete_file_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeleteFileForm>,
) -> Result<Redirect> {
    let (_, admin) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&admin, &form.csrf)?;
    let parent = parent_path(&form.path).unwrap_or_default();
    let file_service = FileService::new(state.clone());
    let operation_path = form.path;
    let confirm_name = form.confirm_name;
    let audit_client_ip = current_audit_client_ip();
    let audit_context = AuditContext::new(admin.username, enabled_audit_client_ip(&state));
    let result = tokio::spawn(with_audit_client_ip(audit_client_ip, async move {
        file_service
            .delete(&operation_path, confirm_name.as_deref(), audit_context)
            .await
    }))
    .await
    .map_err(internal)?
    .map_err(file_operation_app_error)?;
    let notice = if result.audit_durability.is_uncertain() {
        "audit_durability_uncertain"
    } else if result.cleanup_pending {
        "path_delete_queued"
    } else {
        "path_deleted"
    };
    Ok(Redirect::to(&browser_redirect(&parent, notice)))
}

pub(super) struct AdminUploadSuccess {
    file: String,
    outcome: String,
    directory: String,
    audit_durability_uncertain: bool,
}

const ADMIN_UPLOAD_SESSION_REVOKED: &str = "session_revoked";

#[derive(Serialize)]
struct AdminUploadSessionRevoked {
    error: &'static str,
}

pub(super) async fn persist_required_file_audit(
    state: &AppState,
    context: AuditContext,
    action: &'static str,
    object: String,
    detail: String,
) -> bool {
    let result = database(state.db.clone(), move |database| {
        database.audit_with_client_ip(
            &context.actor,
            action,
            Some(&object),
            Some(&detail),
            context.client_ip.as_deref(),
        )
    })
    .await;
    if let Err(error) = result {
        tracing::error!(
            ?error,
            action,
            "filesystem mutation completed but required audit durability is uncertain"
        );
        true
    } else {
        false
    }
}

pub(super) async fn stage_admin_upload(
    state: &AppState,
    directory: &str,
    field: axum::extract::multipart::Field<'_>,
    maximum: u64,
    blocked_extensions: &[String],
) -> Result<(PendingUpload, String, u64)> {
    let file_name = field
        .file_name()
        .ok_or(AppError(StatusCode::BAD_REQUEST, "File name missing"))?;
    let name = path_security::safe_admin_filename(file_name)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid file name"))?
        .to_string();
    if extension_is_blocked(&name, blocked_extensions) {
        return Err(AppError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "File type blocked",
        ));
    }

    let secure_root = state.secure_root.clone();
    let upload_directory = directory.to_string();
    let pending_file = tokio::task::spawn_blocking(move || {
        let mut pending = secure_root
            .begin_upload(&upload_directory)
            .map_err(|_| PendingUploadFileError::Begin)?;
        let file = pending.take_file().map_err(PendingUploadFileError::Take)?;
        Ok::<_, PendingUploadFileError>((pending, file))
    })
    .await
    .map_err(internal)?;
    let (pending, file) = match pending_file {
        Ok(value) => value,
        Err(PendingUploadFileError::Begin) => {
            return Err(AppError(StatusCode::NOT_FOUND, "Target folder unavailable"))
        }
        Err(PendingUploadFileError::Take(error)) => return Err(upload_io_error(error)),
    };

    let mut output = tokio::fs::File::from_std(file);
    let mut total = 0u64;
    let stream = field;
    tokio::pin!(stream);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| AppError(StatusCode::BAD_REQUEST, "Upload aborted"))?;
        let Some(new_total) = add_upload_bytes(total, chunk.len(), maximum) else {
            return Err(AppError(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Upload is too large",
            ));
        };
        let _reservation = match UploadChunkReservation::acquire(state, chunk.len() as u64).await {
            Ok(reservation) => reservation,
            Err(StorageReservationError::CapacityUnavailable) => {
                return Err(AppError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Storage capacity could not be determined",
                ))
            }
            Err(StorageReservationError::InsufficientStorage) => {
                return Err(AppError(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Not enough free storage",
                ))
            }
        };
        total = new_total;
        output.write_all(&chunk).await.map_err(upload_io_error)?;
    }
    output.flush().await.map_err(upload_io_error)?;
    output.sync_all().await.map_err(upload_io_error)?;
    drop(output);
    Ok((pending, name, total))
}

async fn ensure_admin_upload_directory(
    state: &AppState,
    base: &str,
    relative: &str,
    actor: &str,
) -> Result<String> {
    let relative = path_security::validate_relative(relative)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid folder path"))?
        .to_string_lossy()
        .replace('\\', "/");
    if relative.is_empty() {
        return Ok(base.to_string());
    }
    let target = join_display(base, &relative);
    let guard = state.storage_mutation.clone().lock_owned().await;
    let guard = file_ops::recover_pending_file_operations_with_guard(state, guard)
        .await
        .map_err(storage_recovery_app_error)?;
    let secure_root = state.secure_root.clone();
    let base = base.to_string();
    let tree = relative.clone();
    let created = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        secure_root
            .bind_directory(&base)?
            .ensure_directory_tree(&tree)
    })
    .await
    .map_err(internal)?
    .map_err(|error| match error.kind() {
        std::io::ErrorKind::InvalidInput => {
            AppError(StatusCode::BAD_REQUEST, "Invalid folder path")
        }
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
            AppError(StatusCode::CONFLICT, "Upload folder could not be created")
        }
        _ => internal(error),
    })?;
    if !created.is_empty() {
        audit_observation(
            state,
            actor.to_string(),
            "upload_directories_created",
            Some(target.clone()),
            Some(format!("created={}", created.len())),
        )
        .await;
    }
    Ok(target)
}

pub(super) async fn process_admin_upload(
    state: &AppState,
    headers: &HeaderMap,
    mut multipart: Multipart,
) -> Result<AdminUploadSuccess> {
    let (session_token, admin) =
        session(state, headers, true, MissingSession::RedirectToLogin).await?;
    let admin_id = admin.admin_id;
    let _upload_permit = state
        .upload_admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            AppError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Too many concurrent uploads",
            )
        })?;
    let _upload_peer_permit = try_acquire_client_activity(
        state.upload_peer_admission.clone(),
        current_client_limit_key(),
        crate::MAX_IN_FLIGHT_UPLOADS_PER_CLIENT,
    )
    .ok_or(AppError(
        StatusCode::SERVICE_UNAVAILABLE,
        "Too many concurrent uploads from this client",
    ))?;
    let settings = runtime_settings(state);
    if let Some(length) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    {
        match storage_has_room(state, length).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(AppError(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Not enough free storage",
                ))
            }
            Err(_) => {
                return Err(AppError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Storage capacity could not be determined",
                ))
            }
        }
    }

    let mut directory: Option<String> = None;
    let mut csrf_value: Option<String> = None;
    let mut overwrite_existing = false;
    let mut saw_overwrite = false;
    let mut folder_path: Option<String> = None;
    let mut staged: Option<(PendingUpload, String, u64)> = None;
    let mut fields_seen = 0usize;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid upload"))?
    {
        fields_seen += 1;
        if fields_seen > 5 {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "Too many multipart fields",
            ));
        }
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "path" => {
                if directory.is_some() || staged.is_some() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "Upload path was submitted more than once or too late",
                    ));
                }
                let value = limited_multipart_text(field, MAX_UPLOAD_PATH_FIELD_BYTES)
                    .await
                    .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid upload path"))?;
                let value = path_security::validate_relative(&value)
                    .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid upload path"))?
                    .to_string_lossy()
                    .replace('\\', "/");
                directory = Some(value);
            }
            "csrf" => {
                if csrf_value.is_some() || staged.is_some() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "CSRF proof was submitted more than once or too late",
                    ));
                }
                let value = limited_multipart_text(field, 512)
                    .await
                    .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid CSRF proof"))?;
                csrf(&admin, &value)?;
                csrf_value = Some(value);
            }
            "overwrite_existing" => {
                if std::mem::replace(&mut saw_overwrite, true) || staged.is_some() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "Upload option was submitted more than once or too late",
                    ));
                }
                let value = limited_multipart_text(field, MAX_UPLOAD_OPTION_FIELD_BYTES)
                    .await
                    .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid upload option"))?;
                overwrite_existing = value == "1";
                if overwrite_existing && !state.config.storage.replacements_allowed() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "Overwriting is disabled with external storage writers",
                    ));
                }
            }
            "folder_path" => {
                if folder_path.is_some() || staged.is_some() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "Folder path was submitted more than once or too late",
                    ));
                }
                let value = limited_multipart_text(field, MAX_UPLOAD_PATH_FIELD_BYTES)
                    .await
                    .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid folder path"))?;
                let value = path_security::validate_relative(&value)
                    .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid folder path"))?
                    .to_string_lossy()
                    .replace('\\', "/");
                folder_path = Some(value);
            }
            "file" => {
                if staged.is_some() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "Exactly one file is allowed per request",
                    ));
                }
                let target = directory.as_deref().ok_or(AppError(
                    StatusCode::BAD_REQUEST,
                    "Upload path must be submitted before the file",
                ))?;
                if csrf_value.is_none() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "CSRF proof must be submitted before the file",
                    ));
                }
                let target = if let Some(folder_path) = folder_path.as_deref() {
                    ensure_admin_upload_directory(state, target, folder_path, &admin.username)
                        .await?
                } else {
                    target.to_string()
                };
                staged = Some(
                    stage_admin_upload(
                        state,
                        &target,
                        field,
                        settings.max_upload_size,
                        &settings.blocked_extensions,
                    )
                    .await?,
                );
            }
            _ => return Err(AppError(StatusCode::BAD_REQUEST, "Unknown multipart field")),
        }
    }

    let mut directory =
        directory.ok_or(AppError(StatusCode::BAD_REQUEST, "Upload path missing"))?;
    if let Some(folder_path) = folder_path.as_deref() {
        directory = join_display(&directory, folder_path);
    }
    if csrf_value.is_none() {
        return Err(AppError(StatusCode::FORBIDDEN, "CSRF proof missing"));
    }
    let (mut pending, name, total) = staged.ok_or(AppError(
        StatusCode::BAD_REQUEST,
        "Exactly one file is required per request",
    ))?;
    let destination = join_display(&directory, &name);
    let publish_name = name.clone();
    #[cfg(test)]
    if let Some(kind) = state
        .upload_directory_sync_failure
        .lock()
        .expect("upload sync fault lock")
        .take()
    {
        pending.fail_next_directory_sync(kind);
    }
    let task_state = state.clone();
    let upload_permit = _upload_permit;
    let upload_peer_permit = _upload_peer_permit;
    let audit_client_ip = current_audit_client_ip();
    let audit_context = AuditContext::new(admin.username, enabled_audit_client_ip(state));
    let finalizer = tokio::spawn(with_audit_client_ip(audit_client_ip, async move {
        let _upload_permit = upload_permit;
        let _upload_peer_permit = upload_peer_permit;
        let state = &task_state;
        let storage_guard = state.storage_mutation.clone().lock_owned().await;
        let storage_guard =
            file_ops::recover_pending_file_operations_with_guard(state, storage_guard)
                .await
                .map_err(storage_recovery_app_error)?;
        let current_destination = state.secure_root.bind_directory(&directory).map_err(|_| {
            AppError(
                StatusCode::CONFLICT,
                "Upload target changed in the meantime",
            )
        })?;
        if !pending
            .destination_matches(&current_destination)
            .map_err(internal)?
        {
            return Err(AppError(
                StatusCode::CONFLICT,
                "Upload target changed in the meantime",
            ));
        }
        let existed = match state.secure_root.metadata(&destination) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(internal(error)),
        };
        let publish_result = database(state.db.clone(), move |database| {
            // Publishing is not cancelled with the HTTP request. Retain the storage
            // lock through the namespace change, and retain the database connection
            // lock from the exact-session recheck through publication. Session
            // revocation and this commit therefore have one deterministic order.
            let _storage_guard = storage_guard;
            database.with_live_mfa_session(&session_token, admin_id, || {
                if overwrite_existing {
                    pending.publish_replace(&publish_name)
                } else {
                    pending.publish(&publish_name)
                }
            })
        })
        .await?;
        let Some(publish_result) = publish_result else {
            return Err(AppError(
                StatusCode::UNAUTHORIZED,
                ADMIN_UPLOAD_SESSION_REVOKED,
            ));
        };
        let publish_outcome = match publish_result {
            Ok(outcome) => outcome,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(AppError(
                    StatusCode::CONFLICT,
                    "File already exists; replacement must be confirmed for this file",
                ))
            }
            Err(error) => return Err(upload_io_error(error)),
        };
        let replaced = overwrite_existing && existed;
        let durability_uncertain = !publish_outcome.is_durable();
        let detail = format!("file={name};bytes={total};path={destination}");
        if let Some(error) = publish_outcome.sync_error() {
            tracing::warn!(file = %name, %error, "admin upload published but directory fsync failed");
            audit_observation(
                state,
                audit_context.actor.clone(),
                "admin_upload_durability_uncertain",
                Some(destination.clone()),
                Some(detail.clone()),
            )
            .await;
        }
        let audit_durability_uncertain = persist_required_file_audit(
            state,
            audit_context,
            if replaced {
                "admin_upload_replaced"
            } else {
                "admin_upload"
            },
            destination,
            detail,
        )
        .await;
        let outcome = match (replaced, durability_uncertain) {
            (true, true) => "replaced_uncertain",
            (false, true) => "created_uncertain",
            (true, false) => "replaced",
            (false, false) => "created",
        };
        Ok(AdminUploadSuccess {
            file: name,
            outcome: outcome.to_string(),
            directory,
            audit_durability_uncertain,
        })
    }));
    finalizer.await.map_err(internal)?
}

pub(super) async fn admin_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Result<Response> {
    let success = match process_admin_upload(&state, &headers, multipart).await {
        Ok(success) => success,
        Err(AppError(StatusCode::UNAUTHORIZED, ADMIN_UPLOAD_SESSION_REVOKED)) => {
            let mut response = Redirect::to("/login").into_response();
            response.headers_mut().insert(
                header::SET_COOKIE,
                HeaderValue::from_str(&clear_session_cookie(&state)).map_err(internal)?,
            );
            return Ok(response);
        }
        Err(error) => return Err(error),
    };
    let mut response = Redirect::to(&browser_redirect(
        &success.directory,
        if success.audit_durability_uncertain {
            "audit_durability_uncertain"
        } else {
            "upload_ok"
        },
    ))
    .into_response();
    response.headers_mut().insert(
        "x-vaultlink-upload-file",
        HeaderValue::from_str(&encoded(&success.file)).map_err(internal)?,
    );
    response.headers_mut().insert(
        "x-vaultlink-upload-outcome",
        HeaderValue::from_str(&success.outcome).map_err(internal)?,
    );
    if success.audit_durability_uncertain {
        response.headers_mut().insert(
            "x-vaultlink-audit-durability",
            HeaderValue::from_static("uncertain"),
        );
    }
    Ok(response)
}

pub(super) async fn admin_upload_queue(
    State(state): State<AppState>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Response {
    match process_admin_upload(&state, &headers, multipart).await {
        Ok(success) => {
            let status = if success.audit_durability_uncertain {
                StatusCode::ACCEPTED
            } else {
                StatusCode::OK
            };
            (
                status,
                Json(UploadQueueSuccess {
                    file: success.file,
                    outcome: success.outcome,
                    warning: success
                        .audit_durability_uncertain
                        .then_some("audit_durability_uncertain"),
                }),
            )
                .into_response()
        }
        Err(AppError(StatusCode::UNAUTHORIZED, ADMIN_UPLOAD_SESSION_REVOKED)) => (
            StatusCode::UNAUTHORIZED,
            Json(AdminUploadSessionRevoked {
                error: ADMIN_UPLOAD_SESSION_REVOKED,
            }),
        )
            .into_response(),
        Err(AppError(status, message)) => upload_queue_error_response(status, message),
    }
}

pub(super) fn browser_redirect(path: &str, notice: &str) -> String {
    format!("/admin?path={}&notice={notice}", encoded(path))
}

pub(super) fn file_operation_app_error(error: file_ops::FileOperationError) -> AppError {
    use file_ops::FileOperationError;
    match error {
        FileOperationError::InvalidPath => AppError(StatusCode::BAD_REQUEST, "Invalid path"),
        FileOperationError::InvalidName => AppError(StatusCode::BAD_REQUEST, "Invalid name"),
        FileOperationError::NotFound => AppError(StatusCode::NOT_FOUND, "Target not found"),
        FileOperationError::Conflict => {
            AppError(StatusCode::CONFLICT, "Target name already exists")
        }
        FileOperationError::ConfirmationRequired { .. } => AppError(
            StatusCode::CONFLICT,
            "The exact folder name must be confirmed",
        ),
        FileOperationError::Database(database_error)
            if crate::db::is_audit_unavailable(&database_error) =>
        {
            AppError(
                StatusCode::SERVICE_UNAVAILABLE,
                crate::http_auth::AUDIT_UNAVAILABLE_MESSAGE,
            )
        }
        other @ (FileOperationError::Database(_)
        | FileOperationError::Io(_)
        | FileOperationError::Join(_)) => internal(other),
    }
}

pub(super) async fn admin_browser(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<BrowseQuery>,
) -> Result<Html<String>> {
    let (_, s) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let settings = runtime_settings(&state);
    let disk = state
        .disk_stats_cache
        .get(state.secure_root.display_root())
        .await
        .ok();
    let used_storage = disk
        .as_ref()
        .map(|stats| stats.total.saturating_sub(stats.free))
        .map(human)
        .unwrap_or_else(|| "n/v".into());
    let free_storage = disk
        .as_ref()
        .map(|stats| human(stats.free))
        .unwrap_or_else(|| "n/v".into());
    let active_links = database(state.db.clone(), |database| {
        database.count_available_shares(Utc::now())
    })
    .await?;
    let sort_column = file_sort_column(q.sort.as_deref());
    let sort_direction = file_sort_direction(q.direction.as_deref());
    let raw = q.path.unwrap_or_default();
    let after_cursor = q.after.clone();
    let before_cursor = q.before.clone();
    let search =
        q.q.map(|value| value.trim().to_string())
            .filter(|v| !v.is_empty());
    if after_cursor.is_some() && before_cursor.is_some() {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Invalid directory cursor",
        ));
    }
    if search.is_some() && (after_cursor.is_some() || before_cursor.is_some()) {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Directory cursors cannot be combined with search",
        ));
    }
    if search
        .as_ref()
        .is_some_and(|value| value.len() > MAX_SEARCH_QUERY_BYTES)
    {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Search query is too long",
        ));
    }
    let rel = path_security::validate_relative(&raw)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid path"))?
        .to_string_lossy()
        .replace('\\', "/");
    let secure_root = state.secure_root.clone();
    let _scan_peer_permit = try_acquire_client_activity(
        state.expensive_peer_admission.clone(),
        current_client_limit_key(),
        crate::MAX_EXPENSIVE_OPERATIONS_PER_CLIENT,
    )
    .ok_or(AppError(
        StatusCode::SERVICE_UNAVAILABLE,
        "Too many concurrent expensive operations from this client",
    ))?;
    let _scan_permit = state
        .search_admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            AppError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Too many concurrent file searches",
            )
        })?;
    let mut rows = Vec::new();
    let mut truncated = false;
    let mut previous_cursor = None;
    let mut next_cursor = None;
    if let Some(search) = search.clone() {
        let base = rel.clone();
        let search_settings = settings.clone();
        let mut hits = tokio::task::spawn_blocking(move || {
            search_tree(&secure_root, &base, &search, &search_settings)
        })
        .await
        .map_err(internal)?
        .map_err(internal)?;
        sort_search_hits(&mut hits, sort_column, sort_direction);
        for hit in hits {
            rows.push(admin_file_row_view(
                &hit.relative_path,
                hit.relative_path.clone(),
                hit.entry.is_dir,
                hit.entry.len,
                hit.entry.modified,
                &settings,
            ));
        }
    } else {
        let listing_path = rel.clone();
        let scan_limit = settings.max_search_entries;
        let cursor_after = after_cursor.clone();
        let cursor_before = before_cursor.clone();
        let listing_page = tokio::task::spawn_blocking(move || {
            list_directory_cursor_page(
                &secure_root,
                &listing_path,
                cursor_after.as_deref(),
                cursor_before.as_deref(),
                scan_limit,
                sort_column,
                sort_direction,
            )
        })
        .await
        .map_err(internal)?
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::InvalidInput {
                AppError(StatusCode::BAD_REQUEST, "Invalid directory cursor")
            } else {
                internal(error)
            }
        })?;
        previous_cursor = listing_page.previous_cursor;
        next_cursor = listing_page.next_cursor;
        for entry in listing_page.entries {
            let child = join_display(&rel, &entry.name);
            rows.push(admin_file_row_view(
                &child,
                entry.name,
                entry.is_dir,
                entry.len,
                entry.modified,
                &settings,
            ));
        }
        truncated = listing_page.truncated;
    }
    let encoded_path = encoded(&rel);
    let current_folder_target = if raw.is_empty() {
        ".".to_string()
    } else {
        encoded_path.clone()
    };
    let (notice_key, notice_success) = match q.notice.as_deref() {
        Some("directory_created") => (Some("files.folder_created"), true),
        Some("path_renamed") => (Some("files.entry_renamed"), true),
        Some("path_deleted") => (Some("files.entry_deleted"), true),
        Some("path_delete_queued") => (Some("files.entry_removed_cleanup"), true),
        Some("audit_durability_uncertain") => (Some("files.audit_durability_uncertain"), false),
        Some("upload_ok") => (Some("files.uploaded"), true),
        _ => (None, false),
    };
    let headers = [
        ("common.name", super::common::FileSortColumn::Name),
        ("common.type", super::common::FileSortColumn::Type),
        ("common.size", super::common::FileSortColumn::Size),
        ("common.changed", super::common::FileSortColumn::Modified),
    ]
    .into_iter()
    .map(|(label, column)| admin_sort_header_view(label, column, sort_column, sort_direction))
    .collect();
    let body = AdminBrowserTemplate {
        notice_key,
        notice_success,
        used_storage,
        free_storage,
        active_links,
        breadcrumbs: admin_breadcrumb_views(&rel),
        path: rel.clone(),
        path_encoded: encoded_path,
        up_url: parent_path(&rel).map(|parent| format!("/admin?path={}", encoded(&parent))),
        csrf_token: s.csrf_token.clone(),
        replacements_allowed: state.config.storage.replacements_allowed(),
        upload_icon: super::templates::TrustedMarkup::static_icon(crate::ui::Icon::Upload),
        folder_icon: super::templates::TrustedMarkup::static_icon(crate::ui::Icon::Folder),
        more_icon: super::templates::TrustedMarkup::static_icon(crate::ui::Icon::More),
        trash_icon: super::templates::TrustedMarkup::static_icon(crate::ui::Icon::Trash),
        current_folder_target,
        sort: file_sort_column_value(sort_column),
        direction: file_sort_direction_value(sort_direction),
        search: search.clone().unwrap_or_default(),
        search_encoded: search.as_deref().map(encoded),
        headers,
        rows,
        truncated,
        previous_cursor: previous_cursor.map(|cursor| encoded(&cursor)),
        next_cursor: next_cursor.map(|cursor| encoded(&cursor)),
    };
    Ok(Html(super::templates::admin_page(
        &state,
        PageId::Files,
        &body,
        false,
        &s.csrf_token,
        true,
    )?))
}

pub(super) async fn admin_download(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
    Query(q): Query<ShareQuery>,
) -> Result<Response> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let raw = q
        .path
        .ok_or(AppError(StatusCode::BAD_REQUEST, "File path missing"))?;
    let relative = path_security::validate_relative(&raw)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid file path"))?
        .to_string_lossy()
        .replace('\\', "/");
    let secure_root = state.secure_root.clone();
    let open_path = relative.clone();
    let (file, length) = tokio::task::spawn_blocking(move || {
        let file = secure_root.open_file(&open_path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        Ok::<_, std::io::Error>((file, metadata.len()))
    })
    .await
    .map_err(internal)?
    .map_err(|error| match error.kind() {
        std::io::ErrorKind::InvalidInput => AppError(StatusCode::BAD_REQUEST, "Not a file"),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
            AppError(StatusCode::NOT_FOUND, "File unavailable")
        }
        _ => internal(error),
    })?;
    audit_observation(
        &state,
        session.username,
        "admin_download",
        Some(relative.clone()),
        None,
    )
    .await;
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from_stream(ReaderStream::new(tokio::fs::File::from_std(file)))
    };
    let mut response = Response::new(body);
    let name = Path::new(&relative)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{}", encoded(name)))
            .map_err(internal)?,
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&length.to_string()).map_err(internal)?,
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    Ok(response)
}

pub(super) async fn admin_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ShareQuery>,
) -> Result<Response> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let raw = q
        .path
        .ok_or(AppError(StatusCode::BAD_REQUEST, "File path missing"))?;
    let rel = path_security::validate_relative(&raw)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid path"))?
        .to_string_lossy()
        .replace('\\', "/");
    let settings = runtime_settings(&state);
    let mut text_render_permit = if preview_kind(&rel, &settings) == Some(PreviewKind::Text) {
        Some(
            state
                .preview_render_admission
                .clone()
                .try_acquire_many_owned(text_preview_render_permits(settings.max_preview_size))
                .map_err(|_| {
                    AppError(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Too many concurrent text previews",
                    )
                })?,
        )
    } else {
        None
    };
    let secure_root = state.secure_root.clone();
    let preview_path = rel.clone();
    let content =
        tokio::task::spawn_blocking(move || read_preview(&secure_root, &preview_path, &settings))
            .await
            .map_err(internal)?
            .map_err(|_| AppError(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Preview not allowed"))?;
    let content = match content {
        PreviewContent::Text(text)
            if escaped_html_len(&text)
                .is_none_or(|length| length > MAX_RENDERED_TEXT_PREVIEW_BYTES) =>
        {
            PreviewContent::TooLarge {
                size: text.len() as u64,
            }
        }
        content => content,
    };
    let preview_detail = match &content {
        PreviewContent::TooLarge { size } => format!("kind=too_large;bytes={size}"),
        PreviewContent::Text(text) => format!("kind=text;bytes={}", text.len()),
        PreviewContent::Media { kind, size } => format!("kind={kind:?};bytes={size}"),
    };
    audit_observation(
        &state,
        session.username.clone(),
        "admin_preview",
        Some(rel.clone()),
        Some(preview_detail),
    )
    .await;
    match content {
        PreviewContent::Text(text) => {
            let parent = encoded(parent_path(&rel).as_deref().unwrap_or(""));
            let body = AdminTextPreviewTemplate {
                parent_path: &parent,
                relative_path: &rel,
            };
            let page = super::templates::admin_page(
                &state,
                PageId::Preview,
                &body,
                false,
                &session.csrf_token,
                true,
            )?;
            let (stream, page_length) = escaped_text_page_stream(page, text).map_err(internal)?;
            let mut response = Response::new(Body::new(PermitBody {
                inner: Body::from_stream(stream),
                _permit: text_render_permit
                    .take()
                    .expect("text previews reserve render memory before reading"),
            }));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            response.headers_mut().insert(
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&page_length.to_string()).map_err(internal)?,
            );
            Ok(response)
        }
        PreviewContent::TooLarge { size } => {
            let body = AdminPreviewTooLargeTemplate {
                parent_path: encoded(parent_path(&rel).as_deref().unwrap_or("")),
                path: rel,
                message: i18n::localized_text(
                    i18n::current_locale(),
                    "File exceeds the preview limit.",
                )
                .into_owned(),
                size: human(size),
            };
            Ok(Html(super::templates::admin_page(
                &state,
                PageId::Preview,
                &body,
                false,
                &session.csrf_token,
                true,
            )?)
            .into_response())
        }
        PreviewContent::Media { kind, size } => {
            let body = AdminMediaPreviewTemplate {
                parent_path: encoded(parent_path(&rel).as_deref().unwrap_or("")),
                path: rel.clone(),
                size: human(size),
                raw_url: format!("/admin/preview/raw?path={}", encoded(&rel)),
                image: matches!(kind, PreviewKind::Image(_)),
            };
            Ok(Html(super::templates::admin_page(
                &state,
                PageId::Preview,
                &body,
                false,
                &session.csrf_token,
                true,
            )?)
            .into_response())
        }
    }
}

pub(super) async fn admin_preview_raw(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
    Query(q): Query<ShareQuery>,
) -> Result<Response> {
    session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let raw = q
        .path
        .ok_or(AppError(StatusCode::BAD_REQUEST, "File path missing"))?;
    let rel = path_security::validate_relative(&raw)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid path"))?
        .to_string_lossy()
        .replace('\\', "/");
    let settings = runtime_settings(&state);
    let kind = preview_kind(&rel, &settings)
        .filter(|kind| kind.is_media())
        .ok_or(AppError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Preview not allowed",
        ))?;
    raw_preview_response(
        state.secure_root.clone(),
        method,
        headers,
        rel,
        kind,
        settings.max_media_preview_size,
    )
    .await
}
