use askama::Template;
use axum::{
    body::Body,
    extract::{Form, Json, Multipart, Query, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;

use super::{
    admission::PermitBody,
    common::{
        add_upload_bytes, breadcrumbs, encoded, extension_is_blocked, file_sort_column,
        file_sort_column_value, file_sort_direction, file_sort_direction_value, file_sort_header,
        format_file_time, human, internal, join_display, list_directory_sorted_page, parent_path,
        preview_allowed, preview_kind, search_tree, sort_search_hits, BrowseQuery,
    },
    preview_zip::{raw_preview_response, read_preview, PreviewContent},
    public_preview::text_preview_render_permits,
    rendering::{
        admin_page, disk_stats, esc, escaped_html_len, storage_has_room, PageId,
        UploadChunkReservation,
    },
    shares::{share_is_available, ShareQuery},
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
    let (confirmation, form_attributes, button_attributes) = if inspection
        .status
        .directory_non_empty
    {
        (
            format!(
                r#"<div class="vl-form-card"><p class="vl-danger-text"><strong><vl-i18n key="common.warning"/></strong> <vl-i18n key="files.folder_not_empty"/></p><label class="vl-field"><vl-i18n key="files.confirm_folder_name"/> <code>{}</code> <vl-i18n key="files.enter"/><input name="confirm_name" autocomplete="off" data-confirm-input autofocus required></label></div>"#,
                esc(&inspection.name)
            ),
            format!(
                r#" data-delete-confirmation data-required-name="{}""#,
                esc(&inspection.name)
            ),
            " data-confirm-delete disabled",
        )
    } else {
        (String::new(), String::new(), "")
    };
    let body = format!(
        r#"<section class="vl-panel vl-confirm-card"><h2>{}</h2><p><code>/{}</code></p><p class="vl-danger-text"><vl-i18n key="files.delete_irreversible"/></p><p><vl-i18n key="files.affected_shares"/> <strong>{}</strong></p><form method="post" action="/admin/files/delete" class="vl-stack"{form_attributes}><input type="hidden" name="csrf" value="{}"><input type="hidden" name="path" value="{}">{}<div class="vl-inline-actions"><button class="vl-button vl-button--danger"{button_attributes}><vl-i18n key="files.permanent_delete"/></button><a class="vl-button vl-button--secondary" href="/admin?path={}"><vl-i18n key="common.cancel"/></a></div></form></section>"#,
        esc(&heading),
        esc(&inspection.path),
        inspection.affected_shares,
        esc(&admin.csrf_token),
        esc(&inspection.path),
        confirmation,
        encoded(parent_path(&inspection.path).as_deref().unwrap_or("")),
    );
    Ok(Html(admin_page(
        &state,
        PageId::DeleteConfirm,
        &body,
        false,
        &admin.csrf_token,
    )))
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
        .ok_or(AppError(StatusCode::BAD_REQUEST, "Dateiname fehlt"))?;
    let name = path_security::safe_admin_filename(file_name)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Dateiname"))?
        .to_string();
    if extension_is_blocked(&name, blocked_extensions) {
        return Err(AppError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Dateityp blockiert",
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
            return Err(AppError(
                StatusCode::NOT_FOUND,
                "Zielordner nicht verfügbar",
            ))
        }
        Err(PendingUploadFileError::Take(error)) => return Err(upload_io_error(error)),
    };

    let mut output = tokio::fs::File::from_std(file);
    let mut total = 0u64;
    let stream = field;
    tokio::pin!(stream);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| AppError(StatusCode::BAD_REQUEST, "Upload abgebrochen"))?;
        let Some(new_total) = add_upload_bytes(total, chunk.len(), maximum) else {
            return Err(AppError(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Upload ist zu groß",
            ));
        };
        let Some(_reservation) =
            UploadChunkReservation::acquire(state.secure_root.display_root(), chunk.len() as u64)
        else {
            return Err(AppError(
                StatusCode::INSUFFICIENT_STORAGE,
                "Nicht genug freier Speicher",
            ));
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
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Ordnerpfad"))?
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
            AppError(StatusCode::BAD_REQUEST, "Ungültiger Ordnerpfad")
        }
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => AppError(
            StatusCode::CONFLICT,
            "Uploadordner konnte nicht erstellt werden",
        ),
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
                "Zu viele gleichzeitige Uploads",
            )
        })?;
    let _upload_peer_permit = try_acquire_client_activity(
        state.upload_peer_admission.clone(),
        current_client_limit_key(),
        crate::MAX_IN_FLIGHT_UPLOADS_PER_CLIENT,
    )
    .map_err(internal)?
    .ok_or(AppError(
        StatusCode::SERVICE_UNAVAILABLE,
        "Zu viele gleichzeitige Uploads dieses Clients",
    ))?;
    let settings = runtime_settings(state);
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| !storage_has_room(state.secure_root.display_root(), length))
    {
        return Err(AppError(
            StatusCode::INSUFFICIENT_STORAGE,
            "Nicht genug freier Speicher",
        ));
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
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Upload"))?
    {
        fields_seen += 1;
        if fields_seen > 5 {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "Zu viele Multipart-Felder",
            ));
        }
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "path" => {
                if directory.is_some() || staged.is_some() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "Uploadpfad wurde mehrfach oder zu spät übermittelt",
                    ));
                }
                let value = limited_multipart_text(field, MAX_UPLOAD_PATH_FIELD_BYTES)
                    .await
                    .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Uploadpfad"))?;
                let value = path_security::validate_relative(&value)
                    .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Uploadpfad"))?
                    .to_string_lossy()
                    .replace('\\', "/");
                directory = Some(value);
            }
            "csrf" => {
                if csrf_value.is_some() || staged.is_some() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "CSRF-Nachweis wurde mehrfach oder zu spät übermittelt",
                    ));
                }
                let value = limited_multipart_text(field, 512)
                    .await
                    .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger CSRF-Nachweis"))?;
                csrf(&admin, &value)?;
                csrf_value = Some(value);
            }
            "overwrite_existing" => {
                if std::mem::replace(&mut saw_overwrite, true) || staged.is_some() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "Uploadoption wurde mehrfach oder zu spät übermittelt",
                    ));
                }
                let value = limited_multipart_text(field, MAX_UPLOAD_OPTION_FIELD_BYTES)
                    .await
                    .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültige Uploadoption"))?;
                overwrite_existing = value == "1";
                if overwrite_existing && !state.config.storage.replacements_allowed() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "Ueberschreiben ist bei externen Storage-Schreibern deaktiviert",
                    ));
                }
            }
            "folder_path" => {
                if folder_path.is_some() || staged.is_some() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "Ordnerpfad wurde mehrfach oder zu spät übermittelt",
                    ));
                }
                let value = limited_multipart_text(field, MAX_UPLOAD_PATH_FIELD_BYTES)
                    .await
                    .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Ordnerpfad"))?;
                let value = path_security::validate_relative(&value)
                    .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Ordnerpfad"))?
                    .to_string_lossy()
                    .replace('\\', "/");
                folder_path = Some(value);
            }
            "file" => {
                if staged.is_some() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "Pro Request ist genau eine Datei erlaubt",
                    ));
                }
                let target = directory.as_deref().ok_or(AppError(
                    StatusCode::BAD_REQUEST,
                    "Uploadpfad muss vor der Datei übermittelt werden",
                ))?;
                if csrf_value.is_none() {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        "CSRF-Nachweis muss vor der Datei übermittelt werden",
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
            _ => {
                return Err(AppError(
                    StatusCode::BAD_REQUEST,
                    "Unbekanntes Multipart-Feld",
                ))
            }
        }
    }

    let mut directory = directory.ok_or(AppError(StatusCode::BAD_REQUEST, "Uploadpfad fehlt"))?;
    if let Some(folder_path) = folder_path.as_deref() {
        directory = join_display(&directory, folder_path);
    }
    if csrf_value.is_none() {
        return Err(AppError(StatusCode::FORBIDDEN, "CSRF-Nachweis fehlt"));
    }
    let (mut pending, name, total) = staged.ok_or(AppError(
        StatusCode::BAD_REQUEST,
        "Pro Request ist genau eine Datei erforderlich",
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
                "Uploadziel wurde zwischenzeitlich geändert",
            )
        })?;
        if !pending
            .destination_matches(&current_destination)
            .map_err(internal)?
        {
            return Err(AppError(
                StatusCode::CONFLICT,
                "Uploadziel wurde zwischenzeitlich geändert",
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
                    "Datei existiert bereits; Ersetzen muss für diese Datei bestätigt werden",
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
        FileOperationError::InvalidPath => AppError(StatusCode::BAD_REQUEST, "Ungültiger Pfad"),
        FileOperationError::InvalidName => AppError(StatusCode::BAD_REQUEST, "Ungültiger Name"),
        FileOperationError::NotFound => AppError(StatusCode::NOT_FOUND, "Ziel nicht gefunden"),
        FileOperationError::Conflict => {
            AppError(StatusCode::CONFLICT, "Zielname ist bereits vorhanden")
        }
        FileOperationError::ConfirmationRequired { .. } => AppError(
            StatusCode::CONFLICT,
            "Der exakte Ordnername muss bestätigt werden",
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

pub(super) fn file_row_actions(
    path: &str,
    name: &str,
    csrf_token: &str,
    is_directory: bool,
) -> String {
    let download = if is_directory {
        String::new()
    } else {
        format!(
            r#"<a class="vl-button vl-button--secondary vl-button--small" href="/admin/files/download?path={}"><vl-i18n key="common.download"/></a>"#,
            encoded(path)
        )
    };
    format!(
        r#"<a class="vl-button vl-button--secondary vl-button--small" href="/admin/shares/new?path={}"><vl-i18n key="files.share_action"/></a>{download}<details class="vl-action-details"><summary class="vl-icon-button" aria-label="<vl-i18n key="share.more_aria"/>">{}</summary><div class="vl-action-panel"><form method="post" action="/admin/files/rename" class="vl-stack"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="path" value="{}"><label class="vl-field"><vl-i18n key="files.new_name"/><input name="name" value="{}" maxlength="255" required></label><button class="vl-button vl-button--small"><vl-i18n key="common.rename"/></button></form><a class="vl-button vl-button--danger vl-button--small" href="/admin/files/delete?path={}">{} <vl-i18n key="common.delete"/></a></div></details>"#,
        encoded(path),
        crate::ui::icon(crate::ui::Icon::More),
        esc(csrf_token),
        esc(path),
        esc(name),
        encoded(path),
        crate::ui::icon(crate::ui::Icon::Trash),
    )
}

pub(super) fn file_name_cell(path: &str, display_name: &str, is_directory: bool) -> String {
    let target = encoded(path);
    let icon = crate::ui::icon(if is_directory {
        crate::ui::Icon::Folder
    } else {
        crate::ui::Icon::File
    });
    let label = if is_directory {
        format!(
            r#"<a href="/admin?path={target}">{}</a>"#,
            esc(display_name)
        )
    } else {
        esc(display_name)
    };
    format!(
        r#"<label class="vl-file-select"><input type="radio" name="selected_path" value="{}" data-file-select><span>{icon}{label}</span></label>"#,
        esc(path)
    )
}

pub(super) async fn admin_browser(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<BrowseQuery>,
) -> Result<Html<String>> {
    let (_, s) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let settings = runtime_settings(&state);
    let disk = disk_stats(state.secure_root.display_root());
    let used_storage = disk
        .as_ref()
        .map(|stats| stats.total.saturating_sub(stats.free))
        .map(human)
        .unwrap_or_else(|| "n/v".into());
    let free_storage = disk
        .as_ref()
        .map(|stats| human(stats.free))
        .unwrap_or_else(|| "n/v".into());
    let active_links = database(state.db.clone(), |database| database.list_shares())
        .await?
        .into_iter()
        .filter(share_is_available)
        .count();
    let sort_column = file_sort_column(q.sort.as_deref());
    let sort_direction = file_sort_direction(q.direction.as_deref());
    let raw = q.path.unwrap_or_default();
    let page_number = q.page.unwrap_or(0).min(1_000_000);
    let search =
        q.q.map(|value| value.trim().to_string())
            .filter(|v| !v.is_empty());
    if search
        .as_ref()
        .is_some_and(|value| value.len() > MAX_SEARCH_QUERY_BYTES)
    {
        return Err(AppError(StatusCode::BAD_REQUEST, "Suchbegriff ist zu lang"));
    }
    let rel = path_security::validate_relative(&raw)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Pfad"))?
        .to_string_lossy()
        .replace('\\', "/");
    let secure_root = state.secure_root.clone();
    let _scan_peer_permit = try_acquire_client_activity(
        state.expensive_peer_admission.clone(),
        current_client_limit_key(),
        crate::MAX_EXPENSIVE_OPERATIONS_PER_CLIENT,
    )
    .map_err(internal)?
    .ok_or(AppError(
        StatusCode::SERVICE_UNAVAILABLE,
        "Zu viele gleichzeitige aufwendige Vorgänge dieses Clients",
    ))?;
    let _scan_permit = state
        .search_admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            AppError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Zu viele gleichzeitige Dateisuchen",
            )
        })?;
    let mut rows = String::new();
    let mut has_next = false;
    if let Some(search) = search.clone() {
        let base = rel.clone();
        let search_settings = settings.clone();
        let mut hits = tokio::task::spawn_blocking(move || {
            search_tree(secure_root, &base, &search, &search_settings)
        })
        .await
        .map_err(internal)?
        .map_err(internal)?;
        sort_search_hits(&mut hits, sort_column, sort_direction);
        for hit in hits {
            let target = encoded(&hit.relative_path);
            let actions = file_row_actions(
                &hit.relative_path,
                &hit.entry.name,
                &s.csrf_token,
                hit.entry.is_dir,
            );
            let preview = if !hit.entry.is_dir && preview_allowed(&hit.relative_path, &settings) {
                format!(
                    r#"<a class="vl-button vl-button--secondary vl-button--small" href="/admin/preview?path={target}"><vl-i18n key="common.view"/></a> "#
                )
            } else {
                String::new()
            };
            let modified = hit
                .entry
                .modified
                .map(format_file_time)
                .unwrap_or_else(|| "—".into());
            rows += &format!(
                r#"<tr><td data-label="<vl-i18n key="common.name"/>">{}</td><td data-label="<vl-i18n key="common.type"/>">{}</td><td data-label="<vl-i18n key="common.size"/>">{}</td><td data-label="<vl-i18n key="common.changed"/>">{}</td><td data-label="<vl-i18n key="common.action"/>"><div class="vl-inline-actions">{}{}</div></td></tr>"#,
                file_name_cell(&hit.relative_path, &hit.relative_path, hit.entry.is_dir),
                i18n::text(
                    i18n::current_locale(),
                    if hit.entry.is_dir {
                        i18n::FOLDER
                    } else {
                        i18n::FILE
                    }
                ),
                if hit.entry.is_dir {
                    "—".into()
                } else {
                    human(hit.entry.len)
                },
                modified,
                preview,
                actions
            );
        }
    } else {
        let listing_path = rel.clone();
        let scan_limit = settings.max_search_entries;
        let (entries, truncated) = tokio::task::spawn_blocking(move || {
            list_directory_sorted_page(
                &secure_root,
                &listing_path,
                page_number,
                scan_limit,
                sort_column,
                sort_direction,
            )
        })
        .await
        .map_err(internal)?
        .map_err(internal)?;
        has_next = entries.len() > 100;
        for entry in entries.into_iter().take(100) {
            let name = entry.name;
            let is_dir = entry.is_dir;
            let size = entry.len;
            let modified = entry.modified;
            let child = join_display(&rel, &name);
            let target = encoded(&child);
            let actions = file_row_actions(&child, &name, &s.csrf_token, is_dir);
            let display = file_name_cell(&child, &name, is_dir);
            let preview = if !is_dir && preview_allowed(&child, &settings) {
                format!(
                    r#"<a class="vl-button vl-button--secondary vl-button--small" href="/admin/preview?path={target}"><vl-i18n key="common.view"/></a> "#
                )
            } else {
                String::new()
            };
            let modified = modified.map(format_file_time).unwrap_or_else(|| "—".into());
            rows += &format!(
                r#"<tr><td data-label="<vl-i18n key="common.name"/>">{display}</td><td data-label="<vl-i18n key="common.type"/>">{}</td><td data-label="<vl-i18n key="common.size"/>">{}</td><td data-label="<vl-i18n key="common.changed"/>">{}</td><td data-label="<vl-i18n key="common.action"/>"><div class="vl-inline-actions">{}{}</div></td></tr>"#,
                i18n::text(
                    i18n::current_locale(),
                    if is_dir { i18n::FOLDER } else { i18n::FILE }
                ),
                if is_dir { "—".into() } else { human(size) },
                modified,
                preview,
                actions
            );
        }
        if truncated {
            rows += r#"<tr><td colspan="5" class="vl-muted"><vl-i18n key="files.scan_limit"/></td></tr>"#;
        }
    }
    let encoded_path = encoded(&rel);
    let current_folder_target = if raw.is_empty() {
        ".".to_string()
    } else {
        encoded_path.clone()
    };
    let search_value = search.as_deref().unwrap_or("");
    let search_param = if search_value.is_empty() {
        String::new()
    } else {
        format!("&q={}", encoded(search_value))
    };
    let sort_param = format!(
        "&sort={}&direction={}",
        file_sort_column_value(sort_column),
        file_sort_direction_value(sort_direction)
    );
    let previous = if page_number > 0 {
        format!(
            "<a href=\"/admin?path={encoded_path}&page={}{}{}\"><vl-i18n key=\"common.back\"/></a>",
            page_number - 1,
            search_param,
            sort_param,
        )
    } else {
        String::new()
    };
    let next = if has_next {
        format!(
            "<a href=\"/admin?path={encoded_path}&page={}{}{}\"><vl-i18n key=\"common.continue\"/></a>",
            page_number + 1,
            search_param,
            sort_param,
        )
    } else {
        String::new()
    };
    let up = parent_path(&rel)
        .map(|parent| {
            format!(
                r#"<a class="vl-button vl-button--ghost" href="/admin?path={}"><vl-i18n key="files.up"/></a>"#,
                encoded(&parent)
            )
        })
        .unwrap_or_default();
    let notice = match q.notice.as_deref() {
        Some("directory_created") => "<p class=\"vl-notice vl-notice--success\"><vl-i18n key=\"files.folder_created\"/></p>",
        Some("path_renamed") => "<p class=\"vl-notice vl-notice--success\"><vl-i18n key=\"files.entry_renamed\"/></p>",
        Some("path_deleted") => "<p class=\"vl-notice vl-notice--success\"><vl-i18n key=\"files.entry_deleted\"/></p>",
        Some("path_delete_queued") => {
            "<p class=\"vl-notice vl-notice--success\"><vl-i18n key=\"files.entry_removed_cleanup\"/></p>"
        }
        Some("audit_durability_uncertain") => {
            "<p class=\"vl-notice\"><strong><vl-i18n key=\"common.warning\"/></strong> <vl-i18n key=\"files.audit_durability_uncertain\"/></p>"
        }
        Some("upload_ok") => {
            "<p class=\"vl-notice vl-notice--success\"><vl-i18n key=\"files.uploaded\"/></p>"
        }
        _ => "",
    };
    let create_form = format!(
        r#"<details class="vl-create-folder"><summary class="vl-button vl-button--secondary"><vl-i18n key="files.new_folder"/></summary><form method="post" action="/admin/files/directories" class="vl-create-folder__form"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="parent" value="{}"><label class="vl-field vl-create-folder__field"><span><vl-i18n key="files.folder_name"/></span><input name="name" maxlength="255" required></label><button class="vl-button"><vl-i18n key="files.create_folder"/></button></form></details>"#,
        esc(&s.csrf_token),
        esc(&rel),
    );
    let overwrite_control = if !state.config.storage.replacements_allowed() {
        ""
    } else {
        r#"<label class="vl-switch"><input type="checkbox" name="overwrite_existing" value="1"><span><vl-i18n key="share.replace_conflict"/><small><vl-i18n key="share.after_conflict"/></small></span></label>"#
    };
    let upload_form = format!(
        r#"<details class="vl-create-folder vl-upload-dialog"><summary class="vl-button vl-button--secondary">{} <vl-i18n key="upload.files"/></summary><form method="post" enctype="multipart/form-data" action="/admin/files/upload" class="vl-stack" data-upload-queue data-queue-endpoint="/admin/files/upload/queue"><input type="hidden" name="path" value="{}"><input type="hidden" name="csrf" value="{}"><div class="vl-panel-head"><div><strong><vl-i18n key="upload.admin"/></strong><p class="vl-muted"><vl-i18n key="upload.sequential"/></p></div><button class="vl-button vl-button--ghost vl-button--small" type="button" data-details-close><vl-i18n key="common.close"/></button></div>{}<label class="vl-upload-dropzone" data-upload-dropzone><strong><vl-i18n key="upload.drop_here"/></strong><span class="vl-muted"><vl-i18n key="upload.or_add"/></span><input class="vl-upload-input" type="file" name="file" required data-upload-input></label><div class="vl-inline-actions"><label class="vl-button vl-button--secondary vl-button--small">{} <vl-i18n key="upload.folder"/><input class="vl-sr-only" type="file" webkitdirectory directory multiple data-upload-folder-input></label></div><div class="vl-upload-queue" data-upload-list role="status" aria-live="polite"></div><button class="vl-button" data-upload-submit><vl-i18n key="upload.start"/></button></form></details>"#,
        crate::ui::icon(crate::ui::Icon::Upload),
        esc(&rel),
        esc(&s.csrf_token),
        overwrite_control,
        crate::ui::icon(crate::ui::Icon::Folder),
    );
    let name_header = file_sort_header(
        "<vl-i18n key=\"common.name\"/>",
        super::common::FileSortColumn::Name,
        sort_column,
        sort_direction,
        "/admin",
        &rel,
        search.as_deref(),
    );
    let type_header = file_sort_header(
        "<vl-i18n key=\"common.type\"/>",
        super::common::FileSortColumn::Type,
        sort_column,
        sort_direction,
        "/admin",
        &rel,
        search.as_deref(),
    );
    let size_header = file_sort_header(
        "<vl-i18n key=\"common.size\"/>",
        super::common::FileSortColumn::Size,
        sort_column,
        sort_direction,
        "/admin",
        &rel,
        search.as_deref(),
    );
    let modified_header = file_sort_header(
        "<vl-i18n key=\"common.changed\"/>",
        super::common::FileSortColumn::Modified,
        sort_column,
        sort_direction,
        "/admin",
        &rel,
        search.as_deref(),
    );
    let listing = format!(
        r#"<section class="vl-stat-strip" aria-label="<vl-i18n key="audit.storage_aria"/>"><div><strong>{}</strong><span><vl-i18n key="common.used"/></span></div><div><strong>{}</strong><span><vl-i18n key="common.free"/></span></div><div><strong>{}</strong><span><vl-i18n key="share.active_links"/></span></div></section><section class="vl-panel"><div class="vl-browser-head"><div>{}<p class="vl-muted"><vl-i18n key="files.relative_path"/>: /{}</p></div><div class="vl-inline-actions">{}{}{}<a class="vl-button" href="/admin/shares/new?path={}"><vl-i18n key="share.current_folder"/></a></div></div><form method="get" class="vl-toolbar"><input type="hidden" name="path" value="{}"><input type="hidden" name="sort" value="{}"><input type="hidden" name="direction" value="{}"><label class="vl-field vl-search"><span class="vl-sr-only"><vl-i18n key="files.browse"/></span><input name="q" value="{}" placeholder="<vl-i18n key="files.search_placeholder"/>"></label><button class="vl-button"><vl-i18n key="common.search"/></button></form><div class="vl-table-wrap"><table class="vl-data-table"><thead><tr>{}{}{}{}<th><vl-i18n key="common.action"/></th></tr></thead><tbody>{}</tbody></table></div><nav class="vl-pagination" aria-label="<vl-i18n key="files.pages_aria"/>">{} {}</nav><p class="vl-muted"><vl-i18n key="files.entries_page"/></p></section><div class="vl-selection-bar" data-selection-bar hidden><span data-selection-name><vl-i18n key="share.one_selected"/></span><a class="vl-button" data-selection-share href="/admin/shares/new"><vl-i18n key="share.selection"/></a></div>"#,
        esc(&used_storage),
        esc(&free_storage),
        active_links,
        breadcrumbs(&rel, "/admin"),
        esc(&rel),
        up,
        create_form,
        upload_form,
        current_folder_target,
        esc(&rel),
        file_sort_column_value(sort_column),
        file_sort_direction_value(sort_direction),
        esc(search_value),
        name_header,
        type_header,
        size_header,
        modified_header,
        rows,
        previous,
        next,
    );
    let body = format!("{notice}{listing}");
    Ok(Html(admin_page(
        &state,
        PageId::Files,
        &body,
        false,
        &s.csrf_token,
    )))
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
        .ok_or(AppError(StatusCode::BAD_REQUEST, "Dateipfad fehlt"))?;
    let relative = path_security::validate_relative(&raw)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Dateipfad"))?
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
        std::io::ErrorKind::InvalidInput => AppError(StatusCode::BAD_REQUEST, "Keine Datei"),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
            AppError(StatusCode::NOT_FOUND, "Datei nicht verfügbar")
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
        .ok_or(AppError(StatusCode::BAD_REQUEST, "Dateipfad fehlt"))?;
    let rel = path_security::validate_relative(&raw)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Pfad"))?
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
                        "Zu viele gleichzeitige Textvorschauen",
                    )
                })?,
        )
    } else {
        None
    };
    let secure_root = state.secure_root.clone();
    let preview_path = rel.clone();
    let content =
        tokio::task::spawn_blocking(move || read_preview(secure_root, &preview_path, &settings))
            .await
            .map_err(internal)?
            .map_err(|_| AppError(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Vorschau nicht erlaubt"))?;
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
            let body =
                preview_too_large_body(&rel, size, "Datei ist größer als das Preview-Limit.", None);
            Ok(Html(admin_page(
                &state,
                PageId::Preview,
                &body,
                false,
                &session.csrf_token,
            ))
            .into_response())
        }
        PreviewContent::Media { kind, size } => {
            let body = admin_media_preview_body(&rel, kind, size);
            Ok(Html(admin_page(
                &state,
                PageId::Preview,
                &body,
                false,
                &session.csrf_token,
            ))
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
        .ok_or(AppError(StatusCode::BAD_REQUEST, "Dateipfad fehlt"))?;
    let rel = path_security::validate_relative(&raw)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Pfad"))?
        .to_string_lossy()
        .replace('\\', "/");
    let settings = runtime_settings(&state);
    let kind = preview_kind(&rel, &settings)
        .filter(|kind| kind.is_media())
        .ok_or(AppError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Vorschau nicht erlaubt",
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

pub(super) fn admin_media_preview_body(path: &str, kind: PreviewKind, size: u64) -> String {
    let raw = format!("/admin/preview/raw?path={}", encoded(path));
    let viewer = media_viewer(kind, &raw);
    format!(
        r#"<section class="vl-panel"><p class="vl-inline-actions"><a class="vl-button vl-button--secondary" href="/admin?path={}"><vl-i18n key="files.back_to_folder"/></a></p><p><code>/{}</code> <span class="vl-muted">{}</span></p>{}</section>"#,
        encoded(parent_path(path).as_deref().unwrap_or("")),
        esc(path),
        human(size),
        viewer
    )
}

pub(super) fn media_viewer(kind: PreviewKind, raw_url: &str) -> String {
    match kind {
        PreviewKind::Image(_) => format!(
            r#"<img class="vl-media-preview vl-media-preview--image" src="{}" alt="<vl-i18n key="files.preview_alt"/>">"#,
            esc(raw_url)
        ),
        PreviewKind::Pdf => format!(
            r#"<iframe class="vl-media-preview vl-media-preview--pdf" src="{}" title="<vl-i18n key="files.pdf_preview"/>"></iframe>"#,
            esc(raw_url)
        ),
        PreviewKind::Text => String::new(),
    }
}

pub(super) fn preview_too_large_body(
    path: &str,
    size: u64,
    message: &str,
    download_link: Option<&str>,
) -> String {
    let message = i18n::text_from_german(i18n::current_locale(), message);
    let is_public = download_link.is_some();
    let back = if is_public {
        String::new()
    } else {
        format!(
            r#"<a href="/admin?path={}"><vl-i18n key="files.back_to_folder"/></a>"#,
            encoded(parent_path(path).as_deref().unwrap_or(""))
        )
    };
    let heading = if is_public {
        r#"<h1><vl-i18n key="files.preview"/></h1>"#
    } else {
        ""
    };
    format!(
        r#"<section class="vl-panel">{}<p class="vl-inline-actions">{}</p><p><code>/{}</code></p><p class="vl-muted">{} <vl-i18n key="files.size_label"/>: {}.</p></section>"#,
        heading,
        back,
        esc(path),
        esc(&message),
        human(size)
    )
}
