use axum::{
    extract::{Json, Multipart, OriginalUri, Path as AxPath, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use futures_util::StreamExt;
use serde::Serialize;
use tokio::io::AsyncWriteExt;

use super::{
    common::{add_upload_bytes, encoded, extension_is_blocked, internal, join_display},
    files::persist_required_file_audit,
    public::{get_share, get_storage_share},
    rendering::{storage_full_error, storage_has_room, UploadChunkReservation},
    storage_recovery_app_error,
    transfer_runtime::{
        begin_upload_reservation_cancellation_safe, limited_multipart_text, public_share_route,
        public_upload_error, upload_io_error, PendingUploadFileError, UploadQuotaReservation,
    },
    AppError, Result, MAX_UPLOAD_MULTIPART_FIELDS, MAX_UPLOAD_OPTION_FIELD_BYTES,
    MAX_UPLOAD_PATH_FIELD_BYTES, UPLOAD_QUOTA_HEARTBEAT_INTERVAL, UPLOAD_QUOTA_RESERVATION_STEP,
};
use crate::{
    auth,
    db::{
        AuditContext, Permission, UploadReservationBeginOutcome, UploadReservationCommitOutcome,
        UploadReservationExtendOutcome,
    },
    file_ops,
    http_auth::{
        audit_observation, current_audit_client_ip, current_client_limit_key, database,
        enabled_audit_client_ip, required_database, runtime_settings, share_is_unlocked,
        share_unlock_csrf, try_acquire_client_activity, with_audit_client_ip,
    },
    i18n::{self},
    path_security,
    secure_fs::PendingUpload,
    AppState,
};

pub(crate) async fn upload(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    mut multipart: Multipart,
) -> Result<Response> {
    let sh = get_share(&state, &token).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Freigabe ist gesperrt"));
    }
    if !sh.is_directory || !sh.permission.can_upload() {
        return Err(AppError(StatusCode::FORBIDDEN, "Upload nicht erlaubt"));
    }
    let required_csrf = share_unlock_csrf(&state, &headers, &sh).await?;
    if sh.password_hash.is_some() && required_csrf.is_none() {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Freigabe ist gesperrt"));
    }
    let expected_id = sh.id;
    let (sh, storage_guard) = get_storage_share(&state, &token, expected_id).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Freigabe ist gesperrt"));
    }
    if !sh.is_directory || !sh.permission.can_upload() {
        return Err(AppError(StatusCode::FORBIDDEN, "Upload nicht erlaubt"));
    }
    let required_csrf = share_unlock_csrf(&state, &headers, &sh).await?;
    if sh.password_hash.is_some() && required_csrf.is_none() {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Freigabe ist gesperrt"));
    }
    let csrf_header_valid = required_csrf.as_deref().is_some_and(|expected| {
        headers
            .get("x-vaultlink-upload-csrf")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| auth::constant_time_eq(expected, value))
    });
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
    let share_scope = state
        .secure_root
        .bind_directory(&sh.relative_path)
        .map_err(|_| AppError(StatusCode::NOT_FOUND, "Zielordner nicht verfügbar"))?;
    // The descriptor remains bound to the revalidated directory after releasing
    // the mutation lock, so a long request body cannot block admin operations.
    drop(storage_guard);
    let settings = runtime_settings(&state);
    let maximum = sh
        .max_upload_size
        .unwrap_or(settings.max_upload_size)
        .min(crate::config::MAX_UPLOAD_SIZE);
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| !storage_has_room(state.secure_root.display_root(), length))
    {
        return Ok(public_upload_error(
            &token,
            "",
            StatusCode::INSUFFICIENT_STORAGE,
            "Nicht genug freier Speicher",
        ));
    }
    let mut upload_subdir = String::new();
    let mut overwrite_existing = false;
    let mut fields_seen = 0usize;
    let mut saw_path = false;
    let mut saw_overwrite = false;
    let mut saw_csrf = false;
    let mut csrf_validated = required_csrf.is_none() || csrf_header_valid;
    let mut quota_reservation: Option<UploadQuotaReservation> = None;
    let mut prepared_upload: Option<(PendingUpload, String, u64)> = None;
    while let Some(field) = match multipart.next_field().await {
        Ok(field) => field,
        Err(_) => {
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::BAD_REQUEST,
                "Ungültiger Upload",
            ))
        }
    } {
        fields_seen += 1;
        if fields_seen > MAX_UPLOAD_MULTIPART_FIELDS {
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::BAD_REQUEST,
                "Zu viele Multipart-Felder",
            ));
        }
        let field_name = field.name().unwrap_or("").to_string();
        if field_name == "path" {
            if std::mem::replace(&mut saw_path, true) || prepared_upload.is_some() {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::BAD_REQUEST,
                    "Uploadpfad wurde mehrfach oder zu spät übermittelt",
                ));
            }
            let value = match limited_multipart_text(field, MAX_UPLOAD_PATH_FIELD_BYTES).await {
                Ok(value) => value,
                Err(_) => {
                    return Ok(public_upload_error(
                        &token,
                        &upload_subdir,
                        StatusCode::BAD_REQUEST,
                        "Ungültiger Uploadpfad",
                    ))
                }
            };
            if sh.permission == Permission::DownloadUpload {
                upload_subdir = match path_security::validate_relative(&value) {
                    Ok(path) => path.to_string_lossy().replace('\\', "/"),
                    Err(_) => {
                        return Ok(public_upload_error(
                            &token,
                            &upload_subdir,
                            StatusCode::BAD_REQUEST,
                            "Ungültiger Uploadpfad",
                        ))
                    }
                };
            }
            continue;
        }
        if field_name == "overwrite_existing" {
            if std::mem::replace(&mut saw_overwrite, true) {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::BAD_REQUEST,
                    "Uploadoption wurde mehrfach übermittelt",
                ));
            }
            let value = match limited_multipart_text(field, MAX_UPLOAD_OPTION_FIELD_BYTES).await {
                Ok(value) => value,
                Err(_) => {
                    return Ok(public_upload_error(
                        &token,
                        &upload_subdir,
                        StatusCode::BAD_REQUEST,
                        "Ungültiger Upload",
                    ))
                }
            };
            overwrite_existing = value == "1";
            if overwrite_existing && state.config.storage.external_writers {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::BAD_REQUEST,
                    "Ueberschreiben ist bei externen Storage-Schreibern deaktiviert",
                ));
            }
            continue;
        }
        if field_name == "csrf" {
            if std::mem::replace(&mut saw_csrf, true) || prepared_upload.is_some() {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::BAD_REQUEST,
                    "CSRF-Token wurde mehrfach oder zu spät übermittelt",
                ));
            }
            let value = match limited_multipart_text(field, 256).await {
                Ok(value) => value,
                Err(_) => {
                    return Ok(public_upload_error(
                        &token,
                        &upload_subdir,
                        StatusCode::FORBIDDEN,
                        "Ungültiges CSRF-Token",
                    ))
                }
            };
            csrf_validated = required_csrf
                .as_deref()
                .is_none_or(|expected| auth::constant_time_eq(expected, &value));
            if !csrf_validated {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::FORBIDDEN,
                    "Ungültiges CSRF-Token",
                ));
            }
            continue;
        }
        if field_name != "file" {
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::BAD_REQUEST,
                "Unbekanntes Multipart-Feld",
            ));
        }
        if prepared_upload.is_some() {
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::BAD_REQUEST,
                "Pro Request ist genau eine Datei erlaubt",
            ));
        }
        if !csrf_validated {
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::FORBIDDEN,
                "CSRF-Token fehlt",
            ));
        }
        let Some(file_name) = field.file_name() else {
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::BAD_REQUEST,
                "Dateiname fehlt",
            ));
        };
        let name = match path_security::safe_admin_filename(file_name) {
            Ok(name) => name.to_string(),
            Err(_) => {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::BAD_REQUEST,
                    "Ungültiger Dateiname",
                ))
            }
        };
        if extension_is_blocked(&name, &settings.blocked_extensions) {
            return Ok(public_upload_error(
                &token,
                &upload_subdir,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Dateityp blockiert",
            ));
        }
        let reservation_token = auth::random_token(32);
        let share_id = sh.id;
        let pending_ownership = begin_upload_reservation_cancellation_safe(
            state.db.clone(),
            reservation_token.clone(),
            share_id,
        )
        .await?;
        match pending_ownership.outcome() {
            UploadReservationBeginOutcome::Reserved => {
                quota_reservation = Some(UploadQuotaReservation::new(
                    state.db.clone(),
                    reservation_token,
                ));
                pending_ownership.claim();
            }
            UploadReservationBeginOutcome::ByteQuotaReached => {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Kumulatives Uploadlimit erreicht",
                ));
            }
            UploadReservationBeginOutcome::FileQuotaReached => {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Maximale Anzahl hochgeladener Dateien erreicht",
                ));
            }
            UploadReservationBeginOutcome::ShareUnavailable => {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::GONE,
                    "Freigabe nicht verfügbar",
                ));
            }
        }
        let secure_root = share_scope.clone();
        let upload_directory = upload_subdir.clone();
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
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
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
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(_) => {
                    return Ok(public_upload_error(
                        &token,
                        &upload_subdir,
                        StatusCode::BAD_REQUEST,
                        "Upload abgebrochen",
                    ))
                }
            };
            let Some(new_total) = add_upload_bytes(total, chunk.len(), maximum) else {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Upload ist zu groß",
                ));
            };
            let reservation = quota_reservation
                .as_mut()
                .expect("file field has an upload quota reservation");
            if new_total > reservation.reserved_bytes
                || reservation.last_heartbeat.elapsed() >= UPLOAD_QUOTA_HEARTBEAT_INTERVAL
            {
                let rounded_target = if new_total > reservation.reserved_bytes {
                    new_total
                        .checked_add(UPLOAD_QUOTA_RESERVATION_STEP - 1)
                        .map(|value| value / UPLOAD_QUOTA_RESERVATION_STEP)
                        .and_then(|value| value.checked_mul(UPLOAD_QUOTA_RESERVATION_STEP))
                        .unwrap_or(new_total)
                        .min(maximum)
                } else {
                    reservation.reserved_bytes
                };
                let reservation_token = reservation.token().to_string();
                let outcome = database(state.db.clone(), move |database| {
                    database.extend_upload_reservation(&reservation_token, rounded_target)
                })
                .await?;
                let mut accepted_target = rounded_target;
                let outcome = if outcome == UploadReservationExtendOutcome::ByteQuotaReached
                    && rounded_target != new_total
                {
                    accepted_target = new_total;
                    let reservation_token = reservation.token().to_string();
                    database(state.db.clone(), move |database| {
                        database.extend_upload_reservation(&reservation_token, new_total)
                    })
                    .await?
                } else {
                    outcome
                };
                match outcome {
                    UploadReservationExtendOutcome::Extended => {
                        reservation.reserved_bytes = accepted_target;
                        reservation.last_heartbeat = std::time::Instant::now();
                    }
                    UploadReservationExtendOutcome::ByteQuotaReached => {
                        return Ok(public_upload_error(
                            &token,
                            &upload_subdir,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Kumulatives Uploadlimit erreicht",
                        ));
                    }
                    UploadReservationExtendOutcome::NotFound => {
                        return Ok(public_upload_error(
                            &token,
                            &upload_subdir,
                            StatusCode::REQUEST_TIMEOUT,
                            "Uploadreservierung ist abgelaufen",
                        ));
                    }
                    UploadReservationExtendOutcome::ShareUnavailable => {
                        return Ok(public_upload_error(
                            &token,
                            &upload_subdir,
                            StatusCode::GONE,
                            "Freigabe wurde während des Uploads deaktiviert",
                        ));
                    }
                }
            }
            let Some(_reservation) = UploadChunkReservation::acquire(
                state.secure_root.display_root(),
                chunk.len() as u64,
            ) else {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Nicht genug freier Speicher",
                ));
            };
            total = new_total;
            if let Err(e) = output.write_all(&chunk).await {
                return if storage_full_error(&e) {
                    Ok(public_upload_error(
                        &token,
                        &upload_subdir,
                        StatusCode::INSUFFICIENT_STORAGE,
                        "Nicht genug freier Speicher",
                    ))
                } else {
                    Err(upload_io_error(e))
                };
            }
        }
        if let Err(e) = output.flush().await {
            return if storage_full_error(&e) {
                Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Nicht genug freier Speicher",
                ))
            } else {
                Err(upload_io_error(e))
            };
        }
        if let Err(e) = output.sync_all().await {
            return if storage_full_error(&e) {
                Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Nicht genug freier Speicher",
                ))
            } else {
                Err(upload_io_error(e))
            };
        }
        drop(output);
        prepared_upload = Some((pending, name, total));
    }
    // Finalization continues independently of the request future. In
    // particular, cancellation must not stop between the non-cancellable quota
    // commit and publication, otherwise quota could be consumed without a
    // corresponding file ever becoming visible.
    let upload_permit = _upload_permit;
    let upload_peer_permit = _upload_peer_permit;
    let audit_client_ip = current_audit_client_ip();
    let locale = i18n::current_locale();
    let return_to = i18n::current_return_to();
    let audit_context = AuditContext::new("public", enabled_audit_client_ip(&state));
    let finalizer = tokio::spawn(with_audit_client_ip(
        audit_client_ip,
        i18n::scope(locale, return_to, async move {
            let _upload_permit = upload_permit;
            let _upload_peer_permit = upload_peer_permit;
            let Some((mut pending, name, total)) = prepared_upload else {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::BAD_REQUEST,
                    "Datei fehlt",
                ));
            };
            let publish_name = name.clone();
            let allow_replace = !state.config.storage.external_writers
                && sh.upload_conflict_strategy.can_overwrite()
                && overwrite_existing;
            #[cfg(test)]
            if let Some(kind) = state
                .upload_directory_sync_failure
                .lock()
                .expect("upload sync fault lock")
                .take()
            {
                pending.fail_next_directory_sync(kind);
            }
            let storage_guard = state.storage_mutation.clone().lock_owned().await;
            let storage_guard =
                file_ops::recover_pending_file_operations_with_guard(&state, storage_guard)
                    .await
                    .map_err(storage_recovery_app_error)?;
            let current_share = get_share(&state, &token).await?;
            if current_share.id != sh.id
                || !current_share.is_directory
                || !current_share.permission.can_upload()
            {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::GONE,
                    "Freigabe wurde während des Uploads geändert",
                ));
            }
            let current_destination = match state
                .secure_root
                .bind_directory(&current_share.relative_path)
                .and_then(|scope| scope.bind_directory(&upload_subdir))
            {
                Ok(directory) => directory,
                Err(_) => {
                    return Ok(public_upload_error(
                        &token,
                        &upload_subdir,
                        StatusCode::CONFLICT,
                        "Uploadziel wurde während des Uploads geändert",
                    ));
                }
            };
            if !pending
                .destination_matches(&current_destination)
                .map_err(internal)?
            {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::CONFLICT,
                    "Uploadziel wurde während des Uploads geändert",
                ));
            }
            let destination = join_display(&upload_subdir, &name);
            let existed = match share_scope.metadata(&destination) {
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(internal(error)),
            };
            let replaced = allow_replace && existed;
            if existed && !allow_replace {
                return Ok(public_upload_error(
                    &token,
                    &upload_subdir,
                    StatusCode::CONFLICT,
                    "Datei existiert bereits.",
                ));
            }
            // Account for the upload before making the filesystem name visible. A crash
            // can therefore consume quota without publishing a file, but can never leave
            // a published file uncounted and reopen the storage-exhaustion bypass.
            let reservation = quota_reservation
                .as_mut()
                .expect("prepared upload has a quota reservation");
            let reservation_token = reservation.token().to_string();
            let quota_audit_context = audit_context.clone();
            let quota_commit = required_database(state.db.clone(), move |database| {
                database.commit_upload_reservation_and_audit(
                    &reservation_token,
                    total,
                    &quota_audit_context,
                )
            })
            .await?;
            match quota_commit {
                UploadReservationCommitOutcome::Committed => reservation.committed(),
                UploadReservationCommitOutcome::NotFound => {
                    return Ok(public_upload_error(
                        &token,
                        &upload_subdir,
                        StatusCode::REQUEST_TIMEOUT,
                        "Uploadreservierung ist abgelaufen",
                    ));
                }
                UploadReservationCommitOutcome::ShareUnavailable => {
                    return Ok(public_upload_error(
                        &token,
                        &upload_subdir,
                        StatusCode::GONE,
                        "Freigabe wurde während des Uploads deaktiviert",
                    ));
                }
            }
            let publish_result = tokio::task::spawn_blocking(move || {
                // A disconnected client drops the future, but the filesystem publish
                // continues. Keep it serialized until that blocking task really ends.
                let _storage_guard = storage_guard;
                if allow_replace {
                    pending.publish_replace(&publish_name)
                } else {
                    pending.publish(&publish_name)
                }
            })
            .await
            .map_err(internal)?;
            let publish_outcome = match publish_result {
                Ok(outcome) => outcome,
                Err(error) => {
                    if error.kind() == std::io::ErrorKind::AlreadyExists {
                        return Ok(public_upload_error(
                            &token,
                            &upload_subdir,
                            StatusCode::CONFLICT,
                            "Datei existiert bereits.",
                        ));
                    }
                    return if storage_full_error(&error) {
                        Ok(public_upload_error(
                            &token,
                            &upload_subdir,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Nicht genug freier Speicher",
                        ))
                    } else {
                        Err(internal(error))
                    };
                }
            };
            let durability_uncertain = !publish_outcome.is_durable();
            let audit_detail = format!("file={name};bytes={total}");
            if let Some(error) = publish_outcome.sync_error() {
                tracing::warn!(share_id = sh.id, file = %name, %error, "upload published but directory fsync failed");
                audit_observation(
                    &state,
                    "public".into(),
                    "upload_durability_uncertain",
                    Some(sh.id.to_string()),
                    Some(audit_detail.clone()),
                )
                .await;
            }
            let audit_durability_uncertain = persist_required_file_audit(
                &state,
                audit_context,
                if replaced {
                    "upload_replaced"
                } else {
                    "upload"
                },
                sh.id.to_string(),
                audit_detail,
            )
            .await;
            let upload_status = if audit_durability_uncertain {
                "audit_uncertain"
            } else {
                match (replaced, durability_uncertain) {
                    (true, true) => "replaced_uncertain",
                    (false, true) => "uncertain",
                    (true, false) => "replaced",
                    (false, false) => "ok",
                }
            };
            let public_route = public_share_route(&uri, &token);
            let target = if upload_subdir.is_empty() {
                format!("{public_route}?upload={upload_status}")
            } else {
                format!(
                    "{public_route}?path={}&upload={upload_status}",
                    encoded(&upload_subdir)
                )
            };
            let outcome = match (replaced, durability_uncertain) {
                (true, true) => "replaced_uncertain",
                (false, true) => "created_uncertain",
                (true, false) => "replaced",
                (false, false) => "created",
            };
            let mut response = Redirect::to(&target).into_response();
            response.headers_mut().insert(
                "x-vaultlink-upload-file",
                HeaderValue::from_str(&encoded(&name)).map_err(internal)?,
            );
            response.headers_mut().insert(
                "x-vaultlink-upload-outcome",
                HeaderValue::from_static(outcome),
            );
            if durability_uncertain {
                response.headers_mut().insert(
                    "x-vaultlink-durability",
                    HeaderValue::from_static("uncertain"),
                );
            }
            if audit_durability_uncertain {
                response.headers_mut().insert(
                    "x-vaultlink-audit-durability",
                    HeaderValue::from_static("uncertain"),
                );
            }
            Ok(response)
        }),
    ));
    finalizer.await.map_err(internal)?
}

#[derive(Serialize)]
pub(super) struct UploadQueueSuccess {
    pub(super) file: String,
    pub(super) outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) warning: Option<&'static str>,
}

#[derive(Serialize)]
pub(super) struct UploadQueueErrorEnvelope {
    error: UploadQueueError,
}

#[derive(Serialize)]
pub(super) struct UploadQueueError {
    code: String,
    message: String,
}

pub(super) fn upload_queue_error_response(status: StatusCode, message: &str) -> Response {
    let code = match status {
        StatusCode::SERVICE_UNAVAILABLE
            if message == crate::http_auth::AUDIT_UNAVAILABLE_MESSAGE =>
        {
            "audit_unavailable"
        }
        StatusCode::BAD_REQUEST => "invalid_upload",
        StatusCode::UNAUTHORIZED => "share_locked",
        StatusCode::FORBIDDEN => "upload_forbidden",
        StatusCode::NOT_FOUND => "target_not_found",
        StatusCode::CONFLICT => "file_exists",
        StatusCode::PAYLOAD_TOO_LARGE => "upload_too_large",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "blocked_extension",
        StatusCode::INSUFFICIENT_STORAGE => "insufficient_storage",
        _ => "upload_failed",
    };
    let message = i18n::text_from_german(i18n::current_locale(), message);
    (
        status,
        Json(UploadQueueErrorEnvelope {
            error: UploadQueueError {
                code: code.to_string(),
                message,
            },
        }),
    )
        .into_response()
}

pub(super) async fn upload_queue(
    state: State<AppState>,
    uri: OriginalUri,
    headers: HeaderMap,
    token: AxPath<String>,
    multipart: Multipart,
) -> Result<Response> {
    let response = match upload(state, uri, headers, token, multipart).await {
        Ok(response) => response,
        Err(AppError(status, message)) => {
            return Ok(upload_queue_error_response(status, message));
        }
    };
    if response.status().is_redirection() {
        let (file, outcome, audit_uncertain) = upload_success_metadata(&response);
        let status = if audit_uncertain {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        };
        return Ok((
            status,
            Json(UploadQueueSuccess {
                file,
                outcome,
                warning: audit_uncertain.then_some("audit_durability_uncertain"),
            }),
        )
            .into_response());
    }

    let status = response.status();
    Ok(upload_queue_error_response(
        status,
        status.canonical_reason().unwrap_or("Upload fehlgeschlagen"),
    ))
}

/// Preserve the established redirect response for ordinary API uploads, but
/// surface a post-publication audit failure as an explicit non-retryable JSON
/// success. At this point the filesystem effect is already visible.
pub(crate) async fn upload_api(
    state: State<AppState>,
    uri: OriginalUri,
    headers: HeaderMap,
    token: AxPath<String>,
    multipart: Multipart,
) -> Result<Response> {
    let response = upload(state, uri, headers, token, multipart).await?;
    if !response.status().is_redirection() {
        return Ok(response);
    }
    let (file, outcome, audit_uncertain) = upload_success_metadata(&response);
    if !audit_uncertain {
        return Ok(response);
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(UploadQueueSuccess {
            file,
            outcome,
            warning: Some("audit_durability_uncertain"),
        }),
    )
        .into_response())
}

fn upload_success_metadata(response: &Response) -> (String, String, bool) {
    let file = response
        .headers()
        .get("x-vaultlink-upload-file")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            percent_encoding::percent_decode_str(value)
                .decode_utf8_lossy()
                .into_owned()
        })
        .unwrap_or_default();
    let outcome = response
        .headers()
        .get("x-vaultlink-upload-outcome")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("created")
        .to_string();
    let audit_uncertain = response
        .headers()
        .get("x-vaultlink-audit-durability")
        .is_some_and(|value| value == "uncertain");
    (file, outcome, audit_uncertain)
}
