use std::path::Path;

use axum::{
    body::Body,
    extract::{OriginalUri, Path as AxPath, Query, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::Response,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use crate::{
    http_auth::{
        current_client_limit_key, database, runtime_settings, share_is_unlocked,
        try_acquire_client_activity,
    },
    path_security,
    range::parse_byte_range,
    secure_fs::SecureFile,
    AppState,
};

use super::preview_zip::{
    build_zip_temp, direct_zip_stream, plan_zip, zip_error, ReservedZipStream, ZipTempReservation,
};
use super::{
    begin_public_transfer, check_public_transfer_availability, complete_transfer_without_body,
    encoded, get_share, get_storage_share, internal, set_transfer_cookie, transfer_body, AppError,
    BrowseQuery, PeerPermitBody, PermitBody, Result,
};

pub(crate) async fn download_zip(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response> {
    let sh = get_share(&state, &token).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Freigabe ist gesperrt"));
    }
    if !sh.is_directory || !sh.permission.can_download() {
        return Err(AppError(
            StatusCode::FORBIDDEN,
            "ZIP-Download nicht erlaubt",
        ));
    }
    let expected_id = sh.id;
    let (sh, storage_guard) = get_storage_share(&state, &token, expected_id).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Freigabe ist gesperrt"));
    }
    if !sh.is_directory || !sh.permission.can_download() {
        return Err(AppError(
            StatusCode::FORBIDDEN,
            "ZIP-Download nicht erlaubt",
        ));
    }
    let sub = path_security::validate_relative(q.path.as_deref().unwrap_or_default())
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger ZIP-Pfad"))?
        .to_string_lossy()
        .replace('\\', "/");
    let mut expensive_peer_permit = Some(
        try_acquire_client_activity(
            state.expensive_peer_admission.clone(),
            current_client_limit_key(),
            crate::MAX_EXPENSIVE_OPERATIONS_PER_CLIENT,
        )
        .map_err(internal)?
        .ok_or(AppError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Zu viele gleichzeitige aufwendige Vorgänge dieses Clients",
        ))?,
    );
    let mut zip_permit = Some(
        state
            .zip_generation_admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                AppError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Zu viele gleichzeitige ZIP-Erstellungen",
                )
            })?,
    );
    let settings = runtime_settings(&state);
    let secure_root = state
        .secure_root
        .bind_directory(&sh.relative_path)
        .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabeziel nicht verfügbar"))?;
    drop(storage_guard);
    let resource_key = if sub.is_empty() {
        ".".to_string()
    } else {
        sub.clone()
    };
    let transfer =
        begin_public_transfer(&state, &headers, &uri, &sh, resource_key, "zip_download").await?;
    let transfer_cookie_value = transfer.cookie.clone();
    let mut transfer = Some(transfer);
    let plan_scope = secure_root.clone();
    let plan_path = sub.clone();
    let plan_settings = settings.clone();
    let plan =
        tokio::task::spawn_blocking(move || plan_zip(&plan_scope, &plan_path, &plan_settings))
            .await
            .map_err(internal)?
            .map_err(zip_error)?;
    let mut direct_generation = false;
    let body = if let Some(reservation) = ZipTempReservation::acquire(plan.estimated_archive_size) {
        let temp_scope = secure_root.clone();
        let temp_plan = plan.clone();
        match tokio::task::spawn_blocking(move || build_zip_temp(&temp_scope, &temp_plan))
            .await
            .map_err(internal)?
        {
            Ok(file) => {
                let content_length = file.metadata().ok().map(|metadata| metadata.len());
                let stream = ReservedZipStream {
                    inner: ReaderStream::new(tokio::fs::File::from_std(file)),
                    _reservation: reservation,
                };
                transfer_body(
                    stream,
                    &state,
                    transfer.take().expect("ZIP transfer lease"),
                    "zip_download",
                    sh.id,
                    content_length,
                )
            }
            Err(error) if error.is_output_capacity_error() => {
                drop(reservation);
                direct_generation = true;
                transfer_body(
                    direct_zip_stream(secure_root, plan),
                    &state,
                    transfer.take().expect("ZIP transfer lease"),
                    "zip_download",
                    sh.id,
                    None,
                )
            }
            Err(error) => {
                let lease = transfer
                    .as_ref()
                    .expect("ZIP transfer lease")
                    .lease_token
                    .as_ref()
                    .expect("ZIP transfer lease token")
                    .clone();
                let _ = database(state.db.clone(), move |database| {
                    database.cancel_transfer_lease(&lease).map(|_| ())
                })
                .await;
                return Err(zip_error(error));
            }
        }
    } else {
        direct_generation = true;
        transfer_body(
            direct_zip_stream(secure_root, plan),
            &state,
            transfer.take().expect("ZIP transfer lease"),
            "zip_download",
            sh.id,
            None,
        )
    };
    let name = Path::new(&sh.relative_path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("vaultlink");
    let filename = encoded(&format!("{name}.zip"));
    let body = if direct_generation {
        let body = Body::new(PeerPermitBody {
            inner: body,
            _permit: expensive_peer_permit
                .take()
                .expect("ZIP peer generation permit"),
        });
        Body::new(PermitBody {
            inner: body,
            _permit: zip_permit.take().expect("ZIP generation permit"),
        })
    } else {
        // The archive has already been materialized. Slow network reads retain
        // only the bounded temp-file reservation, not a scarce generation slot.
        drop(zip_permit.take());
        drop(expensive_peer_permit.take());
        body
    };
    let mut response = Response::new(body);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{filename}"))
            .map_err(internal)?,
    );
    // Deliberately omit Content-Length for counted GETs. Hyper must poll the
    // wrapped stream through EOF before the transfer lease can be committed.
    set_transfer_cookie(&mut response, &transfer_cookie_value)?;
    Ok(response)
}

pub(crate) async fn download(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response> {
    let sh = get_share(&state, &token).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Freigabe ist gesperrt"));
    }
    if !sh.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "Download nicht erlaubt"));
    }
    let expected_id = sh.id;
    let (sh, storage_guard) = get_storage_share(&state, &token, expected_id).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Freigabe ist gesperrt"));
    }
    if !sh.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "Download nicht erlaubt"));
    }
    let relative_file = if sh.is_directory {
        let rel = q
            .path
            .ok_or(AppError(StatusCode::BAD_REQUEST, "Dateipfad fehlt"))?;
        path_security::validate_relative(&rel)
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Dateipfad"))?
            .to_string_lossy()
            .replace('\\', "/")
    } else {
        sh.relative_path.clone()
    };
    let file = if sh.is_directory {
        state
            .secure_root
            .bind_directory(&sh.relative_path)
            .and_then(|directory| directory.open_file(&relative_file))
            .map(SecureFile::into_file)
    } else {
        state
            .secure_root
            .bind_file(&sh.relative_path)
            .map(SecureFile::into_file)
    }
    .map_err(|_| AppError(StatusCode::NOT_FOUND, "Datei nicht verfügbar"))?;
    drop(storage_guard);
    if method == Method::HEAD {
        check_public_transfer_availability(
            &state,
            &headers,
            &sh,
            relative_file.clone(),
            "download",
        )
        .await?;
    }
    if !file.metadata().map_err(internal)?.is_file() {
        return Err(AppError(StatusCode::BAD_REQUEST, "Keine Datei"));
    }
    let mut f = tokio::fs::File::from_std(file);
    let length = f.metadata().await.map_err(internal)?.len();
    let range = match headers.get(header::RANGE) {
        Some(value) => match value
            .to_str()
            .ok()
            .and_then(|value| parse_byte_range(value, length).ok())
        {
            Some(range) => Some(range),
            None => {
                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                response.headers_mut().insert(
                    header::CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes */{length}")).map_err(internal)?,
                );
                return Ok(response);
            }
        },
        None => None,
    };
    let transfer = if method == Method::GET {
        Some(
            begin_public_transfer(
                &state,
                &headers,
                &uri,
                &sh,
                relative_file.clone(),
                "download",
            )
            .await?,
        )
    } else {
        None
    };
    let (start, end) = range.unwrap_or((0, length.saturating_sub(1)));
    let response_length = if length == 0 { 0 } else { end - start + 1 };
    if start > 0 {
        f.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(internal)?;
    }
    let name = Path::new(&relative_file)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("download");
    let encoded = percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC);
    let (body, transfer_cookie_value) = if let Some(transfer) = transfer {
        let cookie = transfer.cookie.clone();
        let body = if response_length == 0 {
            complete_transfer_without_body(&state, transfer, "download", sh.id).await?;
            Body::empty()
        } else {
            transfer_body(
                ReaderStream::new(f.take(response_length)),
                &state,
                transfer,
                "download",
                sh.id,
                Some(response_length),
            )
        };
        (body, Some(cookie))
    } else {
        (Body::empty(), None)
    };
    let mut r = Response::new(body);
    if range.is_some() {
        *r.status_mut() = StatusCode::PARTIAL_CONTENT;
        r.headers_mut().insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {start}-{end}/{length}")).map_err(internal)?,
        );
    }
    r.headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    r.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&response_length.to_string()).map_err(internal)?,
    );
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(
            mime_guess::from_path(&relative_file)
                .first_or_octet_stream()
                .as_ref(),
        )
        .unwrap(),
    );
    r.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{encoded}"))
            .map_err(internal)?,
    );
    if let Some(cookie) = transfer_cookie_value {
        set_transfer_cookie(&mut r, &cookie)?;
    }
    Ok(r)
}
