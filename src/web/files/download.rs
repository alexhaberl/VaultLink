pub(super) async fn admin_download(
    State(state): State<FileRouteState>,
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
    let secure_root = state.secure_root().clone();
    let open_path = relative.clone();
    let storage_guard = file_ops::acquire_storage_read(&state)
        .await
        .map_err(storage_recovery_app_error)?;
    let (file, length) = tokio::task::spawn_blocking(move || {
        let _storage_guard = storage_guard;
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
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebAdminDownloadOpenTaskJoin,
            error,
        ))
    })?
    .map_err(|error| match error.kind() {
        std::io::ErrorKind::InvalidInput => AppError(StatusCode::BAD_REQUEST, "Not a file"),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
            AppError(StatusCode::NOT_FOUND, "File unavailable")
        }
        _ => AppError::from(report_internal(
            InternalOperation::WebAdminDownloadOpenFailure,
            error,
        )),
    })?;
    audit_observation(
        &state,
        session.username,
        AuditAction::AdminDownload,
        Some(relative.clone()),
        None,
    )
    .await;
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from_stream(ReaderStream::with_capacity(
            tokio::fs::File::from_std(file),
            super::BUFFERED_RESPONSE_CHUNK_BYTES,
        ))
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
        HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{}", encoded(name))).map_err(
            |error| {
                AppError::from(report_internal(
                    InternalOperation::WebAdminDownloadDispositionHeader,
                    error,
                ))
            },
        )?,
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&length.to_string()).map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebAdminDownloadLengthHeader,
                error,
            ))
        })?,
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    Ok(response)
}
