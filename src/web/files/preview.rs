pub(super) async fn admin_preview(
    State(state): State<FileRouteState>,
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
                .try_acquire_preview_render(text_preview_render_permits(settings.max_preview_size))
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
    let secure_root = state.secure_root().clone();
    let preview_path = rel.clone();
    let storage_guard = file_ops::acquire_storage_read(&state)
        .await
        .map_err(storage_recovery_app_error)?;
    let content = tokio::task::spawn_blocking(move || {
        let _storage_guard = storage_guard;
        read_preview(&secure_root, &preview_path, &settings)
    })
    .await
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebAdminPreviewReadTaskJoin,
            error,
        ))
    })?
    .map_err(admin_preview_read_error)?;
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
        AuditAction::AdminPreview,
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
            let (stream, page_length) = escaped_text_page_stream(page, text).map_err(|error| {
                AppError::from(report_internal(
                    InternalOperation::WebAdminPreviewTextStreamBuild,
                    error,
                ))
            })?;
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
                HeaderValue::from_str(&page_length.to_string()).map_err(|error| {
                    AppError::from(report_internal(
                        InternalOperation::WebAdminPreviewContentLengthHeader,
                        error,
                    ))
                })?,
            );
            Ok(response)
        }
        PreviewContent::TooLarge { size } => {
            let body = AdminPreviewTooLargeTemplate {
                parent_path: encoded(parent_path(&rel).as_deref().unwrap_or("")),
                path: rel,
                message: i18n::text(i18n::current_locale(), i18n::PREVIEW_TOO_LARGE).into(),
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
    State(state): State<FileRouteState>,
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
    let storage_guard = file_ops::acquire_storage_read(&state)
        .await
        .map_err(storage_recovery_app_error)?;
    raw_preview_response(
        state.secure_root().clone(),
        method,
        headers,
        rel,
        kind,
        settings.max_media_preview_size,
        storage_guard,
    )
    .await
}

fn admin_preview_read_error(error: std::io::Error) -> AppError {
    AppError::storage_io(error, |_| {
        AppError(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Preview not allowed")
    })
}
