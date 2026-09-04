pub(super) fn set_transfer_cookie(response: &mut Response, cookie: &str) -> Result<()> {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(cookie).map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebTransferCookieHeader,
                error,
            ))
        })?,
    );
    Ok(())
}

pub(super) fn public_share_route(uri: &Uri, token: &str) -> String {
    if uri.path().starts_with("/api/v2/") {
        format!("/api/v2/public/shares/{token}")
    } else {
        format!("/v/{token}")
    }
}

pub(super) fn upload_io_error(error: std::io::Error) -> AppError {
    if storage_full_error(&error) {
        AppError(StatusCode::INSUFFICIENT_STORAGE, "Not enough free storage")
    } else {
        AppError::from(report_internal(
            InternalOperation::WebUploadIoFailure,
            error,
        ))
    }
}

pub(super) enum PendingUploadFileError {
    Begin,
    Take(std::io::Error),
}

pub(super) async fn limited_multipart_text(
    mut field: axum::extract::multipart::Field<'_>,
    maximum: usize,
) -> std::result::Result<String, Option<axum::extract::multipart::MultipartError>> {
    let mut value = Vec::new();
    while let Some(chunk) = field.chunk().await.map_err(Some)? {
        if value
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > maximum)
        {
            return Err(None);
        }
        value.extend_from_slice(&chunk);
    }
    String::from_utf8(value).map_err(|_| None)
}

pub(super) fn public_upload_error(
    token: &str,
    upload_subdir: &str,
    status: StatusCode,
    message: &str,
) -> Response {
    let message = i18n::localized_text(i18n::current_locale(), message).into_owned();
    let back = if upload_subdir.is_empty() {
        format!("/v/{token}")
    } else {
        format!("/v/{token}?path={}", encoded(upload_subdir))
    };
    let body = PublicUploadErrorTemplate {
        message,
        back_link: back,
    };
    let page = super::templates::public_page(i18n::ERROR, &body)
        .expect("the public upload error template writes only to an in-memory string");
    (status, Html(page)).into_response()
}
