use std::io;

use askama::Template;
use axum::{
    body::Body,
    extract::{OriginalUri, Path as AxPath, Query, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::{Html, IntoResponse, Response},
};
use chrono::{Duration, Utc};
use futures_util::StreamExt;

use super::{
    admission::PermitBody,
    common::{
        encoded, human, internal, parent_path, preview_kind, public_preview_error, BrowseQuery,
    },
    preview_zip::{
        raw_preview_response, raw_preview_secure_file_response, read_preview,
        read_preview_secure_file, PreviewContent,
    },
    public::{
        get_share, get_share_for_transfer, get_storage_share, get_storage_share_for_transfer,
    },
    rendering::escaped_html_len,
    shares::PreviewRawQuery,
    transfer_runtime::{
        begin_public_transfer, check_public_transfer_availability, complete_transfer_without_body,
        escaped_text_page_stream, public_share_route, set_transfer_cookie, transfer_body,
    },
    AppError, Result, MAX_RENDERED_TEXT_PREVIEW_BYTES, TEXT_PREVIEW_RENDER_UNIT_BYTES,
};

#[derive(Template)]
#[template(path = "web/public/text_preview.html")]
pub(super) struct PublicTextPreviewTemplate<'a> {
    pub(super) back_link: &'a str,
    pub(super) download_link: &'a str,
}

#[derive(Template)]
#[template(path = "web/public/preview_too_large.html")]
struct PublicPreviewTooLargeTemplate {
    back_link: String,
    download_link: String,
    path: String,
    message: String,
    size: String,
}

#[derive(Template)]
#[template(path = "web/public/media_preview.html")]
struct PublicMediaPreviewTemplate {
    back_link: String,
    download_link: String,
    size: String,
    raw_url: String,
    image: bool,
}
use crate::{
    auth,
    db::PreviewSessionCreateOutcome,
    http_auth::{current_client_limit_key, database, runtime_settings, share_is_unlocked},
    i18n,
    policy::PreviewKind,
    AppState,
};

pub(super) fn public_back_link(
    public_route: &str,
    share_relative_file: &str,
    is_directory_share: bool,
) -> String {
    if !is_directory_share {
        return public_route.to_string();
    }
    let parent = parent_path(share_relative_file).unwrap_or_default();
    if parent.is_empty() {
        public_route.to_string()
    } else {
        format!("{public_route}?path={}", encoded(&parent))
    }
}

pub(super) fn text_preview_render_permits(max_preview_size: u64) -> u32 {
    max_preview_size
        .div_ceil(TEXT_PREVIEW_RENDER_UNIT_BYTES)
        .clamp(1, crate::TEXT_PREVIEW_RENDER_BUDGET_PERMITS as u64) as u32
}

pub(crate) async fn public_preview(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response> {
    let sh = get_share(&state, &token).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    if !sh.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "Preview not allowed"));
    }
    let expected_id = sh.id;
    let (sh, storage_guard) = get_storage_share(&state, &token, expected_id).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    if !sh.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "Preview not allowed"));
    }
    let requested_path = q.path.clone().unwrap_or_default();
    let relative_file = if sh.is_directory {
        if requested_path.is_empty() {
            return Err(AppError(StatusCode::BAD_REQUEST, "File path missing"));
        }
        requested_path.clone()
    } else {
        sh.relative_path.clone()
    };
    let (preview_scope, preview_file) = if sh.is_directory {
        (
            Some(
                state
                    .secure_root
                    .bind_directory(&sh.relative_path)
                    .map_err(|_| AppError(StatusCode::NOT_FOUND, "Share target unavailable"))?,
            ),
            None,
        )
    } else {
        (
            None,
            Some(
                state
                    .secure_root
                    .bind_file(&sh.relative_path)
                    .map_err(|_| AppError(StatusCode::NOT_FOUND, "File unavailable"))?,
            ),
        )
    };
    drop(storage_guard);
    let settings = runtime_settings(&state);
    let is_text_preview = preview_kind(&relative_file, &settings) == Some(PreviewKind::Text);
    let mut text_render_permit = if is_text_preview {
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
    let preview_resource_key = if sh.is_directory {
        requested_path.clone()
    } else {
        sh.relative_path.clone()
    };
    // Hold the transfer reservation while reading and escaping a text preview.
    // A mere availability check here would allow concurrent requests to all do
    // the expensive work before racing to acquire the final remaining slot.
    let mut text_transfer = if is_text_preview {
        Some(
            begin_public_transfer(
                &state,
                &headers,
                &uri,
                &sh,
                preview_resource_key.clone(),
                "preview",
            )
            .await?,
        )
    } else {
        None
    };
    let preview_path = relative_file.clone();
    let content = if sh.is_directory {
        let scope = preview_scope.expect("directory preview scope is bound");
        let requested = requested_path.clone();
        tokio::task::spawn_blocking(move || read_preview(&scope, &requested, &settings)).await
    } else {
        let file = preview_file.expect("file preview is bound");
        tokio::task::spawn_blocking(move || {
            read_preview_secure_file(file, &preview_path, &settings)
        })
        .await
    }
    .map_err(internal)?
    .map_err(|error| public_preview_error(&error))?;
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
    let share_rel = if sh.is_directory {
        requested_path
    } else {
        String::new()
    };
    let public_route = public_share_route(&uri, &token);
    let download_link = if sh.is_directory {
        format!(r#"{public_route}/download?path={}"#, encoded(&share_rel))
    } else {
        format!("{public_route}/download")
    };
    if let PreviewContent::TooLarge { size } = &content {
        let body = PublicPreviewTooLargeTemplate {
            back_link: public_back_link(&public_route, &share_rel, sh.is_directory),
            download_link,
            path: share_rel,
            message: i18n::text(i18n::current_locale(), i18n::PREVIEW_TOO_LARGE).into(),
            size: human(*size),
        };
        return Ok(
            Html(super::templates::public_page(i18n::TITLE_PREVIEW, &body)?).into_response(),
        );
    }
    let mut response = match content {
        PreviewContent::TooLarge { .. } => {
            unreachable!("oversized previews return before response rendering")
        }
        PreviewContent::Text(text) => {
            let back_link = public_back_link(&public_route, &share_rel, sh.is_directory);
            let body = PublicTextPreviewTemplate {
                back_link: &back_link,
                download_link: &download_link,
            };
            let page = super::templates::public_page(i18n::TITLE_PREVIEW, &body)?;
            let (stream, page_length) = escaped_text_page_stream(page, text).map_err(internal)?;
            let transfer = text_transfer
                .take()
                .expect("text previews reserve their transfer before reading");
            let transfer_cookie_value = transfer.cookie().to_string();
            let transfer_body = transfer_body(
                stream,
                &state,
                transfer,
                "preview",
                sh.id,
                Some(page_length),
            );
            let mut response = Response::new(Body::new(PermitBody {
                inner: transfer_body,
                _permit: text_render_permit
                    .take()
                    .expect("text previews reserve render memory before reading"),
            }));
            response.headers_mut().insert(
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&page_length.to_string()).map_err(internal)?,
            );
            set_transfer_cookie(&mut response, &transfer_cookie_value)?;
            response
        }
        PreviewContent::Media { kind, size } => {
            let owner_key = current_client_limit_key().to_string();
            if !state
                .preview_token_limiter
                .check_and_record_attempt(&format!("preview-token:{}:{owner_key}", sh.id))
            {
                return Err(AppError(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many preview requests",
                ));
            }
            let preview_token = auth::random_token(32);
            let stored_preview_token = preview_token.clone();
            let stored_owner_key = owner_key;
            let share_id = sh.id;
            let token_path = if sh.is_directory {
                share_rel.clone()
            } else {
                String::new()
            };
            let expires = Utc::now() + Duration::minutes(5);
            let preview_outcome = database(state.db.clone(), move |db| {
                db.create_preview_session(
                    &stored_preview_token,
                    &stored_owner_key,
                    share_id,
                    &token_path,
                    expires,
                )
            })
            .await?;
            match preview_outcome {
                PreviewSessionCreateOutcome::Created => {}
                PreviewSessionCreateOutcome::OwnerCapacityReached
                | PreviewSessionCreateOutcome::ShareCapacityReached
                | PreviewSessionCreateOutcome::GlobalCapacityReached => {
                    return Err(AppError(
                        StatusCode::TOO_MANY_REQUESTS,
                        "Too many active preview sessions",
                    ));
                }
            }
            let raw_url = if sh.is_directory {
                format!(
                    "{public_route}/preview/raw?path={}&preview_token={}",
                    encoded(&share_rel),
                    encoded(&preview_token)
                )
            } else {
                format!(
                    "{public_route}/preview/raw?preview_token={}",
                    encoded(&preview_token)
                )
            };
            let body = PublicMediaPreviewTemplate {
                back_link: public_back_link(&public_route, &share_rel, sh.is_directory),
                download_link,
                size: human(size),
                raw_url,
                image: matches!(kind, PreviewKind::Image(_)),
            };
            Response::new(Body::from(super::templates::public_page(
                i18n::TITLE_PREVIEW,
                &body,
            )?))
        }
    };
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    Ok(response)
}

pub(crate) async fn public_preview_raw(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(q): Query<PreviewRawQuery>,
) -> Result<Response> {
    let sh = get_share_for_transfer(&state, &token).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    if !sh.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "Preview not allowed"));
    }
    let expected_id = sh.id;
    let (sh, storage_guard) = get_storage_share_for_transfer(&state, &token, expected_id).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    if !sh.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "Preview not allowed"));
    }
    let requested_path = q.path.clone().unwrap_or_default();
    let relative_file = if sh.is_directory {
        if requested_path.is_empty() {
            return Err(AppError(StatusCode::BAD_REQUEST, "File path missing"));
        }
        requested_path.clone()
    } else {
        sh.relative_path.clone()
    };
    let (preview_scope, preview_file) = if sh.is_directory {
        (
            Some(
                state
                    .secure_root
                    .bind_directory(&sh.relative_path)
                    .map_err(|_| AppError(StatusCode::NOT_FOUND, "Share target unavailable"))?,
            ),
            None,
        )
    } else {
        (
            None,
            Some(
                state
                    .secure_root
                    .bind_file(&sh.relative_path)
                    .map_err(|_| AppError(StatusCode::NOT_FOUND, "File unavailable"))?,
            ),
        )
    };
    drop(storage_guard);
    let preview_token = q
        .preview_token
        .ok_or(AppError(StatusCode::FORBIDDEN, "Preview token missing"))?;
    let share_id = sh.id;
    let token_path = if sh.is_directory {
        requested_path.clone()
    } else {
        String::new()
    };
    let token_valid = database(state.db.clone(), move |db| {
        db.preview_session(&preview_token, share_id, &token_path)
    })
    .await?;
    if !token_valid {
        return Err(AppError(
            StatusCode::FORBIDDEN,
            "Preview token is invalid or expired",
        ));
    }
    let resource_key = if sh.is_directory {
        relative_file.clone()
    } else {
        sh.relative_path.clone()
    };
    check_public_transfer_availability(&state, &headers, &sh, resource_key.clone(), "preview")
        .await?;
    let settings = runtime_settings(&state);
    let kind = preview_kind(&relative_file, &settings)
        .filter(|kind| kind.is_media())
        .ok_or(AppError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Preview not allowed",
        ))?;
    let mut response = if sh.is_directory {
        let scope = preview_scope.expect("directory raw preview scope is bound");
        raw_preview_response(
            scope,
            method.clone(),
            headers.clone(),
            relative_file.clone(),
            kind,
            settings.max_media_preview_size,
        )
        .await?
    } else {
        let file = preview_file.expect("file raw preview is bound");
        raw_preview_secure_file_response(
            file,
            method.clone(),
            headers.clone(),
            relative_file.clone(),
            kind,
            settings.max_media_preview_size,
        )
        .await?
    };
    if method == Method::GET && response.status().is_success() {
        let transfer =
            begin_public_transfer(&state, &headers, &uri, &sh, resource_key, "preview").await?;
        let transfer_cookie_value = transfer.cookie().to_string();
        let expected_bytes = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if expected_bytes == Some(0) {
            complete_transfer_without_body(&state, transfer, "preview", sh.id).await?;
        } else {
            let body = std::mem::replace(response.body_mut(), Body::empty());
            let stream = body
                .into_data_stream()
                .map(|item| item.map_err(io::Error::other));
            *response.body_mut() =
                transfer_body(stream, &state, transfer, "preview", sh.id, expected_bytes);
            // TransferBodyStream commits before yielding the first non-empty
            // payload chunk, so disconnects cannot leak uncounted partial data.
        }
        set_transfer_cookie(&mut response, &transfer_cookie_value)?;
    }
    Ok(response)
}
