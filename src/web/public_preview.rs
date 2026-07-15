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
    files::{media_viewer, preview_too_large_body},
    preview_zip::{
        raw_preview_response, raw_preview_secure_file_response, read_preview,
        read_preview_secure_file, PreviewContent,
    },
    public::{get_share, get_storage_share},
    rendering::{esc, escaped_html_len, plain_page},
    shares::PreviewRawQuery,
    transfer_runtime::{
        begin_public_transfer, complete_transfer_without_body, escaped_text_page_stream,
        public_share_route, set_transfer_cookie, transfer_body,
    },
    AppError, Result, MAX_RENDERED_TEXT_PREVIEW_BYTES, TEXT_PREVIEW_RENDER_UNIT_BYTES,
};

#[derive(Template)]
#[template(path = "web/public/text_preview.html")]
struct PublicTextPreviewTemplate<'a> {
    back_link: &'a str,
    download_link: &'a str,
}
use crate::{
    auth,
    db::PreviewSessionCreateOutcome,
    http_auth::{current_client_limit_key, database, runtime_settings, share_is_unlocked},
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

pub(super) fn add_public_preview_actions(
    body: String,
    back_link: &str,
    download_link: Option<&str>,
) -> String {
    let download = download_link
        .map(|link| {
            format!(
                r#"<a class="vl-button vl-button--secondary" href="{}"><vl-i18n key="common.download"/></a>"#,
                esc(link)
            )
        })
        .unwrap_or_default();
    const PREFIX: &str = r#"<section class="vl-panel"><h1><vl-i18n key="files.preview"/></h1>"#;
    let content = body
        .strip_prefix(PREFIX)
        .and_then(|body| body.strip_suffix("</section>"))
        .unwrap_or(&body);
    format!(
        r#"<section class="vl-panel"><h1><vl-i18n key="files.preview"/></h1><p class="vl-inline-actions"><a class="vl-button vl-button--secondary" href="{}"><vl-i18n key="share.back"/></a>{}</p>{}</section>"#,
        esc(back_link),
        download,
        content
    )
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
        return Err(AppError(StatusCode::UNAUTHORIZED, "Freigabe ist gesperrt"));
    }
    if !sh.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "Vorschau nicht erlaubt"));
    }
    let expected_id = sh.id;
    let (sh, storage_guard) = get_storage_share(&state, &token, expected_id).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Freigabe ist gesperrt"));
    }
    if !sh.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "Vorschau nicht erlaubt"));
    }
    let requested_path = q.path.clone().unwrap_or_default();
    let relative_file = if sh.is_directory {
        if requested_path.is_empty() {
            return Err(AppError(StatusCode::BAD_REQUEST, "Dateipfad fehlt"));
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
                    .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabeziel nicht verfügbar"))?,
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
                    .map_err(|_| AppError(StatusCode::NOT_FOUND, "Datei nicht verfügbar"))?,
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
                        "Zu viele gleichzeitige Textvorschauen",
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
        tokio::task::spawn_blocking(move || read_preview(scope, &requested, &settings)).await
    } else {
        let file = preview_file.expect("file preview is bound");
        tokio::task::spawn_blocking(move || {
            read_preview_secure_file(file, &preview_path, &settings)
        })
        .await
    }
    .map_err(internal)?
    .map_err(public_preview_error)?;
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
        let body = preview_too_large_body(
            &share_rel,
            *size,
            "Datei ist größer als das Preview-Limit.",
            Some(&download_link),
        );
        let body = add_public_preview_actions(
            body,
            &public_back_link(&public_route, &share_rel, sh.is_directory),
            Some(&download_link),
        );
        return Ok(Html(plain_page("Vorschau", &body)).into_response());
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
            let page = super::templates::public_page("Vorschau", &body)?;
            let (stream, page_length) = escaped_text_page_stream(page, text).map_err(internal)?;
            let transfer = text_transfer
                .take()
                .expect("text previews reserve their transfer before reading");
            let transfer_cookie_value = transfer.cookie.clone();
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
                    "Zu viele Vorschau-Anfragen",
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
                        "Zu viele aktive Vorschau-Sitzungen",
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
            let viewer = media_viewer(kind, &raw_url);
            let body = format!(
                r#"<section class="vl-panel"><h1><vl-i18n key="files.preview"/></h1><p class="vl-muted">{} - <vl-i18n key="files.raw_token"/></p>{}</section>"#,
                human(size),
                viewer
            );
            let body = add_public_preview_actions(
                body,
                &public_back_link(&public_route, &share_rel, sh.is_directory),
                Some(&download_link),
            );
            Response::new(Body::from(plain_page("Vorschau", &body)))
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
    let sh = get_share(&state, &token).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Freigabe ist gesperrt"));
    }
    if !sh.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "Vorschau nicht erlaubt"));
    }
    let expected_id = sh.id;
    let (sh, storage_guard) = get_storage_share(&state, &token, expected_id).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Freigabe ist gesperrt"));
    }
    if !sh.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "Vorschau nicht erlaubt"));
    }
    let requested_path = q.path.clone().unwrap_or_default();
    let relative_file = if sh.is_directory {
        if requested_path.is_empty() {
            return Err(AppError(StatusCode::BAD_REQUEST, "Dateipfad fehlt"));
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
                    .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabeziel nicht verfügbar"))?,
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
                    .map_err(|_| AppError(StatusCode::NOT_FOUND, "Datei nicht verfügbar"))?,
            ),
        )
    };
    drop(storage_guard);
    let preview_token = q
        .preview_token
        .ok_or(AppError(StatusCode::FORBIDDEN, "Preview-Token fehlt"))?;
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
            "Preview-Token ungueltig oder abgelaufen",
        ));
    }
    let settings = runtime_settings(&state);
    let kind = preview_kind(&relative_file, &settings)
        .filter(|kind| kind.is_media())
        .ok_or(AppError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Vorschau nicht erlaubt",
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
        let resource_key = if sh.is_directory {
            relative_file
        } else {
            sh.relative_path.clone()
        };
        let transfer =
            begin_public_transfer(&state, &headers, &uri, &sh, resource_key, "preview").await?;
        let transfer_cookie_value = transfer.cookie.clone();
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
