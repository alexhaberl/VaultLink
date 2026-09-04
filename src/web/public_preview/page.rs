use axum::{
    body::Body,
    extract::{OriginalUri, Path as AxPath, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
};
use chrono::{Duration, Utc};

use crate::{
    auth,
    db::{PreviewSessionCreateOutcome, Share},
    http_auth::{
        current_audit_client_ip, current_client_limit_key, database, make_transfer_cookie,
        runtime_settings, share_is_unlocked, transfer_cookie, TransferCookieScope,
    },
    i18n,
    internal_reporting::{report_internal, InternalOperation},
    policy::{self, PreviewKind},
    services::public_transfer::{
        escaped_html_len, escaped_text_page_stream, read_preview, read_preview_secure_file,
        transfer_stream, PreparedPreview, PreparedPreviewTarget, PreviewContent,
        PublicTransferClient, PublicTransferLease,
    },
    PublicTransferRouteState,
};

use super::{
    public_back_link, text_preview_render_permits, PublicMediaPreviewTemplate,
    PublicPreviewTooLargeTemplate, PublicTextPreviewTemplate,
};
use crate::web::{
    admission::PermitBody,
    common::{encoded, human, public_preview_error, BrowseQuery},
    templates,
    transfer_runtime::set_transfer_cookie,
    AppError, Result, MAX_RENDERED_TEXT_PREVIEW_BYTES,
};

struct PreviewPageContext {
    share: Share,
    requested_path: String,
    public_route: String,
    content: PreviewContent,
    text_transfer: Option<PublicTransferLease>,
    text_render_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

pub(crate) async fn public_preview(
    State(state): State<PublicTransferRouteState>,
    OriginalUri(_uri): OriginalUri,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(query): Query<BrowseQuery>,
) -> Result<Response> {
    let service = state.public_transfer_service();
    let share = service.share(&token).await?;
    authorize_preview(&state, &headers, &share).await?;
    let (share, storage_guard) = service.storage_share(&token, share.id).await?;
    authorize_preview(&state, &headers, &share).await?;
    let prepared = service
        .prepare_preview(share, query.path, storage_guard)
        .await?;
    let settings = runtime_settings(&state);
    let is_text =
        policy::preview_kind(&prepared.relative_file, &settings) == Some(PreviewKind::Text);
    let render_permit = if is_text {
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
    let resource_key = preview_resource_key(&prepared);
    let text_transfer = if is_text {
        Some(
            service
                .begin(
                    &prepared.share,
                    transfer_client(&state, &headers, &prepared.share),
                    resource_key,
                    "preview",
                )
                .await?,
        )
    } else {
        None
    };
    let share = prepared.share.clone();
    let requested_path = prepared.requested_path.clone();
    let content = read_content(prepared, settings).await?;
    render_preview(
        &state,
        PreviewPageContext {
            share,
            requested_path,
            public_route: format!("/v/{token}"),
            content,
            text_transfer,
            text_render_permit: render_permit,
        },
    )
    .await
}

async fn authorize_preview(
    state: &PublicTransferRouteState,
    headers: &HeaderMap,
    share: &Share,
) -> Result<()> {
    if !share_is_unlocked(state, headers, share).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    if !share.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "Preview not allowed"));
    }
    Ok(())
}

fn preview_resource_key(prepared: &PreparedPreview) -> String {
    if prepared.share.is_directory {
        prepared.requested_path.clone()
    } else {
        prepared.share.relative_path.clone()
    }
}

fn transfer_client(
    state: &PublicTransferRouteState,
    headers: &HeaderMap,
    share: &Share,
) -> PublicTransferClient {
    PublicTransferClient {
        client_key: current_client_limit_key().to_string(),
        session_token: transfer_cookie(headers, share.id).map(str::to_owned),
        audit_client_ip: runtime_settings(state)
            .audit_client_ip_enabled
            .then(current_audit_client_ip)
            .flatten()
            .map(|ip| ip.to_string()),
    }
}

async fn read_content(
    prepared: PreparedPreview,
    settings: crate::runtime::RuntimeSettings,
) -> Result<PreviewContent> {
    let path = prepared.relative_file;
    let content = match prepared.target {
        PreparedPreviewTarget::Directory(directory) => {
            tokio::task::spawn_blocking(move || read_preview(&directory, &path, &settings)).await
        }
        PreparedPreviewTarget::File(file) => {
            tokio::task::spawn_blocking(move || read_preview_secure_file(file, &path, &settings))
                .await
        }
    }
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebPublicPreviewReadJoin,
            error,
        ))
    })?
    .map_err(|error| public_preview_error(&error))?;
    Ok(match content {
        PreviewContent::Text(text)
            if escaped_html_len(&text)
                .is_none_or(|length| length > MAX_RENDERED_TEXT_PREVIEW_BYTES) =>
        {
            PreviewContent::TooLarge {
                size: text.len() as u64,
            }
        }
        content => content,
    })
}

async fn render_preview(
    state: &PublicTransferRouteState,
    mut context: PreviewPageContext,
) -> Result<Response> {
    let share_relative = if context.share.is_directory {
        context.requested_path.clone()
    } else {
        String::new()
    };
    let download_link = if context.share.is_directory {
        format!(
            "{}/download?path={}",
            context.public_route,
            encoded(&share_relative)
        )
    } else {
        format!("{}/download", context.public_route)
    };
    let content = std::mem::replace(&mut context.content, PreviewContent::TooLarge { size: 0 });
    match content {
        PreviewContent::TooLarge { size } => {
            render_too_large(&context, share_relative, download_link, size)
        }
        PreviewContent::Text(text) => {
            render_text(state, context, share_relative, download_link, text).await
        }
        PreviewContent::Media { kind, size } => {
            render_media(state, context, share_relative, download_link, kind, size).await
        }
    }
}

fn render_too_large(
    context: &PreviewPageContext,
    share_relative: String,
    download_link: String,
    size: u64,
) -> Result<Response> {
    let body = PublicPreviewTooLargeTemplate {
        back_link: public_back_link(
            &context.public_route,
            &share_relative,
            context.share.is_directory,
        ),
        download_link,
        path: share_relative,
        message: i18n::text(i18n::current_locale(), i18n::PREVIEW_TOO_LARGE).into(),
        size: human(size),
    };
    Ok(Html(templates::public_page(i18n::TITLE_PREVIEW, &body)?).into_response())
}

async fn render_text(
    state: &PublicTransferRouteState,
    mut context: PreviewPageContext,
    share_relative: String,
    download_link: String,
    text: String,
) -> Result<Response> {
    let back_link = public_back_link(
        &context.public_route,
        &share_relative,
        context.share.is_directory,
    );
    let body = PublicTextPreviewTemplate {
        back_link: &back_link,
        download_link: &download_link,
    };
    let page = templates::public_page(i18n::TITLE_PREVIEW, &body)?;
    let (stream, length) = escaped_text_page_stream(page, text).map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebPublicPreviewTextStreamBuild,
            error,
        ))
    })?;
    let transfer = context
        .text_transfer
        .take()
        .expect("text previews reserve a transfer before reading");
    let cookie = make_transfer_cookie(
        state,
        &context.share,
        transfer.session_token(),
        TransferCookieScope::Web,
    );
    let stream = transfer_stream(
        stream,
        state,
        transfer,
        "preview",
        context.share.id,
        Some(length),
    );
    let mut response = Response::new(Body::new(PermitBody {
        inner: Body::from_stream(stream),
        _permit: context
            .text_render_permit
            .take()
            .expect("text previews reserve render memory before reading"),
    }));
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&length.to_string()).map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebPublicPreviewContentLengthHeader,
                error,
            ))
        })?,
    );
    set_transfer_cookie(&mut response, &cookie)?;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    Ok(response)
}

async fn render_media(
    state: &PublicTransferRouteState,
    context: PreviewPageContext,
    share_relative: String,
    download_link: String,
    kind: PreviewKind,
    size: u64,
) -> Result<Response> {
    let owner_key = current_client_limit_key().to_string();
    if !state
        .preview_token_limiter()
        .check_and_record_attempt(&format!("preview-token:{}:{owner_key}", context.share.id))
    {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many preview requests",
        ));
    }
    let preview_token =
        create_preview_session(state, &context.share, &share_relative, owner_key).await?;
    let raw_url = if context.share.is_directory {
        format!(
            "{}/preview/raw?path={}&preview_token={}",
            context.public_route,
            encoded(&share_relative),
            encoded(&preview_token)
        )
    } else {
        format!(
            "{}/preview/raw?preview_token={}",
            context.public_route,
            encoded(&preview_token)
        )
    };
    let body = PublicMediaPreviewTemplate {
        back_link: public_back_link(
            &context.public_route,
            &share_relative,
            context.share.is_directory,
        ),
        download_link,
        size: human(size),
        raw_url,
        image: matches!(kind, PreviewKind::Image(_)),
    };
    let mut response = Response::new(Body::from(templates::public_page(
        i18n::TITLE_PREVIEW,
        &body,
    )?));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    Ok(response)
}

async fn create_preview_session(
    state: &PublicTransferRouteState,
    share: &Share,
    share_relative: &str,
    owner_key: String,
) -> Result<String> {
    let preview_token = auth::random_token(32);
    let stored_token = preview_token.clone();
    let share_id = share.id;
    let token_path = if share.is_directory {
        share_relative.to_owned()
    } else {
        String::new()
    };
    let expires = Utc::now() + Duration::minutes(5);
    let outcome = database(state.db().clone(), move |database| {
        database.create_preview_session(&stored_token, &owner_key, share_id, &token_path, expires)
    })
    .await?;
    match outcome {
        PreviewSessionCreateOutcome::Created => Ok(preview_token),
        PreviewSessionCreateOutcome::OwnerCapacityReached
        | PreviewSessionCreateOutcome::ShareCapacityReached
        | PreviewSessionCreateOutcome::GlobalCapacityReached => Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many active preview sessions",
        )),
    }
}
