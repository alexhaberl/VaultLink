use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use askama::Template;
use axum::{
    body::Body,
    extract::{OriginalUri, Path as AxPath, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use chrono::{Duration, Utc};
use futures_util::Stream;

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
    download_adapter::BrowseQuery, presentation::public_page, set_transfer_cookie, ApiError,
    ApiResult,
};

const TEXT_PREVIEW_RENDER_UNIT_BYTES: u64 = 1_000_000;
const MAX_RENDERED_TEXT_PREVIEW_BYTES: usize = crate::config::MAX_TEXT_PREVIEW_SIZE as usize;

#[derive(Template)]
#[template(path = "web/public/text_preview.html")]
struct TextPreviewTemplate<'a> {
    back_link: &'a str,
    download_link: &'a str,
}

#[derive(Template)]
#[template(path = "web/public/preview_too_large.html")]
struct TooLargeTemplate {
    back_link: String,
    download_link: String,
    path: String,
    message: String,
    size: String,
}

#[derive(Template)]
#[template(path = "web/public/media_preview.html")]
struct MediaPreviewTemplate {
    back_link: String,
    download_link: String,
    size: String,
    raw_url: String,
    image: bool,
}

struct PreviewContext {
    share: Share,
    requested_path: String,
    public_route: String,
    content: PreviewContent,
    text_transfer: Option<PublicTransferLease>,
    text_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

struct PermitStream<S> {
    inner: S,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl<S> Stream for PermitStream<S>
where
    S: Stream<Item = io::Result<bytes::Bytes>> + Unpin,
{
    type Item = io::Result<bytes::Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(context)
    }
}

pub(crate) async fn public_preview(
    State(state): State<PublicTransferRouteState>,
    OriginalUri(_uri): OriginalUri,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(query): Query<BrowseQuery>,
) -> ApiResult<Response> {
    let service = state.public_transfer_service();
    let share = service.share(&token).await?;
    authorize(&state, &headers, &share).await?;
    let (share, guard) = service.storage_share(&token, share.id).await?;
    authorize(&state, &headers, &share).await?;
    let prepared = service.prepare_preview(share, query.path, guard).await?;
    let settings = runtime_settings(&state);
    let is_text =
        policy::preview_kind(&prepared.relative_file, &settings) == Some(PreviewKind::Text);
    let text_permit = if is_text {
        Some(
            state
                .try_acquire_preview_render(text_render_permits(settings.max_preview_size))
                .map_err(|_| capacity_error())?,
        )
    } else {
        None
    };
    let text_transfer = if is_text {
        Some(
            service
                .begin(
                    &prepared.share,
                    transfer_client(&state, &headers, &prepared.share),
                    resource_key(&prepared),
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
        PreviewContext {
            share,
            requested_path,
            public_route: format!("/api/v2/public/shares/{token}"),
            content,
            text_transfer,
            text_permit,
        },
    )
    .await
}

async fn authorize(
    state: &PublicTransferRouteState,
    headers: &HeaderMap,
    share: &Share,
) -> ApiResult<()> {
    if !share_is_unlocked(state, headers, share).await? {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Unauthorized",
        ));
    }
    if !share.permission.can_download() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Forbidden",
        ));
    }
    Ok(())
}

fn resource_key(prepared: &PreparedPreview) -> String {
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
) -> ApiResult<PreviewContent> {
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
        ApiError::from(report_internal(
            InternalOperation::WebPublicPreviewReadJoin,
            error,
        ))
    })?
    .map_err(|error| preview_io_error(&error))?;
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

fn preview_io_error(error: &io::Error) -> ApiError {
    if matches!(error.raw_os_error(), Some(18 | 40))
        || matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
        )
    {
        ApiError::new(StatusCode::NOT_FOUND, "not_found", "Not Found")
    } else {
        ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "Unsupported Media Type",
        )
    }
}

async fn render_preview(
    state: &PublicTransferRouteState,
    mut context: PreviewContext,
) -> ApiResult<Response> {
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
    context: &PreviewContext,
    share_relative: String,
    download_link: String,
    size: u64,
) -> ApiResult<Response> {
    let body = TooLargeTemplate {
        back_link: back_link(
            &context.public_route,
            &share_relative,
            context.share.is_directory,
        ),
        download_link,
        path: share_relative,
        message: i18n::text(i18n::current_locale(), i18n::PREVIEW_TOO_LARGE).into(),
        size: human(size),
    };
    html_response(public_page(i18n::TITLE_PREVIEW, &body)?)
}

async fn render_text(
    state: &PublicTransferRouteState,
    mut context: PreviewContext,
    share_relative: String,
    download_link: String,
    text: String,
) -> ApiResult<Response> {
    let back = back_link(
        &context.public_route,
        &share_relative,
        context.share.is_directory,
    );
    let page = public_page(
        i18n::TITLE_PREVIEW,
        &TextPreviewTemplate {
            back_link: &back,
            download_link: &download_link,
        },
    )?;
    let (stream, length) = escaped_text_page_stream(page, text).map_err(|error| {
        ApiError::from(report_internal(
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
        TransferCookieScope::Api,
    );
    let stream = transfer_stream(
        stream,
        state,
        transfer,
        "preview",
        context.share.id,
        Some(length),
    );
    let mut response = Response::new(Body::from_stream(PermitStream {
        inner: stream,
        _permit: context
            .text_permit
            .take()
            .expect("text previews reserve render memory before reading"),
    }));
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&length.to_string()).map_err(|error| {
            ApiError::from(report_internal(
                InternalOperation::WebPublicPreviewContentLengthHeader,
                error,
            ))
        })?,
    );
    set_transfer_cookie(&mut response, &cookie)?;
    set_html_content_type(&mut response);
    Ok(response)
}

async fn render_media(
    state: &PublicTransferRouteState,
    context: PreviewContext,
    share_relative: String,
    download_link: String,
    kind: PreviewKind,
    size: u64,
) -> ApiResult<Response> {
    let owner_key = current_client_limit_key().to_string();
    if !state
        .preview_token_limiter()
        .check_and_record_attempt(&format!("preview-token:{}:{owner_key}", context.share.id))
    {
        return Err(rate_error());
    }
    let token = create_preview_session(state, &context.share, &share_relative, owner_key).await?;
    let raw_url = if context.share.is_directory {
        format!(
            "{}/preview/raw?path={}&preview_token={}",
            context.public_route,
            encoded(&share_relative),
            encoded(&token)
        )
    } else {
        format!(
            "{}/preview/raw?preview_token={}",
            context.public_route,
            encoded(&token)
        )
    };
    let body = MediaPreviewTemplate {
        back_link: back_link(
            &context.public_route,
            &share_relative,
            context.share.is_directory,
        ),
        download_link,
        size: human(size),
        raw_url,
        image: matches!(kind, PreviewKind::Image(_)),
    };
    html_response(public_page(i18n::TITLE_PREVIEW, &body)?)
}

async fn create_preview_session(
    state: &PublicTransferRouteState,
    share: &Share,
    share_relative: &str,
    owner_key: String,
) -> ApiResult<String> {
    let token = auth::random_token(32);
    let stored_token = token.clone();
    let share_id = share.id;
    let path = if share.is_directory {
        share_relative.to_owned()
    } else {
        String::new()
    };
    let expires = Utc::now() + Duration::minutes(5);
    let outcome = database(state.db().clone(), move |database| {
        database.create_preview_session(&stored_token, &owner_key, share_id, &path, expires)
    })
    .await?;
    match outcome {
        PreviewSessionCreateOutcome::Created => Ok(token),
        PreviewSessionCreateOutcome::OwnerCapacityReached
        | PreviewSessionCreateOutcome::ShareCapacityReached
        | PreviewSessionCreateOutcome::GlobalCapacityReached => Err(rate_error()),
    }
}

fn text_render_permits(maximum: u64) -> u32 {
    maximum
        .div_ceil(TEXT_PREVIEW_RENDER_UNIT_BYTES)
        .clamp(1, crate::TEXT_PREVIEW_RENDER_BUDGET_PERMITS as u64) as u32
}

fn encoded(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

fn back_link(route: &str, relative: &str, directory: bool) -> String {
    if !directory {
        return route.to_owned();
    }
    let parent = relative
        .trim_matches('/')
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .unwrap_or_default();
    if parent.is_empty() {
        route.to_owned()
    } else {
        format!("{route}?path={}", encoded(parent))
    }
}

fn human(bytes: u64) -> String {
    let mut value = if bytes >= 1_000_000_000 {
        format!("{:.1} GB", bytes as f64 / 1_000_000_000_f64)
    } else if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000_f64)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1_000_f64)
    } else {
        format!("{bytes} B")
    };
    if i18n::current_locale() == i18n::Locale::De {
        value = value.replace('.', ",");
    }
    value
}

fn html_response(page: String) -> ApiResult<Response> {
    let mut response = Response::new(Body::from(page));
    set_html_content_type(&mut response);
    Ok(response)
}

fn set_html_content_type(response: &mut Response) {
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
}

fn rate_error() -> ApiError {
    ApiError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "Too Many Requests",
    )
}

fn capacity_error() -> ApiError {
    let mut error = ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "internal_error",
        "Service Unavailable",
    );
    error.retry_after_seconds = Some(1);
    error
}
