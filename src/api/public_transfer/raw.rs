use std::path::Path;

use axum::{
    body::Body,
    extract::{OriginalUri, Path as AxPath, Query, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::Response,
};
use serde::Deserialize;
use tokio::io::AsyncReadExt as _;
use tokio_util::io::ReaderStream;

use crate::{
    db::Share,
    http_auth::{
        current_audit_client_ip, current_client_limit_key, database, make_transfer_cookie,
        runtime_settings, share_is_unlocked, transfer_cookie, TransferCookieScope,
    },
    internal_reporting::{report_internal, InternalOperation},
    policy::{self, PreviewKind},
    services::public_transfer::{
        complete_transfer_without_body, transfer_stream, PreparedFileSelection,
        PublicTransferClient, PublicTransferError, BUFFERED_RESPONSE_CHUNK_BYTES,
    },
    PublicTransferRouteState,
};

use super::{set_transfer_cookie, ApiError, ApiResult};

#[derive(Deserialize)]
pub(crate) struct PreviewRawQuery {
    path: Option<String>,
    preview_token: Option<String>,
}

pub(crate) async fn public_preview_raw(
    State(state): State<PublicTransferRouteState>,
    OriginalUri(_uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(query): Query<PreviewRawQuery>,
) -> ApiResult<Response> {
    let service = state.public_transfer_service();
    let share = service.share_for_transfer(&token).await?;
    authorize(&state, &headers, &share).await?;
    let (share, guard) = service.storage_share_for_transfer(&token, share.id).await?;
    authorize(&state, &headers, &share).await?;
    let prepared = service.prepare_preview(share, query.path, guard).await?;
    validate_preview_token(
        &state,
        &prepared.share,
        &prepared.requested_path,
        query.preview_token,
    )
    .await?;
    let resource_key = if prepared.share.is_directory {
        prepared.relative_file.clone()
    } else {
        prepared.share.relative_path.clone()
    };
    let session_token = transfer_cookie(&headers, prepared.share.id).map(str::to_owned);
    service
        .check_availability(
            &prepared.share,
            session_token.clone(),
            resource_key.clone(),
            "preview",
        )
        .await?;
    let settings = runtime_settings(&state);
    let kind = policy::preview_kind(&prepared.relative_file, &settings)
        .filter(|kind| kind.is_media())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "Unsupported Media Type",
            )
        })?;
    let share = prepared.share.clone();
    let relative_file = prepared.relative_file.clone();
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    let selection = match prepared
        .select_raw(settings.max_media_preview_size, range)
        .await
    {
        Ok(selection) => selection,
        Err(PublicTransferError::RangeNotSatisfiable(length)) => return unsatisfied_range(length),
        Err(error) => return Err(error.into()),
    };
    let lease = if method == Method::GET {
        Some(
            service
                .begin(
                    &share,
                    transfer_client(&state, session_token),
                    resource_key,
                    "preview",
                )
                .await?,
        )
    } else {
        None
    };
    build_response(
        &state,
        method,
        &share,
        relative_file,
        kind,
        selection,
        lease,
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

async fn validate_preview_token(
    state: &PublicTransferRouteState,
    share: &Share,
    requested_path: &str,
    token: Option<String>,
) -> ApiResult<()> {
    let token =
        token.ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "forbidden", "Forbidden"))?;
    let share_id = share.id;
    let path = if share.is_directory {
        requested_path.to_owned()
    } else {
        String::new()
    };
    let valid = database(state.db().clone(), move |database| {
        database.preview_session(&token, share_id, &path)
    })
    .await?;
    if valid {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Forbidden",
        ))
    }
}

fn transfer_client(
    state: &PublicTransferRouteState,
    session_token: Option<String>,
) -> PublicTransferClient {
    PublicTransferClient {
        client_key: current_client_limit_key().to_string(),
        session_token,
        audit_client_ip: runtime_settings(state)
            .audit_client_ip_enabled
            .then(current_audit_client_ip)
            .flatten()
            .map(|ip| ip.to_string()),
    }
}

async fn build_response(
    state: &PublicTransferRouteState,
    method: Method,
    share: &Share,
    relative_file: String,
    kind: PreviewKind,
    selection: PreparedFileSelection,
    lease: Option<crate::services::public_transfer::PublicTransferLease>,
) -> ApiResult<Response> {
    let cookie = lease.as_ref().map(|lease| {
        make_transfer_cookie(
            state,
            share,
            lease.session_token(),
            TransferCookieScope::Api,
        )
    });
    let mut response = Response::new(Body::empty());
    apply_headers(&mut response, &relative_file, kind, &selection)?;
    let body = match (method == Method::GET, lease) {
        (true, Some(lease)) if selection.response_length == 0 => {
            complete_transfer_without_body(state, lease, "preview", share.id).await?;
            Body::empty()
        }
        (true, Some(lease)) => Body::from_stream(transfer_stream(
            ReaderStream::with_capacity(
                selection.file.take(selection.response_length),
                BUFFERED_RESPONSE_CHUNK_BYTES,
            ),
            state,
            lease,
            "preview",
            share.id,
            Some(selection.response_length),
        )),
        _ => Body::empty(),
    };
    *response.body_mut() = body;
    if let Some(cookie) = cookie {
        set_transfer_cookie(&mut response, &cookie)?;
    }
    Ok(response)
}

fn apply_headers(
    response: &mut Response,
    relative_file: &str,
    kind: PreviewKind,
    selection: &PreparedFileSelection,
) -> ApiResult<()> {
    if selection.partial {
        *response.status_mut() = StatusCode::PARTIAL_CONTENT;
        insert_header(
            response,
            header::CONTENT_RANGE,
            &format!(
                "bytes {}-{}/{}",
                selection.start, selection.end, selection.full_length
            ),
            InternalOperation::WebRawPreviewContentRangeHeader,
        )?;
    }
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    insert_header(
        response,
        header::CONTENT_LENGTH,
        &selection.response_length.to_string(),
        InternalOperation::WebRawPreviewContentLengthHeader,
    )?;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(kind.content_type()),
    );
    let name = Path::new(relative_file)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("preview");
    let name = percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC);
    insert_header(
        response,
        header::CONTENT_DISPOSITION,
        &format!("inline; filename*=UTF-8''{name}"),
        InternalOperation::WebRawPreviewDispositionHeader,
    )?;
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    Ok(())
}

fn unsatisfied_range(length: u64) -> ApiResult<Response> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    insert_header(
        &mut response,
        header::CONTENT_RANGE,
        &format!("bytes */{length}"),
        InternalOperation::WebRawPreviewUnsatisfiedRangeHeader,
    )?;
    Ok(response)
}

fn insert_header(
    response: &mut Response,
    name: header::HeaderName,
    value: &str,
    operation: InternalOperation,
) -> ApiResult<()> {
    let value = HeaderValue::from_str(value)
        .map_err(|error| ApiError::from(report_internal(operation, error)))?;
    response.headers_mut().insert(name, value);
    Ok(())
}
