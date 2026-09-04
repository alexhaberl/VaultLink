use std::path::Path;

use axum::{
    body::Body,
    extract::{OriginalUri, Path as AxPath, Query, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::Response,
};
use tokio::io::AsyncReadExt as _;
use tokio_util::io::ReaderStream;

use crate::{
    http_auth::{
        current_audit_client_ip, current_client_limit_key, make_transfer_cookie, runtime_settings,
        share_is_unlocked, transfer_cookie, TransferCookieScope,
    },
    internal_reporting::{report_internal, InternalOperation},
    services::public_transfer::{
        complete_transfer_without_body, transfer_stream, PreparedFileSelection,
        PublicTransferClient, RangeSelectionError,
    },
    PublicTransferRouteState,
};

use super::super::{
    common::BrowseQuery, transfer_runtime::set_transfer_cookie, AppError, Result,
    BUFFERED_RESPONSE_CHUNK_BYTES,
};

pub(crate) async fn download(
    State(state): State<PublicTransferRouteState>,
    OriginalUri(_uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(query): Query<BrowseQuery>,
) -> Result<Response> {
    let service = state.public_transfer_service();
    let share = service.share_for_transfer(&token).await?;
    authorize_download(&state, &headers, &share).await?;
    let (share, storage_guard) = service.storage_share_for_transfer(&token, share.id).await?;
    authorize_download(&state, &headers, &share).await?;
    let prepared = service
        .prepare_download(share, query.path, storage_guard)
        .await?;
    let share = prepared.share.clone();
    let relative_file = prepared.relative_file.clone();
    let session_token = transfer_cookie(&headers, share.id).map(str::to_owned);
    service
        .check_availability(
            &share,
            session_token.clone(),
            relative_file.clone(),
            "download",
        )
        .await?;
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    let selection = match prepared.select(range).await {
        Ok(selection) => selection,
        Err(RangeSelectionError::Unsatisfied { full_length }) => {
            return unsatisfied_range(full_length)
        }
        Err(RangeSelectionError::Internal(reported)) => return Err(AppError::from(reported)),
    };
    let lease = if method == Method::GET {
        Some(
            service
                .begin(
                    &share,
                    transfer_client(&state, session_token),
                    relative_file.clone(),
                    "download",
                )
                .await?,
        )
    } else {
        None
    };
    build_download_response(&state, method, &share, relative_file, selection, lease).await
}

async fn authorize_download(
    state: &PublicTransferRouteState,
    headers: &HeaderMap,
    share: &crate::db::Share,
) -> Result<()> {
    if !share_is_unlocked(state, headers, share).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    if !share.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "Download not allowed"));
    }
    Ok(())
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

async fn build_download_response(
    state: &PublicTransferRouteState,
    method: Method,
    share: &crate::db::Share,
    relative_file: String,
    selection: PreparedFileSelection,
    lease: Option<crate::services::public_transfer::PublicTransferLease>,
) -> Result<Response> {
    let cookie = lease.as_ref().map(|lease| {
        make_transfer_cookie(
            state,
            share,
            lease.session_token(),
            TransferCookieScope::Web,
        )
    });
    let mut response = Response::new(Body::empty());
    apply_download_headers(&mut response, &relative_file, &selection)?;
    let body = match (method == Method::GET, lease) {
        (true, Some(lease)) if selection.response_length == 0 => {
            complete_transfer_without_body(state, lease, "download", share.id).await?;
            Body::empty()
        }
        (true, Some(lease)) => Body::from_stream(transfer_stream(
            ReaderStream::with_capacity(
                selection.file.take(selection.response_length),
                BUFFERED_RESPONSE_CHUNK_BYTES,
            ),
            state,
            lease,
            "download",
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

fn apply_download_headers(
    response: &mut Response,
    relative_file: &str,
    selection: &PreparedFileSelection,
) -> Result<()> {
    if selection.partial {
        *response.status_mut() = StatusCode::PARTIAL_CONTENT;
        insert_header(
            response,
            header::CONTENT_RANGE,
            &format!(
                "bytes {}-{}/{}",
                selection.start, selection.end, selection.full_length
            ),
            InternalOperation::WebDownloadContentRangeHeader,
        )?;
    }
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    insert_header(
        response,
        header::CONTENT_LENGTH,
        &selection.response_length.to_string(),
        InternalOperation::WebDownloadContentLengthHeader,
    )?;
    insert_header(
        response,
        header::CONTENT_TYPE,
        mime_guess::from_path(relative_file)
            .first_or_octet_stream()
            .as_ref(),
        InternalOperation::WebDownloadContentTypeHeader,
    )?;
    let filename = Path::new(relative_file)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    let filename =
        percent_encoding::utf8_percent_encode(filename, percent_encoding::NON_ALPHANUMERIC);
    insert_header(
        response,
        header::CONTENT_DISPOSITION,
        &format!("attachment; filename*=UTF-8''{filename}"),
        InternalOperation::WebDownloadDispositionHeader,
    )
}

fn insert_header(
    response: &mut Response,
    name: header::HeaderName,
    value: &str,
    operation: InternalOperation,
) -> Result<()> {
    let value = HeaderValue::from_str(value)
        .map_err(|error| AppError::from(report_internal(operation, error)))?;
    response.headers_mut().insert(name, value);
    Ok(())
}

fn unsatisfied_range(length: u64) -> Result<Response> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    insert_header(
        &mut response,
        header::CONTENT_RANGE,
        &format!("bytes */{length}"),
        InternalOperation::WebDownloadUnsatisfiedRangeHeader,
    )?;
    Ok(response)
}
