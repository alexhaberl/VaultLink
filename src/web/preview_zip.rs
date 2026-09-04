use std::path::Path;

use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::Response,
};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
use tokio_util::io::ReaderStream;

use crate::{
    internal_reporting::{report_internal, InternalOperation},
    policy::PreviewKind,
};

#[cfg(test)]
pub(super) use crate::services::public_transfer::{
    build_zip_temp, checked_zip_plan_memory, direct_zip_stream, estimate_zip_archive_size,
    plan_zip, read_preview_opened, write_streaming_central_entry, write_streaming_eocd,
    write_streaming_zip64_eocd, write_streaming_zip64_locator, write_zip_archive,
    zip_requires_direct_stream, zip_temp_reserved_bytes_for_test, StreamingZipEntry,
    TextPreviewReadTestGuard, TextPreviewReadTestHook, ZipBuildError, ZipFilePlan, ZipPlan,
    TEXT_PREVIEW_READ_TEST_HOOK, ZIP64_CENTRAL_EXTRA_SIZE, ZIP64_EXTRA_PAYLOAD_SIZE,
    ZIP64_LOCAL_EXTRA_SIZE, ZIP64_SIZE_FIELDS_SIZE, ZIP64_VERSION, ZIP_EOCD_SIZE,
    ZIP_PLAN_MAX_BYTES,
};
pub(super) use crate::services::public_transfer::{read_preview, PreviewContent};

use super::{common::DirectoryAccess, AppError, Result};

pub(super) async fn raw_preview_response<D: DirectoryAccess, G: Send + 'static>(
    secure_root: D,
    method: Method,
    headers: HeaderMap,
    relative_file: String,
    kind: PreviewKind,
    max_size: u64,
    storage_guard: G,
) -> Result<Response> {
    let open_path = relative_file.clone();
    let file = tokio::task::spawn_blocking(move || {
        // Capability acquisition must retain namespace authority even when the
        // awaiting HTTP future is cancelled. The descriptor remains safe after
        // this blocking task releases the guard and streaming begins.
        let _storage_guard = storage_guard;
        secure_root.open_regular_file(&open_path)
    })
    .await
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebRawPreviewOpenJoin,
            error,
        ))
    })?
    .map_err(|_| AppError(StatusCode::NOT_FOUND, "File unavailable"))?;
    raw_preview_opened_response(file, method, headers, relative_file, kind, max_size).await
}

async fn raw_preview_opened_response(
    file: std::fs::File,
    method: Method,
    headers: HeaderMap,
    relative_file: String,
    kind: PreviewKind,
    max_size: u64,
) -> Result<Response> {
    let (file, metadata) = tokio::task::spawn_blocking(move || {
        let metadata = file.metadata();
        (file, metadata)
    })
    .await
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebRawPreviewOpenJoin,
            error,
        ))
    })?;
    let metadata = metadata.map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebRawPreviewFileMetadata,
            error,
        ))
    })?;
    if !metadata.is_file() {
        return Err(AppError(StatusCode::BAD_REQUEST, "Not a file"));
    }
    let mut file = tokio::fs::File::from_std(file);
    let length = file
        .metadata()
        .await
        .map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebRawPreviewAsyncMetadata,
                error,
            ))
        })?
        .len();
    if length > max_size {
        return Err(AppError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Preview limit reached",
        ));
    }
    let Some(range) = raw_preview_range(&headers, length) else {
        return unsatisfied_range_response(length);
    };
    let (start, end) = range.unwrap_or((0, length.saturating_sub(1)));
    let response_length = if length == 0 { 0 } else { end - start + 1 };
    if start > 0 {
        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|error| {
                AppError::from(report_internal(InternalOperation::WebRawPreviewSeek, error))
            })?;
    }
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from_stream(ReaderStream::with_capacity(
            file.take(response_length),
            super::BUFFERED_RESPONSE_CHUNK_BYTES,
        ))
    };
    let mut response = Response::new(body);
    add_raw_preview_headers(
        &mut response,
        &RawPreviewHeaders {
            relative_file: &relative_file,
            kind,
            range,
            length,
            start,
            end,
            response_length,
        },
    )?;
    Ok(response)
}

fn raw_preview_range(headers: &HeaderMap, length: u64) -> Option<Option<(u64, u64)>> {
    let Some(value) = headers.get(header::RANGE) else {
        return Some(None);
    };
    value
        .to_str()
        .ok()
        .and_then(|value| crate::range::parse_byte_range(value, length).ok())
        .map(Some)
}

fn unsatisfied_range_response(length: u64) -> Result<Response> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    response.headers_mut().insert(
        header::CONTENT_RANGE,
        HeaderValue::from_str(&format!("bytes */{length}")).map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebRawPreviewUnsatisfiedRangeHeader,
                error,
            ))
        })?,
    );
    Ok(response)
}

struct RawPreviewHeaders<'a> {
    relative_file: &'a str,
    kind: PreviewKind,
    range: Option<(u64, u64)>,
    length: u64,
    start: u64,
    end: u64,
    response_length: u64,
}

fn add_raw_preview_headers(response: &mut Response, values: &RawPreviewHeaders<'_>) -> Result<()> {
    if values.range.is_some() {
        *response.status_mut() = StatusCode::PARTIAL_CONTENT;
        response.headers_mut().insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!(
                "bytes {}-{}/{}",
                values.start, values.end, values.length
            ))
            .map_err(|error| {
                AppError::from(report_internal(
                    InternalOperation::WebRawPreviewContentRangeHeader,
                    error,
                ))
            })?,
        );
    }
    let name = Path::new(values.relative_file)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("preview");
    let filename = percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC);
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&values.response_length.to_string()).map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebRawPreviewContentLengthHeader,
                error,
            ))
        })?,
    );
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(values.kind.content_type()),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("inline; filename*=UTF-8''{filename}")).map_err(
            |error| {
                AppError::from(report_internal(
                    InternalOperation::WebRawPreviewDispositionHeader,
                    error,
                ))
            },
        )?,
    );
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    Ok(())
}
