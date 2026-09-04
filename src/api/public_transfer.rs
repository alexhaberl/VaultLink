use axum::{
    http::{header, HeaderValue},
    response::Response,
};

use crate::internal_reporting::{report_internal, InternalOperation};

use super::{ApiError, ApiResult};

#[path = "public_transfer/download.rs"]
mod download_adapter;
#[path = "public_transfer/presentation.rs"]
mod presentation;
#[path = "public_transfer/preview.rs"]
mod preview_adapter;
#[path = "public_transfer/raw.rs"]
mod raw_adapter;
#[path = "public_transfer/zip.rs"]
mod zip_adapter;

pub(super) use download_adapter::download;
pub(super) use preview_adapter::public_preview;
pub(super) use raw_adapter::public_preview_raw;
pub(super) use zip_adapter::download_zip;

fn set_transfer_cookie(response: &mut Response, cookie: &str) -> ApiResult<()> {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(cookie).map_err(|error| {
            ApiError::from(report_internal(
                InternalOperation::WebTransferCookieHeader,
                error,
            ))
        })?,
    );
    Ok(())
}
