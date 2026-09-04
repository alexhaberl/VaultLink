//! Transport-neutral public download, ZIP and preview preparation.
//!
//! HTTP adapters remain responsible for cookies, request headers and response
//! rendering. This service owns capability revalidation, descriptor-safe opens,
//! transfer leases and the streams whose finalizers update the required audit.

mod lease;
mod prepare;
mod preview;
mod stream;
mod zip;

pub(crate) use lease::{PublicTransferClient, PublicTransferLease};
pub(crate) use prepare::{
    PreparedFileSelection, PreparedPreview, PreparedPreviewTarget, PreparedZipScope,
    PublicTransferError, PublicTransferService, RangeSelectionError,
};
pub(crate) use preview::{
    escaped_html_len, escaped_text_page_stream, read_preview, read_preview_secure_file,
    PreviewContent,
};
#[cfg(test)]
pub(crate) use preview::{
    read_preview_opened, TextPreviewReadTestGuard, TextPreviewReadTestHook,
    TEXT_PREVIEW_READ_TEST_HOOK,
};
pub(crate) use stream::{complete_transfer_without_body, transfer_stream};
pub(crate) use zip::{
    build_zip_temp, direct_zip_stream_with_resources, plan_zip, ReservedZipStream, ZipBuildError,
    ZipPlan, ZipTempReservation,
};
#[cfg(test)]
pub(crate) use zip::{
    checked_zip_plan_memory, direct_zip_stream, estimate_zip_archive_size,
    write_streaming_central_entry, write_streaming_eocd, write_streaming_zip64_eocd,
    write_streaming_zip64_locator, write_zip_archive, zip_requires_direct_stream,
    zip_temp_reserved_bytes_for_test, StreamingZipEntry, ZipFilePlan, ZIP64_CENTRAL_EXTRA_SIZE,
    ZIP64_EXTRA_PAYLOAD_SIZE, ZIP64_LOCAL_EXTRA_SIZE, ZIP64_SIZE_FIELDS_SIZE, ZIP64_VERSION,
    ZIP_EOCD_SIZE, ZIP_PLAN_MAX_BYTES,
};

pub(crate) use crate::http_contract::STREAM_BUFFER_BYTES as BUFFERED_RESPONSE_CHUNK_BYTES;
