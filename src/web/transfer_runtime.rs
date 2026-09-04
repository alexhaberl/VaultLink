#[cfg(test)]
use std::future::Future;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use askama::Template;
#[cfg(test)]
use axum::body::Body;
use axum::{
    body::Bytes,
    http::{header, HeaderValue, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
};
use futures_util::Stream;
#[cfg(test)]
use tracing::Instrument as _;

use super::{
    common::encoded,
    rendering::{escaped_html_len, push_html_escaped, storage_full_error},
    AppError, Result, BUFFERED_RESPONSE_CHUNK_BYTES, MAX_RENDERED_TEXT_PREVIEW_BYTES,
    TEXT_PREVIEW_STREAM_MARKER,
};

#[derive(Template)]
#[template(path = "web/public/upload_error.html")]
struct PublicUploadErrorTemplate {
    message: String,
    back_link: String,
}
#[cfg(test)]
use crate::{
    db::{
        AuditContext, Database, TransferLeaseBeginOutcome, TransferLeaseCompleteOutcome,
        UploadReservationBeginOutcome,
    },
    http_auth::{database, database_runtime_permit},
    internal_reporting::report_invariant,
    AppState,
};
use crate::{
    i18n::{self},
    internal_reporting::{report_internal, InternalOperation},
};

#[cfg(test)]
include!("transfer_runtime/lease.rs");
#[cfg(test)]
include!("transfer_runtime/reservation.rs");
#[cfg(test)]
include!("transfer_runtime/stream.rs");
include!("transfer_runtime/text.rs");
include!("transfer_runtime/responses.rs");
