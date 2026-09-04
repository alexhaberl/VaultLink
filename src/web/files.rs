use askama::Template;
use axum::{
    body::Body,
    extract::{Form, Json, Multipart, Query, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::{DateTime, SecondsFormat, Utc};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio_util::io::ReaderStream;
use tracing::Instrument as _;

use crate::log_safety::{EscapedLogPath, EscapedLogValue};

use super::{
    admission::PermitBody,
    common::{
        build_directory_snapshot, encoded, extension_is_blocked, file_sort_column,
        file_sort_column_value, file_sort_direction, file_sort_direction_value, human,
        join_display, list_directory_cursor_page, list_directory_snapshot_cursor_page, parent_path,
        preview_allowed, preview_kind, search_tree, sort_search_hits, BrowseQuery,
    },
    preview_zip::{raw_preview_response, read_preview, PreviewContent},
    public_preview::text_preview_render_permits,
    rendering::{escaped_html_len, storage_has_room, PageId},
    shares::ShareQuery,
    storage_recovery_app_error,
    transfer_runtime::{
        escaped_text_page_stream, limited_multipart_text, upload_io_error, PendingUploadFileError,
    },
    AppError, Result, MAX_RENDERED_TEXT_PREVIEW_BYTES, MAX_SEARCH_QUERY_BYTES,
    MAX_UPLOAD_OPTION_FIELD_BYTES, MAX_UPLOAD_PATH_FIELD_BYTES, SESSION_REVOKED_MESSAGE,
};

include!("files/views.rs");
use crate::{
    db::{AuditAction, AuditContext, MfaSessionProof, RequiredAuditEvent, SessionBound},
    directory_cache::{DirectoryCacheLookup, DirectorySnapshotKey},
    file_ops,
    http_auth::{
        audit_observation, csrf, current_audit_client_ip, current_client_limit_key, database,
        enabled_audit_client_ip, mfa_session, runtime_settings, session, with_audit_client_ip,
        ClientActivityPermit, MissingSession,
    },
    http_contract::request_body_timed_out,
    i18n::{self, Locale},
    internal_reporting::{report_internal, InternalOperation},
    path_security,
    policy::PreviewKind,
    secure_fs::PendingUpload,
    services::{
        error::ServiceError,
        file::{
            FileConflict, FileMutationError, FileMutationResult, FileServiceError,
            FileValidationError,
        },
        public_upload::UploadDisposition,
        upload::{StagedFileError, StagedUploadFile},
    },
    FileRouteState,
};

include!("files/mutations.rs");
include!("files/admin_upload.rs");
include!("files/admin_upload_flow.rs");
include!("files/browser.rs");
include!("files/download.rs");
include!("files/preview.rs");
