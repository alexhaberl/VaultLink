use super::{
    admission::*,
    auth_ui::*,
    common::*,
    preview_zip::*,
    public::*,
    public_preview::*,
    rendering::*,
    router,
    settings_audit::*,
    storage_recovery_app_error,
    transfer::{install_zip_blocking_test_hook, ZipBlockingTestHook, ZipBlockingTestPhase},
    transfer_runtime::*,
    upload::*,
    AppError, ServerRequestId, BUFFERED_RESPONSE_CHUNK_BYTES, DEFAULT_REQUEST_BODY_LIMIT,
    ERROR_CODE_HEADER, MAX_RENDERED_TEXT_PREVIEW_BYTES, MAX_SEARCH_QUERY_BYTES,
    MAX_UPLOAD_PATH_FIELD_BYTES, REQUEST_ID_HEADER, TEXT_PREVIEW_STREAM_MARKER,
};
use crate::config::{
    Admission, Config, Logging, ReverseProxy, Security, Server, ServerMode, Storage, Tls,
};
use crate::{
    auth,
    config::MAX_TEXT_PREVIEW_SIZE,
    db::{
        Permission, Session, Share, TransferLeaseBeginOutcome, UploadConflictStrategy,
        UploadReservationBeginOutcome, UploadReservationCommitOutcome,
        UploadReservationExtendOutcome,
    },
    http_auth::{csrf, runtime_settings, try_acquire_client_activity, try_acquire_share_activity},
    i18n::{self, Locale},
    proxy, AppState,
};
use askama::Template as _;

#[derive(askama::Template)]
#[template(source = r#"<section class="vl-panel"></section>"#, ext = "html")]
struct EmptyPanelTemplate;
use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, Query, Request},
    http::{header, HeaderValue, Method, StatusCode, Uri},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use chrono::{Duration, Utc};
use futures_util::StreamExt;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    io::{self, Read},
    net::SocketAddr,
    path::Path,
    sync::{atomic::Ordering, Arc},
};
use tower::ServiceExt;

fn test_state(root: &Path, data: &Path) -> AppState {
    test_state_with_limit(root, data, 1024 * 1024)
}

fn test_state_with_limit(root: &Path, data: &Path, max_upload_size: u64) -> AppState {
    AppState::new(Config {
        server: Server {
            mode: ServerMode::Development,
            listen_address: "127.0.0.1:8080".into(),
            public_base_url: "http://localhost:8080".into(),
            production_mode: false,
        },
        storage: Storage {
            root_mount_path: root.into(),
            data_directory: data.into(),
            internal_directory: Some(root.join(crate::config::DEFAULT_INTERNAL_DIRECTORY_NAME)),
            require_mount: false,
            external_writers: false,
            allow_external_writer_replace: false,
            expected_filesystem_type: None,
            expected_mount_source: None,
            max_upload_size,
            max_zip_size: 1024 * 1024,
            max_zip_files: 100,
            max_search_entries: 1000,
            max_search_results: 100,
            max_preview_size: 1024,
            preview_extensions: vec!["txt".into(), "log".into(), "md".into()],
            image_preview_extensions: vec![
                "jpg".into(),
                "jpeg".into(),
                "png".into(),
                "gif".into(),
                "webp".into(),
                "bmp".into(),
                "avif".into(),
            ],
            pdf_preview_enabled: true,
            max_media_preview_size: 1024 * 1024,
            blocked_extensions: vec!["exe".into()],
        },
        reverse_proxy: ReverseProxy::default(),
        tls: Tls::default(),
        security: Security {
            secure_cookie: false,
            ..Default::default()
        },
        admission: Admission::default(),
        logging: Logging::default(),
    })
    .unwrap()
}

fn request(method: Method, uri: &str, body: &str) -> Request {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, "vaultlink_locale=de")
        .body(Body::from(body.to_string()))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    request
}

fn zip_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn zip_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn zip_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
