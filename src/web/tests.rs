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
    AppError, BUFFERED_RESPONSE_CHUNK_BYTES, DEFAULT_REQUEST_BODY_LIMIT, ERROR_CODE_HEADER,
    MAX_RENDERED_TEXT_PREVIEW_BYTES, MAX_SEARCH_QUERY_BYTES, MAX_UPLOAD_PATH_FIELD_BYTES,
    TEXT_PREVIEW_STREAM_MARKER,
};
use crate::config::{Config, Logging, ReverseProxy, Security, Server, ServerMode, Storage, Tls};
use crate::{
    auth,
    config::MAX_TEXT_PREVIEW_SIZE,
    db::{
        Permission, Session, Share, TransferLeaseBeginOutcome, UploadConflictStrategy,
        UploadReservationBeginOutcome, UploadReservationCommitOutcome,
        UploadReservationExtendOutcome,
    },
    http_auth::{csrf, runtime_settings, try_acquire_client_activity},
    i18n::{self, Locale},
    proxy, AppState,
};
use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, Request},
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
        logging: Logging::default(),
    })
    .unwrap()
}

fn request(method: Method, uri: &str, body: &str) -> Request {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT_LANGUAGE, "de")
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

#[test]
fn public_preview_back_link_returns_share_parent() {
    assert_eq!(public_back_link("/v/tok", "file.txt", false), "/v/tok");
    assert_eq!(public_back_link("/v/tok", "file.txt", true), "/v/tok");
    assert_eq!(
        public_back_link("/v/tok", "folder/file.txt", true),
        "/v/tok?path=folder"
    );
    assert_eq!(
        public_back_link("/api/v1/public/shares/tok", "folder/file.txt", true),
        "/api/v1/public/shares/tok?path=folder"
    );
}

#[test]
fn storage_full_error_maps_linux_quota_and_space_errors() {
    assert!(storage_full_error(&std::io::Error::from_raw_os_error(28)));
    assert!(storage_full_error(&std::io::Error::from_raw_os_error(122)));
    assert!(!storage_full_error(&std::io::Error::from_raw_os_error(13)));
}

#[test]
fn every_zip_archive_uses_full_zip64_records() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    std::fs::write(root.path().join("docs/tiny.bin"), b"abc").unwrap();
    let state = test_state(root.path(), data.path());
    let scope = state.secure_root.bind_directory("docs").unwrap();
    let files = vec![ZipFilePlan {
        source_path: "tiny.bin".into(),
        archive_name: "tiny.bin".into(),
        scanned_len: 3,
    }];
    let plan = ZipPlan {
        estimated_archive_size: estimate_zip_archive_size(&files).unwrap(),
        files,
        max_data_size: 3,
    };

    let archive = write_zip_archive(&scope, &plan, Vec::new()).unwrap();
    assert_eq!(archive.len() as u64, plan.estimated_archive_size);
    assert_eq!(archive.len(), 265);

    assert_eq!(zip_u32(&archive, 0), 0x0403_4b50);
    assert_eq!(zip_u16(&archive, 4), ZIP64_VERSION);
    assert_eq!(zip_u16(&archive, 6), 0x0808);
    assert_eq!(zip_u32(&archive, 18), u32::MAX);
    assert_eq!(zip_u32(&archive, 22), u32::MAX);
    assert_eq!(zip_u16(&archive, 26), 8);
    assert_eq!(zip_u16(&archive, 28), ZIP64_LOCAL_EXTRA_SIZE as u16);
    assert_eq!(&archive[30..38], b"tiny.bin");
    assert_eq!(zip_u16(&archive, 38), 0x0001);
    assert_eq!(zip_u16(&archive, 40), ZIP64_SIZE_FIELDS_SIZE);
    assert_eq!(zip_u64(&archive, 42), 0);
    assert_eq!(zip_u64(&archive, 50), 0);
    assert_eq!(&archive[58..61], b"abc");

    assert_eq!(zip_u32(&archive, 61), 0x0807_4b50);
    assert_eq!(zip_u32(&archive, 65), 0x3524_41c2);
    assert_eq!(zip_u64(&archive, 69), 3);
    assert_eq!(zip_u64(&archive, 77), 3);

    assert_eq!(zip_u32(&archive, 85), 0x0201_4b50);
    assert_eq!(zip_u16(&archive, 89), ZIP64_VERSION);
    assert_eq!(zip_u16(&archive, 91), ZIP64_VERSION);
    assert_eq!(zip_u32(&archive, 105), u32::MAX);
    assert_eq!(zip_u32(&archive, 109), u32::MAX);
    assert_eq!(zip_u16(&archive, 115), ZIP64_CENTRAL_EXTRA_SIZE as u16);
    assert_eq!(zip_u32(&archive, 127), u32::MAX);
    assert_eq!(&archive[131..139], b"tiny.bin");
    assert_eq!(zip_u16(&archive, 139), 0x0001);
    assert_eq!(zip_u16(&archive, 141), ZIP64_EXTRA_PAYLOAD_SIZE);
    assert_eq!(zip_u64(&archive, 143), 3);
    assert_eq!(zip_u64(&archive, 151), 3);
    assert_eq!(zip_u64(&archive, 159), 0);

    assert_eq!(zip_u32(&archive, 167), 0x0606_4b50);
    assert_eq!(zip_u64(&archive, 171), 44);
    assert_eq!(zip_u16(&archive, 179), ZIP64_VERSION);
    assert_eq!(zip_u16(&archive, 181), ZIP64_VERSION);
    assert_eq!(zip_u64(&archive, 191), 1);
    assert_eq!(zip_u64(&archive, 199), 1);
    assert_eq!(zip_u64(&archive, 207), 82);
    assert_eq!(zip_u64(&archive, 215), 85);
    assert_eq!(zip_u32(&archive, 223), 0x0706_4b50);
    assert_eq!(zip_u64(&archive, 231), 167);
    assert_eq!(zip_u32(&archive, 239), 1);
    assert_eq!(zip_u32(&archive, 243), 0x0605_4b50);
    assert_eq!(zip_u16(&archive, 251), u16::MAX);
    assert_eq!(zip_u16(&archive, 253), u16::MAX);
    assert_eq!(zip_u32(&archive, 255), u32::MAX);
    assert_eq!(zip_u32(&archive, 259), u32::MAX);

    let empty_files = Vec::<ZipFilePlan>::new();
    let empty_plan = ZipPlan {
        estimated_archive_size: estimate_zip_archive_size(&empty_files).unwrap(),
        files: empty_files,
        max_data_size: 0,
    };
    let empty_archive = write_zip_archive(&scope, &empty_plan, Vec::new()).unwrap();
    assert_eq!(empty_archive.len(), 98);
    assert_eq!(zip_u32(&empty_archive, 0), 0x0606_4b50);
    assert_eq!(zip_u64(&empty_archive, 24), 0);
    assert_eq!(zip_u32(&empty_archive, 56), 0x0706_4b50);
    assert_eq!(zip_u32(&empty_archive, 76), 0x0605_4b50);
}

#[test]
fn every_central_entry_uses_zip64_sizes_and_offset() {
    let mut central = Vec::new();
    write_streaming_central_entry(
        &mut central,
        &StreamingZipEntry {
            name: "x".into(),
            crc: 7,
            size: 9,
            local_offset: 11,
        },
    )
    .unwrap();
    assert_eq!(central.len(), 75);
    assert_eq!(zip_u16(&central, 4), ZIP64_VERSION);
    assert_eq!(zip_u32(&central, 20), u32::MAX);
    assert_eq!(zip_u32(&central, 24), u32::MAX);
    assert_eq!(zip_u16(&central, 30), ZIP64_CENTRAL_EXTRA_SIZE as u16);
    assert_eq!(zip_u32(&central, 42), u32::MAX);
    assert_eq!(&central[46..47], b"x");
    assert_eq!(zip_u16(&central, 47), 0x0001);
    assert_eq!(zip_u16(&central, 49), ZIP64_EXTRA_PAYLOAD_SIZE);
    assert_eq!(zip_u64(&central, 51), 9);
    assert_eq!(zip_u64(&central, 59), 9);
    assert_eq!(zip_u64(&central, 67), 11);
}

#[test]
fn zip64_end_records_preserve_64_bit_directory_values() {
    let entries = u16::MAX as u64;
    let central_size = u32::MAX as u64 + 3;
    let central_offset = u32::MAX as u64 + 9;
    let zip64_eocd_offset = 0x2_0000_0042;
    let mut records = Vec::new();
    write_streaming_zip64_eocd(&mut records, entries, central_size, central_offset).unwrap();
    write_streaming_zip64_locator(&mut records, zip64_eocd_offset).unwrap();
    write_streaming_eocd(&mut records).unwrap();

    assert_eq!(records.len(), 98);
    assert_eq!(zip_u32(&records, 0), 0x0606_4b50);
    assert_eq!(zip_u64(&records, 4), 44);
    assert_eq!(zip_u16(&records, 12), ZIP64_VERSION);
    assert_eq!(zip_u16(&records, 14), ZIP64_VERSION);
    assert_eq!(zip_u64(&records, 24), entries);
    assert_eq!(zip_u64(&records, 32), entries);
    assert_eq!(zip_u64(&records, 40), central_size);
    assert_eq!(zip_u64(&records, 48), central_offset);
    assert_eq!(zip_u32(&records, 56), 0x0706_4b50);
    assert_eq!(zip_u64(&records, 64), zip64_eocd_offset);
    assert_eq!(zip_u32(&records, 72), 1);
    assert_eq!(zip_u32(&records, 76), 0x0605_4b50);
    assert_eq!(zip_u16(&records, 84), u16::MAX);
    assert_eq!(zip_u16(&records, 86), u16::MAX);
    assert_eq!(zip_u32(&records, 88), u32::MAX);
    assert_eq!(zip_u32(&records, 92), u32::MAX);
}

#[test]
fn always_zip64_estimate_is_fixed_and_rejects_u64_overflow() {
    assert_eq!(estimate_zip_archive_size(&[]).unwrap(), 98);

    let tiny_file = ZipFilePlan {
        source_path: "tiny.bin".into(),
        archive_name: "tiny.bin".into(),
        scanned_len: 3,
    };
    assert_eq!(estimate_zip_archive_size(&[tiny_file]).unwrap(), 265);

    let multiple_files = [
        ZipFilePlan {
            source_path: "first".into(),
            archive_name: "x".into(),
            scanned_len: 0,
        },
        ZipFilePlan {
            source_path: "second".into(),
            archive_name: "long".into(),
            scanned_len: 10,
        },
    ];
    assert_eq!(estimate_zip_archive_size(&multiple_files).unwrap(), 414);

    let overflowing_file = ZipFilePlan {
        source_path: "overflow.bin".into(),
        archive_name: "overflow.bin".into(),
        scanned_len: u64::MAX,
    };
    assert!(matches!(
        estimate_zip_archive_size(&[overflowing_file]),
        Err(ZipBuildError::Limit("zip archive size overflow"))
    ));
}

#[tokio::test]
async fn response_admission_releases_handlers_but_bounds_stream_bodies() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut state = test_state(root.path(), data.path());
    let admission = Arc::new(tokio::sync::Semaphore::new(1));
    let streams = Arc::new(tokio::sync::Semaphore::new(1));
    state.response_admission = admission.clone();
    state.stream_admission = streams.clone();
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .route("/download", get(|| async { "stream" }))
        .layer(middleware::from_fn_with_state(state, response_admission));

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/download")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(admission.available_permits(), 1);
    assert_eq!(streams.available_permits(), 0);

    let normal = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(normal.status(), StatusCode::OK);
    assert_eq!(admission.available_permits(), 1);

    let saturated = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/download")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(saturated.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        saturated.headers().get(header::RETRY_AFTER),
        Some(&HeaderValue::from_static("1"))
    );

    drop(first);
    assert_eq!(streams.available_permits(), 1);
    assert_eq!(
        app.oneshot(
            Request::builder()
                .uri("/download")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn absolute_body_deadline_stops_a_body_that_never_yields() {
    let inner = Body::from_stream(futures_util::stream::pending::<io::Result<Bytes>>());
    let body = Body::new(AbsoluteDeadlineBody {
        inner,
        deadline: Box::pin(tokio::time::sleep(std::time::Duration::from_millis(1))),
        timed_out: false,
    });
    let error = axum::body::to_bytes(body, 1024)
        .await
        .expect_err("pending body must hit its absolute deadline");
    assert!(error.to_string().contains("deadline"));
    assert!(!upload_request_path("/login"));
    assert!(upload_request_path("/v/token/upload"));
    assert!(upload_request_path("/api/v1/public/shares/token/upload"));
}

#[tokio::test]
async fn public_transfer_deadline_stops_a_stream_that_never_yields() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let mut stream = TransferBodyStream {
        inner: Box::pin(futures_util::stream::pending()),
        database: state.db,
        lease_token: None,
        client_ip: None,
        action: "download",
        share_id: 1,
        heartbeat_stop: None,
        finalize: None,
        pending_chunk: None,
        remaining_bytes: None,
        deadline: Box::pin(tokio::time::sleep(std::time::Duration::from_millis(1))),
        timed_out: false,
        complete: false,
    };
    let error = tokio::time::timeout(std::time::Duration::from_millis(250), stream.next())
        .await
        .expect("transfer deadline must wake the stream")
        .expect("deadline returns one terminal error")
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(stream.next().await.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_cancellation_releases_unclaimed_transfer_and_upload_begins() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let transfer_share = state
        .db
        .create_share(
            "cancelled-transfer",
            None,
            "file.txt",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let upload_share = state
        .db
        .create_share_with_upload_limits(
            "cancelled-upload",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            Some(10),
            Some(100),
            Some(10),
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();

    let transfer_database = state.db.clone();
    let (transfer_ready_sender, transfer_ready_receiver) = tokio::sync::oneshot::channel();
    let transfer_request = tokio::spawn(async move {
        let pending = begin_transfer_lease_cancellation_safe(
            transfer_database,
            "cancelled-session".into(),
            "cancelled-lease".into(),
            transfer_share,
            "file.txt".into(),
            "download",
        )
        .await
        .unwrap();
        assert_eq!(pending.outcome(), TransferLeaseBeginOutcome::NewLease);
        transfer_ready_sender.send(()).unwrap();
        std::future::pending::<()>().await;
        pending.claim();
    });
    transfer_ready_receiver.await.unwrap();
    assert_eq!(
        state
            .db
            .active_transfer_reservations(transfer_share)
            .unwrap(),
        1
    );
    transfer_request.abort();
    let _ = transfer_request.await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while state
            .db
            .active_transfer_reservations(transfer_share)
            .unwrap()
            != 0
        {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("cancelled transfer reservation should be released");
    assert_eq!(
        state
            .db
            .active_transfer_reservations(transfer_share)
            .unwrap(),
        0
    );

    let upload_database = state.db.clone();
    let (upload_ready_sender, upload_ready_receiver) = tokio::sync::oneshot::channel();
    let upload_request = tokio::spawn(async move {
        let pending = begin_upload_reservation_cancellation_safe(
            upload_database,
            "cancelled-upload-reservation".into(),
            upload_share,
            0,
        )
        .await
        .unwrap();
        assert_eq!(pending.outcome(), UploadReservationBeginOutcome::Reserved);
        upload_ready_sender.send(()).unwrap();
        std::future::pending::<()>().await;
        pending.claim();
    });
    upload_ready_receiver.await.unwrap();
    assert_eq!(
        state.db.active_upload_reservations(upload_share).unwrap(),
        1
    );
    upload_request.abort();
    let _ = upload_request.await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while state.db.active_upload_reservations(upload_share).unwrap() != 0 {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("cancelled upload reservation should be released");
    assert_eq!(
        state.db.active_upload_reservations(upload_share).unwrap(),
        0
    );
}

#[tokio::test]
async fn consuming_lease_and_quota_guards_finish_their_durable_ownership() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let transfer_share = state
        .db
        .create_share(
            "consuming-transfer",
            None,
            "file.txt",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let upload_share = state
        .db
        .create_share_with_upload_limits(
            "consuming-upload",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            Some(10),
            Some(100),
            Some(10),
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();

    assert_eq!(
        state
            .db
            .begin_transfer_lease(
                "consuming-session",
                "consuming-lease",
                transfer_share,
                "file.txt",
                "download",
            )
            .unwrap(),
        TransferLeaseBeginOutcome::NewLease
    );
    PublicTransferLease::new(
        state.db.clone(),
        "consuming-lease".into(),
        String::new(),
        None,
        None,
    )
    .cancel()
    .await;
    assert_eq!(
        state
            .db
            .active_transfer_reservations(transfer_share)
            .unwrap(),
        0
    );

    assert_eq!(
        state
            .db
            .begin_upload_reservation("consuming-cancel", upload_share, 0)
            .unwrap(),
        UploadReservationBeginOutcome::Reserved
    );
    UploadQuotaReservation::new(state.db.clone(), "consuming-cancel".into())
        .cancel()
        .await
        .unwrap();
    assert_eq!(
        state.db.active_upload_reservations(upload_share).unwrap(),
        0
    );

    assert_eq!(
        state
            .db
            .begin_upload_reservation("consuming-commit", upload_share, 0)
            .unwrap(),
        UploadReservationBeginOutcome::Reserved
    );
    let committed = UploadQuotaReservation::new(state.db.clone(), "consuming-commit".into());
    assert_eq!(
        state
            .db
            .extend_upload_reservation("consuming-commit", 1)
            .unwrap(),
        UploadReservationExtendOutcome::Extended
    );
    assert_eq!(
        state
            .db
            .commit_upload_reservation("consuming-commit", 1)
            .unwrap(),
        UploadReservationCommitOutcome::Committed
    );
    committed.committed();
    assert_eq!(
        state.db.active_upload_reservations(upload_share).unwrap(),
        0
    );
}

#[test]
fn reservation_drop_schedules_blocking_cleanup_before_immediate_runtime_shutdown() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let transfer_share = state
        .db
        .create_share(
            "shutdown-transfer",
            None,
            "file.txt",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let upload_share = state
        .db
        .create_share_with_upload_limits(
            "shutdown-upload",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            Some(10),
            Some(100),
            Some(10),
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let database = state.db.clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        assert_eq!(
            database
                .begin_transfer_lease(
                    "shutdown-session",
                    "shutdown-lease",
                    transfer_share,
                    "file.txt",
                    "download",
                )
                .unwrap(),
            TransferLeaseBeginOutcome::NewLease
        );
        assert_eq!(
            database
                .begin_upload_reservation("shutdown-upload-reservation", upload_share, 0)
                .unwrap(),
            UploadReservationBeginOutcome::Reserved
        );
        let _transfer = PublicTransferLease::new(
            database.clone(),
            "shutdown-lease".into(),
            String::new(),
            None,
            None,
        );
        let _upload =
            UploadQuotaReservation::new(database.clone(), "shutdown-upload-reservation".into());
    });
    drop(runtime);

    assert_eq!(
        database
            .active_transfer_reservations(transfer_share)
            .unwrap(),
        0
    );
    assert_eq!(
        database.active_upload_reservations(upload_share).unwrap(),
        0
    );
}

#[tokio::test]
async fn unknown_length_transfer_counts_before_its_first_payload_chunk_is_yielded() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db
        .create_share(
            "direct-stream",
            None,
            "file.txt",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    assert_eq!(
        state
            .db
            .begin_transfer_lease(
                "direct-session",
                "direct-lease",
                share_id,
                ".",
                "zip_download",
            )
            .unwrap(),
        TransferLeaseBeginOutcome::NewLease
    );
    let transfer = PublicTransferLease::new(
        state.db.clone(),
        "direct-lease".into(),
        String::new(),
        None,
        None,
    );
    let source = futures_util::stream::iter([
        Ok::<_, io::Error>(Bytes::from_static(b"first")),
        Ok(Bytes::from_static(b"second")),
    ]);
    let mut body =
        transfer_body(source, &state, transfer, "zip_download", share_id, None).into_data_stream();
    assert_eq!(body.next().await.unwrap().unwrap().as_ref(), b"first");
    drop(body); // no EOF poll and no second payload chunk
    assert_eq!(
        state
            .db
            .share_by_token("direct-stream")
            .unwrap()
            .unwrap()
            .download_count,
        1
    );
    assert_eq!(state.db.active_transfer_reservations(share_id).unwrap(), 0);
}

#[tokio::test]
async fn public_transfer_completion_uses_the_validated_audit_ip_snapshot() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("snapshot.txt"), b"snapshot").unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_share(
            "snapshot-transfer",
            None,
            "snapshot.txt",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    state.runtime.write().unwrap().audit_client_ip_enabled = true;
    let response = router(state.clone())
        .oneshot(request(Method::GET, "/v/snapshot-transfer/download", ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let runtime = state.runtime.clone();
    assert!(std::thread::spawn(move || {
        let _guard = runtime.write().unwrap();
        panic!("poison runtime after transfer lease begin");
    })
    .join()
    .is_err());
    assert!(state.runtime.is_poisoned());

    assert_eq!(response_text(response).await, "snapshot");
    let events = state.db.list_audit(Some("download"), 10, 0).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].client_ip.as_deref(), Some("127.0.0.1"));
}

#[tokio::test]
async fn known_length_transfer_counts_before_n_minus_one_bytes_are_yielded() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db
        .create_share(
            "known-stream",
            None,
            "file.txt",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    assert_eq!(
        state
            .db
            .begin_transfer_lease("known-session", "known-lease", share_id, ".", "download",)
            .unwrap(),
        TransferLeaseBeginOutcome::NewLease
    );
    let transfer = PublicTransferLease::new(
        state.db.clone(),
        "known-lease".into(),
        String::new(),
        None,
        None,
    );
    let source = futures_util::stream::iter([
        Ok::<_, io::Error>(Bytes::from_static(b"abcde")),
        Ok(Bytes::from_static(b"f")),
    ]);
    let mut body =
        transfer_body(source, &state, transfer, "download", share_id, Some(6)).into_data_stream();

    assert_eq!(body.next().await.unwrap().unwrap().as_ref(), b"abcde");
    assert_eq!(
        state
            .db
            .share_by_token("known-stream")
            .unwrap()
            .unwrap()
            .download_count,
        1
    );
    assert_eq!(state.db.active_transfer_reservations(share_id).unwrap(), 0);
    drop(body); // the final byte is never requested
}

#[tokio::test]
async fn response_body_wrappers_chunk_buffered_data_and_deadline_streams() {
    let counts = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let peer = "192.0.2.1".parse().unwrap();
    let buffered_slots = Arc::new(tokio::sync::Semaphore::new(1));
    let buffered_permit = buffered_slots.clone().try_acquire_owned().unwrap();
    let buffered_peer = try_acquire_client_activity(counts.clone(), peer, 1)
        .unwrap()
        .unwrap();
    let input = vec![7u8; BUFFERED_RESPONSE_CHUNK_BYTES * 2 + 17];
    let body = Body::new(BufferedAdmissionBody {
        inner: Body::from(input.clone()),
        _permit: buffered_permit,
        _peer_permit: buffered_peer,
        pending: None,
        complete: false,
        deadline: Box::pin(tokio::time::sleep(std::time::Duration::from_secs(1))),
    });
    let mut stream = body.into_data_stream();
    let mut output = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.unwrap();
        assert!(chunk.len() <= BUFFERED_RESPONSE_CHUNK_BYTES);
        output.extend_from_slice(&chunk);
    }
    assert_eq!(output, input);
    drop(stream);
    assert_eq!(buffered_slots.available_permits(), 1);
    assert!(counts.lock().unwrap().is_empty());

    let stream_slots = Arc::new(tokio::sync::Semaphore::new(1));
    let stream_permit = stream_slots.clone().try_acquire_owned().unwrap();
    let stream_peer = try_acquire_client_activity(counts.clone(), peer, 1)
        .unwrap()
        .unwrap();
    let body = Body::new(StreamAdmissionBody {
        inner: Body::from_stream(futures_util::stream::pending::<io::Result<Bytes>>()),
        _permit: stream_permit,
        _peer_permit: stream_peer,
        deadline: Box::pin(tokio::time::sleep(std::time::Duration::from_millis(1))),
        complete: false,
    });
    let error = axum::body::to_bytes(body, 1024)
        .await
        .expect_err("pending stream must hit the response deadline");
    assert!(error.to_string().contains("lifetime"));
    assert_eq!(stream_slots.available_permits(), 1);
    assert!(counts.lock().unwrap().is_empty());
}

#[test]
fn client_activity_limits_group_ipv6_prefixes_and_release_on_drop() {
    let counts = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let first = proxy::client_limit_key("2001:db8:1:2::1".parse().unwrap());
    let rotated = proxy::client_limit_key("2001:db8:1:2:ffff::99".parse().unwrap());
    let other_prefix = proxy::client_limit_key("2001:db8:1:3::1".parse().unwrap());
    assert_eq!(first, rotated);
    let permit = try_acquire_client_activity(counts.clone(), first, 1)
        .unwrap()
        .unwrap();
    assert!(try_acquire_client_activity(counts.clone(), rotated, 1)
        .unwrap()
        .is_none());
    let other = try_acquire_client_activity(counts.clone(), other_prefix, 1)
        .unwrap()
        .unwrap();
    drop(permit);
    assert!(try_acquire_client_activity(counts.clone(), first, 1)
        .unwrap()
        .is_some());
    drop(other);
}

#[tokio::test]
async fn non_upload_routes_reject_large_buffered_bodies() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let app = router(state);
    let oversized = format!(
        "username={}&password=x",
        "a".repeat(DEFAULT_REQUEST_BODY_LIMIT)
    );
    assert_eq!(
        app.oneshot(request(Method::POST, "/login", &oversized))
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn upload_routes_reject_multipart_headers_before_the_parser_can_buffer_them() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_share(
            "guarded-upload",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let app = router(state);
    let boundary = "guard-boundary";
    let body = format!(
        "--{boundary}\r\nX-Long: {}\r\n\r\nvalue\r\n--{boundary}--\r\n",
        "x".repeat(crate::multipart_guard::DEFAULT_MAX_HEADER_BYTES + 1)
    );
    let mut malformed = Request::builder()
        .method(Method::POST)
        .uri("/v/guarded-upload/upload")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap();
    malformed.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    assert_eq!(
        app.clone().oneshot(malformed).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    let mut missing_content_type = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/public/shares/missing/upload")
        .body(Body::empty())
        .unwrap();
    missing_content_type.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    let response = app.oneshot(missing_content_type).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(response.headers()[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("application/json"));
}

#[tokio::test]
async fn zip_temp_and_direct_paths_cap_files_at_the_scanned_size() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    let file_path = root.path().join("docs/file.txt");
    std::fs::write(&file_path, b"small").unwrap();
    let state = test_state(root.path(), data.path());
    let scope = state.secure_root.bind_directory("docs").unwrap();
    let settings = runtime_settings(&state);
    let plan = plan_zip(&scope, "", &settings).unwrap();
    let estimated_archive_size = plan.estimated_archive_size;

    const GROWN_MARKER: &[u8] = b"-must-not-enter-the-archive";
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&file_path)
        .unwrap()
        .write_all(GROWN_MARKER)
        .unwrap();

    let mut temp_file = build_zip_temp(&scope, &plan).unwrap();
    let mut temp_bytes = Vec::new();
    temp_file.read_to_end(&mut temp_bytes).unwrap();

    let mut direct_bytes = Vec::new();
    let mut stream = Box::pin(direct_zip_stream(scope, plan));
    while let Some(chunk) = stream.next().await {
        direct_bytes.extend_from_slice(&chunk.unwrap());
    }

    assert_eq!(direct_bytes, temp_bytes);
    assert_eq!(temp_bytes.len() as u64, estimated_archive_size);
    assert!(temp_bytes.starts_with(b"PK\x03\x04"));
    let eocd = temp_bytes.len() - ZIP_EOCD_SIZE as usize;
    assert_eq!(zip_u32(&temp_bytes, eocd), 0x0605_4b50);
    assert_eq!(zip_u16(&temp_bytes, eocd + 8), u16::MAX);
    assert_eq!(zip_u16(&temp_bytes, eocd + 10), u16::MAX);
    assert_eq!(zip_u32(&temp_bytes, eocd + 12), u32::MAX);
    assert_eq!(zip_u32(&temp_bytes, eocd + 16), u32::MAX);
    assert!(!temp_bytes
        .windows(GROWN_MARKER.len())
        .any(|window| window == GROWN_MARKER));
}

#[test]
fn zero_disables_zip_size_and_file_count_limits() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    std::fs::write(root.path().join("docs/one.txt"), b"one").unwrap();
    std::fs::write(root.path().join("docs/two.txt"), b"two").unwrap();
    let state = test_state(root.path(), data.path());
    let scope = state.secure_root.bind_directory("docs").unwrap();
    let mut settings = runtime_settings(&state);
    settings.max_zip_size = 0;
    settings.max_zip_files = 0;

    let plan = plan_zip(&scope, "", &settings).unwrap();
    assert_eq!(plan.files.len(), 2);
    assert_eq!(plan.max_data_size, 0);
    write_zip_archive(&scope, &plan, Vec::new()).unwrap();
}

#[test]
fn zip_planning_bounds_empty_directory_scans() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    std::fs::create_dir(root.path().join("docs/one")).unwrap();
    std::fs::create_dir(root.path().join("docs/two")).unwrap();
    std::fs::create_dir(root.path().join("single")).unwrap();
    std::fs::write(root.path().join("single/only.txt"), b"one").unwrap();
    let state = test_state(root.path(), data.path());
    let scope = state.secure_root.bind_directory("docs").unwrap();
    let mut settings = runtime_settings(&state);
    settings.max_search_entries = 1;
    assert!(matches!(
        plan_zip(&scope, "", &settings),
        Err(ZipBuildError::Limit("zip scan entry limit exceeded"))
    ));
    let single = state.secure_root.bind_directory("single").unwrap();
    assert_eq!(plan_zip(&single, "", &settings).unwrap().files.len(), 1);
}

#[test]
fn filtered_directory_items_consume_listing_search_and_zip_budgets() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    for _ in 0..2 {
        std::fs::write(
            root.path()
                .join("docs")
                .join(crate::secure_fs::upload_fragment_name()),
            b"partial",
        )
        .unwrap();
    }
    let state = test_state(root.path(), data.path());
    let scope = state.secure_root.bind_directory("docs").unwrap();
    let mut settings = runtime_settings(&state);
    settings.max_search_entries = 1;

    let (entries, truncated) = list_directory_page(&scope, "", 0, 1).unwrap();
    assert!(entries.is_empty());
    assert!(truncated);
    assert!(search_tree(scope.clone(), "", "missing", &settings)
        .unwrap()
        .is_empty());
    assert!(matches!(
        plan_zip(&scope, "", &settings),
        Err(ZipBuildError::Limit("zip scan entry limit exceeded"))
    ));
}

fn multipart_request(uri: &str, name: &str, content: &[u8]) -> Request {
    multipart_request_with_path(uri, name, content, None)
}

fn multipart_request_with_path(
    uri: &str,
    name: &str,
    content: &[u8],
    path: Option<&str>,
) -> Request {
    multipart_request_with_options(uri, name, content, path, false)
}

fn multipart_request_with_options(
    uri: &str,
    name: &str,
    content: &[u8],
    path: Option<&str>,
    overwrite_existing: bool,
) -> Request {
    let boundary = "vaultlink-test-boundary";
    let mut body = Vec::new();
    if let Some(path) = path {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n{path}\r\n"
            )
            .as_bytes(),
        );
    }
    if overwrite_existing {
        body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"overwrite_existing\"\r\n\r\n1\r\n"
                )
                .as_bytes(),
            );
    }
    body.extend_from_slice(format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        ).as_bytes());
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::ACCEPT_LANGUAGE, "de")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    request
}

fn multipart_request_with_late_overwrite(uri: &str, name: &str, content: &[u8]) -> Request {
    let boundary = "vaultlink-late-intent-boundary";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(content);
    body.extend_from_slice(
        format!(
            "\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"overwrite_existing\"\r\n\r\n1\r\n--{boundary}--\r\n"
        )
        .as_bytes(),
    );
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::ACCEPT_LANGUAGE, "de")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    request
}

fn public_folder_upload_request(
    uri: &str,
    path: &str,
    folder_path: &str,
    name: &str,
    content: &[u8],
) -> Request {
    folder_upload_request(uri, path, None, folder_path, name, content)
}

fn raw_multipart_request(uri: &str, boundary: &str, body: Vec<u8>) -> Request {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::ACCEPT_LANGUAGE, "de")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    request
}

const CONTROLLED_UPLOAD_BOUNDARY: &str = "vaultlink-controlled-upload-boundary";

fn controlled_multipart_request(
    uri: &str,
    name: &str,
    content: &[u8],
    overwrite_requested: bool,
) -> (
    Request,
    tokio::sync::mpsc::Sender<std::result::Result<Bytes, io::Error>>,
) {
    let (sender, receiver) = tokio::sync::mpsc::channel(4);
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|chunk| (chunk, receiver))
    });
    let mut prefix = Vec::new();
    if overwrite_requested {
        prefix.extend_from_slice(
            format!(
                "--{CONTROLLED_UPLOAD_BOUNDARY}\r\nContent-Disposition: form-data; name=\"overwrite_existing\"\r\n\r\n1\r\n"
            )
            .as_bytes(),
        );
    }
    prefix.extend_from_slice(
        format!(
            "--{CONTROLLED_UPLOAD_BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    prefix.extend_from_slice(content);
    sender.try_send(Ok(Bytes::from(prefix))).unwrap();
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::ACCEPT_LANGUAGE, "de")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={CONTROLLED_UPLOAD_BOUNDARY}"),
        )
        .body(Body::from_stream(stream))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    (request, sender)
}

async fn finish_controlled_multipart(
    sender: tokio::sync::mpsc::Sender<std::result::Result<Bytes, io::Error>>,
) {
    sender
        .send(Ok(Bytes::from(format!(
            "\r\n--{CONTROLLED_UPLOAD_BOUNDARY}--\r\n"
        ))))
        .await
        .unwrap();
}

async fn wait_for_upload_fragment(root: &Path) {
    let staging = root.join(".vaultlink-internal").join("uploads");
    for _ in 0..200 {
        if std::fs::read_dir(&staging).is_ok_and(|mut entries| entries.next().is_some()) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("upload did not reach staging");
}

fn upload_fragment_count(root: &Path) -> usize {
    std::fs::read_dir(root.join(".vaultlink-internal").join("uploads"))
        .map(|entries| entries.filter_map(std::result::Result::ok).count())
        .unwrap_or_default()
}

async fn wait_for_public_upload_cleanup(state: &AppState, root: &Path, share_id: i64) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if state.db.active_upload_reservations(share_id).unwrap() == 0
                && upload_fragment_count(root) == 0
                && state.upload_admission.available_permits() == 1
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("public upload resources should be released");
}

fn api_share_strategy_request(
    share_id: i64,
    strategy: &str,
    session_token: &str,
    csrf_token: &str,
) -> Request {
    let mut request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/api/v1/shares/{share_id}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("vaultlink_session={session_token}"))
        .header("x-csrf-token", csrf_token)
        .body(Body::from(format!(
            r#"{{"upload_conflict_strategy":"{strategy}"}}"#
        )))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    request
}

fn html_share_strategy_request(
    share_id: i64,
    strategy: &str,
    session_token: &str,
    csrf_token: &str,
) -> Request {
    let mut request = request(
        Method::POST,
        &format!("/admin/shares/{share_id}/upload-conflict"),
        &format!("csrf={csrf_token}&strategy={strategy}"),
    );
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("vaultlink_session={session_token}")).unwrap(),
    );
    request
}

fn public_multipart_request_with_csrf(
    uri: &str,
    name: &str,
    content: &[u8],
    csrf: &str,
) -> Request {
    let boundary = "vaultlink-public-csrf-boundary";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n{csrf}\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::ACCEPT_LANGUAGE, "de")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    request
}

fn admin_multipart_request(
    uri: &str,
    path: &str,
    csrf: &str,
    name: &str,
    content: &[u8],
    overwrite_existing: bool,
) -> Request {
    let boundary = "vaultlink-admin-upload-boundary";
    let mut body = Vec::new();
    for (field, value) in [("path", path), ("csrf", csrf)] {
        body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{value}\r\n"
                )
                .as_bytes(),
            );
    }
    if overwrite_existing {
        body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"overwrite_existing\"\r\n\r\n1\r\n"
                )
                .as_bytes(),
            );
    }
    body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::ACCEPT_LANGUAGE, "de")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    request
}

fn admin_folder_upload_request(
    uri: &str,
    path: &str,
    csrf: &str,
    folder_path: &str,
    name: &str,
    content: &[u8],
) -> Request {
    folder_upload_request(uri, path, Some(csrf), folder_path, name, content)
}

fn folder_upload_request(
    uri: &str,
    path: &str,
    csrf: Option<&str>,
    folder_path: &str,
    name: &str,
    content: &[u8],
) -> Request {
    let boundary = "vaultlink-folder-upload-boundary";
    let mut body = Vec::new();
    for (field, value) in [
        ("path", Some(path)),
        ("csrf", csrf),
        ("folder_path", Some(folder_path)),
    ] {
        if let Some(value) = value {
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{value}\r\n"
                )
                .as_bytes(),
            );
        }
    }
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::ACCEPT_LANGUAGE, "de")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    request
}

async fn response_text(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn windows_1252_byte(ch: char) -> Option<u8> {
    match ch {
        '\u{0000}'..='\u{009f}' | '\u{00a0}'..='\u{00ff}' => Some(ch as u32 as u8),
        '\u{20ac}' => Some(0x80),
        '\u{201a}' => Some(0x82),
        '\u{0192}' => Some(0x83),
        '\u{201e}' => Some(0x84),
        '\u{2026}' => Some(0x85),
        '\u{2020}' => Some(0x86),
        '\u{2021}' => Some(0x87),
        '\u{02c6}' => Some(0x88),
        '\u{2030}' => Some(0x89),
        '\u{0160}' => Some(0x8a),
        '\u{2039}' => Some(0x8b),
        '\u{0152}' => Some(0x8c),
        '\u{017d}' => Some(0x8e),
        '\u{2018}' => Some(0x91),
        '\u{2019}' => Some(0x92),
        '\u{201c}' => Some(0x93),
        '\u{201d}' => Some(0x94),
        '\u{2022}' => Some(0x95),
        '\u{2013}' => Some(0x96),
        '\u{2014}' => Some(0x97),
        '\u{02dc}' => Some(0x98),
        '\u{2122}' => Some(0x99),
        '\u{0161}' => Some(0x9a),
        '\u{203a}' => Some(0x9b),
        '\u{0153}' => Some(0x9c),
        '\u{017e}' => Some(0x9e),
        '\u{0178}' => Some(0x9f),
        _ => None,
    }
}

fn assert_no_mojibake(label: &str, text: &str) {
    if let Some((offset, _)) = text.char_indices().find(|(_, ch)| *ch == '\u{fffd}') {
        panic!("{label} contains the Unicode replacement character at byte {offset}");
    }

    let chars = text.char_indices().collect::<Vec<_>>();
    for start in 0..chars.len() {
        for len in 2..=4 {
            let end = start + len;
            if end > chars.len() {
                continue;
            }
            let Some(bytes) = chars[start..end]
                .iter()
                .map(|(_, ch)| windows_1252_byte(*ch))
                .collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            let expected_len = match bytes[0] {
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => continue,
            };
            if len != expected_len || !bytes[1..].iter().all(|byte| (0x80..=0xbf).contains(byte)) {
                continue;
            }
            let Ok(decoded) = std::str::from_utf8(&bytes) else {
                continue;
            };
            let start_offset = chars[start].0;
            let end_offset = chars.get(end).map_or(text.len(), |(offset, _)| *offset);
            let suspect = &text[start_offset..end_offset];
            panic!(
                    "{label} contains likely Windows-1252/UTF-8 mojibake at byte {start_offset}: {suspect:?} should be {decoded:?}"
                );
        }
    }
}

fn web_production_sources() -> [(&'static str, &'static str); 16] {
    [
        ("src/web.rs", include_str!("../web.rs")),
        ("src/web/account.rs", include_str!("account.rs")),
        ("src/web/admin.rs", include_str!("admin.rs")),
        ("src/web/admission.rs", include_str!("admission.rs")),
        ("src/web/auth_ui.rs", include_str!("auth_ui.rs")),
        ("src/web/common.rs", include_str!("common.rs")),
        ("src/web/files.rs", include_str!("files.rs")),
        ("src/web/preview_zip.rs", include_str!("preview_zip.rs")),
        ("src/web/public.rs", include_str!("public.rs")),
        (
            "src/web/public_preview.rs",
            include_str!("public_preview.rs"),
        ),
        ("src/web/rendering.rs", include_str!("rendering.rs")),
        (
            "src/web/settings_audit.rs",
            include_str!("settings_audit.rs"),
        ),
        ("src/web/shares.rs", include_str!("shares.rs")),
        ("src/web/transfer.rs", include_str!("transfer.rs")),
        (
            "src/web/transfer_runtime.rs",
            include_str!("transfer_runtime.rs"),
        ),
        ("src/web/upload.rs", include_str!("upload.rs")),
    ]
}

fn preview_token_from(html: &str) -> String {
    let marker = "preview_token=";
    let start = html.find(marker).expect("preview token in html") + marker.len();
    let encoded = html[start..]
        .chars()
        .take_while(|c| *c != '"' && *c != '&')
        .collect::<String>();
    percent_encoding::percent_decode_str(&encoded)
        .decode_utf8()
        .unwrap()
        .into_owned()
}

fn range_request(method: Method, uri: &str, range: Option<&str>) -> Request {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(range) = range {
        builder = builder.header(header::RANGE, range);
    }
    let mut request = builder.body(Body::empty()).unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    request
}
#[test]
fn html_is_escaped() {
    assert_eq!(esc("<script>&\""), "&lt;script&gt;&amp;&quot;");
}

#[test]
fn text_preview_budget_tracks_the_retained_input_buffer() {
    // Escaped HTML is emitted in bounded chunks, so the only large retained
    // allocation is the pre-sized source buffer guarded by these permits.
    assert_eq!(text_preview_render_permits(1_000_000), 1);
    assert_eq!(text_preview_render_permits(MAX_TEXT_PREVIEW_SIZE), 64);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(
        crate::TEXT_PREVIEW_RENDER_BUDGET_PERMITS,
    ));
    let held = (0..crate::TEXT_PREVIEW_RENDER_BUDGET_PERMITS)
        .map(|_| {
            semaphore
                .clone()
                .try_acquire_many_owned(text_preview_render_permits(1_000_000))
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert!(semaphore
        .clone()
        .try_acquire_many_owned(text_preview_render_permits(1_000_000))
        .is_err());
    drop(held);
}

#[tokio::test]
async fn text_preview_stream_escapes_in_bounded_chunks_and_enforces_the_output_cap() {
    let text = "<&\"'ä".repeat(20_000);
    let expected = format!("prefix{}suffix", esc(&text));
    let template = format!("prefix{TEXT_PREVIEW_STREAM_MARKER}suffix");
    let (mut stream, declared_length) = escaped_text_page_stream(template, text).unwrap();
    let mut rendered = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.unwrap();
        assert!(chunk.len() <= BUFFERED_RESPONSE_CHUNK_BYTES);
        rendered.extend_from_slice(&chunk);
    }
    assert_eq!(declared_length, rendered.len() as u64);
    assert_eq!(rendered, expected.as_bytes());

    let oversized = "\"".repeat(MAX_RENDERED_TEXT_PREVIEW_BYTES / 6 + 1);
    let template = format!("prefix{TEXT_PREVIEW_STREAM_MARKER}suffix");
    assert!(escaped_text_page_stream(template, oversized).is_err());
}

#[test]
fn missing_session_error_redirects_to_login() {
    let response = AppError(StatusCode::SEE_OTHER, "/login").into_response();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/login");
}

#[test]
fn invalid_credentials_remain_an_error() {
    let response = AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten").into_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(header::LOCATION).is_none());
}

#[test]
fn post_locale_return_targets_are_get_safe() {
    let uri = |value: &str| value.parse::<Uri>().unwrap();
    assert_eq!(
        locale_return_to(&Method::POST, &uri("/admin/account/password")),
        "/admin/account"
    );
    assert_eq!(
        locale_return_to(&Method::POST, &uri("/admin/admins/42/totp")),
        "/admin/admins"
    );
    assert_eq!(
        locale_return_to(&Method::POST, &uri("/admin/files/delete")),
        "/admin"
    );
    assert_eq!(
        locale_return_to(&Method::POST, &uri("/v/share-token/upload/queue")),
        "/v/share-token"
    );
    assert_eq!(
        locale_return_to(&Method::GET, &uri("/admin?path=folder")),
        "/admin?path=folder"
    );
}
#[test]
fn permissions() {
    assert!(!Permission::DownloadOnly.can_upload());
    assert!(!Permission::UploadOnly.can_download());
    assert!(Permission::DownloadUpload.can_download());
}

#[test]
fn csrf_rejects_mismatch() {
    let session = Session {
        admin_id: 1,
        username: "admin".into(),
        csrf_token: "expected".into(),
        mfa_verified: true,
    };
    assert!(csrf(&session, "expected").is_ok());
    assert!(csrf(&session, "wrong").is_err());
}

#[test]
fn inactive_and_expired_shares_are_unusable() {
    let share = |active, expires_at| Share {
        id: 1,
        token: "token".into(),
        alias: None,
        relative_path: "file".into(),
        is_directory: false,
        permission: Permission::DownloadOnly,
        expires_at,
        max_downloads: None,
        max_upload_size: None,
        max_upload_total_size: None,
        max_upload_files: None,
        uploaded_bytes: 0,
        uploaded_files: 0,
        download_count: 0,
        active,
        password_hash: None,
        upload_conflict_strategy: UploadConflictStrategy::Reject,
        created_at: Utc::now().to_rfc3339(),
        upload_policy_epoch: 0,
    };
    assert!(usable(&share(false, None)).is_err());
    assert!(usable(&share(true, Some(Utc::now() - Duration::seconds(1)))).is_err());
    assert!(usable(&share(true, Some(Utc::now() + Duration::hours(1)))).is_ok());
}

#[test]
fn upload_policy_helpers() {
    let blocked = vec!["exe".to_string(), ".SH".to_string()];
    assert!(extension_is_blocked("payload.ExE", &blocked));
    assert!(extension_is_blocked("script.sh", &blocked));
    assert!(!extension_is_blocked("report.pdf", &blocked));
    assert_eq!(add_upload_bytes(5, 5, 10), Some(10));
    assert_eq!(add_upload_bytes(5, 6, 10), None);
    assert_eq!(add_upload_bytes(u64::MAX, 1, u64::MAX), None);
    assert_eq!(human(1_500_000_000), "1.5 GB");
    assert_eq!(format_unit_floor(53_687_091_200, GB), "53");
    assert_eq!(format_unit_decimal(100_000_000_000, GB), "100");
    assert_eq!(format_unit_decimal(100_500_000_000, GB), "100.5");
    assert_eq!(format_unit_decimal(1, GB), "0.000000001");
    assert_eq!(display_limit_unit_floor(1_073_741_824, GB), "1");
    assert_eq!(display_limit_unit_ceil(120_000_000_001, GB), "121");
    assert_eq!(
        display_limit_unit_ceil(u64::MAX, GB),
        u64::MAX.div_ceil(GB).to_string()
    );
    assert_eq!(
        parse_unit_to_bytes("1.5", GB, "bad").unwrap(),
        1_500_000_000
    );
    assert_eq!(
        parse_expiry(Some("2026-07-07T20:32"), Some("-120"))
            .unwrap()
            .unwrap()
            .to_rfc3339(),
        "2026-07-07T18:32:00+00:00"
    );
    assert_eq!(
        parse_expiry(Some("07.07.2026 20:32"), Some("-120"))
            .unwrap()
            .unwrap()
            .to_rfc3339(),
        "2026-07-07T18:32:00+00:00"
    );
    assert!(parse_expiry(Some("2026-07-07T20:32"), Some("invalid")).is_err());
    assert!(parse_expiry(Some("2026-07-07T20:32"), Some("1441")).is_err());
}

#[test]
fn text_preview_detects_growth_after_the_initial_metadata_check() {
    let directory = tempfile::tempdir().unwrap();
    let metadata_path = directory.path().join("metadata.txt");
    let content_path = directory.path().join("content.txt");
    std::fs::write(&metadata_path, b"ok").unwrap();
    std::fs::write(&content_path, b"12345").unwrap();
    let metadata = std::fs::metadata(metadata_path).unwrap();
    let file = std::fs::File::open(content_path).unwrap();
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut settings = runtime_settings(&test_state(root.path(), data.path()));
    settings.max_preview_size = 4;

    match read_preview_opened(file, metadata, "content.txt", &settings).unwrap() {
        PreviewContent::TooLarge { size } => assert_eq!(size, 5),
        _ => panic!("grown preview must be rejected as too large"),
    }
}

#[tokio::test]
async fn admin_shell_renders_nav_icons_and_system_panel() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let html = i18n::scope(Locale::De, "/admin".into(), async {
        admin_page(
            &state,
            PageId::Files,
            r#"<section class="vl-panel"></section>"#,
            true,
            "csrf",
        )
    })
    .await;
    assert!(html.contains("<title>Dateien · VaultLink</title>"));
    for label in ["Dateien", "Links", "Admins", "Einstellungen", "Audit"] {
        assert!(html.contains(&format!("<span>{label}</span>")));
    }
    assert!(html.contains("vl-icon"));
    assert_eq!(html.matches(r#"class="vl-nav-link""#).count(), 5);
    assert_eq!(html.matches(r#"aria-current="page""#).count(), 1);
    assert!(!html.contains('📁'));
    assert!(html.contains("VaultLink erreichbar"));
    assert_no_mojibake("admin shell", &html);
    assert!(!html.contains("Secure Mode"));
}

#[tokio::test]
async fn locale_route_sets_hardened_cookie_and_rejects_external_return_targets() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let app = router(test_state(root.path(), data.path()));

    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/locale",
            "locale=en&return_to=%2Flogin%3Ffrom%3Dswitch",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "/login?from=switch"
    );
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cookie.starts_with("vaultlink_locale=en;"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
    assert!(cookie.contains("Path=/"));
    assert!(!cookie.contains(" Secure;"));

    let response = app
        .oneshot(request(
            Method::POST,
            "/locale",
            "locale=de&return_to=https%3A%2F%2Fevil.example",
        ))
        .await
        .unwrap();
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/");

    let mut secure_state = test_state(root.path(), data.path());
    Arc::make_mut(&mut secure_state.config)
        .security
        .secure_cookie = true;
    let secure_response = router(secure_state)
        .oneshot(request(
            Method::POST,
            "/locale",
            "locale=en&return_to=%2Flogin",
        ))
        .await
        .unwrap();
    assert!(secure_response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains(" Secure;"));
}

#[tokio::test]
async fn http_locale_resolution_uses_accept_language_then_english_fallback() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let app = router(test_state(root.path(), data.path()));

    let request_without_language = Request::builder()
        .uri("/login")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request_without_language).await.unwrap();
    assert_eq!(
        response.headers().get(header::CONTENT_LANGUAGE).unwrap(),
        "en"
    );
    assert!(response_text(response).await.contains("Admin sign in"));

    let mut german = request(Method::GET, "/login", "");
    german.headers_mut().insert(
        header::ACCEPT_LANGUAGE,
        HeaderValue::from_static("de-AT,de;q=0.9"),
    );
    let response = app.clone().oneshot(german).await.unwrap();
    assert_eq!(
        response.headers().get(header::CONTENT_LANGUAGE).unwrap(),
        "de"
    );
    assert!(response_text(response).await.contains("Admin Login"));

    let mut cookie_override = request(Method::GET, "/login", "");
    cookie_override.headers_mut().insert(
        header::ACCEPT_LANGUAGE,
        HeaderValue::from_static("en-US,en;q=0.9"),
    );
    cookie_override.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_locale=de"),
    );
    let response = app.oneshot(cookie_override).await.unwrap();
    assert_eq!(
        response.headers().get(header::CONTENT_LANGUAGE).unwrap(),
        "de"
    );
}

#[tokio::test]
async fn queue_errors_localize_message_without_changing_machine_code() {
    let response = i18n::scope(Locale::En, "/v/token".into(), async {
        upload_queue_error_response(
            StatusCode::CONFLICT,
            "Datei existiert bereits; Ersetzen muss für diese Datei bestätigt werden",
        )
    })
    .await;
    let body = response_text(response).await;
    assert!(body.contains(r#""code":"file_exists""#));
    assert!(body.contains("File already exists"));
    assert!(!body.contains("Datei existiert"));
}

#[tokio::test]
async fn queue_reports_required_audit_failures_with_stable_machine_code() {
    let response = upload_queue_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        crate::http_auth::AUDIT_UNAVAILABLE_MESSAGE,
    );
    let body = response_text(response).await;
    assert!(body.contains(r#""code":"audit_unavailable""#));
}

#[test]
fn file_recovery_required_audit_failure_maps_to_ui_503_marker() {
    let data = tempfile::tempdir().unwrap();
    let database_path = data.path().join("data.sqlite");
    let database = crate::db::Database::open(&database_path).unwrap();
    database
        .create_admin("admin", "old-hash", "secret")
        .unwrap();
    rusqlite::Connection::open(database_path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_file_recovery_audit
             BEFORE INSERT ON audit
             BEGIN SELECT RAISE(FAIL, 'injected file recovery audit failure'); END;",
        )
        .unwrap();
    let database_error = database
        .reset_admin_password_and_audit(
            1,
            "new-hash",
            &crate::db::AuditContext::new("system", None),
        )
        .unwrap_err();
    assert!(crate::db::is_audit_unavailable(&database_error));

    let response = storage_recovery_app_error(crate::file_ops::FileOperationError::Database(
        database_error,
    ))
    .into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.headers().get(ERROR_CODE_HEADER).unwrap(),
        "audit_unavailable"
    );
}

#[tokio::test]
async fn audit_table_sorts_columns_and_keeps_time_descending_by_default() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.runtime.write().unwrap().audit_client_ip_enabled = true;
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_session(
            "audit-session",
            1,
            "audit-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("audit-session").unwrap();
    state
        .db
        .audit_with_client_ip(
            "zulu",
            "download",
            Some("z-object"),
            Some("z-detail"),
            Some("203.0.113.2"),
        )
        .unwrap();
    state
        .db
        .audit_with_client_ip(
            "Alpha",
            "upload",
            Some("a-object"),
            Some("a-detail"),
            Some("203.0.113.1"),
        )
        .unwrap();
    let app = router(state);
    let cookie = HeaderValue::from_static("vaultlink_session=audit-session");

    let mut default_request = request(Method::GET, "/admin/audit", "");
    default_request
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let default_page = response_text(app.clone().oneshot(default_request).await.unwrap()).await;
    assert!(default_page.contains(r#"class="vl-audit-time" aria-sort="descending""#));
    assert!(default_page.contains("sort=user&amp;direction=asc"));
    assert!(default_page.contains("sort=client_ip&amp;direction=asc"));
    assert!(
        default_page
            .find(r#"data-label="User">Alpha</td>"#)
            .unwrap()
            < default_page.find(r#"data-label="User">zulu</td>"#).unwrap()
    );

    let mut descending_request = request(Method::GET, "/admin/audit?sort=user&direction=desc", "");
    descending_request
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let descending_page =
        response_text(app.clone().oneshot(descending_request).await.unwrap()).await;
    assert!(descending_page.contains(r#"class="vl-audit-user" aria-sort="descending""#));
    assert!(descending_page.contains("sort=user&amp;direction=asc"));
    assert!(
        descending_page
            .find(r#"data-label="User">zulu</td>"#)
            .unwrap()
            < descending_page
                .find(r#"data-label="User">Alpha</td>"#)
                .unwrap()
    );

    let mut ascending_request = request(
        Method::GET,
        "/admin/audit?action=upload&sort=user&direction=asc",
        "",
    );
    ascending_request
        .headers_mut()
        .insert(header::COOKIE, cookie);
    let ascending_page = response_text(app.oneshot(ascending_request).await.unwrap()).await;
    assert!(ascending_page.contains(r#"name="sort" value="user""#));
    assert!(ascending_page.contains(r#"name="direction" value="asc""#));
    assert!(ascending_page.contains("action=upload&amp;sort=user&amp;direction=desc"));
    assert!(ascending_page.contains(r#"data-label="User">Alpha</td>"#));
    assert!(!ascending_page.contains(r#"data-label="User">zulu</td>"#));
}

#[tokio::test]
async fn english_locale_covers_main_routes_without_touching_user_values() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("Dateien"), b"public").unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("Abmelden", "hash", "secret").unwrap();
    state
        .db
        .create_session(
            "locale-session",
            1,
            "locale-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("locale-session").unwrap();
    state
        .db
        .create_share(
            "locale-public",
            None,
            "Dateien",
            false,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let app = router(state);
    let routes = [
        ("/login", false),
        ("/admin", true),
        ("/admin/account", true),
        ("/admin/shares", true),
        ("/admin/admins", true),
        ("/admin/settings", true),
        ("/admin/audit", true),
        ("/v/locale-public", false),
    ];
    let forbidden_static_german = [
        "Zum Inhalt springen",
        "Dateibrowser",
        "Dateien durchsuchen",
        "Aktuellen Ordner freigeben",
        "Einstellungen",
        "Nachvollziehbarkeit",
        "Sichere Freigabe",
        "Benutzername",
        "Speichern",
        ">Abmelden</button>",
        ">Zurück<",
        ">Weiter<",
        ">Suchen<",
        ">Löschen<",
        ">Ansehen<",
        ">Erstellen<",
        ">Aktiv<",
        ">Abgelaufen<",
        ">Geschützt<",
        ">Passwort<",
        ">Größe<",
        ">Geändert<",
        ">Aktion<",
        ">Vorschau<",
    ];

    for (uri, authenticated) in routes {
        let mut request = request(Method::GET, uri, "");
        let cookie = if authenticated {
            "vaultlink_locale=en; vaultlink_session=locale-session"
        } else {
            "vaultlink_locale=en"
        };
        request
            .headers_mut()
            .insert(header::COOKIE, HeaderValue::from_static(cookie));
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "route {uri}");
        assert_eq!(
            response.headers().get(header::CONTENT_LANGUAGE).unwrap(),
            "en",
            "route {uri}"
        );
        let html = response_text(response).await;
        assert!(html.contains(r#"<html lang="en">"#), "route {uri}");
        assert!(!html.contains("<vl-i18n"), "unresolved marker on {uri}");
        for fragment in forbidden_static_german {
            assert!(
                !html.contains(fragment),
                "route {uri} still contains German UI fragment {fragment:?}"
            );
        }
        assert!(
            !html
                .chars()
                .any(|ch| matches!(ch, 'ä' | 'ö' | 'ü' | 'Ä' | 'Ö' | 'Ü' | 'ß')),
            "route {uri} still contains a German-specific character"
        );
        if uri == "/admin" || uri == "/v/locale-public" {
            assert!(html.contains("Dateien"), "user file name changed on {uri}");
        }
        if uri == "/admin/admins" {
            assert!(html.contains("Abmelden"), "user name was translated");
            assert!(html.contains("Log out"), "logout action was not translated");
        }
    }
}

#[tokio::test]
async fn login_page_serves_correct_utf8() {
    let response = i18n::scope(Locale::De, "/login".into(), login_page())
        .await
        .into_response();
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/html; charset=utf-8"
    );
    let html = response_text(response).await;
    assert!(html.contains("<meta charset=\"utf-8\">"));
    assert!(html.contains("<title>Login · VaultLink</title>"));
    assert_no_mojibake("login page", &html);
}

#[tokio::test]
async fn csp_requires_self_hosted_styles_and_pages_have_no_inline_styles() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let response = router(test_state(root.path(), data.path()))
        .oneshot(request(Method::GET, "/login", ""))
        .await
        .unwrap();
    let csp = response
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("style-src 'self'"));
    assert!(!csp.contains("unsafe-inline"));
    for (path, source) in web_production_sources() {
        assert!(
            !source.contains(concat!("style", "=")),
            "{path} contains an inline style attribute"
        );
    }
    assert!(!include_str!("../setup.rs").contains(concat!("style", "=")));
}

#[test]
fn user_facing_sources_do_not_contain_mojibake() {
    for (path, source) in web_production_sources() {
        assert_no_mojibake(path, source);
    }
    assert_no_mojibake("src/setup.rs", include_str!("../setup.rs"));
}

#[test]
#[should_panic(expected = "likely Windows-1252/UTF-8 mojibake")]
fn mojibake_guard_rejects_redecoded_utf8_bytes() {
    let broken_folder = ['\u{00f0}', '\u{0178}', '\u{201c}', '\u{0081}']
        .into_iter()
        .collect::<String>();
    assert_no_mojibake("broken folder icon", &broken_folder);
}

#[tokio::test]
async fn settings_form_uses_decimal_whole_preview_defaults() {
    let session = Session {
        admin_id: 1,
        username: "admin".into(),
        csrf_token: "csrf".into(),
        mfa_verified: true,
    };
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let mut settings = runtime_settings(&state);
    settings.max_upload_size = 53_687_091_200;
    settings.max_zip_size = 1_000_000_000;
    settings.max_preview_size = 1_000_000;
    settings.max_media_preview_size = 100_000_000;

    let html = i18n::scope(Locale::De, "/admin/settings".into(), async {
        i18n::render_markers(
            Locale::De,
            &settings_form(&session, &settings, 0, "", false),
        )
    })
    .await;
    assert!(html.contains(&format!(
        r#"name="max_upload_size_gb" type="number" min="1" max="{}" step="1" value="53""#,
        display_limit_unit_floor(crate::config::MAX_UPLOAD_SIZE, GB)
    )));
    assert!(html.contains(r#"name="max_zip_size_gb" type="number" min="0" step="1" value="1""#));
    assert!(html.contains(
        r#"name="max_preview_size_mb" type="number" min="1" max="64" step="1" value="1""#
    ));
    assert!(html.contains(
        r#"name="max_media_preview_size_mb" type="number" min="1" step="1" value="100""#
    ));
    assert!(html.contains("Suche Max. Einträge"));
    assert_eq!(html.matches(r#"class="vl-field-info""#).count(), 16);
    assert!(html.contains("Schema, Host und Port müssen exakt"));
    assert!(html.contains("0 deaktiviert dieses separate Limit"));
    assert!(!html.contains("Max. Dateien pro ZIP (0 ="));
    assert_no_mojibake("settings form", &html);
    assert!(!html.contains("Media-Preview Max. GB"));
}

#[test]
fn custom_datetime_picker_replaces_native_browser_picker() {
    let css = crate::ui::STYLESHEET;
    let picker = i18n::render_markers(Locale::De, &expiry_picker_html());
    assert!(css.contains(".vl-datetime-popover"));
    assert!(!css.contains(r#"datetime-local"]::-webkit-calendar-picker-indicator"#));
    assert!(picker.contains("data-datetime-picker"));
    assert!(picker.contains(r#"name="expires_local""#));
    assert!(picker.contains("TT.MM.JJJJ HH:MM"));
    assert!(!picker.contains(r#"type="datetime-local""#));
}

#[tokio::test]
async fn png_favicon_is_an_actual_32_by_32_image() {
    let response = favicon_png().await.into_response();
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("image/png"))
    );
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(&bytes[12..16], b"IHDR");
    assert_eq!(u32::from_be_bytes(bytes[16..20].try_into().unwrap()), 32);
    assert_eq!(u32::from_be_bytes(bytes[20..24].try_into().unwrap()), 32);
}

#[tokio::test]
async fn file_time_uses_locale_date_order() {
    let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(60 * 60 * 20 + 32 * 60);
    let de = i18n::scope(Locale::De, "/".into(), async { format_file_time(time) }).await;
    let en = i18n::scope(Locale::En, "/".into(), async { format_file_time(time) }).await;
    assert_eq!(
        de,
        r#"<time data-local-time datetime="1970-01-01T20:32:00Z">01.01.1970 20:32 UTC</time>"#
    );
    assert_eq!(
        en,
        r#"<time data-local-time datetime="1970-01-01T20:32:00Z">1970-01-01 20:32 UTC</time>"#
    );
}

#[tokio::test]
async fn byte_sizes_use_locale_decimal_separator() {
    let de = i18n::scope(Locale::De, "/".into(), async { human(1_500_000_000) }).await;
    let en = i18n::scope(Locale::En, "/".into(), async { human(1_500_000_000) }).await;
    assert_eq!(de, "1,5 GB");
    assert_eq!(en, "1.5 GB");
}

#[test]
fn removed_compatibility_symbols_and_html_rewrites_stay_removed() {
    assert!(!include_str!("../setup.rs").contains(concat!("setup_form_", "legacy")));
    for (path, source) in web_production_sources() {
        assert!(
            !source.contains(concat!("body.", "replace(")),
            "{path} contains removed body replacement"
        );
        assert!(
            !source.contains(concat!("body.", "replacen(")),
            "{path} contains removed body replacement"
        );
        assert!(
            !source.contains(concat!("app_", "css()")),
            "{path} contains a removed CSS helper"
        );
        assert!(
            !source.contains(concat!("vl-", "legacy")),
            "{path} contains a legacy UI marker"
        );
        assert!(
            !source.contains(concat!("admins_page_", "v3")),
            "{path} contains a removed page variant"
        );
        assert!(
            !source.contains(concat!("const LOGO_", "SVG: &str = r##")),
            "{path} embeds a removed duplicate logo"
        );
    }
    assert!(!include_str!("../ui.rs").contains(concat!("APP_", "CSS")));
    assert!(!include_str!("../setup.rs").contains(concat!("setup_", "css()")));
    assert!(!include_str!("../setup.rs").contains(concat!("vl-", "legacy")));
    assert!(!include_str!("../secure_fs.rs").contains(concat!("cleanup_upload_", "fragments")));
}

#[test]
fn public_preview_actions_are_rendered_above_content() {
    let body =
            r#"<section class="vl-panel"><h1><vl-i18n key="files.preview"/></h1><pre>long text</pre></section>"#
                .to_string();
    let html = i18n::render_markers(
        Locale::De,
        &add_public_preview_actions(body, "/v/token", Some("/v/token/download")),
    );
    let actions = html.find("Zurück zur Freigabe").unwrap();
    let content = html.find("<pre>long text</pre>").unwrap();
    assert!(actions < content);
    assert!(html.contains("Herunterladen"));
}

#[test]
fn disk_stats_uses_target_path() {
    let root = tempfile::tempdir().unwrap();
    let stats = disk_stats(root.path()).expect("statvfs must work for tempdir");
    assert!(stats.total > 0);
    assert!(stats.free > 0);
}

#[tokio::test]
async fn create_new_prevents_upload_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("existing.txt");
    tokio::fs::write(&path, b"original").await.unwrap();
    let result = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .await;
    assert_eq!(
        result.unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(tokio::fs::read(&path).await.unwrap(), b"original");
}

#[tokio::test]
async fn webauthn_mfa_start_is_rate_limited_before_credential_work() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut state = test_state(root.path(), data.path());
    state.limiter = crate::auth::LoginLimiter::new(1, std::time::Duration::from_secs(300));
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_session(
            "webauthn-pending",
            1,
            "webauthn-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    let app = router(state);

    let request = || {
        Request::builder()
            .method(Method::POST)
            .uri("/mfa/security-key/start")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, "vaultlink_session=webauthn-pending")
            .body(Body::from(r#"{"csrf":"webauthn-csrf"}"#))
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        app.oneshot(request()).await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn router_recovers_invalid_runtime_and_webauthn_snapshots_after_poisoning() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state
        .db
        .create_admin(
            "admin",
            &auth::hash_password("a sufficiently long password").unwrap(),
            &auth::new_totp_secret(),
        )
        .unwrap();
    state
        .db
        .create_session(
            "poison-recovery-session",
            1,
            "poison-recovery-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("poison-recovery-session").unwrap();

    let runtime = state.runtime.clone();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let mut settings = runtime.write().unwrap();
            settings.max_upload_size = 0;
            panic!("inject invalid runtime snapshot poisoning");
        }))
        .is_err()
    );
    let webauthn = state.webauthn.clone();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _service = webauthn.write().unwrap();
            panic!("inject WebAuthn snapshot poisoning");
        }))
        .is_err()
    );

    let app = router(state.clone());
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/admin/account/security-keys/register/start")
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::COOKIE,
            "vaultlink_session=poison-recovery-session",
        )
        .body(Body::from(
            r#"{"csrf":"poison-recovery-csrf","current_password":"a sufficiently long password","label":"Recovery key"}"#,
        ))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!state.runtime.is_poisoned());
    assert!(!state.webauthn.is_poisoned());
    assert_eq!(
        runtime_settings(&state).max_upload_size,
        state.config.storage.max_upload_size
    );
}

#[tokio::test]
async fn http_login_mfa_csrf_session_and_logout() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    state
        .db
        .create_admin(
            "admin",
            &auth::hash_password("a sufficiently long password").unwrap(),
            &secret,
        )
        .unwrap();
    let app = router(state.clone());

    let invalid = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/login",
            "username=admin&password=wrong",
        ))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);

    let login = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/login",
            "username=admin&password=a%20sufficiently%20long%20password",
        ))
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    let pre_mfa_cookie = login
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let pre_mfa_session_token = pre_mfa_cookie.split_once('=').unwrap().1.to_string();
    let pre_mfa_csrf = state
        .db
        .session(&pre_mfa_session_token)
        .unwrap()
        .unwrap()
        .csrf_token;
    let mut mfa_page_request = request(Method::GET, "/mfa", "");
    mfa_page_request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&pre_mfa_cookie).unwrap(),
    );
    let mfa_page = response_text(app.clone().oneshot(mfa_page_request).await.unwrap()).await;
    assert!(mfa_page.contains(&format!("name=\"csrf\" value=\"{pre_mfa_csrf}\"")));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let code = auth::totp_code(&secret, now / 30).unwrap();
    let mut wrong_mfa_csrf = request(Method::POST, "/mfa", &format!("csrf=wrong&code={code}"));
    wrong_mfa_csrf.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&pre_mfa_cookie).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(wrong_mfa_csrf).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut mfa_request = request(
        Method::POST,
        "/mfa",
        &format!("csrf={pre_mfa_csrf}&code={code}"),
    );
    mfa_request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&pre_mfa_cookie).unwrap(),
    );
    let mfa = app.clone().oneshot(mfa_request).await.unwrap();
    assert_eq!(mfa.status(), StatusCode::SEE_OTHER);
    let cookie = mfa
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let session_token = cookie.split_once('=').unwrap().1.to_string();
    assert!(state.db.session(&pre_mfa_session_token).unwrap().is_none());

    let mut admin_request = request(Method::GET, "/admin", "");
    admin_request
        .headers_mut()
        .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
    let admin = app.clone().oneshot(admin_request).await.unwrap();
    assert_eq!(admin.status(), StatusCode::OK);
    assert_eq!(
        admin.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );

    let mut bad_csrf = request(Method::POST, "/logout", "csrf=wrong");
    bad_csrf
        .headers_mut()
        .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
    assert_eq!(
        app.clone().oneshot(bad_csrf).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let csrf = state
        .db
        .session(&session_token)
        .unwrap()
        .unwrap()
        .csrf_token;
    let mut logout_request = request(Method::POST, "/logout", &format!("csrf={csrf}"));
    logout_request
        .headers_mut()
        .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
    assert_eq!(
        app.clone().oneshot(logout_request).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    assert!(state.db.session(&session_token).unwrap().is_none());
}

#[tokio::test]
async fn share_creation_page_uses_browser_selected_path() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file.txt"), b"file").unwrap();
    std::fs::write(root.path().join("B.txt"), b"second").unwrap();
    std::fs::write(root.path().join("A.txt"), b"first").unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.runtime.write().unwrap().max_upload_size = 120_000_000_001;
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_session(
            "session-token",
            1,
            "csrf-token",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("session-token").unwrap();
    let app = router(state.clone());
    let cookie = HeaderValue::from_static("vaultlink_session=session-token");

    let javascript = response_text(
        app.clone()
            .oneshot(request(Method::GET, "/assets/app.js", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(javascript.contains("initDeleteConfirmation"));
    assert!(javascript.contains("input.value!==form.dataset.requiredName"));
    assert!(javascript.contains("initFieldInfoTooltips"));
    assert!(javascript.contains("--vl-tooltip-left"));
    assert!(javascript.contains("closeActionDetails"));
    assert!(javascript.contains(".vl-action-details[open]"));
    assert!(javascript.contains("e.key!=='Escape'"));
    assert!(javascript.contains("summary?.focus()"));
    assert!(javascript.contains("ensureWebauthnAvailable"));
    assert!(javascript.contains("webauthnFailureMessage"));
    assert!(javascript.contains("NotAllowedError"));
    assert!(javascript.contains("initLocalTimes"));
    assert!(javascript.contains("time[data-local-time]"));

    let mut browser_root = request(Method::GET, "/admin", "");
    browser_root
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let browser_root = response_text(app.clone().oneshot(browser_root).await.unwrap()).await;
    assert!(browser_root.contains("Aktuellen Ordner freigeben"));
    assert!(browser_root.contains(r#"/admin/shares/new?path=."#));
    assert!(browser_root.contains(r#"action="/admin/files/directories""#));
    assert!(browser_root.contains(r#"action="/admin/files/rename""#));
    assert!(browser_root.contains(r#"/admin/files/delete?path=file%2Etxt"#));
    assert!(browser_root.contains(r#"/admin/files/download?path=file%2Etxt"#));
    assert!(browser_root.contains("sort=name&amp;direction=desc"));
    assert!(browser_root.find("A.txt").unwrap() < browser_root.find("B.txt").unwrap());

    let mut descending = request(Method::GET, "/admin?sort=name&direction=desc", "");
    descending
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let descending = response_text(app.clone().oneshot(descending).await.unwrap()).await;
    assert!(descending.find("B.txt").unwrap() < descending.find("A.txt").unwrap());

    let mut direct_download = request(Method::GET, "/admin/files/download?path=file.txt", "");
    direct_download
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let direct_download = app.clone().oneshot(direct_download).await.unwrap();
    assert_eq!(direct_download.status(), StatusCode::OK);
    assert_eq!(
        direct_download
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .unwrap(),
        "attachment; filename*=UTF-8''file%2Etxt"
    );
    assert_eq!(
        axum::body::to_bytes(direct_download.into_body(), usize::MAX)
            .await
            .unwrap()
            .as_ref(),
        b"file"
    );

    let mut create_folder = request(
        Method::POST,
        "/admin/files/directories",
        "csrf=csrf-token&parent=&name=Neu",
    );
    create_folder
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone().oneshot(create_folder).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    assert!(root.path().join("Neu").is_dir());

    std::fs::create_dir(root.path().join("tree")).unwrap();
    std::fs::write(root.path().join("tree/child.txt"), b"child").unwrap();
    let mut delete_confirmation = request(Method::GET, "/admin/files/delete?path=tree", "");
    delete_confirmation
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let delete_confirmation =
        response_text(app.clone().oneshot(delete_confirmation).await.unwrap()).await;
    assert!(delete_confirmation.contains(r#"name="confirm_name""#));
    assert!(delete_confirmation.contains("data-confirm-input autofocus"));
    assert!(delete_confirmation.contains(r#"data-delete-confirmation data-required-name="tree""#));
    assert!(delete_confirmation.contains(r#"data-confirm-delete disabled"#));
    assert!(delete_confirmation.contains("tree"));

    let mut browser_folder = request(Method::GET, "/admin?path=uploads", "");
    browser_folder
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let browser_folder = response_text(app.clone().oneshot(browser_folder).await.unwrap()).await;
    assert!(browser_folder.contains(r#"/admin/shares/new?path=uploads"#));

    let mut folder_request = request(Method::GET, "/admin/shares/new?path=uploads", "");
    folder_request
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let folder = response_text(app.clone().oneshot(folder_request).await.unwrap()).await;
    assert!(folder.contains(r#"<strong>/uploads</strong>"#));
    assert!(folder.contains(r#"<input type="hidden" name="path" value="uploads">"#));
    assert!(folder.contains(r#"pattern="[A-Za-z0-9_-]{12,32}""#));
    assert!(folder.contains(r#"value="upload_only""#));
    assert!(folder.contains(
        r#"name="max_upload_total_size_gb" type="number" min="1" step="any" value="121" required"#
    ));

    let mut file_request = request(Method::GET, "/admin/shares/new?path=file.txt", "");
    file_request.headers_mut().insert(header::COOKIE, cookie);
    let file = response_text(app.clone().oneshot(file_request).await.unwrap()).await;
    assert!(file.contains(r#"<strong>/file.txt</strong>"#));
    assert!(file.contains(r#"<input type="hidden" name="path" value="file.txt">"#));
    assert!(file.contains(r#"value="download_only""#));
    assert!(!file.contains(r#"value="upload_only""#));
    assert!(!file.contains("data-upload-rules"));

    let mut missing_password = request(
            Method::POST,
            "/admin/shares",
            "csrf=csrf-token&path=uploads&permission=upload_only&alias=&max_downloads=&password_enabled=1&password=&password_confirm=",
        );
    missing_password.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=session-token"),
    );
    assert_eq!(
        app.clone()
            .oneshot(missing_password)
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );

    let mut short_alias = request(
            Method::POST,
            "/admin/shares",
            "csrf=csrf-token&path=uploads&permission=upload_only&alias=short&max_downloads=&password=&password_confirm=",
        );
    short_alias.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=session-token"),
    );
    assert_eq!(
        app.clone().oneshot(short_alias).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    let mut create_request = request(
            Method::POST,
            "/admin/shares",
            "csrf=csrf-token&path=uploads&permission=upload_only&alias=&max_downloads=&password=&password_confirm=",
        );
    create_request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=session-token"),
    );
    assert_eq!(
        app.clone().oneshot(create_request).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );

    let mut rejected_zero = request(
            Method::POST,
            "/admin/shares",
            "csrf=csrf-token&path=uploads&permission=upload_only&alias=&max_downloads=&max_upload_size_gb=0&password=&password_confirm=",
        );
    rejected_zero.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=session-token"),
    );
    assert_eq!(
        app.clone().oneshot(rejected_zero).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    let mut rejected_oversized = request(
            Method::POST,
            "/admin/shares",
            "csrf=csrf-token&path=uploads&permission=upload_only&alias=&max_downloads=9223372036854775808&password=&password_confirm=",
        );
    rejected_oversized.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=session-token"),
    );
    assert_eq!(
        app.clone()
            .oneshot(rejected_oversized)
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );

    let mut upload_limit = request(
            Method::POST,
            "/admin/shares",
            "csrf=csrf-token&path=uploads&permission=upload_only&alias=&max_downloads=&max_upload_size_gb=2&password=&password_confirm=",
        );
    upload_limit.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=session-token"),
    );
    assert_eq!(
        app.clone().oneshot(upload_limit).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    let shares = state.db.list_shares().unwrap();
    assert_eq!(shares.len(), 2);
    assert!(shares.iter().all(|share| share.relative_path == "uploads"));
    assert!(shares.iter().all(|share| share.max_downloads.is_none()));
    assert_eq!(
        shares
            .iter()
            .filter(|share| share.max_upload_size == Some(2 * GB))
            .count(),
        1
    );

    let edited_share_id = shares
        .iter()
        .find(|share| share.max_upload_size == Some(2 * GB))
        .unwrap()
        .id;
    let mut shares_request = request(Method::GET, "/admin/shares", "");
    shares_request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=session-token"),
    );
    let shares_page = response_text(app.clone().oneshot(shares_request).await.unwrap()).await;
    assert!(shares_page.contains("Kumulatives Uploadlimit in GB"));
    assert!(shares_page.contains(r#"name="max_upload_total_size_gb""#));
    assert!(!shares_page.contains("Kumulatives Uploadlimit (Bytes)"));

    let mut update_quota = request(
        Method::POST,
        &format!("/admin/shares/{edited_share_id}/upload-conflict"),
        "csrf=csrf-token&max_upload_total_size_gb=125.5&max_upload_files=900",
    );
    update_quota.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=session-token"),
    );
    assert_eq!(
        app.clone().oneshot(update_quota).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    let edited_share = state
        .db
        .list_shares()
        .unwrap()
        .into_iter()
        .find(|share| share.id == edited_share_id)
        .unwrap();
    assert_eq!(edited_share.max_upload_total_size, Some(125_500_000_000));
    assert_eq!(edited_share.max_upload_files, Some(900));

    state
        .db
        .create_share(
            "legacy-token",
            Some("old"),
            "uploads",
            true,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let retired_alias = app
        .oneshot(request(Method::GET, "/s/old", ""))
        .await
        .unwrap();
    assert_eq!(retired_alias.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn web_share_creation_ignores_hidden_upload_fields_and_rejects_blank_protection() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("documents")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_session(
            "session-token",
            1,
            "csrf-token",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("session-token").unwrap();
    let app = router(state.clone());
    let cookie = HeaderValue::from_static("vaultlink_session=session-token");

    let mut download_only = request(
        Method::POST,
        "/admin/shares",
        "csrf=csrf-token&path=documents&permission=download_only&alias=&max_upload_size_gb=not-a-number&max_upload_total_size_gb=121&max_upload_files=1000&overwrite_allowed=1&password=&password_confirm=",
    );
    download_only
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone().oneshot(download_only).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    let shares = state.db.list_shares().unwrap();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].permission, Permission::DownloadOnly);
    assert_eq!(shares[0].max_upload_size, None);
    assert_eq!(shares[0].max_upload_total_size, None);
    assert_eq!(shares[0].max_upload_files, None);
    assert_eq!(
        shares[0].upload_conflict_strategy,
        UploadConflictStrategy::Reject
    );

    let mut whitespace_password = request(
        Method::POST,
        "/admin/shares",
        "csrf=csrf-token&path=documents&permission=upload_only&alias=&password_enabled=1&password=++++++++++++&password_confirm=++++++++++++",
    );
    whitespace_password
        .headers_mut()
        .insert(header::COOKIE, cookie);
    assert_eq!(
        app.oneshot(whitespace_password).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(state.db.list_shares().unwrap().len(), 1);
}

#[tokio::test]
async fn public_share_scope_blocks_sibling_symlink_http_flows() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("share-a/real")).unwrap();
    std::fs::create_dir_all(root.path().join("share-b/uploads")).unwrap();
    std::fs::write(root.path().join("share-a/real/allowed.txt"), "allowed").unwrap();
    std::fs::write(root.path().join("share-b/secret.txt"), "secret").unwrap();
    symlink("real", root.path().join("share-a/inside")).unwrap();
    symlink("../share-b", root.path().join("share-a/outside")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_share(
            "scope",
            None,
            "share-a",
            true,
            &Permission::DownloadUpload,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let app = router(state.clone());

    let allowed = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/v/scope/download?path=inside/allowed.txt",
            "",
        ))
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
    assert_eq!(response_text(allowed).await, "allowed");

    for uri in [
        "/v/scope?path=outside",
        "/v/scope/download?path=outside/secret.txt",
        "/v/scope/preview?path=outside/secret.txt",
        "/v/scope/download.zip?path=outside",
    ] {
        assert_eq!(
            app.clone()
                .oneshot(request(Method::GET, uri, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND,
            "{uri} crossed the share boundary"
        );
    }
    let upload = app
        .oneshot(multipart_request_with_path(
            "/v/scope/upload",
            "created.txt",
            b"blocked",
            Some("outside/uploads"),
        ))
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::NOT_FOUND);
    assert!(!root.path().join("share-b/uploads/created.txt").exists());
}

#[tokio::test]
async fn transfer_session_counts_range_resume_once_and_abort_not_at_all() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file.txt"), b"abcdef").unwrap();
    std::fs::create_dir(root.path().join("zipdocs")).unwrap();
    std::fs::write(root.path().join("zipdocs/one.txt"), b"one").unwrap();
    std::fs::write(root.path().join("zipdocs/two.txt"), b"two").unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let _share_id = state
        .db
        .create_share(
            "limited",
            None,
            "file.txt",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let aborted_id = state
        .db
        .create_share(
            "aborted",
            None,
            "file.txt",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let known_length_id = state
        .db
        .create_share(
            "known-length",
            None,
            "file.txt",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    std::fs::write(root.path().join("empty.txt"), b"").unwrap();
    state
        .db
        .create_share(
            "empty",
            None,
            "empty.txt",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let exhausted_zip_id = state
        .db
        .create_share(
            "zip-exhausted",
            None,
            "zipdocs",
            true,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let failing_zip_id = state
        .db
        .create_share(
            "zip-failing",
            None,
            "zipdocs",
            true,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    assert!(state.db.count_download(exhausted_zip_id).unwrap());
    state.runtime.write().unwrap().max_search_entries = 1;
    let app = router(state.clone());

    assert_eq!(
        app.clone()
            .oneshot(request(Method::GET, "/v/zip-exhausted/download.zip", "",))
            .await
            .unwrap()
            .status(),
        StatusCode::GONE
    );
    assert_eq!(
        app.clone()
            .oneshot(request(Method::GET, "/v/zip-failing/download.zip", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    for _ in 0..100 {
        if state
            .db
            .active_transfer_reservations(failing_zip_id)
            .unwrap()
            == 0
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    assert_eq!(
        state
            .db
            .active_transfer_reservations(failing_zip_id)
            .unwrap(),
        0
    );
    assert_eq!(
        state
            .db
            .share_by_token("zip-failing")
            .unwrap()
            .unwrap()
            .download_count,
        0
    );

    let available_head = app
        .clone()
        .oneshot(request(Method::HEAD, "/v/limited/download", ""))
        .await
        .unwrap();
    assert_eq!(available_head.status(), StatusCode::OK);
    assert_eq!(available_head.headers()[header::CONTENT_LENGTH], "6");
    assert_eq!(
        state
            .db
            .share_by_token("limited")
            .unwrap()
            .unwrap()
            .download_count,
        0
    );

    let first = app
        .clone()
        .oneshot(range_request(
            Method::GET,
            "/v/limited/download",
            Some("bytes=0-2"),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::PARTIAL_CONTENT);
    let transfer_cookie = first
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert_eq!(
        app.clone()
            .oneshot(request(Method::HEAD, "/v/limited/download", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::GONE
    );
    assert_eq!(response_text(first).await, "abc");
    for _ in 0..100 {
        if state
            .db
            .share_by_token("limited")
            .unwrap()
            .unwrap()
            .download_count
            == 1
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    assert_eq!(
        state
            .db
            .share_by_token("limited")
            .unwrap()
            .unwrap()
            .download_count,
        1
    );
    assert_eq!(
        app.clone()
            .oneshot(request(Method::HEAD, "/v/limited/download", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::GONE
    );
    let mut counted_session_head = request(Method::HEAD, "/v/limited/download", "");
    counted_session_head.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&transfer_cookie).unwrap(),
    );
    assert_eq!(
        app.clone()
            .oneshot(counted_session_head)
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    // The first non-empty known-length payload chunk consumes the transfer
    // before it is yielded, even if the consumer never polls source EOF.
    let known_length = app
        .clone()
        .oneshot(request(Method::GET, "/v/known-length/download", ""))
        .await
        .unwrap();
    assert_eq!(known_length.headers()[header::CONTENT_LENGTH], "6");
    let mut body = known_length.into_body().into_data_stream();
    assert_eq!(body.next().await.unwrap().unwrap().as_ref(), b"abcdef");
    drop(body); // deliberately never poll the stream to EOF
    for _ in 0..100 {
        if state
            .db
            .active_transfer_reservations(known_length_id)
            .unwrap()
            == 0
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    assert_eq!(
        state
            .db
            .share_by_token("known-length")
            .unwrap()
            .unwrap()
            .download_count,
        1
    );
    assert_eq!(
        app.clone()
            .oneshot(request(Method::GET, "/v/known-length/download", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::GONE
    );

    let empty = app
        .clone()
        .oneshot(request(Method::GET, "/v/empty/download", ""))
        .await
        .unwrap();
    assert_eq!(empty.headers()[header::CONTENT_LENGTH], "0");
    drop(empty);
    assert_eq!(
        state
            .db
            .share_by_token("empty")
            .unwrap()
            .unwrap()
            .download_count,
        1
    );

    let mut resumed = range_request(Method::GET, "/v/limited/download", Some("bytes=3-5"));
    resumed.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&transfer_cookie).unwrap(),
    );
    let resumed = app.clone().oneshot(resumed).await.unwrap();
    assert_eq!(resumed.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(response_text(resumed).await, "def");
    assert_eq!(
        app.clone()
            .oneshot(request(Method::GET, "/v/limited/download", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::GONE
    );

    let aborted = app
        .clone()
        .oneshot(request(Method::GET, "/v/aborted/download", ""))
        .await
        .unwrap();
    assert_eq!(aborted.status(), StatusCode::OK);
    drop(aborted);
    for _ in 0..100 {
        if state.db.active_transfer_reservations(aborted_id).unwrap() == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    assert_eq!(
        state.db.active_transfer_reservations(aborted_id).unwrap(),
        0
    );
    assert_eq!(
        state
            .db
            .share_by_token("aborted")
            .unwrap()
            .unwrap()
            .download_count,
        0
    );
}

#[tokio::test]
async fn hyper_http1_counts_a_known_length_download_before_connection_close() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("http.txt"), b"abcdef").unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_share(
            "http-count",
            None,
            "http.txt",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = router(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
    client
        .write_all(
            b"GET /v/http-count/download HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.to_ascii_lowercase().contains("content-length: 6"));
    assert!(!response
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked"));
    assert!(response.contains("abcdef"));
    assert_eq!(
        state
            .db
            .share_by_token("http-count")
            .unwrap()
            .unwrap()
            .download_count,
        1
    );

    server.abort();
}

#[tokio::test]
async fn locked_public_shares_are_rejected_before_the_global_storage_lock() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("protected.txt"), b"secret").unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let password_hash = auth::hash_password("share password 123").unwrap();
    state
        .db
        .create_share(
            "locked-fast",
            None,
            "protected.txt",
            false,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            Some(password_hash.as_str()),
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let app = router(state.clone());

    let _storage_guard = state.storage_mutation.lock().await;
    let page = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        app.clone()
            .oneshot(request(Method::GET, "/v/locked-fast", "")),
    )
    .await
    .expect("locked share page waited for the storage mutation lock")
    .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert!(response_text(page).await.contains("Geschützte Freigabe"));

    let download = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        app.oneshot(request(Method::GET, "/v/locked-fast/download", "")),
    )
    .await
    .expect("locked download waited for the storage mutation lock")
    .unwrap();
    assert_eq!(download.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn detached_public_upload_finalizer_preserves_the_audit_client_ip() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_share(
            "audit-upload",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    state.runtime.write().unwrap().audit_client_ip_enabled = true;
    let response = router(state.clone())
        .oneshot(multipart_request(
            "/v/audit-upload/upload",
            "audit.txt",
            b"content",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let events = state.db.list_audit(Some("upload"), 10, 0).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].client_ip.as_deref(), Some("127.0.0.1"));
}

#[tokio::test]
async fn http_share_permissions_password_unlock_and_range() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file.txt"), b"0123456789").unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_share(
            "download",
            None,
            "file.txt",
            false,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    state
        .db
        .create_share(
            "upload",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let password_hash = auth::hash_password("share password 123").unwrap();
    state
        .db
        .create_share(
            "protected",
            None,
            "file.txt",
            false,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            Some(password_hash.as_str()),
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let app = router(state.clone());

    let mut range_request = request(Method::GET, "/v/download/download", "");
    range_request
        .headers_mut()
        .insert(header::RANGE, HeaderValue::from_static("bytes=2-5"));
    let range = app.clone().oneshot(range_request).await.unwrap();
    assert_eq!(range.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        range.headers().get(header::CONTENT_RANGE).unwrap(),
        "bytes 2-5/10"
    );
    assert_eq!(
        app.clone()
            .oneshot(request(Method::HEAD, "/v/download/download", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(request(Method::GET, "/v/upload/download", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(request(Method::GET, "/v/protected/download", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let wrong = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/v/protected/unlock",
            "password=wrong",
        ))
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    let unlocked = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/v/protected/unlock",
            "password=share%20password%20123",
        ))
        .await
        .unwrap();
    assert_eq!(unlocked.status(), StatusCode::SEE_OTHER);
    let cookie = unlocked
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let mut protected_download = request(Method::GET, "/v/protected/download", "");
    protected_download
        .headers_mut()
        .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
    assert_eq!(
        app.oneshot(protected_download).await.unwrap().status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn account_disables_totp_only_with_two_keys_and_keeps_key_management_compact() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let password = "current-admin-password";
    let password_hash = auth::hash_password(password).unwrap();
    let secret = auth::new_totp_secret();
    state
        .db
        .create_admin("admin", &password_hash, &secret)
        .unwrap();
    state
        .db
        .create_session(
            "account-security-session",
            1,
            "account-security-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("account-security-session").unwrap();
    let app = router(state.clone());
    let cookie = HeaderValue::from_static("vaultlink_session=account-security-session");

    let mut before_keys = request(Method::GET, "/admin/account", "");
    before_keys
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let before_keys = response_text(app.clone().oneshot(before_keys).await.unwrap()).await;
    assert!(before_keys.contains("Ab zwei Keys änderbar"));
    assert!(!before_keys.contains(r#"action="/admin/account/totp""#));

    let first = match state
        .db
        .add_admin_webauthn_credential_for_session(
            "account-security-session",
            1,
            "Primary",
            "credential-a",
            "{}",
            None,
        )
        .unwrap()
    {
        crate::db::AdminWebauthnCredentialRegistrationOutcome::Registered(id) => id,
        crate::db::AdminWebauthnCredentialRegistrationOutcome::SessionUnavailable => {
            panic!("verified account session must accept a security key")
        }
    };
    state
        .db
        .add_admin_webauthn_credential_for_session(
            "account-security-session",
            1,
            "Backup",
            "credential-b",
            "{}",
            None,
        )
        .unwrap();
    let mut with_keys = request(Method::GET, "/admin/account", "");
    with_keys
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let with_keys = response_text(app.clone().oneshot(with_keys).await.unwrap()).await;
    assert_eq!(
        with_keys.matches(r#"class="vl-security-key-row""#).count(),
        3
    );
    assert!(with_keys.contains(r#"action="/admin/account/totp""#));
    assert!(with_keys.contains("Bearbeiten"));
    assert!(with_keys.contains(" UTC"));
    assert!(!with_keys.contains(r#"class="vl-field-info""#));

    let code = auth::totp_code(&secret, Utc::now().timestamp() as u64 / 30).unwrap();
    let mut disable = request(
        Method::POST,
        "/admin/account/totp",
        &format!(
            "csrf=account-security-csrf&current_password={password}&current_code={code}&enabled=false"
        ),
    );
    disable.headers_mut().insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone().oneshot(disable).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    assert!(!state.db.admin("admin").unwrap().unwrap().totp_enabled);

    let mut account = request(Method::GET, "/admin/account", "");
    account.headers_mut().insert(header::COOKIE, cookie.clone());
    let account = response_text(app.clone().oneshot(account).await.unwrap()).await;
    assert!(account.contains("TOTP ist deaktiviert"));
    assert!(!account.contains(r#"action="/admin/account/mfa/start""#));

    state
        .db
        .create_session(
            "key-only-mfa-session",
            1,
            "key-only-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    let mut mfa_page = request(Method::GET, "/mfa", "");
    mfa_page.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=key-only-mfa-session"),
    );
    let mfa_page = response_text(app.clone().oneshot(mfa_page).await.unwrap()).await;
    assert!(!mfa_page.contains(r#"name="code""#));
    assert!(mfa_page.contains("data-security-key-login"));

    let mut protected_delete = request(
        Method::POST,
        &format!("/admin/account/security-keys/{first}/delete"),
        &format!("csrf=account-security-csrf&current_password={password}"),
    );
    protected_delete
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone()
            .oneshot(protected_delete)
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );

    state
        .db
        .add_admin_webauthn_credential_for_session(
            "account-security-session",
            1,
            "Spare",
            "credential-c",
            "{}",
            None,
        )
        .unwrap();
    let mut delete = request(
        Method::POST,
        &format!("/admin/account/security-keys/{first}/delete"),
        &format!("csrf=account-security-csrf&current_password={password}"),
    );
    delete.headers_mut().insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone().oneshot(delete).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(state.db.admin_webauthn_credentials(1).unwrap().len(), 2);

    let mut enable = request(
        Method::POST,
        "/admin/account/totp",
        &format!("csrf=account-security-csrf&current_password={password}&enabled=true"),
    );
    enable.headers_mut().insert(header::COOKIE, cookie);
    assert_eq!(
        app.oneshot(enable).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    assert!(state.db.admin("admin").unwrap().unwrap().totp_enabled);
}

#[tokio::test]
async fn account_ui_changes_password_and_confirms_new_mfa_before_activation() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let current_password = "current-admin-password";
    let replacement_password = "replacement-admin-password";
    let password_hash = auth::hash_password(current_password).unwrap();
    let old_secret = auth::new_totp_secret();
    state.runtime.write().unwrap().audit_client_ip_enabled = true;
    state
        .db
        .create_admin("admin", &password_hash, &old_secret)
        .unwrap();
    state
        .db
        .create_session(
            "account-session",
            1,
            "account-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("account-session").unwrap();
    let app = router(state.clone());
    let account_cookie = HeaderValue::from_static("vaultlink_session=account-session");

    let mut account_request = request(Method::GET, "/admin/account", "");
    account_request
        .headers_mut()
        .insert(header::COOKIE, account_cookie.clone());
    let account_html = response_text(app.clone().oneshot(account_request).await.unwrap()).await;
    assert!(account_html.contains("Mein Konto"));
    assert!(account_html.contains("Aktueller Benutzer"));
    assert!(account_html.contains(">admin<"));
    assert!(account_html.contains(r#"action="/admin/account/password""#));
    assert!(account_html.contains(r#"action="/admin/account/mfa/start""#));
    assert!(account_html.contains(r#"action="/locale""#));
    assert!(!account_html.contains(r#"class="vl-field-info""#));
    assert!(account_html.contains("Ab zwei Keys änderbar"));
    assert!(account_html.contains(r#"maxlength="256""#));
    assert!(account_html.contains("höchstens 256 Zeichen"));

    let mut wrong_password = request(
            Method::POST,
            "/admin/account/password",
            "csrf=account-csrf&current_password=wrong-password&new_password=replacement-admin-password&password_confirm=replacement-admin-password",
        );
    wrong_password
        .headers_mut()
        .insert(header::COOKIE, account_cookie.clone());
    assert_eq!(
        app.clone().oneshot(wrong_password).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(state.db.session("account-session").unwrap().is_some());
    assert!(auth::verify_password(
        &state.db.admin("admin").unwrap().unwrap().password_hash,
        current_password
    ));

    let mut change_password = request(
            Method::POST,
            "/admin/account/password",
            "csrf=account-csrf&current_password=current-admin-password&new_password=replacement-admin-password&password_confirm=replacement-admin-password",
        );
    change_password
        .headers_mut()
        .insert(header::COOKIE, account_cookie);
    let changed = app.clone().oneshot(change_password).await.unwrap();
    assert_eq!(changed.status(), StatusCode::SEE_OTHER);
    assert_eq!(changed.headers().get(header::LOCATION).unwrap(), "/login");
    assert!(changed
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    assert!(state.db.session("account-session").unwrap().is_none());
    assert!(auth::verify_password(
        &state.db.admin("admin").unwrap().unwrap().password_hash,
        replacement_password
    ));

    state
        .db
        .create_session(
            "account-mfa-session",
            1,
            "account-mfa-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("account-mfa-session").unwrap();
    let mfa_cookie = HeaderValue::from_static("vaultlink_session=account-mfa-session");

    let mut rejected_start = request(
        Method::POST,
        "/admin/account/mfa/start",
        "csrf=account-mfa-csrf&current_password=replacement-admin-password&current_code=abcdef",
    );
    rejected_start
        .headers_mut()
        .insert(header::COOKIE, mfa_cookie.clone());
    assert_eq!(
        app.clone().oneshot(rejected_start).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        state
            .db
            .admin("admin")
            .unwrap()
            .unwrap()
            .totp_secret
            .expose_secret(),
        old_secret.as_str()
    );
    assert!(state.db.session("account-mfa-session").unwrap().is_some());

    let current_step = Utc::now().timestamp() as u64 / 30;
    let current_code = auth::totp_code(&old_secret, current_step).unwrap();
    let mut start_mfa = request(
            Method::POST,
            "/admin/account/mfa/start",
            &format!("csrf=account-mfa-csrf&current_password=replacement-admin-password&current_code={current_code}"),
        );
    start_mfa
        .headers_mut()
        .insert(header::COOKIE, mfa_cookie.clone());
    let start_response = app.clone().oneshot(start_mfa).await.unwrap();
    assert_eq!(start_response.status(), StatusCode::OK);
    let start_html = response_text(start_response).await;
    assert!(start_html.contains("Die bisherige MFA bleibt"));
    assert!(!start_html.contains(r#"action="/locale""#));
    let token_marker = r#"name="enrollment_token" value=""#;
    let token_start = start_html.find(token_marker).unwrap() + token_marker.len();
    let enrollment_token = start_html[token_start..]
        .split('"')
        .next()
        .unwrap()
        .to_string();
    let secret_marker = "otpauth://totp/VaultLink:admin?secret=";
    let secret_start = start_html.find(secret_marker).unwrap() + secret_marker.len();
    let new_secret = start_html[secret_start..]
        .split('&')
        .next()
        .unwrap()
        .to_string();
    assert_ne!(new_secret, old_secret);
    assert_eq!(
        state
            .db
            .admin("admin")
            .unwrap()
            .unwrap()
            .totp_secret
            .expose_secret(),
        old_secret.as_str()
    );

    let mut wrong_confirmation = request(
        Method::POST,
        "/admin/account/mfa/confirm",
        &format!("csrf=account-mfa-csrf&enrollment_token={enrollment_token}&code=abcdef"),
    );
    wrong_confirmation
        .headers_mut()
        .insert(header::COOKIE, mfa_cookie.clone());
    assert_eq!(
        app.clone()
            .oneshot(wrong_confirmation)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        state
            .db
            .admin("admin")
            .unwrap()
            .unwrap()
            .totp_secret
            .expose_secret(),
        old_secret.as_str()
    );
    assert!(state.db.session("account-mfa-session").unwrap().is_some());

    let new_code = auth::totp_code(&new_secret, Utc::now().timestamp() as u64 / 30).unwrap();
    let mut confirm_mfa = request(
        Method::POST,
        "/admin/account/mfa/confirm",
        &format!("csrf=account-mfa-csrf&enrollment_token={enrollment_token}&code={new_code}"),
    );
    confirm_mfa.headers_mut().insert(header::COOKIE, mfa_cookie);
    let confirmed = app.clone().oneshot(confirm_mfa).await.unwrap();
    assert_eq!(confirmed.status(), StatusCode::SEE_OTHER);
    assert_eq!(confirmed.headers().get(header::LOCATION).unwrap(), "/login");
    assert!(confirmed
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    assert_eq!(
        state
            .db
            .admin("admin")
            .unwrap()
            .unwrap()
            .totp_secret
            .expose_secret(),
        new_secret.as_str()
    );
    assert!(state.db.session("account-mfa-session").unwrap().is_none());
    assert_eq!(
        state
            .db
            .count_audit(Some("account_password_changed"))
            .unwrap(),
        1
    );
    assert_eq!(
        state.db.count_audit(Some("account_mfa_changed")).unwrap(),
        1
    );
    for action in ["account_password_changed", "account_mfa_changed"] {
        let events = state.db.list_audit(Some(action), 10, 0).unwrap();
        assert_eq!(events[0].client_ip.as_deref(), Some("127.0.0.1"));
    }
}

#[tokio::test]
async fn admin_ui_creates_admin_and_updates_runtime_settings() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_session(
            "session-token",
            1,
            "csrf-token",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("session-token").unwrap();
    let app = router(state.clone());
    let cookie = HeaderValue::from_static("vaultlink_session=session-token");

    let login_page = response_text(
        app.clone()
            .oneshot(request(Method::GET, "/login", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(!login_page.contains("Hauptnavigation"));
    assert!(!login_page.contains("Link erstellen"));
    assert!(login_page.contains("vl-brand"));
    assert!(login_page.contains("<svg"));

    let mut create_admin = request(
            Method::POST,
            "/admin/admins",
            "csrf=csrf-token&username=ops&password=another%20long%20password&password_confirm=another%20long%20password",
        );
    create_admin
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let response = app.clone().oneshot(create_admin).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let created_admin_page = response_text(response).await;
    assert!(created_admin_page.contains("TOTP QR-Code"));
    assert!(created_admin_page.contains("<svg"));
    assert!(created_admin_page.contains("otpauth://totp/VaultLink:ops"));
    assert!(!created_admin_page.contains(r#"action="/locale""#));
    assert!(created_admin_page
        .contains(r#"class="vl-button vl-button--secondary" href="/admin/admins""#));
    assert!(state.db.admin("ops").unwrap().is_some());

    let mut deactivate = request(
        Method::POST,
        "/admin/admins/2/deactivate",
        "csrf=csrf-token",
    );
    deactivate
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone().oneshot(deactivate).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    assert!(state.db.admin("ops").unwrap().is_none());
    let login_disabled = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/login",
            "username=ops&password=another%20long%20password",
        ))
        .await
        .unwrap();
    assert_eq!(login_disabled.status(), StatusCode::UNAUTHORIZED);
    let mut self_deactivate = request(
        Method::POST,
        "/admin/admins/1/deactivate",
        "csrf=csrf-token",
    );
    self_deactivate
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone().oneshot(self_deactivate).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    state.db.create_admin("later", "hash", "secret").unwrap();
    let mut admin_list = request(Method::GET, "/admin/admins", "");
    admin_list
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let admin_list_html = response_text(app.clone().oneshot(admin_list).await.unwrap()).await;
    assert!(admin_list_html.contains("Aktive Admins"));
    assert!(admin_list_html.contains("Stillgelegte Admins"));
    assert!(!admin_list_html.contains("Admin-Löschen ist bewusst nicht enthalten"));
    assert!(admin_list_html.contains("Aktueller Admin"));
    assert!(!admin_list_html.contains("Eigene Passwort- und MFA-Änderungen"));
    assert_eq!(admin_list_html.matches("Passwort setzen").count(), 2);
    assert!(
        admin_list_html.find(r#"data-label="ID">1</td>"#).unwrap()
            < admin_list_html.find(r#"data-label="ID">3</td>"#).unwrap()
    );
    assert!(
        admin_list_html.find("Aktive Admins").unwrap()
            < admin_list_html.find("Stillgelegte Admins").unwrap()
    );
    assert!(admin_list_html.contains("MFA zurücksetzen"));
    assert!(admin_list_html.contains("Passwort setzen"));
    state
        .db
        .create_session(
            "later-session",
            3,
            "later-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("later-session").unwrap();
    let mut reset_password = request(
        Method::POST,
        "/admin/admins/3/password",
        "csrf=csrf-token&password=new%20long%20password&password_confirm=new%20long%20password",
    );
    reset_password
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let reset_password_response = app.clone().oneshot(reset_password).await.unwrap();
    assert_eq!(reset_password_response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        reset_password_response
            .headers()
            .get(header::LOCATION)
            .unwrap(),
        "/admin/admins?notice=password_reset"
    );
    let mut notice_page = request(Method::GET, "/admin/admins?notice=password_reset", "");
    notice_page
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let notice_html = response_text(app.clone().oneshot(notice_page).await.unwrap()).await;
    assert!(notice_html.contains("Passwort wurde gesetzt"));
    assert!(state.db.session("later-session").unwrap().is_none());
    let login_with_new_password = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/login",
            "username=later&password=new%20long%20password",
        ))
        .await
        .unwrap();
    assert_eq!(login_with_new_password.status(), StatusCode::SEE_OTHER);
    let mut self_password_reset = request(
        Method::POST,
        "/admin/admins/1/password",
        "csrf=csrf-token&password=new%20long%20password&password_confirm=new%20long%20password",
    );
    self_password_reset
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone()
            .oneshot(self_password_reset)
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut reset_totp = request(Method::POST, "/admin/admins/3/totp", "csrf=csrf-token");
    reset_totp
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let reset_totp_response = app.clone().oneshot(reset_totp).await.unwrap();
    assert_eq!(reset_totp_response.status(), StatusCode::OK);
    let reset_totp_html = response_text(reset_totp_response).await;
    assert!(reset_totp_html.contains("MFA zurückgesetzt"));
    assert!(reset_totp_html.contains("TOTP QR-Code"));
    assert!(reset_totp_html.contains("otpauth://totp/VaultLink:later"));
    assert!(!reset_totp_html.contains(r#"action="/locale""#));

    let mut settings_request = request(
            Method::POST,
            "/admin/settings",
            "csrf=csrf-token&public_base_url=http%3A%2F%2Flocalhost%3A9999&max_upload_size_gb=16&blocked_extensions=exe%2Cbat&share_password_min_length=12&share_password_max_length=128&share_unlock_minutes=30&max_zip_size_gb=2&max_zip_files=20&max_search_entries=200&max_search_results=20&max_preview_size_mb=64&preview_extensions=txt%2Clog&image_preview_extensions=jpg%2Cpng&pdf_preview_enabled=on&max_media_preview_size_mb=4096",
        );
    settings_request
        .headers_mut()
        .insert(header::COOKIE, cookie);
    let response = app.clone().oneshot(settings_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let runtime = state.runtime.read().unwrap().clone();
    assert_eq!(runtime.public_base_url, "http://localhost:9999");
    assert_eq!(runtime.max_upload_size, 16 * GB);
    assert_eq!(runtime.blocked_extensions, ["exe", "bat"]);
    assert!(state
        .db
        .runtime_settings()
        .unwrap()
        .iter()
        .any(|(key, value)| key == "max_preview_size" && value == &(64 * MB).to_string()));
}

#[tokio::test]
async fn upload_only_never_exposes_target_paths_or_existing_content() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("private-drop")).unwrap();
    std::fs::write(
        root.path().join("private-drop/hidden-secret.txt"),
        b"secret",
    )
    .unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_share(
            "drop-token",
            None,
            "private-drop",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let app = router(state);

    let html = response_text(
        app.clone()
            .oneshot(request(Method::GET, "/v/drop-token", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(html.contains("Datei hochladen"));
    assert!(html.contains("Vorhandene Dateien und Ordner bleiben verborgen"));
    assert!(html.contains("Erfolgreiche Uploads werden protokolliert"));
    assert!(html.contains("data-upload-folder-input"));
    assert!(html.contains("webkitdirectory"));
    assert!(!html.contains("private-drop"));
    assert!(!html.contains("hidden-secret.txt"));
    assert!(!html.contains("Dateien durchsuchen"));
    assert!(!html.contains("Datei herunterladen"));

    let folder_upload = app
        .clone()
        .oneshot(public_folder_upload_request(
            "/v/drop-token/upload/queue",
            "",
            "Eingang/Projekt",
            "neu.txt",
            b"private folder upload",
        ))
        .await
        .unwrap();
    assert_eq!(folder_upload.status(), StatusCode::OK);
    assert_eq!(
        std::fs::read(root.path().join("private-drop/Eingang/Projekt/neu.txt")).unwrap(),
        b"private folder upload"
    );

    let api_body = response_text(
        app.oneshot(request(Method::GET, "/api/v1/public/shares/drop-token", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(api_body.contains(r#""path":"""#));
    assert!(!api_body.contains("private-drop"));
    assert!(!api_body.contains("hidden-secret.txt"));
}

#[tokio::test]
async fn admin_upload_is_csrf_protected_atomic_and_queue_compatible() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_session(
            "session-token",
            1,
            "csrf-token",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("session-token").unwrap();
    let app = router(state.clone());
    let cookie = HeaderValue::from_static("vaultlink_session=session-token");

    let mut wrong_csrf = admin_multipart_request(
        "/admin/files/upload",
        "uploads",
        "wrong",
        "blocked.txt",
        b"content",
        false,
    );
    wrong_csrf
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone().oneshot(wrong_csrf).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert!(!root.path().join("uploads/blocked.txt").exists());

    let mut first = admin_multipart_request(
        "/admin/files/upload",
        "uploads",
        "csrf-token",
        "grüße.txt",
        b"first",
        false,
    );
    first.headers_mut().insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone().oneshot(first).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        std::fs::read(root.path().join("uploads/grüße.txt")).unwrap(),
        b"first"
    );

    let mut conflict = admin_multipart_request(
        "/admin/files/upload/queue",
        "uploads",
        "csrf-token",
        "grüße.txt",
        b"second",
        false,
    );
    conflict
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let conflict = app.clone().oneshot(conflict).await.unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert!(response_text(conflict).await.contains("file_exists"));

    let mut replace = admin_multipart_request(
        "/admin/files/upload/queue",
        "uploads",
        "csrf-token",
        "grüße.txt",
        b"second",
        true,
    );
    replace.headers_mut().insert(header::COOKIE, cookie.clone());
    let replace = app.clone().oneshot(replace).await.unwrap();
    assert_eq!(replace.status(), StatusCode::OK);
    let replace_body = response_text(replace).await;
    assert!(replace_body.contains(r#""file":"grüße.txt""#));
    assert!(replace_body.contains(r#""outcome":"replaced"#));
    assert_eq!(
        std::fs::read(root.path().join("uploads/grüße.txt")).unwrap(),
        b"second"
    );

    let mut folder_upload = admin_folder_upload_request(
        "/admin/files/upload/queue",
        "uploads",
        "csrf-token",
        "Album/2026/Sommer",
        "foto.txt",
        b"folder content",
    );
    folder_upload
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let folder_upload = app.clone().oneshot(folder_upload).await.unwrap();
    assert_eq!(folder_upload.status(), StatusCode::OK);
    assert_eq!(
        std::fs::read(root.path().join("uploads/Album/2026/Sommer/foto.txt")).unwrap(),
        b"folder content"
    );
    assert_eq!(
        state
            .db
            .list_audit(Some("upload_directories_created"), 10, 0)
            .unwrap()
            .len(),
        1
    );

    let mut blocked = admin_multipart_request(
        "/admin/files/upload/queue",
        "uploads",
        "csrf-token",
        "payload.exe",
        b"x",
        false,
    );
    blocked.headers_mut().insert(header::COOKIE, cookie);
    assert_eq!(
        app.clone().oneshot(blocked).await.unwrap().status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );

    let javascript = response_text(
        app.oneshot(request(Method::GET, "/assets/app.js", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(javascript.contains("input.multiple = true"));
    assert!(javascript.contains("webkitRelativePath"));
    assert!(javascript.contains("folder_path"));
    assert!(javascript.contains("await uploadItem(item)"));
    assert!(javascript.contains("Erneut versuchen"));
    assert!(!javascript.contains("Promise.all"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_upload_rechecks_the_exact_mfa_session_before_publish() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_admin("other-admin", "hash", "other-secret")
        .unwrap();
    for token in ["queue-session", "browser-session"] {
        state
            .db
            .create_session(token, 1, "csrf-token", Utc::now() + Duration::hours(1))
            .unwrap();
        state.db.verify_mfa(token).unwrap();
    }
    let app = router(state.clone());

    let storage_guard = state.storage_mutation.clone().lock_owned().await;
    let mut queued = admin_multipart_request(
        "/admin/files/upload/queue",
        "uploads",
        "csrf-token",
        "queue-revoked.txt",
        b"must not publish",
        false,
    );
    queued.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=queue-session"),
    );
    let queue_app = app.clone();
    let queued = tokio::spawn(async move { queue_app.oneshot(queued).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;
    state.db.delete_session("queue-session").unwrap();
    drop(storage_guard);

    let queued = queued.await.unwrap();
    assert_eq!(queued.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_text(queued).await,
        r#"{"error":"session_revoked"}"#
    );
    assert!(!root.path().join("uploads/queue-revoked.txt").exists());

    let storage_guard = state.storage_mutation.clone().lock_owned().await;
    let mut browser = admin_multipart_request(
        "/admin/files/upload",
        "uploads",
        "csrf-token",
        "browser-revoked.txt",
        b"must not publish",
        false,
    );
    browser.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=browser-session"),
    );
    let browser_app = app.clone();
    let browser = tokio::spawn(async move { browser_app.oneshot(browser).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;
    state.db.deactivate_admin(1).unwrap();
    drop(storage_guard);

    let browser = browser.await.unwrap();
    assert_eq!(browser.status(), StatusCode::SEE_OTHER);
    assert_eq!(browser.headers().get(header::LOCATION).unwrap(), "/login");
    assert!(browser
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    assert!(!root.path().join("uploads/browser-revoked.txt").exists());
    assert!(state
        .db
        .list_audit(Some("admin_upload"), 10, 0)
        .unwrap()
        .is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn text_preview_reserves_transfer_and_render_capacity_before_reading() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    let preview_path = "lease-race-preview.txt";
    std::fs::write(root.path().join("docs").join(preview_path), b"preview").unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_share(
            "preview-race",
            None,
            "docs",
            true,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let hook = Arc::new(TextPreviewReadTestHook {
        path: preview_path.to_string(),
        entered: std::sync::atomic::AtomicUsize::new(0),
        released: std::sync::Mutex::new(false),
        wake: std::sync::Condvar::new(),
    });
    let hook_slot = TEXT_PREVIEW_READ_TEST_HOOK.get_or_init(|| std::sync::Mutex::new(None));
    assert!(hook_slot.lock().unwrap().replace(hook.clone()).is_none());
    let hook_guard = TextPreviewReadTestGuard(hook.clone());

    let app = router(state);
    let first_app = app.clone();
    let first = tokio::spawn(async move {
        first_app
            .oneshot(request(
                Method::GET,
                "/v/preview-race/preview?path=lease-race-preview.txt",
                "",
            ))
            .await
            .unwrap()
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while hook.entered.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let second_app = app.clone();
    let second = tokio::spawn(async move {
        second_app
            .oneshot(request(
                Method::GET,
                "/v/preview-race/preview?path=lease-race-preview.txt",
                "",
            ))
            .await
            .unwrap()
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if second.is_finished() || hook.entered.load(Ordering::Acquire) >= 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let reads_before_release = hook.entered.load(Ordering::Acquire);
    hook.release();

    let first = first.await.unwrap();
    let second = second.await.unwrap();
    drop(hook_guard);
    assert_eq!(reads_before_release, 1);
    assert!(matches!(
        (first.status(), second.status()),
        (StatusCode::OK, StatusCode::GONE) | (StatusCode::GONE, StatusCode::OK)
    ));
    drop(first);
    drop(second);

    let render_root = tempfile::tempdir().unwrap();
    let render_data = tempfile::tempdir().unwrap();
    std::fs::create_dir(render_root.path().join("docs")).unwrap();
    let render_path = "render-budget-preview.txt";
    std::fs::write(
        render_root.path().join("docs").join(render_path),
        b"preview",
    )
    .unwrap();
    let render_state = test_state(render_root.path(), render_data.path());
    render_state.runtime.write().unwrap().max_preview_size = MAX_TEXT_PREVIEW_SIZE;
    render_state
        .db
        .create_admin("admin", "hash", "secret")
        .unwrap();
    render_state
        .db
        .create_share(
            "preview-render-race",
            None,
            "docs",
            true,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let render_hook = Arc::new(TextPreviewReadTestHook {
        path: render_path.to_string(),
        entered: std::sync::atomic::AtomicUsize::new(0),
        released: std::sync::Mutex::new(false),
        wake: std::sync::Condvar::new(),
    });
    assert!(hook_slot
        .lock()
        .unwrap()
        .replace(render_hook.clone())
        .is_none());
    let render_hook_guard = TextPreviewReadTestGuard(render_hook.clone());
    let render_app = router(render_state);
    let first_render_app = render_app.clone();
    let first_render = tokio::spawn(async move {
        first_render_app
            .oneshot(request(
                Method::GET,
                "/v/preview-render-race/preview?path=render-budget-preview.txt",
                "",
            ))
            .await
            .unwrap()
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while render_hook.entered.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let second_render = render_app
        .oneshot(request(
            Method::GET,
            "/v/preview-render-race/preview?path=render-budget-preview.txt",
            "",
        ))
        .await
        .unwrap();
    assert_eq!(second_render.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(render_hook.entered.load(Ordering::Acquire), 1);
    render_hook.release();
    assert_eq!(first_render.await.unwrap().status(), StatusCode::OK);
    drop(render_hook_guard);
}

fn active_expensive_peer_operations(state: &AppState) -> usize {
    state
        .expensive_peer_admission
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .values()
        .sum()
}

async fn wait_for_zip_hook(hook: &ZipBlockingTestHook) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while hook.entered.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("ZIP blocking hook should be reached");
}

async fn wait_for_zip_resources_released(state: &AppState, share_id: i64) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if state.zip_generation_admission.available_permits() == 1
                && active_expensive_peer_operations(state) == 0
                && state.db.active_transfer_reservations(share_id).unwrap() == 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("ZIP resources should be released by their single owner");

    // A second cancellation callback must neither recreate a lease nor alter
    // either admission counter after the owner has already been consumed.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert_eq!(state.zip_generation_admission.available_permits(), 1);
    assert_eq!(active_expensive_peer_operations(state), 0);
    assert_eq!(state.db.active_transfer_reservations(share_id).unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_zip_plan_retains_permits_and_lease_until_blocking_work_finishes() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let share_path = "zip-plan-cancellation-docs";
    std::fs::create_dir(root.path().join(share_path)).unwrap();
    std::fs::write(root.path().join(share_path).join("note.txt"), b"note").unwrap();
    let mut state = test_state(root.path(), data.path());
    state.zip_generation_admission = Arc::new(tokio::sync::Semaphore::new(1));
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db
        .create_share(
            "zip-plan-cancellation",
            None,
            share_path,
            true,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let hook = Arc::new(ZipBlockingTestHook {
        path: share_path.into(),
        phase: ZipBlockingTestPhase::Plan,
        panic_after_release: false,
        entered: std::sync::atomic::AtomicUsize::new(0),
        released: std::sync::Mutex::new(false),
        wake: std::sync::Condvar::new(),
    });
    let hook_guard = install_zip_blocking_test_hook(hook.clone());
    let app = router(state.clone());
    let request = tokio::spawn(async move {
        app.oneshot(request(
            Method::GET,
            "/v/zip-plan-cancellation/download.zip",
            "",
        ))
        .await
        .unwrap()
    });
    wait_for_zip_hook(&hook).await;

    assert_eq!(state.zip_generation_admission.available_permits(), 0);
    assert_eq!(active_expensive_peer_operations(&state), 1);
    assert_eq!(state.db.active_transfer_reservations(share_id).unwrap(), 1);
    request.abort();
    let _ = request.await;
    tokio::task::yield_now().await;
    assert_eq!(state.zip_generation_admission.available_permits(), 0);
    assert_eq!(active_expensive_peer_operations(&state), 1);
    assert_eq!(state.db.active_transfer_reservations(share_id).unwrap(), 1);

    hook.release();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if state.zip_generation_admission.available_permits() == 1
                && active_expensive_peer_operations(&state) == 0
                && state.db.active_transfer_reservations(share_id).unwrap() == 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("cancelled ZIP plan should release its single resource owner");
    assert_eq!(
        state
            .db
            .share_by_token("zip-plan-cancellation")
            .unwrap()
            .unwrap()
            .download_count,
        0
    );
    drop(hook_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zip_blocking_join_error_releases_transfer_lease_and_admission_once() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let share_path = "zip-blocking-panic-docs";
    std::fs::create_dir(root.path().join(share_path)).unwrap();
    std::fs::write(root.path().join(share_path).join("note.txt"), b"note").unwrap();
    let mut state = test_state(root.path(), data.path());
    state.zip_generation_admission = Arc::new(tokio::sync::Semaphore::new(1));
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db
        .create_share(
            "zip-blocking-panic",
            None,
            share_path,
            true,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let hook = Arc::new(ZipBlockingTestHook {
        path: share_path.into(),
        phase: ZipBlockingTestPhase::Plan,
        panic_after_release: true,
        entered: std::sync::atomic::AtomicUsize::new(0),
        released: std::sync::Mutex::new(false),
        wake: std::sync::Condvar::new(),
    });
    let hook_guard = install_zip_blocking_test_hook(hook.clone());
    let app = router(state.clone());
    let request = tokio::spawn(async move {
        app.oneshot(request(
            Method::GET,
            "/v/zip-blocking-panic/download.zip",
            "",
        ))
        .await
        .unwrap()
    });
    wait_for_zip_hook(&hook).await;
    assert_eq!(state.zip_generation_admission.available_permits(), 0);
    assert_eq!(active_expensive_peer_operations(&state), 1);
    assert_eq!(state.db.active_transfer_reservations(share_id).unwrap(), 1);

    hook.release();
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), request)
        .await
        .expect("panicking ZIP task should join")
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    wait_for_zip_resources_released(&state, share_id).await;
    assert_eq!(
        state
            .db
            .share_by_token("zip-blocking-panic")
            .unwrap()
            .unwrap()
            .download_count,
        0
    );
    drop(hook_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_capacity_zip_materialization_error_releases_resources_once() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let share_path = "zip-materialization-error-docs";
    let source_path = root.path().join(share_path).join("note.txt");
    std::fs::create_dir(root.path().join(share_path)).unwrap();
    std::fs::write(&source_path, b"note").unwrap();
    let mut state = test_state(root.path(), data.path());
    state.zip_generation_admission = Arc::new(tokio::sync::Semaphore::new(1));
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db
        .create_share(
            "zip-materialization-error",
            None,
            share_path,
            true,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let hook = Arc::new(ZipBlockingTestHook {
        path: share_path.into(),
        phase: ZipBlockingTestPhase::Materialize,
        panic_after_release: false,
        entered: std::sync::atomic::AtomicUsize::new(0),
        released: std::sync::Mutex::new(false),
        wake: std::sync::Condvar::new(),
    });
    let hook_guard = install_zip_blocking_test_hook(hook.clone());
    let app = router(state.clone());
    let request = tokio::spawn(async move {
        app.oneshot(request(
            Method::GET,
            "/v/zip-materialization-error/download.zip",
            "",
        ))
        .await
        .unwrap()
    });
    wait_for_zip_hook(&hook).await;
    assert_eq!(state.zip_generation_admission.available_permits(), 0);
    assert_eq!(active_expensive_peer_operations(&state), 1);
    assert_eq!(state.db.active_transfer_reservations(share_id).unwrap(), 1);

    // Planning has completed, so removing the source here deterministically
    // produces ZipBuildError::Source rather than the capacity fallback.
    std::fs::remove_file(source_path).unwrap();
    hook.release();
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), request)
        .await
        .expect("failed ZIP materialization should return")
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    wait_for_zip_resources_released(&state, share_id).await;
    assert_eq!(
        state
            .db
            .share_by_token("zip-materialization-error")
            .unwrap()
            .unwrap()
            .download_count,
        0
    );
    drop(hook_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_zip_error_before_first_chunk_releases_resources_once() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let share_path = "zip-direct-error-docs";
    let source_path = root.path().join(share_path).join("note.txt");
    std::fs::create_dir(root.path().join(share_path)).unwrap();
    std::fs::write(&source_path, b"note").unwrap();
    let mut state = test_state(root.path(), data.path());
    state.zip_generation_admission = Arc::new(tokio::sync::Semaphore::new(1));
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db
        .create_share(
            "zip-direct-error",
            None,
            share_path,
            true,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let hook = Arc::new(ZipBlockingTestHook {
        path: share_path.into(),
        phase: ZipBlockingTestPhase::Direct,
        panic_after_release: false,
        entered: std::sync::atomic::AtomicUsize::new(0),
        released: std::sync::Mutex::new(false),
        wake: std::sync::Condvar::new(),
    });
    let hook_guard = install_zip_blocking_test_hook(hook.clone());
    let response = router(state.clone())
        .oneshot(request(Method::GET, "/v/zip-direct-error/download.zip", ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    wait_for_zip_hook(&hook).await;
    assert_eq!(state.zip_generation_admission.available_permits(), 0);
    assert_eq!(active_expensive_peer_operations(&state), 1);
    assert_eq!(state.db.active_transfer_reservations(share_id).unwrap(), 1);

    std::fs::remove_file(source_path).unwrap();
    let mut body = response.into_body().into_data_stream();
    hook.release();
    let first = tokio::time::timeout(std::time::Duration::from_secs(2), body.next())
        .await
        .expect("direct ZIP producer should report its source error")
        .expect("direct ZIP producer should emit an error item");
    assert!(first.is_err(), "no payload may precede the producer error");
    drop(body);

    wait_for_zip_resources_released(&state, share_id).await;
    assert_eq!(
        state
            .db
            .share_by_token("zip-direct-error")
            .unwrap()
            .unwrap()
            .download_count,
        0
    );
    drop(hook_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_zip_materialization_retains_capacity_until_blocking_work_finishes() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let share_path = "zip-cancellation-docs";
    std::fs::create_dir(root.path().join(share_path)).unwrap();
    std::fs::write(root.path().join(share_path).join("note.txt"), b"note").unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db
        .create_share(
            "zip-cancellation",
            None,
            share_path,
            true,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let expected_temp_reservation = plan_zip(
        &state.secure_root.bind_directory(share_path).unwrap(),
        "",
        &runtime_settings(&state),
    )
    .unwrap()
    .estimated_archive_size;
    let hook = Arc::new(ZipBlockingTestHook {
        path: share_path.into(),
        phase: ZipBlockingTestPhase::Materialize,
        panic_after_release: false,
        entered: std::sync::atomic::AtomicUsize::new(0),
        released: std::sync::Mutex::new(false),
        wake: std::sync::Condvar::new(),
    });
    let hook_guard = install_zip_blocking_test_hook(hook.clone());
    let app = router(state.clone());
    let request = tokio::spawn(async move {
        app.oneshot(request(Method::GET, "/v/zip-cancellation/download.zip", ""))
            .await
            .unwrap()
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while hook.entered.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    assert_eq!(
        state.zip_generation_admission.available_permits(),
        crate::MAX_CONCURRENT_ZIP_GENERATIONS - 1
    );
    assert!(zip_temp_reserved_bytes_for_test() >= expected_temp_reservation);
    assert_eq!(state.db.active_transfer_reservations(share_id).unwrap(), 1);

    request.abort();
    let _ = request.await;
    tokio::task::yield_now().await;
    assert_eq!(
        state.zip_generation_admission.available_permits(),
        crate::MAX_CONCURRENT_ZIP_GENERATIONS - 1,
        "request cancellation released ZIP capacity around live blocking work"
    );
    assert!(
        zip_temp_reserved_bytes_for_test() >= expected_temp_reservation,
        "request cancellation released the temp budget around live materialization"
    );
    assert_eq!(state.db.active_transfer_reservations(share_id).unwrap(), 1);

    hook.release();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if state.zip_generation_admission.available_permits()
                == crate::MAX_CONCURRENT_ZIP_GENERATIONS
                && state.db.active_transfer_reservations(share_id).unwrap() == 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    drop(hook_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_direct_zip_keeps_permits_in_the_blocking_producer() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let share_path = "zip-direct-cancellation-docs";
    std::fs::create_dir(root.path().join(share_path)).unwrap();
    std::fs::write(root.path().join(share_path).join("note.txt"), b"note").unwrap();
    let mut state = test_state(root.path(), data.path());
    state.zip_generation_admission = Arc::new(tokio::sync::Semaphore::new(1));
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db
        .create_share(
            "zip-direct-cancellation",
            None,
            share_path,
            true,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let hook = Arc::new(ZipBlockingTestHook {
        path: share_path.into(),
        phase: ZipBlockingTestPhase::Direct,
        panic_after_release: false,
        entered: std::sync::atomic::AtomicUsize::new(0),
        released: std::sync::Mutex::new(false),
        wake: std::sync::Condvar::new(),
    });
    let hook_guard = install_zip_blocking_test_hook(hook.clone());
    let response = router(state.clone())
        .oneshot(request(
            Method::GET,
            "/v/zip-direct-cancellation/download.zip",
            "",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    wait_for_zip_hook(&hook).await;
    assert_eq!(state.zip_generation_admission.available_permits(), 0);
    assert_eq!(active_expensive_peer_operations(&state), 1);
    assert_eq!(state.db.active_transfer_reservations(share_id).unwrap(), 1);

    drop(response);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while state.db.active_transfer_reservations(share_id).unwrap() != 0 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("dropping the direct ZIP body should cancel its lease once");
    assert_eq!(state.zip_generation_admission.available_permits(), 0);
    assert_eq!(active_expensive_peer_operations(&state), 1);
    assert_eq!(
        state
            .db
            .share_by_token("zip-direct-cancellation")
            .unwrap()
            .unwrap()
            .download_count,
        0
    );

    hook.release();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if state.zip_generation_admission.available_permits() == 1
                && active_expensive_peer_operations(&state) == 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("direct ZIP permits should outlive the cancelled body but not the producer");
    assert_eq!(state.db.active_transfer_reservations(share_id).unwrap(), 0);
    assert_eq!(
        state
            .db
            .share_by_token("zip-direct-cancellation")
            .unwrap()
            .unwrap()
            .download_count,
        0
    );
    drop(hook_guard);
}

#[tokio::test]
async fn public_zip_and_directory_scans_have_dedicated_admission() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    std::fs::write(root.path().join("docs/note.txt"), b"note").unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_share(
            "admission",
            None,
            "docs",
            true,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let _zip_permits = state
        .zip_generation_admission
        .clone()
        .try_acquire_many_owned(crate::MAX_CONCURRENT_ZIP_GENERATIONS as u32)
        .unwrap();
    let _search_permits = state
        .search_admission
        .clone()
        .try_acquire_many_owned(crate::MAX_CONCURRENT_SEARCHES as u32)
        .unwrap();
    let app = router(state);

    assert_eq!(
        app.clone()
            .oneshot(request(Method::GET, "/v/admission/download.zip", "",))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        app.clone()
            .oneshot(request(Method::GET, "/v/admission?q=note", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let long_query = "x".repeat(MAX_SEARCH_QUERY_BYTES + 1);
    assert_eq!(
        app.oneshot(request(
            Method::GET,
            &format!("/v/admission?q={long_query}"),
            "",
        ))
        .await
        .unwrap()
        .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn public_folder_preview_zip_search_and_subfolder_upload() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("docs/sub")).unwrap();
    std::fs::write(root.path().join("docs/note.txt"), b"<b>hello</b>").unwrap();
    std::fs::write(root.path().join("docs/B.txt"), b"second").unwrap();
    std::fs::write(root.path().join("docs/A.txt"), b"first").unwrap();
    std::fs::write(root.path().join("docs/bad.html"), b"<script>x</script>").unwrap();
    std::fs::write(
        root.path().join("docs/image.png"),
        b"\x89PNG\r\n\x1a\npreview",
    )
    .unwrap();
    std::fs::write(root.path().join("docs/file.pdf"), b"%PDF-1.7\npreview").unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let du_id = state
        .db
        .create_share(
            "du",
            None,
            "docs",
            true,
            &Permission::DownloadUpload,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    state
        .db
        .create_share(
            "uo",
            None,
            "docs",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let media_id = state
        .db
        .create_share(
            "media",
            None,
            "docs",
            true,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let app = router(state.clone());

    let listing = response_text(
        app.clone()
            .oneshot(request(Method::GET, "/v/du?q=note", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(listing.contains("note.txt"));
    assert!(listing.contains("download.zip"));
    assert!(!listing.contains("Hauptnavigation"));
    assert!(!listing.contains("Secure Mode"));
    assert!(!listing.contains("/admin/settings"));

    let folder_upload = app
        .clone()
        .oneshot(public_folder_upload_request(
            "/v/du/upload/queue",
            "",
            "Fotos/2026/Sommer",
            "bild.txt",
            b"public folder upload",
        ))
        .await
        .unwrap();
    assert_eq!(folder_upload.status(), StatusCode::OK);
    assert_eq!(
        std::fs::read(root.path().join("docs/Fotos/2026/Sommer/bild.txt")).unwrap(),
        b"public folder upload"
    );
    let traversal = app
        .clone()
        .oneshot(public_folder_upload_request(
            "/v/du/upload/queue",
            "",
            "../escape",
            "blocked.txt",
            b"blocked",
        ))
        .await
        .unwrap();
    assert_eq!(traversal.status(), StatusCode::BAD_REQUEST);
    assert!(!root.path().join("escape/blocked.txt").exists());

    let sorted_listing = response_text(
        app.clone()
            .oneshot(request(Method::GET, "/v/du", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(sorted_listing.find("A.txt").unwrap() < sorted_listing.find("B.txt").unwrap());
    assert!(sorted_listing.contains("sort=name&amp;direction=desc"));
    assert!(sorted_listing.contains("sort=type&amp;direction=asc"));
    let descending_listing = response_text(
        app.clone()
            .oneshot(request(Method::GET, "/v/du?sort=name&direction=desc", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(descending_listing.find("B.txt").unwrap() < descending_listing.find("A.txt").unwrap());
    let subfolder_listing = response_text(
        app.clone()
            .oneshot(request(Method::GET, "/v/du?path=sub", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(subfolder_listing
        .contains(r#"<a class="vl-button vl-button--secondary" href="/v/du?path=">Hoch</a>"#));

    let preview = response_text(
        app.clone()
            .oneshot(request(Method::GET, "/v/du/preview?path=note.txt", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(preview.contains("&lt;b&gt;hello&lt;/b&gt;"));
    assert_eq!(
        app.clone()
            .oneshot(request(Method::GET, "/v/du/preview?path=bad.html", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );

    let image_preview = response_text(
        app.clone()
            .oneshot(request(Method::GET, "/v/media/preview?path=image.png", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(image_preview.contains("<img"));
    let image_token = preview_token_from(&image_preview);
    assert!(!image_token.is_empty());
    assert!(state
        .db
        .preview_session(&image_token, media_id, "image.png")
        .unwrap());
    let raw_image_uri = format!("/v/media/preview/raw?path=image.png&preview_token={image_token}");
    let raw_image = app
        .clone()
        .oneshot(range_request(
            Method::GET,
            &raw_image_uri,
            Some("bytes=0-3"),
        ))
        .await
        .unwrap();
    assert_eq!(raw_image.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        raw_image.headers().get(header::CONTENT_TYPE).unwrap(),
        "image/png"
    );
    assert_eq!(
        raw_image
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .unwrap(),
        "inline; filename*=UTF-8''image%2Epng"
    );
    assert_eq!(
        raw_image.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    let raw_image_bytes = axum::body::to_bytes(raw_image.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(raw_image_bytes.as_ref(), b"\x89PNG");
    for _ in 0..100 {
        if state
            .db
            .share_by_token("media")
            .unwrap()
            .unwrap()
            .download_count
            == 1
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    let head_image = app
        .clone()
        .oneshot(range_request(Method::HEAD, &raw_image_uri, None))
        .await
        .unwrap();
    assert_eq!(head_image.status(), StatusCode::OK);
    let bad_range = app
        .clone()
        .oneshot(range_request(
            Method::GET,
            &raw_image_uri,
            Some("bytes=999-1000"),
        ))
        .await
        .unwrap();
    assert_eq!(bad_range.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        app.clone()
            .oneshot(request(Method::GET, "/v/media/preview?path=image.png", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(request(Method::GET, &raw_image_uri, ""))
            .await
            .unwrap()
            .status(),
        StatusCode::GONE
    );

    let pdf_preview = response_text(
        app.clone()
            .oneshot(request(Method::GET, "/v/du/preview?path=file.pdf", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(pdf_preview.contains("<iframe"));
    let pdf_token = preview_token_from(&pdf_preview);
    assert!(state
        .db
        .preview_session(&pdf_token, du_id, "file.pdf")
        .unwrap());
    let raw_pdf = app
        .clone()
        .oneshot(range_request(
            Method::GET,
            &format!("/v/du/preview/raw?path=file.pdf&preview_token={pdf_token}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(raw_pdf.status(), StatusCode::OK);
    assert_eq!(
        raw_pdf.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/pdf"
    );
    assert_eq!(
        app.clone()
            .oneshot(request(
                Method::GET,
                "/v/du/preview/raw?path=image.png&preview_token=wrong",
                "",
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );

    let zip = app
        .clone()
        .oneshot(request(Method::GET, "/v/du/download.zip", ""))
        .await
        .unwrap();
    if zip.status() != StatusCode::OK {
        let status = zip.status();
        let body = response_text(zip).await;
        panic!("ZIP failed with {status}: {body}");
    }
    assert_eq!(
        zip.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/zip"
    );

    let uploaded = app
        .clone()
        .oneshot(multipart_request_with_path(
            "/v/du/upload",
            "new.txt",
            b"new",
            Some("sub"),
        ))
        .await
        .unwrap();
    assert_eq!(uploaded.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        std::fs::read(root.path().join("docs/sub/new.txt")).unwrap(),
        b"new"
    );

    let upload_only_page = response_text(
        app.clone()
            .oneshot(request(Method::GET, "/v/uo", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(!upload_only_page.contains("note.txt"));
    assert_eq!(
        app.oneshot(request(Method::GET, "/v/uo/preview?path=note.txt", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn password_rotation_rejects_an_authorized_upload_before_its_file_field() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db
        .create_share(
            "epoch-upload",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();

    let boundary = "vaultlink-epoch-boundary";
    let (body_sender, body_receiver) = tokio::sync::mpsc::channel::<io::Result<Bytes>>(1);
    let body_stream = futures_util::stream::unfold(body_receiver, |mut receiver| async move {
        receiver.recv().await.map(|item| (item, receiver))
    });
    let mut upload_request = Request::builder()
        .method(Method::POST)
        .uri("/v/epoch-upload/upload")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from_stream(body_stream))
        .unwrap();
    upload_request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));

    let app = router(state.clone());
    let upload = tokio::spawn(async move { app.oneshot(upload_request).await.unwrap() });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while state.upload_admission.available_permits() != 31 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("upload should authorize before polling the file field");

    assert!(state
        .db
        .set_share_password(share_id, Some("rotated-password-hash"))
        .unwrap());
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"late.txt\"\r\nContent-Type: application/octet-stream\r\n\r\nlate\r\n--{boundary}--\r\n"
    );
    body_sender.send(Ok(Bytes::from(body))).await.unwrap();
    drop(body_sender);

    let response = upload.await.unwrap();
    assert_eq!(response.status(), StatusCode::GONE);
    assert!(!root.path().join("uploads/late.txt").exists());
    assert_eq!(state.db.active_upload_reservations(share_id).unwrap(), 0);
}

#[tokio::test]
async fn http_upload_enforces_limit_extension_conflict_and_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state_with_limit(root.path(), data.path(), 8);
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_share(
            "upload",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    state
        .db
        .create_share(
            "replace",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::OverwriteAllowed,
        )
        .unwrap();
    state
        .db
        .create_share(
            "roundtrip",
            None,
            "uploads",
            true,
            &Permission::DownloadUpload,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let app = router(state.clone());

    let replace_page = response_text(
        app.clone()
            .oneshot(request(Method::GET, "/v/replace", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(replace_page.contains("Bestehende Datei ersetzen"));
    let upload_page = response_text(
        app.clone()
            .oneshot(request(Method::GET, "/v/upload", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(!upload_page.contains("Bestehende Datei ersetzen"));

    let uploaded = app
        .clone()
        .oneshot(multipart_request("/v/upload/upload", "ok.txt", b"content"))
        .await
        .unwrap();
    assert_eq!(uploaded.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        std::fs::read(root.path().join("uploads/ok.txt")).unwrap(),
        b"content"
    );
    let queued = app
        .clone()
        .oneshot(multipart_request(
            "/v/upload/upload/queue",
            "grüße.txt",
            b"queued",
        ))
        .await
        .unwrap();
    assert_eq!(queued.status(), StatusCode::OK);
    let queued_body = response_text(queued).await;
    assert!(queued_body.contains(r#""file":"grüße.txt""#));
    assert!(queued_body.contains(r#""outcome":"created"#));
    assert_eq!(
        std::fs::read(root.path().join("uploads/grüße.txt")).unwrap(),
        b"queued"
    );
    *state
        .upload_directory_sync_failure
        .lock()
        .expect("upload sync fault lock") = Some(std::io::ErrorKind::Other);
    let uncertain = app
        .clone()
        .oneshot(multipart_request("/v/upload/upload", "uncertain.txt", b"x"))
        .await
        .unwrap();
    assert_eq!(uncertain.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        uncertain.headers().get("x-vaultlink-durability").unwrap(),
        "uncertain"
    );
    assert!(uncertain
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("upload=uncertain"));
    assert_eq!(
        std::fs::read(root.path().join("uploads/uncertain.txt")).unwrap(),
        b"x"
    );
    let percent_name = app
        .clone()
        .oneshot(multipart_request(
            "/v/roundtrip/upload",
            "100%.txt",
            b"percent",
        ))
        .await
        .unwrap();
    assert_eq!(percent_name.status(), StatusCode::SEE_OTHER);
    let percent_download = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/v/roundtrip/download?path=100%25.txt",
            "",
        ))
        .await
        .unwrap();
    assert_eq!(percent_download.status(), StatusCode::OK);
    assert_eq!(response_text(percent_download).await, "percent");
    for unsafe_name in ["C:escape.txt", "CON.txt"] {
        assert_eq!(
            app.clone()
                .oneshot(multipart_request("/v/upload/upload", unsafe_name, b"x"))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST,
            "unsafe upload name was accepted: {unsafe_name}"
        );
    }
    let huge_path = "a".repeat(MAX_UPLOAD_PATH_FIELD_BYTES + 1);
    assert_eq!(
        app.clone()
            .oneshot(multipart_request_with_path(
                "/v/roundtrip/upload",
                "never.txt",
                b"x",
                Some(&huge_path),
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert!(!root.path().join("uploads/never.txt").exists());
    let conflict = app
        .clone()
        .oneshot(multipart_request("/v/upload/upload", "ok.txt", b"new"))
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    let conflict_body = response_text(conflict).await;
    assert!(conflict_body.contains("Datei existiert bereits"));
    assert!(conflict_body.contains("Zurück zur Freigabe"));
    assert!(conflict_body.contains(r#"href="/v/upload""#));
    let replace_without_checkbox = app
        .clone()
        .oneshot(multipart_request("/v/replace/upload", "ok.txt", b"new"))
        .await
        .unwrap();
    assert_eq!(replace_without_checkbox.status(), StatusCode::CONFLICT);
    let replace_without_checkbox_body = response_text(replace_without_checkbox).await;
    assert!(replace_without_checkbox_body.contains("Zurück zur Freigabe"));
    let replaced = app
        .clone()
        .oneshot(multipart_request_with_options(
            "/v/replace/upload",
            "ok.txt",
            b"new",
            None,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(replaced.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        std::fs::read(root.path().join("uploads/ok.txt")).unwrap(),
        b"new"
    );
    let blocked = app
        .clone()
        .oneshot(multipart_request("/v/upload/upload", "bad.exe", b"x"))
        .await
        .unwrap();
    assert_eq!(blocked.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let blocked_body = response_text(blocked).await;
    assert!(blocked_body.contains("Dateityp blockiert"));
    assert!(blocked_body.contains("Zurück zur Freigabe"));

    let blocked_with_overwrite = app
        .clone()
        .oneshot(multipart_request_with_options(
            "/v/replace/upload",
            "bad.exe",
            b"x",
            None,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(
        blocked_with_overwrite.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    let blocked_with_overwrite_body = response_text(blocked_with_overwrite).await;
    assert!(blocked_with_overwrite_body.contains("Dateityp blockiert"));
    assert!(blocked_with_overwrite_body.contains("Zurück zur Freigabe"));

    let too_large = app
        .oneshot(multipart_request(
            "/v/upload/upload",
            "large.txt",
            b"123456789",
        ))
        .await
        .unwrap();
    assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let too_large_body = response_text(too_large).await;
    assert!(too_large_body.contains("Upload ist zu groß"));
    assert!(too_large_body.contains("Zurück zur Freigabe"));
    let remaining_parts = std::fs::read_dir(root.path().join("uploads"))
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".part"))
        .count();
    assert_eq!(remaining_parts, 0);
}

#[tokio::test]
async fn public_upload_rejects_missing_duplicate_late_and_unknown_fields_without_leaks() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let mut state = test_state(root.path(), data.path());
    state.upload_admission = Arc::new(tokio::sync::Semaphore::new(1));
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db
        .create_share(
            "multipart-states",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let app = router(state.clone());
    let boundary = "vaultlink-field-state-boundary";
    let closing = format!("--{boundary}--\r\n");
    let path = |value: &str| {
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n{value}\r\n")
    };
    let file = |name: &str, value: &str| {
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n{value}\r\n"
        )
    };
    let unknown = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"surprise\"\r\n\r\nvalue\r\n"
    );
    let cases = [
        (
            "missing",
            format!("{}{}", path("unused"), closing),
            "Datei fehlt",
        ),
        (
            "duplicate-path",
            format!("{}{}{}", path("first"), path("second"), closing),
            "Uploadpfad",
        ),
        (
            "late-path",
            format!("{}{}{}", file("late.txt", "one"), path("late"), closing),
            "Uploadpfad",
        ),
        (
            "multiple-files",
            format!(
                "{}{}{}",
                file("first.txt", "one"),
                file("second.txt", "two"),
                closing
            ),
            "genau eine Datei",
        ),
        (
            "unknown",
            format!("{unknown}{closing}"),
            "Unbekanntes Multipart-Feld",
        ),
    ];

    for (case, body, expected_message) in cases {
        let response = app
            .clone()
            .oneshot(raw_multipart_request(
                "/v/multipart-states/upload",
                boundary,
                body.into_bytes(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "case {case}");
        assert!(
            response_text(response).await.contains(expected_message),
            "case {case} did not report {expected_message}"
        );
        wait_for_public_upload_cleanup(&state, root.path(), share_id).await;
        assert!(!root.path().join("uploads/late.txt").exists());
        assert!(!root.path().join("uploads/first.txt").exists());
        assert!(!root.path().join("uploads/second.txt").exists());
    }
    assert_eq!(state.db.active_upload_reservations(share_id).unwrap(), 0);
    assert!(state
        .db
        .list_audit(Some("upload"), 10, 0)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn public_upload_binds_intent_after_the_complete_multipart_envelope() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    std::fs::write(root.path().join("uploads/existing.txt"), b"old").unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db
        .create_share(
            "late-intent",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::OverwriteAllowed,
        )
        .unwrap();
    let response = router(state.clone())
        .oneshot(multipart_request_with_late_overwrite(
            "/v/late-intent/upload",
            "existing.txt",
            b"new",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get("x-vaultlink-upload-outcome")
            .unwrap(),
        "replaced"
    );
    assert_eq!(
        std::fs::read(root.path().join("uploads/existing.txt")).unwrap(),
        b"new"
    );
    assert_eq!(state.db.active_upload_reservations(share_id).unwrap(), 0);
    assert_eq!(
        state
            .db
            .share_by_token("late-intent")
            .unwrap()
            .unwrap()
            .uploaded_bytes,
        3
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_upload_cancellation_during_staging_releases_the_typed_owner() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let mut state = test_state(root.path(), data.path());
    state.upload_admission = Arc::new(tokio::sync::Semaphore::new(1));
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db
        .create_share(
            "cancel-staging",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let hook = PublicUploadTestHook::blocking("cancel-staging", PublicUploadTestPhase::Staging);
    let hook_guard = install_public_upload_test_hook(hook.clone());
    let app = router(state.clone());
    let request = tokio::spawn(async move {
        app.oneshot(multipart_request(
            "/v/cancel-staging/upload",
            "cancelled.txt",
            b"content",
        ))
        .await
        .unwrap()
    });
    hook.wait_until_entered().await;

    assert_eq!(state.upload_admission.available_permits(), 0);
    assert_eq!(state.db.active_upload_reservations(share_id).unwrap(), 1);
    assert_eq!(upload_fragment_count(root.path()), 1);
    request.abort();
    let _ = request.await;

    wait_for_public_upload_cleanup(&state, root.path(), share_id).await;
    assert!(!root.path().join("uploads/cancelled.txt").exists());
    assert!(state
        .db
        .list_audit(Some("upload"), 10, 0)
        .unwrap()
        .is_empty());
    drop(hook_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_upload_cancellation_after_finalizer_handoff_does_not_abort_publish() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let mut state = test_state(root.path(), data.path());
    state.upload_admission = Arc::new(tokio::sync::Semaphore::new(1));
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db
        .create_share(
            "cancel-finalizer",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let hook = PublicUploadTestHook::blocking("cancel-finalizer", PublicUploadTestPhase::Finalizer);
    let hook_guard = install_public_upload_test_hook(hook.clone());
    let app = router(state.clone());
    let request = tokio::spawn(async move {
        app.oneshot(multipart_request(
            "/v/cancel-finalizer/upload",
            "published.txt",
            b"content",
        ))
        .await
        .unwrap()
    });
    hook.wait_until_entered().await;

    request.abort();
    let _ = request.await;
    tokio::task::yield_now().await;
    assert_eq!(state.upload_admission.available_permits(), 0);
    assert_eq!(state.db.active_upload_reservations(share_id).unwrap(), 1);
    assert_eq!(upload_fragment_count(root.path()), 1);

    hook.release();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if state.upload_admission.available_permits() == 1
                && state.db.active_upload_reservations(share_id).unwrap() == 0
                && root.path().join("uploads/published.txt").exists()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("detached upload finalizer should publish and release ownership");
    assert_eq!(
        std::fs::read(root.path().join("uploads/published.txt")).unwrap(),
        b"content"
    );
    assert_eq!(state.db.list_audit(Some("upload"), 10, 0).unwrap().len(), 1);
    drop(hook_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_upload_staging_io_failure_cleans_fragment_and_quota() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let mut state = test_state(root.path(), data.path());
    state.upload_admission = Arc::new(tokio::sync::Semaphore::new(1));
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db
        .create_share(
            "staging-failure",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let hook = PublicUploadTestHook::failing(
        "staging-failure",
        PublicUploadTestPhase::StagingSync,
        io::ErrorKind::Other,
    );
    let hook_guard = install_public_upload_test_hook(hook.clone());
    let response = router(state.clone())
        .oneshot(multipart_request(
            "/v/staging-failure/upload",
            "never.txt",
            b"content",
        ))
        .await
        .unwrap();
    hook.wait_until_entered().await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    wait_for_public_upload_cleanup(&state, root.path(), share_id).await;
    assert!(!root.path().join("uploads/never.txt").exists());
    assert!(state
        .db
        .list_audit(Some("upload"), 10, 0)
        .unwrap()
        .is_empty());
    drop(hook_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_upload_uses_the_policy_that_wins_before_finalization() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    std::fs::write(root.path().join("uploads/existing.txt"), b"old").unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_session(
            "policy-session",
            1,
            "policy-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("policy-session").unwrap();
    let share_id = state
        .db
        .create_share(
            "policy-first",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::OverwriteAllowed,
        )
        .unwrap();
    let app = router(state.clone());
    let (upload, sender) =
        controlled_multipart_request("/v/policy-first/upload", "existing.txt", b"new", true);
    let upload_app = app.clone();
    let upload = tokio::spawn(async move { upload_app.oneshot(upload).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;

    let policy = app
        .clone()
        .oneshot(api_share_strategy_request(
            share_id,
            "reject",
            "policy-session",
            "policy-csrf",
        ))
        .await
        .unwrap();
    assert_eq!(policy.status(), StatusCode::OK);
    finish_controlled_multipart(sender).await;

    let upload = upload.await.unwrap();
    assert_eq!(upload.status(), StatusCode::CONFLICT);
    assert_eq!(
        std::fs::read(root.path().join("uploads/existing.txt")).unwrap(),
        b"old"
    );
    assert_eq!(state.db.active_upload_reservations(share_id).unwrap(), 0);
    let share = state.db.share_by_token("policy-first").unwrap().unwrap();
    assert_eq!(
        share.upload_conflict_strategy,
        UploadConflictStrategy::Reject
    );
    assert_eq!(share.uploaded_bytes, 0);
    assert_eq!(share.uploaded_files, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_upload_publish_wins_before_a_waiting_policy_change() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    std::fs::write(root.path().join("uploads/existing.txt"), b"old").unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_session(
            "policy-session",
            1,
            "policy-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("policy-session").unwrap();
    let share_id = state
        .db
        .create_share(
            "upload-first",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::OverwriteAllowed,
        )
        .unwrap();
    let hook = PublicUploadTestHook::blocking("upload-first", PublicUploadTestPhase::StorageLocked);
    let hook_guard = install_public_upload_test_hook(hook.clone());
    let app = router(state.clone());
    let (upload, sender) =
        controlled_multipart_request("/v/upload-first/upload", "existing.txt", b"new", true);
    let upload_app = app.clone();
    let upload = tokio::spawn(async move { upload_app.oneshot(upload).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;

    finish_controlled_multipart(sender).await;
    hook.wait_until_entered().await;
    let policy_app = app.clone();
    let policy = tokio::spawn(async move {
        policy_app
            .oneshot(api_share_strategy_request(
                share_id,
                "reject",
                "policy-session",
                "policy-csrf",
            ))
            .await
            .unwrap()
    });
    tokio::task::yield_now().await;
    assert!(!policy.is_finished());

    hook.release();
    let upload = upload.await.unwrap();
    assert_eq!(upload.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        std::fs::read(root.path().join("uploads/existing.txt")).unwrap(),
        b"new"
    );
    let policy = policy.await.unwrap();
    assert_eq!(policy.status(), StatusCode::OK);
    assert_eq!(state.db.active_upload_reservations(share_id).unwrap(), 0);
    let share = state.db.share_by_token("upload-first").unwrap().unwrap();
    assert_eq!(
        share.upload_conflict_strategy,
        UploadConflictStrategy::Reject
    );
    assert_eq!(share.uploaded_bytes, 3);
    assert_eq!(share.uploaded_files, 1);
    drop(hook_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_upload_uses_the_html_policy_that_wins_before_finalization() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    std::fs::write(root.path().join("uploads/existing.txt"), b"old").unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_session(
            "html-policy-session",
            1,
            "html-policy-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("html-policy-session").unwrap();
    let share_id = state
        .db
        .create_share(
            "html-policy-first",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::OverwriteAllowed,
        )
        .unwrap();
    let app = router(state.clone());
    let (upload, sender) =
        controlled_multipart_request("/v/html-policy-first/upload", "existing.txt", b"new", true);
    let upload_app = app.clone();
    let upload = tokio::spawn(async move { upload_app.oneshot(upload).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;

    let policy = app
        .clone()
        .oneshot(html_share_strategy_request(
            share_id,
            "reject",
            "html-policy-session",
            "html-policy-csrf",
        ))
        .await
        .unwrap();
    assert_eq!(policy.status(), StatusCode::SEE_OTHER);
    finish_controlled_multipart(sender).await;

    let upload = upload.await.unwrap();
    assert_eq!(upload.status(), StatusCode::CONFLICT);
    assert_eq!(
        std::fs::read(root.path().join("uploads/existing.txt")).unwrap(),
        b"old"
    );
    assert_eq!(state.db.active_upload_reservations(share_id).unwrap(), 0);
    let share = state
        .db
        .share_by_token("html-policy-first")
        .unwrap()
        .unwrap();
    assert_eq!(
        share.upload_conflict_strategy,
        UploadConflictStrategy::Reject
    );
    assert_eq!(share.uploaded_bytes, 0);
    assert_eq!(share.uploaded_files, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_upload_publish_wins_before_a_waiting_html_policy_change() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    std::fs::write(root.path().join("uploads/existing.txt"), b"old").unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_session(
            "html-upload-session",
            1,
            "html-upload-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("html-upload-session").unwrap();
    let share_id = state
        .db
        .create_share(
            "html-upload-first",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::OverwriteAllowed,
        )
        .unwrap();
    let hook =
        PublicUploadTestHook::blocking("html-upload-first", PublicUploadTestPhase::StorageLocked);
    let hook_guard = install_public_upload_test_hook(hook.clone());
    let app = router(state.clone());
    let (upload, sender) =
        controlled_multipart_request("/v/html-upload-first/upload", "existing.txt", b"new", true);
    let upload_app = app.clone();
    let upload = tokio::spawn(async move { upload_app.oneshot(upload).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;

    finish_controlled_multipart(sender).await;
    hook.wait_until_entered().await;
    let policy_app = app.clone();
    let policy = tokio::spawn(async move {
        policy_app
            .oneshot(html_share_strategy_request(
                share_id,
                "reject",
                "html-upload-session",
                "html-upload-csrf",
            ))
            .await
            .unwrap()
    });
    tokio::task::yield_now().await;
    assert!(!policy.is_finished());

    hook.release();
    let upload = upload.await.unwrap();
    assert_eq!(upload.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        std::fs::read(root.path().join("uploads/existing.txt")).unwrap(),
        b"new"
    );
    let policy = policy.await.unwrap();
    assert_eq!(policy.status(), StatusCode::SEE_OTHER);
    assert_eq!(state.db.active_upload_reservations(share_id).unwrap(), 0);
    let share = state
        .db
        .share_by_token("html-upload-first")
        .unwrap()
        .unwrap();
    assert_eq!(
        share.upload_conflict_strategy,
        UploadConflictStrategy::Reject
    );
    assert_eq!(share.uploaded_bytes, 3);
    assert_eq!(share.uploaded_files, 1);
    drop(hook_guard);
}

#[tokio::test]
async fn protected_public_upload_binds_csrf_and_enforces_persistent_quota() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let password_hash = auth::hash_password("correct horse battery staple").unwrap();
    let share_id = state
        .db
        .create_share_with_upload_limits(
            "protected-upload",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            Some(5),
            Some(5),
            Some(2),
            1,
            Some(&password_hash),
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let app = router(state.clone());

    let unlock = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/v/protected-upload/unlock",
            "password=correct+horse+battery+staple",
        ))
        .await
        .unwrap();
    assert_eq!(unlock.status(), StatusCode::SEE_OTHER);
    let unlock_cookie = unlock
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let mut page_request = request(Method::GET, "/v/protected-upload", "");
    page_request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&unlock_cookie).unwrap(),
    );
    let page = response_text(app.clone().oneshot(page_request).await.unwrap()).await;
    let csrf_marker = "name=\"csrf\" value=\"";
    let csrf_start = page.find(csrf_marker).unwrap() + csrf_marker.len();
    let csrf_end = csrf_start + page[csrf_start..].find('"').unwrap();
    let upload_csrf = page[csrf_start..csrf_end].to_string();
    assert!(!upload_csrf.is_empty());

    let mut missing_csrf = multipart_request("/v/protected-upload/upload", "missing.txt", b"x");
    missing_csrf.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&unlock_cookie).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(missing_csrf).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    let mut wrong_csrf = public_multipart_request_with_csrf(
        "/v/protected-upload/upload",
        "wrong.txt",
        b"x",
        "wrong",
    );
    wrong_csrf.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&unlock_cookie).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(wrong_csrf).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    let mut duplicate_cookie = public_multipart_request_with_csrf(
        "/v/protected-upload/upload",
        "duplicate.txt",
        b"x",
        &upload_csrf,
    );
    duplicate_cookie.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&format!(
            "{unlock_cookie}; {}=attacker",
            crate::http_auth::unlock_cookie_name(share_id)
        ))
        .unwrap(),
    );
    assert_eq!(
        app.clone()
            .oneshot(duplicate_cookie)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let reserved_name = format!(".vaultlink-delete-{}.tombstone", "A".repeat(24));
    let mut reserved = public_multipart_request_with_csrf(
        "/v/protected-upload/upload",
        &reserved_name,
        b"x",
        &upload_csrf,
    );
    reserved.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&unlock_cookie).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(reserved).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert!(!root.path().join("uploads").join(&reserved_name).exists());
    assert_eq!(state.db.active_upload_reservations(share_id).unwrap(), 0);
    let share = state
        .db
        .share_by_token("protected-upload")
        .unwrap()
        .unwrap();
    assert_eq!((share.uploaded_bytes, share.uploaded_files), (0, 0));

    let mut accepted = public_multipart_request_with_csrf(
        "/v/protected-upload/upload",
        "first.txt",
        b"1234",
        &upload_csrf,
    );
    accepted.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&unlock_cookie).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(accepted).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    let share = state
        .db
        .share_by_token("protected-upload")
        .unwrap()
        .unwrap();
    assert_eq!((share.uploaded_bytes, share.uploaded_files), (4, 1));

    let mut conflict = public_multipart_request_with_csrf(
        "/v/protected-upload/upload",
        "first.txt",
        b"5",
        &upload_csrf,
    );
    conflict.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&unlock_cookie).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(conflict).await.unwrap().status(),
        StatusCode::CONFLICT
    );
    assert_eq!(state.db.active_upload_reservations(share_id).unwrap(), 0);

    let mut over_quota = multipart_request("/v/protected-upload/upload", "too-large.txt", b"56");
    over_quota.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&unlock_cookie).unwrap(),
    );
    over_quota.headers_mut().insert(
        "x-vaultlink-upload-csrf",
        HeaderValue::from_str(&upload_csrf).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(over_quota).await.unwrap().status(),
        StatusCode::INSUFFICIENT_STORAGE
    );
    for _ in 0..100 {
        if state.db.active_upload_reservations(share_id).unwrap() == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    let share = state
        .db
        .share_by_token("protected-upload")
        .unwrap()
        .unwrap();
    assert_eq!((share.uploaded_bytes, share.uploaded_files), (4, 1));
    assert_eq!(state.db.active_upload_reservations(share_id).unwrap(), 0);

    let mut exact_quota = multipart_request("/v/protected-upload/upload", "last.txt", b"5");
    exact_quota.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&unlock_cookie).unwrap(),
    );
    exact_quota.headers_mut().insert(
        "x-vaultlink-upload-csrf",
        HeaderValue::from_str(&upload_csrf).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(exact_quota).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    let share = state
        .db
        .share_by_token("protected-upload")
        .unwrap()
        .unwrap();
    assert_eq!((share.uploaded_bytes, share.uploaded_files), (5, 2));
}

#[tokio::test]
async fn external_writers_disable_saved_public_overwrite_policy() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    std::fs::write(root.path().join("uploads/report.txt"), b"external").unwrap();
    let mut state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_session(
            "external-admin-session",
            1,
            "external-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("external-admin-session").unwrap();
    state
        .db
        .create_share(
            "external-writers",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::OverwriteAllowed,
        )
        .unwrap();
    let mut config = (*state.config).clone();
    config.storage.external_writers = true;
    state.config = std::sync::Arc::new(config);
    let app = router(state);

    let page = response_text(
        app.clone()
            .oneshot(request(Method::GET, "/v/external-writers", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(!page.contains("overwrite_existing"));

    let mut admin_request = request(Method::GET, "/admin/shares", "");
    admin_request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=external-admin-session"),
    );
    let admin_page = response_text(app.clone().oneshot(admin_request).await.unwrap()).await;
    assert!(admin_page.contains("max_upload_total_size_gb"));
    assert!(admin_page.contains("max_upload_files"));
    assert!(!admin_page.contains("overwrite_allowed"));

    let response = app
        .oneshot(multipart_request_with_options(
            "/v/external-writers/upload",
            "report.txt",
            b"vaultlink",
            None,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        std::fs::read(root.path().join("uploads/report.txt")).unwrap(),
        b"external"
    );
}

#[tokio::test]
async fn explicit_external_writer_replace_opt_in_enables_last_writer_wins() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    std::fs::write(root.path().join("uploads/report.txt"), b"external").unwrap();
    let mut state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_session(
            "external-replace-admin-session",
            1,
            "external-replace-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state
        .db
        .verify_mfa("external-replace-admin-session")
        .unwrap();
    state
        .db
        .create_share(
            "external-replace",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::OverwriteAllowed,
        )
        .unwrap();
    let mut config = (*state.config).clone();
    config.storage.external_writers = true;
    config.storage.allow_external_writer_replace = true;
    state.config = std::sync::Arc::new(config);
    let app = router(state);

    let page = response_text(
        app.clone()
            .oneshot(request(Method::GET, "/v/external-replace", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(page.contains("overwrite_existing"));

    let mut admin_request = request(Method::GET, "/admin/shares", "");
    admin_request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=external-replace-admin-session"),
    );
    let admin_page = response_text(app.clone().oneshot(admin_request).await.unwrap()).await;
    assert!(admin_page.contains("overwrite_allowed"));

    let response = app
        .oneshot(multipart_request_with_options(
            "/v/external-replace/upload",
            "report.txt",
            b"vaultlink",
            None,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        std::fs::read(root.path().join("uploads/report.txt")).unwrap(),
        b"vaultlink"
    );
}

#[tokio::test]
async fn api_upload_route_can_stream_beyond_the_buffered_body_limit() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state_with_limit(root.path(), data.path(), 2_000_000);
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_share(
            "large-upload",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let app = router(state);
    let content = vec![b'x'; DEFAULT_REQUEST_BODY_LIMIT + 64 * 1024];
    let response = app
        .oneshot(multipart_request(
            "/api/v1/public/shares/large-upload/upload",
            "large.bin",
            &content,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("/api/v1/public/shares/large-upload"));
    assert_eq!(
        std::fs::metadata(root.path().join("uploads/large.bin"))
            .unwrap()
            .len(),
        content.len() as u64
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_upload_revocation_covers_password_mfa_and_expiry_and_releases_admission() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    for name in ["password.txt", "mfa.txt", "expired.txt"] {
        std::fs::write(root.path().join("uploads").join(name), b"original").unwrap();
    }
    let mut state = test_state(root.path(), data.path());
    state.upload_admission = Arc::new(tokio::sync::Semaphore::new(1));
    state
        .db
        .create_admin("admin", "old-hash", "secret")
        .unwrap();
    let app = router(state.clone());

    state
        .db
        .create_session(
            "password-session",
            1,
            "csrf-token",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("password-session").unwrap();
    let storage_guard = state.storage_mutation.clone().lock_owned().await;
    let mut upload = admin_multipart_request(
        "/admin/files/upload/queue",
        "uploads",
        "csrf-token",
        "password.txt",
        b"must not replace",
        true,
    );
    upload.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=password-session"),
    );
    let upload_app = app.clone();
    let upload = tokio::spawn(async move { upload_app.oneshot(upload).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;
    assert!(matches!(
        state
            .db
            .change_admin_password_cas(1, "old-hash", "new-hash", None)
            .unwrap(),
        crate::db::AdminPasswordChangeOutcome::Changed
    ));
    drop(storage_guard);
    let response = upload.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_text(response).await,
        r#"{"error":"session_revoked"}"#
    );
    assert_eq!(
        std::fs::read(root.path().join("uploads/password.txt")).unwrap(),
        b"original"
    );
    assert_eq!(state.upload_admission.available_permits(), 1);

    state
        .db
        .create_session(
            "mfa-session",
            1,
            "csrf-token",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("mfa-session").unwrap();
    let storage_guard = state.storage_mutation.clone().lock_owned().await;
    let mut upload = admin_multipart_request(
        "/admin/files/upload/queue",
        "uploads",
        "csrf-token",
        "mfa.txt",
        b"must not replace",
        true,
    );
    upload.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=mfa-session"),
    );
    let upload_app = app.clone();
    let upload = tokio::spawn(async move { upload_app.oneshot(upload).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;
    assert!(state
        .db
        .reset_admin_totp(1, &auth::new_totp_secret())
        .unwrap()
        .is_some());
    drop(storage_guard);
    let response = upload.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_text(response).await,
        r#"{"error":"session_revoked"}"#
    );
    assert_eq!(
        std::fs::read(root.path().join("uploads/mfa.txt")).unwrap(),
        b"original"
    );
    assert_eq!(state.upload_admission.available_permits(), 1);

    state
        .db
        .create_session(
            "expiry-session",
            1,
            "csrf-token",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("expiry-session").unwrap();
    let storage_guard = state.storage_mutation.clone().lock_owned().await;
    let mut upload = admin_multipart_request(
        "/admin/files/upload/queue",
        "uploads",
        "csrf-token",
        "expired.txt",
        b"must not replace",
        true,
    );
    upload.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=expiry-session"),
    );
    let upload_app = app.clone();
    let upload = tokio::spawn(async move { upload_app.oneshot(upload).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;
    state.db.expire_session_for_test("expiry-session").unwrap();
    drop(storage_guard);
    let response = upload.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_text(response).await,
        r#"{"error":"session_revoked"}"#
    );
    assert_eq!(
        std::fs::read(root.path().join("uploads/expired.txt")).unwrap(),
        b"original"
    );

    assert_eq!(state.upload_admission.available_permits(), 1);
    assert!(state.upload_peer_admission.lock().unwrap().is_empty());
    assert_eq!(state.db.count_audit(Some("admin_upload")).unwrap(), 0);
    assert_eq!(
        state.db.count_audit(Some("admin_upload_replaced")).unwrap(),
        0
    );
}
