#[tokio::test]
async fn response_admission_releases_handlers_but_bounds_stream_bodies() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut state = test_state(root.path(), data.path());
    let admission = Arc::new(tokio::sync::Semaphore::new(1));
    let streams = Arc::new(tokio::sync::Semaphore::new(1));
    state.replace_response_admission_for_test(admission.clone());
    state.replace_stream_admission_for_test(streams.clone());
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
async fn public_stream_ceiling_preserves_global_capacity_for_admin_downloads() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut state = test_state(root.path(), data.path());
    let public_streams = Arc::new(tokio::sync::Semaphore::new(1));
    let all_streams = Arc::new(tokio::sync::Semaphore::new(2));
    state.replace_public_stream_admission_for_test(public_streams.clone());
    state.replace_stream_admission_for_test(all_streams.clone());
    let pending = || async {
        Response::new(Body::from_stream(futures_util::stream::pending::<
            io::Result<Bytes>,
        >()))
    };
    let app = Router::new()
        .route("/v/token/download", get(pending))
        .route("/admin/files/download", get(pending))
        .layer(middleware::from_fn_with_state(state, response_admission));

    let public = app
        .clone()
        .oneshot(request(Method::GET, "/v/token/download", ""))
        .await
        .unwrap();
    assert_eq!(public.status(), StatusCode::OK);
    assert_eq!(public_streams.available_permits(), 0);
    assert_eq!(all_streams.available_permits(), 1);

    let rejected = app
        .clone()
        .oneshot(request(Method::GET, "/v/token/download", ""))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(rejected.headers().get(header::RETRY_AFTER).unwrap(), "1");
    assert_eq!(all_streams.available_permits(), 1);

    let admin = app
        .clone()
        .oneshot(request(Method::GET, "/admin/files/download", ""))
        .await
        .unwrap();
    assert_eq!(admin.status(), StatusCode::OK);
    assert_eq!(all_streams.available_permits(), 0);

    drop(admin);
    drop(public);
    assert_eq!(public_streams.available_permits(), 1);
    assert_eq!(all_streams.available_permits(), 2);
}

#[tokio::test]
async fn trusted_forwarded_clients_receive_independent_stream_limits() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut state = test_state(root.path(), data.path());
    let mut config = state.config().clone();
    config.server.mode = ServerMode::ReverseProxy;
    config.reverse_proxy.enabled = true;
    config.reverse_proxy.trust_x_forwarded_headers = true;
    config.reverse_proxy.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];
    state.replace_config_for_test(config);
    state.replace_response_admission_for_test(Arc::new(tokio::sync::Semaphore::new(
        crate::MAX_IN_FLIGHT_STREAMS_PER_CLIENT + 2,
    )));
    state.replace_stream_admission_for_test(Arc::new(tokio::sync::Semaphore::new(
        crate::MAX_IN_FLIGHT_STREAMS_PER_CLIENT + 2,
    )));
    let app = Router::new()
        .route(
            "/download",
            get(|| async {
                Response::new(Body::from_stream(futures_util::stream::pending::<
                    io::Result<Bytes>,
                >()))
            }),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            response_admission,
        ))
        .layer(middleware::from_fn_with_state(
            state,
            audit_client_ip_context,
        ));
    let forwarded_request = |identity: &str| {
        let mut request = Request::builder()
            .uri("/download")
            .header("x-forwarded-for", identity)
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
        ));
        request
    };

    let mut held_responses = Vec::new();
    for _ in 0..crate::MAX_IN_FLIGHT_STREAMS_PER_CLIENT {
        let response = app
            .clone()
            .oneshot(forwarded_request("198.18.255.1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        held_responses.push(response);
    }

    let same_client = app
        .clone()
        .oneshot(forwarded_request("198.18.255.1"))
        .await
        .unwrap();
    assert_eq!(same_client.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        same_client.headers().get(header::RETRY_AFTER),
        Some(&HeaderValue::from_static("1"))
    );

    let distinct_client = app
        .clone()
        .oneshot(forwarded_request("198.18.255.2"))
        .await
        .unwrap();
    assert_eq!(distinct_client.status(), StatusCode::OK);

    drop(held_responses);
    assert_eq!(
        app.oneshot(forwarded_request("198.18.255.1"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn malformed_trusted_forwarding_is_rejected_before_admission_with_security_headers() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut state = test_state(root.path(), data.path());
    let mut config = state.config().clone();
    config.server.mode = ServerMode::ReverseProxy;
    config.reverse_proxy.enabled = true;
    config.reverse_proxy.trust_x_forwarded_headers = true;
    config.reverse_proxy.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];
    state.replace_config_for_test(config);
    state.replace_response_admission_for_test(Arc::new(tokio::sync::Semaphore::new(0)));
    let mut forwarded = request(Method::GET, "/assets/vaultlink.css", "");
    forwarded
        .headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("not-an-ip"));

    let response = router(state).oneshot(forwarded).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
}

#[tokio::test]
async fn absolute_body_deadline_stops_a_body_that_never_yields() {
    let inner = Body::from_stream(futures_util::stream::pending::<io::Result<Bytes>>());
    let body = Body::new(AbsoluteDeadlineBody {
        inner,
        deadline: Box::pin(tokio::time::sleep(std::time::Duration::from_millis(1))),
        minimum_progress: None,
        timed_out: false,
    });
    let error = axum::body::to_bytes(body, 1024)
        .await
        .expect_err("pending body must hit its absolute deadline");
    assert!(error.to_string().contains("deadline"));
    assert!(!upload_request_path("/login"));
    assert!(upload_request_path("/v/token/upload"));
    assert!(upload_request_path("/api/v2/public/shares/token/upload"));
}

#[tokio::test]
async fn minimum_upload_progress_stops_a_body_after_grace_and_window() {
    let inner = Body::from_stream(futures_util::stream::pending::<io::Result<Bytes>>());
    let body = Body::new(AbsoluteDeadlineBody {
        inner,
        deadline: Box::pin(tokio::time::sleep(std::time::Duration::from_secs(1))),
        minimum_progress: Some(MinimumProgress::with_intervals(
            1,
            std::time::Duration::from_millis(1),
            std::time::Duration::from_millis(1),
        )),
        timed_out: false,
    });
    let error = axum::body::to_bytes(body, 1024)
        .await
        .expect_err("pending upload must fail its minimum progress window");
    assert!(error.to_string().contains("minimum request body progress"));
}

#[test]
fn upload_deadline_scales_with_content_length_and_honors_operator_cap() {
    let admission = Admission::default();
    assert_eq!(
        upload_request_body_deadline(&admission, Some(1)),
        std::time::Duration::from_secs(15 * 60)
    );
    assert_eq!(
        upload_request_body_deadline(
            &admission,
            Some(admission.upload_min_bytes_per_second * 1_000),
        ),
        std::time::Duration::from_secs(5 * 60 + 1_000)
    );
    assert_eq!(
        upload_request_body_deadline(&admission, None),
        std::time::Duration::from_secs(admission.upload_max_duration_seconds)
    );
    let mut tightened = admission;
    tightened.upload_max_duration_seconds = 600;
    assert_eq!(
        upload_request_body_deadline(&tightened, Some(1)),
        std::time::Duration::from_secs(600)
    );
}

#[tokio::test]
async fn public_transfer_deadline_stops_a_stream_that_never_yields() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let mut stream = TransferBodyStream {
        inner: Box::pin(futures_util::stream::pending()),
        database: state.db().clone(),
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
        request_span: tracing::Span::none(),
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
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let transfer_share = state
        .db()
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
        .db()
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

    let transfer_database = state.db().clone();
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
            .db()
            .active_transfer_reservations(transfer_share)
            .unwrap(),
        1
    );
    transfer_request.abort();
    let _ = transfer_request.await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while state
            .db()
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
            .db()
            .active_transfer_reservations(transfer_share)
            .unwrap(),
        0
    );

    let upload_database = state.db().clone();
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
        state.db().active_upload_reservations(upload_share).unwrap(),
        1
    );
    upload_request.abort();
    let _ = upload_request.await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while state.db().active_upload_reservations(upload_share).unwrap() != 0 {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("cancelled upload reservation should be released");
    assert_eq!(
        state.db().active_upload_reservations(upload_share).unwrap(),
        0
    );
}

#[tokio::test]
async fn consuming_lease_and_quota_guards_finish_their_durable_ownership() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let transfer_share = state
        .db()
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
        .db()
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
            .db()
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
        state.db().clone(),
        "consuming-lease".into(),
        String::new(),
        None,
        None,
    )
    .cancel()
    .await;
    assert_eq!(
        state
            .db()
            .active_transfer_reservations(transfer_share)
            .unwrap(),
        0
    );

    assert_eq!(
        state
            .db()
            .begin_upload_reservation("consuming-cancel", upload_share, 0)
            .unwrap(),
        UploadReservationBeginOutcome::Reserved
    );
    UploadQuotaReservation::new(state.db().clone(), "consuming-cancel".into())
        .cancel()
        .await
        .unwrap();
    assert_eq!(
        state.db().active_upload_reservations(upload_share).unwrap(),
        0
    );

    assert_eq!(
        state
            .db()
            .begin_upload_reservation("consuming-commit", upload_share, 0)
            .unwrap(),
        UploadReservationBeginOutcome::Reserved
    );
    let committed = UploadQuotaReservation::new(state.db().clone(), "consuming-commit".into());
    assert_eq!(
        state
            .db()
            .extend_upload_reservation("consuming-commit", 1)
            .unwrap(),
        UploadReservationExtendOutcome::Extended
    );
    assert_eq!(
        state
            .db()
            .commit_upload_reservation("consuming-commit", 1)
            .unwrap(),
        UploadReservationCommitOutcome::Committed
    );
    committed.committed();
    assert_eq!(
        state.db().active_upload_reservations(upload_share).unwrap(),
        0
    );
}

#[test]
fn reservation_drop_schedules_blocking_cleanup_before_immediate_runtime_shutdown() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let transfer_share = state
        .db()
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
        .db()
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
    let database = state.db();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reservation_drop_uses_fair_async_cleanup_when_database_executor_is_saturated() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let upload_share = state
        .db()
        .create_share_with_upload_limits(
            "saturated-cleanup-upload",
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
    state
        .db()
        .begin_upload_reservation("saturated-cleanup-reservation", upload_share, 0)
        .unwrap();

    let mut permits = Vec::new();
    while state.db().runtime_available_permits() > 0 {
        permits.push(state.db().acquire_runtime_permit().await.unwrap());
    }
    drop(UploadQuotaReservation::new(
        state.db().clone(),
        "saturated-cleanup-reservation".into(),
    ));
    tokio::task::yield_now().await;
    assert_eq!(
        state.db().active_upload_reservations(upload_share).unwrap(),
        1
    );

    drop(permits.pop());
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while state.db().active_upload_reservations(upload_share).unwrap() != 0 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("queued reservation cleanup did not acquire released executor capacity");
}

#[tokio::test]
async fn unknown_length_transfer_counts_before_its_first_payload_chunk_is_yielded() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
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
            .db()
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
        state.db().clone(),
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
            .db()
            .share_by_token("direct-stream")
            .unwrap()
            .unwrap()
            .download_count,
        1
    );
    assert_eq!(
        state.db().active_transfer_reservations(share_id).unwrap(),
        0
    );
}

#[tokio::test]
async fn public_transfer_completion_uses_the_validated_audit_ip_snapshot() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("snapshot.txt"), b"snapshot").unwrap();
    let mut state = test_state(root.path(), data.path());
    let mut config = state.config().clone();
    config.server.mode = ServerMode::ReverseProxy;
    config.reverse_proxy.enabled = true;
    config.reverse_proxy.trust_x_forwarded_headers = true;
    config.reverse_proxy.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];
    state.replace_config_for_test(config);
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
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
    state.mutate_runtime_for_test(|runtime| runtime.audit_client_ip_enabled = true);
    let mut download = request(Method::GET, "/v/snapshot-transfer/download", "");
    download
        .headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
    let response = router(state.clone()).oneshot(download).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(state.stream_peer_admission_contains_for_test("203.0.113.10".parse().unwrap()));

    state.poison_runtime_for_test();
    assert!(state.runtime_is_poisoned_for_test());

    assert_eq!(response_text(response).await, "snapshot");
    let events = state.db().list_audit(Some("download"), 10, 0).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].client_ip.as_deref(), Some("203.0.113.10"));
}

#[tokio::test]
async fn known_length_transfer_counts_before_n_minus_one_bytes_are_yielded() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
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
            .db()
            .begin_transfer_lease("known-session", "known-lease", share_id, ".", "download",)
            .unwrap(),
        TransferLeaseBeginOutcome::NewLease
    );
    let transfer = PublicTransferLease::new(
        state.db().clone(),
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
            .db()
            .share_by_token("known-stream")
            .unwrap()
            .unwrap()
            .download_count,
        1
    );
    assert_eq!(
        state.db().active_transfer_reservations(share_id).unwrap(),
        0
    );
    drop(body); // the final byte is never requested
}

#[tokio::test]
async fn response_body_wrappers_chunk_buffered_data_and_deadline_streams() {
    let counts = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let peer = "192.0.2.1".parse().unwrap();
    let buffered_slots = Arc::new(tokio::sync::Semaphore::new(1));
    let buffered_permit = buffered_slots.clone().try_acquire_owned().unwrap();
    let buffered_peer = try_acquire_client_activity(counts.clone(), peer, 1).unwrap();
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
    let stream_peer = try_acquire_client_activity(counts.clone(), peer, 1).unwrap();
    let body = Body::new(StreamAdmissionBody {
        inner: Body::from_stream(futures_util::stream::pending::<io::Result<Bytes>>()),
        _permit: stream_permit,
        _peer_permit: stream_peer,
        _public_permit: None,
        deadline: Box::pin(tokio::time::sleep(std::time::Duration::from_millis(1))),
        minimum_progress: MinimumProgress::with_intervals(
            1,
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        ),
        transferred_data_bytes: 0,
        operation: "download",
        public: true,
        complete: false,
    });
    let error = axum::body::to_bytes(body, 1024)
        .await
        .expect_err("pending stream must hit the response deadline");
    assert!(error.to_string().contains("lifetime"));
    assert_eq!(stream_slots.available_permits(), 1);
    assert!(counts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn timed_out_started_stream_drops_its_producer_immediately() {
    struct DropMarker(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for DropMarker {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let marker = DropMarker(dropped.clone());
    let producer =
        futures_util::stream::once(async { Ok::<_, io::Error>(Bytes::from_static(b"started")) })
            .chain(
                futures_util::stream::pending::<io::Result<Bytes>>().map(move |item| {
                    let _keep_marker_alive = &marker;
                    item
                }),
            );
    let global = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = global.clone().try_acquire_owned().unwrap();
    let counts = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let peer = "192.0.2.10".parse().unwrap();
    let peer_permit = try_acquire_client_activity(counts, peer, 1).unwrap();
    let body = Body::new(StreamAdmissionBody {
        inner: Body::from_stream(producer),
        _permit: permit,
        _peer_permit: peer_permit,
        _public_permit: None,
        deadline: Box::pin(tokio::time::sleep(std::time::Duration::from_millis(10))),
        minimum_progress: MinimumProgress::with_intervals(
            1,
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        ),
        transferred_data_bytes: 0,
        operation: "download",
        public: true,
        complete: false,
    });
    let mut stream = body.into_data_stream();
    assert_eq!(stream.next().await.unwrap().unwrap().as_ref(), b"started");
    let error = stream
        .next()
        .await
        .expect("timeout frame")
        .expect_err("started stream must time out");
    assert!(error.to_string().contains("lifetime"));
    assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(global.available_permits(), 0);
    drop(stream);
    assert_eq!(global.available_permits(), 1);
}

#[test]
fn client_activity_limits_group_ipv6_prefixes_and_release_on_drop() {
    let counts = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let first = proxy::client_limit_key("2001:db8:1:2::1".parse().unwrap());
    let rotated = proxy::client_limit_key("2001:db8:1:2:ffff::99".parse().unwrap());
    let other_prefix = proxy::client_limit_key("2001:db8:1:3::1".parse().unwrap());
    assert_eq!(first, rotated);
    let permit = try_acquire_client_activity(counts.clone(), first, 1).unwrap();
    assert!(try_acquire_client_activity(counts.clone(), rotated, 1).is_none());
    let other = try_acquire_client_activity(counts.clone(), other_prefix, 1).unwrap();
    drop(permit);
    assert!(try_acquire_client_activity(counts, first, 1).is_some());
    drop(other);
}

#[test]
fn share_activity_limits_are_scoped_and_release_on_drop() {
    let counts = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let first = try_acquire_share_activity(counts.clone(), 7, 1).unwrap();
    assert!(try_acquire_share_activity(counts.clone(), 7, 1).is_none());
    let other = try_acquire_share_activity(counts.clone(), 8, 1).unwrap();
    drop(first);
    assert!(try_acquire_share_activity(counts, 7, 1).is_some());
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
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
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
        .uri("/api/v2/public/shares/missing/upload")
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
