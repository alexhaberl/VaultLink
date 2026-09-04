#[tokio::test]
async fn password_rotation_rejects_an_authorized_upload_before_its_file_field() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
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
        while state.upload_admission_available_for_test() != 31 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("upload should authorize before polling the file field");

    assert!(state
        .db()
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
    assert_eq!(state.db().active_upload_reservations(share_id).unwrap(), 0);
}

#[tokio::test]
async fn http_upload_enforces_limit_extension_conflict_and_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state_with_limit(root.path(), data.path(), 8);
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
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
        .db()
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
        .db()
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
    state.inject_upload_directory_sync_failure_for_test(std::io::ErrorKind::Other);
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
    state
        .secure_root()
        .fail_next_upload_publication_rename_after_success(std::io::ErrorKind::TimedOut);
    state
        .secure_root()
        .fail_next_upload_publication_identity_probes(std::io::ErrorKind::WouldBlock, 2);
    let response_loss = app
        .clone()
        .oneshot(multipart_request(
            "/v/upload/upload",
            "response-loss.txt",
            b"visible",
        ))
        .await
        .unwrap();
    assert_eq!(response_loss.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response_loss
            .headers()
            .get("x-vaultlink-durability")
            .unwrap(),
        "uncertain"
    );
    assert_eq!(
        std::fs::read(root.path().join("uploads/response-loss.txt")).unwrap(),
        b"visible"
    );

    state
        .secure_root()
        .fail_next_upload_publication_rename_after_success(std::io::ErrorKind::ConnectionReset);
    state
        .secure_root()
        .fail_next_upload_publication_identity_probes(std::io::ErrorKind::WouldBlock, 2);
    let replace_response_loss = app
        .clone()
        .oneshot(multipart_request_with_options(
            "/v/replace/upload",
            "ok.txt",
            b"updated",
            None,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(replace_response_loss.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        replace_response_loss
            .headers()
            .get("x-vaultlink-durability")
            .unwrap(),
        "uncertain"
    );
    assert_eq!(
        std::fs::read(root.path().join("uploads/ok.txt")).unwrap(),
        b"updated"
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
    assert!(!state.db().audit_priorities("upload").unwrap().is_empty());
    assert!(state
        .db()
        .audit_priorities("upload")
        .unwrap()
        .iter()
        .all(|priority| *priority == 100));
    assert_eq!(
        state.db().audit_priorities("upload_replaced").unwrap(),
        [100, 100]
    );
    assert_eq!(
        state
            .db()
            .audit_priorities("upload_durability_uncertain")
            .unwrap(),
        [100, 100, 100]
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
    state.replace_upload_admission_for_test(Arc::new(tokio::sync::Semaphore::new(1)));
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
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
    assert_eq!(state.db().active_upload_reservations(share_id).unwrap(), 0);
    assert!(state
        .db()
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
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
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
    assert_eq!(state.db().active_upload_reservations(share_id).unwrap(), 0);
    assert_eq!(
        state
            .db()
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
    state.replace_upload_admission_for_test(Arc::new(tokio::sync::Semaphore::new(1)));
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
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

    assert_eq!(state.upload_admission_available_for_test(), 0);
    assert_eq!(state.db().active_upload_reservations(share_id).unwrap(), 1);
    assert_eq!(upload_fragment_count(root.path()), 1);
    request.abort();
    let _ = request.await;

    wait_for_public_upload_cleanup(&state, root.path(), share_id).await;
    assert!(!root.path().join("uploads/cancelled.txt").exists());
    assert!(state
        .db()
        .list_audit(Some("upload"), 10, 0)
        .unwrap()
        .is_empty());
    drop(hook_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn public_upload_target_binding_is_detached_and_retains_admission_on_cancellation() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let mut state = test_state(root.path(), data.path());
    state.replace_upload_admission_for_test(Arc::new(tokio::sync::Semaphore::new(1)));
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
        .create_share(
            "cancel-target-binding",
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
    let hook = PublicUploadTestHook::blocking(
        "cancel-target-binding",
        PublicUploadTestPhase::TargetBinding,
    );
    let hook_guard = install_public_upload_test_hook(hook.clone());
    let watchdog_hook = hook.clone();
    let watchdog = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(1_500));
        watchdog_hook.release();
    });
    let app = router(state.clone());
    let request = tokio::spawn(async move {
        app.oneshot(multipart_request(
            "/v/cancel-target-binding/upload",
            "cancelled.txt",
            b"content",
        ))
        .await
        .unwrap()
    });
    let started = std::time::Instant::now();
    hook.wait_until_entered().await;

    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "descriptor binding must not block the single async runtime worker"
    );
    assert_eq!(state.upload_admission_available_for_test(), 0);
    assert_eq!(state.db().active_upload_reservations(share_id).unwrap(), 0);
    request.abort();
    let _ = request.await;
    tokio::task::yield_now().await;
    assert_eq!(
        state.upload_admission_available_for_test(),
        0,
        "the detached descriptor bind must retain admission after HTTP cancellation"
    );

    hook.release();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while state.upload_admission_available_for_test() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("target binding should release admission after the blocking task exits");
    assert_eq!(state.db().active_upload_reservations(share_id).unwrap(), 0);
    assert_eq!(upload_fragment_count(root.path()), 0);
    assert!(!root.path().join("uploads/cancelled.txt").exists());
    watchdog.join().unwrap();
    drop(hook_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_upload_target_binding_failure_releases_admission_without_staging() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let mut state = test_state(root.path(), data.path());
    state.replace_upload_admission_for_test(Arc::new(tokio::sync::Semaphore::new(1)));
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
        .create_share(
            "failed-target-binding",
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
        "failed-target-binding",
        PublicUploadTestPhase::TargetBinding,
        io::ErrorKind::NotFound,
    );
    let hook_guard = install_public_upload_test_hook(hook.clone());
    let response = router(state.clone())
        .oneshot(multipart_request(
            "/v/failed-target-binding/upload",
            "never.txt",
            b"content",
        ))
        .await
        .unwrap();
    hook.wait_until_entered().await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(state.upload_admission_available_for_test(), 1);
    assert_eq!(state.db().active_upload_reservations(share_id).unwrap(), 0);
    assert_eq!(upload_fragment_count(root.path()), 0);
    assert!(!root.path().join("uploads/never.txt").exists());
    drop(hook_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_upload_cancellation_after_finalizer_handoff_does_not_abort_publish() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let mut state = test_state(root.path(), data.path());
    state.replace_upload_admission_for_test(Arc::new(tokio::sync::Semaphore::new(1)));
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
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
    assert_eq!(state.upload_admission_available_for_test(), 0);
    assert_eq!(state.db().active_upload_reservations(share_id).unwrap(), 1);
    assert_eq!(upload_fragment_count(root.path()), 1);

    hook.release();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if state.upload_admission_available_for_test() == 1
                && state.db().active_upload_reservations(share_id).unwrap() == 0
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
    assert_eq!(
        state.db().list_audit(Some("upload"), 10, 0).unwrap().len(),
        1
    );
    drop(hook_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_upload_staging_io_failure_cleans_fragment_and_quota() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let mut state = test_state(root.path(), data.path());
    state.replace_upload_admission_for_test(Arc::new(tokio::sync::Semaphore::new(1)));
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
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
        .db()
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
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "policy-session",
            1,
            "policy-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("policy-session").unwrap();
    let share_id = state
        .db()
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
    let hook = PublicUploadTestHook::blocking("policy-first", PublicUploadTestPhase::Finalizer);
    let hook_guard = install_public_upload_test_hook(hook.clone());
    let app = router(state.clone());
    let (upload, sender) =
        controlled_multipart_request("/v/policy-first/upload", "existing.txt", b"new", true);
    let upload_app = app.clone();
    let upload = tokio::spawn(async move { upload_app.oneshot(upload).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;
    finish_controlled_multipart(sender).await;
    hook.wait_until_entered().await;

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
    hook.release();

    let upload = upload.await.unwrap();
    assert_eq!(upload.status(), StatusCode::CONFLICT);
    assert_eq!(
        std::fs::read(root.path().join("uploads/existing.txt")).unwrap(),
        b"old"
    );
    assert_eq!(state.db().active_upload_reservations(share_id).unwrap(), 0);
    let share = state.db().share_by_token("policy-first").unwrap().unwrap();
    assert_eq!(
        share.upload_conflict_strategy,
        UploadConflictStrategy::Reject
    );
    assert_eq!(share.uploaded_bytes, 0);
    assert_eq!(share.uploaded_files, 0);
    drop(hook_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_upload_publish_wins_before_a_waiting_policy_change() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    std::fs::write(root.path().join("uploads/existing.txt"), b"old").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "policy-session",
            1,
            "policy-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("policy-session").unwrap();
    let share_id = state
        .db()
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
    assert_eq!(state.db().active_upload_reservations(share_id).unwrap(), 0);
    let share = state.db().share_by_token("upload-first").unwrap().unwrap();
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
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "html-policy-session",
            1,
            "html-policy-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("html-policy-session").unwrap();
    let share_id = state
        .db()
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
    let hook =
        PublicUploadTestHook::blocking("html-policy-first", PublicUploadTestPhase::Finalizer);
    let hook_guard = install_public_upload_test_hook(hook.clone());
    let app = router(state.clone());
    let (upload, sender) =
        controlled_multipart_request("/v/html-policy-first/upload", "existing.txt", b"new", true);
    let upload_app = app.clone();
    let upload = tokio::spawn(async move { upload_app.oneshot(upload).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;
    finish_controlled_multipart(sender).await;
    hook.wait_until_entered().await;

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
    hook.release();

    let upload = upload.await.unwrap();
    assert_eq!(upload.status(), StatusCode::CONFLICT);
    assert_eq!(
        std::fs::read(root.path().join("uploads/existing.txt")).unwrap(),
        b"old"
    );
    assert_eq!(state.db().active_upload_reservations(share_id).unwrap(), 0);
    let share = state
        .db()
        .share_by_token("html-policy-first")
        .unwrap()
        .unwrap();
    assert_eq!(
        share.upload_conflict_strategy,
        UploadConflictStrategy::Reject
    );
    assert_eq!(share.uploaded_bytes, 0);
    assert_eq!(share.uploaded_files, 0);
    drop(hook_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_upload_publish_wins_before_a_waiting_html_policy_change() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    std::fs::write(root.path().join("uploads/existing.txt"), b"old").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "html-upload-session",
            1,
            "html-upload-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("html-upload-session").unwrap();
    let share_id = state
        .db()
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
    assert_eq!(state.db().active_upload_reservations(share_id).unwrap(), 0);
    let share = state
        .db()
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
