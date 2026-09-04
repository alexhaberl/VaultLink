fn active_expensive_peer_operations(state: &AppState) -> usize {
    state.expensive_peer_admission_count_for_test()
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
            if state.zip_generation_admission_available_for_test() == 1
                && active_expensive_peer_operations(state) == 0
                && state.db().active_transfer_reservations(share_id).unwrap() == 0
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
    assert_eq!(state.zip_generation_admission_available_for_test(), 1);
    assert_eq!(active_expensive_peer_operations(state), 0);
    assert_eq!(state.db().active_transfer_reservations(share_id).unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_zip_plan_retains_permits_and_lease_until_blocking_work_finishes() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let share_path = "zip-plan-cancellation-docs";
    std::fs::create_dir(root.path().join(share_path)).unwrap();
    std::fs::write(root.path().join(share_path).join("note.txt"), b"note").unwrap();
    let mut state = test_state(root.path(), data.path());
    state.replace_zip_generation_admission_for_test(Arc::new(tokio::sync::Semaphore::new(1)));
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
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

    assert_eq!(state.zip_generation_admission_available_for_test(), 0);
    assert_eq!(active_expensive_peer_operations(&state), 1);
    assert_eq!(state.db().active_transfer_reservations(share_id).unwrap(), 1);
    request.abort();
    let _ = request.await;
    tokio::task::yield_now().await;
    assert_eq!(state.zip_generation_admission_available_for_test(), 0);
    assert_eq!(active_expensive_peer_operations(&state), 1);
    assert_eq!(state.db().active_transfer_reservations(share_id).unwrap(), 1);

    hook.release();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if state.zip_generation_admission_available_for_test() == 1
                && active_expensive_peer_operations(&state) == 0
                && state.db().active_transfer_reservations(share_id).unwrap() == 0
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
            .db()
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
    state.replace_zip_generation_admission_for_test(Arc::new(tokio::sync::Semaphore::new(1)));
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
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
    assert_eq!(state.zip_generation_admission_available_for_test(), 0);
    assert_eq!(active_expensive_peer_operations(&state), 1);
    assert_eq!(state.db().active_transfer_reservations(share_id).unwrap(), 1);

    hook.release();
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), request)
        .await
        .expect("panicking ZIP task should join")
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    wait_for_zip_resources_released(&state, share_id).await;
    assert_eq!(
        state
            .db()
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
    state.replace_zip_generation_admission_for_test(Arc::new(tokio::sync::Semaphore::new(1)));
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
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
    assert_eq!(state.zip_generation_admission_available_for_test(), 0);
    assert_eq!(active_expensive_peer_operations(&state), 1);
    assert_eq!(state.db().active_transfer_reservations(share_id).unwrap(), 1);

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
            .db()
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
    state.replace_zip_generation_admission_for_test(Arc::new(tokio::sync::Semaphore::new(1)));
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
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
    assert_eq!(state.zip_generation_admission_available_for_test(), 0);
    assert_eq!(active_expensive_peer_operations(&state), 1);
    assert_eq!(state.db().active_transfer_reservations(share_id).unwrap(), 1);

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
            .db()
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
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
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
        &state.secure_root().bind_directory(share_path).unwrap(),
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
        state.zip_generation_admission_available_for_test(),
        crate::MAX_CONCURRENT_ZIP_GENERATIONS - 1
    );
    assert!(zip_temp_reserved_bytes_for_test() >= expected_temp_reservation);
    assert_eq!(state.db().active_transfer_reservations(share_id).unwrap(), 1);

    request.abort();
    let _ = request.await;
    tokio::task::yield_now().await;
    assert_eq!(
        state.zip_generation_admission_available_for_test(),
        crate::MAX_CONCURRENT_ZIP_GENERATIONS - 1,
        "request cancellation released ZIP capacity around live blocking work"
    );
    assert!(
        zip_temp_reserved_bytes_for_test() >= expected_temp_reservation,
        "request cancellation released the temp budget around live materialization"
    );
    assert_eq!(state.db().active_transfer_reservations(share_id).unwrap(), 1);

    hook.release();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if state.zip_generation_admission_available_for_test()
                == crate::MAX_CONCURRENT_ZIP_GENERATIONS
                && state.db().active_transfer_reservations(share_id).unwrap() == 0
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
    state.replace_zip_generation_admission_for_test(Arc::new(tokio::sync::Semaphore::new(1)));
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
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
    assert_eq!(state.zip_generation_admission_available_for_test(), 0);
    assert_eq!(active_expensive_peer_operations(&state), 1);
    assert_eq!(state.db().active_transfer_reservations(share_id).unwrap(), 1);

    drop(response);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while state.db().active_transfer_reservations(share_id).unwrap() != 0 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("dropping the direct ZIP body should cancel its lease once");
    assert_eq!(state.zip_generation_admission_available_for_test(), 0);
    assert_eq!(active_expensive_peer_operations(&state), 1);
    assert_eq!(
        state
            .db()
            .share_by_token("zip-direct-cancellation")
            .unwrap()
            .unwrap()
            .download_count,
        0
    );

    hook.release();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if state.zip_generation_admission_available_for_test() == 1
                && active_expensive_peer_operations(&state) == 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("direct ZIP permits should outlive the cancelled body but not the producer");
    assert_eq!(state.db().active_transfer_reservations(share_id).unwrap(), 0);
    assert_eq!(
        state
            .db()
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
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
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
    let _zip_permits = state.try_acquire_all_zip_generation_for_test();
    let _search_permits = state.try_acquire_all_search_for_test();
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
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let du_id = state
        .db()
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
        .db()
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
        .db()
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
    assert_eq!(
        state
            .db()
            .audit_priorities("upload_directories_created")
            .unwrap(),
        [100]
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
        .db()
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
            .db()
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
    assert_eq!(head_image.status(), StatusCode::GONE);
    let bad_range = app
        .clone()
        .oneshot(range_request(
            Method::GET,
            &raw_image_uri,
            Some("bytes=999-1000"),
        ))
        .await
        .unwrap();
    assert_eq!(bad_range.status(), StatusCode::GONE);
    assert_eq!(
        app.clone()
            .oneshot(request(Method::GET, "/v/media/preview?path=image.png", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::GONE
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
        .db()
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
