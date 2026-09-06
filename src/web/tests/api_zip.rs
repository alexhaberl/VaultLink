#[tokio::test]
async fn api_zip_archive_headers_authorization_and_capacity() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    std::fs::write(root.path().join("docs/note.txt"), b"note").unwrap();
    let mut state = test_state(root.path(), data.path());
    state.replace_zip_generation_admission_for_test(Arc::new(tokio::sync::Semaphore::new(1)));
    state.db().create_admin("admin", "hash", "secret").unwrap();
    for (token, permission, password, directory) in [
        ("api-zip", Permission::DownloadOnly, None, true),
        ("api-locked", Permission::DownloadOnly, Some("hash"), true),
        ("api-upload", Permission::UploadOnly, None, true),
        ("api-file", Permission::DownloadOnly, None, false),
    ] {
        state
            .db()
            .create_share(
                token,
                None,
                if directory { "docs" } else { "docs/note.txt" },
                directory,
                &permission,
                None,
                None,
                None,
                1,
                password,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
    }
    let app = router(state.clone());
    for (token, status) in [
        ("api-locked", StatusCode::UNAUTHORIZED),
        ("api-upload", StatusCode::FORBIDDEN),
        ("api-file", StatusCode::FORBIDDEN),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(request(Method::GET, &ZipTestRoute::Api.uri(token), ""))
                .await
                .unwrap()
                .status(),
            status
        );
    }
    let uri = ZipTestRoute::Api.uri("api-zip");
    let response = app
        .clone()
        .oneshot(request(Method::GET, &uri, ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/zip");
    assert!(response.headers()[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .contains("docs%2Ezip"));
    let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.contains("Path=/api/v2/public/shares/api-zip;"));
    assert!(cookie.contains("HttpOnly; SameSite=Strict;"));
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(&bytes[..4], b"PK\x03\x04");
    assert!(bytes.windows(8).any(|part| part == b"note.txt"));
    assert!(bytes.windows(4).any(|part| part == b"note"));
    let share = state.db().share_by_token("api-zip").unwrap().unwrap();
    assert_eq!(share.download_count, 1);
    wait_for_zip_resources_released(&state, share.id).await;
    let occupied = state.try_acquire_zip_generation().unwrap();
    let response = app
        .clone()
        .oneshot(request(Method::GET, &uri, ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::RETRY_AFTER], "1");
    drop(occupied);
    state.mutate_runtime_for_test(|runtime| runtime.max_zip_size = 1);
    assert_eq!(
        app.oneshot(request(Method::GET, &uri, ""))
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    wait_for_zip_resources_released(&state, share.id).await;
}
