#[tokio::test]
async fn protected_public_upload_binds_csrf_and_enforces_persistent_quota() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let password_hash = auth::hash_password("correct horse battery staple").unwrap();
    let share_id = state
        .db()
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
    assert_eq!(state.db().active_upload_reservations(share_id).unwrap(), 0);
    let share = state
        .db()
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
        .db()
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
    assert_eq!(state.db().active_upload_reservations(share_id).unwrap(), 0);

    let mut over_quota = folder_upload_request(
        "/v/protected-upload/upload",
        "",
        Some(&upload_csrf),
        "unaccounted/directories",
        "too-large.txt",
        b"56",
    );
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
        if state.db().active_upload_reservations(share_id).unwrap() == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    let share = state
        .db()
        .share_by_token("protected-upload")
        .unwrap()
        .unwrap();
    assert_eq!((share.uploaded_bytes, share.uploaded_files), (4, 1));
    assert_eq!(state.db().active_upload_reservations(share_id).unwrap(), 0);
    assert!(!root.path().join("uploads/unaccounted").exists());

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
        .db()
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
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "external-admin-session",
            1,
            "external-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("external-admin-session").unwrap();
    state
        .db()
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
    let mut config = state.config().clone();
    config.storage.external_writers = true;
    state.replace_config_for_test(config);
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
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "external-replace-admin-session",
            1,
            "external-replace-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state
        .db()
        .verify_mfa("external-replace-admin-session")
        .unwrap();
    state
        .db()
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
    let mut config = state.config().clone();
    config.storage.external_writers = true;
    config.storage.allow_external_writer_replace = true;
    state.replace_config_for_test(config);
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
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
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
            "/api/v2/public/shares/large-upload/upload",
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
        .starts_with("/api/v2/public/shares/large-upload"));
    assert_eq!(
        std::fs::metadata(root.path().join("uploads/large.bin"))
            .unwrap()
            .len(),
        content.len() as u64
    );
}
