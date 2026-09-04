#[tokio::test]
async fn api_file_search_filters_before_pagination() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    for index in 0..180 {
        std::fs::write(root.path().join(format!("ordinary-{index:03}.txt")), "x").unwrap();
    }
    std::fs::write(root.path().join("only-late-match.txt"), "match").unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, _) = api_login(&state, &secret).await;
    let app = crate::web::router(state.clone());
    let mut request = json_request(Method::GET, "/api/v2/files?path=&q=only-late-match", "");
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("only-late-match.txt"), "{body}");
    assert!(body.contains(r#""truncated":false"#));
    assert!(body.contains(r#""has_next":false"#));

    let too_long = "x".repeat(MAX_SEARCH_QUERY_BYTES + 1);
    let mut request = json_request(
        Method::GET,
        &format!("/api/v2/files?path=&q={too_long}"),
        "",
    );
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    let all_searches = state.try_acquire_all_search_for_test();
    let mut request = json_request(Method::GET, "/api/v2/files?path=", "");
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::OK
    );
    let mut request = json_request(Method::GET, "/api/v2/files?path=&q=ordinary", "");
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop(all_searches);

    let peer = "127.0.0.1".parse().unwrap();
    let peer_permits = (0..crate::MAX_EXPENSIVE_OPERATIONS_PER_CLIENT)
        .map(|_| {
            state.try_acquire_expensive_peer(peer).unwrap()
        })
        .collect::<Vec<_>>();
    let mut request = json_request(Method::GET, "/api/v2/files?path=", "");
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::OK
    );
    let mut request = json_request(Method::GET, "/api/v2/files?path=&q=ordinary", "");
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    assert_eq!(
        app.oneshot(request).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop(peer_permits);
}

#[test]
fn api_file_pages_count_filtered_raw_directory_items() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    for _ in 0..2 {
        std::fs::write(
            root.path().join(crate::secure_fs::upload_fragment_name()),
            b"partial",
        )
        .unwrap();
    }
    let state = test_state(root.path(), data.path());
    let (entries, truncated) = list_file_page(state.secure_root(), "", 0, None, 1).unwrap();
    assert!(entries.is_empty());
    assert!(truncated);
    let (entries, truncated) =
        list_file_page(state.secure_root(), "", 0, Some("missing"), 1).unwrap();
    assert!(entries.is_empty());
    assert!(truncated);
}

#[tokio::test]
async fn api_unlock_cookie_authorizes_followup_api_download() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("secret.txt"), "protected content").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let password_hash = auth::hash_password("very strong share password").unwrap();
    state
        .db()
        .create_share(
            "protected-token",
            None,
            "secret.txt",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            Some(&password_hash),
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let app = crate::web::router(state.clone());
    let locked_metadata = app
        .clone()
        .oneshot(json_request(
            Method::GET,
            "/api/v2/public/shares/protected-token",
            "",
        ))
        .await
        .unwrap();
    assert_eq!(locked_metadata.status(), StatusCode::OK);
    assert_eq!(response_text(locked_metadata).await, r#"{"locked":true}"#);
    let unlock = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/v2/public/shares/protected-token/unlock",
            r#"{"password":"very strong share password"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(unlock.status(), StatusCode::OK);
    let set_cookie = unlock
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.contains("Path=/api/v2/public/shares/protected-token"));
    let unlock_cookie = set_cookie.split(';').next().unwrap().to_string();

    let mut download = json_request(
        Method::GET,
        "/api/v2/public/shares/protected-token/download",
        "",
    );
    download.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&unlock_cookie).unwrap(),
    );
    let download = app.clone().oneshot(download).await.unwrap();
    assert_eq!(download.status(), StatusCode::OK);
    assert!(download
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|value| value
            .to_str()
            .unwrap()
            .contains("Path=/api/v2/public/shares/protected-token")));
    assert_eq!(response_text(download).await, "protected content");
    for _ in 0..100 {
        if state
            .db()
            .share_by_token("protected-token")
            .unwrap()
            .unwrap()
            .download_count
            == 1
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    let mut metadata_request =
        json_request(Method::GET, "/api/v2/public/shares/protected-token", "");
    metadata_request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&unlock_cookie).unwrap(),
    );
    let metadata = app.oneshot(metadata_request).await.unwrap();
    assert_eq!(metadata.status(), StatusCode::GONE);
}

#[tokio::test]
async fn api_media_preview_keeps_unlock_and_raw_routes_api_scoped() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("protected")).unwrap();
    std::fs::write(root.path().join("protected/image.png"), b"\x89PNG").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let password_hash = auth::hash_password("very strong share password").unwrap();
    state
        .db()
        .create_share(
            "media-token",
            None,
            "protected",
            true,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            Some(&password_hash),
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let app = crate::web::router(state.clone());
    let unlock = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/v2/public/shares/media-token/unlock",
            r#"{"password":"very strong share password"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(unlock.status(), StatusCode::OK);
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

    let mut preview = json_request(
        Method::GET,
        "/api/v2/public/shares/media-token/preview?path=image.png",
        "",
    );
    preview.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&unlock_cookie).unwrap(),
    );
    let preview = app.clone().oneshot(preview).await.unwrap();
    assert_eq!(preview.status(), StatusCode::OK);
    let preview = response_text(preview).await;
    assert!(preview.contains("/api/v2/public/shares/media-token/preview/raw?path=image%2Epng"));
    assert!(preview.contains("href=\"/api/v2/public/shares/media-token\""));
    assert!(!preview.contains("/v/media-token/preview/raw"));
    assert!(!preview.contains("href=\"/v/media-token\""));
    let token_start = preview.find("preview_token=").unwrap() + "preview_token=".len();
    let preview_token = preview[token_start..]
        .chars()
        .take_while(|character| *character != '"' && *character != '&')
        .collect::<String>();

    let mut raw = json_request(
            Method::GET,
            &format!(
                "/api/v2/public/shares/media-token/preview/raw?path=image.png&preview_token={preview_token}"
            ),
            "",
        );
    raw.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&unlock_cookie).unwrap(),
    );
    let raw = app.oneshot(raw).await.unwrap();
    assert_eq!(raw.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(raw.into_body(), usize::MAX)
            .await
            .unwrap()
            .as_ref(),
        b"\x89PNG"
    );
    assert_eq!(
        state
            .db()
            .share_by_token("media-token")
            .unwrap()
            .unwrap()
            .download_count,
        1
    );
}

#[tokio::test]
async fn api_reports_active_upload_reservations_as_quota_conflict() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let share_id = state
        .db()
        .create_share_with_upload_limits(
            "quota-conflict",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            Some(5),
            Some(20),
            Some(3),
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    for token in ["active-one", "active-two"] {
        assert_eq!(
            state
                .db()
                .begin_upload_reservation(token, share_id, 0)
                .unwrap(),
            crate::db::UploadReservationBeginOutcome::Reserved
        );
        assert_eq!(
            state.db().extend_upload_reservation(token, 5).unwrap(),
            crate::db::UploadReservationExtendOutcome::Extended
        );
    }
    let app = crate::web::router(state.clone());
    let mut update = json_request(
        Method::PATCH,
        &format!("/api/v2/shares/{share_id}"),
        r#"{"upload_conflict_strategy":"overwrite_allowed","max_upload_total_size":5,"max_upload_files":1}"#,
    );
    authorize_mutation(&mut update, &session_cookie, &csrf);
    let response = app.oneshot(update).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(response_text(response)
        .await
        .contains(r#""code":"upload_quota_in_use""#));
    let share = state.db().share_by_token("quota-conflict").unwrap().unwrap();
    assert_eq!(
        share.upload_conflict_strategy,
        UploadConflictStrategy::Reject
    );
    assert_eq!(share.max_upload_total_size, Some(20));
    assert_eq!(share.max_upload_files, Some(3));
}

#[tokio::test]
async fn api_admin_file_mutations_update_shares_and_require_tree_confirmation() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    std::fs::write(root.path().join("docs/file.txt"), b"content").unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    state
        .db()
        .create_share(
            "file-token",
            None,
            "docs/file.txt",
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
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let app = crate::web::router(state.clone());

    let mut create = json_request(
        Method::POST,
        "/api/v2/files/directories",
        r#"{"parent":"","name":"tree"}"#,
    );
    authorize_mutation(&mut create, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(create).await.unwrap().status(),
        StatusCode::CREATED
    );

    let mut rename = json_request(
        Method::PATCH,
        "/api/v2/files",
        r#"{"path":"docs/file.txt","name":"final.txt"}"#,
    );
    authorize_mutation(&mut rename, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(rename).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        state
            .db()
            .share_by_token("file-token")
            .unwrap()
            .unwrap()
            .relative_path,
        "docs/final.txt"
    );

    std::fs::write(root.path().join("tree/child.txt"), b"child").unwrap();
    state
        .db()
        .create_share(
            "tree-token",
            None,
            "tree/child.txt",
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
    let mut unconfirmed = json_request(Method::DELETE, "/api/v2/files", r#"{"path":"tree"}"#);
    authorize_mutation(&mut unconfirmed, &session_cookie, &csrf);
    let unconfirmed = app.clone().oneshot(unconfirmed).await.unwrap();
    assert_eq!(unconfirmed.status(), StatusCode::CONFLICT);
    assert!(response_text(unconfirmed)
        .await
        .contains("confirmation_required"));
    assert!(root.path().join("tree").exists());

    let cleanup_guard = state
        .storage_cleanup()
        .serialization_for_test()
        .lock_owned()
        .await;
    let cleanup_worker = state.start_storage_cleanup_worker().unwrap();
    let mut confirmed = json_request(
        Method::DELETE,
        "/api/v2/files",
        r#"{"path":"tree","confirm_name":"tree"}"#,
    );
    authorize_mutation(&mut confirmed, &session_cookie, &csrf);
    assert_eq!(
        app.oneshot(confirmed).await.unwrap().status(),
        StatusCode::ACCEPTED
    );
    assert!(!root.path().join("tree").exists());
    let tombstone_exists = || {
        std::fs::read_dir(
            root.path()
                .join(crate::path_security::INTERNAL_STORAGE_DIRECTORY_NAME)
                .join("tombstones"),
        )
        .unwrap()
        .any(|entry| crate::secure_fs::is_deletion_tombstone_name(&entry.unwrap().file_name()))
    };
    assert!(tombstone_exists());
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    assert!(tombstone_exists());
    drop(cleanup_guard);
    for _ in 0..100 {
        if !tombstone_exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(!tombstone_exists());
    assert!(
        !state
            .db()
            .share_by_token("tree-token")
            .unwrap()
            .unwrap()
            .active
    );
    cleanup_worker.shutdown().await.unwrap();
}

fn authorize_mutation(request: &mut Request<Body>, session_cookie: &str, csrf: &str) {
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(session_cookie).unwrap(),
    );
    request
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(csrf).unwrap());
}
