#[tokio::test]
async fn share_creation_page_uses_browser_selected_path() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file.txt"), b"file").unwrap();
    std::fs::write(root.path().join("B.txt"), b"second").unwrap();
    std::fs::write(root.path().join("A.txt"), b"first").unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.mutate_runtime_for_test(|runtime| runtime.max_upload_size = 120_000_000_001);
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "session-token",
            1,
            "csrf-token",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("session-token").unwrap();
    let app = router(state.clone());
    let cookie = HeaderValue::from_static("vaultlink_locale=de; vaultlink_session=session-token");

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
    let shares = state.db().list_shares().unwrap();
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
        HeaderValue::from_static("vaultlink_locale=de; vaultlink_session=session-token"),
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
        .db()
        .list_shares()
        .unwrap()
        .into_iter()
        .find(|share| share.id == edited_share_id)
        .unwrap();
    assert_eq!(edited_share.max_upload_total_size, Some(125_500_000_000));
    assert_eq!(edited_share.max_upload_files, Some(900));

    state
        .db()
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
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "session-token",
            1,
            "csrf-token",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("session-token").unwrap();
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
    let shares = state.db().list_shares().unwrap();
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
    assert_eq!(state.db().list_shares().unwrap().len(), 1);
}

#[tokio::test]
async fn web_hashes_share_password_before_waiting_for_storage_mutation() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("documents")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "session-token",
            1,
            "csrf-token",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("session-token").unwrap();
    let app = router(state.clone());
    let _storage_mutation_gate = state.block_storage_mutations_for_test().await;
    let _argon2_capacity = state.acquire_all_argon2_for_test().await;
    let mut create = request(
        Method::POST,
        "/admin/shares",
        "csrf=csrf-token&path=documents&permission=download_only&password_enabled=1&password=very+strong+share+password&password_confirm=very+strong+share+password",
    );
    create.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=session-token"),
    );

    let response = tokio::time::timeout(std::time::Duration::from_secs(1), app.oneshot(create))
        .await
        .expect("Argon2 admission must run before the held storage lock")
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(state.db().list_shares().unwrap().is_empty());
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
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
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
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let _share_id = state
        .db()
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
        .db()
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
        .db()
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
        .db()
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
        .db()
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
        .db()
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
    assert!(state.db().count_download(exhausted_zip_id).unwrap());
    state.mutate_runtime_for_test(|runtime| runtime.max_search_entries = 1);
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
            .db()
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
            .db()
            .active_transfer_reservations(failing_zip_id)
            .unwrap(),
        0
    );
    assert_eq!(
        state
            .db()
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
            .db()
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
            .db()
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
            .db()
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
            .db()
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
            .db()
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
            .db()
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
        if state.db().active_transfer_reservations(aborted_id).unwrap() == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    assert_eq!(
        state.db().active_transfer_reservations(aborted_id).unwrap(),
        0
    );
    assert_eq!(
        state
            .db()
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
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
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
            .db()
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
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let password_hash = auth::hash_password("share password 123").unwrap();
    state
        .db()
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

    let _storage_guard = state.acquire_storage_test_exclusive().await;
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
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
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
    state.mutate_runtime_for_test(|runtime| runtime.audit_client_ip_enabled = true);
    let response = router(state.clone())
        .oneshot(multipart_request(
            "/v/audit-upload/upload",
            "audit.txt",
            b"content",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let events = state.db().list_audit(Some("upload"), 10, 0).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].client_ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(state.db().audit_priorities("upload").unwrap(), [100]);
}

#[tokio::test]
async fn http_share_permissions_password_unlock_and_range() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file.txt"), b"0123456789").unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
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
    let password_hash = auth::hash_password("share password 123").unwrap();
    state
        .db()
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
