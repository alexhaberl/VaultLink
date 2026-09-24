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
    let (upload, sender) = controlled_multipart_request(
        &state,
        "/v/html-upload-first/upload",
        "existing.txt",
        b"new",
        true,
    );
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
#[tokio::test]
async fn public_upload_operation_replays_receipt_without_republishing() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share(
            "idempotent-upload",
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
    let creation = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v/idempotent-upload/upload/operations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(creation.status(), StatusCode::CREATED);
    let ticket: serde_json::Value = serde_json::from_str(&response_text(creation).await).unwrap();
    let id = ticket["upload_id"].as_str().unwrap();
    let status_url = ticket["status_url"].as_str().unwrap();
    let mut first = multipart_request(
        &state,
        "/v/idempotent-upload/upload/queue",
        "once.txt",
        b"first",
    );
    first
        .headers_mut()
        .insert("idempotency-key", id.parse().unwrap());
    let first_result = app.clone().oneshot(first).await.unwrap();
    assert_eq!(first_result.status(), StatusCode::OK);
    assert!(response_text(first_result)
        .await
        .contains("\"outcome\":\"created\""));
    let status = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(status_url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    let status: serde_json::Value = serde_json::from_str(&response_text(status).await).unwrap();
    assert_eq!(status["state"], "completed");
    assert!(status["result"].get("warnings").is_none());
    std::fs::remove_file(root.path().join("uploads/once.txt")).unwrap();
    let mut replay = multipart_request(
        &state,
        "/v/idempotent-upload/upload/queue",
        "once.txt",
        b"first",
    );
    replay
        .headers_mut()
        .insert("idempotency-key", id.parse().unwrap());
    let replay_result = app.clone().oneshot(replay).await.unwrap();
    assert_eq!(replay_result.status(), StatusCode::OK);
    assert!(!root.path().join("uploads/once.txt").exists());
    let mut conflict = multipart_request(
        &state,
        "/v/idempotent-upload/upload/queue",
        "once.txt",
        b"other",
    );
    conflict
        .headers_mut()
        .insert("idempotency-key", id.parse().unwrap());
    let conflict_result = app.clone().oneshot(conflict).await.unwrap();
    assert_eq!(conflict_result.status(), StatusCode::CONFLICT);
    assert!(response_text(conflict_result)
        .await
        .contains("upload_id_conflict"));
    let share = state
        .db()
        .share_by_token("idempotent-upload")
        .unwrap()
        .unwrap();
    assert_eq!((share.uploaded_bytes, share.uploaded_files), (5, 1));
    assert_eq!(state.db().count_audit(Some("upload")).unwrap(), 1);
    let quota_charged: i64 = rusqlite::Connection::open(data.path().join("data.sqlite"))
        .unwrap()
        .query_row(
            "SELECT quota_charged FROM upload_operations WHERE id_hash=?1",
            [crate::db::token_hash(id)],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(quota_charged, 1);

    let creation = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v/idempotent-upload/upload/operations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let ticket: serde_json::Value = serde_json::from_str(&response_text(creation).await).unwrap();
    let second_id = ticket["upload_id"].as_str().unwrap();
    let make_prefixed_request = || {
        let boundary = "prefixed-upload-id";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"upload_id\"\r\n\r\n{second_id}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"prefixed.txt\"\r\n\r\nbytes\r\n--{boundary}--\r\n"
        );
        Request::builder()
            .method(Method::POST)
            .uri("/v/idempotent-upload/upload/queue")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap()
    };
    assert_eq!(
        app.clone()
            .oneshot(make_prefixed_request())
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(make_prefixed_request())
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        std::fs::read(root.path().join("uploads/prefixed.txt")).unwrap(),
        b"bytes"
    );

    let mismatch_boundary = "mismatched-upload-id";
    let mismatch_body = format!(
        "--{mismatch_boundary}\r\nContent-Disposition: form-data; name=\"upload_id\"\r\n\r\n{second_id}\r\n--{mismatch_boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"once.txt\"\r\n\r\nfirst\r\n--{mismatch_boundary}--\r\n"
    );
    let mismatch = Request::builder()
        .method(Method::POST)
        .uri("/v/idempotent-upload/upload/queue")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={mismatch_boundary}"),
        )
        .header("idempotency-key", id)
        .body(Body::from(mismatch_body))
        .unwrap();
    let mismatch_result = app.clone().oneshot(mismatch).await.unwrap();
    assert_eq!(mismatch_result.status(), StatusCode::BAD_REQUEST);

    let creation = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v/idempotent-upload/upload/operations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let ticket: serde_json::Value = serde_json::from_str(&response_text(creation).await).unwrap();
    let third_id = ticket["upload_id"].as_str().unwrap();
    let share = state
        .db()
        .share_by_token("idempotent-upload")
        .unwrap()
        .unwrap();
    assert!(matches!(
        state
            .db()
            .claim_upload_operation(crate::db::UploadOperationScope::Share(share.id), third_id)
            .unwrap(),
        crate::db::UploadOperationClaim::Started
    ));
    let boundary = "parallel-upload-id";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"upload_id\"\r\n\r\n{third_id}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"parallel.txt\"\r\n\r\nparallel\r\n--{boundary}--\r\n"
    );
    let make_request = || {
        Request::builder()
            .method(Method::POST)
            .uri("/v/idempotent-upload/upload/queue")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body.clone()))
            .unwrap()
    };
    let busy = app.clone().oneshot(make_request()).await.unwrap();
    assert_eq!(busy.status(), StatusCode::CONFLICT);
    assert_eq!(busy.headers()[header::RETRY_AFTER], "1");
    let busy_body = response_text(busy).await;
    assert!(busy_body.contains("upload_in_progress"));
    assert!(busy_body.contains(&format!(
        "/v/idempotent-upload/upload/operations/{third_id}"
    )));
    state
        .db()
        .release_upload_operation(&crate::db::token_hash(third_id))
        .unwrap();
    assert_eq!(
        app.oneshot(make_request()).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        std::fs::read(root.path().join("uploads/parallel.txt")).unwrap(),
        b"parallel"
    );
}
