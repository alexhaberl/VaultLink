#[test]
fn share_mutation_response_snapshots_are_db_owned_required_audit_outputs() {
    let database = crate::db::Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    database
        .create_session(
            "snapshot-session",
            1,
            "csrf",
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .unwrap();
    assert!(database.verify_mfa("snapshot-session").unwrap());

    let proof = crate::db::MfaSessionProof::for_test("snapshot-session", 1);
    let create_context = crate::db::AuditContext::new("admin", None);
    let created: crate::db::SessionBound<(i64, crate::db::Share)> =
        crate::db::required_session_audit_job(move |database| {
            database.create_share_with_upload_limits_for_mfa_session(
                &proof,
                "snapshot-token",
                Some("snapshot-alias"),
                "snapshot.txt",
                false,
                &crate::db::Permission::DownloadOnly,
                None,
                None,
                None,
                None,
                None,
                None,
                &crate::db::UploadConflictStrategy::Reject,
                &create_context,
                Some("response snapshot contract".into()),
            )
        })(database.clone())
        .unwrap();
    let (share_id, created_share) = match created {
        crate::db::SessionBound::Authorized(snapshot) => snapshot,
        crate::db::SessionBound::SessionUnavailable => panic!("verified session was rejected"),
    };
    assert_eq!(created_share.id, share_id);
    assert_eq!(created_share.token, "snapshot-token");

    let proof = crate::db::MfaSessionProof::for_test("snapshot-session", 1);
    let update_context = crate::db::AuditContext::new("admin", None);
    let events = vec![crate::db::RequiredAuditEvent::new(
        crate::db::AuditAction::ShareDeactivated,
        Some(share_id.to_string()),
        None,
    )];
    let updated: crate::db::SessionBound<(
        crate::db::ShareControlsUpdateOutcome,
        Option<crate::db::Share>,
    )> = crate::db::required_session_audit_job(move |database| {
        database.update_share_controls_for_mfa_session(
            &proof,
            share_id,
            Some(false),
            None,
            None,
            &update_context,
            &events,
        )
    })(database)
    .unwrap();
    let (outcome, updated_share) = match updated {
        crate::db::SessionBound::Authorized(snapshot) => snapshot,
        crate::db::SessionBound::SessionUnavailable => panic!("verified session was rejected"),
    };
    assert_eq!(outcome, crate::db::ShareControlsUpdateOutcome::Updated);
    assert!(!updated_share.unwrap().active);
}

#[tokio::test]
async fn api_creates_share_and_hides_secrets() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    std::fs::write(root.path().join("docs/readme.txt"), "hello").unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let app = crate::web::router(state.clone());

    let _special_socket =
        std::os::unix::net::UnixListener::bind(root.path().join("special-share-target.sock"))
            .unwrap();
    let mut special_target = json_request(
        Method::POST,
        "/api/v2/shares",
        r#"{"path":"special-share-target.sock","permission":"download_only"}"#,
    );
    special_target.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    special_target
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    assert_eq!(
        app.clone().oneshot(special_target).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert!(state
        .db()
        .list_shares()
        .unwrap()
        .iter()
        .all(|share| share.relative_path != "special-share-target.sock"));

    let mut invalid_limit = json_request(
        Method::POST,
        "/api/v2/shares",
        r#"{"path":"docs","permission":"download_only","max_downloads":0}"#,
    );
    invalid_limit.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    invalid_limit
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    assert_eq!(
        app.clone().oneshot(invalid_limit).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    let mut oversized_limit = json_request(
        Method::POST,
        "/api/v2/shares",
        r#"{"path":"docs","permission":"download_only","max_downloads":9223372036854775808}"#,
    );
    oversized_limit.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    oversized_limit
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    assert_eq!(
        app.clone().oneshot(oversized_limit).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    let mut expired = json_request(
        Method::POST,
        "/api/v2/shares",
        r#"{"path":"docs","permission":"download_only","expires_at":"2000-01-01T00:00:00Z"}"#,
    );
    expired.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    expired
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    assert_eq!(
        app.clone().oneshot(expired).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    let mut create = json_request(
        Method::POST,
        "/api/v2/shares",
        r#"{"path":"docs","permission":"download_upload","alias":"docs-api-123","max_downloads":5,"password":"very strong share password","overwrite_allowed":true}"#,
    );
    create.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    create
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    let response = app.clone().oneshot(create).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains(r#""alias":"docs-api-123""#));
    assert!(body.contains(r#""url":"http://localhost:8080/s/docs-api-123""#));
    assert!(body.contains(r#""password_protected":true"#));
    assert!(body.contains(r#""upload_conflict_strategy":"overwrite_allowed""#));
    assert!(!body.contains("password_hash"));
    let audit_events = state.db().list_audit(Some("share_created"), 10, 0).unwrap();
    let detail = audit_events[0].detail.as_deref().unwrap();
    assert!(detail.contains("path=docs"));
    assert!(detail.contains("permission=download_upload"));
    assert!(detail.contains("alias=docs-api-123"));
    assert!(detail.contains("transfer_limit=5"));
    assert!(detail.contains("password_protected=true"));
    assert!(detail.contains("overwrite_allowed=true"));

    let share_id = json_i64_value(&body, "id");
    let audit_count = state.db().count_audit(None).unwrap();
    let mut empty_update = json_request(Method::PATCH, &format!("/api/v2/shares/{share_id}"), "{}");
    empty_update.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    empty_update
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    let empty_update = app.clone().oneshot(empty_update).await.unwrap();
    assert_eq!(empty_update.status(), StatusCode::OK);
    let empty_update_body = response_text(empty_update).await;
    assert_eq!(json_i64_value(&empty_update_body, "id"), share_id);
    assert!(empty_update_body.contains(r#""active":true"#));
    assert_eq!(state.db().count_audit(None).unwrap(), audit_count);

    let mut list = json_request(Method::GET, "/api/v2/shares", "");
    list.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    let response = app.clone().oneshot(list).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("docs-api-123"));
    assert!(!body.contains("very strong share password"));
    assert!(!body.contains("password_hash"));
    let list_body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(list_body["shares"].as_array().unwrap().len(), 1);
    assert!(list_body["next_cursor"].is_null());

    let mut invalid_page = json_request(Method::GET, "/api/v2/shares?limit=0", "");
    invalid_page.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(invalid_page).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    let mut update = json_request(
        Method::PATCH,
        &format!("/api/v2/shares/{share_id}"),
        r#"{"active":false}"#,
    );
    authorize_mutation(&mut update, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(update).await.unwrap().status(),
        StatusCode::OK
    );

    let mut activate = json_request(
        Method::POST,
        &format!("/api/v2/shares/{share_id}/activate"),
        "{}",
    );
    authorize_mutation(&mut activate, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(activate).await.unwrap().status(),
        StatusCode::OK
    );

    let mut deactivate = json_request(
        Method::POST,
        &format!("/api/v2/shares/{share_id}/deactivate"),
        "{}",
    );
    authorize_mutation(&mut deactivate, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(deactivate).await.unwrap().status(),
        StatusCode::OK
    );

    let mut set_password = json_request(
        Method::PUT,
        &format!("/api/v2/shares/{share_id}/password"),
        r#"{"password":"replacement share password"}"#,
    );
    authorize_mutation(&mut set_password, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(set_password).await.unwrap().status(),
        StatusCode::OK
    );

    let mut remove_password = json_request(
        Method::DELETE,
        &format!("/api/v2/shares/{share_id}/password"),
        "",
    );
    authorize_mutation(&mut remove_password, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(remove_password).await.unwrap().status(),
        StatusCode::OK
    );

    let mut delete = json_request(Method::DELETE, &format!("/api/v2/shares/{share_id}"), "");
    authorize_mutation(&mut delete, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(delete).await.unwrap().status(),
        StatusCode::OK
    );
    assert!(state.db().list_shares().unwrap().is_empty());

    let mut missing_delete = json_request(Method::DELETE, "/api/v2/shares/999999", "");
    missing_delete.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    missing_delete
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    assert_eq!(
        app.oneshot(missing_delete).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn api_hashes_share_password_before_waiting_for_storage_mutation() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
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
    let app = crate::web::router(state.clone());
    let _storage_mutation_gate = state.block_storage_mutations_for_test().await;
    let _argon2_capacity = state.acquire_all_argon2_for_test().await;
    let mut create = json_request(
        Method::POST,
        "/api/v2/shares",
        r#"{"path":"docs","permission":"download_only","password":"very strong share password"}"#,
    );
    authorize_mutation(&mut create, "vaultlink_session=session-token", "csrf-token");

    let response = tokio::time::timeout(std::time::Duration::from_secs(1), app.oneshot(create))
        .await
        .expect("Argon2 admission must run before the held storage lock")
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(state.db().list_shares().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_share_mutation_rechecks_the_exact_session_after_waiting_for_storage() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "queued-api-session",
            1,
            "csrf-token",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("queued-api-session").unwrap();
    let share_id = state
        .db()
        .create_share(
            "queued-api-share",
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

    // Make the initial session lookup observable: it refreshes activity before
    // the handler queues on the storage lock. This avoids a timing-only test.
    let probe = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    let stale_activity = (Utc::now() - Duration::minutes(2)).to_rfc3339();
    probe
        .execute("UPDATE sessions SET last_activity_at=?1", [&stale_activity])
        .unwrap();

    let storage_guard = state.acquire_storage_test_exclusive().await;
    let mut request = json_request(
        Method::POST,
        &format!("/api/v2/shares/{share_id}/deactivate"),
        "{}",
    );
    authorize_mutation(
        &mut request,
        "vaultlink_session=queued-api-session",
        "csrf-token",
    );
    let app = crate::web::router(state.clone());
    let queued = tokio::spawn(async move { app.oneshot(request).await.unwrap() });

    let mut initial_check_completed = false;
    for _ in 0..100 {
        let current_activity: String = probe
            .query_row("SELECT last_activity_at FROM sessions", [], |row| {
                row.get(0)
            })
            .unwrap();
        if current_activity != stale_activity {
            initial_check_completed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        initial_check_completed,
        "request did not complete its initial session check"
    );

    state.db().delete_session("queued-api-session").unwrap();
    drop(storage_guard);
    let response = queued.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response_text(response)
        .await
        .contains(r#""code":"session_revoked""#));
    assert!(
        state
            .db()
            .share_by_token("queued-api-share")
            .unwrap()
            .unwrap()
            .active
    );
    assert_eq!(state.db().count_audit(Some("share_deactivated")).unwrap(), 0);
}

#[tokio::test]
async fn external_writers_reject_api_overwrite_configuration() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    let mut state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let mut config = state.config().clone();
    config.storage.external_writers = true;
    state.replace_config_for_test(config);
    let app = crate::web::router(state.clone());

    let mut create = json_request(
        Method::POST,
        "/api/v2/shares",
        r#"{"path":"docs","permission":"download_upload","overwrite_allowed":true}"#,
    );
    create.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    create
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    assert_eq!(
        app.clone().oneshot(create).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    let share_id = state
        .db()
        .create_share(
            "external-api",
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
    state.db().set_share_active(share_id, false).unwrap();
    let mut update = json_request(
        Method::PATCH,
        &format!("/api/v2/shares/{share_id}"),
        r#"{"active":true,"upload_conflict_strategy":"overwrite_allowed"}"#,
    );
    update.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    update
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    assert_eq!(
        app.oneshot(update).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert!(!state.db().list_shares().unwrap()[0].active);
}

#[tokio::test]
async fn external_writer_replace_opt_in_allows_api_overwrite_configuration() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    let mut state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let mut config = state.config().clone();
    config.storage.external_writers = true;
    config.storage.allow_external_writer_replace = true;
    state.replace_config_for_test(config);
    let app = crate::web::router(state.clone());

    let mut create = json_request(
        Method::POST,
        "/api/v2/shares",
        r#"{"path":"docs","permission":"download_upload","overwrite_allowed":true}"#,
    );
    create.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    create
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    assert_eq!(app.oneshot(create).await.unwrap().status(), StatusCode::OK);
    assert!(state.db().list_shares().unwrap()[0]
        .upload_conflict_strategy
        .can_overwrite());
}
