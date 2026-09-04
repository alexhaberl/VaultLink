#[tokio::test]
async fn stale_session_cookies_use_revoked_contract_but_missing_cookie_stays_unauthorized() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let app = router(state.clone());

    state
        .db()
        .create_session(
            "already-revoked-session",
            1,
            "already-revoked-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("already-revoked-session").unwrap();
    state
        .db()
        .delete_session("already-revoked-session")
        .unwrap();
    let mut html = request(
        Method::POST,
        "/admin/files/directories",
        "csrf=already-revoked-csrf&parent=&name=forbidden-html",
    );
    html.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=already-revoked-session"),
    );
    let response = app.clone().oneshot(html).await.unwrap();
    assert_revoked_admin_redirect_clears_both_session_cookies(&response);

    state
        .db()
        .create_session(
            "queue-stale-session",
            1,
            "queue-stale-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("queue-stale-session").unwrap();
    state.db().delete_session("queue-stale-session").unwrap();
    let mut queue = admin_multipart_request(
        "/admin/files/upload/queue",
        "uploads",
        "queue-stale-csrf",
        "forbidden-queue.txt",
        b"must not be staged",
        false,
    );
    queue.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=queue-stale-session"),
    );
    let response = app.clone().oneshot(queue).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_text(response).await,
        r#"{"error":"session_revoked"}"#
    );

    state
        .db()
        .create_session(
            "absolute-expired-session",
            1,
            "absolute-expired-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("absolute-expired-session").unwrap();
    let probe = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    probe
        .execute(
            "UPDATE sessions SET expires_at=?1 WHERE csrf_token=?2",
            [
                (Utc::now() - Duration::seconds(1)).to_rfc3339().as_str(),
                "absolute-expired-csrf",
            ],
        )
        .unwrap();
    let absolute = Request::builder()
        .method(Method::POST)
        .uri("/api/v2/files/directories")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, "vaultlink_session=absolute-expired-session")
        .header("x-csrf-token", "absolute-expired-csrf")
        .body(Body::from(r#"{"parent":"","name":"forbidden-absolute"}"#))
        .unwrap();
    let response = app.clone().oneshot(absolute).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response_text(response)
        .await
        .contains(r#""code":"session_revoked""#));

    state
        .db()
        .create_session(
            "idle-expired-session",
            1,
            "idle-expired-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("idle-expired-session").unwrap();
    let idle_expired_at = (Utc::now() - Duration::hours(2)).to_rfc3339();
    probe
        .execute(
            "UPDATE sessions SET last_activity_at=?1 WHERE csrf_token=?2",
            [idle_expired_at.as_str(), "idle-expired-csrf"],
        )
        .unwrap();
    let idle = Request::builder()
        .method(Method::POST)
        .uri("/api/v2/files/directories")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, "vaultlink_session=idle-expired-session")
        .header("x-csrf-token", "idle-expired-csrf")
        .body(Body::from(r#"{"parent":"","name":"forbidden-idle"}"#))
        .unwrap();
    let response = app.clone().oneshot(idle).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response_text(response)
        .await
        .contains(r#""code":"session_revoked""#));

    let missing = Request::builder()
        .method(Method::POST)
        .uri("/api/v2/files/directories")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"parent":"","name":"missing-cookie"}"#))
        .unwrap();
    let response = app.oneshot(missing).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response_text(response).await;
    assert!(body.contains(r#""code":"unauthorized""#));
    assert!(!body.contains("session_revoked"));

    assert!(!root.path().join("forbidden-html").exists());
    assert!(!root.path().join("forbidden-absolute").exists());
    assert!(!root.path().join("forbidden-idle").exists());
    assert!(!root.path().join("uploads/forbidden-queue.txt").exists());
    assert_eq!(upload_fragment_count(root.path()), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_api_admin_totp_reset_preserves_credentials_state_and_audit() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state
        .db()
        .create_admin("actor", "hash", "actor-secret")
        .unwrap();
    state
        .db()
        .create_admin("target", "hash", "target-secret")
        .unwrap();
    state
        .db()
        .create_session(
            "target-credential-setup-session",
            2,
            "target-credential-setup-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state
        .db()
        .verify_mfa("target-credential-setup-session")
        .unwrap();
    state
        .db()
        .add_admin_webauthn_credential_for_session(
            "target-credential-setup-session",
            2,
            "preserved",
            "credential-id",
            b"credential",
            None,
        )
        .unwrap();
    state
        .db()
        .create_session(
            "admin-reset-revoked-session",
            1,
            "admin-reset-revoked-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state
        .db()
        .verify_mfa("admin-reset-revoked-session")
        .unwrap();

    let probe = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    let before = probe
        .query_row(
            "SELECT totp_generation,totp_key_id,totp_ciphertext FROM admins WHERE id=2",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .unwrap();
    let stale_activity = (Utc::now() - Duration::minutes(2)).to_rfc3339();
    probe
        .execute(
            "UPDATE sessions SET last_activity_at=?1 WHERE csrf_token=?2",
            [stale_activity.as_str(), "admin-reset-revoked-csrf"],
        )
        .unwrap();
    let settings_guard = state.acquire_security_settings_mutation().await;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v2/admins/2/totp/reset")
        .header(
            header::COOKIE,
            "vaultlink_session=admin-reset-revoked-session",
        )
        .header("x-csrf-token", "admin-reset-revoked-csrf")
        .body(Body::empty())
        .unwrap();
    let app = router(state.clone());
    let reset = tokio::spawn(async move { app.oneshot(request).await.unwrap() });
    wait_for_initial_session_check(&probe, "admin-reset-revoked-csrf", &stale_activity).await;
    state
        .db()
        .delete_session("admin-reset-revoked-session")
        .unwrap();
    drop(settings_guard);

    let response = reset.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response_text(response)
        .await
        .contains(r#""code":"session_revoked""#));
    let after = probe
        .query_row(
            "SELECT totp_generation,totp_key_id,totp_ciphertext FROM admins WHERE id=2",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(after, before);
    assert_eq!(state.db().admin_webauthn_credentials(2).unwrap().len(), 1);
    assert_eq!(state.db().count_audit(Some("admin_totp_reset")).unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_authorized_to_staged_admin_upload_releases_every_phase_owner() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let mut state = test_state(root.path(), data.path());
    state.replace_upload_admission_for_test(Arc::new(tokio::sync::Semaphore::new(1)));
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "cancelled-staging-session",
            1,
            "cancelled-staging-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("cancelled-staging-session").unwrap();

    let (request, sender) = controlled_admin_multipart_request(
        "/admin/files/upload/queue",
        "uploads",
        "cancelled-staging-csrf",
        "cancelled-staging-session",
        "cancelled-during-staging.txt",
        b"the multipart body deliberately remains open",
    );
    let app = router(state.clone());
    let upload = tokio::spawn(async move { app.oneshot(request).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;

    assert_eq!(state.upload_admission_available_for_test(), 0);
    assert_eq!(state.upload_peer_admission_count_for_test(), 1);
    assert_eq!(upload_fragment_count(root.path()), 1);
    assert!(!upload.is_finished());

    upload.abort();
    let _ = upload.await;
    drop(sender);

    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if state.upload_admission_available_for_test() == 1
                && state.upload_peer_admission_count_for_test() == 0
                && upload_fragment_count(root.path()) == 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("cancelling staging must drop authorization, admission and the temporary file");

    assert!(!root
        .path()
        .join("uploads/cancelled-during-staging.txt")
        .exists());
    assert_eq!(state.db().count_audit(Some("admin_upload")).unwrap(), 0);
    assert_eq!(
        state
            .db()
            .count_audit(Some("admin_upload_replaced"))
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_admin_upload_retains_fence_resources_until_revocation_commits() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let mut state = test_state(root.path(), data.path());
    state.replace_upload_admission_for_test(Arc::new(tokio::sync::Semaphore::new(1)));
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "cancelled-admin-upload-session",
            1,
            "cancelled-admin-upload-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state
        .db()
        .verify_mfa("cancelled-admin-upload-session")
        .unwrap();

    // Stall the multipart at EOF in the Staged phase. Closing the body moves
    // the upload through Prepared into the detached finalizer; acquiring the
    // namespace fence below proves that finalizer reached Committed.
    let (upload, sender) = controlled_admin_multipart_request(
        "/admin/files/upload/queue",
        "uploads",
        "cancelled-admin-upload-csrf",
        "cancelled-admin-upload-session",
        "cancelled-finalizer.txt",
        b"must never be published",
    );
    let app = router(state.clone());
    let upload = tokio::spawn(async move { app.oneshot(upload).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;
    let initial_storage_guard = state.acquire_storage_test_exclusive().await;
    let mut writer = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    let writer = writer
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    finish_controlled_multipart(sender).await;
    drop(initial_storage_guard);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while state.try_acquire_storage_test_exclusive().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("upload finalizer should acquire the storage mutation lock");
    assert_eq!(state.upload_admission_available_for_test(), 0);
    assert!(state.try_acquire_storage_test_exclusive().is_err());

    // Dropping the HTTP future must only detach the Committed -> Published
    // transition. The finalizer remains the single owner of its permits,
    // storage lock, staged file and exact-session proof until the DB fence
    // resolves.
    upload.abort();
    let _ = upload.await;
    tokio::task::yield_now().await;
    assert_eq!(state.upload_admission_available_for_test(), 0);
    assert!(state.try_acquire_storage_test_exclusive().is_err());
    assert_eq!(upload_fragment_count(root.path()), 1);

    writer
        .execute(
            "DELETE FROM sessions WHERE csrf_token=?1",
            ["cancelled-admin-upload-csrf"],
        )
        .unwrap();
    writer.commit().unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if state.upload_admission_available_for_test() == 1
                && state.try_acquire_storage_test_exclusive().is_ok()
                && upload_fragment_count(root.path()) == 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("detached upload finalizer should release every resource");

    assert!(!root.path().join("uploads/cancelled-finalizer.txt").exists());
    assert_eq!(state.upload_peer_admission_count_for_test(), 0);
    assert_eq!(state.db().count_audit(Some("admin_upload")).unwrap(), 0);
    assert_eq!(
        state
            .db()
            .count_audit(Some("admin_upload_replaced"))
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_folder_creation_retains_permits_proof_and_fence_until_commit() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let mut state = test_state(root.path(), data.path());
    state.replace_upload_admission_for_test(Arc::new(tokio::sync::Semaphore::new(1)));
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "cancelled-folder-session",
            1,
            "cancelled-folder-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("cancelled-folder-session").unwrap();

    let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::channel();
    state.install_upload_directory_creation_barrier_for_test((entered_sender, release_receiver));
    let mut upload = admin_folder_upload_request(
        "/admin/files/upload/queue",
        "uploads",
        "cancelled-folder-csrf",
        "committed/despite-cancellation",
        "never-staged.txt",
        b"request body is abandoned after the directory fence",
    );
    upload.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=cancelled-folder-session"),
    );
    let app = router(state.clone());
    let upload = tokio::spawn(async move { app.oneshot(upload).await.unwrap() });
    tokio::task::spawn_blocking(move || {
        entered_receiver
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("folder creation should enter its live-session transaction")
    })
    .await
    .unwrap();

    upload.abort();
    let _ = upload.await;
    tokio::task::yield_now().await;
    assert_eq!(state.upload_admission_available_for_test(), 0);
    assert!(state.try_acquire_storage_test_exclusive().is_err());
    assert_eq!(state.upload_peer_admission_count_for_test(), 1);

    let revoke_database = state.db().clone();
    let revocation = tokio::task::spawn_blocking(move || {
        revoke_database.delete_session("cancelled-folder-session")
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        !revocation.is_finished(),
        "revocation must wait for the already-authorized folder mutation"
    );
    release_sender.send(()).unwrap();
    revocation.await.unwrap().unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if state.upload_admission_available_for_test() == 1
                && state.try_acquire_storage_test_exclusive().is_ok()
                && state.upload_peer_admission_count_for_test() == 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("detached folder finalizer should release every retained resource");

    assert!(root
        .path()
        .join("uploads/committed/despite-cancellation")
        .is_dir());
    assert!(!root
        .path()
        .join("uploads/committed/despite-cancellation/never-staged.txt")
        .exists());
    assert_eq!(
        state
            .db()
            .count_audit(Some("upload_directories_created"))
            .unwrap(),
        1
    );
    assert!(state
        .db()
        .session("cancelled-folder-session")
        .unwrap()
        .is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_admin_folder_upload_creates_no_directory_or_success_audit() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let mut state = test_state(root.path(), data.path());
    state.replace_upload_admission_for_test(Arc::new(tokio::sync::Semaphore::new(1)));
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "revoked-folder-upload-session",
            1,
            "revoked-folder-upload-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state
        .db()
        .verify_mfa("revoked-folder-upload-session")
        .unwrap();

    let probe = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    let stale_activity = (Utc::now() - Duration::minutes(2)).to_rfc3339();
    probe
        .execute(
            "UPDATE sessions SET last_activity_at=?1 WHERE csrf_token=?2",
            [stale_activity.as_str(), "revoked-folder-upload-csrf"],
        )
        .unwrap();
    let storage_guard = state.acquire_storage_test_exclusive().await;
    let mut upload = admin_folder_upload_request(
        "/admin/files/upload/queue",
        "uploads",
        "revoked-folder-upload-csrf",
        "revoked/nested/folder",
        "must-not-exist.txt",
        b"must never be staged or published",
    );
    upload.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=revoked-folder-upload-session"),
    );
    let app = router(state.clone());
    let upload = tokio::spawn(async move { app.oneshot(upload).await.unwrap() });
    wait_for_initial_session_check(&probe, "revoked-folder-upload-csrf", &stale_activity).await;
    state
        .db()
        .delete_session("revoked-folder-upload-session")
        .unwrap();
    drop(storage_guard);

    let response = upload.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_text(response).await,
        r#"{"error":"session_revoked"}"#
    );
    assert!(!root.path().join("uploads/revoked").exists());
    assert_eq!(upload_fragment_count(root.path()), 0);
    assert_eq!(state.upload_admission_available_for_test(), 1);
    assert_eq!(state.upload_peer_admission_count_for_test(), 0);
    assert_eq!(
        state
            .db()
            .count_audit(Some("upload_directories_created"))
            .unwrap(),
        0
    );
    assert_eq!(state.db().count_audit(Some("admin_upload")).unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streamed_admin_upload_keeps_storage_and_sqlite_writer_sections_short() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let mut state = test_state_with_limit(root.path(), data.path(), 2 * 1024 * 1024);
    state.replace_upload_admission_for_test(Arc::new(tokio::sync::Semaphore::new(1)));
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "streamed-admin-upload-session",
            1,
            "streamed-admin-upload-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state
        .db()
        .verify_mfa("streamed-admin-upload-session")
        .unwrap();
    let content = vec![b's'; 128 * 1024];
    let (request, sender) = controlled_admin_multipart_request(
        "/admin/files/upload/queue",
        "uploads",
        "streamed-admin-upload-csrf",
        "streamed-admin-upload-session",
        "slow-stream.bin",
        &content,
    );
    let app = router(state.clone());
    let upload = tokio::spawn(async move { app.oneshot(request).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;

    // The request is deliberately stalled inside the file field. Neither the
    // storage namespace lock nor SQLite's writer slot belongs to streaming.
    let storage_guard = state
        .try_acquire_storage_test_exclusive()
        .expect("multipart streaming must not hold the storage lock");
    let mut writer = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    let writer = writer
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .expect("multipart streaming must not hold SQLite's writer slot");
    assert_eq!(state.upload_admission_available_for_test(), 0);
    assert!(!upload.is_finished());
    drop(writer);
    drop(storage_guard);

    finish_controlled_multipart(sender).await;
    let response = upload.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response_text(response)
        .await
        .contains(r#""outcome":"created""#));
    assert_eq!(
        std::fs::read(root.path().join("uploads/slow-stream.bin")).unwrap(),
        content
    );
    assert_eq!(state.upload_admission_available_for_test(), 1);
    assert_eq!(state.upload_peer_admission_count_for_test(), 0);
    assert_eq!(state.db().count_audit(Some("admin_upload")).unwrap(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn busy_logout_is_retryable_and_never_reports_false_revocation_success() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "busy-logout-session",
            1,
            "busy-logout-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("busy-logout-session").unwrap();

    let proof = crate::db::MfaSessionProof::for_test("busy-logout-session", 1);
    let database = state.db().clone();
    let (entered_sender, entered_receiver) = tokio::sync::oneshot::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::channel();
    let holder = tokio::task::spawn_blocking(move || {
        database.required_transaction_for_mfa_session(
            &proof,
            &crate::db::AuditContext::new("admin", None),
            |_transaction| -> rusqlite::Result<_> {
                entered_sender.send(()).unwrap();
                release_receiver.recv().unwrap();
                Ok(((), Vec::new()))
            },
        )
    });
    entered_receiver.await.unwrap();

    let mut logout = request(Method::POST, "/logout", "csrf=busy-logout-csrf");
    logout.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=busy-logout-session"),
    );
    let busy_started = std::time::Instant::now();
    let first = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        router(state.clone()).oneshot(logout),
    )
    .await
    .expect("logout should expose SQLite's five-second busy timeout")
    .unwrap();
    let busy_elapsed = busy_started.elapsed();
    let first_status = first.status();
    let retry_after = first
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    // Database::session intentionally performs an idle-touch UPDATE. Use a
    // separate read-only connection while the writer is still fenced.
    let probe = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    let session_remained = probe
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sessions WHERE csrf_token=?1)",
            ["busy-logout-csrf"],
            |row| row.get::<_, bool>(0),
        )
        .unwrap();
    let logout_audits_before_retry = state.db().count_audit(Some("logout")).unwrap();

    // Always release the blocking holder before assertions so a diagnostic
    // failure cannot strand the test runtime on a blocking task.
    release_sender.send(()).unwrap();
    assert!(matches!(
        holder.await.unwrap().unwrap(),
        crate::db::SessionBound::Authorized(())
    ));
    assert_eq!(first_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(retry_after.as_deref(), Some("1"));
    assert!(busy_elapsed >= std::time::Duration::from_secs(4));
    assert!(session_remained);
    assert_eq!(logout_audits_before_retry, 0);

    let mut retry = request(Method::POST, "/logout", "csrf=busy-logout-csrf");
    retry.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=busy-logout-session"),
    );
    let retry = router(state.clone()).oneshot(retry).await.unwrap();
    assert_eq!(retry.status(), StatusCode::SEE_OTHER);
    assert_eq!(retry.headers().get(header::LOCATION).unwrap(), "/login");
    assert!(state.db().session("busy-logout-session").unwrap().is_none());
    assert_eq!(state.db().count_audit(Some("logout")).unwrap(), 1);
}

#[tokio::test]
async fn html_admin_create_maps_only_the_unique_constraint_to_conflict() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "admin-create-session",
            1,
            "admin-create-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("admin-create-session").unwrap();
    let app = router(state.clone());
    let cookie = HeaderValue::from_static("vaultlink_session=admin-create-session");

    let mut duplicate = request(
        Method::POST,
        "/admin/admins",
        "csrf=admin-create-csrf&username=admin&password=another-secure-password&password_confirm=another-secure-password",
    );
    duplicate
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let duplicate = app.clone().oneshot(duplicate).await.unwrap();
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
    assert_ne!(
        duplicate.headers().get(ERROR_CODE_HEADER),
        Some(&HeaderValue::from_static("audit_unavailable"))
    );

    rusqlite::Connection::open(data.path().join("data.sqlite"))
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_html_admin_create_audit
             BEFORE INSERT ON audit
             WHEN NEW.action='admin_created'
             BEGIN SELECT RAISE(FAIL, 'injected admin create audit failure'); END;",
        )
        .unwrap();
    let mut audit_failure = request(
        Method::POST,
        "/admin/admins",
        "csrf=admin-create-csrf&username=audit-ops&password=another-secure-password&password_confirm=another-secure-password",
    );
    audit_failure.headers_mut().insert(header::COOKIE, cookie);
    let audit_failure = app.oneshot(audit_failure).await.unwrap();
    assert_eq!(audit_failure.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        audit_failure.headers().get(ERROR_CODE_HEADER).unwrap(),
        "audit_unavailable"
    );
    assert!(state.db().admin("audit-ops").unwrap().is_none());
    assert_eq!(state.db().count_audit(Some("admin_created")).unwrap(), 0);
}

#[tokio::test]
async fn html_share_create_maps_only_the_unique_constraint_to_conflict() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "share-create-session",
            1,
            "share-create-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("share-create-session").unwrap();
    state
        .db()
        .create_share(
            "existing-share-token",
            Some("duplicate-alias-123"),
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
    let app = router(state.clone());
    let cookie = HeaderValue::from_static("vaultlink_session=share-create-session");

    let mut duplicate = request(
        Method::POST,
        "/admin/shares",
        "csrf=share-create-csrf&path=docs&permission=download_only&alias=duplicate-alias-123",
    );
    duplicate
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let duplicate = app.clone().oneshot(duplicate).await.unwrap();
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
    assert_ne!(
        duplicate.headers().get(ERROR_CODE_HEADER),
        Some(&HeaderValue::from_static("audit_unavailable"))
    );

    rusqlite::Connection::open(data.path().join("data.sqlite"))
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_html_share_create_audit
             BEFORE INSERT ON audit
             WHEN NEW.action='share_created'
             BEGIN SELECT RAISE(FAIL, 'injected share create audit failure'); END;",
        )
        .unwrap();
    let mut audit_failure = request(
        Method::POST,
        "/admin/shares",
        "csrf=share-create-csrf&path=docs&permission=download_only&alias=audit-failure-alias",
    );
    audit_failure.headers_mut().insert(header::COOKIE, cookie);
    let audit_failure = app.oneshot(audit_failure).await.unwrap();
    assert_eq!(audit_failure.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        audit_failure.headers().get(ERROR_CODE_HEADER).unwrap(),
        "audit_unavailable"
    );
    assert!(state
        .db()
        .share_by_alias("audit-failure-alias")
        .unwrap()
        .is_none());
    assert_eq!(state.db().list_shares().unwrap().len(), 1);
    assert_eq!(state.db().count_audit(Some("share_created")).unwrap(), 0);
}
