#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_upload_revocation_covers_password_mfa_and_expiry_and_releases_admission() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    for name in ["password.txt", "mfa.txt", "expired.txt"] {
        std::fs::write(root.path().join("uploads").join(name), b"original").unwrap();
    }
    let mut state = test_state(root.path(), data.path());
    state.replace_upload_admission_for_test(Arc::new(tokio::sync::Semaphore::new(1)));
    state
        .db()
        .create_admin("admin", "old-hash", "secret")
        .unwrap();
    let app = router(state.clone());

    state
        .db()
        .create_session(
            "password-session",
            1,
            "csrf-token",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("password-session").unwrap();
    let (upload, sender) = controlled_admin_multipart_request_with_overwrite(
        "/admin/files/upload/queue",
        "uploads",
        "csrf-token",
        "password-session",
        "password.txt",
        b"must not replace",
        true,
    );
    let upload_app = app.clone();
    let upload = tokio::spawn(async move { upload_app.oneshot(upload).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;
    let storage_guard = state.acquire_storage_test_exclusive().await;
    finish_controlled_multipart(sender).await;
    assert!(matches!(
        state
            .db()
            .change_admin_password_cas(1, "old-hash", "new-hash", None)
            .unwrap(),
        crate::db::AdminPasswordChangeOutcome::Changed
    ));
    drop(storage_guard);
    let response = upload.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_text(response).await,
        r#"{"error":"session_revoked"}"#
    );
    assert_eq!(
        std::fs::read(root.path().join("uploads/password.txt")).unwrap(),
        b"original"
    );
    assert_eq!(state.upload_admission_available_for_test(), 1);

    state
        .db()
        .create_session(
            "mfa-session",
            1,
            "csrf-token",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("mfa-session").unwrap();
    let (upload, sender) = controlled_admin_multipart_request_with_overwrite(
        "/admin/files/upload/queue",
        "uploads",
        "csrf-token",
        "mfa-session",
        "mfa.txt",
        b"must not replace",
        true,
    );
    let upload_app = app.clone();
    let upload = tokio::spawn(async move { upload_app.oneshot(upload).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;
    let storage_guard = state.acquire_storage_test_exclusive().await;
    finish_controlled_multipart(sender).await;
    assert!(state
        .db()
        .reset_admin_totp(1, &auth::new_totp_secret())
        .unwrap()
        .is_some());
    drop(storage_guard);
    let response = upload.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_text(response).await,
        r#"{"error":"session_revoked"}"#
    );
    assert_eq!(
        std::fs::read(root.path().join("uploads/mfa.txt")).unwrap(),
        b"original"
    );
    assert_eq!(state.upload_admission_available_for_test(), 1);

    state
        .db()
        .create_session(
            "expiry-session",
            1,
            "csrf-token",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("expiry-session").unwrap();
    let (upload, sender) = controlled_admin_multipart_request_with_overwrite(
        "/admin/files/upload/queue",
        "uploads",
        "csrf-token",
        "expiry-session",
        "expired.txt",
        b"must not replace",
        true,
    );
    let upload_app = app.clone();
    let upload = tokio::spawn(async move { upload_app.oneshot(upload).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;
    let storage_guard = state.acquire_storage_test_exclusive().await;
    finish_controlled_multipart(sender).await;
    state.db().expire_session_for_test("expiry-session").unwrap();
    drop(storage_guard);
    let response = upload.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_text(response).await,
        r#"{"error":"session_revoked"}"#
    );
    assert_eq!(
        std::fs::read(root.path().join("uploads/expired.txt")).unwrap(),
        b"original"
    );

    assert_eq!(state.upload_admission_available_for_test(), 1);
    assert_eq!(state.upload_peer_admission_count_for_test(), 0);
    assert_eq!(state.db().count_audit(Some("admin_upload")).unwrap(), 0);
    assert_eq!(
        state.db().count_audit(Some("admin_upload_replaced")).unwrap(),
        0
    );
}

fn assert_revoked_admin_redirect_clears_both_session_cookies(response: &Response) {
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/login");
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|cookie| cookie.to_str().unwrap())
        .collect::<Vec<_>>();
    for name in ["vaultlink_session", "__Host-vaultlink_session"] {
        assert!(
            cookies.iter().any(|cookie| {
                cookie.starts_with(&format!("{name}=;")) && cookie.contains("Max-Age=0")
            }),
            "revocation response did not clear {name}: {cookies:?}"
        );
    }
}

async fn wait_for_initial_session_check(
    probe: &rusqlite::Connection,
    csrf_token: &str,
    stale_activity: &str,
) {
    for _ in 0..100 {
        let current_activity: String = probe
            .query_row(
                "SELECT last_activity_at FROM sessions WHERE csrf_token=?1",
                [csrf_token],
                |row| row.get(0),
            )
            .unwrap();
        if current_activity != stale_activity {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("request did not complete its initial session check");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_admin_file_rename_and_delete_preserve_storage_shares_and_audit() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("rename-source.txt"), b"rename-original").unwrap();
    std::fs::write(root.path().join("delete-target.txt"), b"delete-original").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share(
            "rename-share",
            None,
            "rename-source.txt",
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
            "delete-share",
            None,
            "delete-target.txt",
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
    let app = router(state.clone());
    let probe = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();

    state
        .db()
        .create_session(
            "rename-revoked-session",
            1,
            "rename-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("rename-revoked-session").unwrap();
    let stale_activity = (Utc::now() - Duration::minutes(2)).to_rfc3339();
    probe
        .execute(
            "UPDATE sessions SET last_activity_at=?1 WHERE csrf_token=?2",
            [stale_activity.as_str(), "rename-csrf"],
        )
        .unwrap();
    let storage_guard = state.acquire_storage_test_exclusive().await;
    let mut rename = request(
        Method::POST,
        "/admin/files/rename",
        "csrf=rename-csrf&path=rename-source.txt&name=rename-destination.txt",
    );
    rename.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=rename-revoked-session"),
    );
    let rename_app = app.clone();
    let rename = tokio::spawn(async move { rename_app.oneshot(rename).await.unwrap() });
    wait_for_initial_session_check(&probe, "rename-csrf", &stale_activity).await;
    state.db().delete_session("rename-revoked-session").unwrap();
    drop(storage_guard);

    let response = rename.await.unwrap();
    assert_revoked_admin_redirect_clears_both_session_cookies(&response);
    assert_eq!(
        std::fs::read(root.path().join("rename-source.txt")).unwrap(),
        b"rename-original"
    );
    assert!(!root.path().join("rename-destination.txt").exists());
    let rename_share = state.db().share_by_token("rename-share").unwrap().unwrap();
    assert_eq!(rename_share.relative_path, "rename-source.txt");
    assert!(rename_share.active);
    assert_eq!(state.db().count_audit(Some("path_renamed")).unwrap(), 0);

    state
        .db()
        .create_session(
            "delete-revoked-session",
            1,
            "delete-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("delete-revoked-session").unwrap();
    let stale_activity = (Utc::now() - Duration::minutes(2)).to_rfc3339();
    probe
        .execute(
            "UPDATE sessions SET last_activity_at=?1 WHERE csrf_token=?2",
            [stale_activity.as_str(), "delete-csrf"],
        )
        .unwrap();
    let storage_guard = state.acquire_storage_test_exclusive().await;
    let mut delete = request(
        Method::POST,
        "/admin/files/delete",
        "csrf=delete-csrf&path=delete-target.txt",
    );
    delete.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=delete-revoked-session"),
    );
    let delete_app = app.clone();
    let delete = tokio::spawn(async move { delete_app.oneshot(delete).await.unwrap() });
    wait_for_initial_session_check(&probe, "delete-csrf", &stale_activity).await;
    state.db().delete_session("delete-revoked-session").unwrap();
    drop(storage_guard);

    let response = delete.await.unwrap();
    assert_revoked_admin_redirect_clears_both_session_cookies(&response);
    assert_eq!(
        std::fs::read(root.path().join("delete-target.txt")).unwrap(),
        b"delete-original"
    );
    let delete_share = state.db().share_by_token("delete-share").unwrap().unwrap();
    assert_eq!(delete_share.relative_path, "delete-target.txt");
    assert!(delete_share.active);
    assert_eq!(state.db().count_audit(Some("path_deleted")).unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_admin_settings_preserve_sqlite_runtime_webauthn_and_audit() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "settings-revoked-session",
            1,
            "settings-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("settings-revoked-session").unwrap();
    let persisted_before = state.db().runtime_settings().unwrap();
    let runtime_before = state.runtime_settings_snapshot();
    let webauthn_before = state.webauthn_snapshot_for_test().instance_id();

    let probe = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    let stale_activity = (Utc::now() - Duration::minutes(2)).to_rfc3339();
    probe
        .execute(
            "UPDATE sessions SET last_activity_at=?1 WHERE csrf_token=?2",
            [stale_activity.as_str(), "settings-csrf"],
        )
        .unwrap();
    let settings_guard = state.acquire_security_settings_mutation().await;
    let mut update = request(
        Method::POST,
        "/admin/settings",
        "csrf=settings-csrf&public_base_url=http%3A%2F%2Flocalhost%3A9999&max_upload_size_gb=16&blocked_extensions=exe%2Cbat&share_password_min_length=12&share_password_max_length=128&share_unlock_minutes=30&max_zip_size_gb=2&max_zip_files=20&max_search_entries=200&max_search_results=20&max_preview_size_mb=64&preview_extensions=txt%2Clog&image_preview_extensions=jpg%2Cpng&pdf_preview_enabled=on&max_media_preview_size_mb=4096",
    );
    update.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=settings-revoked-session"),
    );
    let app = router(state.clone());
    let update = tokio::spawn(async move { app.oneshot(update).await.unwrap() });
    wait_for_initial_session_check(&probe, "settings-csrf", &stale_activity).await;
    state.db().delete_session("settings-revoked-session").unwrap();
    drop(settings_guard);

    let response = update.await.unwrap();
    assert_revoked_admin_redirect_clears_both_session_cookies(&response);
    assert_eq!(state.db().runtime_settings().unwrap(), persisted_before);
    assert_eq!(state.runtime_settings_snapshot(), runtime_before);
    assert_eq!(
        state.webauthn_snapshot_for_test().instance_id(),
        webauthn_before
    );
    assert_eq!(state.db().count_audit(Some("settings_updated")).unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authorized_settings_publication_finishes_before_waiting_logout_returns() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "settings-wins-session",
            1,
            "settings-wins-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("settings-wins-session").unwrap();
    let webauthn_before = state.webauthn_snapshot_for_test().instance_id();

    let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::channel();
    state.install_settings_publication_barrier_for_test((entered_sender, release_receiver));

    let mut update = request(
        Method::POST,
        "/admin/settings",
        "csrf=settings-wins-csrf&public_base_url=http%3A%2F%2Flocalhost%3A9999&max_upload_size_gb=16&blocked_extensions=exe%2Cbat&share_password_min_length=12&share_password_max_length=128&share_unlock_minutes=30&max_zip_size_gb=2&max_zip_files=20&max_search_entries=200&max_search_results=20&max_preview_size_mb=64&preview_extensions=txt%2Clog&image_preview_extensions=jpg%2Cpng&pdf_preview_enabled=on&max_media_preview_size_mb=4096",
    );
    update.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=settings-wins-session"),
    );
    let update_app = router(state.clone());
    let update = tokio::spawn(async move { update_app.oneshot(update).await.unwrap() });
    tokio::task::spawn_blocking(move || {
        entered_receiver
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("settings transaction should reach snapshot publication")
    })
    .await
    .unwrap();

    let mut logout = request(Method::POST, "/logout", "csrf=settings-wins-csrf");
    logout.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=settings-wins-session"),
    );
    let logout_state = state.clone();
    let logout = tokio::spawn(async move {
        let response = router(logout_state.clone()).oneshot(logout).await.unwrap();
        let observed_runtime = runtime_settings(&logout_state);
        let observed_webauthn = logout_state.webauthn_snapshot_for_test().instance_id();
        (response, observed_runtime, observed_webauthn)
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        !logout.is_finished(),
        "logout must wait while the authorized settings transaction owns the fence"
    );

    release_sender.send(()).unwrap();
    let update_response = update.await.unwrap();
    assert_eq!(update_response.status(), StatusCode::OK);
    let (logout_response, observed_runtime, observed_webauthn) = logout.await.unwrap();
    assert_eq!(logout_response.status(), StatusCode::SEE_OTHER);
    assert_eq!(observed_runtime.public_base_url, "http://localhost:9999");
    assert_ne!(observed_webauthn, webauthn_before);
    assert!(state
        .db()
        .runtime_settings()
        .unwrap()
        .iter()
        .any(|(key, value)| key == "public_base_url" && value == "http://localhost:9999"));
    assert_eq!(state.db().count_audit(Some("settings_updated")).unwrap(), 1);
    assert_eq!(state.db().count_audit(Some("logout")).unwrap(), 1);
    assert!(state.db().session("settings-wins-session").unwrap().is_none());
}
