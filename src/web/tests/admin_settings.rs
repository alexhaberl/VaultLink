#[tokio::test]
async fn admin_ui_creates_admin_and_updates_runtime_settings() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
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
    let cookie = HeaderValue::from_static("vaultlink_locale=de; vaultlink_session=session-token");

    let login_page = response_text(
        app.clone()
            .oneshot(request(Method::GET, "/login", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(!login_page.contains("Hauptnavigation"));
    assert!(!login_page.contains("Link erstellen"));
    assert!(login_page.contains("vl-brand"));
    assert!(login_page.contains("<svg"));
    assert!(login_page.contains("vl-file-front"));
    assert!(!login_page.contains("vl-logo-g"));

    let mut create_admin = request(
            Method::POST,
            "/admin/admins",
            "csrf=csrf-token&username=ops&password=another%20long%20password&password_confirm=another%20long%20password",
        );
    create_admin
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let response = app.clone().oneshot(create_admin).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let created_admin_page = response_text(response).await;
    assert!(created_admin_page.contains("TOTP QR-Code"));
    assert!(created_admin_page.contains("<svg"));
    assert!(created_admin_page.contains("otpauth://totp/VaultLink:ops"));
    assert!(!created_admin_page.contains(r#"action="/locale""#));
    assert!(created_admin_page
        .contains(r#"class="vl-button vl-button--secondary" href="/admin/admins""#));
    assert!(state.db().admin("ops").unwrap().is_some());

    let mut deactivate = request(
        Method::POST,
        "/admin/admins/2/deactivate",
        "csrf=csrf-token",
    );
    deactivate
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone().oneshot(deactivate).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    assert!(state.db().admin("ops").unwrap().is_none());
    let login_disabled = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/login",
            "username=ops&password=another%20long%20password",
        ))
        .await
        .unwrap();
    assert_eq!(login_disabled.status(), StatusCode::UNAUTHORIZED);
    let mut self_deactivate = request(
        Method::POST,
        "/admin/admins/1/deactivate",
        "csrf=csrf-token",
    );
    self_deactivate
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone().oneshot(self_deactivate).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    state.db().create_admin("later", "hash", "secret").unwrap();
    let mut admin_list = request(Method::GET, "/admin/admins", "");
    admin_list
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let admin_list_html = response_text(app.clone().oneshot(admin_list).await.unwrap()).await;
    assert!(admin_list_html.contains("Aktive Admins"));
    assert!(admin_list_html.contains("Stillgelegte Admins"));
    assert!(!admin_list_html.contains("Admin-Löschen ist bewusst nicht enthalten"));
    assert!(admin_list_html.contains("Aktueller Admin"));
    assert!(!admin_list_html.contains("Eigene Passwort- und MFA-Änderungen"));
    assert_eq!(admin_list_html.matches("Passwort setzen").count(), 2);
    assert!(
        admin_list_html.find(r#"data-label="ID">1</td>"#).unwrap()
            < admin_list_html.find(r#"data-label="ID">3</td>"#).unwrap()
    );
    assert!(
        admin_list_html.find("Aktive Admins").unwrap()
            < admin_list_html.find("Stillgelegte Admins").unwrap()
    );
    assert!(admin_list_html.contains("MFA zurücksetzen"));
    assert!(admin_list_html.contains("Passwort setzen"));
    state
        .db()
        .create_session(
            "later-session",
            3,
            "later-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("later-session").unwrap();
    let mut reset_password = request(
        Method::POST,
        "/admin/admins/3/password",
        "csrf=csrf-token&password=new%20long%20password&password_confirm=new%20long%20password",
    );
    reset_password
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let reset_password_response = app.clone().oneshot(reset_password).await.unwrap();
    assert_eq!(reset_password_response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        reset_password_response
            .headers()
            .get(header::LOCATION)
            .unwrap(),
        "/admin/admins?notice=password_reset"
    );
    let mut notice_page = request(Method::GET, "/admin/admins?notice=password_reset", "");
    notice_page
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let notice_html = response_text(app.clone().oneshot(notice_page).await.unwrap()).await;
    assert!(notice_html.contains("Passwort wurde gesetzt"));
    assert!(state.db().session("later-session").unwrap().is_none());
    let login_with_new_password = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/login",
            "username=later&password=new%20long%20password",
        ))
        .await
        .unwrap();
    assert_eq!(login_with_new_password.status(), StatusCode::SEE_OTHER);
    let mut self_password_reset = request(
        Method::POST,
        "/admin/admins/1/password",
        "csrf=csrf-token&password=new%20long%20password&password_confirm=new%20long%20password",
    );
    self_password_reset
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone()
            .oneshot(self_password_reset)
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut reset_totp = request(Method::POST, "/admin/admins/3/totp", "csrf=csrf-token");
    reset_totp
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let reset_totp_response = app.clone().oneshot(reset_totp).await.unwrap();
    assert_eq!(reset_totp_response.status(), StatusCode::OK);
    let reset_totp_html = response_text(reset_totp_response).await;
    assert!(reset_totp_html.contains("MFA zurückgesetzt"));
    assert!(reset_totp_html.contains("TOTP QR-Code"));
    assert!(reset_totp_html.contains("otpauth://totp/VaultLink:later"));
    assert!(!reset_totp_html.contains(r#"action="/locale""#));

    let mut settings_request = request(
            Method::POST,
            "/admin/settings",
            "csrf=csrf-token&public_base_url=http%3A%2F%2Flocalhost%3A9999&max_upload_size_gb=16&blocked_extensions=exe%2Cbat&share_password_min_length=12&share_password_max_length=128&share_unlock_minutes=30&max_zip_size_gb=2&max_zip_files=20&max_search_entries=200&max_search_results=20&max_preview_size_mb=64&preview_extensions=txt%2Clog&image_preview_extensions=jpg%2Cpng&pdf_preview_enabled=on&max_media_preview_size_mb=4096",
        );
    settings_request
        .headers_mut()
        .insert(header::COOKIE, cookie);
    let response = app.clone().oneshot(settings_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let runtime = state.runtime_settings_snapshot();
    assert_eq!(runtime.public_base_url, "http://localhost:9999");
    assert_eq!(runtime.max_upload_size, 16 * GB);
    assert_eq!(runtime.blocked_extensions, ["exe", "bat"]);
    assert!(state
        .db()
        .runtime_settings()
        .unwrap()
        .iter()
        .any(|(key, value)| key == "max_preview_size" && value == &(64 * MB).to_string()));
}

#[tokio::test]
async fn upload_only_never_exposes_target_paths_or_existing_content() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("private-drop")).unwrap();
    std::fs::write(
        root.path().join("private-drop/hidden-secret.txt"),
        b"secret",
    )
    .unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share(
            "drop-token",
            None,
            "private-drop",
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

    let html = response_text(
        app.clone()
            .oneshot(request(Method::GET, "/v/drop-token", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(html.contains("Datei hochladen"));
    assert!(html.contains("Vorhandene Dateien und Ordner bleiben verborgen"));
    assert!(html.contains("Erfolgreiche Uploads werden protokolliert"));
    assert!(html.contains("data-upload-folder-input"));
    assert!(html.contains("webkitdirectory"));
    assert!(!html.contains("private-drop"));
    assert!(!html.contains("hidden-secret.txt"));
    assert!(!html.contains("Dateien durchsuchen"));
    assert!(!html.contains("Datei herunterladen"));

    let folder_upload = app
        .clone()
        .oneshot(public_folder_upload_request(
            "/v/drop-token/upload/queue",
            "",
            "Eingang/Projekt",
            "neu.txt",
            b"private folder upload",
        ))
        .await
        .unwrap();
    assert_eq!(folder_upload.status(), StatusCode::OK);
    assert_eq!(
        std::fs::read(root.path().join("private-drop/Eingang/Projekt/neu.txt")).unwrap(),
        b"private folder upload"
    );

    let api_body = response_text(
        app.oneshot(request(Method::GET, "/api/v2/public/shares/drop-token", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(api_body.contains(r#""path":"""#));
    assert!(!api_body.contains("private-drop"));
    assert!(!api_body.contains("hidden-secret.txt"));
}

#[tokio::test]
async fn public_folder_upload_propagates_first_and_later_mkdir_uncertainty() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share(
            "mkdir-response-loss",
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

    state
        .secure_root()
        .fail_next_create_directory_mkdir_after_success(std::io::ErrorKind::TimedOut);
    state
        .secure_root()
        .fail_next_create_directory_probe(std::io::ErrorKind::WouldBlock);
    let first = app
        .clone()
        .oneshot(public_folder_upload_request(
            "/v/mkdir-response-loss/upload/queue",
            "",
            "first/nested",
            "one.txt",
            b"one",
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert!(response_text(first)
        .await
        .contains(r#""outcome":"created_uncertain""#));
    assert_eq!(
        std::fs::read(root.path().join("uploads/first/nested/one.txt")).unwrap(),
        b"one"
    );

    let fault_root = state.secure_root().clone();
    state.secure_root().after_next_directory_tree_create(move || {
        fault_root
            .fail_next_create_directory_mkdir_after_success(std::io::ErrorKind::ConnectionReset);
        fault_root.fail_next_create_directory_probe(std::io::ErrorKind::WouldBlock);
    });
    let later = app
        .oneshot(public_folder_upload_request(
            "/v/mkdir-response-loss/upload/queue",
            "",
            "later/nested",
            "two.txt",
            b"two",
        ))
        .await
        .unwrap();
    assert_eq!(later.status(), StatusCode::OK);
    assert!(response_text(later)
        .await
        .contains(r#""outcome":"created_uncertain""#));
    assert_eq!(
        std::fs::read(root.path().join("uploads/later/nested/two.txt")).unwrap(),
        b"two"
    );
    assert_eq!(
        state
            .db()
            .count_audit(Some("upload_directories_created"))
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn public_folder_partial_creation_after_quota_commit_is_audited_outcome_not_500() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share_with_upload_limits(
            "partial-folder",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            Some(100),
            Some(100),
            Some(10),
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let external_root = root.path().to_path_buf();
    state.secure_root().after_next_directory_tree_create(move || {
        std::fs::write(external_root.join("uploads/partial/blocker"), b"external").unwrap();
    });
    let app = router(state.clone());

    let response = app
        .oneshot(public_folder_upload_request(
            "/v/partial-folder/upload/queue",
            "",
            "partial/blocker/child",
            "not-published.txt",
            b"payload",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response_text(response)
        .await
        .contains(r#""outcome":"directory_uncertain""#));
    assert!(root.path().join("uploads/partial").is_dir());
    assert!(root.path().join("uploads/partial/blocker").is_file());
    assert!(!root
        .path()
        .join("uploads/partial/blocker/child/not-published.txt")
        .exists());
    let share = state.db().share_by_token("partial-folder").unwrap().unwrap();
    assert_eq!((share.uploaded_bytes, share.uploaded_files), (7, 1));
    let events = state
        .db()
        .list_audit(Some("upload_directories_created"), 10, 0)
        .unwrap();
    assert_eq!(events.len(), 1);
    assert!(events[0]
        .detail
        .as_deref()
        .is_some_and(|detail| detail.contains("complete=false")));
    assert_eq!(upload_fragment_count(root.path()), 0);
}

#[tokio::test]
async fn admin_upload_is_csrf_protected_atomic_and_queue_compatible() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
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

    let mut wrong_csrf = admin_multipart_request(
        "/admin/files/upload",
        "uploads",
        "wrong",
        "blocked.txt",
        b"content",
        false,
    );
    wrong_csrf
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone().oneshot(wrong_csrf).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert!(!root.path().join("uploads/blocked.txt").exists());

    let mut first = admin_multipart_request(
        "/admin/files/upload",
        "uploads",
        "csrf-token",
        "grüße.txt",
        b"first",
        false,
    );
    first.headers_mut().insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone().oneshot(first).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        std::fs::read(root.path().join("uploads/grüße.txt")).unwrap(),
        b"first"
    );

    let mut conflict = admin_multipart_request(
        "/admin/files/upload/queue",
        "uploads",
        "csrf-token",
        "grüße.txt",
        b"second",
        false,
    );
    conflict
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let conflict = app.clone().oneshot(conflict).await.unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert!(response_text(conflict).await.contains("file_exists"));

    let mut replace = admin_multipart_request(
        "/admin/files/upload/queue",
        "uploads",
        "csrf-token",
        "grüße.txt",
        b"second",
        true,
    );
    replace.headers_mut().insert(header::COOKIE, cookie.clone());
    let replace = app.clone().oneshot(replace).await.unwrap();
    assert_eq!(replace.status(), StatusCode::OK);
    let replace_body = response_text(replace).await;
    assert!(replace_body.contains(r#""file":"grüße.txt""#));
    assert!(replace_body.contains(r#""outcome":"replaced"#));
    assert_eq!(
        std::fs::read(root.path().join("uploads/grüße.txt")).unwrap(),
        b"second"
    );

    let mut folder_upload = admin_folder_upload_request(
        "/admin/files/upload/queue",
        "uploads",
        "csrf-token",
        "Album/2026/Sommer",
        "foto.txt",
        b"folder content",
    );
    folder_upload
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let folder_upload = app.clone().oneshot(folder_upload).await.unwrap();
    assert_eq!(folder_upload.status(), StatusCode::OK);
    assert_eq!(
        std::fs::read(root.path().join("uploads/Album/2026/Sommer/foto.txt")).unwrap(),
        b"folder content"
    );
    assert_eq!(
        state
            .db()
            .list_audit(Some("upload_directories_created"), 10, 0)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        state.db().audit_priorities("admin_upload").unwrap(),
        [100, 100]
    );
    assert_eq!(
        state.db().audit_priorities("admin_upload_replaced").unwrap(),
        [100]
    );
    assert_eq!(
        state
            .db()
            .audit_priorities("upload_directories_created")
            .unwrap(),
        [100]
    );

    let mut blocked = admin_multipart_request(
        "/admin/files/upload/queue",
        "uploads",
        "csrf-token",
        "payload.exe",
        b"x",
        false,
    );
    blocked.headers_mut().insert(header::COOKIE, cookie);
    assert_eq!(
        app.clone().oneshot(blocked).await.unwrap().status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );

    let javascript = response_text(
        app.oneshot(request(Method::GET, "/assets/app.js", ""))
            .await
            .unwrap(),
    )
    .await;
    assert!(javascript.contains("input.multiple = true"));
    assert!(javascript.contains("webkitRelativePath"));
    assert!(javascript.contains("folder_path"));
    assert!(javascript.contains("await uploadItem(item)"));
    assert!(javascript.contains("Erneut versuchen"));
    assert!(!javascript.contains("Promise.all"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_upload_rechecks_the_exact_mfa_session_before_publish() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_admin("other-admin", "hash", "other-secret")
        .unwrap();
    for token in ["queue-session", "browser-session"] {
        state
            .db()
            .create_session(token, 1, "csrf-token", Utc::now() + Duration::hours(1))
            .unwrap();
        state.db().verify_mfa(token).unwrap();
    }
    let app = router(state.clone());

    let (queued, sender) = controlled_admin_multipart_request(
        "/admin/files/upload/queue",
        "uploads",
        "csrf-token",
        "queue-session",
        "queue-revoked.txt",
        b"must not publish",
    );
    let queue_app = app.clone();
    let queued = tokio::spawn(async move { queue_app.oneshot(queued).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;
    let storage_guard = state.acquire_storage_test_exclusive().await;
    finish_controlled_multipart(sender).await;
    state.db().delete_session("queue-session").unwrap();
    drop(storage_guard);

    let queued = queued.await.unwrap();
    assert_eq!(queued.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_text(queued).await,
        r#"{"error":"session_revoked"}"#
    );
    assert!(!root.path().join("uploads/queue-revoked.txt").exists());

    let (browser, sender) = controlled_admin_multipart_request(
        "/admin/files/upload",
        "uploads",
        "csrf-token",
        "browser-session",
        "browser-revoked.txt",
        b"must not publish",
    );
    let browser_app = app.clone();
    let browser = tokio::spawn(async move { browser_app.oneshot(browser).await.unwrap() });
    wait_for_upload_fragment(root.path()).await;
    let storage_guard = state.acquire_storage_test_exclusive().await;
    finish_controlled_multipart(sender).await;
    state.db().deactivate_admin(1).unwrap();
    drop(storage_guard);

    let browser = browser.await.unwrap();
    assert_eq!(browser.status(), StatusCode::SEE_OTHER);
    assert_eq!(browser.headers().get(header::LOCATION).unwrap(), "/login");
    assert!(browser
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    assert!(!root.path().join("uploads/browser-revoked.txt").exists());
    assert!(state
        .db()
        .list_audit(Some("admin_upload"), 10, 0)
        .unwrap()
        .is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn text_preview_reserves_transfer_and_render_capacity_before_reading() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    let preview_path = "lease-race-preview.txt";
    std::fs::write(root.path().join("docs").join(preview_path), b"preview").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share(
            "preview-race",
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
    let hook = Arc::new(TextPreviewReadTestHook {
        path: preview_path.to_string(),
        entered: std::sync::atomic::AtomicUsize::new(0),
        released: std::sync::Mutex::new(false),
        wake: std::sync::Condvar::new(),
    });
    let hook_slot = TEXT_PREVIEW_READ_TEST_HOOK.get_or_init(|| std::sync::Mutex::new(None));
    assert!(hook_slot.lock().unwrap().replace(hook.clone()).is_none());
    let hook_guard = TextPreviewReadTestGuard(hook.clone());

    let app = router(state);
    let first_app = app.clone();
    let first = tokio::spawn(async move {
        first_app
            .oneshot(request(
                Method::GET,
                "/v/preview-race/preview?path=lease-race-preview.txt",
                "",
            ))
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

    let second_app = app.clone();
    let second = tokio::spawn(async move {
        second_app
            .oneshot(request(
                Method::GET,
                "/v/preview-race/preview?path=lease-race-preview.txt",
                "",
            ))
            .await
            .unwrap()
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if second.is_finished() || hook.entered.load(Ordering::Acquire) >= 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let reads_before_release = hook.entered.load(Ordering::Acquire);
    hook.release();

    let first = first.await.unwrap();
    let second = second.await.unwrap();
    drop(hook_guard);
    assert_eq!(reads_before_release, 1);
    assert!(matches!(
        (first.status(), second.status()),
        (StatusCode::OK, StatusCode::GONE) | (StatusCode::GONE, StatusCode::OK)
    ));
    drop(first);
    drop(second);

    let render_root = tempfile::tempdir().unwrap();
    let render_data = tempfile::tempdir().unwrap();
    std::fs::create_dir(render_root.path().join("docs")).unwrap();
    let render_path = "render-budget-preview.txt";
    std::fs::write(
        render_root.path().join("docs").join(render_path),
        b"preview",
    )
    .unwrap();
    let render_state = test_state(render_root.path(), render_data.path());
    render_state.mutate_runtime_for_test(|runtime| {
        runtime.max_preview_size = MAX_TEXT_PREVIEW_SIZE;
    });
    render_state
        .db()
        .create_admin("admin", "hash", "secret")
        .unwrap();
    render_state
        .db()
        .create_share(
            "preview-render-race",
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
    let render_hook = Arc::new(TextPreviewReadTestHook {
        path: render_path.to_string(),
        entered: std::sync::atomic::AtomicUsize::new(0),
        released: std::sync::Mutex::new(false),
        wake: std::sync::Condvar::new(),
    });
    assert!(hook_slot
        .lock()
        .unwrap()
        .replace(render_hook.clone())
        .is_none());
    let render_hook_guard = TextPreviewReadTestGuard(render_hook.clone());
    let render_app = router(render_state);
    let first_render_app = render_app.clone();
    let first_render = tokio::spawn(async move {
        first_render_app
            .oneshot(request(
                Method::GET,
                "/v/preview-render-race/preview?path=render-budget-preview.txt",
                "",
            ))
            .await
            .unwrap()
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while render_hook.entered.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let second_render = render_app
        .oneshot(request(
            Method::GET,
            "/v/preview-render-race/preview?path=render-budget-preview.txt",
            "",
        ))
        .await
        .unwrap();
    assert_eq!(second_render.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(render_hook.entered.load(Ordering::Acquire), 1);
    render_hook.release();
    assert_eq!(first_render.await.unwrap().status(), StatusCode::OK);
    drop(render_hook_guard);
}
