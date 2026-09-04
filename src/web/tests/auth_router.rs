#[tokio::test]
async fn disk_stats_uses_target_path() {
    let root = tempfile::tempdir().unwrap();
    let stats = crate::disk_stats::DiskStatsCache::new()
        .get(root.path())
        .await
        .expect("statvfs must work for tempdir");
    assert!(stats.total > 0);
    assert!(stats.free > 0);
}

#[tokio::test]
async fn create_new_prevents_upload_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("existing.txt");
    tokio::fs::write(&path, b"original").await.unwrap();
    let result = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .await;
    assert_eq!(
        result.unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(tokio::fs::read(&path).await.unwrap(), b"original");
}

#[tokio::test]
async fn webauthn_mfa_start_is_rate_limited_before_credential_work() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut state = test_state(root.path(), data.path());
    state.replace_login_limiter_for_test(crate::auth::LoginLimiter::new(
        1,
        std::time::Duration::from_secs(300),
    ));
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "webauthn-pending",
            1,
            "webauthn-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    let app = router(state);

    let request = || {
        Request::builder()
            .method(Method::POST)
            .uri("/mfa/security-key/start")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, "vaultlink_session=webauthn-pending")
            .body(Body::from(r#"{"csrf":"webauthn-csrf"}"#))
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        app.oneshot(request()).await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn router_recovers_invalid_runtime_and_webauthn_snapshots_after_poisoning() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state
        .db()
        .create_admin(
            "admin",
            &auth::hash_password("a sufficiently long password").unwrap(),
            &auth::new_totp_secret(),
        )
        .unwrap();
    state
        .db()
        .create_session(
            "poison-recovery-session",
            1,
            "poison-recovery-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("poison-recovery-session").unwrap();

    state.poison_runtime_for_test();
    state.poison_webauthn_for_test();

    let app = router(state.clone());
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/admin/account/security-keys/register/start")
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::COOKIE,
            "vaultlink_session=poison-recovery-session",
        )
        .body(Body::from(
            r#"{"csrf":"poison-recovery-csrf","current_password":"a sufficiently long password","label":"Recovery key"}"#,
        ))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!state.runtime_is_poisoned_for_test());
    assert!(!state.webauthn_is_poisoned_for_test());
    assert_eq!(
        runtime_settings(&state).max_upload_size,
        state.config().storage.max_upload_size
    );
}

#[tokio::test]
async fn http_login_mfa_csrf_session_and_logout() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    state
        .db()
        .create_admin(
            "admin",
            &auth::hash_password("a sufficiently long password").unwrap(),
            &secret,
        )
        .unwrap();
    let app = router(state.clone());

    let invalid = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/login",
            "username=admin&password=wrong",
        ))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);

    let login = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/login",
            "username=admin&password=a%20sufficiently%20long%20password",
        ))
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    let pre_mfa_cookie = login
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let pre_mfa_session_token = pre_mfa_cookie.split_once('=').unwrap().1.to_string();
    let pre_mfa_csrf = state
        .db()
        .session(&pre_mfa_session_token)
        .unwrap()
        .unwrap()
        .csrf_token;
    let mut mfa_page_request = request(Method::GET, "/mfa", "");
    mfa_page_request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&pre_mfa_cookie).unwrap(),
    );
    let mfa_page = response_text(app.clone().oneshot(mfa_page_request).await.unwrap()).await;
    assert!(mfa_page.contains(&format!("name=\"csrf\" value=\"{pre_mfa_csrf}\"")));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let code = auth::totp_code(&secret, now / 30).unwrap();
    let mut wrong_mfa_csrf = request(Method::POST, "/mfa", &format!("csrf=wrong&code={code}"));
    wrong_mfa_csrf.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&pre_mfa_cookie).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(wrong_mfa_csrf).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut mfa_request = request(
        Method::POST,
        "/mfa",
        &format!("csrf={pre_mfa_csrf}&code={code}"),
    );
    mfa_request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&pre_mfa_cookie).unwrap(),
    );
    let mfa = app.clone().oneshot(mfa_request).await.unwrap();
    assert_eq!(mfa.status(), StatusCode::SEE_OTHER);
    let cookie = mfa
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let session_token = cookie.split_once('=').unwrap().1.to_string();
    assert!(state.db().session(&pre_mfa_session_token).unwrap().is_none());

    let mut admin_request = request(Method::GET, "/admin", "");
    admin_request
        .headers_mut()
        .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
    let admin = app.clone().oneshot(admin_request).await.unwrap();
    assert_eq!(admin.status(), StatusCode::OK);
    assert_eq!(
        admin.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );

    let mut bad_csrf = request(Method::POST, "/logout", "csrf=wrong");
    bad_csrf
        .headers_mut()
        .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
    assert_eq!(
        app.clone().oneshot(bad_csrf).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let csrf = state
        .db()
        .session(&session_token)
        .unwrap()
        .unwrap()
        .csrf_token;
    let mut logout_request = request(Method::POST, "/logout", &format!("csrf={csrf}"));
    logout_request
        .headers_mut()
        .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
    assert_eq!(
        app.clone().oneshot(logout_request).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    assert!(state.db().session(&session_token).unwrap().is_none());
}
