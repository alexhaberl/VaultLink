#[test]
fn session_bound_outcomes_have_an_explicit_api_contract() {
    assert_eq!(
        session_bound(crate::db::SessionBound::Authorized(7)).unwrap(),
        7
    );
    let error = session_bound::<()>(crate::db::SessionBound::SessionUnavailable).unwrap_err();
    assert_eq!(error.status, StatusCode::UNAUTHORIZED);
    assert_eq!(error.code, "session_revoked");
}

#[cfg(panic = "unwind")]
#[tokio::test]
async fn panic_payload_is_not_returned_by_the_api_boundary() {
    let response = api_panic_response(Box::new("secret\r\nforged-log-line".to_owned()));
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response_text(response).await,
        r#"{"error":{"code":"internal_error","message":"Internal error"}}"#
    );
}

#[tokio::test]
async fn health_reports_the_exact_package_version() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let app = crate::web::router(test_state(root.path(), data.path()));
    for path in [
        "/api/v2/health",
        "/api/v2/health/live",
        "/api/v2/health/ready",
    ] {
        let response = app
            .clone()
            .oneshot(json_request(Method::GET, path, ""))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            response_text(response).await,
            format!(r#"{{"ok":true,"version":"{}"}}"#, env!("CARGO_PKG_VERSION")),
            "{path}"
        );
    }
}

#[tokio::test]
async fn liveness_stays_up_when_readiness_dependencies_fail() {
    for component in ["database", "storage"] {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let mut state = test_state(root.path(), data.path());
        let (probe, calls) =
            crate::readiness::ReadinessProbe::for_test(std::time::Duration::ZERO, Some(component));
        state.replace_readiness_for_test(probe);
        let app = crate::web::router(state);

        let ready = app
            .clone()
            .oneshot(json_request(Method::GET, "/api/v2/health/ready", ""))
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response_text(ready).await,
            format!(
                r#"{{"ok":false,"version":"{}"}}"#,
                env!("CARGO_PKG_VERSION")
            )
        );
        assert_eq!(
            app.clone()
                .oneshot(json_request(Method::GET, "/api/v2/health/ready", "",))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        for path in ["/api/v2/health", "/api/v2/health/live"] {
            assert_eq!(
                app.clone()
                    .oneshot(json_request(Method::GET, path, ""))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn readiness_is_single_flight_cached_and_times_out() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut state = test_state(root.path(), data.path());
    let (probe, calls) =
        crate::readiness::ReadinessProbe::for_test(std::time::Duration::from_millis(100), None);
    state.replace_readiness_for_test(probe);
    let app = crate::web::router(state);
    let responses = futures_util::future::join_all((0..8).map(|_| {
        app.clone()
            .oneshot(json_request(Method::GET, "/api/v2/health/ready", ""))
    }))
    .await;
    assert!(responses
        .into_iter()
        .all(|response| response.unwrap().status() == StatusCode::OK));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    assert_eq!(
        app.oneshot(json_request(Method::GET, "/api/v2/health/ready", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);

    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut state = test_state(root.path(), data.path());
    let (probe, timeout_calls) =
        crate::readiness::ReadinessProbe::for_test(std::time::Duration::from_millis(2_100), None);
    state.replace_readiness_for_test(probe);
    let response = crate::web::router(state)
        .oneshot(json_request(Method::GET, "/api/v2/health/ready", ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(timeout_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn error_normalization_preserves_protocol_headers() {
    let app = Router::new()
        .route(
            "/range",
            get(|| async {
                let mut response =
                    (StatusCode::RANGE_NOT_SATISFIABLE, "invalid range").into_response();
                response.headers_mut().insert(
                    header::CONTENT_RANGE,
                    HeaderValue::from_static("bytes */10"),
                );
                response
            }),
        )
        .layer(middleware::from_fn(normalize_api_errors));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/range")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        response.headers().get(header::CONTENT_RANGE).unwrap(),
        "bytes */10"
    );
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json; charset=utf-8"
    );
}

#[tokio::test]
async fn argon2_overload_is_identical_for_known_and_unknown_logins() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state
        .db()
        .create_admin("admin", &hash, &auth::new_totp_secret())
        .unwrap();
    state
        .admin_login_limiter()
        .replace_active_admins(state.db().active_admin_usernames().unwrap());
    let _capacity = state.acquire_all_argon2_for_test().await;
    let app = crate::web::router(state.clone());

    let known = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/v2/session/login",
            r#"{"username":"admin","password":"wrong password"}"#,
        ))
        .await
        .unwrap();
    let unknown = app
        .oneshot(json_request(
            Method::POST,
            "/api/v2/session/login",
            r#"{"username":"absent","password":"wrong password"}"#,
        ))
        .await
        .unwrap();

    assert_eq!(known.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(unknown.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(known.headers().get(header::RETRY_AFTER).unwrap(), "1");
    assert_eq!(unknown.headers().get(header::RETRY_AFTER).unwrap(), "1");
    assert_eq!(response_text(known).await, response_text(unknown).await);
}

#[tokio::test]
async fn known_and_unknown_login_errors_are_identical_english_with_a_german_cookie() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state
        .db()
        .create_admin("admin", &hash, &auth::new_totp_secret())
        .unwrap();
    state
        .admin_login_limiter()
        .replace_active_admins(state.db().active_admin_usernames().unwrap());
    let app = crate::web::router(state);

    let login = |username: &str| {
        let mut request = json_request(
            Method::POST,
            "/api/v2/session/login",
            &format!(r#"{{"username":"{username}","password":"wrong password"}}"#),
        );
        request.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_static("vaultlink_locale=de"),
        );
        request.headers_mut().insert(
            header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("de-AT,de;q=0.9"),
        );
        request
    };

    let known = app.clone().oneshot(login("admin")).await.unwrap();
    let unknown = app.oneshot(login("absent")).await.unwrap();
    assert_eq!(known.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);
    let known_body = response_text(known).await;
    let unknown_body = response_text(unknown).await;
    assert_eq!(known_body, unknown_body);
    assert_eq!(
        known_body,
        r#"{"error":{"code":"invalid_credentials","message":"Invalid credentials"}}"#
    );
}

async fn api_login(state: &AppState, secret: &str) -> (String, String) {
    let app = crate::web::router(state.clone());
    let login = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/v2/session/login",
            r#"{"username":"admin","password":"correct horse battery staple"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let pre_mfa_cookie = cookie(&login);
    let login_body = response_text(login).await;
    let pre_mfa_csrf = json_string_value(&login_body, "csrf_token");
    let mfa_code = current_totp(secret);
    let mut missing_csrf = json_request(
        Method::POST,
        "/api/v2/session/mfa",
        &format!(r#"{{"code":"{mfa_code}"}}"#),
    );
    missing_csrf.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&pre_mfa_cookie).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(missing_csrf).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut mfa = json_request(
        Method::POST,
        "/api/v2/session/mfa",
        &format!(r#"{{"code":"{mfa_code}"}}"#),
    );
    mfa.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&pre_mfa_cookie).unwrap(),
    );
    mfa.headers_mut().insert(
        "x-csrf-token",
        HeaderValue::from_str(&pre_mfa_csrf).unwrap(),
    );
    let mfa = app.oneshot(mfa).await.unwrap();
    assert_eq!(mfa.status(), StatusCode::OK);
    let session_cookie = cookie(&mfa);
    let mfa_body = response_text(mfa).await;
    let csrf = json_string_value(&mfa_body, "csrf_token");
    (session_cookie, csrf)
}

#[tokio::test]
async fn api_session_requires_mfa_and_csrf() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();

    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let app = crate::web::router(state.clone());
    let mut me = json_request(Method::GET, "/api/v2/session/me", "");
    me.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    let me = app.clone().oneshot(me).await.unwrap();
    assert_eq!(me.status(), StatusCode::OK);
    let body = response_text(me).await;
    assert!(body.contains(r#""username":"admin""#));
    assert!(body.contains(&csrf));

    let mut logout_without_csrf = json_request(Method::POST, "/api/v2/session/logout", "{}");
    logout_without_csrf.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    let response = app.oneshot(logout_without_csrf).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains(r#""code":"forbidden""#));
    assert!(body.contains(r#""message":"Request forbidden""#));
}

#[tokio::test]
async fn api_rejects_reusing_one_totp_code_for_two_sessions() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    let app = crate::web::router(state.clone());

    let mut pending_sessions = Vec::new();
    for _ in 0..2 {
        let login = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/api/v2/session/login",
                r#"{"username":"admin","password":"correct horse battery staple"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let session_cookie = cookie(&login);
        let login_body = response_text(login).await;
        pending_sessions.push((session_cookie, json_string_value(&login_body, "csrf_token")));
    }

    let code = current_totp(&secret);
    for (index, (session_cookie, csrf)) in pending_sessions.into_iter().enumerate() {
        let mut request = json_request(
            Method::POST,
            "/api/v2/session/mfa",
            &format!(r#"{{"code":"{code}"}}"#),
        );
        request.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        request
            .headers_mut()
            .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            if index == 0 {
                StatusCode::OK
            } else {
                StatusCode::UNAUTHORIZED
            }
        );
    }
}
