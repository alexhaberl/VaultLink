async fn api_create_monitoring_token(
    state: &AppState,
    session_cookie: &str,
    csrf: &str,
    name: &str,
) -> (i64, String, serde_json::Value) {
    let mut request = json_request(
        Method::POST,
        "/api/v2/service-tokens",
        &serde_json::json!({
            "name": name,
            "expires_at": null,
            "current_password": "correct horse battery staple"
        })
        .to_string(),
    );
    authorize_mutation(&mut request, session_cookie, csrf);
    let response = crate::web::router(state.clone())
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let body: serde_json::Value = serde_json::from_str(&response_text(response).await).unwrap();
    let id = body["id"].as_i64().unwrap();
    let token = body["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("vlk_st_v1_"));
    assert_eq!(token.len(), "vlk_st_v1_".len() + 43);
    (id, token, body)
}

fn authorize_bearer(request: &mut Request<Body>, scheme: &str, token: &str) {
    request.headers_mut().insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("{scheme} {token}")).unwrap(),
    );
}

async fn assert_service_token_is_neutral_on_public_route(
    app: &Router,
    baseline: Request<Body>,
    mut with_bearer: Request<Body>,
    token: &str,
    route: &str,
) {
    authorize_bearer(&mut with_bearer, "Bearer", token);
    let baseline = app.clone().oneshot(baseline).await.unwrap();
    let with_bearer = app.clone().oneshot(with_bearer).await.unwrap();
    assert_eq!(
        with_bearer.status(),
        baseline.status(),
        "service token changed public route status for {route}"
    );
    assert_eq!(
        response_text(with_bearer).await,
        response_text(baseline).await,
        "service token changed public route response for {route}"
    );
}

fn service_token_last_used_at(state: &AppState, token_id: i64) -> Option<String> {
    state
        .db()
        .list_service_tokens()
        .unwrap()
        .into_iter()
        .find(|token| token.id == token_id)
        .unwrap()
        .last_used_at
}

#[tokio::test]
async fn service_token_api_requires_reauthentication_and_never_lists_the_secret() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let app = crate::web::router(state.clone());

    let mut missing_csrf = json_request(
        Method::POST,
        "/api/v2/service-tokens",
        r#"{"name":"Home Assistant","expires_at":null,"current_password":"correct horse battery staple"}"#,
    );
    missing_csrf.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(missing_csrf).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    let mut invalid_name = json_request(
        Method::POST,
        "/api/v2/service-tokens",
        r#"{"name":" Home Assistant ","expires_at":null,"current_password":"correct horse battery staple"}"#,
    );
    authorize_mutation(&mut invalid_name, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(invalid_name).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    let mut wrong_password = json_request(
        Method::POST,
        "/api/v2/service-tokens",
        r#"{"name":"Home Assistant","expires_at":null,"current_password":"wrong password"}"#,
    );
    authorize_mutation(&mut wrong_password, &session_cookie, &csrf);
    let response = app.clone().oneshot(wrong_password).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_text(response).await,
        r#"{"error":{"code":"unauthorized","message":"Invalid credentials"}}"#
    );
    let (token_id, token, created) =
        api_create_monitoring_token(&state, &session_cookie, &csrf, "Home Assistant").await;
    assert_eq!(created["name"], "Home Assistant");
    assert_eq!(created["created_by"], "admin");
    assert_eq!(created["scope"], "monitoring:read");
    assert_eq!(created["status"], "active");
    assert!(created["expires_at"].is_null());
    assert!(created["last_used_at"].is_null());
    assert!(created.get("token_hash").is_none());

    let mut list = json_request(Method::GET, "/api/v2/service-tokens", "");
    list.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    let response = app.clone().oneshot(list).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let list_body = response_text(response).await;
    assert!(!list_body.contains(&token));
    assert!(!list_body.contains("token_hash"));
    let listed: serde_json::Value = serde_json::from_str(&list_body).unwrap();
    assert_eq!(listed["service_tokens"].as_array().unwrap().len(), 1);
    assert_eq!(listed["service_tokens"][0]["id"], token_id);
    assert!(listed["service_tokens"][0].get("token").is_none());

    for path in [
        "/api/v2/session/me",
        "/api/v2/files?path=",
        "/api/v2/shares",
        "/api/v2/admins",
        "/api/v2/settings",
        "/api/v2/audit",
        "/api/v2/service-tokens",
    ] {
        let mut request = json_request(Method::GET, path, "");
        authorize_bearer(&mut request, "Bearer", &token);
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "Bearer token unexpectedly authorized {path}"
        );
    }

    let mut monitoring = json_request(Method::GET, "/api/v2/monitoring/summary", "");
    authorize_bearer(&mut monitoring, "Bearer", &token);
    assert_eq!(
        app.clone().oneshot(monitoring).await.unwrap().status(),
        StatusCode::OK
    );

    let connection = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    assert_eq!(
        connection
            .execute(
                "UPDATE service_tokens SET expires_at='2000-01-01T00:00:00Z' WHERE id=?1",
                [token_id],
            )
            .unwrap(),
        1
    );
    drop(connection);
    let mut expired_list = json_request(Method::GET, "/api/v2/service-tokens", "");
    expired_list.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    let response = app.clone().oneshot(expired_list).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let expired_list: serde_json::Value =
        serde_json::from_str(&response_text(response).await).unwrap();
    assert_eq!(expired_list["service_tokens"][0]["status"], "expired");
    let mut expired = json_request(Method::GET, "/api/v2/monitoring/summary", "");
    authorize_bearer(&mut expired, "Bearer", &token);
    let response = app.clone().oneshot(expired).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_text(response).await,
        r#"{"error":{"code":"unauthorized","message":"Authentication required"}}"#
    );

    let mut delete_without_csrf = json_request(
        Method::DELETE,
        &format!("/api/v2/service-tokens/{token_id}"),
        "",
    );
    delete_without_csrf.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    assert_eq!(
        app.clone()
            .oneshot(delete_without_csrf)
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );

    let mut delete = json_request(
        Method::DELETE,
        &format!("/api/v2/service-tokens/{token_id}"),
        "",
    );
    authorize_mutation(&mut delete, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(delete).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    let mut revoked = json_request(Method::GET, "/api/v2/monitoring/summary", "");
    authorize_bearer(&mut revoked, "Bearer", &token);
    let response = app.clone().oneshot(revoked).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_text(response).await,
        r#"{"error":{"code":"unauthorized","message":"Authentication required"}}"#
    );
    assert_eq!(
        state.db().count_audit(Some("service_token_created")).unwrap(),
        1
    );
    assert_eq!(
        state.db().count_audit(Some("service_token_revoked")).unwrap(),
        1
    );
}

#[tokio::test]
async fn service_token_api_enforces_expiration_boundaries() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let password = "correct horse battery staple";
    let hash = auth::hash_password(password).unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let app = crate::web::router(state.clone());

    for (index, expires_at) in [Utc::now() - Duration::seconds(1), Utc::now()]
        .into_iter()
        .enumerate()
    {
        let body = serde_json::json!({
            "name": format!("Rejected expiry {index}"),
            "expires_at": expires_at,
            "current_password": password,
        })
        .to_string();
        let mut request = json_request(Method::POST, "/api/v2/service-tokens", &body);
        authorize_mutation(&mut request, &session_cookie, &csrf);
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert!(state.db().list_service_tokens().unwrap().is_empty());

    let future = Utc::now() + Duration::days(30);
    let future_string = future.to_rfc3339();
    let body = serde_json::json!({
        "name": "Expiring monitor",
        "expires_at": future,
        "current_password": password,
    })
    .to_string();
    let mut request = json_request(Method::POST, "/api/v2/service-tokens", &body);
    authorize_mutation(&mut request, &session_cookie, &csrf);
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    let created: serde_json::Value = serde_json::from_str(&response_text(response).await).unwrap();
    assert_eq!(created["expires_at"].as_str(), Some(future_string.as_str()));
    assert_eq!(created["status"], "active");
    assert!(created["token"].as_str().unwrap().starts_with("vlk_st_v1_"));
    assert_eq!(state.db().list_service_tokens().unwrap().len(), 1);
    assert_eq!(
        state.db().count_audit(Some("service_token_created")).unwrap(),
        1
    );
}

#[tokio::test]
async fn monitoring_authentication_is_exact_unambiguous_and_scope_checked() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let (token_id, token, _) =
        api_create_monitoring_token(&state, &session_cookie, &csrf, "HA strict auth").await;
    let app = crate::web::router(state.clone());

    let mut lower_case_scheme = json_request(Method::GET, "/api/v2/monitoring/summary", "");
    authorize_bearer(&mut lower_case_scheme, "bearer", &token);
    assert_eq!(
        app.clone()
            .oneshot(lower_case_scheme)
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    let missing = app
        .clone()
        .oneshot(json_request(Method::GET, "/api/v2/monitoring/summary", ""))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    let unauthorized_body = response_text(missing).await;
    assert_eq!(
        unauthorized_body,
        r#"{"error":{"code":"unauthorized","message":"Authentication required"}}"#
    );

    let encoded = token.strip_prefix("vlk_st_v1_").unwrap();
    for value in [
        format!("Basic {token}"),
        format!("Bearer  {token}"),
        format!("Bearer vlk_st_v1_{}", &encoded[..42]),
        format!("Bearer vlk_st_v1_{}!", &encoded[..42]),
    ] {
        let mut request = json_request(Method::GET, "/api/v2/monitoring/summary", "");
        request.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&value).unwrap(),
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{value}");
        assert_eq!(response_text(response).await, unauthorized_body, "{value}");
    }

    let mut mixed = json_request(Method::GET, "/api/v2/monitoring/summary", "");
    mixed.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    authorize_bearer(&mut mixed, "Bearer", &token);
    let response = app.clone().oneshot(mixed).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_text(response).await,
        r#"{"error":{"code":"ambiguous_authentication","message":"Ambiguous authentication"}}"#
    );

    let mut duplicate = json_request(Method::GET, "/api/v2/monitoring/summary", "");
    duplicate.headers_mut().append(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    duplicate.headers_mut().append(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("bearer {token}")).unwrap(),
    );
    let response = app.clone().oneshot(duplicate).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response_text(response)
        .await
        .contains(r#""code":"ambiguous_authentication""#));

    let mut joined = json_request(Method::GET, "/api/v2/monitoring/summary", "");
    joined.headers_mut().insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}, Bearer {token}")).unwrap(),
    );
    let response = app.clone().oneshot(joined).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response_text(response)
        .await
        .contains(r#""code":"ambiguous_authentication""#));

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
    let mut pre_mfa = json_request(Method::GET, "/api/v2/monitoring/summary", "");
    pre_mfa.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&pre_mfa_cookie).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(pre_mfa).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    let connection = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    connection
        .pragma_update(None, "ignore_check_constraints", 1)
        .unwrap();
    assert_eq!(
        connection
            .execute(
                "UPDATE service_tokens SET scope_mask=0 WHERE id=?1",
                [token_id],
            )
            .unwrap(),
        1
    );
    drop(connection);
    let mut insufficient = json_request(Method::GET, "/api/v2/monitoring/summary", "");
    authorize_bearer(&mut insufficient, "BEARER", &token);
    let response = app.oneshot(insufficient).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_text(response).await,
        r#"{"error":{"code":"insufficient_scope","message":"Service token scope is insufficient"}}"#
    );
}

#[tokio::test]
async fn monitoring_shares_admits_and_authenticates_before_parsing_query() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, _) = api_login(&state, &secret).await;
    state.replace_monitoring_limiter_for_test(crate::auth::LoginLimiter::new(
        2,
        std::time::Duration::from_secs(60),
    ));
    let app = crate::web::router(state);

    let malformed_uri = "/api/v2/monitoring/shares?limit=not-a-number";
    let unauthenticated = app
        .clone()
        .oneshot(json_request(Method::GET, malformed_uri, ""))
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    assert!(response_text(unauthenticated)
        .await
        .contains(r#""code":"unauthorized""#));

    let mut authenticated = json_request(Method::GET, malformed_uri, "");
    authenticated.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    let malformed = app.clone().oneshot(authenticated).await.unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert!(response_text(malformed)
        .await
        .contains(r#""code":"bad_request""#));

    let mut after_budget = json_request(Method::GET, "/api/v2/monitoring/shares", "");
    after_budget.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    let limited = app.oneshot(after_budget).await.unwrap();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.headers().get(header::RETRY_AFTER).unwrap(), "60");
}

#[tokio::test]
async fn monitoring_is_get_only_and_successful_reads_are_not_audited() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut state = test_state(root.path(), data.path());
    state.replace_disk_stats_cache_for_test(crate::disk_stats::DiskStatsCache::for_test(|_| {
        Ok(crate::disk_stats::DiskStats { free: 1, total: 2 })
    }));
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let (token_id, token, _) =
        api_create_monitoring_token(&state, &session_cookie, &csrf, "HA GET only").await;
    let app = crate::web::router(state.clone());
    let audit_count = state.db().count_audit(None).unwrap();

    for path in ["/api/v2/monitoring/summary", "/api/v2/monitoring/shares"] {
        let mut request = json_request(Method::HEAD, path, "");
        authorize_bearer(&mut request, "Bearer", &token);
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "HEAD unexpectedly reached monitoring authentication for {path}"
        );
    }
    assert!(service_token_last_used_at(&state, token_id).is_none());

    for path in [
        "/api/v2/monitoring/summary",
        "/api/v2/monitoring/shares?limit=1",
    ] {
        let mut request = json_request(Method::GET, path, "");
        authorize_bearer(&mut request, "Bearer", &token);
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK,
            "GET failed for {path}"
        );
    }
    assert!(service_token_last_used_at(&state, token_id).is_some());
    assert_eq!(state.db().count_audit(None).unwrap(), audit_count);
}

#[tokio::test]
async fn service_tokens_are_isolated_from_other_api_html_and_public_authority() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let (token_id, token, _) =
        api_create_monitoring_token(&state, &session_cookie, &csrf, "HA isolation").await;
    let app = crate::web::router(state.clone());
    let audit_count = state.db().count_audit(None).unwrap();

    let settings_json = serde_json::to_string(&settings_body(runtime_settings(&state))).unwrap();
    let private_api_requests = vec![
        (Method::GET, "/api/v2/session/me", String::new()),
        (
            Method::POST,
            "/api/v2/session/mfa",
            r#"{"code":"000000"}"#.to_owned(),
        ),
        (Method::POST, "/api/v2/session/logout", String::new()),
        (Method::GET, "/api/v2/files?path=", String::new()),
        (
            Method::POST,
            "/api/v2/files/directories",
            r#"{"parent":"","name":"private"}"#.to_owned(),
        ),
        (
            Method::PATCH,
            "/api/v2/files",
            r#"{"path":"old","name":"new"}"#.to_owned(),
        ),
        (
            Method::DELETE,
            "/api/v2/files",
            r#"{"path":"old","confirm_name":null}"#.to_owned(),
        ),
        (Method::GET, "/api/v2/shares", String::new()),
        (
            Method::POST,
            "/api/v2/shares",
            r#"{"path":"private","permission":"download_only"}"#.to_owned(),
        ),
        (
            Method::PATCH,
            "/api/v2/shares/1",
            r#"{"active":false}"#.to_owned(),
        ),
        (Method::DELETE, "/api/v2/shares/1", String::new()),
        (
            Method::POST,
            "/api/v2/shares/1/activate",
            String::new(),
        ),
        (
            Method::POST,
            "/api/v2/shares/1/deactivate",
            String::new(),
        ),
        (
            Method::PUT,
            "/api/v2/shares/1/password",
            r#"{"password":"private share password"}"#.to_owned(),
        ),
        (
            Method::DELETE,
            "/api/v2/shares/1/password",
            String::new(),
        ),
        (Method::GET, "/api/v2/admins", String::new()),
        (
            Method::POST,
            "/api/v2/admins",
            r#"{"username":"private-admin","password":"private admin password"}"#.to_owned(),
        ),
        (
            Method::POST,
            "/api/v2/admins/1/activate",
            String::new(),
        ),
        (
            Method::POST,
            "/api/v2/admins/1/deactivate",
            String::new(),
        ),
        (
            Method::PUT,
            "/api/v2/admins/1/password",
            r#"{"password":"private admin password"}"#.to_owned(),
        ),
        (
            Method::POST,
            "/api/v2/admins/1/totp/reset",
            String::new(),
        ),
        (Method::GET, "/api/v2/settings", String::new()),
        (Method::PUT, "/api/v2/settings", settings_json),
        (Method::GET, "/api/v2/audit", String::new()),
        (
            Method::DELETE,
            "/api/v2/audit/client-ips",
            r#"{"confirmation":"IP-DATEN LÖSCHEN"}"#.to_owned(),
        ),
        (Method::GET, "/api/v2/service-tokens", String::new()),
        (
            Method::POST,
            "/api/v2/service-tokens",
            r#"{"name":"forbidden","expires_at":null,"current_password":"correct horse battery staple"}"#.to_owned(),
        ),
        (
            Method::DELETE,
            "/api/v2/service-tokens/1",
            String::new(),
        ),
    ];
    for (method, path, body) in private_api_requests {
        let mut request = json_request(method, path, &body);
        authorize_bearer(&mut request, "Bearer", &token);
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "service token unexpectedly reached private API {path}: {}",
            response_text(response).await
        );
    }

    for path in [
        "/admin",
        "/admin/account",
        "/admin/files/download?path=private",
        "/admin/shares",
        "/admin/admins",
        "/admin/service-tokens",
        "/admin/settings",
        "/admin/audit",
    ] {
        let mut request = json_request(Method::GET, path, "");
        authorize_bearer(&mut request, "Bearer", &token);
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "service token unexpectedly reached protected HTML {path}"
        );
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/login");
    }

    let query = json_request(
        Method::GET,
        &format!("/api/v2/monitoring/summary?token={token}"),
        "",
    );
    assert_eq!(
        app.clone().oneshot(query).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let mut cookie_transport = json_request(Method::GET, "/api/v2/monitoring/summary", "");
    cookie_transport.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("{}={token}", crate::http_auth::SESSION_COOKIE)).unwrap(),
    );
    assert_eq!(
        app.clone()
            .oneshot(cookie_transport)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut alternate_header = json_request(Method::GET, "/api/v2/monitoring/summary", "");
    alternate_header.headers_mut().insert(
        "x-vaultlink-service-token",
        HeaderValue::from_str(&token).unwrap(),
    );
    assert_eq!(
        app.clone()
            .oneshot(alternate_header)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let public_token = format!("public-capability-{token_id}");
    state
        .db()
        .create_share(
            &public_token,
            None,
            "private-public-path",
            false,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            Some("opaque-password-hash"),
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let public_path = format!("/api/v2/public/shares/{public_token}");
    let baseline = app
        .clone()
        .oneshot(json_request(Method::GET, &public_path, ""))
        .await
        .unwrap();
    assert_eq!(baseline.status(), StatusCode::OK);
    let baseline_body = response_text(baseline).await;
    assert_eq!(baseline_body, r#"{"locked":true}"#);
    let mut with_bearer = json_request(Method::GET, &public_path, "");
    authorize_bearer(&mut with_bearer, "Bearer", &token);
    let with_bearer = app.clone().oneshot(with_bearer).await.unwrap();
    assert_eq!(with_bearer.status(), StatusCode::OK);
    assert_eq!(response_text(with_bearer).await, baseline_body);

    let missing_public_token = format!("missing-public-capability-{token_id}");
    for (method, suffix, body) in [
        (Method::GET, "", ""),
        (Method::POST, "/unlock", r#"{"password":"irrelevant"}"#),
        (Method::GET, "/download", ""),
        (Method::HEAD, "/download", ""),
        (Method::GET, "/preview", ""),
        (Method::GET, "/preview/raw", ""),
        (Method::HEAD, "/preview/raw", ""),
        (Method::GET, "/download.zip", ""),
    ] {
        let route = format!("/api/v2/public/shares/{missing_public_token}{suffix}");
        assert_service_token_is_neutral_on_public_route(
            &app,
            json_request(method.clone(), &route, body),
            json_request(method, &route, body),
            &token,
            &route,
        )
        .await;
    }
    let upload_route = format!("/api/v2/public/shares/{missing_public_token}/upload");
    assert_service_token_is_neutral_on_public_route(
        &app,
        multipart_request(&upload_route, "neutral.txt", b"public baseline"),
        multipart_request(&upload_route, "neutral.txt", b"public baseline"),
        &token,
        &upload_route,
    )
    .await;

    let mut health = json_request(Method::GET, "/api/v2/health/live", "");
    authorize_bearer(&mut health, "Bearer", &token);
    assert_eq!(app.oneshot(health).await.unwrap().status(), StatusCode::OK);
    assert!(service_token_last_used_at(&state, token_id).is_none());
    assert_eq!(state.db().count_audit(None).unwrap(), audit_count);
}

#[tokio::test]
async fn monitoring_summary_keeps_metrics_when_storage_probe_fails() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut state = test_state(root.path(), data.path());
    state.replace_disk_stats_cache_for_test(crate::disk_stats::DiskStatsCache::for_test(|_| {
        Err(std::io::Error::other("injected storage probe failure"))
    }));
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    state
        .db()
        .create_share(
            "storage-failure-summary-share",
            None,
            "summary-path",
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
    let (session_cookie, _) = api_login(&state, &secret).await;
    let mut request = json_request(Method::GET, "/api/v2/monitoring/summary", "");
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    let response = crate::web::router(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let summary: serde_json::Value = serde_json::from_str(&response_text(response).await).unwrap();
    assert!(summary["storage"].is_null());
    assert_eq!(summary["shares"]["total"], 1);
    assert_eq!(summary["shares"]["available"], 1);
    assert_eq!(
        summary["transfers"]["month"],
        Utc::now().format("%Y-%m").to_string()
    );
    assert_eq!(summary["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn monitoring_contract_is_redacted_filtered_and_cursor_paginated() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut state = test_state(root.path(), data.path());
    state.replace_disk_stats_cache_for_test(crate::disk_stats::DiskStatsCache::for_test(|_| {
        Ok(crate::disk_stats::DiskStats {
            free: 123,
            total: 456,
        })
    }));
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();

    let available_id = state
        .db()
        .create_share_with_upload_limits(
            "monitor-available-secret",
            Some("monitor-available-alias"),
            "available-folder",
            true,
            &Permission::DownloadUpload,
            None,
            None,
            Some(10),
            Some(100),
            Some(5),
            1,
            Some("redacted-password-hash"),
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let inactive_id = state
        .db()
        .create_share(
            "monitor-inactive-secret",
            None,
            "inactive-file",
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
    state.db().set_share_active(inactive_id, false).unwrap();
    let expired_id = state
        .db()
        .create_share(
            "monitor-expired-secret",
            None,
            "expired-file",
            false,
            &Permission::DownloadOnly,
            Some(Utc::now() - Duration::days(1)),
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let limited_id = state
        .db()
        .create_share(
            "monitor-limited-secret",
            None,
            "limited-file",
            false,
            &Permission::DownloadOnly,
            None,
            Some(2),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let connection = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    connection
        .execute(
            "INSERT INTO public_upload_usage(share_id,uploaded_bytes,uploaded_files) VALUES(?1,40,2)",
            [available_id],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE shares SET download_count=2 WHERE id=?1",
            [limited_id],
        )
        .unwrap();
    drop(connection);

    let (session_cookie, _) = api_login(&state, &secret).await;
    let app = crate::web::router(state.clone());
    let authenticated = |uri: &str| {
        let mut request = json_request(Method::GET, uri, "");
        request.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        request
    };

    let summary = app
        .clone()
        .oneshot(authenticated("/api/v2/monitoring/summary"))
        .await
        .unwrap();
    assert_eq!(summary.status(), StatusCode::OK);
    let summary: serde_json::Value = serde_json::from_str(&response_text(summary).await).unwrap();
    assert!(DateTime::parse_from_rfc3339(summary["generated_at"].as_str().unwrap()).is_ok());
    assert_eq!(summary["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(summary["shares"]["total"], 4);
    assert_eq!(summary["shares"]["available"], 1);
    assert_eq!(summary["shares"]["inactive"], 1);
    assert_eq!(summary["shares"]["expired"], 1);
    assert_eq!(summary["shares"]["download_limit_reached"], 1);
    assert_eq!(summary["shares"]["protected"], 1);
    assert_eq!(
        summary["transfers"]["month"],
        Utc::now().format("%Y-%m").to_string()
    );
    assert_eq!(summary["transfers"]["download"], 0);
    assert_eq!(summary["transfers"]["zip_download"], 0);
    assert_eq!(summary["transfers"]["preview"], 0);
    assert!(DateTime::parse_from_rfc3339(
        summary["transfers"]["statistics_started_at"]
            .as_str()
            .unwrap()
    )
    .is_ok());
    assert_eq!(summary["storage"]["free_bytes"], 123);
    assert_eq!(summary["storage"]["total_bytes"], 456);

    let first = app
        .clone()
        .oneshot(authenticated("/api/v2/monitoring/shares?limit=2"))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_text = response_text(first).await;
    for secret in [
        "monitor-available-secret",
        "monitor-inactive-secret",
        "monitor-expired-secret",
        "monitor-limited-secret",
        "monitor-available-alias",
        "available-folder",
        "redacted-password-hash",
    ] {
        assert!(!first_text.contains(secret));
    }
    for forbidden_key in ["token", "url", "alias", "relative_path", "password_hash"] {
        assert!(!first_text.contains(&format!(r#""{forbidden_key}""#)));
    }
    let first: serde_json::Value = serde_json::from_str(&first_text).unwrap();
    let first_shares = first["shares"].as_array().unwrap();
    assert_eq!(first_shares.len(), 2);
    assert_eq!(first_shares[0]["id"], limited_id);
    assert_eq!(first_shares[0]["status"], "download_limit_reached");
    assert_eq!(first_shares[0]["download_count"], 2);
    assert_eq!(first_shares[0]["max_downloads"], 2);
    assert_eq!(first_shares[1]["id"], expired_id);
    assert_eq!(first_shares[1]["status"], "expired");
    assert_eq!(first["next_cursor"], expired_id);

    let second = app
        .clone()
        .oneshot(authenticated(&format!(
            "/api/v2/monitoring/shares?limit=2&cursor={expired_id}"
        )))
        .await
        .unwrap();
    let second: serde_json::Value = serde_json::from_str(&response_text(second).await).unwrap();
    assert_eq!(second["shares"][0]["id"], inactive_id);
    assert_eq!(second["shares"][0]["status"], "inactive");
    assert_eq!(second["shares"][1]["id"], available_id);
    assert_eq!(second["shares"][1]["status"], "available");
    assert!(second["next_cursor"].is_null());

    let available = app
        .clone()
        .oneshot(authenticated(
            "/api/v2/monitoring/shares?status=available&limit=200",
        ))
        .await
        .unwrap();
    let available: serde_json::Value =
        serde_json::from_str(&response_text(available).await).unwrap();
    assert_eq!(available["shares"].as_array().unwrap().len(), 1);
    assert_eq!(available["shares"][0]["id"], available_id);
    assert_eq!(available["shares"][0]["permission"], "download_upload");
    assert_eq!(available["shares"][0]["is_directory"], true);
    assert_eq!(available["shares"][0]["password_protected"], true);
    assert_eq!(available["shares"][0]["max_upload_size_bytes"], 10);
    assert_eq!(available["shares"][0]["uploaded_bytes"], 40);
    assert_eq!(available["shares"][0]["max_upload_total_size_bytes"], 100);
    assert_eq!(available["shares"][0]["uploaded_files"], 2);
    assert_eq!(available["shares"][0]["max_upload_files"], 5);

    for uri in [
        "/api/v2/monitoring/shares?limit=0",
        "/api/v2/monitoring/shares?limit=201",
        "/api/v2/monitoring/shares?cursor=0",
        "/api/v2/monitoring/shares?status=unknown",
    ] {
        let response = app.clone().oneshot(authenticated(uri)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        assert!(response_text(response)
            .await
            .contains(r#""code":"bad_request""#));
    }
}

#[tokio::test]
async fn monitoring_rate_limit_is_per_effective_client_ip() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut state = test_state(root.path(), data.path());
    state.replace_disk_stats_cache_for_test(crate::disk_stats::DiskStatsCache::for_test(|_| {
        Ok(crate::disk_stats::DiskStats { free: 1, total: 2 })
    }));
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, _) = api_login(&state, &secret).await;
    let app = crate::web::router(state);
    let request = |peer: &str| {
        let mut request = json_request(Method::GET, "/api/v2/monitoring/summary", "");
        request.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        );
        request.extensions_mut().insert(ConnectInfo(
            format!("{peer}:40000").parse::<SocketAddr>().unwrap(),
        ));
        request
    };

    for attempt in 1..=120 {
        assert_eq!(
            app.clone()
                .oneshot(request("127.0.0.1"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK,
            "attempt {attempt}"
        );
    }
    let limited = app.clone().oneshot(request("127.0.0.1")).await.unwrap();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.headers().get(header::RETRY_AFTER).unwrap(), "60");
    assert_eq!(
        response_text(limited).await,
        r#"{"error":{"code":"rate_limited","message":"Too many monitoring requests"}}"#
    );
    assert_eq!(
        app.oneshot(request("127.0.0.2")).await.unwrap().status(),
        StatusCode::OK
    );
}

#[test]
fn request_timeout_has_a_stable_api_error_code() {
    assert_eq!(
        status_code_name(StatusCode::REQUEST_TIMEOUT),
        "request_timeout"
    );
}

#[tokio::test]
async fn reported_internal_error_keeps_the_generic_api_contract() {
    let reported = crate::internal_reporting::report_invariant(
        crate::internal_reporting::InternalOperation::ApiShareUpdateResultInvariant,
    );
    let response = ApiError::from(reported).into_response();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert!(!response.headers().contains_key(header::RETRY_AFTER));
    assert_eq!(
        String::from_utf8(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec()
        )
        .unwrap(),
        r#"{"error":{"code":"internal_error","message":"Internal error"}}"#
    );
}
