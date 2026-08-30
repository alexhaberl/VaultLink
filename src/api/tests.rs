use super::*;
use crate::config::{Config, Logging, ReverseProxy, Security, Server, ServerMode, Storage, Tls};
use axum::{
    body::{to_bytes, Body},
    http::{Method, Request},
};
use chrono::{DateTime, Duration, Utc};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;

fn test_state(root: &Path, data: &Path) -> AppState {
    AppState::new(Config {
        server: Server {
            mode: ServerMode::Development,
            listen_address: "127.0.0.1:8080".into(),
            public_base_url: "http://localhost:8080".into(),
            production_mode: false,
        },
        storage: Storage {
            root_mount_path: root.into(),
            data_directory: data.into(),
            internal_directory: Some(root.join(crate::config::DEFAULT_INTERNAL_DIRECTORY_NAME)),
            require_mount: false,
            external_writers: false,
            allow_external_writer_replace: false,
            expected_filesystem_type: None,
            expected_mount_source: None,
            max_upload_size: 1_000_000,
            max_zip_size: 1_000_000_000,
            max_zip_files: 100,
            max_search_entries: 1000,
            max_search_results: 100,
            max_preview_size: 1_000_000,
            preview_extensions: vec!["txt".into(), "md".into()],
            image_preview_extensions: vec!["jpg".into(), "png".into()],
            pdf_preview_enabled: true,
            max_media_preview_size: 100_000_000,
            blocked_extensions: vec!["exe".into()],
        },
        reverse_proxy: ReverseProxy::default(),
        tls: Tls::default(),
        security: Security {
            secure_cookie: false,
            ..Default::default()
        },
        logging: Logging::default(),
    })
    .unwrap()
}

fn json_request(method: Method, uri: &str, body: &str) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    request
}

fn multipart_request(uri: &str, name: &str, content: &[u8]) -> Request<Body> {
    let boundary = "vaultlink-api-test-boundary";
    let mut body = Vec::new();
    body.extend_from_slice(format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        ).as_bytes());
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    request
}

async fn response_text(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

fn json_string_value(body: &str, key: &str) -> String {
    let marker = format!("\"{key}\":\"");
    let start = body.find(&marker).expect("json key") + marker.len();
    let end = body[start..].find('"').expect("json value end") + start;
    body[start..end].to_string()
}

fn json_i64_value(body: &str, key: &str) -> i64 {
    let marker = format!("\"{key}\":");
    let start = body.find(&marker).expect("json key") + marker.len();
    let end = body[start..]
        .find(|c: char| !c.is_ascii_digit())
        .map(|offset| start + offset)
        .unwrap_or(body.len());
    body[start..end].parse().unwrap()
}

fn cookie(response: &Response) -> String {
    response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

fn current_totp(secret: &str) -> String {
    let step = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;
    auth::totp_code(secret, step).unwrap()
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
        state.readiness = probe;
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
    state.readiness = probe;
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
    state.readiness = probe;
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
        .db
        .create_admin("admin", &hash, &auth::new_totp_secret())
        .unwrap();
    state
        .admin_login_limiter
        .replace_active_admins(state.db.active_admin_usernames().unwrap());
    let _capacity = state
        .argon2_admission
        .clone()
        .acquire_many_owned(crate::MAX_CONCURRENT_ARGON2_OPERATIONS as u32)
        .await
        .unwrap();
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
        .db
        .create_admin("admin", &hash, &auth::new_totp_secret())
        .unwrap();
    state
        .admin_login_limiter
        .replace_active_admins(state.db.active_admin_usernames().unwrap());
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
    state.db.create_admin("admin", &hash, &secret).unwrap();

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
    state.db.create_admin("admin", &hash, &secret).unwrap();
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

#[tokio::test]
async fn api_creates_share_and_hides_secrets() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    std::fs::write(root.path().join("docs/readme.txt"), "hello").unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db.create_admin("admin", &hash, &secret).unwrap();
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
        .db
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
    let audit_events = state.db.list_audit(Some("share_created"), 10, 0).unwrap();
    let detail = audit_events[0].detail.as_deref().unwrap();
    assert!(detail.contains("path=docs"));
    assert!(detail.contains("permission=download_upload"));
    assert!(detail.contains("alias=docs-api-123"));
    assert!(detail.contains("transfer_limit=5"));
    assert!(detail.contains("password_protected=true"));
    assert!(detail.contains("overwrite_allowed=true"));

    let share_id = json_i64_value(&body, "id");
    let audit_count = state.db.count_audit(None).unwrap();
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
    assert_eq!(state.db.count_audit(None).unwrap(), audit_count);

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
    assert!(state.db.list_shares().unwrap().is_empty());

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
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_session(
            "session-token",
            1,
            "csrf-token",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db.verify_mfa("session-token").unwrap();
    let app = crate::web::router(state.clone());
    let _storage_guard = state.storage_mutation.lock().await;
    let _argon2_capacity = state
        .argon2_admission
        .clone()
        .acquire_many_owned(crate::MAX_CONCURRENT_ARGON2_OPERATIONS as u32)
        .await
        .unwrap();
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
    assert!(state.db.list_shares().unwrap().is_empty());
}

#[tokio::test]
async fn external_writers_reject_api_overwrite_configuration() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    let mut state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db.create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let mut config = (*state.config).clone();
    config.storage.external_writers = true;
    state.config = std::sync::Arc::new(config);
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
        .db
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
    state.db.set_share_active(share_id, false).unwrap();
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
    assert!(!state.db.list_shares().unwrap()[0].active);
}

#[tokio::test]
async fn external_writer_replace_opt_in_allows_api_overwrite_configuration() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    let mut state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db.create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let mut config = (*state.config).clone();
    config.storage.external_writers = true;
    config.storage.allow_external_writer_replace = true;
    state.config = std::sync::Arc::new(config);
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
    assert!(state.db.list_shares().unwrap()[0]
        .upload_conflict_strategy
        .can_overwrite());
}

#[tokio::test]
async fn api_admin_and_settings_flows_are_csrf_protected() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db.create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let app = crate::web::router(state.clone());

    let mut create_admin = json_request(
        Method::POST,
        "/api/v2/admins",
        r#"{"username":"ops","password":"another correct horse password"}"#,
    );
    create_admin.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    create_admin
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    let response = app.clone().oneshot(create_admin).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains(r#""username":"ops""#));
    assert!(body.contains("otpauth://totp/VaultLink:ops"));
    let ops_id = json_i64_value(&body, "id");
    assert!(state.admin_login_limiter.has_active_admin("OPS"));

    let mut deactivate = json_request(
        Method::POST,
        &format!("/api/v2/admins/{ops_id}/deactivate"),
        "{}",
    );
    deactivate.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    let response = app.clone().oneshot(deactivate).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains(r#""message":"Request forbidden""#));

    let mut list = json_request(Method::GET, "/api/v2/admins", "");
    list.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    let response = app.clone().oneshot(list).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response_text(response)
        .await
        .contains(r#""username":"ops""#));

    let mut deactivate = json_request(
        Method::POST,
        &format!("/api/v2/admins/{ops_id}/deactivate"),
        "{}",
    );
    authorize_mutation(&mut deactivate, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(deactivate).await.unwrap().status(),
        StatusCode::OK
    );
    assert!(!state.admin_login_limiter.has_active_admin("ops"));

    let mut activate = json_request(
        Method::POST,
        &format!("/api/v2/admins/{ops_id}/activate"),
        "{}",
    );
    authorize_mutation(&mut activate, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(activate).await.unwrap().status(),
        StatusCode::OK
    );
    assert!(state.admin_login_limiter.has_active_admin("ops"));

    let mut reset_password = json_request(
        Method::PUT,
        &format!("/api/v2/admins/{ops_id}/password"),
        r#"{"password":"rotated correct horse password"}"#,
    );
    authorize_mutation(&mut reset_password, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(reset_password).await.unwrap().status(),
        StatusCode::OK
    );

    let mut reset_totp = json_request(
        Method::POST,
        &format!("/api/v2/admins/{ops_id}/totp/reset"),
        "{}",
    );
    authorize_mutation(&mut reset_totp, &session_cookie, &csrf);
    let response = app.clone().oneshot(reset_totp).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains(r#""username":"ops""#));
    assert!(body.contains("otpauth://totp/VaultLink:ops"));

    let mut self_deactivate = json_request(Method::POST, "/api/v2/admins/1/deactivate", "{}");
    authorize_mutation(&mut self_deactivate, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(self_deactivate).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    let mut missing = json_request(Method::POST, "/api/v2/admins/999999/activate", "{}");
    authorize_mutation(&mut missing, &session_cookie, &csrf);
    assert_eq!(
        app.oneshot(missing).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn api_settings_are_canonical_and_restart_safe() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let config = state.config.as_ref().clone();
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db.create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let app = crate::web::router(state.clone());
    let original_webauthn = state.webauthn.read().unwrap().instance_id();

    let mut invalid_body = settings_body(runtime_settings(&state));
    invalid_body.public_base_url.clear();
    let invalid_json = serde_json::to_string(&invalid_body).unwrap();
    let mut invalid = json_request(Method::PUT, "/api/v2/settings", &invalid_json);
    invalid.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    invalid
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    assert_eq!(
        app.clone().oneshot(invalid).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert!(state.db.runtime_settings().unwrap().is_empty());

    let mut valid_body = settings_body(runtime_settings(&state));
    valid_body.public_base_url = "http://localhost:8081/".into();
    valid_body.blocked_extensions = vec!["EXE, .SH".into()];
    valid_body.audit_client_ip_enabled = Some(true);
    let valid_json = serde_json::to_string(&valid_body).unwrap();
    let mut valid = json_request(Method::PUT, "/api/v2/settings", &valid_json);
    valid.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    valid
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    let response = app.clone().oneshot(valid).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response_text(response)
        .await
        .contains(r#""audit_client_ip_enabled":true"#));
    let current = runtime_settings(&state);
    assert_eq!(current.public_base_url, "http://localhost:8081");
    assert_eq!(current.blocked_extensions, ["exe", "sh"]);
    assert!(current.audit_client_ip_enabled);
    assert_ne!(
        state.webauthn.read().unwrap().instance_id(),
        original_webauthn
    );

    let mut legacy_json = serde_json::to_value(settings_body(current)).unwrap();
    legacy_json
        .as_object_mut()
        .unwrap()
        .remove("audit_client_ip_enabled");
    let mut legacy_update = json_request(
        Method::PUT,
        "/api/v2/settings",
        &serde_json::to_string(&legacy_json).unwrap(),
    );
    legacy_update.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    legacy_update
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    assert_eq!(
        app.clone().oneshot(legacy_update).await.unwrap().status(),
        StatusCode::OK
    );
    assert!(runtime_settings(&state).audit_client_ip_enabled);

    drop(app);
    drop(state);
    let restarted = AppState::new(config).unwrap();
    let restarted = runtime_settings(&restarted);
    assert_eq!(restarted.public_base_url, "http://localhost:8081");
    assert_eq!(restarted.blocked_extensions, ["exe", "sh"]);
    assert!(restarted.audit_client_ip_enabled);
}

#[tokio::test]
async fn api_audit_client_ips_are_opt_in_and_can_be_deleted_only_when_disabled() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db.create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    state
        .db
        .audit_with_client_ip("admin", "client_ip_test", None, None, Some("203.0.113.10"))
        .unwrap();
    assert_eq!(state.db.count_audit_client_ips().unwrap(), 1);
    let app = crate::web::router(state.clone());

    let mut list_disabled = json_request(Method::GET, "/api/v2/audit", "");
    list_disabled.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    let response = app.clone().oneshot(list_disabled).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains(r#""client_ip_enabled":false"#));
    assert!(!body.contains(r#""client_ip":"#));
    assert!(!body.contains("203.0.113.10"));

    state.runtime.write().unwrap().audit_client_ip_enabled = true;
    let mut list_enabled = json_request(Method::GET, "/api/v2/audit", "");
    list_enabled.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    let response = app.clone().oneshot(list_enabled).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains(r#""client_ip_enabled":true"#));
    assert!(body.contains(r#""client_ip":"203.0.113.10""#));

    let mut wrong_confirmation = json_request(
        Method::DELETE,
        "/api/v2/audit/client-ips",
        r#"{"confirmation":"LÖSCHEN"}"#,
    );
    wrong_confirmation.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    wrong_confirmation
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    let response = app.clone().oneshot(wrong_confirmation).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response_text(response)
        .await
        .contains("confirmation_required"));
    assert_eq!(state.db.count_audit_client_ips().unwrap(), 1);

    let mut delete_enabled = json_request(
        Method::DELETE,
        "/api/v2/audit/client-ips",
        r#"{"confirmation":"IP-DATEN LÖSCHEN"}"#,
    );
    delete_enabled.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    delete_enabled
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    let response = app.clone().oneshot(delete_enabled).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(response_text(response)
        .await
        .contains("client_ip_logging_enabled"));
    assert_eq!(state.db.count_audit_client_ips().unwrap(), 1);

    state.runtime.write().unwrap().audit_client_ip_enabled = false;
    let mut delete_without_csrf = json_request(
        Method::DELETE,
        "/api/v2/audit/client-ips",
        r#"{"confirmation":"IP-DATEN LÖSCHEN"}"#,
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
    assert_eq!(state.db.count_audit_client_ips().unwrap(), 1);

    let mut delete = json_request(
        Method::DELETE,
        "/api/v2/audit/client-ips",
        r#"{"confirmation":"IP-DATEN LÖSCHEN"}"#,
    );
    delete.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    delete
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    let response = app.oneshot(delete).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response_text(response).await.contains(r#""deleted":1"#));
    assert_eq!(state.db.count_audit_client_ips().unwrap(), 0);
}

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
    state.db.create_admin("admin", &hash, &secret).unwrap();
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

    let all_searches = state
        .search_admission
        .clone()
        .try_acquire_many_owned(crate::MAX_CONCURRENT_SEARCHES as u32)
        .unwrap();
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
            crate::http_auth::try_acquire_client_activity(
                state.expensive_peer_admission.clone(),
                peer,
                crate::MAX_EXPENSIVE_OPERATIONS_PER_CLIENT,
            )
            .unwrap()
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
    let (entries, truncated) = list_file_page(&state.secure_root, "", 0, None, 1).unwrap();
    assert!(entries.is_empty());
    assert!(truncated);
    let (entries, truncated) =
        list_file_page(&state.secure_root, "", 0, Some("missing"), 1).unwrap();
    assert!(entries.is_empty());
    assert!(truncated);
}

#[tokio::test]
async fn api_unlock_cookie_authorizes_followup_api_download() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("secret.txt"), "protected content").unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let password_hash = auth::hash_password("very strong share password").unwrap();
    state
        .db
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
            .db
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
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let password_hash = auth::hash_password("very strong share password").unwrap();
    state
        .db
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
            .db
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
    state.db.create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let share_id = state
        .db
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
                .db
                .begin_upload_reservation(token, share_id, 0)
                .unwrap(),
            crate::db::UploadReservationBeginOutcome::Reserved
        );
        assert_eq!(
            state.db.extend_upload_reservation(token, 5).unwrap(),
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
    let share = state.db.share_by_token("quota-conflict").unwrap().unwrap();
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
    state.db.create_admin("admin", &hash, &secret).unwrap();
    state
        .db
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
            .db
            .share_by_token("file-token")
            .unwrap()
            .unwrap()
            .relative_path,
        "docs/final.txt"
    );

    std::fs::write(root.path().join("tree/child.txt"), b"child").unwrap();
    state
        .db
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
        .storage_cleanup
        .serialization_for_test()
        .lock_owned()
        .await;
    let cleanup_worker = state
        .storage_cleanup
        .start_worker(state.secure_root.clone())
        .unwrap();
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
            .db
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

#[tokio::test]
async fn api_delegated_public_upload_errors_are_json() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state
        .db
        .create_admin("admin", &hash, &auth::new_totp_secret())
        .unwrap();
    state
        .db
        .create_share(
            "upload-token",
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
    let app = crate::web::router(state);
    let response = app
        .oneshot(multipart_request(
            "/api/v2/public/shares/upload-token/upload",
            "blocked.exe",
            b"blocked",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(response
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("application/json"));
    let body = response_text(response).await;
    assert!(body.contains(r#""code":"unsupported_media_type""#));
    assert!(!body.contains("<html"));
    assert!(!body.contains("Zurück zur Freigabe"));
}

#[tokio::test]
async fn api_upload_reports_required_audit_failure_and_never_publishes_the_file() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db
        .create_share_with_upload_limits(
            "audit-failure-upload",
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
    let fault = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    fault
        .execute_batch(
            "CREATE TRIGGER fail_upload_quota_audit
             BEFORE INSERT ON audit
             WHEN NEW.action='upload_quota_committed'
             BEGIN SELECT RAISE(ABORT, 'injected upload audit failure'); END;",
        )
        .unwrap();
    let app = crate::web::router(state.clone());

    let response = app
        .oneshot(multipart_request(
            "/api/v2/public/shares/audit-failure-upload/upload",
            "must-not-appear.txt",
            b"payload",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("application/json"));
    let body = response_text(response).await;
    assert!(body.contains(r#""code":"audit_unavailable""#));
    assert!(!root.path().join("uploads/must-not-appear.txt").exists());
    let share = state
        .db
        .share_by_token("audit-failure-upload")
        .unwrap()
        .unwrap();
    assert_eq!((share.uploaded_bytes, share.uploaded_files), (0, 0));
    for _ in 0..100 {
        if state.db.active_upload_reservations(share_id).unwrap() == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    assert_eq!(state.db.active_upload_reservations(share_id).unwrap(), 0);
}

#[tokio::test]
async fn api_upload_reports_post_publication_audit_uncertainty_without_retry_signal() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db.create_admin("admin", "hash", "secret").unwrap();
    state
        .db
        .create_share_with_upload_limits(
            "post-publish-audit-failure",
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
    let fault = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    fault
        .execute_batch(
            "CREATE TRIGGER fail_published_upload_audit
             BEFORE INSERT ON audit
             WHEN NEW.action='upload'
             BEGIN SELECT RAISE(ABORT, 'injected post-publication audit failure'); END;",
        )
        .unwrap();
    let app = crate::web::router(state.clone());

    let response = app
        .oneshot(multipart_request(
            "/api/v2/public/shares/post-publish-audit-failure/upload",
            "already-visible.txt",
            b"payload",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(response
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("application/json"));
    let body = response_text(response).await;
    assert!(body.contains(r#""warning":"audit_durability_uncertain""#));
    assert!(body.contains(r#""file":"already-visible.txt""#));
    assert!(root.path().join("uploads/already-visible.txt").exists());
    let share = state
        .db
        .share_by_token("post-publish-audit-failure")
        .unwrap()
        .unwrap();
    assert_eq!((share.uploaded_bytes, share.uploaded_files), (7, 1));
}

#[test]
fn only_required_audit_introduces_a_new_service_unavailable_code() {
    use crate::http_auth::{HttpAuthError, HttpAuthErrorKind};

    let capacity = ApiError::from(HttpAuthError::with_kind(
        StatusCode::SERVICE_UNAVAILABLE,
        "capacity",
        HttpAuthErrorKind::CapacityUnavailable,
    ));
    assert_eq!(capacity.code, "request_failed");

    let audit = ApiError::from(HttpAuthError::with_kind(
        StatusCode::SERVICE_UNAVAILABLE,
        "audit",
        HttpAuthErrorKind::AuditUnavailable,
    ));
    assert_eq!(audit.code, "audit_unavailable");
}

#[test]
fn file_recovery_required_audit_failure_maps_to_stable_503_code() {
    let data = tempfile::tempdir().unwrap();
    let database_path = data.path().join("data.sqlite");
    let database = crate::db::Database::open(&database_path).unwrap();
    database
        .create_admin("admin", "old-hash", "secret")
        .unwrap();
    rusqlite::Connection::open(database_path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_file_recovery_audit
             BEFORE INSERT ON audit
             BEGIN SELECT RAISE(FAIL, 'injected file recovery audit failure'); END;",
        )
        .unwrap();
    let database_error = database
        .reset_admin_password_and_audit(
            1,
            "new-hash",
            &crate::db::AuditContext::new("system", None),
        )
        .unwrap_err();
    assert!(crate::db::is_audit_unavailable(&database_error));

    let mapped = files::file_operation_error(crate::file_ops::FileOperationError::Database(
        database_error,
    ));
    assert_eq!(mapped.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(mapped.code, "audit_unavailable");
    assert_eq!(mapped.message, "Security audit temporarily unavailable");
}

#[tokio::test]
async fn api_share_creation_preserves_audit_unavailable_from_real_pending_recovery() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("old.txt"), b"content").unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db.create_admin("admin", &hash, &secret).unwrap();
    state
        .db
        .create_share(
            "pending-recovery-token",
            None,
            "old.txt",
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
    let fault = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    fault
        .execute_batch(
            "CREATE TRIGGER fail_pending_recovery_audit
             BEFORE INSERT ON audit
             BEGIN SELECT RAISE(FAIL, 'injected recovery audit failure'); END;",
        )
        .unwrap();

    let rename = crate::file_ops::rename(
        &state,
        "old.txt",
        "new.txt",
        crate::db::AuditContext::new("admin", None),
    )
    .await
    .unwrap();
    assert!(rename.audit_durability.is_uncertain());
    assert_eq!(
        state.secure_root.pending_file_operations().unwrap().len(),
        1
    );

    let app = crate::web::router(state.clone());
    let mut request = json_request(
        Method::POST,
        "/api/v2/shares",
        r#"{"path":"new.txt","permission":"download_only"}"#,
    );
    authorize_mutation(&mut request, &session_cookie, &csrf);
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response_text(response)
        .await
        .contains(r#""code":"audit_unavailable""#));
    assert_eq!(
        state.secure_root.pending_file_operations().unwrap().len(),
        1
    );
    assert_eq!(
        state
            .db
            .share_by_token("pending-recovery-token")
            .unwrap()
            .unwrap()
            .relative_path,
        "old.txt"
    );
}

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
        .db
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
    state.db.create_admin("admin", &hash, &secret).unwrap();
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
        state.db.count_audit(Some("service_token_created")).unwrap(),
        1
    );
    assert_eq!(
        state.db.count_audit(Some("service_token_revoked")).unwrap(),
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
    state.db.create_admin("admin", &hash, &secret).unwrap();
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
    assert!(state.db.list_service_tokens().unwrap().is_empty());

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
    assert_eq!(state.db.list_service_tokens().unwrap().len(), 1);
    assert_eq!(
        state.db.count_audit(Some("service_token_created")).unwrap(),
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
    state.db.create_admin("admin", &hash, &secret).unwrap();
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
    state.db.create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, _) = api_login(&state, &secret).await;
    state.monitoring_limiter =
        crate::auth::LoginLimiter::new(2, std::time::Duration::from_secs(60));
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
    state.disk_stats_cache = crate::disk_stats::DiskStatsCache::for_test(|_| {
        Ok(crate::disk_stats::DiskStats { free: 1, total: 2 })
    });
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db.create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let (token_id, token, _) =
        api_create_monitoring_token(&state, &session_cookie, &csrf, "HA GET only").await;
    let app = crate::web::router(state.clone());
    let audit_count = state.db.count_audit(None).unwrap();

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
    assert_eq!(state.db.count_audit(None).unwrap(), audit_count);
}

#[tokio::test]
async fn service_tokens_are_isolated_from_other_api_html_and_public_authority() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db.create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let (token_id, token, _) =
        api_create_monitoring_token(&state, &session_cookie, &csrf, "HA isolation").await;
    let app = crate::web::router(state.clone());
    let audit_count = state.db.count_audit(None).unwrap();

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
        .db
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
    assert_eq!(state.db.count_audit(None).unwrap(), audit_count);
}

#[tokio::test]
async fn monitoring_summary_keeps_metrics_when_storage_probe_fails() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut state = test_state(root.path(), data.path());
    state.disk_stats_cache = crate::disk_stats::DiskStatsCache::for_test(|_| {
        Err(std::io::Error::other("injected storage probe failure"))
    });
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db.create_admin("admin", &hash, &secret).unwrap();
    state
        .db
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
    state.disk_stats_cache = crate::disk_stats::DiskStatsCache::for_test(|_| {
        Ok(crate::disk_stats::DiskStats {
            free: 123,
            total: 456,
        })
    });
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db.create_admin("admin", &hash, &secret).unwrap();

    let available_id = state
        .db
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
        .db
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
    state.db.set_share_active(inactive_id, false).unwrap();
    let expired_id = state
        .db
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
        .db
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
    state.disk_stats_cache = crate::disk_stats::DiskStatsCache::for_test(|_| {
        Ok(crate::disk_stats::DiskStats { free: 1, total: 2 })
    });
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db.create_admin("admin", &hash, &secret).unwrap();
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
