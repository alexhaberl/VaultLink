use super::*;
use crate::config::{Config, Logging, ReverseProxy, Security, Server, ServerMode, Storage, Tls};
use axum::{
    body::{to_bytes, Body},
    http::{Method, Request},
};
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
    let response = app
        .oneshot(json_request(Method::GET, "/api/v1/health", ""))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_text(response).await,
        format!(r#"{{"ok":true,"version":"{}"}}"#, env!("CARGO_PKG_VERSION"))
    );
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
            "/api/v1/session/login",
            r#"{"username":"admin","password":"wrong password"}"#,
        ))
        .await
        .unwrap();
    let unknown = app
        .oneshot(json_request(
            Method::POST,
            "/api/v1/session/login",
            r#"{"username":"absent","password":"wrong password"}"#,
        ))
        .await
        .unwrap();

    assert_eq!(known.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(unknown.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response_text(known).await, response_text(unknown).await);
}

async fn api_login(state: &AppState, secret: &str) -> (String, String) {
    let app = crate::web::router(state.clone());
    let login = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/v1/session/login",
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
        "/api/v1/session/mfa",
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
        "/api/v1/session/mfa",
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
    let mut me = json_request(Method::GET, "/api/v1/session/me", "");
    me.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    let me = app.clone().oneshot(me).await.unwrap();
    assert_eq!(me.status(), StatusCode::OK);
    let body = response_text(me).await;
    assert!(body.contains(r#""username":"admin""#));
    assert!(body.contains(&csrf));

    let mut logout_without_csrf = json_request(Method::POST, "/api/v1/session/logout", "{}");
    logout_without_csrf.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    let response = app.oneshot(logout_without_csrf).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains(r#""code":"forbidden""#));
    assert!(body.contains("CSRF"));
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
                "/api/v1/session/login",
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
            "/api/v1/session/mfa",
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
        "/api/v1/shares",
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
        "/api/v1/shares",
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
        "/api/v1/shares",
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
        "/api/v1/shares",
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
        "/api/v1/shares",
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
    let mut empty_update = json_request(Method::PATCH, &format!("/api/v1/shares/{share_id}"), "{}");
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

    let mut list = json_request(Method::GET, "/api/v1/shares", "");
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

    let mut update = json_request(
        Method::PATCH,
        &format!("/api/v1/shares/{share_id}"),
        r#"{"active":false}"#,
    );
    authorize_mutation(&mut update, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(update).await.unwrap().status(),
        StatusCode::OK
    );

    let mut activate = json_request(
        Method::POST,
        &format!("/api/v1/shares/{share_id}/activate"),
        "{}",
    );
    authorize_mutation(&mut activate, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(activate).await.unwrap().status(),
        StatusCode::OK
    );

    let mut deactivate = json_request(
        Method::POST,
        &format!("/api/v1/shares/{share_id}/deactivate"),
        "{}",
    );
    authorize_mutation(&mut deactivate, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(deactivate).await.unwrap().status(),
        StatusCode::OK
    );

    let mut set_password = json_request(
        Method::PUT,
        &format!("/api/v1/shares/{share_id}/password"),
        r#"{"password":"replacement share password"}"#,
    );
    authorize_mutation(&mut set_password, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(set_password).await.unwrap().status(),
        StatusCode::OK
    );

    let mut remove_password = json_request(
        Method::DELETE,
        &format!("/api/v1/shares/{share_id}/password"),
        "",
    );
    authorize_mutation(&mut remove_password, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(remove_password).await.unwrap().status(),
        StatusCode::OK
    );

    let mut delete = json_request(Method::DELETE, &format!("/api/v1/shares/{share_id}"), "");
    authorize_mutation(&mut delete, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(delete).await.unwrap().status(),
        StatusCode::OK
    );
    assert!(state.db.list_shares().unwrap().is_empty());

    let mut missing_delete = json_request(Method::DELETE, "/api/v1/shares/999999", "");
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
        "/api/v1/shares",
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
        &format!("/api/v1/shares/{share_id}"),
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
        "/api/v1/admins",
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

    let mut deactivate = json_request(
        Method::POST,
        &format!("/api/v1/admins/{ops_id}/deactivate"),
        "{}",
    );
    deactivate.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    let response = app.clone().oneshot(deactivate).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("CSRF"));

    let mut list = json_request(Method::GET, "/api/v1/admins", "");
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
        &format!("/api/v1/admins/{ops_id}/deactivate"),
        "{}",
    );
    authorize_mutation(&mut deactivate, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(deactivate).await.unwrap().status(),
        StatusCode::OK
    );

    let mut activate = json_request(
        Method::POST,
        &format!("/api/v1/admins/{ops_id}/activate"),
        "{}",
    );
    authorize_mutation(&mut activate, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(activate).await.unwrap().status(),
        StatusCode::OK
    );

    let mut reset_password = json_request(
        Method::PUT,
        &format!("/api/v1/admins/{ops_id}/password"),
        r#"{"password":"rotated correct horse password"}"#,
    );
    authorize_mutation(&mut reset_password, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(reset_password).await.unwrap().status(),
        StatusCode::OK
    );

    let mut reset_totp = json_request(
        Method::POST,
        &format!("/api/v1/admins/{ops_id}/totp/reset"),
        "{}",
    );
    authorize_mutation(&mut reset_totp, &session_cookie, &csrf);
    let response = app.clone().oneshot(reset_totp).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains(r#""username":"ops""#));
    assert!(body.contains("otpauth://totp/VaultLink:ops"));

    let mut self_deactivate = json_request(Method::POST, "/api/v1/admins/1/deactivate", "{}");
    authorize_mutation(&mut self_deactivate, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(self_deactivate).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    let mut missing = json_request(Method::POST, "/api/v1/admins/999999/activate", "{}");
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
    let mut invalid = json_request(Method::PUT, "/api/v1/settings", &invalid_json);
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
    let mut valid = json_request(Method::PUT, "/api/v1/settings", &valid_json);
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
        "/api/v1/settings",
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

    let mut list_disabled = json_request(Method::GET, "/api/v1/audit", "");
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
    let mut list_enabled = json_request(Method::GET, "/api/v1/audit", "");
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
        "/api/v1/audit/client-ips",
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
        "/api/v1/audit/client-ips",
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
        "/api/v1/audit/client-ips",
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
        "/api/v1/audit/client-ips",
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
    let mut request = json_request(Method::GET, "/api/v1/files?path=&q=only-late-match", "");
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
        &format!("/api/v1/files?path=&q={too_long}"),
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
    let mut request = json_request(Method::GET, "/api/v1/files?path=", "");
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::OK
    );
    let mut request = json_request(Method::GET, "/api/v1/files?path=&q=ordinary", "");
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
            .unwrap()
        })
        .collect::<Vec<_>>();
    let mut request = json_request(Method::GET, "/api/v1/files?path=", "");
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::OK
    );
    let mut request = json_request(Method::GET, "/api/v1/files?path=&q=ordinary", "");
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
    let (entries, truncated) = list_file_page(state.secure_root.clone(), "", 0, None, 1).unwrap();
    assert!(entries.is_empty());
    assert!(truncated);
    let (entries, truncated) =
        list_file_page(state.secure_root, "", 0, Some("missing"), 1).unwrap();
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
            "/api/v1/public/shares/protected-token",
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
            "/api/v1/public/shares/protected-token/unlock",
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
    assert!(set_cookie.contains("Path=/api/v1/public/shares/protected-token"));
    let unlock_cookie = set_cookie.split(';').next().unwrap().to_string();

    let mut download = json_request(
        Method::GET,
        "/api/v1/public/shares/protected-token/download",
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
            .contains("Path=/api/v1/public/shares/protected-token")));
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
        json_request(Method::GET, "/api/v1/public/shares/protected-token", "");
    metadata_request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&unlock_cookie).unwrap(),
    );
    let metadata = app.oneshot(metadata_request).await.unwrap();
    assert_eq!(metadata.status(), StatusCode::OK);
    assert!(response_text(metadata)
        .await
        .contains(r#""download_count":1"#));
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
            "/api/v1/public/shares/media-token/unlock",
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
        "/api/v1/public/shares/media-token/preview?path=image.png",
        "",
    );
    preview.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&unlock_cookie).unwrap(),
    );
    let preview = app.clone().oneshot(preview).await.unwrap();
    assert_eq!(preview.status(), StatusCode::OK);
    let preview = response_text(preview).await;
    assert!(preview.contains("/api/v1/public/shares/media-token/preview/raw?path=image%2Epng"));
    assert!(preview.contains("href=\"/api/v1/public/shares/media-token\""));
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
                "/api/v1/public/shares/media-token/preview/raw?path=image.png&preview_token={preview_token}"
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
            state.db.begin_upload_reservation(token, share_id).unwrap(),
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
        &format!("/api/v1/shares/{share_id}"),
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
        "/api/v1/files/directories",
        r#"{"parent":"","name":"tree"}"#,
    );
    authorize_mutation(&mut create, &session_cookie, &csrf);
    assert_eq!(
        app.clone().oneshot(create).await.unwrap().status(),
        StatusCode::CREATED
    );

    let mut rename = json_request(
        Method::PATCH,
        "/api/v1/files",
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
    let mut unconfirmed = json_request(Method::DELETE, "/api/v1/files", r#"{"path":"tree"}"#);
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
        "/api/v1/files",
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
            "/api/v1/public/shares/upload-token/upload",
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
            "/api/v1/public/shares/audit-failure-upload/upload",
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
            "/api/v1/public/shares/post-publish-audit-failure/upload",
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
    assert_eq!(mapped.message, crate::http_auth::AUDIT_UNAVAILABLE_MESSAGE);
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
        "/api/v1/shares",
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
