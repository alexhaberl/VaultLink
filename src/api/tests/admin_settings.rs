#[tokio::test]
async fn api_admin_and_settings_flows_are_csrf_protected() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
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
    assert!(state.db().admin("OPS").unwrap().is_some());

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
    assert!(state.db().admin("ops").unwrap().is_none());

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
    assert!(state.db().admin("ops").unwrap().is_some());

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
async fn admin_mutation_and_sessions_roll_back_without_resetting_login_history() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    state
        .db()
        .create_admin("ops", "ops-password-hash", &auth::new_totp_secret())
        .unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let ops_id = state
        .db()
        .list_admins()
        .unwrap()
        .into_iter()
        .find(|admin| admin.username == "ops")
        .unwrap()
        .id;
    state
        .db()
        .create_session(
            "ops-session",
            ops_id,
            "ops-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    assert!(state.db().verify_mfa("ops-session").unwrap());
    assert!(state
        .admin_login_limiter()
        .check_and_record_attempt("ops", "192.0.2.44".parse().unwrap()));
    let admins_before = state
        .db()
        .list_admins()
        .unwrap()
        .into_iter()
        .map(|admin| (admin.id, admin.username, admin.created_at, admin.active))
        .collect::<Vec<_>>();
    let limiter_before = state.admin_login_limiter().snapshot_for_test();
    let audit_before = state.db().count_audit(None).unwrap();
    rusqlite::Connection::open(data.path().join("data.sqlite"))
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_admin_deactivation_audit
             BEFORE INSERT ON audit
             WHEN NEW.action='admin_deactivated'
             BEGIN SELECT RAISE(FAIL, 'injected admin deactivation audit failure'); END;",
        )
        .unwrap();

    let mut deactivate = json_request(
        Method::POST,
        &format!("/api/v2/admins/{ops_id}/deactivate"),
        "{}",
    );
    authorize_mutation(&mut deactivate, &session_cookie, &csrf);
    let response = crate::web::router(state.clone())
        .oneshot(deactivate)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response_text(response)
        .await
        .contains(r#""code":"audit_unavailable""#));
    let admins_after = state
        .db()
        .list_admins()
        .unwrap()
        .into_iter()
        .map(|admin| (admin.id, admin.username, admin.created_at, admin.active))
        .collect::<Vec<_>>();
    assert_eq!(admins_after, admins_before);
    assert!(state.db().session("ops-session").unwrap().is_some());
    let limiter_after = state.admin_login_limiter().snapshot_for_test();
    assert_eq!(limiter_after, limiter_before);
    assert_eq!(state.db().count_audit(None).unwrap(), audit_before);
    assert_eq!(
        state.db().count_audit(Some("admin_deactivated")).unwrap(),
        0
    );
}

#[tokio::test]
async fn runtime_settings_publication_rolls_back_when_required_audit_fails() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let persisted_before = state.db().runtime_settings().unwrap();
    let runtime_before = runtime_settings(&state);
    let webauthn_before = state.webauthn_snapshot_for_test().instance_id();
    let audit_before = state.db().count_audit(None).unwrap();
    rusqlite::Connection::open(data.path().join("data.sqlite"))
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_runtime_settings_audit
             BEFORE INSERT ON audit
             WHEN NEW.action='settings_updated'
             BEGIN SELECT RAISE(FAIL, 'injected settings audit failure'); END;",
        )
        .unwrap();
    let mut update = settings_body(runtime_before.clone());
    update.public_base_url = "http://localhost:8081/".into();
    let mut request = json_request(
        Method::PUT,
        "/api/v2/settings",
        &serde_json::to_string(&update).unwrap(),
    );
    authorize_mutation(&mut request, &session_cookie, &csrf);

    let response = crate::web::router(state.clone())
        .oneshot(request)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response_text(response)
        .await
        .contains(r#""code":"audit_unavailable""#));
    assert_eq!(state.db().runtime_settings().unwrap(), persisted_before);
    assert_eq!(runtime_settings(&state), runtime_before);
    assert_eq!(
        state.webauthn_snapshot_for_test().instance_id(),
        webauthn_before
    );
    assert_eq!(state.db().count_audit(None).unwrap(), audit_before);
    assert_eq!(state.db().count_audit(Some("settings_updated")).unwrap(), 0);
}

#[tokio::test]
async fn api_settings_are_canonical_and_restart_safe() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let config = state.config().clone();
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let app = crate::web::router(state.clone());
    let original_webauthn = state.webauthn_snapshot_for_test().instance_id();

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
    assert!(state.db().runtime_settings().unwrap().is_empty());

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
        state.webauthn_snapshot_for_test().instance_id(),
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
    state.db().create_admin("admin", &hash, &secret).unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    state
        .db()
        .audit_with_client_ip("admin", "client_ip_test", None, None, Some("203.0.113.10"))
        .unwrap();
    assert_eq!(state.db().count_audit_client_ips().unwrap(), 1);
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

    state.mutate_runtime_for_test(|runtime| runtime.audit_client_ip_enabled = true);
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
    assert_eq!(state.db().count_audit_client_ips().unwrap(), 1);

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
    assert_eq!(state.db().count_audit_client_ips().unwrap(), 1);

    state.mutate_runtime_for_test(|runtime| runtime.audit_client_ip_enabled = false);
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
    assert_eq!(state.db().count_audit_client_ips().unwrap(), 1);

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
    assert_eq!(state.db().count_audit_client_ips().unwrap(), 0);
}
