#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_totp_mutation_redirects_when_session_is_revoked_before_commit() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let password = "current-admin-password";
    let password_hash = auth::hash_password(password).unwrap();
    let secret = auth::new_totp_secret();
    state
        .db()
        .create_admin("admin", &password_hash, &secret)
        .unwrap();
    state
        .db()
        .create_session(
            "revoked-account-session",
            1,
            "account-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("revoked-account-session").unwrap();
    for (label, credential_id) in [("Primary", "credential-a"), ("Backup", "credential-b")] {
        assert!(matches!(
            state
                .db()
                .add_admin_webauthn_credential_for_session(
                    "revoked-account-session",
                    1,
                    label,
                    credential_id,
                    "{}",
                    None,
                )
                .unwrap(),
            crate::db::AdminWebauthnCredentialRegistrationOutcome::Registered(_)
        ));
    }

    // Observe completion of the initial authentication without relying on a
    // sleep: session lookup refreshes this deliberately stale timestamp before
    // the handler waits for the settings mutation lock.
    let probe = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    let stale_activity = (Utc::now() - Duration::minutes(2)).to_rfc3339();
    probe
        .execute("UPDATE sessions SET last_activity_at=?1", [&stale_activity])
        .unwrap();
    let settings_guard = state.acquire_security_settings_mutation().await;
    let code = auth::totp_code(&secret, Utc::now().timestamp() as u64 / 30).unwrap();
    let mut disable = request(
        Method::POST,
        "/admin/account/totp",
        &format!("csrf=account-csrf&current_password={password}&current_code={code}&enabled=false"),
    );
    disable.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=revoked-account-session"),
    );
    let app = router(state.clone());
    let queued = tokio::spawn(async move { app.oneshot(disable).await.unwrap() });

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

    state.db().delete_session("revoked-account-session").unwrap();
    drop(settings_guard);
    let response = queued.await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/login");
    assert!(response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    assert!(state.db().admin("admin").unwrap().unwrap().totp_enabled);
    assert_eq!(
        state.db().count_audit(Some("admin_totp_disabled")).unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_security_key_finish_preserves_pending_challenge_and_audit() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state
        .db()
        .create_admin(
            "admin",
            &auth::hash_password("current-admin-password").unwrap(),
            &auth::new_totp_secret(),
        )
        .unwrap();
    state
        .db()
        .create_session(
            "revoked-registration-session",
            1,
            "registration-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("revoked-registration-session").unwrap();
    let webauthn = state.webauthn_snapshot_for_test();
    webauthn
        .start_registration("revoked-registration-session", 1, "admin", &[])
        .unwrap();
    assert!(webauthn.has_pending_registration("revoked-registration-session"));

    // Hold the first lock in the commit order so the request deterministically
    // completes its initial MFA lookup before revocation wins the DB fence.
    let probe = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    let stale_activity = (Utc::now() - Duration::minutes(2)).to_rfc3339();
    probe
        .execute("UPDATE sessions SET last_activity_at=?1", [&stale_activity])
        .unwrap();
    let settings_guard = state.acquire_security_settings_mutation().await;
    let mut finish = request(
        Method::POST,
        "/admin/account/security-keys/register/finish",
        r#"{"csrf":"registration-csrf","label":"Primary","credential":{}}"#,
    );
    finish.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    finish.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=revoked-registration-session"),
    );
    let app = router(state.clone());
    let queued = tokio::spawn(async move { app.oneshot(finish).await.unwrap() });

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

    state
        .db()
        .delete_session("revoked-registration-session")
        .unwrap();
    drop(settings_guard);
    let response = queued.await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/login");
    assert!(response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    assert!(webauthn.has_pending_registration("revoked-registration-session"));
    assert!(state.db().admin_webauthn_credentials(1).unwrap().is_empty());
    assert_eq!(
        state
            .db()
            .count_audit(Some("webauthn_credential_added"))
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_security_key_start_does_not_publish_a_pending_challenge() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let password = "current-admin-password";
    state
        .db()
        .create_admin(
            "admin",
            &auth::hash_password(password).unwrap(),
            &auth::new_totp_secret(),
        )
        .unwrap();
    state
        .db()
        .create_session(
            "revoked-registration-start",
            1,
            "registration-start-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("revoked-registration-start").unwrap();
    let webauthn = state.webauthn_snapshot_for_test();

    let probe = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    let stale_activity = (Utc::now() - Duration::minutes(2)).to_rfc3339();
    probe
        .execute("UPDATE sessions SET last_activity_at=?1", [&stale_activity])
        .unwrap();
    let settings_guard = state.acquire_security_settings_mutation().await;
    let mut start = request(
        Method::POST,
        "/admin/account/security-keys/register/start",
        &format!(
            r#"{{"csrf":"registration-start-csrf","current_password":"{password}","label":"Primary"}}"#
        ),
    );
    start.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    start.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=revoked-registration-start"),
    );
    let app = router(state.clone());
    let queued = tokio::spawn(async move { app.oneshot(start).await.unwrap() });

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

    state
        .db()
        .delete_session("revoked-registration-start")
        .unwrap();
    drop(settings_guard);
    let response = queued.await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/login");
    assert!(!webauthn.has_pending_registration("revoked-registration-start"));
}

#[tokio::test]
async fn invalid_security_key_finish_remains_a_bad_request_without_success_audit() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state
        .db()
        .create_admin(
            "admin",
            &auth::hash_password("current-admin-password").unwrap(),
            &auth::new_totp_secret(),
        )
        .unwrap();
    state
        .db()
        .create_session(
            "invalid-registration-session",
            1,
            "registration-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("invalid-registration-session").unwrap();
    let webauthn = state.webauthn_snapshot_for_test();
    webauthn
        .start_registration("invalid-registration-session", 1, "admin", &[])
        .unwrap();

    let mut finish = request(
        Method::POST,
        "/admin/account/security-keys/register/finish",
        r#"{"csrf":"registration-csrf","label":"Primary","credential":{}}"#,
    );
    finish.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    finish.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=invalid-registration-session"),
    );
    let response = router(state.clone()).oneshot(finish).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!webauthn.has_pending_registration("invalid-registration-session"));
    assert!(state.db().admin_webauthn_credentials(1).unwrap().is_empty());
    assert_eq!(
        state
            .db()
            .count_audit(Some("webauthn_credential_added"))
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn account_disables_totp_only_with_two_keys_and_keeps_key_management_compact() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let password = "current-admin-password";
    let password_hash = auth::hash_password(password).unwrap();
    let secret = auth::new_totp_secret();
    state
        .db()
        .create_admin("admin", &password_hash, &secret)
        .unwrap();
    state
        .db()
        .create_session(
            "account-security-session",
            1,
            "account-security-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("account-security-session").unwrap();
    let app = router(state.clone());
    let cookie =
        HeaderValue::from_static("vaultlink_locale=de; vaultlink_session=account-security-session");

    let mut before_keys = request(Method::GET, "/admin/account", "");
    before_keys
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let before_keys = response_text(app.clone().oneshot(before_keys).await.unwrap()).await;
    assert!(before_keys.contains("Ab zwei Keys änderbar"));
    assert!(!before_keys.contains(r#"action="/admin/account/totp""#));

    let first = match state
        .db()
        .add_admin_webauthn_credential_for_session(
            "account-security-session",
            1,
            "Primary",
            "credential-a",
            "{}",
            None,
        )
        .unwrap()
    {
        crate::db::AdminWebauthnCredentialRegistrationOutcome::Registered(id) => id,
        crate::db::AdminWebauthnCredentialRegistrationOutcome::SessionUnavailable => {
            panic!("verified account session must accept a security key")
        }
    };
    state
        .db()
        .add_admin_webauthn_credential_for_session(
            "account-security-session",
            1,
            "Backup",
            "credential-b",
            "{}",
            None,
        )
        .unwrap();
    let mut with_keys = request(Method::GET, "/admin/account", "");
    with_keys
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let with_keys = response_text(app.clone().oneshot(with_keys).await.unwrap()).await;
    assert_eq!(
        with_keys.matches(r#"class="vl-security-key-row""#).count(),
        3
    );
    assert!(with_keys.contains(r#"action="/admin/account/totp""#));
    assert!(with_keys.contains("Bearbeiten"));
    assert!(with_keys.contains(" UTC"));
    assert!(!with_keys.contains(r#"class="vl-field-info""#));

    let code = auth::totp_code(&secret, Utc::now().timestamp() as u64 / 30).unwrap();
    let mut disable = request(
        Method::POST,
        "/admin/account/totp",
        &format!(
            "csrf=account-security-csrf&current_password={password}&current_code={code}&enabled=false"
        ),
    );
    disable.headers_mut().insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone().oneshot(disable).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    assert!(!state.db().admin("admin").unwrap().unwrap().totp_enabled);

    let mut account = request(Method::GET, "/admin/account", "");
    account.headers_mut().insert(header::COOKIE, cookie.clone());
    let account = response_text(app.clone().oneshot(account).await.unwrap()).await;
    assert!(account.contains("TOTP ist deaktiviert"));
    assert!(!account.contains(r#"action="/admin/account/mfa/start""#));

    state
        .db()
        .create_session(
            "key-only-mfa-session",
            1,
            "key-only-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    let mut mfa_page = request(Method::GET, "/mfa", "");
    mfa_page.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=key-only-mfa-session"),
    );
    let mfa_page = response_text(app.clone().oneshot(mfa_page).await.unwrap()).await;
    assert!(!mfa_page.contains(r#"name="code""#));
    assert!(mfa_page.contains("data-security-key-login"));

    let mut protected_delete = request(
        Method::POST,
        &format!("/admin/account/security-keys/{first}/delete"),
        &format!("csrf=account-security-csrf&current_password={password}"),
    );
    protected_delete
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone()
            .oneshot(protected_delete)
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );

    state
        .db()
        .add_admin_webauthn_credential_for_session(
            "account-security-session",
            1,
            "Spare",
            "credential-c",
            "{}",
            None,
        )
        .unwrap();
    let mut delete = request(
        Method::POST,
        &format!("/admin/account/security-keys/{first}/delete"),
        &format!("csrf=account-security-csrf&current_password={password}"),
    );
    delete.headers_mut().insert(header::COOKIE, cookie);
    let deleted = app.clone().oneshot(delete).await.unwrap();
    assert_eq!(deleted.status(), StatusCode::SEE_OTHER);
    assert_eq!(deleted.headers().get(header::LOCATION).unwrap(), "/login");
    assert!(deleted
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    assert_eq!(state.db().admin_webauthn_credentials(1).unwrap().len(), 2);
    assert!(state
        .db()
        .session("account-security-session")
        .unwrap()
        .is_none());
    assert!(state.db().session("key-only-mfa-session").unwrap().is_none());

    state
        .db()
        .create_session(
            "post-key-delete-session",
            1,
            "post-key-delete-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    assert!(state.db().verify_mfa("post-key-delete-session").unwrap());

    let mut enable = request(
        Method::POST,
        "/admin/account/totp",
        &format!("csrf=post-key-delete-csrf&current_password={password}&enabled=true"),
    );
    enable.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=post-key-delete-session"),
    );
    assert_eq!(
        app.oneshot(enable).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    assert!(state.db().admin("admin").unwrap().unwrap().totp_enabled);
}

#[tokio::test]
async fn account_ui_changes_password_and_confirms_new_mfa_before_activation() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let current_password = "current-admin-password";
    let replacement_password = "replacement-admin-password";
    let password_hash = auth::hash_password(current_password).unwrap();
    let old_secret = auth::new_totp_secret();
    state.mutate_runtime_for_test(|runtime| runtime.audit_client_ip_enabled = true);
    state
        .db()
        .create_admin("admin", &password_hash, &old_secret)
        .unwrap();
    state
        .db()
        .create_session(
            "account-session",
            1,
            "account-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("account-session").unwrap();
    let app = router(state.clone());
    let account_cookie =
        HeaderValue::from_static("vaultlink_locale=de; vaultlink_session=account-session");

    let mut account_request = request(Method::GET, "/admin/account", "");
    account_request
        .headers_mut()
        .insert(header::COOKIE, account_cookie.clone());
    let account_html = response_text(app.clone().oneshot(account_request).await.unwrap()).await;
    assert!(account_html.contains("Mein Konto"));
    assert!(account_html.contains("Aktueller Benutzer"));
    assert!(account_html.contains(">admin<"));
    assert!(account_html.contains(r#"action="/admin/account/password""#));
    assert!(account_html.contains(r#"action="/admin/account/mfa/start""#));
    assert!(account_html.contains(r#"action="/locale""#));
    assert!(!account_html.contains(r#"class="vl-field-info""#));
    assert!(account_html.contains("Ab zwei Keys änderbar"));
    assert!(account_html.contains(r#"maxlength="256""#));
    assert!(account_html.contains("höchstens 256 Zeichen"));

    let mut wrong_password = request(
            Method::POST,
            "/admin/account/password",
            "csrf=account-csrf&current_password=wrong-password&new_password=replacement-admin-password&password_confirm=replacement-admin-password",
        );
    wrong_password
        .headers_mut()
        .insert(header::COOKIE, account_cookie.clone());
    assert_eq!(
        app.clone().oneshot(wrong_password).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(state.db().session("account-session").unwrap().is_some());
    assert!(auth::verify_password(
        &state.db().admin("admin").unwrap().unwrap().password_hash,
        current_password
    ));

    let mut change_password = request(
            Method::POST,
            "/admin/account/password",
            "csrf=account-csrf&current_password=current-admin-password&new_password=replacement-admin-password&password_confirm=replacement-admin-password",
        );
    change_password
        .headers_mut()
        .insert(header::COOKIE, account_cookie);
    let changed = app.clone().oneshot(change_password).await.unwrap();
    assert_eq!(changed.status(), StatusCode::SEE_OTHER);
    assert_eq!(changed.headers().get(header::LOCATION).unwrap(), "/login");
    assert!(changed
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    assert!(state.db().session("account-session").unwrap().is_none());
    assert!(auth::verify_password(
        &state.db().admin("admin").unwrap().unwrap().password_hash,
        replacement_password
    ));

    state
        .db()
        .create_session(
            "account-mfa-session",
            1,
            "account-mfa-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("account-mfa-session").unwrap();
    let mfa_cookie =
        HeaderValue::from_static("vaultlink_locale=de; vaultlink_session=account-mfa-session");

    let mut rejected_start = request(
        Method::POST,
        "/admin/account/mfa/start",
        "csrf=account-mfa-csrf&current_password=replacement-admin-password&current_code=abcdef",
    );
    rejected_start
        .headers_mut()
        .insert(header::COOKIE, mfa_cookie.clone());
    assert_eq!(
        app.clone().oneshot(rejected_start).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        state
            .db()
            .admin("admin")
            .unwrap()
            .unwrap()
            .totp_secret
            .expose_secret(),
        old_secret.as_str()
    );
    assert!(state.db().session("account-mfa-session").unwrap().is_some());

    let current_step = Utc::now().timestamp() as u64 / 30;
    let current_code = auth::totp_code(&old_secret, current_step).unwrap();
    let mut start_mfa = request(
            Method::POST,
            "/admin/account/mfa/start",
            &format!("csrf=account-mfa-csrf&current_password=replacement-admin-password&current_code={current_code}"),
        );
    start_mfa
        .headers_mut()
        .insert(header::COOKIE, mfa_cookie.clone());
    let start_response = app.clone().oneshot(start_mfa).await.unwrap();
    assert_eq!(start_response.status(), StatusCode::OK);
    let start_html = response_text(start_response).await;
    assert!(start_html.contains("Die bisherige MFA bleibt"));
    assert!(!start_html.contains(r#"action="/locale""#));
    let token_marker = r#"name="enrollment_token" value=""#;
    let token_start = start_html.find(token_marker).unwrap() + token_marker.len();
    let enrollment_token = start_html[token_start..]
        .split('"')
        .next()
        .unwrap()
        .to_string();
    let secret_marker = "otpauth://totp/VaultLink:admin?secret=";
    let secret_start = start_html.find(secret_marker).unwrap() + secret_marker.len();
    let new_secret = start_html[secret_start..]
        .split('&')
        .next()
        .unwrap()
        .to_string();
    assert_ne!(new_secret, old_secret);
    assert_eq!(
        state
            .db()
            .admin("admin")
            .unwrap()
            .unwrap()
            .totp_secret
            .expose_secret(),
        old_secret.as_str()
    );

    let mut wrong_confirmation = request(
        Method::POST,
        "/admin/account/mfa/confirm",
        &format!("csrf=account-mfa-csrf&enrollment_token={enrollment_token}&code=abcdef"),
    );
    wrong_confirmation
        .headers_mut()
        .insert(header::COOKIE, mfa_cookie.clone());
    assert_eq!(
        app.clone()
            .oneshot(wrong_confirmation)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        state
            .db()
            .admin("admin")
            .unwrap()
            .unwrap()
            .totp_secret
            .expose_secret(),
        old_secret.as_str()
    );
    assert!(state.db().session("account-mfa-session").unwrap().is_some());

    let new_code = auth::totp_code(&new_secret, Utc::now().timestamp() as u64 / 30).unwrap();
    let mut confirm_mfa = request(
        Method::POST,
        "/admin/account/mfa/confirm",
        &format!("csrf=account-mfa-csrf&enrollment_token={enrollment_token}&code={new_code}"),
    );
    confirm_mfa.headers_mut().insert(header::COOKIE, mfa_cookie);
    let confirmed = app.clone().oneshot(confirm_mfa).await.unwrap();
    assert_eq!(confirmed.status(), StatusCode::SEE_OTHER);
    assert_eq!(confirmed.headers().get(header::LOCATION).unwrap(), "/login");
    assert!(confirmed
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    assert_eq!(
        state
            .db()
            .admin("admin")
            .unwrap()
            .unwrap()
            .totp_secret
            .expose_secret(),
        new_secret.as_str()
    );
    assert!(state.db().session("account-mfa-session").unwrap().is_none());
    assert_eq!(
        state
            .db()
            .count_audit(Some("account_password_changed"))
            .unwrap(),
        1
    );
    assert_eq!(
        state.db().count_audit(Some("account_mfa_changed")).unwrap(),
        1
    );
    for action in ["account_password_changed", "account_mfa_changed"] {
        let events = state.db().list_audit(Some(action), 10, 0).unwrap();
        assert_eq!(events[0].client_ip.as_deref(), Some("127.0.0.1"));
    }
}

#[tokio::test]
async fn service_token_ui_requires_mfa_reauth_and_shows_secret_only_once() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let current_password = "current-admin-password";
    let password_hash = auth::hash_password(current_password).unwrap();
    state
        .db()
        .create_admin("admin", &password_hash, "secret")
        .unwrap();
    state
        .db()
        .create_session(
            "service-token-session",
            1,
            "service-token-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    let app = router(state.clone());
    let cookie =
        HeaderValue::from_static("vaultlink_locale=en; vaultlink_session=service-token-session");

    let mut before_mfa = request(Method::GET, "/admin/service-tokens", "");
    before_mfa
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone().oneshot(before_mfa).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    state.db().verify_mfa("service-token-session").unwrap();
    let mut initial_page = request(Method::GET, "/admin/service-tokens", "");
    initial_page
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let initial_response = app.clone().oneshot(initial_page).await.unwrap();
    assert_eq!(initial_response.status(), StatusCode::OK);
    let initial_html = response_text(initial_response).await;
    assert!(initial_html.contains("Service tokens"));
    assert!(initial_html.contains("monitoring:read"));
    assert!(initial_html.contains(r#"type="datetime-local" value="20"#));
    assert!(initial_html.contains(r#"data-default-expiry-months="12""#));
    assert!(initial_html.contains(r#"name="no_expiry""#));
    assert!(initial_html.contains("Without expiration, the token remains valid"));

    let create_body = concat!(
        "csrf=service-token-csrf&current_password=current-admin-password",
        "&name=Home+Assistant+%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        "&no_expiry=1"
    );
    let mut wrong_csrf = request(
        Method::POST,
        "/admin/service-tokens",
        &create_body.replace("service-token-csrf", "wrong-csrf"),
    );
    wrong_csrf
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone().oneshot(wrong_csrf).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert!(state.db().list_service_tokens().unwrap().is_empty());

    let mut padded_name = request(
        Method::POST,
        "/admin/service-tokens",
        "csrf=service-token-csrf&current_password=current-admin-password&name=%20Home+Assistant%20&no_expiry=1",
    );
    padded_name
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone().oneshot(padded_name).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert!(state.db().list_service_tokens().unwrap().is_empty());

    let mut wrong_password = request(
        Method::POST,
        "/admin/service-tokens",
        &create_body.replace("current-admin-password", "wrong-password"),
    );
    wrong_password
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone().oneshot(wrong_password).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(state.db().list_service_tokens().unwrap().is_empty());

    let mut create = request(Method::POST, "/admin/service-tokens", create_body);
    create.headers_mut().insert(header::COOKIE, cookie.clone());
    let created_response = app.clone().oneshot(create).await.unwrap();
    assert_eq!(created_response.status(), StatusCode::OK);
    assert_eq!(
        created_response.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    let created_html = response_text(created_response).await;
    assert!(created_html.contains("This token is shown only now"));
    assert!(created_html.contains("Home Assistant"));
    assert!(created_html.contains("alert(1)"));
    assert!(!created_html.contains("<script>alert(1)</script>"));
    assert!(!created_html.contains(r#"action="/locale""#));
    let token_start = created_html.find("vlk_st_v1_").unwrap();
    let token_end = created_html[token_start..].find('<').unwrap() + token_start;
    let plaintext_token = &created_html[token_start..token_end];
    assert_eq!(plaintext_token.len(), "vlk_st_v1_".len() + 43);
    assert!(created_html.contains(&format!(r#"data-copy="{plaintext_token}""#)));
    assert_eq!(
        state.db().count_audit(Some("service_token_created")).unwrap(),
        1
    );

    let tokens = state.db().list_service_tokens().unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].name, "Home Assistant <script>alert(1)</script>");
    assert!(tokens[0].expires_at.is_none());
    let token_id = tokens[0].id;

    let mut listing = request(Method::GET, "/admin/service-tokens", "");
    listing.headers_mut().insert(header::COOKIE, cookie.clone());
    let listing_html = response_text(app.clone().oneshot(listing).await.unwrap()).await;
    assert!(listing_html.contains("Home Assistant"));
    assert!(listing_html.contains("alert(1)"));
    assert!(listing_html.contains(&format!(r#"data-label="ID">{token_id}</td>"#)));
    assert!(listing_html.contains("No expiration"));
    assert!(listing_html.contains(r#"<span class="vl-badge vl-badge--success">Active</span>"#));
    assert!(!listing_html.contains(plaintext_token));
    assert!(!listing_html.contains("<script>alert(1)</script>"));

    state.db().expire_service_token_for_test(token_id).unwrap();
    let mut expired_listing = request(Method::GET, "/admin/service-tokens", "");
    expired_listing
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let expired_html = response_text(app.clone().oneshot(expired_listing).await.unwrap()).await;
    assert!(expired_html.contains(r#"<span class="vl-badge vl-badge--warning">Expired</span>"#));
    assert!(!expired_html.contains(r#"<span class="vl-badge vl-badge--success">Active</span>"#));
    assert!(!expired_html.contains(plaintext_token));

    let german_cookie =
        HeaderValue::from_static("vaultlink_locale=de; vaultlink_session=service-token-session");
    let mut german_listing = request(Method::GET, "/admin/service-tokens", "");
    german_listing
        .headers_mut()
        .insert(header::COOKIE, german_cookie);
    let german_html = response_text(app.clone().oneshot(german_listing).await.unwrap()).await;
    assert!(german_html.contains("Instanzweite API-Zugänge"));
    assert!(german_html.contains("Ohne Ablauf bleibt das Token"));
    assert!(german_html.contains("Home Assistant"));
    assert!(german_html.contains("alert(1)"));
    assert!(!german_html.contains("Without expiration, the token remains valid"));
    assert!(!german_html.contains("<vl-i18n"));

    state
        .db()
        .create_admin("revoking-admin", &password_hash, "revoking-secret")
        .unwrap();
    state
        .db()
        .create_session(
            "revoking-admin-session",
            2,
            "revoking-admin-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("revoking-admin-session").unwrap();
    let revoking_admin_cookie =
        HeaderValue::from_static("vaultlink_locale=en; vaultlink_session=revoking-admin-session");

    let mut wrong_revoke_csrf = request(
        Method::POST,
        &format!("/admin/service-tokens/{token_id}/revoke"),
        "csrf=wrong-csrf",
    );
    wrong_revoke_csrf
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    assert_eq!(
        app.clone()
            .oneshot(wrong_revoke_csrf)
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(state.db().list_service_tokens().unwrap().len(), 1);

    let mut revoke = request(
        Method::POST,
        &format!("/admin/service-tokens/{token_id}/revoke"),
        "csrf=revoking-admin-csrf",
    );
    revoke
        .headers_mut()
        .insert(header::COOKIE, revoking_admin_cookie);
    let revoked = app.clone().oneshot(revoke).await.unwrap();
    assert_eq!(revoked.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        revoked.headers().get(header::LOCATION).unwrap(),
        "/admin/service-tokens?notice=revoked"
    );
    assert!(state.db().list_service_tokens().unwrap().is_empty());
    assert_eq!(
        state.db().count_audit(Some("service_token_revoked")).unwrap(),
        1
    );
    let revoke_events = state
        .db()
        .list_audit(Some("service_token_revoked"), 10, 0)
        .unwrap();
    assert_eq!(revoke_events[0].actor, "revoking-admin");
}
