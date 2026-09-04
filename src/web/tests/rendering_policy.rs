#[test]
fn html_is_escaped() {
    assert_eq!(esc("<script>&\""), "&lt;script&gt;&amp;&quot;");
}

#[test]
fn text_preview_budget_tracks_the_retained_input_buffer() {
    // Escaped HTML is emitted in bounded chunks, so the only large retained
    // allocation is the pre-sized source buffer guarded by these permits.
    assert_eq!(text_preview_render_permits(1_000_000), 1);
    assert_eq!(text_preview_render_permits(MAX_TEXT_PREVIEW_SIZE), 64);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(
        crate::TEXT_PREVIEW_RENDER_BUDGET_PERMITS,
    ));
    let held = (0..crate::TEXT_PREVIEW_RENDER_BUDGET_PERMITS)
        .map(|_| {
            semaphore
                .clone()
                .try_acquire_many_owned(text_preview_render_permits(1_000_000))
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert!(semaphore
        .try_acquire_many_owned(text_preview_render_permits(1_000_000))
        .is_err());
    drop(held);
}

#[tokio::test]
async fn text_preview_stream_escapes_in_bounded_chunks_and_enforces_the_output_cap() {
    let text = "<&\"'ä".repeat(20_000);
    let expected = format!("prefix{}suffix", esc(&text));
    let template = format!("prefix{TEXT_PREVIEW_STREAM_MARKER}suffix");
    let (mut stream, declared_length) = escaped_text_page_stream(template, text).unwrap();
    let mut rendered = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.unwrap();
        assert!(chunk.len() <= BUFFERED_RESPONSE_CHUNK_BYTES);
        rendered.extend_from_slice(&chunk);
    }
    assert_eq!(declared_length, rendered.len() as u64);
    assert_eq!(rendered, expected.as_bytes());

    let oversized = "\"".repeat(MAX_RENDERED_TEXT_PREVIEW_BYTES / 6 + 1);
    let template = format!("prefix{TEXT_PREVIEW_STREAM_MARKER}suffix");
    assert!(escaped_text_page_stream(template, oversized).is_err());
}

#[test]
fn missing_session_error_redirects_to_login() {
    let response = AppError(StatusCode::SEE_OTHER, "/login").into_response();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/login");
}

#[test]
fn invalid_credentials_remain_an_error() {
    let response = AppError(StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(header::LOCATION).is_none());
}

#[tokio::test]
async fn english_backend_capacity_message_is_localized_only_at_the_ui_boundary() {
    assert_eq!(
        crate::http_auth::ARGON2_BUSY_MESSAGE,
        "Password processing temporarily unavailable"
    );
    let german = i18n::scope(Locale::De, "/login".into(), async {
        response_text(
            AppError(
                StatusCode::SERVICE_UNAVAILABLE,
                crate::http_auth::ARGON2_BUSY_MESSAGE,
            )
            .into_response(),
        )
        .await
    })
    .await;
    assert!(german.contains("Passwortverarbeitung vorübergehend nicht verfügbar"));
    assert!(!german.contains(crate::http_auth::ARGON2_BUSY_MESSAGE));
}

#[test]
fn post_locale_return_targets_are_get_safe() {
    let uri = |value: &str| value.parse::<Uri>().unwrap();
    assert_eq!(
        locale_return_to(&Method::POST, &uri("/admin/account/password")),
        "/admin/account"
    );
    assert_eq!(
        locale_return_to(&Method::POST, &uri("/admin/admins/42/totp")),
        "/admin/admins"
    );
    assert_eq!(
        locale_return_to(&Method::POST, &uri("/admin/service-tokens/42/revoke")),
        "/admin/service-tokens"
    );
    assert_eq!(
        locale_return_to(&Method::POST, &uri("/admin/files/delete")),
        "/admin"
    );
    assert_eq!(
        locale_return_to(&Method::POST, &uri("/v/share-token/upload/queue")),
        "/v/share-token"
    );
    assert_eq!(
        locale_return_to(&Method::GET, &uri("/admin?path=folder")),
        "/admin?path=folder"
    );
}
#[test]
fn permissions() {
    assert!(!Permission::DownloadOnly.can_upload());
    assert!(!Permission::UploadOnly.can_download());
    assert!(Permission::DownloadUpload.can_download());
}

#[test]
fn csrf_rejects_mismatch() {
    let session = Session {
        admin_id: 1,
        username: "admin".into(),
        csrf_token: "expected".into(),
        mfa_verified: true,
    };
    assert!(csrf(&session, "expected").is_ok());
    assert!(csrf(&session, "wrong").is_err());
}

#[test]
fn inactive_and_expired_shares_are_unusable() {
    let share = |active, expires_at| Share {
        id: 1,
        token: "token".into(),
        alias: None,
        relative_path: "file".into(),
        is_directory: false,
        permission: Permission::DownloadOnly,
        expires_at,
        max_downloads: None,
        max_upload_size: None,
        max_upload_total_size: None,
        max_upload_files: None,
        uploaded_bytes: 0,
        uploaded_files: 0,
        download_count: 0,
        active,
        password_hash: None,
        upload_conflict_strategy: UploadConflictStrategy::Reject,
        created_at: Utc::now().to_rfc3339(),
        upload_policy_epoch: 0,
    };
    assert!(usable(&share(false, None)).is_err());
    assert!(usable(&share(true, Some(Utc::now() - Duration::seconds(1)))).is_err());
    assert!(usable(&share(true, Some(Utc::now() + Duration::hours(1)))).is_ok());
}

#[test]
fn upload_policy_helpers() {
    let blocked = vec!["exe".to_string(), ".SH".to_string()];
    assert!(extension_is_blocked("payload.ExE", &blocked));
    assert!(extension_is_blocked("script.sh", &blocked));
    assert!(!extension_is_blocked("report.pdf", &blocked));
    assert_eq!(add_upload_bytes(5, 5, 10), Some(10));
    assert_eq!(add_upload_bytes(5, 6, 10), None);
    assert_eq!(add_upload_bytes(u64::MAX, 1, u64::MAX), None);
    assert_eq!(human(1_500_000_000), "1.5 GB");
    assert_eq!(format_unit_floor(53_687_091_200, GB), "53");
    assert_eq!(format_unit_decimal(100_000_000_000, GB), "100");
    assert_eq!(format_unit_decimal(100_500_000_000, GB), "100.5");
    assert_eq!(format_unit_decimal(1, GB), "0.000000001");
    assert_eq!(display_limit_unit_floor(1_073_741_824, GB), "1");
    assert_eq!(display_limit_unit_ceil(120_000_000_001, GB), "121");
    assert_eq!(
        display_limit_unit_ceil(u64::MAX, GB),
        u64::MAX.div_ceil(GB).to_string()
    );
    assert_eq!(
        parse_unit_to_bytes("1.5", GB, "bad").unwrap(),
        1_500_000_000
    );
    assert_eq!(
        parse_expiry(Some("2026-07-07T20:32"), Some("-120"))
            .unwrap()
            .unwrap()
            .to_rfc3339(),
        "2026-07-07T18:32:00+00:00"
    );
    assert_eq!(
        parse_expiry(Some("07.07.2026 20:32"), Some("-120"))
            .unwrap()
            .unwrap()
            .to_rfc3339(),
        "2026-07-07T18:32:00+00:00"
    );
    assert!(parse_expiry(Some("2026-07-07T20:32"), Some("invalid")).is_err());
    assert!(parse_expiry(Some("2026-07-07T20:32"), Some("1441")).is_err());
}

#[test]
fn text_preview_detects_growth_after_the_initial_metadata_check() {
    let directory = tempfile::tempdir().unwrap();
    let metadata_path = directory.path().join("metadata.txt");
    let content_path = directory.path().join("content.txt");
    std::fs::write(&metadata_path, b"ok").unwrap();
    std::fs::write(&content_path, b"12345").unwrap();
    let metadata = std::fs::metadata(metadata_path).unwrap();
    let file = std::fs::File::open(content_path).unwrap();
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut settings = runtime_settings(&test_state(root.path(), data.path()));
    settings.max_preview_size = 4;

    match read_preview_opened(file, &metadata, "content.txt", &settings).unwrap() {
        PreviewContent::TooLarge { size } => assert_eq!(size, 5),
        _ => panic!("grown preview must be rejected as too large"),
    }
}

#[tokio::test]
async fn admin_shell_renders_nav_icons_and_system_panel() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let html = i18n::scope(Locale::De, "/admin".into(), async {
        super::templates::admin_page(
            &state,
            PageId::Files,
            &EmptyPanelTemplate,
            true,
            "csrf",
            true,
        )
        .unwrap()
    })
    .await;
    assert!(html.contains("<title>Dateien · VaultLink</title>"));
    for label in [
        "Dateien",
        "Links",
        "Admins",
        "Service-Tokens",
        "Einstellungen",
        "Audit",
    ] {
        assert!(html.contains(&format!("<span>{label}</span>")));
    }
    assert!(html.contains("vl-icon"));
    assert_eq!(html.matches(r#"class="vl-nav-link""#).count(), 6);
    assert_eq!(html.matches(r#"aria-current="page""#).count(), 1);
    assert!(!html.contains('📁'));
    assert!(html.contains("VaultLink erreichbar"));
    assert_no_mojibake("admin shell", &html);
    assert!(!html.contains("Secure Mode"));
}

#[tokio::test]
async fn locale_route_sets_hardened_cookie_and_rejects_external_return_targets() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let app = router(test_state(root.path(), data.path()));

    let mut locale_request = request(
        Method::POST,
        "/locale",
        "locale=en&return_to=%2Flogin%3Ffrom%3Dswitch",
    );
    locale_request.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("http://localhost:8080"),
    );
    let response = app.clone().oneshot(locale_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "/login?from=switch"
    );
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cookie.starts_with("vaultlink_locale=en;"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
    assert!(cookie.contains("Path=/"));
    assert!(!cookie.contains(" Secure;"));

    let mut external_request = request(
        Method::POST,
        "/locale",
        "locale=de&return_to=https%3A%2F%2Fevil.example",
    );
    external_request.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("http://localhost:8080"),
    );
    let response = app.oneshot(external_request).await.unwrap();
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/");

    let mut secure_state = test_state(root.path(), data.path());
    let mut secure_config = secure_state.config().clone();
    secure_config.security.secure_cookie = true;
    secure_state.replace_config_for_test(secure_config);
    let mut secure_request = request(Method::POST, "/locale", "locale=en&return_to=%2Flogin");
    secure_request.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("http://localhost:8080"),
    );
    let secure_response = router(secure_state).oneshot(secure_request).await.unwrap();
    assert!(secure_response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains(" Secure;"));
}

#[tokio::test]
async fn http_locale_resolution_defaults_to_english_and_cookie_overrides_it() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let app = router(test_state(root.path(), data.path()));

    let request_without_language = Request::builder()
        .uri("/login")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request_without_language).await.unwrap();
    assert_eq!(
        response.headers().get(header::CONTENT_LANGUAGE).unwrap(),
        "en"
    );
    assert!(response_text(response).await.contains("Admin sign in"));

    let mut german_header = request(Method::GET, "/login", "");
    german_header.headers_mut().remove(header::COOKIE);
    german_header.headers_mut().insert(
        header::ACCEPT_LANGUAGE,
        HeaderValue::from_static("de-AT,de;q=0.9"),
    );
    let response = app.clone().oneshot(german_header).await.unwrap();
    assert_eq!(
        response.headers().get(header::CONTENT_LANGUAGE).unwrap(),
        "en"
    );
    assert!(response_text(response).await.contains("Admin sign in"));

    let mut cookie_override = request(Method::GET, "/login", "");
    cookie_override.headers_mut().insert(
        header::ACCEPT_LANGUAGE,
        HeaderValue::from_static("en-US,en;q=0.9"),
    );
    cookie_override.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_locale=de"),
    );
    let response = app.clone().oneshot(cookie_override).await.unwrap();
    assert_eq!(
        response.headers().get(header::CONTENT_LANGUAGE).unwrap(),
        "de"
    );

    let mut english_cookie = request(Method::GET, "/login", "");
    english_cookie.headers_mut().insert(
        header::ACCEPT_LANGUAGE,
        HeaderValue::from_static("de-AT,de;q=0.9"),
    );
    english_cookie.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_locale=en"),
    );
    let response = app.oneshot(english_cookie).await.unwrap();
    assert_eq!(
        response.headers().get(header::CONTENT_LANGUAGE).unwrap(),
        "en"
    );
}

#[tokio::test]
async fn queue_errors_localize_message_without_changing_machine_code() {
    let response = i18n::scope(Locale::En, "/v/token".into(), async {
        upload_queue_error_response(
            StatusCode::CONFLICT,
            "Datei existiert bereits; Ersetzen muss für diese Datei bestätigt werden",
        )
    })
    .await;
    let body = response_text(response).await;
    assert!(body.contains(r#""code":"file_exists""#));
    assert!(body.contains("File already exists"));
    assert!(!body.contains("Datei existiert"));
}

#[tokio::test]
async fn queue_reports_required_audit_failures_with_stable_machine_code() {
    let response = i18n::scope(Locale::De, "/admin".into(), async {
        upload_queue_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            crate::http_auth::AUDIT_UNAVAILABLE_MESSAGE,
        )
    })
    .await;
    let body = response_text(response).await;
    assert!(body.contains(r#""code":"audit_unavailable""#));
    assert!(body.contains("Sicherheitsprotokoll vorübergehend nicht verfügbar"));
}

#[test]
fn file_recovery_required_audit_failure_maps_to_ui_503_marker() {
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

    let response = storage_recovery_app_error(crate::file_ops::FileOperationError::Database(
        database_error,
    ))
    .into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.headers().get(ERROR_CODE_HEADER).unwrap(),
        "audit_unavailable"
    );
}

#[test]
fn file_database_busy_and_locked_errors_map_to_retryable_ui_capacity() {
    for code in [rusqlite::ffi::SQLITE_BUSY, rusqlite::ffi::SQLITE_LOCKED] {
        for recovery in [false, true] {
            let file_error = crate::file_ops::FileOperationError::Database(
                rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None),
            );
            let mapped = if recovery {
                storage_recovery_app_error(file_error)
            } else {
                super::files::file_operation_app_error(file_error)
            };
            assert_eq!(mapped.0, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(mapped.1, crate::http_auth::DATABASE_BUSY_MESSAGE);

            let response = mapped.into_response();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "1");
        }
    }
}

#[test]
fn file_database_executor_capacity_keeps_the_ui_capacity_contract() {
    for recovery in [false, true] {
        let error = crate::file_ops::FileOperationError::DatabaseCapacity;
        let mapped = if recovery {
            storage_recovery_app_error(error)
        } else {
            super::files::file_operation_app_error(error)
        };
        assert_eq!(mapped.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(mapped.1, crate::http_auth::DATABASE_BUSY_MESSAGE);
        let response = mapped.into_response();
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "1");
    }
}

#[tokio::test]
async fn audit_table_sorts_columns_and_keeps_time_descending_by_default() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.mutate_runtime_for_test(|runtime| runtime.audit_client_ip_enabled = true);
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "audit-session",
            1,
            "audit-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("audit-session").unwrap();
    state
        .db()
        .audit_with_client_ip(
            "zulu",
            "download",
            Some("z-object"),
            Some("z-detail"),
            Some("203.0.113.2"),
        )
        .unwrap();
    state
        .db()
        .audit_with_client_ip(
            "Alpha",
            "upload",
            Some("a-object"),
            Some("a-detail"),
            Some("203.0.113.1"),
        )
        .unwrap();
    let app = router(state);
    let cookie = HeaderValue::from_static("vaultlink_session=audit-session");

    let mut default_request = request(Method::GET, "/admin/audit", "");
    default_request
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let default_page = response_text(app.clone().oneshot(default_request).await.unwrap()).await;
    assert!(default_page.contains(r#"class="vl-audit-time" aria-sort="descending""#));
    assert!(default_page.contains("sort=user&amp;direction=asc"));
    assert!(default_page.contains("sort=client_ip&amp;direction=asc"));
    assert!(
        default_page
            .find(r#"data-label="User">Alpha</td>"#)
            .unwrap()
            < default_page.find(r#"data-label="User">zulu</td>"#).unwrap()
    );

    let mut descending_request = request(Method::GET, "/admin/audit?sort=user&direction=desc", "");
    descending_request
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let descending_page =
        response_text(app.clone().oneshot(descending_request).await.unwrap()).await;
    assert!(descending_page.contains(r#"class="vl-audit-user" aria-sort="descending""#));
    assert!(descending_page.contains("sort=user&amp;direction=asc"));
    assert!(
        descending_page
            .find(r#"data-label="User">zulu</td>"#)
            .unwrap()
            < descending_page
                .find(r#"data-label="User">Alpha</td>"#)
                .unwrap()
    );

    let mut ascending_request = request(
        Method::GET,
        "/admin/audit?action=upload&sort=user&direction=asc",
        "",
    );
    ascending_request
        .headers_mut()
        .insert(header::COOKIE, cookie);
    let ascending_page = response_text(app.oneshot(ascending_request).await.unwrap()).await;
    assert!(ascending_page.contains(r#"name="sort" value="user""#));
    assert!(ascending_page.contains(r#"name="direction" value="asc""#));
    assert!(ascending_page.contains("action=upload&amp;sort=user&amp;direction=desc"));
    assert!(ascending_page.contains(r#"data-label="User">Alpha</td>"#));
    assert!(!ascending_page.contains(r#"data-label="User">zulu</td>"#));
}

#[tokio::test]
async fn english_locale_covers_main_routes_without_touching_user_values() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("Dateien"), b"public").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("Abmelden", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "locale-session",
            1,
            "locale-csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("locale-session").unwrap();
    state
        .db()
        .create_share(
            "locale-public",
            None,
            "Dateien",
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
    let app = router(state);
    let routes = [
        ("/login", false),
        ("/admin", true),
        ("/admin/account", true),
        ("/admin/shares", true),
        ("/admin/admins", true),
        ("/admin/service-tokens", true),
        ("/admin/settings", true),
        ("/admin/audit", true),
        ("/v/locale-public", false),
    ];
    let forbidden_static_german = [
        "Zum Inhalt springen",
        "Dateibrowser",
        "Dateien durchsuchen",
        "Aktuellen Ordner freigeben",
        "Einstellungen",
        "Nachvollziehbarkeit",
        "Sichere Freigabe",
        "Benutzername",
        "Speichern",
        ">Abmelden</button>",
        ">Zurück<",
        ">Weiter<",
        ">Suchen<",
        ">Löschen<",
        ">Ansehen<",
        ">Erstellen<",
        ">Aktiv<",
        ">Abgelaufen<",
        ">Geschützt<",
        ">Passwort<",
        ">Größe<",
        ">Geändert<",
        ">Aktion<",
        ">Vorschau<",
    ];

    for (uri, authenticated) in routes {
        let mut request = request(Method::GET, uri, "");
        let cookie = if authenticated {
            "vaultlink_locale=en; vaultlink_session=locale-session"
        } else {
            "vaultlink_locale=en"
        };
        request
            .headers_mut()
            .insert(header::COOKIE, HeaderValue::from_static(cookie));
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "route {uri}");
        assert_eq!(
            response.headers().get(header::CONTENT_LANGUAGE).unwrap(),
            "en",
            "route {uri}"
        );
        let html = response_text(response).await;
        assert!(html.contains(r#"<html lang="en">"#), "route {uri}");
        assert!(!html.contains("<vl-i18n"), "unresolved marker on {uri}");
        for fragment in forbidden_static_german {
            assert!(
                !html.contains(fragment),
                "route {uri} still contains German UI fragment {fragment:?}"
            );
        }
        assert!(
            !html
                .chars()
                .any(|ch| matches!(ch, 'ä' | 'ö' | 'ü' | 'Ä' | 'Ö' | 'Ü' | 'ß')),
            "route {uri} still contains a German-specific character"
        );
        if uri == "/admin" || uri == "/v/locale-public" {
            assert!(html.contains("Dateien"), "user file name changed on {uri}");
        }
        if uri == "/admin/admins" {
            assert!(html.contains("Abmelden"), "user name was translated");
            assert!(html.contains("Log out"), "logout action was not translated");
        }
    }
}

#[tokio::test]
async fn login_page_serves_correct_utf8() {
    let response = i18n::scope(Locale::De, "/login".into(), login_page())
        .await
        .into_response();
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/html; charset=utf-8"
    );
    let html = response_text(response).await;
    assert!(html.contains("<meta charset=\"utf-8\">"));
    assert!(html.contains("<title>Login · VaultLink</title>"));
    assert_no_mojibake("login page", &html);
}

#[tokio::test]
async fn csp_requires_self_hosted_styles_and_pages_have_no_inline_styles() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let response = router(test_state(root.path(), data.path()))
        .oneshot(request(Method::GET, "/login", ""))
        .await
        .unwrap();
    let csp = response
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("style-src 'self'"));
    assert!(!csp.contains("unsafe-inline"));
    for (path, source) in web_production_sources() {
        assert!(
            !source.contains(concat!("style", "=")),
            "{path} contains an inline style attribute"
        );
    }
    assert!(!include_str!("../../setup.rs").contains(concat!("style", "=")));
}

#[test]
fn user_facing_sources_do_not_contain_mojibake() {
    for (path, source) in web_production_sources() {
        assert_no_mojibake(path, source);
    }
    assert_no_mojibake("src/setup.rs", include_str!("../../setup.rs"));
}

#[test]
#[should_panic(expected = "likely Windows-1252/UTF-8 mojibake")]
fn mojibake_guard_rejects_redecoded_utf8_bytes() {
    let broken_folder = ['\u{00f0}', '\u{0178}', '\u{201c}', '\u{0081}']
        .into_iter()
        .collect::<String>();
    assert_no_mojibake("broken folder icon", &broken_folder);
}

#[tokio::test]
async fn settings_form_uses_decimal_whole_preview_defaults() {
    let session = Session {
        admin_id: 1,
        username: "admin".into(),
        csrf_token: "csrf".into(),
        mfa_verified: true,
    };
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let mut settings = runtime_settings(&state);
    settings.max_upload_size = 53_687_091_200;
    settings.max_zip_size = 1_000_000_000;
    settings.max_preview_size = 1_000_000;
    settings.max_media_preview_size = 100_000_000;

    let html = i18n::scope(Locale::De, "/admin/settings".into(), async {
        i18n::render_markers(
            Locale::De,
            &settings_form_template(&session, &settings, 0, "", false)
                .render()
                .unwrap(),
        )
    })
    .await;
    assert!(html.contains(&format!(
        r#"name="max_upload_size_gb" type="number" min="1" max="{}" step="1" value="53""#,
        display_limit_unit_floor(crate::config::MAX_UPLOAD_SIZE, GB)
    )));
    assert!(html.contains(r#"name="max_zip_size_gb" type="number" min="0" step="1" value="1""#));
    assert!(html.contains(
        r#"name="max_preview_size_mb" type="number" min="1" max="64" step="1" value="1""#
    ));
    assert!(html.contains(
        r#"name="max_media_preview_size_mb" type="number" min="1" step="1" value="100""#
    ));
    assert!(html.contains("Suche Max. Einträge"));
    assert_eq!(html.matches(r#"class="vl-field-info""#).count(), 16);
    assert!(html.contains("Schema, Host und Port müssen exakt"));
    assert!(html.contains("0 deaktiviert dieses separate Limit"));
    assert!(!html.contains("Max. Dateien pro ZIP (0 ="));
    assert_no_mojibake("settings form", &html);
    assert!(!html.contains("Media-Preview Max. GB"));
}

#[tokio::test]
async fn png_favicon_is_an_actual_32_by_32_image() {
    let response = favicon_png(Query(AssetQuery::default()))
        .await
        .into_response();
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("image/png"))
    );
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(&bytes[12..16], b"IHDR");
    assert_eq!(u32::from_be_bytes(bytes[16..20].try_into().unwrap()), 32);
    assert_eq!(u32::from_be_bytes(bytes[20..24].try_into().unwrap()), 32);
}

#[tokio::test]
async fn versioned_assets_are_immutable_and_app_javascript_is_cached_per_locale() {
    let unversioned = app_js(Query(AssetQuery::default())).await;
    assert_eq!(
        unversioned.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );

    let german = app_js(Query(AssetQuery {
        v: Some(ASSET_VERSION.into()),
        lang: Some("de".into()),
    }))
    .await;
    assert_eq!(
        german.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static(
            "public, max-age=31536000, immutable"
        ))
    );
    assert!(response_text(german).await.contains("Kopiert"));

    let english = app_js(Query(AssetQuery {
        v: Some(ASSET_VERSION.into()),
        lang: Some("en".into()),
    }))
    .await;
    let english = response_text(english).await;
    assert!(english.contains("Copied"));
    assert!(english.contains("await navigator.clipboard.writeText(b.dataset.copy)"));
    assert!(english.contains("b.textContent='Copied'"));
    assert!(english.contains("catch(_){b.textContent='Copy failed'"));
    assert!(english.contains("addLocalCalendarMonths(new Date(),defaultMonths)"));
    assert!(english.contains("result.setDate(1);result.setMonth"));
    assert!(!english.contains("new Date(`${expiry.defaultValue}Z`)"));
}

#[tokio::test]
async fn full_router_preserves_asset_cache_policy_and_keeps_pages_no_store() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let app = router(test_state(root.path(), data.path()));

    let asset = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/assets/app.js?v={ASSET_VERSION}&lang=en"),
            "",
        ))
        .await
        .unwrap();
    assert_eq!(
        asset.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static(
            "public, max-age=31536000, immutable"
        ))
    );

    let page = app
        .oneshot(request(Method::GET, "/login", ""))
        .await
        .unwrap();
    assert_eq!(
        page.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
}

#[tokio::test]
async fn full_router_exposes_only_the_v2_api_namespace() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let app = router(test_state(root.path(), data.path()));
    let removed = format!("/api/{}/health", "v1");
    assert_eq!(
        app.clone()
            .oneshot(request(Method::GET, &removed, ""))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.oneshot(request(Method::GET, "/api/v2/health", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn request_ids_are_server_generated_and_propagated() {
    use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};

    let app = Router::new()
        .route(
            "/",
            get(|axum::Extension(ServerRequestId(request_id))| async move { request_id }),
        )
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(middleware::from_fn(super::attach_server_request_id))
        .layer(SetRequestIdLayer::new(REQUEST_ID_HEADER, MakeRequestUuid))
        .layer(middleware::from_fn(super::discard_client_request_id));
    let mut spoofed = request(Method::GET, "/api/v2/health", "");
    *spoofed.uri_mut() = Uri::from_static("/");
    spoofed.headers_mut().insert(
        REQUEST_ID_HEADER,
        HeaderValue::from_static("client-controlled"),
    );

    let response = app.oneshot(spoofed).await.unwrap();
    let request_id = response
        .headers()
        .get(REQUEST_ID_HEADER)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let handler_request_id = response_text(response).await;

    assert_ne!(request_id, "client-controlled");
    assert_eq!(request_id.len(), 36);
    assert!(request_id.bytes().enumerate().all(|(index, byte)| {
        if [8, 13, 18, 23].contains(&index) {
            byte == b'-'
        } else {
            byte.is_ascii_hexdigit()
        }
    }));
    assert_eq!(handler_request_id, request_id);
}

#[tokio::test]
async fn file_time_uses_locale_date_order() {
    let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(60 * 60 * 20 + 32 * 60);
    let utc = chrono::DateTime::<Utc>::from(time);
    let de = i18n::scope(Locale::De, "/".into(), async { format_utc_minute(utc) }).await;
    let en = i18n::scope(Locale::En, "/".into(), async { format_utc_minute(utc) }).await;
    assert_eq!(de, "01.01.1970 20:32 UTC");
    assert_eq!(en, "1970-01-01 20:32 UTC");
}

#[tokio::test]
async fn byte_sizes_use_locale_decimal_separator() {
    let de = i18n::scope(Locale::De, "/".into(), async { human(1_500_000_000) }).await;
    let en = i18n::scope(Locale::En, "/".into(), async { human(1_500_000_000) }).await;
    assert_eq!(de, "1,5 GB");
    assert_eq!(en, "1.5 GB");
}

#[test]
fn removed_compatibility_symbols_and_html_rewrites_stay_removed() {
    assert!(!include_str!("../../setup.rs").contains(concat!("setup_form_", "legacy")));
    for (path, source) in web_production_sources() {
        assert!(
            !source.contains(concat!("body.", "replace(")),
            "{path} contains removed body replacement"
        );
        assert!(
            !source.contains(concat!("body.", "replacen(")),
            "{path} contains removed body replacement"
        );
        assert!(
            !source.contains(concat!("app_", "css()")),
            "{path} contains a removed CSS helper"
        );
        assert!(
            !source.contains(concat!("vl-", "legacy")),
            "{path} contains a legacy UI marker"
        );
        assert!(
            !source.contains(concat!("admins_page_", "v3")),
            "{path} contains a removed page variant"
        );
        assert!(
            !source.contains(concat!("const LOGO_", "SVG: &str = r##")),
            "{path} embeds a removed duplicate logo"
        );
    }
    assert!(!include_str!("../../ui.rs").contains(concat!("APP_", "CSS")));
    assert!(!include_str!("../../setup.rs").contains(concat!("setup_", "css()")));
    assert!(!include_str!("../../setup.rs").contains(concat!("vl-", "legacy")));
    assert!(!include_str!("../../secure_fs.rs").contains(concat!("cleanup_upload_", "fragments")));
}

#[test]
fn public_preview_actions_are_rendered_above_content() {
    let body = PublicTextPreviewTemplate {
        back_link: "/v/token",
        download_link: "/v/token/download",
    }
    .render()
    .unwrap()
    .replace("<!--VAULTLINK_ESCAPED_TEXT_PREVIEW_STREAM-->", "long text");
    let html = i18n::render_markers(Locale::De, &body);
    let actions = html.find("Zurück zur Freigabe").unwrap();
    let content = html.find("<pre>long text</pre>").unwrap();
    assert!(actions < content);
    assert!(html.contains("Herunterladen"));
}
