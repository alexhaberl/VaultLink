const WEB_SOURCE: &str = include_str!("web.rs");
const WEB_TEST_SOURCE: &str = include_str!("web/tests.rs");
const WEB_PUBLIC_PREVIEW_SOURCE: &str = include_str!("web/public_preview.rs");
const WEB_UPLOAD_SOURCE: &str = include_str!("web/upload.rs");
const API_SOURCE: &str = include_str!("api.rs");
const API_TEST_SOURCE: &str = include_str!("api/tests.rs");

fn compact(source: &str) -> String {
    let mut source: String = source.chars().filter(|ch| !ch.is_whitespace()).collect();
    while source.contains(",)") {
        source = source.replace(",)", ")");
    }
    source
}

fn router_registration_block(source: &str) -> String {
    let source = compact(source);
    let start = source
        .find("pubfnrouter(")
        .expect("router function must remain directly inventoryable");
    let terminal = ".with_state(state)";
    let end = source[start..]
        .find(terminal)
        .map(|offset| start + offset + terminal.len())
        .expect("router must terminate by installing AppState");
    source[start..end].to_owned()
}

fn occurrences(source: &str, needle: &str) -> usize {
    source.match_indices(needle).count()
}

fn assert_route(router: &str, path: &str, methods: &str) {
    let route_prefix = format!(r#".route("{path}","#);
    assert_eq!(
        occurrences(router, &route_prefix),
        1,
        "route {path:?} must be registered exactly once"
    );

    let expected = compact(&format!(r#".route("{path}",{methods})"#));
    assert!(
        router.contains(&expected),
        "route {path:?} no longer has the expected method/handler mapping: {methods}"
    );
}

fn assert_fragments_in_order(source: &str, fragments: &[&str]) {
    let mut cursor = 0;
    for fragment in fragments {
        let fragment = compact(fragment);
        let relative = source[cursor..]
            .find(&fragment)
            .unwrap_or_else(|| panic!("missing or reordered router fragment: {fragment}"));
        cursor += relative + fragment.len();
    }
}

#[test]
fn web_route_inventory_is_explicit_and_complete() {
    let router = router_registration_block(WEB_SOURCE);
    let expected = [
        ("/", r#"get(|| async { Redirect::to("/admin") })"#),
        ("/login", "get(auth_ui::login_page).post(auth_ui::login)"),
        ("/mfa", "get(auth_ui::mfa_page).post(auth_ui::mfa)"),
        (
            "/mfa/security-key/start",
            "post(auth_ui::start_security_key_authentication)",
        ),
        (
            "/mfa/security-key/finish",
            "post(auth_ui::finish_security_key_authentication)",
        ),
        ("/locale", "post(rendering::set_locale)"),
        ("/logout", "post(auth_ui::logout)"),
        ("/admin", "get(files::admin_browser)"),
        ("/admin/account", "get(account::account_page)"),
        (
            "/admin/account/password",
            "post(account::change_account_password)",
        ),
        ("/admin/account/mfa/start", "post(account::start_account_mfa)"),
        (
            "/admin/account/mfa/confirm",
            "post(account::confirm_account_mfa)",
        ),
        ("/admin/account/totp", "post(account::set_account_totp)"),
        (
            "/admin/account/security-keys/register/start",
            "post(account::start_security_key_registration)",
        ),
        (
            "/admin/account/security-keys/register/finish",
            "post(account::finish_security_key_registration)",
        ),
        (
            "/admin/account/security-keys/{id}/delete",
            "post(account::delete_security_key)",
        ),
        (
            "/admin/files/directories",
            "post(files::create_directory_ui)",
        ),
        (
            "/admin/files/upload",
            "post(files::admin_upload).layer(DefaultBodyLimit::max(limit)).layer(middleware::from_fn(guard_multipart_upload))",
        ),
        (
            "/admin/files/upload/queue",
            "post(files::admin_upload_queue).layer(DefaultBodyLimit::max(limit)).layer(middleware::from_fn(guard_multipart_upload))",
        ),
        ("/admin/files/rename", "post(files::rename_file_ui)"),
        (
            "/admin/files/download",
            "get(files::admin_download).head(files::admin_download)",
        ),
        (
            "/admin/files/delete",
            "get(files::delete_file_confirmation).post(files::delete_file_ui)",
        ),
        ("/admin/preview", "get(files::admin_preview)"),
        (
            "/admin/preview/raw",
            "get(files::admin_preview_raw).head(files::admin_preview_raw)",
        ),
        (
            "/admin/shares",
            "get(shares::share_index_page).post(shares::create_share)",
        ),
        ("/admin/shares/new", "get(shares::share_create_page)"),
        ("/admin/shares/{id}/toggle", "post(shares::toggle_share)"),
        (
            "/admin/shares/{id}/upload-conflict",
            "post(shares::set_share_upload_conflict)",
        ),
        (
            "/admin/shares/{id}/password",
            "post(shares::set_share_password)",
        ),
        ("/admin/shares/{id}/delete", "post(shares::delete_share)"),
        (
            "/admin/admins",
            "get(admin::admins_page).post(admin::create_admin_ui)",
        ),
        (
            "/admin/admins/{id}/deactivate",
            "post(admin::deactivate_admin)",
        ),
        (
            "/admin/admins/{id}/activate",
            "post(admin::activate_admin)",
        ),
        (
            "/admin/admins/{id}/password",
            "post(admin::reset_admin_password)",
        ),
        ("/admin/admins/{id}/totp", "post(admin::reset_admin_totp)"),
        (
            "/admin/settings",
            "get(settings_audit::settings_page).post(settings_audit::update_settings)",
        ),
        (
            "/admin/settings/audit-ips/delete",
            "get(settings_audit::audit_ips_delete_confirmation).post(settings_audit::delete_audit_ips_ui)",
        ),
        ("/admin/audit", "get(settings_audit::audit_page)"),
        ("/v/{token}", "get(public::public_page)"),
        ("/v/{token}/preview", "get(public_preview::public_preview)"),
        (
            "/v/{token}/preview/raw",
            "get(public_preview::public_preview_raw).head(public_preview::public_preview_raw)",
        ),
        ("/v/{token}/unlock", "post(public::unlock_share)"),
        (
            "/v/{token}/download",
            "get(transfer::download).head(transfer::download)",
        ),
        ("/v/{token}/download.zip", "get(transfer::download_zip)"),
        (
            "/v/{token}/upload",
            "post(upload::upload).layer(DefaultBodyLimit::max(limit)).layer(middleware::from_fn(guard_multipart_upload))",
        ),
        (
            "/v/{token}/upload/queue",
            "post(upload::upload_queue).layer(DefaultBodyLimit::max(limit)).layer(middleware::from_fn(guard_multipart_upload))",
        ),
        ("/s/{alias}", "get(public::short_redirect)"),
        ("/assets/vaultlink.css", "get(rendering::stylesheet_asset)"),
        ("/assets/app.js", "get(rendering::app_js)"),
        ("/assets/vaultlink-logo.svg", "get(rendering::logo_svg)"),
        ("/assets/favicon.svg", "get(rendering::favicon_svg)"),
        ("/assets/favicon-32.png", "get(rendering::favicon_png)"),
        ("/favicon.ico", "get(rendering::favicon_png)"),
    ];

    assert_eq!(expected.len(), 53);
    assert_eq!(occurrences(&router, ".route("), expected.len());
    for (path, methods) in expected {
        assert_route(&router, path, methods);
    }
}

#[test]
fn api_route_inventory_is_explicit_and_complete() {
    let router = router_registration_block(API_SOURCE);
    let expected = [
        ("/health", "get(health)"),
        ("/health/live", "get(health)"),
        ("/health/ready", "get(readiness)"),
        ("/session/login", "post(login)"),
        ("/session/mfa", "post(mfa)"),
        ("/session/logout", "post(logout)"),
        ("/session/me", "get(me)"),
        (
            "/files",
            "get(files).patch(rename_file_entry).delete(delete_file_entry)",
        ),
        ("/files/directories", "post(create_directory)"),
        ("/shares", "get(list_shares).post(create_share)"),
        (
            "/shares/{id}",
            "patch(update_share).delete(delete_share)",
        ),
        ("/shares/{id}/activate", "post(activate_share)"),
        ("/shares/{id}/deactivate", "post(deactivate_share)"),
        (
            "/shares/{id}/password",
            "put(set_share_password).delete(remove_share_password)",
        ),
        ("/admins", "get(list_admins).post(create_admin)"),
        ("/admins/{id}/activate", "post(activate_admin)"),
        ("/admins/{id}/deactivate", "post(deactivate_admin)"),
        ("/admins/{id}/password", "put(reset_admin_password)"),
        ("/admins/{id}/totp/reset", "post(reset_admin_totp)"),
        ("/settings", "get(get_settings).put(update_settings)"),
        ("/audit", "get(list_audit)"),
        ("/audit/client-ips", "delete(delete_audit_client_ips)"),
        ("/public/shares/{token}", "get(public_share)"),
        ("/public/shares/{token}/unlock", "post(unlock_share)"),
        (
            "/public/shares/{token}/download",
            "get(crate::web::download).head(crate::web::download)",
        ),
        (
            "/public/shares/{token}/preview",
            "get(crate::web::public_preview)",
        ),
        (
            "/public/shares/{token}/preview/raw",
            "get(crate::web::public_preview_raw).head(crate::web::public_preview_raw)",
        ),
        (
            "/public/shares/{token}/download.zip",
            "get(crate::web::download_zip)",
        ),
        (
            "/public/shares/{token}/upload",
            "post(crate::web::upload_api).layer(DefaultBodyLimit::max(crate::web::HARD_MULTIPART_LIMIT.min(usize::MAX as u64) as usize)).layer(middleware::from_fn(crate::web::guard_multipart_upload))",
        ),
    ];

    assert_eq!(expected.len(), 29);
    assert_eq!(occurrences(&router, ".route("), expected.len());
    for (path, methods) in expected {
        assert_route(&router, path, methods);
    }
}

#[test]
fn approved_source_level_registration_counts_include_test_fixtures() {
    let web = compact(WEB_SOURCE);
    let web_tests = compact(WEB_TEST_SOURCE);
    let api = compact(API_SOURCE);
    let api_tests = compact(API_TEST_SOURCE);
    let web_router = router_registration_block(WEB_SOURCE);
    let api_router = router_registration_block(API_SOURCE);

    assert_eq!(occurrences(&web, ".route("), 53);
    assert_eq!(occurrences(&web_tests, ".route("), 3);
    assert_eq!(
        occurrences(&web, ".route(") + occurrences(&web_tests, ".route("),
        56
    );
    assert_eq!(occurrences(&api, ".route("), 29);
    assert_eq!(occurrences(&api_tests, ".route("), 1);
    assert_eq!(
        occurrences(&api, ".route(") + occurrences(&api_tests, ".route("),
        30
    );
    assert_eq!(
        occurrences(&web, ".route("),
        occurrences(&web_router, ".route("),
        "the Web production source contains only production route registrations"
    );
    assert_eq!(
        occurrences(&api, ".route("),
        occurrences(&api_router, ".route("),
        "the API production source contains only production route registrations"
    );
    assert!(web_tests
        .contains(r#".route("/",get(||async{"ok"})).route("/download",get(||async{"stream"}))"#));
    assert!(api_tests.contains(r#".route("/range",get(||async{"#));
}

#[test]
fn head_and_upload_routes_keep_their_explicit_guards() {
    let web = router_registration_block(WEB_SOURCE);
    let api = router_registration_block(API_SOURCE);

    for (path, methods) in [
        (
            "/admin/preview/raw",
            "get(files::admin_preview_raw).head(files::admin_preview_raw)",
        ),
        (
            "/v/{token}/preview/raw",
            "get(public_preview::public_preview_raw).head(public_preview::public_preview_raw)",
        ),
        (
            "/v/{token}/download",
            "get(transfer::download).head(transfer::download)",
        ),
    ] {
        assert_route(&web, path, methods);
    }
    for (path, methods) in [
        (
            "/public/shares/{token}/download",
            "get(crate::web::download).head(crate::web::download)",
        ),
        (
            "/public/shares/{token}/preview/raw",
            "get(crate::web::public_preview_raw).head(crate::web::public_preview_raw)",
        ),
    ] {
        assert_route(&api, path, methods);
    }

    assert_eq!(occurrences(&web, "guard_multipart_upload"), 4);
    assert_eq!(occurrences(&web, "DefaultBodyLimit::max(limit)"), 4);
    assert_eq!(occurrences(&api, "crate::web::guard_multipart_upload"), 1);
    assert_eq!(
        occurrences(
            &api,
            "DefaultBodyLimit::max(crate::web::HARD_MULTIPART_LIMIT"
        ),
        1
    );
}

#[test]
fn nesting_layer_order_and_original_uri_contract_remain_visible() {
    let web_router = router_registration_block(WEB_SOURCE);
    let api_router = router_registration_block(API_SOURCE);
    let web_source = compact(&format!(
        "{WEB_SOURCE}{WEB_PUBLIC_PREVIEW_SOURCE}{WEB_UPLOAD_SOURCE}"
    ));

    assert_fragments_in_order(
        &web_router,
        &[
            r#".nest("/api/v2", crate::api::router(state.clone()))"#,
            r#".route("/", get(|| async { Redirect::to("/admin") }))"#,
            ".layer(DefaultBodyLimit::max(DEFAULT_REQUEST_BODY_LIMIT))",
            ".layer(middleware::from_fn(admission::absolute_request_body_deadline))",
            ".layer(RequestBodyTimeoutLayer::new(REQUEST_BODY_IDLE_TIMEOUT))",
            ".layer(PropagateRequestIdLayer::x_request_id())",
            ".layer(TraceLayer::new_for_http()",
            ".layer(middleware::from_fn(attach_server_request_id))",
            ".layer(SetRequestIdLayer::new(",
            ".layer(middleware::from_fn(discard_client_request_id))",
            ".layer(CatchPanicLayer::new())",
            ".layer(middleware::from_fn_with_state(state.clone(),admission::response_admission))",
            ".layer(middleware::from_fn(admission::locale_context))",
            ".layer(middleware::from_fn_with_state(state.clone(),admission::audit_client_ip_context))",
            ".layer(middleware::from_fn_with_state(state.clone(),admission::security_headers))",
            ".with_state(state)",
        ],
    );
    assert!(WEB_SOURCE.contains("request_id = %request"));
    assert!(WEB_SOURCE.contains(".get::<ServerRequestId>()"));
    assert_fragments_in_order(
        &api_router,
        &[
            r#".route("/public/shares/{token}/upload","#,
            ".layer(DefaultBodyLimit::max(",
            ".layer(middleware::from_fn(crate::web::guard_multipart_upload))",
            ".layer(middleware::from_fn(normalize_api_errors))",
            ".with_state(state)",
        ],
    );

    for handler_signature in [
        "pub(crate)asyncfnpublic_preview(State(state):State<AppState>,OriginalUri(uri):OriginalUri,",
        "pub(crate)asyncfnpublic_preview_raw(State(state):State<AppState>,OriginalUri(uri):OriginalUri,",
        "pub(crate)asyncfnupload(State(state):State<AppState>,OriginalUri(uri):OriginalUri,",
        "pub(crate)asyncfnupload_api(state:State<AppState>,uri:OriginalUri,",
    ] {
        assert!(
            web_source.contains(handler_signature),
            "nested public handler must keep OriginalUri extraction: {handler_signature}"
        );
    }
}

#[test]
fn api_v1_router_is_fully_removed() {
    let current_sources =
        format!("{WEB_SOURCE}{API_SOURCE}{WEB_PUBLIC_PREVIEW_SOURCE}{WEB_UPLOAD_SOURCE}");
    assert!(
        !current_sources.contains(&format!("/api/{}", "v1")),
        "the removed API v1 namespace must not reappear"
    );
    assert!(WEB_SOURCE.contains(r#".nest("/api/v2", crate::api::router(state.clone()))"#));
}

#[test]
fn release_profile_unwinds_for_catch_panic_layer() {
    let manifest: toml::Value = toml::from_str(include_str!("../Cargo.toml")).unwrap();
    assert_eq!(
        manifest["profile"]["release"]["panic"].as_str(),
        Some("unwind")
    );
    assert!(WEB_SOURCE.contains("#[cfg(panic = \"unwind\")]"));
}
