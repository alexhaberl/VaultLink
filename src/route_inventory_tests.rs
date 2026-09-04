const WEB_SOURCE: &str = include_str!("web.rs");
const WEB_TEST_SOURCE: &str = include_str!("web/tests.rs");
const WEB_PUBLIC_PREVIEW_SOURCE: &str = include_str!("web/public_preview.rs");
const WEB_UPLOAD_SOURCE: &str = include_str!("web/upload.rs");
const API_SOURCE: &str = include_str!("api.rs");
const API_TEST_SOURCE: &str = include_str!("api/tests.rs");
const WEB_ACCOUNT_SOURCE: &str = include_str!("web/account.rs");
const WEB_ADMIN_SOURCE: &str = include_str!("web/admin.rs");
const WEB_FILES_SOURCE: &str = include_str!("web/files.rs");
const WEB_SETTINGS_SOURCE: &str = include_str!("web/settings_audit.rs");
const WEB_SHARES_SOURCE: &str = include_str!("web/shares.rs");
const WEB_SERVICE_TOKENS_SOURCE: &str = include_str!("web/service_tokens.rs");
const API_ADMINS_SOURCE: &str = include_str!("api/admins.rs");
const API_FILES_SOURCE: &str = include_str!("api/files.rs");
const API_SETTINGS_SOURCE: &str = include_str!("api/settings_audit.rs");
const API_SHARES_SOURCE: &str = include_str!("api/shares.rs");
const API_SERVICE_TOKENS_SOURCE: &str = include_str!("api/service_tokens.rs");
const DB_SOURCE: &str = include_str!("db.rs");
const DB_AUDIT_SOURCE: &str = include_str!("db/audit.rs");
const DB_AUTH_SOURCE: &str = include_str!("db/auth.rs");
const DB_RUNTIME_SETTINGS_SOURCE: &str = include_str!("db/runtime_settings.rs");
const DB_SHARES_SOURCE: &str = include_str!("db/shares.rs");

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

fn mutation_handlers(router: &str) -> Vec<String> {
    for unsupported in [".on(", ".route_service(", ".fallback_service("] {
        assert!(
            !router.contains(unsupported),
            "alternate routing primitive {unsupported:?} requires an explicit mutation-inventory review"
        );
    }
    let mut handlers = Vec::new();
    for method in ["post(", "put(", "patch(", "delete("] {
        let mut remaining = router;
        while let Some(offset) = remaining.find(method) {
            let argument = &remaining[offset + method.len()..];
            let end = argument
                .find(')')
                .expect("mutation routing call must have a handler argument");
            handlers.push(argument[..end].to_string());
            remaining = &argument[end + 1..];
        }
    }
    handlers.sort_unstable();
    handlers
}

fn production_function<'a>(source: &'a str, name: &str) -> &'a str {
    let marker = format!("fn {name}(");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("production source must contain function {name}"));
    let remaining = &source[start..];
    let end = [
        "\npub(super) async fn ",
        "\npub(crate) async fn ",
        "\npub async fn ",
        "\nasync fn ",
        "\nfn ",
    ]
    .into_iter()
    .filter_map(|next_function| remaining[1..].find(next_function).map(|index| index + 1))
    .min()
    .unwrap_or(remaining.len());
    &remaining[..end]
}

fn guard_session_bound_handlers(
    router: &str,
    source_name: &str,
    source: &str,
    handlers: &[(&str, &str)],
    guarded: &mut Vec<String>,
) {
    const PROOF_COMMIT_MARKERS: [&str; 8] = [
        "_for_mfa_session(&proof",
        "_for_session(&proof",
        "with_live_mfa_fence(&proof",
        "commit_runtime_settings(&state,proof",
        "commit_runtime_settings(&state,authenticated.proof().clone()",
        ".create_directory(proof,",
        ".rename(proof,",
        ".delete(proof,",
    ];

    let routed = mutation_handlers(router);
    for &(route_handler, implementation) in handlers {
        assert!(
            routed.iter().any(|handler| handler == route_handler),
            "{route_handler} is no longer a mutation in the reviewed router"
        );
        let body = compact(production_function(source, implementation));
        assert!(
            body.contains("mfa_session("),
            "{route_handler} ({source_name}) must authenticate with mfa_session"
        );
        assert!(
            body.contains(".proof()"),
            "{route_handler} ({source_name}) must retain an exact-session proof"
        );
        assert!(
            PROOF_COMMIT_MARKERS
                .iter()
                .any(|marker| body.contains(marker)),
            "{route_handler} ({source_name}) must pass that proof to its commit boundary"
        );
        assert!(
            body.contains("session_bound(") || body.contains("SessionBound::SessionUnavailable"),
            "{route_handler} ({source_name}) must map SessionUnavailable through its route contract"
        );
        guarded.push(route_handler.to_string());
    }
}

fn assert_mutation_inventory_is_guarded(router: &str, guarded: Vec<String>, exempt: &[&str]) {
    let mut expected = guarded;
    expected.extend(exempt.iter().map(|handler| (*handler).to_string()));
    expected.sort_unstable();
    assert_eq!(
        mutation_handlers(router),
        expected,
        "every mutation route must be explicitly proof-guarded or exempt"
    );
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
            "/admin/service-tokens",
            "get(service_tokens::service_tokens_page).post(service_tokens::create_service_token)",
        ),
        (
            "/admin/service-tokens/{id}/revoke",
            "post(service_tokens::revoke_service_token)",
        ),
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

    assert_eq!(expected.len(), 55);
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
            "/monitoring/summary",
            "get(monitoring_summary).head(monitoring_method_not_allowed)",
        ),
        (
            "/monitoring/shares",
            "get(monitoring_share_page).head(monitoring_method_not_allowed)",
        ),
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
        (
            "/service-tokens",
            "get(list_service_tokens).post(create_service_token)",
        ),
        ("/service-tokens/{id}", "delete(revoke_service_token)"),
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

    assert_eq!(expected.len(), 33);
    assert_eq!(occurrences(&router, ".route("), expected.len());
    for (path, methods) in expected {
        assert_route(&router, path, methods);
    }
}

#[test]
fn privileged_mutations_keep_the_exact_session_proof_until_commit() {
    let web = router_registration_block(WEB_SOURCE);
    let mut guarded_web = Vec::new();
    guard_session_bound_handlers(
        &web,
        "src/web/account.rs",
        WEB_ACCOUNT_SOURCE,
        &[
            (
                "account::change_account_password",
                "change_account_password",
            ),
            ("account::confirm_account_mfa", "confirm_account_mfa"),
            ("account::delete_security_key", "delete_security_key"),
            (
                "account::finish_security_key_registration",
                "finish_security_key_registration",
            ),
            ("account::set_account_totp", "set_account_totp"),
            ("account::start_account_mfa", "start_account_mfa"),
            (
                "account::start_security_key_registration",
                "start_security_key_registration",
            ),
        ],
        &mut guarded_web,
    );
    guard_session_bound_handlers(
        &web,
        "src/web/admin.rs",
        WEB_ADMIN_SOURCE,
        &[
            ("admin::activate_admin", "activate_admin"),
            ("admin::create_admin_ui", "create_admin_ui"),
            ("admin::deactivate_admin", "deactivate_admin"),
            ("admin::reset_admin_password", "reset_admin_password"),
            ("admin::reset_admin_totp", "reset_admin_totp"),
        ],
        &mut guarded_web,
    );
    for (source_name, source, handler) in [
        (
            "src/web/account.rs",
            WEB_ACCOUNT_SOURCE,
            "delete_security_key",
        ),
        ("src/web/admin.rs", WEB_ADMIN_SOURCE, "reset_admin_totp"),
        ("src/api/admins.rs", API_ADMINS_SOURCE, "reset_admin_totp"),
    ] {
        let body = compact(production_function(source, handler));
        assert!(
            body.contains("security_settings_mutation.clone().lock_owned().await"),
            "{handler} ({source_name}) must acquire the security-settings mutation guard before deleting WebAuthn credentials"
        );
        assert!(
            body.contains("let_security_settings_guard=security_settings_guard"),
            "{handler} ({source_name}) must retain the security-settings guard inside its non-cancellable database task"
        );
    }
    let registration_finish = compact(production_function(
        WEB_ACCOUNT_SOURCE,
        "finish_security_key_registration",
    ));
    assert_fragments_in_order(
        &registration_finish,
        &[
            "security_settings_mutation.clone().lock_owned().await",
            "webauthn_registration_key()",
            "with_registration_mutations(|registrations|",
            "required_transaction_for_mfa_session(&proof",
            "registrations.finish(&ceremony_key,admin_id,&credential)",
            "insert_admin_webauthn_credential_in_transaction(",
            "RequiredAuditEvent::new(AuditAction::WebauthnCredentialAdded",
        ],
    );
    assert!(
        !registration_finish.contains("session_cookie("),
        "registration finish must carry only its opaque proof-derived ceremony key"
    );
    let registration_start = compact(production_function(
        WEB_ACCOUNT_SOURCE,
        "start_security_key_registration",
    ));
    assert_fragments_in_order(
        &registration_start,
        &[
            "security_settings_mutation.clone().lock_owned().await",
            "webauthn_registration_key()",
            "prepare_registration(ceremony_key",
            "with_registration_mutations(|registrations|",
            "with_live_mfa_fence(&proof",
            "registrations.commit_start(prepared)",
        ],
    );
    assert!(
        !registration_start.contains("session_cookie("),
        "registration start must carry only its opaque proof-derived ceremony key"
    );
    guard_session_bound_handlers(
        &web,
        "src/web/files.rs",
        WEB_FILES_SOURCE,
        &[
            ("files::admin_upload", "process_admin_upload"),
            ("files::admin_upload_queue", "process_admin_upload"),
            ("files::create_directory_ui", "create_directory_ui"),
            ("files::delete_file_ui", "delete_file_ui"),
            ("files::rename_file_ui", "rename_file_ui"),
        ],
        &mut guarded_web,
    );
    let upload = compact(production_function(
        WEB_FILES_SOURCE,
        "process_admin_upload",
    ));
    let upload_directory = compact(production_function(
        WEB_FILES_SOURCE,
        "ensure_admin_upload_directory",
    ));
    assert!(upload.contains("ensure_admin_upload_directory(state,admin.proof().clone()"));
    assert!(upload_directory.contains("proof:MfaSessionProof"));
    assert!(
        upload_directory.contains("with_live_mfa_fence(&proof")
            || upload_directory.contains("required_transaction_for_mfa_session(&proof"),
        "folder_path creation must remain behind a live-session DB fence"
    );
    assert!(upload_directory.contains("SessionBound::SessionUnavailable"));
    assert!(upload_directory.contains("ADMIN_UPLOAD_SESSION_REVOKED"));
    guard_session_bound_handlers(
        &web,
        "src/web/settings_audit.rs",
        WEB_SETTINGS_SOURCE,
        &[
            ("settings_audit::delete_audit_ips_ui", "delete_audit_ips_ui"),
            ("settings_audit::update_settings", "update_settings"),
        ],
        &mut guarded_web,
    );
    guard_session_bound_handlers(
        &web,
        "src/web/shares.rs",
        WEB_SHARES_SOURCE,
        &[
            ("shares::create_share", "create_share"),
            ("shares::delete_share", "delete_share"),
            ("shares::set_share_password", "set_share_password"),
            (
                "shares::set_share_upload_conflict",
                "set_share_upload_conflict",
            ),
            ("shares::toggle_share", "toggle_share"),
        ],
        &mut guarded_web,
    );
    guard_session_bound_handlers(
        &web,
        "src/web/service_tokens.rs",
        WEB_SERVICE_TOKENS_SOURCE,
        &[
            (
                "service_tokens::create_service_token",
                "create_service_token",
            ),
            (
                "service_tokens::revoke_service_token",
                "revoke_service_token",
            ),
        ],
        &mut guarded_web,
    );
    assert_mutation_inventory_is_guarded(
        &web,
        guarded_web,
        &[
            "auth_ui::finish_security_key_authentication",
            "auth_ui::login",
            "auth_ui::logout",
            "auth_ui::mfa",
            "auth_ui::start_security_key_authentication",
            "public::unlock_share",
            "rendering::set_locale",
            "upload::upload",
            "upload::upload_queue",
        ],
    );

    let api = router_registration_block(API_SOURCE);
    let mut guarded_api = Vec::new();
    guard_session_bound_handlers(
        &api,
        "src/api/admins.rs",
        API_ADMINS_SOURCE,
        &[
            ("activate_admin", "set_admin_active_api"),
            ("create_admin", "create_admin"),
            ("deactivate_admin", "set_admin_active_api"),
            ("reset_admin_password", "reset_admin_password"),
            ("reset_admin_totp", "reset_admin_totp"),
        ],
        &mut guarded_api,
    );
    guard_session_bound_handlers(
        &api,
        "src/api/files.rs",
        API_FILES_SOURCE,
        &[
            ("create_directory", "create_directory"),
            ("delete_file_entry", "delete_file_entry"),
            ("rename_file_entry", "rename_file_entry"),
        ],
        &mut guarded_api,
    );
    guard_session_bound_handlers(
        &api,
        "src/api/settings_audit.rs",
        API_SETTINGS_SOURCE,
        &[
            ("delete_audit_client_ips", "delete_audit_client_ips"),
            ("update_settings", "update_settings"),
        ],
        &mut guarded_api,
    );
    guard_session_bound_handlers(
        &api,
        "src/api/shares.rs",
        API_SHARES_SOURCE,
        &[
            ("activate_share", "set_share_active_api"),
            ("create_share", "create_share"),
            ("deactivate_share", "set_share_active_api"),
            ("delete_share", "delete_share"),
            ("remove_share_password", "remove_share_password"),
            ("set_share_password", "set_share_password"),
            ("update_share", "update_share"),
        ],
        &mut guarded_api,
    );
    guard_session_bound_handlers(
        &api,
        "src/api/service_tokens.rs",
        API_SERVICE_TOKENS_SOURCE,
        &[
            ("create_service_token", "create_service_token"),
            ("revoke_service_token", "revoke_service_token"),
        ],
        &mut guarded_api,
    );
    assert_mutation_inventory_is_guarded(
        &api,
        guarded_api,
        &[
            "crate::web::upload_api",
            "login",
            "logout",
            "mfa",
            "unlock_share",
        ],
    );
}

#[test]
fn enrollment_times_are_captured_after_the_session_fenced_writer_begins() {
    for handler in [
        "start_admin_mfa_enrollment_and_audit_for_session",
        "activate_admin_mfa_enrollment_for_session",
    ] {
        let body = compact(production_function(DB_AUTH_SOURCE, handler));
        let fence = body
            .find("required_transaction_for_mfa_session(proof,context")
            .unwrap_or_else(|| panic!("{handler} must retain its live-session writer fence"));
        let now = body[fence..]
            .find("Utc::now()")
            .map(|offset| fence + offset)
            .unwrap_or_else(|| panic!("{handler} must capture its enrollment time"));
        assert!(
            now > fence,
            "{handler} must capture time only after BEGIN IMMEDIATE and live-session validation"
        );
        assert!(
            !body[..fence].contains("Utc::now()"),
            "{handler} must not use a timestamp captured while waiting for SQLite's writer slot"
        );
    }
}

#[test]
fn proof_factories_and_legacy_mutators_are_not_production_escape_hatches() {
    let database = compact(DB_SOURCE);
    assert!(database.contains("implMfaSessionProof{fnfrom_token("));
    assert!(!database.contains("pub(crate)fnfrom_token("));
    assert!(database.contains("implAuthenticatedMfaSession{fnnew("));
    assert!(!database.contains("pub(crate)fnnew(token:&str,session:Session)"));

    let auth = compact(DB_AUTH_SOURCE);
    assert_eq!(occurrences(&auth, "AuthenticatedMfaSession::new("), 1);
    let factory = compact(production_function(
        DB_AUTH_SOURCE,
        "authenticated_mfa_session",
    ));
    assert!(factory.contains("self.session(token)?"));
    assert!(factory.contains("if!session.mfa_verified"));
    assert!(factory.contains("AuthenticatedMfaSession::new(token,session)"));

    for (source_name, source, legacy) in [
        ("db/auth.rs", DB_AUTH_SOURCE, "create_admin_and_audit"),
        ("db/auth.rs", DB_AUTH_SOURCE, "activate_admin_and_audit"),
        ("db/auth.rs", DB_AUTH_SOURCE, "deactivate_admin_and_audit"),
        ("db/auth.rs", DB_AUTH_SOURCE, "change_admin_password_cas"),
        (
            "db/auth.rs",
            DB_AUTH_SOURCE,
            "start_admin_mfa_enrollment_and_audit",
        ),
        (
            "db/auth.rs",
            DB_AUTH_SOURCE,
            "activate_admin_mfa_enrollment",
        ),
        (
            "db/auth.rs",
            DB_AUTH_SOURCE,
            "reset_admin_password_and_audit",
        ),
        ("db/auth.rs", DB_AUTH_SOURCE, "reset_admin_totp_and_audit"),
        (
            "db/auth.rs",
            DB_AUTH_SOURCE,
            "cleanup_expired_admin_mfa_enrollments",
        ),
        (
            "db/auth.rs",
            DB_AUTH_SOURCE,
            "update_admin_webauthn_credential",
        ),
        (
            "db/shares.rs",
            DB_SHARES_SOURCE,
            "create_share_with_upload_limits_and_audit",
        ),
        (
            "db/shares.rs",
            DB_SHARES_SOURCE,
            "update_share_controls_and_audit",
        ),
        ("db/shares.rs", DB_SHARES_SOURCE, "delete_share_and_audit"),
        (
            "db/runtime_settings.rs",
            DB_RUNTIME_SETTINGS_SOURCE,
            "replace_runtime_settings_and_audit",
        ),
        (
            "db/audit.rs",
            DB_AUDIT_SOURCE,
            "delete_audit_client_ips_if_disabled_and_audit",
        ),
    ] {
        let source = compact(source);
        assert!(
            source.contains(&format!("#[cfg(test)]pubfn{legacy}(")),
            "{legacy} in {source_name} must remain unavailable in production builds"
        );
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

    assert_eq!(occurrences(&web, ".route("), 55);
    assert_eq!(occurrences(&web_tests, ".route("), 4);
    assert_eq!(
        occurrences(&web, ".route(") + occurrences(&web_tests, ".route("),
        59
    );
    assert_eq!(occurrences(&api, ".route("), 33);
    assert_eq!(occurrences(&api_tests, ".route("), 1);
    assert_eq!(
        occurrences(&api, ".route(") + occurrences(&api_tests, ".route("),
        34
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
            "/monitoring/summary",
            "get(monitoring_summary).head(monitoring_method_not_allowed)",
        ),
        (
            "/monitoring/shares",
            "get(monitoring_share_page).head(monitoring_method_not_allowed)",
        ),
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
