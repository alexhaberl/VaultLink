#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{AuthContract, RouteMethod, RouteSpec, RouteSurface};
    use axum::{
        body::Body,
        http::{Method, Request},
    };
    use tower::ServiceExt;

    const UNMATCHED_SETUP_ROUTE_STATUS: StatusCode = StatusCode::IM_A_TEAPOT;

    fn test_setup_state(config_path: PathBuf) -> SetupState {
        let (start_sender, _start_receiver) = tokio::sync::oneshot::channel();
        SetupState {
            config_path: Arc::new(config_path),
            token: Arc::new("token".into()),
            commit: Arc::new(tokio::sync::Mutex::new(false)),
            start_sender: Arc::new(tokio::sync::Mutex::new(Some(start_sender))),
            start_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    fn request(method: Method, uri: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn setup_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("vaultlink_setup=token"),
        );
        headers
    }

    fn authorized_request(method: Method, uri: &str, body: &str) -> Request<Body> {
        let mut request = request(method, uri, body);
        request.headers_mut().extend(setup_headers());
        request
    }

    fn setup_contract_request(spec: &RouteSpec, authorized: bool) -> Request<Body> {
        let method = match spec.method {
            RouteMethod::Get => Method::GET,
            RouteMethod::Head => Method::HEAD,
            RouteMethod::Post => Method::POST,
            RouteMethod::Put => Method::PUT,
            RouteMethod::Patch => Method::PATCH,
            RouteMethod::Delete => Method::DELETE,
        };
        let uri = if spec.path == "/browse" {
            "/browse?path=%2Fdefinitely-missing-vaultlink-route-contract"
        } else {
            spec.path
        };
        let (content_type, body) = match spec.path {
            "/" if spec.method == RouteMethod::Post => (
                "application/x-www-form-urlencoded",
                "server_mode=invalid&listen_address=127.0.0.1%3A8080&public_base_url=http%3A%2F%2Flocalhost%3A8080&root_mount_path=%2Ftmp&data_directory=%2Ftmp&internal_directory=%2Ftmp&expected_filesystem_type=&expected_mount_source=&max_upload_size_mb=1&max_zip_size_gb=1&max_zip_files=10&max_search_entries=100&max_search_results=10&max_preview_size_mb=1&preview_extensions=txt&image_preview_extensions=png&max_media_preview_size_mb=1&blocked_extensions=exe&trusted_proxies=&certificate_source=files&tls_cert_file=&tls_key_file=&letsencrypt_contact_email=&letsencrypt_cache_dir=acme&log_level=info&admin_username=admin&admin_password=not-a-real-password&admin_password_confirm=not-a-real-password",
            ),
            "/bootstrap" => ("application/json", "{}"),
            "/locale" => (
                "application/x-www-form-urlencoded",
                "locale=en&return_to=%2F",
            ),
            _ => ("application/octet-stream", ""),
        };
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(body))
            .unwrap();
        if authorized {
            request.headers_mut().extend(setup_headers());
        }
        request
    }

    #[tokio::test]
    async fn every_declared_setup_route_is_routable_and_enforces_setup_token() {
        let config_dir = tempfile::tempdir().unwrap();
        let app = setup_router(test_setup_state(config_dir.path().join("config.toml")))
            .fallback(|| async { UNMATCHED_SETUP_ROUTE_STATUS });

        for spec in SETUP_ROUTE_SPECS {
            assert_eq!(spec.surface, RouteSurface::Setup, "{spec:?}");
            let anonymous = app
                .clone()
                .oneshot(setup_contract_request(spec, false))
                .await
                .unwrap();
            assert_ne!(
                anonymous.status(),
                UNMATCHED_SETUP_ROUTE_STATUS,
                "declared setup route did not match: {spec:?}"
            );

            match spec.auth {
                AuthContract::SetupToken => {
                    assert_eq!(
                        anonymous.status(),
                        StatusCode::UNAUTHORIZED,
                        "setup-token route did not reject an anonymous request: {spec:?}"
                    );
                    let authorized = app
                        .clone()
                        .oneshot(setup_contract_request(spec, true))
                        .await
                        .unwrap();
                    assert_ne!(
                        authorized.status(),
                        UNMATCHED_SETUP_ROUTE_STATUS,
                        "authorized setup route did not match: {spec:?}"
                    );
                    assert_ne!(
                        authorized.status(),
                        StatusCode::UNAUTHORIZED,
                        "valid setup token was rejected: {spec:?}"
                    );
                }
                AuthContract::Public => {}
                contract => panic!("unsupported setup auth contract {contract:?}: {spec:?}"),
            }
        }
    }

    async fn response_text(response: Response) -> String {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    fn form(root: &Path, data: &Path) -> SetupForm {
        SetupForm {
            server_mode: "development".into(),
            listen_address: "127.0.0.1:8080".into(),
            public_base_url: "http://localhost:8080".into(),
            root_mount_path: root.display().to_string(),
            data_directory: data.display().to_string(),
            internal_directory: root
                .join(crate::config::DEFAULT_INTERNAL_DIRECTORY_NAME)
                .display()
                .to_string(),
            require_mount: None,
            external_writers: None,
            allow_external_writer_replace: None,
            expected_filesystem_type: String::new(),
            expected_mount_source: String::new(),
            max_upload_size_mb: "1".into(),
            max_zip_size_gb: "1".into(),
            max_zip_files: "10".into(),
            max_search_entries: "100".into(),
            max_search_results: "10".into(),
            max_preview_size_mb: "1".into(),
            preview_extensions: "txt,log".into(),
            image_preview_extensions: "jpg,png".into(),
            pdf_preview_enabled: Some("on".into()),
            max_media_preview_size_mb: "1".into(),
            blocked_extensions: "exe".into(),
            audit_client_ip_enabled: None,
            trusted_proxies: "127.0.0.1".into(),
            certificate_source: "files".into(),
            tls_cert_file: "".into(),
            tls_key_file: "".into(),
            letsencrypt_contact_email: "".into(),
            letsencrypt_cache_dir: "acme".into(),
            letsencrypt_staging: Some("on".into()),
            hsts_enabled: None,
            log_level: "info".into(),
            admin_username: "admin".into(),
            admin_password: "a very long password".into(),
            admin_password_confirm: "a very long password".into(),
        }
    }

    fn configure_production_mount_policy(form: &mut SetupForm, root: &Path) {
        form.internal_directory = root
            .parent()
            .unwrap()
            .join(".vaultlink-internal")
            .display()
            .to_string();
        form.require_mount = Some("on".into());
        form.expected_filesystem_type = "ext4".into();
        form.expected_mount_source = "/dev/mapper/vaultlink-test".into();
    }

    #[tokio::test]
    async fn setup_form_uses_branding_units_log_dropdown_and_directory_picker() {
        let html = i18n::scope(Locale::De, "/".into(), async {
            page(&setup_form(None), None)
        })
        .await;
        assert!(html.contains("VaultLink<small>Secure file sharing</small>"));
        assert!(html.contains(r#"href="/assets/favicon.svg""#));
        assert!(html.contains(r#"href="/assets/favicon-32.png""#));
        assert!(html.contains(r#"<html lang="de">"#));
        assert!(html.contains("Ersteinrichtung"));
        assert!(
            html.contains("Lokaler Bootstrap für die initiale Konfiguration und den ersten Admin.")
        );
        assert!(!html.contains("Setup bindet ausschließlich an Loopback."));
        assert!(html
            .contains(r#"name="max_upload_size_mb" type="number" min="1" step="1" value="50000""#));
        assert!(
            html.contains(r#"name="max_zip_size_gb" type="number" min="0" step="1" value="20""#)
        );
        assert!(html.contains(
            r#"name="max_preview_size_mb" type="number" min="1" max="64" step="1" value="50""#
        ));
        assert!(html.contains("Max. Quelldaten pro ZIP in GB"));
        assert!(!html.contains("Max. Quelldaten pro ZIP in GB (0 = kein separates Limit)"));
        assert!(html.contains("Max. Dateien pro ZIP"));
        assert!(!html.contains("Max. Dateien pro ZIP (0 = kein separates Limit)"));
        assert!(html.contains("name=\"max_media_preview_size_mb\""));
        assert!(html.contains("<select name=\"log_level\">"));
        assert!(html.contains("VaultLink-Dienstadresse nach dem Setup"));
        assert!(html.contains("Hier lauscht der spätere VaultLink-Dienst."));
        assert!(!html.contains("Die lokale Setup-Adresse bleibt davon unabhängig"));
        assert!(
            html.contains(r#"name="admin_username" value="admin" minlength="3" maxlength="64""#)
        );
        assert!(html.contains("data-dir-picker=\"root_mount_path\""));
        assert!(html.contains("data-dir-picker=\"internal_directory\""));
        assert!(html.contains(r#"name="data_directory" value="/var/lib/vaultlink" required"#));
        assert!(!html.contains(r#"name="data_directory" value="/tmp/vaultlink-data""#));
        assert!(html.contains(
            r#"<input name="internal_directory" value="/tmp/vaultlink-root/.vaultlink-internal" required>"#
        ));
        assert!(!html.contains(r#"name="internal_directory" data-mount-policy-field"#));
        assert!(html.contains("data-require-mount"));
        assert!(html.contains("data-external-writers"));
        assert!(html.contains("data-external-writers-field"));
        assert!(html.contains("Externe SMB-Clients"));
        assert!(!html.contains("Externe SMB-Schreiber"));
        assert!(html.contains("data-external-writer-replace-field"));
        assert!(html.contains("SMB-Replace erlauben"));
        assert!(html.contains("data-detected-mount"));
        assert!(html.contains("data-refresh-mounts"));
        assert!(html.contains(
            r#"<input type="hidden" name="expected_filesystem_type" data-mount-policy-field>"#
        ));
        assert!(!html.contains(r#"<select name="expected_filesystem_type""#));
        assert!(html.contains(
            r#"<input type="hidden" name="expected_mount_source" data-mount-policy-field>"#
        ));
        assert!(!html.contains("Erwartete Mount-Quelle"));
        assert!(html.contains("data-file-picker=\"tls_cert_file\""));
        assert!(html.contains("data-file-picker=\"tls_key_file\""));
        assert!(html.contains("data-dir-dialog"));
        assert!(html.contains("data-server-mode"));
        assert!(html.contains("data-production-section"));
        assert!(html.contains("data-mode-only=\"reverse_proxy\""));
        assert!(html.contains("data-certificate-only=\"files\""));
        assert!(html.contains("data-certificate-only=\"letsencrypt\""));
        assert!(!html.contains("Reverse Proxy aktiv"));
        assert!(!html.contains("Standalone TLS aktiv"));
        assert!(!html.contains("name=\"production_mode\""));
        assert!(!html.contains("name=\"secure_cookie\""));
        assert!(SETUP_JAVASCRIPT.contains("fallbackToRoot"));
        assert!(SETUP_JAVASCRIPT.contains("fetch('/mounts')"));
        assert!(!SETUP_JAVASCRIPT.contains("?token="));
        assert!(SETUP_JAVASCRIPT.contains("history.replaceState"));
        assert!(SETUP_JAVASCRIPT.contains("applyDetectedMount"));
        assert!(SETUP_JAVASCRIPT
            .contains("internal_directory.value === '/tmp/vaultlink-root/.vaultlink-internal'"));
        assert!(SETUP_JAVASCRIPT.contains("expectedFilesystemType.value = ''"));
        assert!(SETUP_JAVASCRIPT.contains("expectedMountSource.value = ''"));
        assert!(SETUP_JAVASCRIPT.contains("internalDirectory.readOnly = !requireMount.checked"));
        assert!(SETUP_JAVASCRIPT.contains("form.addEventListener('submit', syncConditionalFields)"));
        assert!(SETUP_JAVASCRIPT.contains("previousMountPoint"));
        assert!(SETUP_JAVASCRIPT.contains("externalWritersField.hidden = !cifsStorage"));
        assert!(SETUP_JAVASCRIPT
            .contains("externalWriterReplaceField.hidden = !externalClientsEnabled"));
        assert!(!SETUP_JAVASCRIPT.contains("`Ordner ${entry.name}`"));
        assert!(!html.contains("Max Upload Bytes"));
        assert!(!html.contains("Log Level<br><input"));
        assert!(!html.contains("<vl-i18n"));
    }

    #[tokio::test]
    async fn setup_http_locale_defaults_to_english_and_cookie_overrides_it() {
        let config_dir = tempfile::tempdir().unwrap();
        let app = setup_router(test_setup_state(config_dir.path().join("config.toml")));

        let fallback = authorized_request(Method::GET, "/", "");
        let response = app.clone().oneshot(fallback).await.unwrap();
        assert_eq!(response.headers()[header::CONTENT_LANGUAGE], "en");
        let english = response_text(response).await;
        assert!(english.contains(r#"<html lang="en">"#));
        assert!(english.contains("Initial setup"));
        assert!(english.contains("VaultLink service address after setup"));
        assert!(english.contains(r#"name="return_to" value="/""#));
        assert!(english.contains(r#">DE</button><span aria-hidden="true">/</span>"#));
        for german_fragment in [
            "Ersteinrichtung",
            "Sicherheit",
            "Durchsuchen",
            "Datenverzeichnis",
            "Blockierte Endungen",
            "Suche Max. Einträge",
            "Erster Admin",
            "Benutzername",
            "Passwort bestätigen",
            "Setup schreiben",
            "Verzeichnis auswählen",
        ] {
            assert!(!english.contains(german_fragment), "{german_fragment}");
        }
        assert!(!english.contains("<vl-i18n"));

        let mut german_header = authorized_request(Method::GET, "/", "");
        german_header.headers_mut().insert(
            header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("de-AT,de;q=0.9"),
        );
        let response = app.clone().oneshot(german_header).await.unwrap();
        assert_eq!(response.headers()[header::CONTENT_LANGUAGE], "en");
        assert!(response_text(response).await.contains("Initial setup"));

        let mut german_cookie = authorized_request(Method::GET, "/", "");
        german_cookie.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_static("vaultlink_setup=token; vaultlink_locale=de"),
        );
        let response = app.clone().oneshot(german_cookie).await.unwrap();
        assert_eq!(response.headers()[header::CONTENT_LANGUAGE], "de");
        let german = response_text(response).await;
        assert!(german.contains(r#"<html lang="de">"#));
        assert!(german.contains("Ersteinrichtung"));
        assert!(german.contains("VaultLink-Dienstadresse nach dem Setup"));
        for english_fragment in [
            "Initial setup",
            "Choose directory",
            "Save setup",
            "First administrator",
            "Blocked extensions",
        ] {
            assert!(!german.contains(english_fragment), "{english_fragment}");
        }
        assert!(!german.contains("<vl-i18n"));

        let mut cookie_override = authorized_request(Method::GET, "/", "");
        cookie_override.headers_mut().insert(
            header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        cookie_override.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_static("vaultlink_setup=token; vaultlink_locale=de"),
        );
        let response = app.oneshot(cookie_override).await.unwrap();
        assert_eq!(response.headers()[header::CONTENT_LANGUAGE], "de");
        assert!(response_text(response).await.contains("Ersteinrichtung"));

        let config_dir = tempfile::tempdir().unwrap();
        let unauthorized_app =
            setup_router(test_setup_state(config_dir.path().join("config.toml")));
        let unauthorized = unauthorized_app
            .oneshot(request(Method::GET, "/", ""))
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(unauthorized.headers()[header::CONTENT_LANGUAGE], "en");
        let unauthorized = response_text(unauthorized).await;
        assert!(unauthorized.contains("The setup token is missing or invalid."));
        assert!(unauthorized.contains("vl-locale-switch"));
        assert!(!unauthorized.contains("<vl-i18n"));
    }

    #[tokio::test]
    async fn setup_locale_route_uses_clean_return_path_and_rejects_external_return() {
        let config_dir = tempfile::tempdir().unwrap();
        let app = setup_router(test_setup_state(config_dir.path().join("config.toml")));

        let response = app
            .clone()
            .oneshot(request(Method::POST, "/locale", "locale=de&return_to=%2F"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/");
        let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(cookie.starts_with("vaultlink_locale=de;"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));

        let external = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/locale",
                "locale=en&return_to=https%3A%2F%2Fevil.example%2F",
            ))
            .await
            .unwrap();
        assert_eq!(external.headers()[header::LOCATION], "/");

        let non_get_setup_path = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/locale",
                "locale=en&return_to=%2Fcomplete%3Ftoken%3Dtoken",
            ))
            .await
            .unwrap();
        assert_eq!(non_get_setup_path.headers()[header::LOCATION], "/");

        let invalid = app
            .oneshot(request(
                Method::POST,
                "/locale",
                "locale=fr&return_to=%2F%3Ftoken%3Dtoken",
            ))
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        assert_eq!(invalid.headers()[header::CONTENT_LANGUAGE], "en");
        assert!(response_text(invalid).await.contains("Invalid language"));
    }

    #[tokio::test]
    async fn transitional_setup_pages_do_not_offer_a_lossy_locale_redirect() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let state = test_setup_state(config_dir.path().join("config.toml"));

        let response = i18n::scope(Locale::En, "/".into(), async {
            submit_setup(
                State(state.clone()),
                setup_headers(),
                Form(form(root.path(), data.path())),
            )
            .await
        })
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_text(response).await;
        assert!(body.contains("Secret stored safely"));
        assert!(!body.contains(r#"action="/locale""#));

        let response = i18n::scope(Locale::En, "/complete".into(), async {
            complete_setup(State(state), setup_headers()).await
        })
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_text(response).await;
        assert!(body.contains("Start VaultLink now"));
        assert!(!body.contains(r#"action="/locale""#));
    }

    #[tokio::test]
    async fn setup_javascript_localizes_visible_picker_text() {
        let config_dir = tempfile::tempdir().unwrap();
        let app = setup_router(test_setup_state(config_dir.path().join("config.toml")));

        let english = request(Method::GET, "/assets/setup.js", "");
        let response = app.clone().oneshot(english).await.unwrap();
        assert_eq!(response.headers()[header::CONTENT_LANGUAGE], "en");
        let english = response_text(response).await;
        assert!(english.contains("Directory cannot be read."));
        assert!(english.contains("Choose file"));
        assert!(!english.contains("Verzeichnis kann nicht gelesen werden."));
        assert!(!english.contains("<vl-i18n"));

        let mut german = request(Method::GET, "/assets/setup.js", "");
        german.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_static("vaultlink_locale=de"),
        );
        let response = app.oneshot(german).await.unwrap();
        assert_eq!(response.headers()[header::CONTENT_LANGUAGE], "de");
        let german = response_text(response).await;
        assert!(german.contains("Verzeichnis kann nicht gelesen werden."));
        assert!(german.contains("Datei auswählen"));
        assert!(!german.contains("<vl-i18n"));
    }

    #[tokio::test]
    async fn setup_serves_the_shared_logo_favicons() {
        let config_dir = tempfile::tempdir().unwrap();
        let app = setup_router(test_setup_state(config_dir.path().join("config.toml")));

        let svg = app
            .clone()
            .oneshot(request(Method::GET, "/assets/favicon.svg", ""))
            .await
            .unwrap();
        assert_eq!(
            svg.headers()[header::CONTENT_TYPE],
            "image/svg+xml; charset=utf-8"
        );
        assert_eq!(response_text(svg).await, ui::LOGO_SVG);

        let png = app
            .oneshot(request(Method::GET, "/assets/favicon-32.png", ""))
            .await
            .unwrap();
        assert_eq!(png.headers()[header::CONTENT_TYPE], "image/png");
        let bytes = axum::body::to_bytes(png.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(bytes.as_ref(), ui::FAVICON_PNG);
    }

    #[tokio::test]
    async fn setup_markers_cannot_collide_with_escaped_user_data() {
        let marker_shaped = r#"><vl-i18n key="setup.server"/>"#;
        let html = i18n::scope(Locale::En, "/".into(), async {
            page(&setup_form(Some(marker_shaped)), Some(marker_shaped))
        })
        .await;
        assert!(!html.contains("<vl-i18n"));
        assert!(html.contains("setup.server"));
        assert!(html.contains("Initial setup"));
    }

    #[tokio::test]
    async fn setup_error_payloads_are_autoescaped_by_askama() {
        let payload = r#"<img src=x onerror=alert(1)>"#;
        let html = i18n::scope(Locale::En, "/".into(), async {
            page(&setup_form(Some(payload)), None)
        })
        .await;
        assert!(!html.contains(payload));
        assert!(!html.contains("<img src=x"));
        assert!(html.contains("img src=x onerror=alert(1)"));
    }

    #[test]
    fn setup_qr_svg_renders_totp_code() {
        let qr = TrustedMarkup::generated_qr(
            "otpauth://totp/VaultLink:admin?secret=ABC&issuer=VaultLink",
        )
        .unwrap();
        let rendered = SetupCompletedTemplate {
            qr: &qr,
            secret: "ABC",
            otpauth: "otpauth://fixture",
        }
        .render()
        .unwrap();
        assert!(rendered.contains("<svg"));
        assert!(rendered.contains("#081226"));
        assert!(!rendered.contains("&lt;svg"));
    }

    #[test]
    fn setup_bind_must_be_loopback() {
        assert!(validate_setup_listen("127.0.0.1:8090".parse().unwrap()).is_ok());
        assert!(validate_setup_listen("127.0.0.1:0".parse().unwrap()).is_err());
        assert!(validate_setup_listen("0.0.0.0:8090".parse().unwrap()).is_err());
        assert!(validate_setup_listen("192.0.2.10:8090".parse().unwrap()).is_err());
        assert!(validate_setup_listen("[::]:8090".parse().unwrap()).is_err());
    }

    #[tokio::test]
    async fn setup_admin_username_is_three_to_sixty_four_safe_ascii_characters() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();

        for invalid in ["ab".to_string(), "a".repeat(65), "admín".to_string()] {
            let mut invalid_form = form(root.path(), data.path());
            invalid_form.admin_username = invalid;
            let error = match build_and_store(&config_dir.path().join("invalid.toml"), invalid_form)
                .await
            {
                Ok(_) => panic!("invalid setup username was accepted"),
                Err(error) => error,
            };
            assert_eq!(error, i18n::text(Locale::En, i18n::USERNAME_POLICY));
        }

        let max_length_username = "a".repeat(64);
        let mut valid_form = form(root.path(), data.path());
        valid_form.admin_username = max_length_username.clone();
        build_and_store(&config_dir.path().join("config.toml"), valid_form)
            .await
            .unwrap();
        let database = Database::open(data.path().join("data.sqlite")).unwrap();
        assert!(database.admin(&max_length_username).unwrap().is_some());
    }

    #[tokio::test]
    async fn setup_validation_errors_follow_the_selected_locale() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();

        let mut invalid_extensions = form(root.path(), data.path());
        invalid_extensions.preview_extensions = "txt,../bad".into();
        let error = i18n::scope(Locale::De, "/".into(), async {
            match build_and_store(
                &config_dir.path().join("invalid-extensions.toml"),
                invalid_extensions,
            )
            .await
            {
                Ok(_) => panic!("invalid extension list was accepted"),
                Err(error) => error,
            }
        })
        .await;
        assert_eq!(error, "Eine Endungsliste enthält ungültige Werte.");

        let mut invalid_config = form(root.path(), data.path());
        invalid_config.listen_address = "0.0.0.0:8080".into();
        let error = i18n::scope(Locale::De, "/".into(), async {
            match build_and_store(
                &config_dir.path().join("invalid-config.toml"),
                invalid_config,
            )
            .await
            {
                Ok(_) => panic!("invalid setup configuration was accepted"),
                Err(error) => error,
            }
        })
        .await;
        assert!(error.starts_with("Die Setup-Eingaben ergeben keine gültige"));
    }

    #[tokio::test]
    async fn empty_preview_extensions_leave_no_setup_artifacts() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.toml");
        let mut setup_form = form(root.path(), data.path());
        setup_form.preview_extensions.clear();

        let error = build_and_store_with_mount_validator(&config_path, setup_form, |_| {
            Ok(SetupStorageValidation::TestBypass)
        })
        .await
        .err()
        .expect("empty preview extensions must fail");
        assert!(error.contains("preview_extensions must not be empty"));
        assert!(!config_path.exists());
        assert!(!data.path().join("data.sqlite").exists());
    }

    #[tokio::test]
    async fn overlong_admin_password_cannot_be_persisted_by_setup() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.toml");
        let mut setup_form = form(root.path(), data.path());
        let password = "x".repeat(auth::MAX_PASSWORD_BYTES + 1);
        setup_form.admin_password = password.clone().into();
        setup_form.admin_password_confirm = password.into();

        let error = build_and_store_with_mount_validator(&config_path, setup_form, |_| {
            Ok(SetupStorageValidation::TestBypass)
        })
        .await
        .err()
        .expect("overlong admin passwords must fail");
        assert!(error.contains("256"));
        assert!(!config_path.exists());
        assert!(!data.path().join("data.sqlite").exists());
    }

    #[test]
    fn setup_terminal_explains_headless_ssh_tunnel_and_local_url() {
        let output =
            setup_access_instructions("127.0.0.1:8090".parse().unwrap(), "one-time-setup-token");
        assert!(output.contains("lauscht ausschließlich auf Loopback"));
        assert!(output.contains("ssh -4 -N -L 127.0.0.1:8090:127.0.0.1:8090 BENUTZER@SERVER"));
        assert!(output
            .lines()
            .any(|line| line == "http://127.0.0.1:8090/#token=one-time-setup-token"));
        assert_eq!(output.matches("one-time-setup-token").count(), 1);
    }

    #[test]
    fn setup_terminal_formats_ipv6_loopback_for_ssh() {
        let output = setup_access_instructions("[::1]:8091".parse().unwrap(), "token");
        assert!(output.contains("ssh -4 -N -L 127.0.0.1:8091:[::1]:8091 BENUTZER@SERVER"));
        assert!(output
            .lines()
            .any(|line| line == "http://127.0.0.1:8091/#token=token"));
    }

    #[test]
    fn setup_browser_is_confined_to_mode_specific_roots() {
        assert!(setup_browse_path_allowed(
            Path::new("/tmp/vaultlink"),
            None,
            Some("development")
        ));
        assert!(!setup_browse_path_allowed(
            Path::new("/tmp/vaultlink"),
            None,
            Some("reverse_proxy")
        ));
        assert!(setup_browse_path_allowed(
            Path::new("/mnt/storage"),
            None,
            Some("reverse_proxy")
        ));
        assert!(setup_browse_path_allowed(
            Path::new("/etc/letsencrypt/live/example/fullchain.pem"),
            Some("certificate"),
            Some("standalone_tls")
        ));
        assert!(setup_browse_path_allowed(
            Path::new("/etc/pki/tls/certs/example.crt"),
            Some("certificate"),
            Some("standalone_tls")
        ));
        assert!(setup_browse_path_allowed(
            Path::new("/etc/pki/tls/private/example.key"),
            Some("private_key"),
            Some("standalone_tls")
        ));
        assert!(!setup_browse_path_allowed(
            Path::new("/home/operator/secret.pem"),
            Some("certificate"),
            Some("standalone_tls")
        ));
    }

    #[test]
    fn setup_browser_uses_openat2_and_rejects_symlink_components() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir_in("/tmp").unwrap();
        let directory = root.path().join("storage");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("visible.pem"), b"certificate").unwrap();
        let entries = read_setup_browse_directory(&directory, true, Some("certificate")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "visible.pem");

        let link = root.path().join("linked-storage");
        symlink(&directory, &link).unwrap();
        assert!(read_setup_browse_directory(&link, true, Some("certificate")).is_err());
    }

    #[tokio::test]
    async fn setup_mount_discovery_requires_cookie_and_returns_json() {
        let config_dir = tempfile::tempdir().unwrap();
        let app = setup_router(test_setup_state(config_dir.path().join("config.toml")));

        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/mounts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let authorized = app
            .oneshot(authorized_request(Method::GET, "/mounts", ""))
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&response_text(authorized).await).unwrap();
        assert!(body["mounts"].is_array());
        assert!(body["error"].is_null());
    }

    #[test]
    fn mount_layout_readiness_requires_real_preprovisioned_directories() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("shared");
        let internal = base.path().join(".vaultlink-internal");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&internal).unwrap();
        std::fs::create_dir(internal.join("uploads")).unwrap();
        assert!(!mount_layout_ready(&root, &internal));
        std::fs::create_dir(internal.join("tombstones")).unwrap();
        assert!(mount_layout_ready(&root, &internal));
    }

    #[tokio::test]
    async fn setup_writes_config_and_initial_admin() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.toml");
        let result = build_and_store(&config_path, form(root.path(), data.path()))
            .await
            .unwrap();
        assert!(!result.totp_secret.expose_secret().is_empty());
        let config = Config::load(&config_path).unwrap();
        assert_eq!(config.storage.max_preview_size, 1_000_000);
        let confirmed_fragment = setup_confirmed_body(&config, "Secret geschlossen.")
            .render()
            .unwrap();
        let confirmed = i18n::render_markers(Locale::De, &confirmed_fragment);
        assert!(confirmed.contains("VaultLink jetzt starten"));
        assert!(confirmed.contains("Development"));
        assert!(!confirmed.contains("<vl-i18n"));
        let setup_source = concat!(
            include_str!("../setup.rs"),
            include_str!("state.rs"),
            include_str!("routes.rs"),
            include_str!("handlers.rs"),
            include_str!("commit.rs"),
            include_str!("discovery.rs"),
            include_str!("views.rs"),
        );
        assert!(!setup_source.contains(concat!("Ctrl", "+C")));
        let database = Database::open(data.path().join("data.sqlite")).unwrap();
        assert_eq!(database.admin_count().unwrap(), 1);
        assert!(database.admin("admin").unwrap().is_some());
    }

    #[tokio::test]
    async fn development_setup_creates_a_missing_local_root() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("new-storage-root");
        let data = base.path().join("new-data-directory");
        let config_path = base.path().join("config.toml");

        build_and_store(&config_path, form(&root, &data))
            .await
            .unwrap();

        assert!(root.is_dir());
        assert!(data.join("data.sqlite").is_file());
        let config = Config::load(&config_path).unwrap();
        assert_eq!(
            config.storage.internal_directory.as_deref(),
            Some(
                root.join(crate::config::DEFAULT_INTERNAL_DIRECTORY_NAME)
                    .as_path()
            )
        );
    }

    #[tokio::test]
    async fn setup_start_button_signals_transition_to_normal_server() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.toml");
        build_and_store(&config_path, form(root.path(), data.path()))
            .await
            .unwrap();
        let (start_sender, start_receiver) = tokio::sync::oneshot::channel();
        let requested = Arc::new(AtomicBool::new(false));
        let state = SetupState {
            config_path: Arc::new(config_path),
            token: Arc::new("token".into()),
            commit: Arc::new(tokio::sync::Mutex::new(true)),
            start_sender: Arc::new(tokio::sync::Mutex::new(Some(start_sender))),
            start_requested: requested.clone(),
        };

        let response = i18n::scope(Locale::De, "/start".into(), async {
            start_server(State(state), setup_headers()).await
        })
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("VaultLink wird gestartet"));
        assert!(!body.contains("vl-locale-switch"));
        assert!(!body.contains("<vl-i18n"));
        tokio::time::timeout(std::time::Duration::from_secs(1), start_receiver)
            .await
            .unwrap()
            .unwrap();
        assert!(requested.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn setup_writes_letsencrypt_standalone_config() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.toml");
        let mut form = form(root.path(), data.path());
        form.server_mode = "standalone_tls".into();
        form.listen_address = "0.0.0.0:443".into();
        form.public_base_url = "https://files.example.test".into();
        configure_production_mount_policy(&mut form, root.path());
        form.certificate_source = "letsencrypt".into();
        form.letsencrypt_contact_email = "admin@example.test".into();
        let result = build_and_store_with_mount_validator(&config_path, form, |_| {
            Ok(SetupStorageValidation::TestBypass)
        })
        .await
        .unwrap();
        assert!(!result.totp_secret.expose_secret().is_empty());
        let config = Config::load(&config_path).unwrap();
        assert_eq!(
            config.tls.certificate_source,
            CertificateSource::LetsEncrypt
        );
        assert!(config.tls.letsencrypt_staging);
        assert_eq!(config.storage.max_media_preview_size, 1_000_000);
    }

    #[tokio::test]
    async fn setup_server_mode_enables_reverse_proxy_security_without_redundant_toggles() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.toml");
        let mut form = form(root.path(), data.path());
        form.server_mode = "reverse_proxy".into();
        form.public_base_url = "https://files.example.test".into();
        configure_production_mount_policy(&mut form, root.path());
        build_and_store_with_mount_validator(&config_path, form, |_| {
            Ok(SetupStorageValidation::TestBypass)
        })
        .await
        .unwrap();
        let config = Config::load(&config_path).unwrap();
        assert!(config.server.production_mode);
        assert!(config.security.secure_cookie);
        assert!(config.reverse_proxy.enabled);
        assert!(config.reverse_proxy.trust_x_forwarded_headers);
        assert!(!config.tls.enabled);
    }

    #[tokio::test]
    async fn development_setup_rejects_blank_internal_directory_without_inference() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.toml");
        let mut form = form(root.path(), data.path());
        form.internal_directory.clear();

        let error = match build_and_store(&config_path, form).await {
            Ok(_) => panic!("development setup inferred a missing internal storage boundary"),
            Err(error) => error,
        };
        assert!(error.contains("storage.internal_directory must be configured explicitly"));
        assert!(!config_path.exists());
        assert!(!root
            .path()
            .join(crate::config::DEFAULT_INTERNAL_DIRECTORY_NAME)
            .exists());
    }

    #[tokio::test]
    async fn production_setup_rejects_missing_explicit_mount_policy() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let mut form = form(root.path(), data.path());
        form.server_mode = "reverse_proxy".into();
        form.public_base_url = "https://files.example.test".into();

        let error = match build_and_store(&config_dir.path().join("config.toml"), form).await {
            Ok(_) => panic!("production setup without mount policy unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(error.contains("internal_directory"));
    }

    #[tokio::test]
    async fn production_setup_rejects_data_symlinked_into_the_visible_tree_before_writing_secrets()
    {
        use std::os::unix::fs::symlink;

        let mount = tempfile::tempdir().unwrap();
        let shared = mount.path().join("shared");
        let internal = mount.path().join(".vaultlink-internal");
        let real_data = shared.join("state");
        let data_alias = mount.path().join("data-alias");
        std::fs::create_dir(&shared).unwrap();
        std::fs::create_dir(&internal).unwrap();
        std::fs::create_dir(&real_data).unwrap();
        symlink(&real_data, &data_alias).unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.toml");
        let mut form = form(&shared, &data_alias);
        form.server_mode = "reverse_proxy".into();
        form.public_base_url = "https://files.example.test".into();
        form.internal_directory = internal.display().to_string();
        form.require_mount = Some("on".into());
        form.expected_filesystem_type = "ext4".into();
        form.expected_mount_source = "/dev/mapper/vaultlink-test".into();

        let error = match build_and_store(&config_path, form).await {
            Ok(_) => panic!("setup accepted SQLite state inside the visible tree"),
            Err(error) => error,
        };
        assert!(error.contains("user-visible root_mount_path"));
        assert!(!config_path.exists());
        assert!(!real_data.join("data.sqlite").exists());
    }

    #[tokio::test]
    async fn setup_never_overwrites_an_existing_different_config() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.toml");
        build_and_store(&config_path, form(root.path(), data.path()))
            .await
            .unwrap();
        let original = std::fs::read(&config_path).unwrap();

        let mut changed = form(root.path(), data.path());
        changed.public_base_url = "http://localhost:9999".into();
        assert!(build_and_store(&config_path, changed).await.is_err());
        assert_eq!(std::fs::read(&config_path).unwrap(), original);
    }

    #[tokio::test]
    async fn setup_recovers_matching_config_when_admin_commit_was_missing() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.toml");
        build_and_store(&config_path, form(root.path(), data.path()))
            .await
            .unwrap();
        std::fs::remove_file(data.path().join("data.sqlite")).unwrap();

        build_and_store(&config_path, form(root.path(), data.path()))
            .await
            .unwrap();
        let database = Database::open(data.path().join("data.sqlite")).unwrap();
        assert_eq!(database.admin_count().unwrap(), 1);
    }

    #[tokio::test]
    async fn setup_recovers_committed_totp_until_the_operator_confirms_it() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.toml");

        let first = build_and_store(&config_path, form(root.path(), data.path()))
            .await
            .unwrap();
        assert!(initial_setup_pending_path(data.path()).is_file());
        let recovered = build_and_store(&config_path, form(root.path(), data.path()))
            .await
            .unwrap();
        assert_eq!(
            recovered.totp_secret.expose_secret(),
            first.totp_secret.expose_secret()
        );

        clear_initial_setup_pending(data.path()).unwrap();
        assert!(!initial_setup_pending_path(data.path()).exists());
        assert!(
            build_and_store(&config_path, form(root.path(), data.path()))
                .await
                .is_err()
        );
    }
}
