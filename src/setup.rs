use std::{
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use axum::{
    extract::{Form, Query, Request, State},
    http::{header, HeaderValue, StatusCode, Uri},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Json, Router,
};
use qrcode::{render::svg, QrCode};
use serde::{Deserialize, Serialize};

use crate::{
    auth,
    config::{
        CertificateSource, Config, Logging, ReverseProxy, Security, Server, ServerMode, Storage,
        Tls,
    },
    db::{Database, InitialAdminOutcome},
    i18n::{self, Locale},
    runtime, storage_mount, ui,
};

#[derive(Clone)]
struct SetupState {
    config_path: Arc<PathBuf>,
    token: Arc<String>,
    commit: Arc<tokio::sync::Mutex<bool>>,
    start_sender: Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    start_requested: Arc<AtomicBool>,
}

const INITIAL_SETUP_PENDING_FILE: &str = ".vaultlink-initial-setup.pending";

#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

#[derive(Deserialize)]
struct CompleteSetupForm {
    token: String,
}

#[derive(Deserialize)]
struct SetupLocaleForm {
    locale: String,
    return_to: String,
}

#[derive(Deserialize)]
struct SetupForm {
    token: String,
    server_mode: String,
    listen_address: String,
    public_base_url: String,
    production_mode: Option<String>,
    root_mount_path: String,
    data_directory: String,
    internal_directory: String,
    require_mount: Option<String>,
    external_writers: Option<String>,
    expected_filesystem_type: String,
    expected_mount_source: String,
    max_upload_size_mb: String,
    max_zip_size_gb: String,
    max_zip_files: String,
    max_search_entries: String,
    max_search_results: String,
    max_preview_size_mb: String,
    preview_extensions: String,
    image_preview_extensions: String,
    pdf_preview_enabled: Option<String>,
    max_media_preview_size_mb: String,
    blocked_extensions: String,
    secure_cookie: Option<String>,
    audit_client_ip_enabled: Option<String>,
    trusted_proxies: String,
    certificate_source: String,
    tls_cert_file: String,
    tls_key_file: String,
    letsencrypt_contact_email: String,
    letsencrypt_cache_dir: String,
    letsencrypt_staging: Option<String>,
    hsts_enabled: Option<String>,
    log_level: String,
    admin_username: String,
    admin_password: String,
    admin_password_confirm: String,
}

pub async fn run(
    config_path: PathBuf,
    listen: SocketAddr,
) -> Result<bool, Box<dyn std::error::Error>> {
    validate_setup_listen(listen)?;
    let token = auth::random_token(32);
    println!("{}", setup_access_instructions(listen, &token));
    let (start_sender, start_receiver) = tokio::sync::oneshot::channel();
    let start_requested = Arc::new(AtomicBool::new(false));
    let state = SetupState {
        config_path: Arc::new(config_path),
        token: Arc::new(token),
        commit: Arc::new(tokio::sync::Mutex::new(false)),
        start_sender: Arc::new(tokio::sync::Mutex::new(Some(start_sender))),
        start_requested: start_requested.clone(),
    };
    let app = setup_router(state);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = start_receiver => {},
                _ = tokio::signal::ctrl_c() => {},
            }
        })
        .await?;
    Ok(start_requested.load(Ordering::Acquire))
}

fn setup_router(state: SetupState) -> Router {
    Router::new()
        .route("/", get(setup_page).post(submit_setup))
        .route("/locale", axum::routing::post(set_setup_locale))
        .route("/complete", axum::routing::post(complete_setup))
        .route("/start", axum::routing::post(start_server))
        .route("/browse", get(setup_browse))
        .route("/assets/vaultlink.css", get(stylesheet_asset))
        .route("/assets/setup.js", get(setup_javascript_asset))
        .layer(middleware::from_fn(setup_security_headers))
        .layer(middleware::from_fn(setup_locale_context))
        .with_state(state)
}

async fn stylesheet_asset() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        format!(
            "@layer vl-legacy, vl-reset, vl-tokens, vl-base, vl-components, vl-layouts, vl-utilities;\n@layer vl-legacy {{{}}}\n{}",
            setup_css(),
            ui::STYLESHEET
        ),
    )
}

async fn setup_javascript_asset() -> impl IntoResponse {
    let script = i18n::render_markers(i18n::current_locale(), SETUP_JAVASCRIPT);
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        script,
    )
}

async fn setup_locale_context(request: Request, next: Next) -> Response {
    let locale = Locale::resolve(request.headers());
    let return_to = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    i18n::scope(locale, return_to, async move {
        let mut response = next.run(request).await;
        let is_localized_content = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.starts_with("text/html") || value.starts_with("application/javascript")
            });
        if is_localized_content {
            response.headers_mut().insert(
                header::CONTENT_LANGUAGE,
                HeaderValue::from_static(locale.code()),
            );
        }
        response
    })
    .await
}

async fn setup_security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; connect-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    response
}

fn safe_setup_return_to(value: &str) -> String {
    if !value.starts_with('/') || value.starts_with("//") || value.contains('\\') {
        return "/".to_string();
    }
    let Ok(uri) = value.parse::<Uri>() else {
        return "/".to_string();
    };
    if uri.scheme().is_some() || uri.authority().is_some() || uri.path() != "/" {
        return "/".to_string();
    }
    uri.path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string())
}

async fn set_setup_locale(Form(form): Form<SetupLocaleForm>) -> Response {
    let Some(locale) = Locale::parse(&form.locale) else {
        return (
            StatusCode::BAD_REQUEST,
            Html(page(
                r#"<section><h1><vl-i18n key="common.error"/></h1><p><vl-i18n key="error.invalid_language"/></p></section>"#,
                None,
            )),
        )
            .into_response();
    };
    let return_to = safe_setup_return_to(&form.return_to);
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000",
        i18n::LOCALE_COOKIE,
        locale.code()
    );
    let mut response = Redirect::to(&return_to).into_response();
    match HeaderValue::from_str(&cookie) {
        Ok(cookie) => {
            response.headers_mut().insert(header::SET_COOKIE, cookie);
            response
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn setup_return_to(token: Option<&str>) -> String {
    if let Some(token) = token {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("token", token)
            .finish();
        return format!("/?{query}");
    }
    safe_setup_return_to(&i18n::current_return_to())
}

fn setup_locale_switcher(token: Option<&str>) -> String {
    let locale = i18n::current_locale();
    let return_to = setup_return_to(token);
    format!(
        r#"<form class="vl-locale-switch" method="post" action="/locale" aria-label="{}"><input type="hidden" name="return_to" value="{}"><button class="vl-locale-switch__option" name="locale" value="de" type="submit"{}>DE</button><span aria-hidden="true">/</span><button class="vl-locale-switch__option" name="locale" value="en" type="submit"{}>EN</button></form>"#,
        esc(i18n::text(locale, i18n::LANGUAGE)),
        esc(&return_to),
        if locale == Locale::De {
            r#" aria-current="true""#
        } else {
            ""
        },
        if locale == Locale::En {
            r#" aria-current="true""#
        } else {
            ""
        },
    )
}

fn validate_setup_listen(listen: SocketAddr) -> Result<(), &'static str> {
    if listen.port() == 0 {
        Err("setup port must not be 0")
    } else if listen.ip().is_loopback() {
        Ok(())
    } else {
        Err("setup bind address must be loopback-only")
    }
}

fn setup_access_instructions(listen: SocketAddr, token: &str) -> String {
    let port = listen.port();
    let tunnel_target = match listen.ip() {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    };
    format!(
        "VaultLink-Setup lauscht ausschlie\u{00df}lich auf Loopback ({listen}). / VaultLink setup listens only on loopback.\n\
         Headless-Server / headless server: Auf dem eigenen Rechner in einem zweiten Terminal ausf\u{00fc}hren; replace BENUTZER and SERVER:\n\
         ssh -4 -N -L 127.0.0.1:{port}:{tunnel_target}:{port} BENUTZER@SERVER\n\
         Danach diese lokale URL im Browser \u{00f6}ffnen / then open this local browser URL:\n\
         http://127.0.0.1:{port}/?token={token}\n\
         Das Setup-Token wird nur einmal ausgegeben und ist f\u{00fc}r das Browserformular erforderlich. / The setup token is printed once and is required by the browser form."
    )
}

async fn setup_page(State(state): State<SetupState>, Query(query): Query<TokenQuery>) -> Response {
    if query.token.as_deref() != Some(state.token.as_str()) {
        return (
            StatusCode::UNAUTHORIZED,
            Html(page(
                r#"<section><h1><vl-i18n key="common.error"/></h1><p><vl-i18n key="setup.token_invalid"/></p></section>"#,
                query.token.as_deref(),
            )),
        )
            .into_response();
    }
    Html(page(
        &setup_form(&state.token, None),
        Some(state.token.as_str()),
    ))
    .into_response()
}

async fn submit_setup(State(state): State<SetupState>, Form(form): Form<SetupForm>) -> Response {
    if form.token != *state.token {
        return (
            StatusCode::UNAUTHORIZED,
            Html(page(
                r#"<section><h1><vl-i18n key="common.error"/></h1><p><vl-i18n key="setup.token_invalid"/></p></section>"#,
                Some(&form.token),
            )),
        )
            .into_response();
    }
    let completed = state.commit.lock().await;
    if *completed {
        return (
            StatusCode::CONFLICT,
            Html(page(
                r#"<section><h1><vl-i18n key="common.error"/></h1><p><vl-i18n key="setup.already_completed"/></p></section>"#,
                Some(state.token.as_str()),
            )),
        )
            .into_response();
    }
    match build_and_store(&state.config_path, form).await {
        Ok(result) => match qr_svg(&result.otpauth) {
            Ok(qr) => {
                Html(page_without_locale_switcher(
                    &format!(
                    r#"<section><h1><vl-i18n key="setup.completed"/></h1><p><vl-i18n key="setup.config_admin_created"/></p><p><vl-i18n key="setup.totp_recovery_help"/></p><div class="qr-card" aria-label="<vl-i18n key="setup.totp_qr_code"/>">{}</div><div class="secret-block"><code>{}</code><code>{}</code></div><form method="post" action="/complete"><input type="hidden" name="token" value="{}"><button><vl-i18n key="setup.secret_saved"/></button></form></section>"#,
                    qr,
                    esc(&result.totp_secret),
                    esc(&result.otpauth),
                    esc(&state.token)
                ),
                ))
                .into_response()
            }
            Err(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(page(
                    &format!(
                        r#"<section><h1><vl-i18n key="common.error"/></h1><p>{}</p></section>"#,
                        esc(&error)
                    ),
                    Some(state.token.as_str()),
                )),
            )
                .into_response(),
        },
        Err(error) => {
            let body = setup_form(&state.token, Some(&error));
            (
                StatusCode::BAD_REQUEST,
                Html(page(&body, Some(state.token.as_str()))),
            )
                .into_response()
        }
    }
}

async fn complete_setup(
    State(state): State<SetupState>,
    Form(form): Form<CompleteSetupForm>,
) -> Response {
    if form.token != *state.token {
        return (
            StatusCode::UNAUTHORIZED,
            Html(page(
                r#"<section><h1><vl-i18n key="common.error"/></h1><p><vl-i18n key="setup.token_invalid"/></p></section>"#,
                Some(&form.token),
            )),
        )
            .into_response();
    }
    let mut completed = state.commit.lock().await;
    if *completed {
        return match Config::load(state.config_path.as_ref()) {
            Ok(config) => Html(page_without_locale_switcher(&setup_confirmed_body(
                &config,
                state.token.as_ref(),
                i18n::text(i18n::current_locale(), i18n::SETUP_TOTP_ALREADY_CLOSED),
            )))
            .into_response(),
            Err(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(page(
                    &format!(
                        r#"<section><h1><vl-i18n key="common.error"/></h1><p><vl-i18n key="setup.config_load_failed"/> {}</p></section>"#,
                        esc(&error.to_string())
                    ),
                    Some(state.token.as_str()),
                )),
            )
                .into_response(),
        };
    }
    let config = match Config::load(state.config_path.as_ref()) {
        Ok(config) => config,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(page(
                    &format!(
                        r#"<section><h1><vl-i18n key="common.error"/></h1><p><vl-i18n key="setup.config_load_failed"/> {}</p></section>"#,
                        esc(&error.to_string())
                    ),
                    Some(state.token.as_str()),
                )),
            )
                .into_response()
        }
    };
    match clear_initial_setup_pending(&config.storage.data_directory) {
        Ok(()) => {
            *completed = true;
            Html(page_without_locale_switcher(&setup_confirmed_body(
                &config,
                state.token.as_ref(),
                i18n::text(i18n::current_locale(), i18n::SETUP_TOTP_CLOSED),
            )))
            .into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(page(
                &format!(
                    r#"<section><h1><vl-i18n key="common.error"/></h1><p><vl-i18n key="setup.confirmation_failed"/> {}</p></section>"#,
                    esc(&error)
                ),
                Some(state.token.as_str()),
            )),
        )
            .into_response(),
    }
}

fn setup_confirmed_body(config: &Config, token: &str, message: &str) -> String {
    let mode = match &config.server.mode {
        ServerMode::Development => "Development",
        ServerMode::ReverseProxy => "Reverse Proxy",
        ServerMode::StandaloneTls => "Standalone TLS",
    };
    format!(
        r#"<section><h1><vl-i18n key="setup.confirmed"/></h1><p>{}</p><p><vl-i18n key="setup.configured_for_mode"/> <strong>{mode}</strong>.</p><form method="post" action="/start"><input type="hidden" name="token" value="{}"><button><vl-i18n key="setup.start_now"/></button></form><p class="muted"><vl-i18n key="setup.service_start_help"/></p></section>"#,
        esc(message),
        esc(token),
    )
}

async fn start_server(
    State(state): State<SetupState>,
    Form(form): Form<CompleteSetupForm>,
) -> Response {
    if form.token != *state.token {
        return (
            StatusCode::UNAUTHORIZED,
            Html(page(
                r#"<section><h1><vl-i18n key="common.error"/></h1><p><vl-i18n key="setup.token_invalid"/></p></section>"#,
                Some(&form.token),
            )),
        )
            .into_response();
    }
    if !*state.commit.lock().await {
        return (
            StatusCode::CONFLICT,
            Html(page(
                r#"<section><h1><vl-i18n key="common.error"/></h1><p><vl-i18n key="setup.totp_confirm_first"/></p></section>"#,
                Some(state.token.as_str()),
            )),
        )
            .into_response();
    }
    let config = match Config::load(state.config_path.as_ref()) {
        Ok(config) => config,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(page(
                    &format!(
                        r#"<section><h1><vl-i18n key="common.error"/></h1><p><vl-i18n key="setup.config_load_failed"/> {}</p></section>"#,
                        esc(&error.to_string())
                    ),
                    Some(state.token.as_str()),
                )),
            )
                .into_response()
        }
    };
    let Some(sender) = state.start_sender.lock().await.take() else {
        return (
            StatusCode::CONFLICT,
            Html(page(
                r#"<section><h1><vl-i18n key="common.error"/></h1><p><vl-i18n key="setup.start_already_requested"/></p></section>"#,
                Some(state.token.as_str()),
            )),
        )
            .into_response();
    };
    let start_requested = state.start_requested.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        start_requested.store(true, Ordering::Release);
        if sender.send(()).is_err() {
            start_requested.store(false, Ordering::Release);
        }
    });
    Html(page_without_locale_switcher(
        &format!(
            r#"<section><h1><vl-i18n key="setup.starting"/></h1><p><vl-i18n key="setup.listener_transition"/></p><p><a class="button" href="{}"><vl-i18n key="setup.open_vaultlink"/></a></p><p class="muted"><vl-i18n key="setup.start_delay"/></p></section>"#,
            esc(&config.server.public_base_url),
        ),
    ))
    .into_response()
}

struct SetupResult {
    totp_secret: String,
    otpauth: String,
}

async fn build_and_store(config_path: &Path, form: SetupForm) -> Result<SetupResult, String> {
    build_and_store_with_mount_validator(config_path, form, |storage| {
        storage_mount::validate(storage).map_err(|error| error.to_string())
    })
    .await
}

async fn build_and_store_with_mount_validator<F>(
    config_path: &Path,
    form: SetupForm,
    validate_mount: F,
) -> Result<SetupResult, String>
where
    F: FnOnce(&Storage) -> Result<(), String>,
{
    if form.admin_password != form.admin_password_confirm {
        return Err(i18n::text(i18n::current_locale(), i18n::PASSWORD_MISMATCH).into());
    }
    if form.admin_password.chars().count() < 14 {
        return Err(i18n::text(i18n::current_locale(), i18n::PASSWORD_MIN_14).into());
    }
    if form.admin_username.len() < 3
        || form.admin_username.len() > 64
        || !form
            .admin_username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(i18n::text(i18n::current_locale(), i18n::USERNAME_POLICY).into());
    }
    let mode = match form.server_mode.as_str() {
        "development" => ServerMode::Development,
        "reverse_proxy" => ServerMode::ReverseProxy,
        "standalone_tls" => ServerMode::StandaloneTls,
        _ => {
            return Err(i18n::text(i18n::current_locale(), i18n::SETUP_INVALID_SERVER_MODE).into())
        }
    };
    let standalone_tls = matches!(mode, ServerMode::StandaloneTls);
    let reverse_proxy_mode = matches!(mode, ServerMode::ReverseProxy);
    let production_mode = !matches!(mode, ServerMode::Development);
    let external_writers = form.external_writers.is_some();
    let require_mount = production_mode || form.require_mount.is_some() || external_writers;
    let optional_mount_value = |value: String| {
        let value = value.trim().to_string();
        (!value.is_empty()).then_some(value)
    };
    let internal_directory = optional_mount_value(form.internal_directory).map(PathBuf::from);
    let expected_filesystem_type = optional_mount_value(form.expected_filesystem_type);
    let expected_mount_source = optional_mount_value(form.expected_mount_source);
    let certificate_source = match form.certificate_source.as_str() {
        "files" => CertificateSource::Files,
        "letsencrypt" => CertificateSource::LetsEncrypt,
        _ => {
            return Err(i18n::text(
                i18n::current_locale(),
                i18n::SETUP_INVALID_CERTIFICATE_SOURCE,
            )
            .into())
        }
    };
    let invalid_extensions =
        || i18n::text(i18n::current_locale(), i18n::SETUP_INVALID_EXTENSIONS).to_string();
    let preview_extensions = runtime::parse_extension_list(&form.preview_extensions)
        .map_err(|_| invalid_extensions())?;
    let image_preview_extensions = runtime::parse_extension_list(&form.image_preview_extensions)
        .map_err(|_| invalid_extensions())?;
    let blocked_extensions = runtime::parse_extension_list(&form.blocked_extensions)
        .map_err(|_| invalid_extensions())?;
    let trusted_proxies = form
        .trusted_proxies
        .split([',', '\n', '\r', ' ', '\t'])
        .filter_map(|value| {
            let value = value.trim();
            (!value.is_empty()).then_some(value.parse())
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            i18n::text(i18n::current_locale(), i18n::SETUP_INVALID_TRUSTED_PROXIES).to_string()
        })?;
    let config = Config {
        server: Server {
            mode,
            listen_address: form.listen_address,
            public_base_url: form.public_base_url,
            production_mode: production_mode || form.production_mode.is_some(),
        },
        storage: Storage {
            root_mount_path: form.root_mount_path.into(),
            data_directory: form.data_directory.into(),
            internal_directory,
            require_mount,
            external_writers,
            expected_filesystem_type,
            expected_mount_source,
            max_upload_size: parse_unit_to_bytes(
                "max_upload_size_mb",
                &form.max_upload_size_mb,
                MB,
            )?,
            max_zip_size: parse_unit_to_bytes("max_zip_size_gb", &form.max_zip_size_gb, GB)?,
            max_zip_files: parse_usize("max_zip_files", &form.max_zip_files)?,
            max_search_entries: parse_usize("max_search_entries", &form.max_search_entries)?,
            max_search_results: parse_usize("max_search_results", &form.max_search_results)?,
            max_preview_size: parse_unit_to_bytes(
                "max_preview_size_mb",
                &form.max_preview_size_mb,
                MB,
            )?,
            preview_extensions,
            image_preview_extensions,
            pdf_preview_enabled: form.pdf_preview_enabled.is_some(),
            max_media_preview_size: parse_unit_to_bytes(
                "max_media_preview_size_mb",
                &form.max_media_preview_size_mb,
                MB,
            )?,
            blocked_extensions,
        },
        reverse_proxy: ReverseProxy {
            enabled: reverse_proxy_mode,
            allow_non_loopback: false,
            trusted_proxies,
            trust_x_forwarded_headers: reverse_proxy_mode,
        },
        tls: Tls {
            enabled: standalone_tls,
            certificate_source,
            cert_file: form.tls_cert_file.into(),
            key_file: form.tls_key_file.into(),
            hsts_enabled: form.hsts_enabled.is_some(),
            reload_on_cert_change: standalone_tls && form.certificate_source == "files",
            letsencrypt_contact_email: form.letsencrypt_contact_email,
            letsencrypt_cache_dir: form.letsencrypt_cache_dir.into(),
            letsencrypt_staging: form.letsencrypt_staging.is_some(),
        },
        security: Security {
            secure_cookie: production_mode || form.secure_cookie.is_some(),
            audit_client_ip_enabled: form.audit_client_ip_enabled.is_some(),
            ..Default::default()
        },
        logging: Logging {
            level: if form.log_level.trim().is_empty() {
                "info".into()
            } else {
                form.log_level
            },
        },
    };
    config.validate().map_err(|error| {
        format!(
            "{}: {error}",
            i18n::text(i18n::current_locale(), i18n::SETUP_INVALID_CONFIGURATION)
        )
    })?;
    if config.storage.require_mount {
        validate_mount(&config.storage)?;
    }
    let serialized = toml::to_string_pretty(&config).map_err(|error| error.to_string())?;
    let recovering_existing_config = if config_path.exists() {
        let existing = Config::load(config_path).map_err(|error| {
            let prefix = match i18n::current_locale() {
                Locale::De => "Vorhandene Konfiguration kann nicht sicher fortgesetzt werden",
                Locale::En => "Existing configuration cannot be resumed safely",
            };
            format!("{prefix}: {error}")
        })?;
        let existing_serialized =
            toml::to_string_pretty(&existing).map_err(|error| error.to_string())?;
        if existing_serialized != serialized {
            return Err(i18n::text(i18n::current_locale(), i18n::SETUP_CONFIG_EXISTS).into());
        }
        true
    } else {
        false
    };
    let totp_secret = auth::new_totp_secret();
    let submitted_password = form.admin_password.clone();
    let password = form.admin_password;
    let hash = tokio::task::spawn_blocking(move || auth::hash_password(&password))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&config.storage.data_directory).map_err(|error| error.to_string())?;
    let database = Database::open(config.storage.data_directory.join("data.sqlite"))
        .map_err(|error| error.to_string())?;
    if database.admin_count().map_err(|error| error.to_string())? != 0 {
        if recovering_existing_config
            && read_initial_setup_pending(&config.storage.data_directory)?.as_deref()
                == Some(form.admin_username.as_str())
        {
            let admin = database
                .admin(&form.admin_username)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| {
                    i18n::text(i18n::current_locale(), i18n::SETUP_RECOVERY_UNAVAILABLE).to_string()
                })?;
            let password_hash = admin.password_hash.clone();
            let password_valid = tokio::task::spawn_blocking(move || {
                auth::verify_password(&password_hash, &submitted_password)
            })
            .await
            .map_err(|error| error.to_string())?;
            if !password_valid {
                return Err(
                    i18n::text(i18n::current_locale(), i18n::SETUP_RECOVERY_UNAVAILABLE).into(),
                );
            }
            let totp_secret = admin.totp_secret;
            let otpauth = format!(
                "otpauth://totp/VaultLink:{}?secret={}&issuer=VaultLink",
                form.admin_username, totp_secret
            );
            return Ok(SetupResult {
                totp_secret,
                otpauth,
            });
        }
        return Err(i18n::text(i18n::current_locale(), i18n::SETUP_INITIAL_ADMIN_EXISTS).into());
    }
    let wrote_config = if recovering_existing_config {
        false
    } else {
        write_config_atomic_new(config_path, &serialized).map_err(|error| error.to_string())?;
        true
    };
    if let Err(error) =
        ensure_initial_setup_pending(&config.storage.data_directory, &form.admin_username)
    {
        if wrote_config {
            let _ = std::fs::remove_file(config_path);
            let _ = sync_parent(config_path);
        }
        return Err(error);
    }
    match database.create_initial_admin(&form.admin_username, &hash, &totp_secret) {
        Ok(InitialAdminOutcome::Created) => {}
        Ok(InitialAdminOutcome::AlreadyInitialized) => {
            return Err(
                i18n::text(i18n::current_locale(), i18n::SETUP_INITIAL_ADMIN_EXISTS).into(),
            );
        }
        Err(error) => {
            if wrote_config {
                let _ = std::fs::remove_file(config_path);
                let _ = sync_parent(config_path);
            }
            return Err(error.to_string());
        }
    }
    let otpauth = format!(
        "otpauth://totp/VaultLink:{}?secret={}&issuer=VaultLink",
        form.admin_username, totp_secret
    );
    Ok(SetupResult {
        totp_secret,
        otpauth,
    })
}

fn initial_setup_pending_path(data_directory: &Path) -> PathBuf {
    data_directory.join(INITIAL_SETUP_PENDING_FILE)
}

fn read_initial_setup_pending(data_directory: &Path) -> Result<Option<String>, String> {
    let path = initial_setup_pending_path(data_directory);
    match std::fs::read_to_string(path) {
        Ok(username) => Ok(Some(username.trim().to_string())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn ensure_initial_setup_pending(data_directory: &Path, username: &str) -> Result<(), String> {
    if let Some(existing) = read_initial_setup_pending(data_directory)? {
        return if existing == username {
            Ok(())
        } else {
            Err(i18n::text(i18n::current_locale(), i18n::SETUP_PENDING_OTHER_ADMIN).into())
        };
    }
    let path = initial_setup_pending_path(data_directory);
    write_config_atomic_new(&path, &format!("{username}\n")).map_err(|error| error.to_string())
}

fn clear_initial_setup_pending(data_directory: &Path) -> Result<(), String> {
    let path = initial_setup_pending_path(data_directory);
    match std::fs::remove_file(&path) {
        Ok(()) => sync_parent(&path).map_err(|error| error.to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn write_config_atomic_new(path: &Path, content: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(content.as_bytes())?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
    Ok(())
}

fn parse_unit_to_bytes(name: &str, value: &str, unit: u64) -> Result<u64, String> {
    let value = value
        .trim()
        .parse::<u64>()
        .map_err(|_| match i18n::current_locale() {
            Locale::De => format!("{name} muss eine positive ganze Zahl sein."),
            Locale::En => format!("{name} must be a positive integer."),
        })?;
    value
        .checked_mul(unit)
        .ok_or_else(|| match i18n::current_locale() {
            Locale::De => format!("{name} ist zu groß."),
            Locale::En => format!("{name} is too large."),
        })
}

fn parse_usize(name: &str, value: &str) -> Result<usize, String> {
    value
        .trim()
        .parse::<usize>()
        .map_err(|_| match i18n::current_locale() {
            Locale::De => format!("{name} muss eine positive Zahl sein."),
            Locale::En => format!("{name} must be a positive number."),
        })
}

const MB: u64 = 1_000_000;
const GB: u64 = 1_000_000_000;

#[derive(Deserialize)]
struct BrowseQuery {
    token: Option<String>,
    path: Option<String>,
    mode: Option<String>,
    file_kind: Option<String>,
}

#[derive(Serialize)]
struct BrowseEntry {
    name: String,
    path: String,
    is_directory: bool,
}

#[derive(Serialize)]
struct BrowseResponse {
    path: String,
    parent: Option<String>,
    entries: Vec<BrowseEntry>,
}

async fn setup_browse(
    State(state): State<SetupState>,
    Query(query): Query<BrowseQuery>,
) -> Response {
    if query.token.as_deref() != Some(state.token.as_str()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let requested = query.path.unwrap_or_else(|| "/".to_string());
    let include_files = query.mode.as_deref() == Some("file");
    let file_kind = query.file_kind.as_deref();
    let path = PathBuf::from(&requested);
    if !path.is_absolute() {
        return (StatusCode::BAD_REQUEST, "path must be absolute").into_response();
    }
    let read_dir = match std::fs::read_dir(&path) {
        Ok(read_dir) => read_dir,
        Err(_) => return (StatusCode::BAD_REQUEST, "path is not readable").into_response(),
    };
    let mut entries = Vec::new();
    for entry in read_dir.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let is_directory = file_type.is_dir();
        let entry_path = entry.path();
        if !is_directory
            && !(include_files
                && file_type.is_file()
                && setup_picker_file_allowed(&entry_path, file_kind))
        {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry_path.display().to_string();
        entries.push(BrowseEntry {
            name,
            path,
            is_directory,
        });
    }
    entries.sort_by_key(|entry| (!entry.is_directory, entry.name.to_lowercase()));
    let parent = path
        .parent()
        .filter(|parent| *parent != path)
        .map(|parent| parent.display().to_string());
    Json(BrowseResponse {
        path: path.display().to_string(),
        parent,
        entries,
    })
    .into_response()
}

fn setup_picker_file_allowed(path: &Path, file_kind: Option<&str>) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);
    matches!(
        (file_kind, extension.as_deref()),
        (Some("certificate"), Some("pem" | "crt" | "cer"))
            | (Some("private_key"), Some("pem" | "key"))
    )
}

fn setup_form(token: &str, error: Option<&str>) -> String {
    let error = error
        .map(|error| format!(r#"<p class="bad">{}</p>"#, esc(error)))
        .unwrap_or_default();
    let token = esc(token);
    format!(
        r#"
<section class="hero">
  <div><p class="eyebrow"><vl-i18n key="setup.title"/></p><h1><vl-i18n key="setup.initial_setup"/></h1><p class="muted"><vl-i18n key="setup.local_bootstrap"/></p></div>
  <div class="side-panel"><strong><vl-i18n key="setup.security"/></strong><p class="muted"><vl-i18n key="setup.acme_proxy_help"/></p></div>
</section>
{error}
<form method="post" class="setup-form" data-setup-token="{token}">
  <input type="hidden" name="token" value="{token}">
  <section class="form-card"><h2><vl-i18n key="setup.server"/></h2><div class="form-grid">
    <label><vl-i18n key="setup.mode"/><br><select name="server_mode" data-server-mode><option value="development">Development</option><option value="reverse_proxy">Reverse Proxy</option><option value="standalone_tls">Standalone TLS</option></select></label>
    <label><vl-i18n key="setup.service_address"/><br><input name="listen_address" value="127.0.0.1:8080" required><small class="muted"><vl-i18n key="setup.service_address_help"/></small></label>
    <label><vl-i18n key="setup.public_base_url"/><br><input name="public_base_url" value="http://localhost:8080" required></label>
    <label><vl-i18n key="setup.log_level"/><br><select name="log_level"><option value="error">error</option><option value="warn">warn</option><option value="info" selected>info</option><option value="debug">debug</option><option value="trace">trace</option></select></label>
  </div></section>
  <section class="form-card"><h2><vl-i18n key="setup.storage"/></h2><div class="form-grid">
    <label><vl-i18n key="setup.root_mount_path"/><br><div class="input-action"><input name="root_mount_path" value="/tmp/vaultlink-root" required><button class="secondary small" type="button" data-dir-picker="root_mount_path"><vl-i18n key="setup.browse"/></button></div></label>
    <label><vl-i18n key="setup.data_directory"/><br><div class="input-action"><input name="data_directory" value="/tmp/vaultlink-data" required><button class="secondary small" type="button" data-dir-picker="data_directory"><vl-i18n key="setup.browse"/></button></div></label>
    <label><vl-i18n key="setup.internal_directory"/><br><div class="input-action"><input name="internal_directory" data-mount-policy-field><button class="secondary small" type="button" data-dir-picker="internal_directory"><vl-i18n key="setup.browse"/></button></div></label>
    <label><vl-i18n key="setup.expected_filesystem_type"/><br><input name="expected_filesystem_type" placeholder="ext4 oder cifs" data-mount-policy-field></label>
    <label><vl-i18n key="setup.expected_mount_source"/><br><input name="expected_mount_source" placeholder="/dev/mapper/storage oder //server/share" data-mount-policy-field></label>
    <label class="toggle-card"><input type="checkbox" name="require_mount" data-require-mount><span><vl-i18n key="setup.require_mount"/><small><vl-i18n key="setup.require_mount_help"/></small></span></label>
    <label class="toggle-card"><input type="checkbox" name="external_writers" data-external-writers><span><vl-i18n key="setup.external_writers"/><small><vl-i18n key="setup.external_writers_help"/></small></span></label>
    <label><vl-i18n key="setup.max_upload_mb"/><br><input name="max_upload_size_mb" type="number" min="1" step="1" value="100" required></label>
    <label><vl-i18n key="setup.blocked_extensions"/><br><input name="blocked_extensions" value="exe,sh,php"></label>
  </div></section>
  <section class="form-card"><h2><vl-i18n key="setup.zip_search_preview"/></h2><div class="form-grid">
    <label><vl-i18n key="setup.zip_max_gb"/><br><input name="max_zip_size_gb" type="number" min="0" step="1" value="1" required></label>
    <label><vl-i18n key="setup.zip_max_files"/><br><input name="max_zip_files" type="number" min="0" value="10000" required></label>
    <label><vl-i18n key="setup.search_max_entries"/><br><input name="max_search_entries" type="number" min="1" value="50000" required></label>
    <label><vl-i18n key="setup.search_max_results"/><br><input name="max_search_results" type="number" min="1" value="500" required></label>
    <label><vl-i18n key="setup.text_preview_max_mb"/><br><input name="max_preview_size_mb" type="number" min="1" step="1" value="1" required></label>
    <label><vl-i18n key="setup.text_preview_extensions"/><br><input name="preview_extensions" value="txt,log,md,csv,json,toml,yaml,yml,ini,conf" required></label>
    <label><vl-i18n key="setup.media_preview_max_mb"/><br><input name="max_media_preview_size_mb" type="number" min="1" step="1" value="100" required></label>
    <label><vl-i18n key="setup.image_preview_extensions"/><br><input name="image_preview_extensions" value="jpg,jpeg,png,gif,webp,bmp,avif"></label>
    <label class="toggle-card"><input type="checkbox" name="pdf_preview_enabled" checked><span><vl-i18n key="setup.pdf_preview_enabled"/><small><vl-i18n key="setup.pdf_preview_help"/></small></span></label>
  </div></section>
  <section class="form-card" data-production-section><h2><vl-i18n key="setup.proxy_tls"/></h2><div class="form-grid">
    <label data-mode-only="reverse_proxy"><vl-i18n key="setup.trusted_proxies"/><br><input name="trusted_proxies" value="127.0.0.1,::1"></label>
    <label data-mode-only="standalone_tls"><vl-i18n key="setup.certificate_source"/><br><select name="certificate_source" data-certificate-source><option value="files"><vl-i18n key="setup.pem_files"/></option><option value="letsencrypt"><vl-i18n key="setup.letsencrypt_auto"/></option></select></label>
    <label data-certificate-only="files"><vl-i18n key="setup.tls_cert_file"/><br><div class="input-action"><input name="tls_cert_file"><button class="secondary small" type="button" data-file-picker="tls_cert_file"><vl-i18n key="setup.browse"/></button></div></label>
    <label data-certificate-only="files"><vl-i18n key="setup.tls_key_file"/><br><div class="input-action"><input name="tls_key_file"><button class="secondary small" type="button" data-file-picker="tls_key_file"><vl-i18n key="setup.browse"/></button></div></label>
    <label data-certificate-only="letsencrypt"><vl-i18n key="setup.letsencrypt_email"/><br><input name="letsencrypt_contact_email" placeholder="admin@example.com"></label>
    <label data-certificate-only="letsencrypt"><vl-i18n key="setup.acme_cache_directory"/><br><div class="input-action"><input name="letsencrypt_cache_dir" value="acme" required><button class="secondary small" type="button" data-dir-picker="letsencrypt_cache_dir"><vl-i18n key="setup.browse"/></button></div></label>
    <label class="toggle-card" data-certificate-only="letsencrypt"><input type="checkbox" name="letsencrypt_staging" checked><span><vl-i18n key="setup.letsencrypt_staging"/><small><vl-i18n key="setup.letsencrypt_staging_help"/></small></span></label>
    <label class="toggle-card"><input type="checkbox" name="hsts_enabled"><span><vl-i18n key="setup.hsts_enabled"/><small><vl-i18n key="setup.hsts_help"/></small></span></label>
  </div></section>
  <section class="form-card"><h2><vl-i18n key="setup.audit_privacy"/></h2><div class="form-grid"><label class="toggle-card"><input type="checkbox" name="audit_client_ip_enabled"><span><vl-i18n key="setup.audit_ip"/><small><vl-i18n key="setup.audit_ip_help"/></small></span></label></div></section>
  <section class="form-card"><h2><vl-i18n key="setup.first_admin"/></h2><div class="form-grid">
    <label><vl-i18n key="auth.username"/><br><input name="admin_username" value="admin" minlength="3" maxlength="64" required></label>
    <label><vl-i18n key="auth.password"/><br><input name="admin_password" type="password" minlength="14" required></label>
    <label><vl-i18n key="account.confirm_password"/><br><input name="admin_password_confirm" type="password" minlength="14" required></label>
  </div></section>
  <p class="form-actions"><button><vl-i18n key="setup.write"/></button></p>
</form>
<dialog data-dir-dialog class="dir-dialog"><div class="dir-dialog-head"><strong data-picker-title><vl-i18n key="setup.choose_directory"/></strong><button class="secondary small" type="button" data-dir-close><vl-i18n key="common.close"/></button></div><p class="muted" data-dir-current>/</p><div class="button-group"><button class="secondary small" type="button" data-dir-up><vl-i18n key="files.up"/></button><button class="small" type="button" data-dir-use><vl-i18n key="setup.use_directory"/></button></div><p class="muted" data-picker-help><vl-i18n key="setup.server_directories_help"/></p><div class="dir-list" data-dir-list></div></dialog>
"#
    )
}

fn page(body: &str, token: Option<&str>) -> String {
    render_page(body, &setup_locale_switcher(token))
}

// Transitional setup responses may contain a one-time TOTP secret or the only
// button that moves the listener into server mode. They deliberately omit the
// locale form because those responses are produced by POST and cannot be
// replayed safely after a locale redirect.
fn page_without_locale_switcher(body: &str) -> String {
    render_page(body, "")
}

fn render_page(body: &str, locale_switcher: &str) -> String {
    let _legacy_logo_kept_for_migration_tests = SETUP_LOGO_SVG;
    let locale = i18n::current_locale();
    let body = i18n::render_markers(locale, body);
    format!(
        r##"<!doctype html><html lang="{}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{}</title><link rel="stylesheet" href="/assets/vaultlink.css"><script src="/assets/setup.js" defer></script></head><body class="vl-ui"><a class="vl-skip-link" href="#main-content">{}</a><div class="vl-setup-shell"><main id="main-content" class="vl-setup-main"><header class="vl-setup-header">{}{}</header>{}</main></div></body></html>"##,
        locale.code(),
        esc(i18n::text(locale, i18n::SETUP_TITLE)),
        i18n::text(locale, i18n::SKIP_TO_CONTENT),
        ui::brand_lockup(i18n::text(locale, i18n::BRAND_TAGLINE)),
        locale_switcher,
        body
    )
}
fn setup_css() -> &'static str {
    r#":root{--bg:#070d1b;--card:#121b31;--card2:#172542;--text:#f4f7ff;--soft:#d7e3fb;--muted:#9fb0d0;--accent:#5aa7ff;--line:#263653;--line2:#3b5076;--bad:#ff7b86;--good:#55d69a}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top right,#221b57 0,#081020 34%,#050914 100%);color:var(--text);font:16px system-ui,-apple-system,Segoe UI,sans-serif}main{max-width:1220px;margin:auto;padding:2rem}.setup-shell{min-height:100vh}.public-brand{display:flex;align-items:center;gap:.8rem;margin:0 0 1.5rem;font-weight:900}.public-brand svg{width:48px;height:48px;border-radius:14px;box-shadow:0 12px 28px rgba(47,103,189,.25)}.public-brand small{display:block;color:var(--muted);font-weight:700}.hero,section{background:linear-gradient(180deg,rgba(23,37,66,.92),rgba(18,27,49,.92));border:1px solid rgba(90,167,255,.16);border-radius:22px;padding:1.35rem;margin:1rem 0;box-shadow:0 18px 60px rgba(0,0,0,.22)}.hero{display:grid;grid-template-columns:minmax(0,1fr) 360px;gap:1rem;align-items:center}.eyebrow{color:#9ed0ff;text-transform:uppercase;letter-spacing:.16em;font-weight:900;font-size:.78rem}.side-panel{padding:1rem;border-radius:18px;border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.045)}h1{font-size:clamp(2rem,4vw,3.4rem);line-height:1;margin:.2rem 0 .7rem}h2{margin:0 0 .9rem;font-size:1.12rem;color:#dbeafe}.muted{color:var(--muted)}.bad{color:var(--bad);font-weight:800}.qr-card{display:inline-flex;margin:1rem 0;padding:1rem;border-radius:18px;background:#f8fbff;box-shadow:0 18px 42px rgba(0,0,0,.28)}.qr-card svg{display:block;width:220px;height:220px}.secret-block{display:grid;gap:.6rem;margin:1rem 0}.secret-block code{display:block;max-width:100%;overflow:auto;padding:.85rem;border-radius:12px;background:#081226;border:1px solid var(--line2);color:#dbeafe}.form-card{padding:1rem;border:1px solid rgba(90,167,255,.16);border-radius:18px;background:rgba(90,167,255,.045);margin:1rem 0}.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:.9rem;align-items:end}label{display:block;color:var(--soft);font-weight:700}input,select,button{font:inherit;padding:.72rem .8rem;border-radius:12px;border:1px solid var(--line2);background:#0b1326;color:var(--text);max-width:100%}label input,label select{margin-top:.25rem;width:100%}input:focus,select:focus{outline:2px solid rgba(90,167,255,.35);border-color:var(--accent)}button,.button{display:inline-flex;align-items:center;justify-content:center;gap:.4rem;cursor:pointer;padding:.78rem 1rem;border-radius:12px;background:linear-gradient(135deg,#2f67bd,#4e7de2);border:1px solid rgba(255,255,255,.1);color:white;box-shadow:0 10px 24px rgba(47,103,189,.22);font-weight:800;line-height:1.1;text-decoration:none;white-space:nowrap}.secondary{background:rgba(90,167,255,.12);border-color:rgba(90,167,255,.35);box-shadow:none;color:#dbeafe}.small{padding:.55rem .75rem;border-radius:10px;font-size:.92rem}.form-actions,.button-group{display:flex;gap:.55rem;flex-wrap:wrap;align-items:center}.input-action{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.45rem;align-items:end}.toggle-card{display:flex;align-items:center;gap:.85rem;width:100%;min-width:260px;padding:.9rem 1rem;border:1px solid rgba(90,167,255,.22);border-radius:16px;background:rgba(90,167,255,.07);cursor:pointer}.toggle-card input{position:absolute;opacity:0;width:1px;height:1px}.toggle-card>input+span{position:relative;display:grid;gap:.15rem;padding-left:68px;color:var(--text)}.toggle-card>input+span::before{content:"";position:absolute;left:0;top:50%;transform:translateY(-50%);width:54px;height:30px;border-radius:999px;background:#1f2b45;border:1px solid var(--line2);box-shadow:inset 0 1px 4px rgba(0,0,0,.28)}.toggle-card>input+span::after{content:"";position:absolute;left:4px;top:50%;transform:translateY(-50%);width:22px;height:22px;border-radius:999px;background:#dbeafe;transition:transform .18s ease,background .18s ease}.toggle-card>input:checked+span::before{background:linear-gradient(135deg,#2f67bd,#4e7de2);border-color:rgba(255,255,255,.18)}.toggle-card>input:checked+span::after{transform:translate(24px,-50%);background:#fff}.toggle-card small{display:block;color:var(--muted);font-weight:600;line-height:1.35}.dir-dialog{width:min(720px,92vw);border:1px solid rgba(90,167,255,.22);border-radius:20px;background:#101a30;color:var(--text);box-shadow:0 30px 90px rgba(0,0,0,.55);padding:1rem}.dir-dialog::backdrop{background:rgba(0,0,0,.55)}.dir-dialog-head{display:flex;justify-content:space-between;gap:1rem;align-items:center}.dir-list{display:grid;gap:.45rem;max-height:420px;overflow:auto;margin-top:.9rem}.dir-entry{display:flex;justify-content:space-between;gap:.8rem;align-items:center;padding:.75rem .85rem;border:1px solid rgba(255,255,255,.08);border-radius:14px;background:rgba(255,255,255,.035);color:var(--text);text-align:left}.dir-entry:hover{filter:brightness(1.08)}@media(max-width:850px){main{padding:1rem}.hero{grid-template-columns:1fr}.input-action{grid-template-columns:1fr}.form-actions{display:block}}"#
}

const SETUP_JAVASCRIPT: &str = r#"
document.addEventListener('DOMContentLoaded', () => {
  const form = document.querySelector('[data-setup-token]');
  if (!form) return;

  const mode = form.querySelector('[data-server-mode]');
  const certificateSource = form.querySelector('[data-certificate-source]');
  const requireMount = form.querySelector('[data-require-mount]');
  const externalWriters = form.querySelector('[data-external-writers]');
  const syncConditionalFields = () => {
    const selectedMode = mode?.value || 'development';
    const selectedCertificate = certificateSource?.value || 'files';
    const standalone = selectedMode === 'standalone_tls';
    const production = selectedMode !== 'development';
    if (production || externalWriters?.checked) requireMount.checked = true;
    const mountPolicyRequired = production || requireMount?.checked || externalWriters?.checked;
    form.querySelectorAll('[data-mount-policy-field]').forEach(element => {
      element.required = mountPolicyRequired;
    });
    form.querySelectorAll('[data-production-section]').forEach(element => {
      element.hidden = selectedMode === 'development';
    });
    form.querySelectorAll('[data-mode-only]').forEach(element => {
      element.hidden = element.dataset.modeOnly !== selectedMode;
    });
    form.querySelectorAll('[data-certificate-only]').forEach(element => {
      element.hidden = !standalone || element.dataset.certificateOnly !== selectedCertificate;
    });
    for (const name of ['tls_cert_file', 'tls_key_file']) {
      const input = form.elements[name];
      if (input) input.required = standalone && selectedCertificate === 'files';
    }
    for (const name of ['letsencrypt_contact_email', 'letsencrypt_cache_dir']) {
      const input = form.elements[name];
      if (input) input.required = standalone && selectedCertificate === 'letsencrypt';
    }
  };
  mode?.addEventListener('change', syncConditionalFields);
  certificateSource?.addEventListener('change', syncConditionalFields);
  requireMount?.addEventListener('change', syncConditionalFields);
  externalWriters?.addEventListener('change', syncConditionalFields);
  syncConditionalFields();

  const dialog = document.querySelector('[data-dir-dialog]');
  if (!dialog?.showModal) return;
  const token = form.dataset.setupToken;
  const list = dialog.querySelector('[data-dir-list]');
  const current = dialog.querySelector('[data-dir-current]');
  const pickerTitle = dialog.querySelector('[data-picker-title]');
  const pickerHelp = dialog.querySelector('[data-picker-help]');
  const useDirectory = dialog.querySelector('[data-dir-use]');
  let target = null;
  let path = '/';
  let pickerMode = 'directory';
  let pickerFileKind = '';

  async function load(requestedPath, fallbackToRoot = false) {
    const response = await fetch(`/browse?token=${encodeURIComponent(token)}&path=${encodeURIComponent(requestedPath)}&mode=${pickerMode}&file_kind=${encodeURIComponent(pickerFileKind)}`);
    if (!response.ok) {
      if (fallbackToRoot && requestedPath !== '/') return load('/', false);
      list.innerHTML = '<p class="bad"><vl-i18n key="setup.directory_unreadable"/></p>';
      return;
    }
    const data = await response.json();
    path = data.path;
    current.textContent = path;
    const up = dialog.querySelector('[data-dir-up]');
    up.disabled = !data.parent;
    up.dataset.parent = data.parent || '';
    list.innerHTML = '';
    for (const entry of data.entries) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'dir-entry';
      button.dataset.entryType = entry.is_directory ? 'directory' : 'file';
      button.textContent = entry.name;
      button.addEventListener('click', () => {
        if (entry.is_directory) {
          load(entry.path);
        } else {
          target.value = entry.path;
          dialog.close();
        }
      });
      list.appendChild(button);
    }
    if (!data.entries.length) {
      list.innerHTML = `<p class="muted">${pickerMode === 'file' ? '<vl-i18n key="setup.no_files_or_directories"/>' : '<vl-i18n key="setup.no_subdirectories"/>'}</p>`;
    }
  }

  function openPicker(button, mode) {
    pickerMode = mode;
    target = form.elements[button.dataset.dirPicker || button.dataset.filePicker];
    pickerFileKind = target?.name === 'tls_cert_file' ? 'certificate'
      : target?.name === 'tls_key_file' ? 'private_key' : '';
    const value = target?.value || '';
    path = value.startsWith('/') ? value : '/';
    if (pickerMode === 'file' && path !== '/') {
      path = path.slice(0, path.lastIndexOf('/')) || '/';
    }
    pickerTitle.textContent = pickerMode === 'file' ? '<vl-i18n key="setup.choose_file"/>' : '<vl-i18n key="setup.choose_directory"/>';
    pickerHelp.textContent = pickerMode === 'file'
      ? pickerFileKind === 'certificate'
        ? '<vl-i18n key="setup.certificate_files_help"/>'
        : '<vl-i18n key="setup.private_key_files_help"/>'
      : '<vl-i18n key="setup.server_directories_help"/>';
    useDirectory.hidden = pickerMode === 'file';
    load(path, true);
    dialog.showModal();
  }

  document.querySelectorAll('[data-dir-picker]').forEach(button => button.addEventListener('click', () => openPicker(button, 'directory')));
  document.querySelectorAll('[data-file-picker]').forEach(button => button.addEventListener('click', () => openPicker(button, 'file')));
  dialog.querySelector('[data-dir-close]').addEventListener('click', () => dialog.close());
  dialog.querySelector('[data-dir-up]').addEventListener('click', event => {
    if (event.currentTarget.dataset.parent) load(event.currentTarget.dataset.parent);
  });
  dialog.querySelector('[data-dir-use]').addEventListener('click', () => {
    if (target) target.value = path;
    dialog.close();
  });
});
"#;

const SETUP_LOGO_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="VaultLink"><defs><linearGradient id="setup-g" x1="9" y1="7" x2="55" y2="59" gradientUnits="userSpaceOnUse"><stop stop-color="#5aa7ff"/><stop offset="1" stop-color="#7c5cff"/></linearGradient><filter id="setup-s" x="-20%" y="-20%" width="140%" height="140%"><feDropShadow dx="0" dy="6" stdDeviation="5" flood-color="#193b8f" flood-opacity=".35"/></filter></defs><rect width="64" height="64" rx="18" fill="#081226"/><path filter="url(#setup-s)" d="M32 7 51 15v15c0 13-7.8 22.8-19 27-11.2-4.2-19-14-19-27V15L32 7Z" fill="url(#setup-g)"/><path d="M24.4 36.7a7.5 7.5 0 0 1 0-10.6l4.1-4.1a7.5 7.5 0 0 1 10.6 0 2.8 2.8 0 0 1-4 4 1.9 1.9 0 0 0-2.7 0l-4.1 4.1a1.9 1.9 0 0 0 2.7 2.7 2.8 2.8 0 0 1 4 4 7.5 7.5 0 0 1-10.6-.1Z" fill="#f3f7ff"/><path d="M28.8 42a2.8 2.8 0 0 1 0-4 1.9 1.9 0 0 0 2.7 0l4.1-4.1a1.9 1.9 0 0 0-2.7-2.7 2.8 2.8 0 1 1-4-4 7.5 7.5 0 0 1 10.6 10.7L35.4 42a7.5 7.5 0 0 1-10.6 0Z" fill="#dbeafe" opacity=".95"/><path d="M27 32h10" stroke="#081226" stroke-width="4.2" stroke-linecap="round" opacity=".45"/></svg>"##;

fn qr_svg(data: &str) -> Result<String, String> {
    let code = QrCode::new(data.as_bytes()).map_err(|error| error.to_string())?;
    Ok(code
        .render::<svg::Color<'_>>()
        .min_dimensions(220, 220)
        .dark_color(svg::Color("#081226"))
        .light_color(svg::Color("#f8fbff"))
        .build())
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request},
    };
    use tower::ServiceExt;

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

    async fn response_text(response: Response) -> String {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    fn form(root: &Path, data: &Path) -> SetupForm {
        SetupForm {
            token: "token".into(),
            server_mode: "development".into(),
            listen_address: "127.0.0.1:8080".into(),
            public_base_url: "http://localhost:8080".into(),
            production_mode: None,
            root_mount_path: root.display().to_string(),
            data_directory: data.display().to_string(),
            internal_directory: String::new(),
            require_mount: None,
            external_writers: None,
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
            secure_cookie: None,
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
            .join(".vaultlink-internal-test")
            .display()
            .to_string();
        form.require_mount = Some("on".into());
        form.expected_filesystem_type = "ext4".into();
        form.expected_mount_source = "/dev/mapper/vaultlink-test".into();
    }

    #[tokio::test]
    async fn setup_form_uses_branding_units_log_dropdown_and_directory_picker() {
        let html = i18n::scope(Locale::De, "/?token=token".into(), async {
            page(&setup_form("token", None), Some("token"))
        })
        .await;
        assert!(html.contains("VaultLink<small>Secure file sharing</small>"));
        assert!(html.contains(r#"<html lang="de">"#));
        assert!(html.contains("Ersteinrichtung"));
        assert!(html.contains("name=\"max_upload_size_mb\""));
        assert!(html.contains("name=\"max_zip_size_gb\""));
        assert!(html.contains("name=\"max_preview_size_mb\""));
        assert!(html.contains("name=\"max_media_preview_size_mb\""));
        assert!(html.contains("<select name=\"log_level\">"));
        assert!(html.contains("VaultLink-Dienstadresse nach dem Setup"));
        assert!(html.contains("Die lokale Setup-Adresse bleibt davon unabhängig"));
        assert!(
            html.contains(r#"name="admin_username" value="admin" minlength="3" maxlength="64""#)
        );
        assert!(html.contains("data-dir-picker=\"root_mount_path\""));
        assert!(html.contains("data-dir-picker=\"internal_directory\""));
        assert!(html.contains("data-require-mount"));
        assert!(html.contains("data-external-writers"));
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
        assert!(SETUP_JAVASCRIPT.contains("fallbackToRoot"));
        assert!(!SETUP_JAVASCRIPT.contains("`Ordner ${entry.name}`"));
        assert!(!html.contains("Max Upload Bytes"));
        assert!(!html.contains("Log Level<br><input"));
        assert!(!html.contains("<vl-i18n"));
    }

    #[tokio::test]
    async fn setup_http_locale_uses_cookie_then_accept_language_then_english() {
        let config_dir = tempfile::tempdir().unwrap();
        let app = setup_router(test_setup_state(config_dir.path().join("config.toml")));

        let fallback = Request::builder()
            .uri("/?token=token")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(fallback).await.unwrap();
        assert_eq!(response.headers()[header::CONTENT_LANGUAGE], "en");
        let english = response_text(response).await;
        assert!(english.contains(r#"<html lang="en">"#));
        assert!(english.contains("Initial setup"));
        assert!(english.contains("VaultLink service address after setup"));
        assert!(english.contains(r#"name="return_to" value="/?token=token""#));
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

        let mut german = request(Method::GET, "/?token=token", "");
        german.headers_mut().insert(
            header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("de-AT,de;q=0.9"),
        );
        let response = app.clone().oneshot(german).await.unwrap();
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

        let mut cookie_override = request(Method::GET, "/?token=token", "");
        cookie_override.headers_mut().insert(
            header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        cookie_override.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_static("vaultlink_locale=de"),
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
    async fn setup_locale_route_preserves_token_and_rejects_external_return() {
        let config_dir = tempfile::tempdir().unwrap();
        let app = setup_router(test_setup_state(config_dir.path().join("config.toml")));

        let response = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/locale",
                "locale=de&return_to=%2F%3Ftoken%3Dtoken",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/?token=token");
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
            submit_setup(State(state.clone()), Form(form(root.path(), data.path()))).await
        })
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_text(response).await;
        assert!(body.contains("Secret stored safely"));
        assert!(!body.contains(r#"action="/locale""#));

        let response = i18n::scope(Locale::En, "/complete".into(), async {
            complete_setup(
                State(state),
                Form(CompleteSetupForm {
                    token: "token".into(),
                }),
            )
            .await
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
        german
            .headers_mut()
            .insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static("de"));
        let response = app.oneshot(german).await.unwrap();
        assert_eq!(response.headers()[header::CONTENT_LANGUAGE], "de");
        let german = response_text(response).await;
        assert!(german.contains("Verzeichnis kann nicht gelesen werden."));
        assert!(german.contains("Datei auswählen"));
        assert!(!german.contains("<vl-i18n"));
    }

    #[tokio::test]
    async fn setup_markers_cannot_collide_with_escaped_user_data() {
        let marker_shaped = r#"><vl-i18n key="setup.server"/>"#;
        let html = i18n::scope(Locale::En, "/".into(), async {
            page(
                &setup_form(marker_shaped, Some(marker_shaped)),
                Some(marker_shaped),
            )
        })
        .await;
        assert!(!html.contains("<vl-i18n"));
        assert!(html.contains(r#"&lt;vl-i18n key=&quot;setup.server&quot;/&gt;"#));
        assert!(html.contains("Initial setup"));
    }

    #[test]
    fn setup_qr_svg_renders_totp_code() {
        let qr = qr_svg("otpauth://totp/VaultLink:admin?secret=ABC&issuer=VaultLink").unwrap();
        assert!(qr.contains("<svg"));
        assert!(qr.contains("#081226"));
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

    #[test]
    fn setup_terminal_explains_headless_ssh_tunnel_and_local_url() {
        let output =
            setup_access_instructions("127.0.0.1:8090".parse().unwrap(), "one-time-setup-token");
        assert!(output.contains("lauscht ausschließlich auf Loopback"));
        assert!(output.contains("ssh -4 -N -L 127.0.0.1:8090:127.0.0.1:8090 BENUTZER@SERVER"));
        assert!(output
            .lines()
            .any(|line| line == "http://127.0.0.1:8090/?token=one-time-setup-token"));
        assert_eq!(output.matches("one-time-setup-token").count(), 1);
    }

    #[test]
    fn setup_terminal_formats_ipv6_loopback_for_ssh() {
        let output = setup_access_instructions("[::1]:8091".parse().unwrap(), "token");
        assert!(output.contains("ssh -4 -N -L 127.0.0.1:8091:[::1]:8091 BENUTZER@SERVER"));
        assert!(output
            .lines()
            .any(|line| line == "http://127.0.0.1:8091/?token=token"));
    }

    #[tokio::test]
    async fn setup_browser_filters_certificate_and_private_key_files_server_side() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("certs")).unwrap();
        std::fs::write(root.path().join("server.pem"), "certificate").unwrap();
        std::fs::write(root.path().join("server.crt"), "certificate").unwrap();
        std::fs::write(root.path().join("server.key"), "private key").unwrap();
        std::fs::write(root.path().join("setup-ui-proxy.py"), "script").unwrap();
        let (start_sender, _start_receiver) = tokio::sync::oneshot::channel();
        let state = SetupState {
            config_path: Arc::new(root.path().join("config.toml")),
            token: Arc::new("token".into()),
            commit: Arc::new(tokio::sync::Mutex::new(false)),
            start_sender: Arc::new(tokio::sync::Mutex::new(Some(start_sender))),
            start_requested: Arc::new(AtomicBool::new(false)),
        };
        let browse = |mode, file_kind| BrowseQuery {
            token: Some("token".into()),
            path: Some(root.path().display().to_string()),
            mode,
            file_kind,
        };

        let directory_response =
            setup_browse(State(state.clone()), Query(browse(None, None))).await;
        let directory_body = axum::body::to_bytes(directory_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let directory_body = String::from_utf8(directory_body.to_vec()).unwrap();
        assert!(directory_body.contains("certs"));
        assert!(!directory_body.contains("server.pem"));

        let certificate_response = setup_browse(
            State(state.clone()),
            Query(browse(Some("file".into()), Some("certificate".into()))),
        )
        .await;
        let certificate_body = axum::body::to_bytes(certificate_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let certificate_body = String::from_utf8(certificate_body.to_vec()).unwrap();
        assert!(certificate_body.contains("certs"));
        assert!(certificate_body.contains("server.pem"));
        assert!(certificate_body.contains("server.crt"));
        assert!(!certificate_body.contains("server.key"));
        assert!(!certificate_body.contains("setup-ui-proxy.py"));

        let key_response = setup_browse(
            State(state),
            Query(browse(Some("file".into()), Some("private_key".into()))),
        )
        .await;
        let key_body = axum::body::to_bytes(key_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let key_body = String::from_utf8(key_body.to_vec()).unwrap();
        assert!(key_body.contains("server.pem"));
        assert!(key_body.contains("server.key"));
        assert!(!key_body.contains("server.crt"));
        assert!(!key_body.contains("setup-ui-proxy.py"));
        assert!(key_body.contains(r#""is_directory":false"#));
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
        assert!(!result.totp_secret.is_empty());
        let config = Config::load(&config_path).unwrap();
        assert_eq!(config.storage.max_preview_size, 1_000_000);
        let confirmed = i18n::render_markers(
            Locale::De,
            &setup_confirmed_body(&config, "token", "Secret geschlossen."),
        );
        assert!(confirmed.contains("VaultLink jetzt starten"));
        assert!(confirmed.contains("Development"));
        assert!(!confirmed.contains("<vl-i18n"));
        assert!(!include_str!("setup.rs").contains(concat!("Ctrl", "+C")));
        let database = Database::open(data.path().join("data.sqlite")).unwrap();
        assert_eq!(database.admin_count().unwrap(), 1);
        assert!(database.admin("admin").unwrap().is_some());
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
            start_server(
                State(state),
                Form(CompleteSetupForm {
                    token: "token".into(),
                }),
            )
            .await
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
        form.production_mode = Some("on".into());
        configure_production_mount_policy(&mut form, root.path());
        form.secure_cookie = Some("on".into());
        form.certificate_source = "letsencrypt".into();
        form.letsencrypt_contact_email = "admin@example.test".into();
        let result = build_and_store_with_mount_validator(&config_path, form, |_| Ok(()))
            .await
            .unwrap();
        assert!(!result.totp_secret.is_empty());
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
        build_and_store_with_mount_validator(&config_path, form, |_| Ok(()))
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
        assert_eq!(recovered.totp_secret, first.totp_secret);

        clear_initial_setup_pending(data.path()).unwrap();
        assert!(!initial_setup_pending_path(data.path()).exists());
        assert!(
            build_and_store(&config_path, form(root.path(), data.path()))
                .await
                .is_err()
        );
    }
}
