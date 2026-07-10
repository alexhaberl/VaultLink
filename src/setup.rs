use std::{
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    extract::{Form, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
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
    runtime,
};

#[derive(Clone)]
struct SetupState {
    config_path: Arc<PathBuf>,
    token: Arc<String>,
    commit: Arc<tokio::sync::Mutex<bool>>,
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
struct SetupForm {
    token: String,
    server_mode: String,
    listen_address: String,
    public_base_url: String,
    production_mode: Option<String>,
    root_mount_path: String,
    data_directory: String,
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
    reverse_proxy_enabled: Option<String>,
    trusted_proxies: String,
    tls_enabled: Option<String>,
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
) -> Result<(), Box<dyn std::error::Error>> {
    validate_setup_listen(listen)?;
    let token = auth::random_token(32);
    println!("VaultLink setup URL:");
    println!("http://{listen}/?token={token}");
    println!("The setup token is printed once and is required by the browser form.");
    let state = SetupState {
        config_path: Arc::new(config_path),
        token: Arc::new(token),
        commit: Arc::new(tokio::sync::Mutex::new(false)),
    };
    let app = Router::new()
        .route("/", get(setup_page).post(submit_setup))
        .route("/complete", axum::routing::post(complete_setup))
        .route("/browse", get(setup_browse))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn validate_setup_listen(listen: SocketAddr) -> Result<(), &'static str> {
    if listen.ip().is_loopback() {
        Ok(())
    } else {
        Err("setup bind address must be loopback-only")
    }
}

async fn setup_page(State(state): State<SetupState>, Query(query): Query<TokenQuery>) -> Response {
    if query.token.as_deref() != Some(state.token.as_str()) {
        return (
            StatusCode::UNAUTHORIZED,
            Html(page("Setup-Token fehlt oder ist ungültig.")),
        )
            .into_response();
    }
    Html(page(&setup_form(&state.token, None))).into_response()
}

async fn submit_setup(State(state): State<SetupState>, Form(form): Form<SetupForm>) -> Response {
    if form.token != *state.token {
        return (
            StatusCode::UNAUTHORIZED,
            Html(page("Setup-Token fehlt oder ist ungültig.")),
        )
            .into_response();
    }
    let completed = state.commit.lock().await;
    if *completed {
        return (
            StatusCode::CONFLICT,
            Html(page("Setup wurde bereits abgeschlossen.")),
        )
            .into_response();
    }
    match build_and_store(&state.config_path, form).await {
        Ok(result) => match qr_svg(&result.otpauth) {
            Ok(qr) => {
                Html(page(&format!(
                    r#"<section><h1>Setup abgeschlossen</h1><p>Config wurde geschrieben und der erste Admin wurde angelegt.</p><p>Das TOTP-Secret bleibt bis zur ausdrÃ¼cklichen BestÃ¤tigung Ã¼ber diesen lokalen Setup-Flow wiederherstellbar. QR-Code mit der Authenticator-App scannen oder Secret manuell eintragen.</p><div class="qr-card" aria-label="TOTP QR-Code">{}</div><div class="secret-block"><code>{}</code><code>{}</code></div><form method="post" action="/complete"><input type="hidden" name="token" value="{}"><button>Secret sicher gespeichert</button></form><p>Danach den Setup-Prozess mit Ctrl+C beenden und VaultLink normal starten.</p></section>"#,
                    qr,
                    esc(&result.totp_secret),
                    esc(&result.otpauth),
                    esc(&state.token)
                )))
                .into_response()
            }
            Err(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(page(&format!(
                    "<section><h1>Fehler</h1><p>{}</p></section>",
                    esc(&error)
                ))),
            )
                .into_response(),
        },
        Err(error) => {
            let body = setup_form(&state.token, Some(&error));
            (StatusCode::BAD_REQUEST, Html(page(&body))).into_response()
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
            Html(page("Setup-Token fehlt oder ist ungÃ¼ltig.")),
        )
            .into_response();
    }
    let mut completed = state.commit.lock().await;
    if *completed {
        return Html(page(
            "<section><h1>Setup bestÃ¤tigt</h1><p>Die TOTP-Wiederherstellung ist bereits geschlossen.</p></section>",
        ))
        .into_response();
    }
    let config = match Config::load(state.config_path.as_ref()) {
        Ok(config) => config,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(page(&format!(
                    "Konfiguration kann nicht geladen werden: {}",
                    esc(&error.to_string())
                ))),
            )
                .into_response()
        }
    };
    match clear_initial_setup_pending(&config.storage.data_directory) {
        Ok(()) => {
            *completed = true;
            Html(page(
                "<section><h1>Setup bestÃ¤tigt</h1><p>Die TOTP-Wiederherstellung wurde geschlossen. VaultLink kann jetzt normal gestartet werden.</p></section>",
            ))
            .into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(page(&format!(
                "Setup-BestÃ¤tigung fehlgeschlagen: {}",
                esc(&error)
            ))),
        )
            .into_response(),
    }
}

struct SetupResult {
    totp_secret: String,
    otpauth: String,
}

async fn build_and_store(config_path: &Path, form: SetupForm) -> Result<SetupResult, String> {
    if form.admin_password != form.admin_password_confirm {
        return Err("Admin-Passwörter stimmen nicht überein.".into());
    }
    if form.admin_password.chars().count() < 14 {
        return Err("Admin-Passwort muss mindestens 14 Zeichen enthalten.".into());
    }
    if form.admin_username.len() < 3
        || !form
            .admin_username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("Admin-Benutzername muss sichere ASCII-Zeichen verwenden.".into());
    }
    let mode = match form.server_mode.as_str() {
        "development" => ServerMode::Development,
        "reverse_proxy" => ServerMode::ReverseProxy,
        "standalone_tls" => ServerMode::StandaloneTls,
        _ => return Err("Ungültiger Servermodus.".into()),
    };
    let standalone_tls = matches!(mode, ServerMode::StandaloneTls);
    let certificate_source = match form.certificate_source.as_str() {
        "files" => CertificateSource::Files,
        "letsencrypt" => CertificateSource::LetsEncrypt,
        _ => return Err("Ungültige TLS-Zertifikatsquelle.".into()),
    };
    let preview_extensions = runtime::parse_extension_list(&form.preview_extensions)?;
    let image_preview_extensions = runtime::parse_extension_list(&form.image_preview_extensions)?;
    let blocked_extensions = runtime::parse_extension_list(&form.blocked_extensions)?;
    let trusted_proxies = form
        .trusted_proxies
        .split([',', '\n', '\r', ' ', '\t'])
        .filter_map(|value| {
            let value = value.trim();
            (!value.is_empty()).then_some(value.parse())
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Trusted Proxies enthalten ungültige IPs.".to_string())?;
    let config = Config {
        server: Server {
            mode,
            listen_address: form.listen_address,
            public_base_url: form.public_base_url,
            production_mode: form.production_mode.is_some(),
        },
        storage: Storage {
            root_mount_path: form.root_mount_path.into(),
            data_directory: form.data_directory.into(),
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
            enabled: form.reverse_proxy_enabled.is_some(),
            allow_non_loopback: false,
            trusted_proxies,
            trust_x_forwarded_headers: form.reverse_proxy_enabled.is_some(),
        },
        tls: Tls {
            enabled: form.tls_enabled.is_some()
                || certificate_source == CertificateSource::LetsEncrypt,
            certificate_source,
            cert_file: form.tls_cert_file.into(),
            key_file: form.tls_key_file.into(),
            hsts_enabled: form.hsts_enabled.is_some(),
            reload_on_cert_change: standalone_tls
                && form.tls_enabled.is_some()
                && form.certificate_source == "files",
            letsencrypt_contact_email: form.letsencrypt_contact_email,
            letsencrypt_cache_dir: form.letsencrypt_cache_dir.into(),
            letsencrypt_staging: form.letsencrypt_staging.is_some(),
        },
        security: Security {
            secure_cookie: form.secure_cookie.is_some(),
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
    config.validate().map_err(|error| error.to_string())?;
    let serialized = toml::to_string_pretty(&config).map_err(|error| error.to_string())?;
    let recovering_existing_config = if config_path.exists() {
        let existing = Config::load(config_path).map_err(|error| {
            format!("Vorhandene Konfiguration kann nicht sicher fortgesetzt werden: {error}")
        })?;
        let existing_serialized =
            toml::to_string_pretty(&existing).map_err(|error| error.to_string())?;
        if existing_serialized != serialized {
            return Err(
                "Konfigurationsdatei existiert bereits und wird nicht überschrieben.".into(),
            );
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
                .ok_or_else(|| "Initial setup recovery is unavailable".to_string())?;
            let password_hash = admin.password_hash.clone();
            let password_valid = tokio::task::spawn_blocking(move || {
                auth::verify_password(&password_hash, &submitted_password)
            })
            .await
            .map_err(|error| error.to_string())?;
            if !password_valid {
                return Err("Initial setup recovery is unavailable".into());
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
        return Err("Datenbank enthält bereits Admins; Setup legt nur den ersten Admin an.".into());
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
                "Datenbank enthält bereits Admins; Setup legt nur den ersten Admin an.".into(),
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
            Err("Pending initial setup belongs to a different administrator".into())
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

fn sync_parent(_path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(_path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
    }
    Ok(())
}

fn parse_unit_to_bytes(name: &str, value: &str, unit: u64) -> Result<u64, String> {
    let value = value
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("{name} muss eine positive ganze Zahl sein."))?;
    value
        .checked_mul(unit)
        .ok_or_else(|| format!("{name} ist zu groß."))
}

fn parse_usize(name: &str, value: &str) -> Result<usize, String> {
    value
        .trim()
        .parse::<usize>()
        .map_err(|_| format!("{name} muss eine positive Zahl sein."))
}

const MB: u64 = 1_000_000;
const GB: u64 = 1_000_000_000;

#[derive(Deserialize)]
struct BrowseQuery {
    token: Option<String>,
    path: Option<String>,
}

#[derive(Serialize)]
struct BrowseEntry {
    name: String,
    path: String,
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
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path().display().to_string();
        entries.push(BrowseEntry { name, path });
    }
    entries.sort_by_key(|entry| entry.name.to_lowercase());
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

fn setup_form(token: &str, error: Option<&str>) -> String {
    let error = error
        .map(|error| format!(r#"<p class="bad">{}</p>"#, esc(error)))
        .unwrap_or_default();
    format!(
        r#"<section class="hero"><div><p class="eyebrow">VaultLink Setup</p><h1>Ersteinrichtung</h1><p class="muted">Lokaler Bootstrap für die initiale Konfiguration und den ersten Admin. Setup bindet ausschließlich an Loopback.</p></div><div class="side-panel"><strong>Sicherheit</strong><p class="muted">Built-in Let&apos;s Encrypt funktioniert nur, wenn VaultLink selbst Port 443 öffentlich erreicht. Hinter Nginx/Caddy bitte Reverse Proxy verwenden.</p></div></section>{error}<form method="post" class="setup-form" data-setup-token="{}"><input type="hidden" name="token" value="{}"><section class="form-card"><h2>Server</h2><div class="form-grid"><label>Modus<br><select name="server_mode"><option value="development">Development</option><option value="reverse_proxy">Reverse Proxy</option><option value="standalone_tls">Standalone TLS</option></select></label><label>Listen-Adresse<br><input name="listen_address" value="127.0.0.1:8080" required></label><label>Public Base URL<br><input name="public_base_url" value="http://localhost:8080" required></label><label>Log Level<br><select name="log_level"><option value="error">error</option><option value="warn">warn</option><option value="info" selected>info</option><option value="debug">debug</option><option value="trace">trace</option></select></label><label class="toggle-card"><input type="checkbox" name="production_mode"><span>Production Mode<small>Aktiviert produktive Startvalidierung.</small></span></label></div></section><section class="form-card"><h2>Storage</h2><div class="form-grid"><label>Root Mount Path<br><div class="input-action"><input name="root_mount_path" value="/tmp/vaultlink-root" required><button class="secondary small" type="button" data-dir-picker="root_mount_path">Durchsuchen</button></div></label><label>Data Directory<br><div class="input-action"><input name="data_directory" value="/tmp/vaultlink-data" required><button class="secondary small" type="button" data-dir-picker="data_directory">Durchsuchen</button></div></label><label>Max. Upload MB<br><input name="max_upload_size_mb" type="number" min="1" step="1" value="100" required></label><label>Blockierte Endungen<br><input name="blocked_extensions" value="exe,sh,php"></label></div></section><section class="form-card"><h2>ZIP, Suche und Preview</h2><div class="form-grid"><label>ZIP Max. GB<br><input name="max_zip_size_gb" type="number" min="1" step="1" value="1" required></label><label>ZIP Max. Dateien<br><input name="max_zip_files" type="number" min="1" value="10000" required></label><label>Suche Max. Einträge<br><input name="max_search_entries" type="number" min="1" value="50000" required></label><label>Suche Max. Treffer<br><input name="max_search_results" type="number" min="1" value="500" required></label><label>Text-Preview Max. MB<br><input name="max_preview_size_mb" type="number" min="1" step="1" value="1" required></label><label>Text-Preview-Endungen<br><input name="preview_extensions" value="txt,log,md,csv,json,toml,yaml,yml,ini,conf" required></label><label>Media-Preview Max. MB<br><input name="max_media_preview_size_mb" type="number" min="1" step="1" value="100" required></label><label>Bild-Preview-Endungen<br><input name="image_preview_extensions" value="jpg,jpeg,png,gif,webp,bmp,avif"></label><label class="toggle-card"><input type="checkbox" name="pdf_preview_enabled" checked><span>PDF-Preview aktiv<small>PDFs werden inline mit sicheren Headern angezeigt.</small></span></label></div></section><section class="form-card"><h2>Proxy und TLS</h2><div class="form-grid"><label class="toggle-card"><input type="checkbox" name="secure_cookie"><span>Secure Cookies<small>Für produktiven HTTPS-Betrieb aktivieren.</small></span></label><label class="toggle-card"><input type="checkbox" name="reverse_proxy_enabled"><span>Reverse Proxy aktiv<small>Forwarded Header nur von Trusted Proxies akzeptieren.</small></span></label><label>Trusted Proxies<br><input name="trusted_proxies" value="127.0.0.1,::1"></label><label class="toggle-card"><input type="checkbox" name="tls_enabled"><span>Standalone TLS aktiv<small>Nur ohne Reverse Proxy verwenden.</small></span></label><label>Zertifikatsquelle<br><select name="certificate_source"><option value="files">PEM-Dateien</option><option value="letsencrypt">Let&apos;s Encrypt Auto</option></select></label><label>TLS Cert File<br><input name="tls_cert_file"></label><label>TLS Key File<br><input name="tls_key_file"></label><label>Let&apos;s Encrypt Kontakt-E-Mail<br><input name="letsencrypt_contact_email" placeholder="admin@example.com"></label><label>ACME Cache Directory<br><div class="input-action"><input name="letsencrypt_cache_dir" value="acme" required><button class="secondary small" type="button" data-dir-picker="letsencrypt_cache_dir">Durchsuchen</button></div></label><label class="toggle-card"><input type="checkbox" name="letsencrypt_staging" checked><span>Let&apos;s Encrypt Staging<small>Für erste Tests ohne Rate-Limit-Risiko.</small></span></label><label class="toggle-card"><input type="checkbox" name="hsts_enabled"><span>HSTS aktiv<small>Nur bei finalem vertrauenswürdigem HTTPS aktivieren.</small></span></label></div></section><section class="form-card"><h2>Erster Admin</h2><div class="form-grid"><label>Benutzername<br><input name="admin_username" value="admin" required></label><label>Passwort<br><input name="admin_password" type="password" minlength="14" required></label><label>Passwort bestätigen<br><input name="admin_password_confirm" type="password" minlength="14" required></label></div></section><p class="form-actions"><button>Setup schreiben</button></p></form><dialog data-dir-dialog class="dir-dialog"><div class="dir-dialog-head"><strong>Verzeichnis auswählen</strong><button class="secondary small" type="button" data-dir-close>Schließen</button></div><p class="muted" data-dir-current>/</p><div class="button-group"><button class="secondary small" type="button" data-dir-up>Hoch</button><button class="small" type="button" data-dir-use>Dieses Verzeichnis übernehmen</button></div><div class="dir-list" data-dir-list></div></dialog>"#,
        esc(token),
        esc(token)
    )
}

fn page(body: &str) -> String {
    format!(
        r##"<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VaultLink Setup</title><style>{}</style><script>{}</script></head><body><div class="setup-shell"><main><div class="public-brand">{}<div>VaultLink<small>Secure file links</small></div></div>{}</main></div></body></html>"##,
        setup_css(),
        setup_js(),
        SETUP_LOGO_SVG,
        body
    )
}
fn setup_css() -> &'static str {
    r#":root{--bg:#070d1b;--card:#121b31;--card2:#172542;--text:#f4f7ff;--soft:#d7e3fb;--muted:#9fb0d0;--accent:#5aa7ff;--line:#263653;--line2:#3b5076;--bad:#ff7b86;--good:#55d69a}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top right,#221b57 0,#081020 34%,#050914 100%);color:var(--text);font:16px system-ui,-apple-system,Segoe UI,sans-serif}main{max-width:1220px;margin:auto;padding:2rem}.setup-shell{min-height:100vh}.public-brand{display:flex;align-items:center;gap:.8rem;margin:0 0 1.5rem;font-weight:900}.public-brand svg{width:48px;height:48px;border-radius:14px;box-shadow:0 12px 28px rgba(47,103,189,.25)}.public-brand small{display:block;color:var(--muted);font-weight:700}.hero,section{background:linear-gradient(180deg,rgba(23,37,66,.92),rgba(18,27,49,.92));border:1px solid rgba(90,167,255,.16);border-radius:22px;padding:1.35rem;margin:1rem 0;box-shadow:0 18px 60px rgba(0,0,0,.22)}.hero{display:grid;grid-template-columns:minmax(0,1fr) 360px;gap:1rem;align-items:center}.eyebrow{color:#9ed0ff;text-transform:uppercase;letter-spacing:.16em;font-weight:900;font-size:.78rem}.side-panel{padding:1rem;border-radius:18px;border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.045)}h1{font-size:clamp(2rem,4vw,3.4rem);line-height:1;margin:.2rem 0 .7rem}h2{margin:0 0 .9rem;font-size:1.12rem;color:#dbeafe}.muted{color:var(--muted)}.bad{color:var(--bad);font-weight:800}.qr-card{display:inline-flex;margin:1rem 0;padding:1rem;border-radius:18px;background:#f8fbff;box-shadow:0 18px 42px rgba(0,0,0,.28)}.qr-card svg{display:block;width:220px;height:220px}.secret-block{display:grid;gap:.6rem;margin:1rem 0}.secret-block code{display:block;max-width:100%;overflow:auto;padding:.85rem;border-radius:12px;background:#081226;border:1px solid var(--line2);color:#dbeafe}.form-card{padding:1rem;border:1px solid rgba(90,167,255,.16);border-radius:18px;background:rgba(90,167,255,.045);margin:1rem 0}.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:.9rem;align-items:end}label{display:block;color:var(--soft);font-weight:700}input,select,button{font:inherit;padding:.72rem .8rem;border-radius:12px;border:1px solid var(--line2);background:#0b1326;color:var(--text);max-width:100%}label input,label select{margin-top:.25rem;width:100%}input:focus,select:focus{outline:2px solid rgba(90,167,255,.35);border-color:var(--accent)}button,.button{display:inline-flex;align-items:center;justify-content:center;gap:.4rem;cursor:pointer;padding:.78rem 1rem;border-radius:12px;background:linear-gradient(135deg,#2f67bd,#4e7de2);border:1px solid rgba(255,255,255,.1);color:white;box-shadow:0 10px 24px rgba(47,103,189,.22);font-weight:800;line-height:1.1;text-decoration:none;white-space:nowrap}.secondary{background:rgba(90,167,255,.12);border-color:rgba(90,167,255,.35);box-shadow:none;color:#dbeafe}.small{padding:.55rem .75rem;border-radius:10px;font-size:.92rem}.form-actions,.button-group{display:flex;gap:.55rem;flex-wrap:wrap;align-items:center}.input-action{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.45rem;align-items:end}.toggle-card{display:flex;align-items:center;gap:.85rem;width:100%;min-width:260px;padding:.9rem 1rem;border:1px solid rgba(90,167,255,.22);border-radius:16px;background:rgba(90,167,255,.07);cursor:pointer}.toggle-card input{position:absolute;opacity:0;width:1px;height:1px}.toggle-card>input+span{position:relative;display:grid;gap:.15rem;padding-left:68px;color:var(--text)}.toggle-card>input+span::before{content:"";position:absolute;left:0;top:50%;transform:translateY(-50%);width:54px;height:30px;border-radius:999px;background:#1f2b45;border:1px solid var(--line2);box-shadow:inset 0 1px 4px rgba(0,0,0,.28)}.toggle-card>input+span::after{content:"";position:absolute;left:4px;top:50%;transform:translateY(-50%);width:22px;height:22px;border-radius:999px;background:#dbeafe;transition:transform .18s ease,background .18s ease}.toggle-card>input:checked+span::before{background:linear-gradient(135deg,#2f67bd,#4e7de2);border-color:rgba(255,255,255,.18)}.toggle-card>input:checked+span::after{transform:translate(24px,-50%);background:#fff}.toggle-card small{display:block;color:var(--muted);font-weight:600;line-height:1.35}.dir-dialog{width:min(720px,92vw);border:1px solid rgba(90,167,255,.22);border-radius:20px;background:#101a30;color:var(--text);box-shadow:0 30px 90px rgba(0,0,0,.55);padding:1rem}.dir-dialog::backdrop{background:rgba(0,0,0,.55)}.dir-dialog-head{display:flex;justify-content:space-between;gap:1rem;align-items:center}.dir-list{display:grid;gap:.45rem;max-height:420px;overflow:auto;margin-top:.9rem}.dir-entry{display:flex;justify-content:space-between;gap:.8rem;align-items:center;padding:.75rem .85rem;border:1px solid rgba(255,255,255,.08);border-radius:14px;background:rgba(255,255,255,.035);color:var(--text);text-align:left}.dir-entry:hover{filter:brightness(1.08)}@media(max-width:850px){main{padding:1rem}.hero{grid-template-columns:1fr}.input-action{grid-template-columns:1fr}.form-actions{display:block}}"#
}

fn setup_js() -> &'static str {
    r#"document.addEventListener('DOMContentLoaded',()=>{const form=document.querySelector('[data-setup-token]');const dialog=document.querySelector('[data-dir-dialog]');if(!form||!dialog||!dialog.showModal)return;const token=form.dataset.setupToken;const list=dialog.querySelector('[data-dir-list]');const current=dialog.querySelector('[data-dir-current]');let target=null;let path='/';async function load(p){const res=await fetch(`/browse?token=${encodeURIComponent(token)}&path=${encodeURIComponent(p)}`);if(!res.ok){list.innerHTML='<p class="bad">Verzeichnis kann nicht gelesen werden.</p>';return;}const data=await res.json();path=data.path;current.textContent=path;dialog.querySelector('[data-dir-up]').disabled=!data.parent;dialog.querySelector('[data-dir-up]').dataset.parent=data.parent||'';list.innerHTML='';for(const entry of data.entries){const b=document.createElement('button');b.type='button';b.className='dir-entry';b.textContent='Ordner '+entry.name;b.addEventListener('click',()=>load(entry.path));list.appendChild(b);}if(!data.entries.length){list.innerHTML='<p class="muted">Keine Unterverzeichnisse.</p>';}}document.querySelectorAll('[data-dir-picker]').forEach(button=>button.addEventListener('click',()=>{target=form.elements[button.dataset.dirPicker];path=(target&&target.value&&target.value.startsWith('/'))?target.value:'/';load(path);dialog.showModal();}));dialog.querySelector('[data-dir-close]').addEventListener('click',()=>dialog.close());dialog.querySelector('[data-dir-up]').addEventListener('click',e=>{if(e.currentTarget.dataset.parent)load(e.currentTarget.dataset.parent);});dialog.querySelector('[data-dir-use]').addEventListener('click',()=>{if(target)target.value=path;dialog.close();});});"#
}

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

    fn form(root: &Path, data: &Path) -> SetupForm {
        SetupForm {
            token: "token".into(),
            server_mode: "development".into(),
            listen_address: "127.0.0.1:8080".into(),
            public_base_url: "http://localhost:8080".into(),
            production_mode: None,
            root_mount_path: root.display().to_string(),
            data_directory: data.display().to_string(),
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
            secure_cookie: None,
            reverse_proxy_enabled: None,
            trusted_proxies: "127.0.0.1".into(),
            tls_enabled: None,
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

    #[test]
    fn setup_form_uses_branding_units_log_dropdown_and_directory_picker() {
        let html = page(&setup_form("token", None));
        assert!(html.contains("VaultLink<small>Secure file links</small>"));
        assert!(html.contains("SETUP") || html.contains("Ersteinrichtung"));
        assert!(html.contains("name=\"max_upload_size_mb\""));
        assert!(html.contains("name=\"max_zip_size_gb\""));
        assert!(html.contains("name=\"max_preview_size_mb\""));
        assert!(html.contains("name=\"max_media_preview_size_mb\""));
        assert!(html.contains("<select name=\"log_level\">"));
        assert!(html.contains("data-dir-picker=\"root_mount_path\""));
        assert!(html.contains("data-dir-dialog"));
        assert!(!html.contains("Max Upload Bytes"));
        assert!(!html.contains("Log Level<br><input"));
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
        assert!(validate_setup_listen("0.0.0.0:8090".parse().unwrap()).is_err());
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
        let database = Database::open(data.path().join("data.sqlite")).unwrap();
        assert_eq!(database.admin_count().unwrap(), 1);
        assert!(database.admin("admin").unwrap().is_some());
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
        form.secure_cookie = Some("on".into());
        form.tls_enabled = Some("on".into());
        form.certificate_source = "letsencrypt".into();
        form.letsencrypt_contact_email = "admin@example.test".into();
        let result = build_and_store(&config_path, form).await.unwrap();
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
