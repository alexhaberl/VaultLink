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
    Router,
};
use serde::Deserialize;

use crate::{
    auth,
    config::{
        CertificateSource, Config, Logging, ReverseProxy, Security, Server, ServerMode, Storage,
        Tls,
    },
    db::Database,
    runtime,
};

#[derive(Clone)]
struct SetupState {
    config_path: Arc<PathBuf>,
    token: Arc<String>,
}

#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
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
    max_upload_size: String,
    max_zip_size: String,
    max_zip_files: String,
    max_search_entries: String,
    max_search_results: String,
    max_preview_size: String,
    preview_extensions: String,
    image_preview_extensions: String,
    pdf_preview_enabled: Option<String>,
    max_media_preview_size: String,
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
    };
    let app = Router::new()
        .route("/", get(setup_page).post(submit_setup))
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
    match build_and_store(&state.config_path, form).await {
        Ok(result) => Html(page(&format!(
            r#"<section><h1>Setup abgeschlossen</h1><p>Config wurde geschrieben und der erste Admin wurde angelegt.</p><p>Dieses TOTP-Secret wird nur jetzt angezeigt:</p><p><code>{}</code></p><p><code>{}</code></p><p>Setup-Prozess jetzt mit Ctrl+C beenden und VaultLink normal starten.</p></section>"#,
            esc(&result.totp_secret),
            esc(&result.otpauth)
        )))
        .into_response(),
        Err(error) => {
            let body = setup_form(&state.token, Some(&error));
            (StatusCode::BAD_REQUEST, Html(page(&body))).into_response()
        }
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
        _ => return Err("Ungueltige TLS-Zertifikatsquelle.".into()),
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
            max_upload_size: parse_u64("max_upload_size", &form.max_upload_size)?,
            max_zip_size: parse_u64("max_zip_size", &form.max_zip_size)?,
            max_zip_files: parse_usize("max_zip_files", &form.max_zip_files)?,
            max_search_entries: parse_usize("max_search_entries", &form.max_search_entries)?,
            max_search_results: parse_usize("max_search_results", &form.max_search_results)?,
            max_preview_size: parse_u64("max_preview_size", &form.max_preview_size)?,
            preview_extensions,
            image_preview_extensions,
            pdf_preview_enabled: form.pdf_preview_enabled.is_some(),
            max_media_preview_size: parse_u64(
                "max_media_preview_size",
                &form.max_media_preview_size,
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
    write_config_atomic(config_path, &config).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&config.storage.data_directory).map_err(|error| error.to_string())?;
    let database = Database::open(config.storage.data_directory.join("data.sqlite"))
        .map_err(|error| error.to_string())?;
    if database.admin_count().map_err(|error| error.to_string())? != 0 {
        return Err("Datenbank enthält bereits Admins; Setup legt nur den ersten Admin an.".into());
    }
    let totp_secret = auth::new_totp_secret();
    let password = form.admin_password;
    let hash = tokio::task::spawn_blocking(move || auth::hash_password(&password))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
    database
        .create_admin(&form.admin_username, &hash, &totp_secret)
        .map_err(|error| error.to_string())?;
    let otpauth = format!(
        "otpauth://totp/VaultLink:{}?secret={}&issuer=VaultLink",
        form.admin_username, totp_secret
    );
    Ok(SetupResult {
        totp_secret,
        otpauth,
    })
}

fn write_config_atomic(path: &Path, config: &Config) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    let content = toml::to_string_pretty(config).map_err(std::io::Error::other)?;
    temporary.write_all(content.as_bytes())?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map(|_| ())
        .map_err(|error| error.error)
}

fn parse_u64(name: &str, value: &str) -> Result<u64, String> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("{name} muss eine positive Zahl sein."))
}

fn parse_usize(name: &str, value: &str) -> Result<usize, String> {
    value
        .trim()
        .parse::<usize>()
        .map_err(|_| format!("{name} muss eine positive Zahl sein."))
}

#[allow(dead_code)]
fn setup_form_legacy(token: &str, error: Option<&str>) -> String {
    let error = error
        .map(|error| format!(r#"<p class="bad">{}</p>"#, esc(error)))
        .unwrap_or_default();
    format!(
        r#"<section><h1>VaultLink Setup</h1>{error}<form method="post" class="grid"><input type="hidden" name="token" value="{}"><h2>Server</h2><label>Modus<br><select name="server_mode"><option value="development">development</option><option value="reverse_proxy">reverse_proxy</option><option value="standalone_tls">standalone_tls</option></select></label><label>Listen Address<br><input name="listen_address" value="127.0.0.1:8080" required></label><label>Public Base URL<br><input name="public_base_url" value="http://localhost:8080" required></label><label><input type="checkbox" name="production_mode"> Production Mode</label><h2>Storage</h2><label>Root Mount Path<br><input name="root_mount_path" value="./dev-mount" required></label><label>Data Directory<br><input name="data_directory" value="./dev-data" required></label><label>Max Upload Bytes<br><input name="max_upload_size" type="number" value="1073741824" required></label><label>Blocked Extensions<br><input name="blocked_extensions" value="exe,sh,php"></label><h2>ZIP / Suche / Preview</h2><label>Max ZIP Bytes<br><input name="max_zip_size" type="number" value="1073741824" required></label><label>Max ZIP Files<br><input name="max_zip_files" type="number" value="10000" required></label><label>Max Search Entries<br><input name="max_search_entries" type="number" value="50000" required></label><label>Max Search Results<br><input name="max_search_results" type="number" value="500" required></label><label>Max Preview Bytes<br><input name="max_preview_size" type="number" value="1048576" required></label><label>Preview Extensions<br><input name="preview_extensions" value="txt,log,md,csv,json,toml,yaml,yml,ini,conf" required></label><h2>Proxy/TLS</h2><label><input type="checkbox" name="secure_cookie"> Secure Cookies</label><label><input type="checkbox" name="reverse_proxy_enabled"> Reverse Proxy aktiv</label><label>Trusted Proxies<br><input name="trusted_proxies" value="127.0.0.1,::1"></label><label><input type="checkbox" name="tls_enabled"> Standalone TLS aktiv</label><label>TLS Cert File<br><input name="tls_cert_file"></label><label>TLS Key File<br><input name="tls_key_file"></label><label><input type="checkbox" name="hsts_enabled"> HSTS</label><label>Log Level<br><input name="log_level" value="info"></label><h2>Erster Admin</h2><label>Benutzername<br><input name="admin_username" value="admin" required></label><label>Passwort<br><input name="admin_password" type="password" minlength="14" required></label><label>Passwort bestätigen<br><input name="admin_password_confirm" type="password" minlength="14" required></label><p><button>Setup schreiben</button></p></form></section>"#,
        esc(token)
    )
}

fn setup_form(token: &str, error: Option<&str>) -> String {
    let error = error
        .map(|error| format!(r#"<p class="bad">{}</p>"#, esc(error)))
        .unwrap_or_default();
    format!(
        r#"<section><h1>VaultLink Setup</h1>{error}<p class="muted">Built-in Let&apos;s Encrypt funktioniert nur, wenn VaultLink selbst Port 443 oeffentlich erreicht. Hinter Nginx/Caddy bitte Reverse Proxy verwenden.</p><form method="post" class="grid"><input type="hidden" name="token" value="{}"><h2>Server</h2><label>Modus<br><select name="server_mode"><option value="development">development</option><option value="reverse_proxy">reverse_proxy</option><option value="standalone_tls">standalone_tls</option></select></label><label>Listen Address<br><input name="listen_address" value="127.0.0.1:8080" required></label><label>Public Base URL<br><input name="public_base_url" value="http://localhost:8080" required></label><label><input type="checkbox" name="production_mode"> Production Mode</label><h2>Storage</h2><label>Root Mount Path<br><input name="root_mount_path" value="./dev-mount" required></label><label>Data Directory<br><input name="data_directory" value="./dev-data" required></label><label>Max Upload Bytes<br><input name="max_upload_size" type="number" value="1073741824" required></label><label>Blocked Extensions<br><input name="blocked_extensions" value="exe,sh,php"></label><h2>ZIP / Suche / Preview</h2><label>Max ZIP Bytes<br><input name="max_zip_size" type="number" value="1073741824" required></label><label>Max ZIP Files<br><input name="max_zip_files" type="number" value="10000" required></label><label>Max Search Entries<br><input name="max_search_entries" type="number" value="50000" required></label><label>Max Search Results<br><input name="max_search_results" type="number" value="500" required></label><label>Text Preview Max Bytes<br><input name="max_preview_size" type="number" value="1048576" required></label><label>Text Preview Extensions<br><input name="preview_extensions" value="txt,log,md,csv,json,toml,yaml,yml,ini,conf" required></label><label>Media Preview Max Bytes<br><input name="max_media_preview_size" type="number" value="104857600" required></label><label>Image Preview Extensions<br><input name="image_preview_extensions" value="jpg,jpeg,png,gif,webp,bmp,avif"></label><label><input type="checkbox" name="pdf_preview_enabled" checked> PDF Preview aktiv</label><h2>Proxy/TLS</h2><label><input type="checkbox" name="secure_cookie"> Secure Cookies</label><label><input type="checkbox" name="reverse_proxy_enabled"> Reverse Proxy aktiv</label><label>Trusted Proxies<br><input name="trusted_proxies" value="127.0.0.1,::1"></label><label><input type="checkbox" name="tls_enabled"> Standalone TLS aktiv</label><label>Zertifikatsquelle<br><select name="certificate_source"><option value="files">PEM-Dateien</option><option value="letsencrypt">Let&apos;s Encrypt Auto</option></select></label><label>TLS Cert File<br><input name="tls_cert_file"></label><label>TLS Key File<br><input name="tls_key_file"></label><label>Let&apos;s Encrypt Kontakt-E-Mail<br><input name="letsencrypt_contact_email" placeholder="admin@example.com"></label><label>ACME Cache Directory<br><input name="letsencrypt_cache_dir" value="acme" required></label><label><input type="checkbox" name="letsencrypt_staging" checked> Let&apos;s Encrypt Staging verwenden</label><label><input type="checkbox" name="hsts_enabled"> HSTS</label><label>Log Level<br><input name="log_level" value="info"></label><h2>Erster Admin</h2><label>Benutzername<br><input name="admin_username" value="admin" required></label><label>Passwort<br><input name="admin_password" type="password" minlength="14" required></label><label>Passwort bestaetigen<br><input name="admin_password_confirm" type="password" minlength="14" required></label><p><button>Setup schreiben</button></p></form></section>"#,
        esc(token)
    )
}

fn page(body: &str) -> String {
    format!(
        r#"<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VaultLink Setup</title><style>:root{{--bg:#0b1020;--card:#151c31;--text:#edf2ff;--muted:#9eabc7;--accent:#6ea8fe;--bad:#ff7b86}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:16px system-ui,sans-serif}}main{{max-width:1100px;margin:auto;padding:1rem}}section{{background:var(--card);padding:1.25rem;border-radius:12px}}input,select,button{{font:inherit;padding:.65rem;border-radius:7px;border:1px solid #46516d;background:#0e1528;color:var(--text);max-width:100%}}button{{cursor:pointer;background:#264f94}}label{{display:block;margin:.7rem 0}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:.75rem}}h2{{grid-column:1/-1}}.bad{{color:var(--bad)}}code{{overflow-wrap:anywhere}}</style></head><body><main>{}</main></body></html>"#,
        body
    )
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
            max_upload_size: "1024".into(),
            max_zip_size: "2048".into(),
            max_zip_files: "10".into(),
            max_search_entries: "100".into(),
            max_search_results: "10".into(),
            max_preview_size: "512".into(),
            preview_extensions: "txt,log".into(),
            image_preview_extensions: "jpg,png".into(),
            pdf_preview_enabled: Some("on".into()),
            max_media_preview_size: "4096".into(),
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
        assert_eq!(config.storage.max_preview_size, 512);
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
        assert_eq!(config.storage.max_media_preview_size, 4096);
    }
}
