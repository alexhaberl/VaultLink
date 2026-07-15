use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// Hard ceiling for an entire multipart request body. This protects the server from
/// configurations that cannot be represented by the HTTP upload routes.
pub const MAX_MULTIPART_BODY_SIZE: u64 = 128 * 1024 * 1024 * 1024;
/// Maximum file payload. One MiB is reserved for multipart boundaries, filenames,
/// and the bounded auxiliary form fields.
pub const MAX_UPLOAD_SIZE: u64 = MAX_MULTIPART_BODY_SIZE - 1024 * 1024;
pub const DEFAULT_INTERNAL_DIRECTORY_NAME: &str = ".vaultlink-internal";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: Server,
    pub storage: Storage,
    #[serde(default)]
    pub reverse_proxy: ReverseProxy,
    #[serde(default)]
    pub tls: Tls,
    #[serde(default)]
    pub security: Security,
    #[serde(default)]
    pub logging: Logging,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalReadinessTarget {
    pub url: String,
    pub connect_to: Option<String>,
    pub insecure: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ServerMode {
    Development,
    ReverseProxy,
    StandaloneTls,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub mode: ServerMode,
    pub listen_address: String,
    pub public_base_url: String,
    #[serde(default)]
    pub production_mode: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    pub root_mount_path: PathBuf,
    pub data_directory: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internal_directory: Option<PathBuf>,
    #[serde(default)]
    pub require_mount: bool,
    #[serde(default)]
    pub external_writers: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_filesystem_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_mount_source: Option<String>,
    #[serde(default = "default_upload_size")]
    pub max_upload_size: u64,
    #[serde(default = "default_zip_size")]
    pub max_zip_size: u64,
    #[serde(default = "default_zip_files")]
    pub max_zip_files: usize,
    #[serde(default = "default_search_entries")]
    pub max_search_entries: usize,
    #[serde(default = "default_search_results")]
    pub max_search_results: usize,
    #[serde(default = "default_preview_size")]
    pub max_preview_size: u64,
    #[serde(default = "default_preview_extensions")]
    pub preview_extensions: Vec<String>,
    #[serde(default = "default_image_preview_extensions")]
    pub image_preview_extensions: Vec<String>,
    #[serde(default = "yes")]
    pub pdf_preview_enabled: bool,
    #[serde(default = "default_media_preview_size")]
    pub max_media_preview_size: u64,
    #[serde(default)]
    pub blocked_extensions: Vec<String>,
}

fn default_upload_size() -> u64 {
    100_000_000
}
fn default_zip_size() -> u64 {
    1_000_000_000
}
fn default_zip_files() -> usize {
    10_000
}
fn default_search_entries() -> usize {
    50_000
}
fn default_search_results() -> usize {
    500
}
fn default_preview_size() -> u64 {
    1_000_000
}
fn default_preview_extensions() -> Vec<String> {
    [
        "txt", "log", "md", "csv", "json", "toml", "yaml", "yml", "ini", "conf",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}
fn default_image_preview_extensions() -> Vec<String> {
    ["jpg", "jpeg", "png", "gif", "webp", "bmp", "avif"]
        .into_iter()
        .map(str::to_string)
        .collect()
}
fn default_media_preview_size() -> u64 {
    100_000_000
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReverseProxy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allow_non_loopback: bool,
    #[serde(default)]
    pub trusted_proxies: Vec<IpAddr>,
    #[serde(default)]
    pub trust_x_forwarded_headers: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CertificateSource {
    #[default]
    Files,
    #[serde(rename = "letsencrypt")]
    LetsEncrypt,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub certificate_source: CertificateSource,
    #[serde(default)]
    pub cert_file: PathBuf,
    #[serde(default)]
    pub key_file: PathBuf,
    #[serde(default)]
    pub hsts_enabled: bool,
    #[serde(default)]
    pub reload_on_cert_change: bool,
    #[serde(default)]
    pub letsencrypt_contact_email: String,
    #[serde(default = "default_letsencrypt_cache_dir")]
    pub letsencrypt_cache_dir: PathBuf,
    #[serde(default = "yes")]
    pub letsencrypt_staging: bool,
}

fn default_letsencrypt_cache_dir() -> PathBuf {
    PathBuf::from("acme")
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Security {
    #[serde(default = "default_session_hours")]
    pub session_hours: i64,
    #[serde(default = "default_attempts")]
    pub login_attempts: usize,
    #[serde(default = "default_window")]
    pub login_window_seconds: u64,
    #[serde(default = "yes")]
    pub secure_cookie: bool,
    #[serde(default = "default_share_password_min")]
    pub share_password_min_length: usize,
    #[serde(default = "default_share_password_max")]
    pub share_password_max_length: usize,
    #[serde(default = "default_share_unlock_minutes")]
    pub share_unlock_minutes: i64,
    #[serde(default = "default_attempts")]
    pub share_password_attempts: usize,
    #[serde(default)]
    pub audit_client_ip_enabled: bool,
}
impl Default for Security {
    fn default() -> Self {
        Self {
            session_hours: default_session_hours(),
            login_attempts: default_attempts(),
            login_window_seconds: default_window(),
            secure_cookie: true,
            share_password_min_length: default_share_password_min(),
            share_password_max_length: default_share_password_max(),
            share_unlock_minutes: default_share_unlock_minutes(),
            share_password_attempts: default_attempts(),
            audit_client_ip_enabled: false,
        }
    }
}
fn default_session_hours() -> i64 {
    12
}
fn default_attempts() -> usize {
    5
}
fn default_window() -> u64 {
    300
}
fn yes() -> bool {
    true
}
fn default_share_password_min() -> usize {
    12
}
fn default_share_password_max() -> usize {
    256
}
fn default_share_unlock_minutes() -> i64 {
    60
}

const MAX_SESSION_HOURS: i64 = 24 * 365;
const MAX_AUTH_ATTEMPTS: usize = 100;
const MAX_LOGIN_WINDOW_SECONDS: u64 = 24 * 60 * 60;
const MAX_SHARE_PASSWORD_LENGTH: usize = 1_024;
const MAX_SHARE_UNLOCK_MINUTES: i64 = 30 * 24 * 60;
pub(crate) const MAX_TEXT_PREVIEW_SIZE: u64 = 64_000_000;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Logging {
    #[serde(default = "default_level")]
    pub level: String,
}
impl Default for Logging {
    fn default() -> Self {
        Self {
            level: default_level(),
        }
    }
}
fn default_level() -> String {
    "info".into()
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read configuration: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

fn local_readiness_peer_ip(listen_ip: IpAddr) -> IpAddr {
    match listen_ip {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let value = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&value)?;
        config.validate()?;
        Ok(config)
    }

    pub fn local_readiness_target(&self) -> Result<LocalReadinessTarget, ConfigError> {
        let listen: SocketAddr = self.server.listen_address.parse().map_err(|_| {
            ConfigError::Invalid("listen_address must be an IP socket address".into())
        })?;
        let local_ip = local_readiness_peer_ip(listen.ip());
        let local = SocketAddr::new(local_ip, listen.port());

        if self.server.mode != ServerMode::StandaloneTls {
            return Ok(LocalReadinessTarget {
                url: format!("http://{local}/api/v1/health"),
                connect_to: None,
                insecure: false,
            });
        }

        let mut public_url = Url::parse(&self.server.public_base_url)
            .map_err(|error| ConfigError::Invalid(format!("public_base_url: {error}")))?;
        let public_host = public_url
            .host_str()
            .ok_or_else(|| ConfigError::Invalid("public_base_url must contain a host".into()))?
            .to_string();
        let public_port = public_url.port_or_known_default().ok_or_else(|| {
            ConfigError::Invalid("public_base_url must contain a known port".into())
        })?;
        public_url.set_path("/api/v1/health");
        public_url.set_query(None);
        public_url.set_fragment(None);

        Ok(LocalReadinessTarget {
            url: public_url.to_string(),
            connect_to: Some(format!(
                "{}:{public_port}:{}:{}",
                curl_connect_host(&public_host),
                curl_connect_host(&local.ip().to_string()),
                local.port()
            )),
            insecure: true,
        })
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.server.public_base_url.starts_with("http://")
            && !self.server.public_base_url.starts_with("https://")
        {
            return Err(ConfigError::Invalid(
                "public_base_url must use canonical HTTP(S) authority syntax".into(),
            ));
        }
        let url = Url::parse(&self.server.public_base_url)
            .map_err(|e| ConfigError::Invalid(format!("public_base_url: {e}")))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(ConfigError::Invalid(
                "public_base_url must be an absolute HTTP(S) URL without credentials, query, or fragment"
                    .into(),
            ));
        }
        let authority_start = self
            .server
            .public_base_url
            .find("://")
            .map(|index| index + 3)
            .unwrap_or_default();
        if url.path() != "/" || self.server.public_base_url[authority_start..].contains(['/', '\\'])
        {
            return Err(ConfigError::Invalid(
                "public_base_url must use the root path and omit the trailing slash".into(),
            ));
        }
        let listen: std::net::SocketAddr = self.server.listen_address.parse().map_err(|_| {
            ConfigError::Invalid("listen_address must be an IP socket address".into())
        })?;
        match self.server.mode {
            ServerMode::Development => {
                if self.server.production_mode {
                    return Err(ConfigError::Invalid(
                        "development mode cannot be production_mode".into(),
                    ));
                }
                if !listen.ip().is_loopback() {
                    return Err(ConfigError::Invalid(
                        "development mode must bind to localhost".into(),
                    ));
                }
                if url.scheme() != "http" {
                    return Err(ConfigError::Invalid(
                        "development public_base_url must use http".into(),
                    ));
                }
            }
            ServerMode::ReverseProxy => {
                if !self.server.production_mode || url.scheme() != "https" {
                    return Err(ConfigError::Invalid(
                        "reverse_proxy mode requires production_mode and HTTPS public_base_url"
                            .into(),
                    ));
                }
                if !self.reverse_proxy.enabled || self.reverse_proxy.trusted_proxies.is_empty() {
                    return Err(ConfigError::Invalid(
                        "reverse_proxy mode requires enabled=true and trusted_proxies".into(),
                    ));
                }
                if !listen.ip().is_loopback() && !self.reverse_proxy.allow_non_loopback {
                    return Err(ConfigError::Invalid(
                        "non-loopback reverse proxy binding requires allow_non_loopback=true"
                            .into(),
                    ));
                }
                if !listen.ip().is_loopback()
                    && !self
                        .reverse_proxy
                        .trusted_proxies
                        .iter()
                        .copied()
                        .map(crate::proxy::canonical_peer_ip)
                        .any(|proxy| !proxy.is_loopback())
                {
                    return Err(ConfigError::Invalid(
                        "non-loopback binding requires a non-loopback trusted proxy".into(),
                    ));
                }
                let readiness_peer = local_readiness_peer_ip(listen.ip());
                if !crate::proxy::is_trusted_proxy_peer(
                    readiness_peer,
                    &self.reverse_proxy.trusted_proxies,
                ) {
                    return Err(ConfigError::Invalid(format!(
                        "reverse_proxy trusted_proxies must include the local readiness peer {readiness_peer}"
                    )));
                }
                if self.tls.enabled {
                    return Err(ConfigError::Invalid(
                        "reverse_proxy mode must not enable application TLS".into(),
                    ));
                }
                if self.tls.certificate_source == CertificateSource::LetsEncrypt {
                    return Err(ConfigError::Invalid(
                        "letsencrypt certificate_source is valid only in standalone_tls mode"
                            .into(),
                    ));
                }
            }
            ServerMode::StandaloneTls => {
                if !self.server.production_mode || url.scheme() != "https" || !self.tls.enabled {
                    return Err(ConfigError::Invalid(
                        "standalone_tls requires production_mode, HTTPS URL and TLS enabled".into(),
                    ));
                }
                match self.tls.certificate_source {
                    CertificateSource::Files => validate_tls_files(&self.tls)?,
                    CertificateSource::LetsEncrypt => {
                        validate_letsencrypt(&url, &self.storage, &self.tls)?
                    }
                }
                if self.tls.reload_on_cert_change
                    && self.tls.certificate_source != CertificateSource::Files
                {
                    return Err(ConfigError::Invalid(
                        "reload_on_cert_change is valid only for certificate_source=\"files\""
                            .into(),
                    ));
                }
                if self.reverse_proxy.enabled {
                    return Err(ConfigError::Invalid(
                        "standalone_tls cannot enable reverse proxy trust".into(),
                    ));
                }
            }
        }
        if self.tls.certificate_source == CertificateSource::LetsEncrypt
            && !matches!(self.server.mode, ServerMode::StandaloneTls)
        {
            return Err(ConfigError::Invalid(
                "letsencrypt certificate_source is valid only in standalone_tls mode".into(),
            ));
        }
        if self.server.production_mode && !self.security.secure_cookie {
            return Err(ConfigError::Invalid(
                "secure_cookie is mandatory in production".into(),
            ));
        }
        if self.tls.hsts_enabled && matches!(self.server.mode, ServerMode::Development) {
            return Err(ConfigError::Invalid(
                "HSTS is invalid in development mode".into(),
            ));
        }
        if self.tls.hsts_enabled
            && self.tls.certificate_source == CertificateSource::LetsEncrypt
            && self.tls.letsencrypt_staging
        {
            return Err(ConfigError::Invalid(
                "HSTS must be disabled while letsencrypt_staging is true".into(),
            ));
        }
        if self.tls.reload_on_cert_change && !matches!(self.server.mode, ServerMode::StandaloneTls)
        {
            return Err(ConfigError::Invalid(
                "reload_on_cert_change is valid only in standalone_tls mode".into(),
            ));
        }
        if self.storage.max_upload_size == 0 {
            return Err(ConfigError::Invalid(
                "max_upload_size must be positive".into(),
            ));
        }
        if self.storage.max_upload_size > MAX_UPLOAD_SIZE {
            return Err(ConfigError::Invalid(format!(
                "max_upload_size must not exceed {MAX_UPLOAD_SIZE} bytes"
            )));
        }
        if self.storage.max_search_entries == 0
            || self.storage.max_search_results == 0
            || self.storage.max_preview_size == 0
            || self.storage.max_media_preview_size == 0
        {
            return Err(ConfigError::Invalid(
                "storage limits must be positive".into(),
            ));
        }
        if self.storage.max_preview_size > MAX_TEXT_PREVIEW_SIZE {
            return Err(ConfigError::Invalid(format!(
                "max_preview_size must not exceed {MAX_TEXT_PREVIEW_SIZE} bytes"
            )));
        }
        validate_mount_policy(&self.storage, self.server.production_mode)?;
        if self.storage.preview_extensions.is_empty() {
            return Err(ConfigError::Invalid(
                "preview_extensions must not be empty".into(),
            ));
        }
        validate_extensions("preview_extensions", &self.storage.preview_extensions)?;
        validate_extensions(
            "image_preview_extensions",
            &self.storage.image_preview_extensions,
        )?;
        if self
            .storage
            .image_preview_extensions
            .iter()
            .any(|extension| {
                matches!(
                    extension
                        .trim_start_matches('.')
                        .to_ascii_lowercase()
                        .as_str(),
                    "svg" | "html" | "htm" | "xml" | "xhtml"
                )
            })
        {
            return Err(ConfigError::Invalid(
                "image_preview_extensions must not include active content types".into(),
            ));
        }
        if !(1..=MAX_SESSION_HOURS).contains(&self.security.session_hours) {
            return Err(ConfigError::Invalid(format!(
                "session_hours must be between 1 and {MAX_SESSION_HOURS}"
            )));
        }
        if !(1..=MAX_AUTH_ATTEMPTS).contains(&self.security.login_attempts) {
            return Err(ConfigError::Invalid(format!(
                "login_attempts must be between 1 and {MAX_AUTH_ATTEMPTS}"
            )));
        }
        if !(1..=MAX_LOGIN_WINDOW_SECONDS).contains(&self.security.login_window_seconds) {
            return Err(ConfigError::Invalid(format!(
                "login_window_seconds must be between 1 and {MAX_LOGIN_WINDOW_SECONDS}"
            )));
        }
        if self.security.share_password_min_length < 8
            || self.security.share_password_max_length < self.security.share_password_min_length
            || self.security.share_password_max_length > MAX_SHARE_PASSWORD_LENGTH
            || !(1..=MAX_SHARE_UNLOCK_MINUTES).contains(&self.security.share_unlock_minutes)
            || !(1..=MAX_AUTH_ATTEMPTS).contains(&self.security.share_password_attempts)
        {
            return Err(ConfigError::Invalid("invalid share password policy".into()));
        }
        Ok(())
    }
}

fn validate_mount_policy(storage: &Storage, production_mode: bool) -> Result<(), ConfigError> {
    if production_mode && !storage.require_mount {
        return Err(ConfigError::Invalid(
            "production_mode=true requires require_mount=true and an explicit fail-closed mount identity"
                .into(),
        ));
    }
    if storage.external_writers && !storage.require_mount {
        return Err(ConfigError::Invalid(
            "external_writers=true requires require_mount=true and an explicit mount identity"
                .into(),
        ));
    }
    if !storage.require_mount {
        let canonical_lock_domain = storage
            .root_mount_path
            .join(DEFAULT_INTERNAL_DIRECTORY_NAME);
        if storage
            .internal_directory
            .as_ref()
            .is_some_and(|internal| internal != &canonical_lock_domain)
        {
            return Err(ConfigError::Invalid(format!(
                "internal_directory must be omitted or use the canonical development lock domain {}",
                canonical_lock_domain.display()
            )));
        }
    }
    if let Some(internal) = &storage.internal_directory {
        if storage.require_mount && !internal.is_absolute() {
            return Err(ConfigError::Invalid(
                "require_mount=true requires an absolute internal_directory".into(),
            ));
        }
        if storage.require_mount
            && (internal.starts_with(&storage.root_mount_path)
                || storage.root_mount_path.starts_with(internal))
        {
            return Err(ConfigError::Invalid(
                "internal_directory must be a sibling outside the user-visible root_mount_path"
                    .into(),
            ));
        }
    }
    if !storage.require_mount {
        if storage.expected_filesystem_type.is_some() || storage.expected_mount_source.is_some() {
            return Err(ConfigError::Invalid(
                "expected_filesystem_type and expected_mount_source require require_mount=true"
                    .into(),
            ));
        }
        return Ok(());
    }

    if !storage.root_mount_path.is_absolute() || !storage.data_directory.is_absolute() {
        return Err(ConfigError::Invalid(
            "require_mount=true requires absolute root_mount_path and data_directory paths".into(),
        ));
    }
    let internal_directory = storage.internal_directory.as_deref().ok_or_else(|| {
        ConfigError::Invalid(
            "require_mount=true requires a pre-provisioned internal_directory outside root_mount_path"
                .into(),
        )
    })?;
    let canonical_lock_domain = storage
        .root_mount_path
        .parent()
        .map(|parent| parent.join(DEFAULT_INTERNAL_DIRECTORY_NAME))
        .ok_or_else(|| {
            ConfigError::Invalid(
                "root_mount_path needs a parent directory for the private lock domain".into(),
            )
        })?;
    if internal_directory != canonical_lock_domain {
        return Err(ConfigError::Invalid(format!(
            "internal_directory must be the canonical private sibling {} so one storage root cannot use multiple lock domains",
            canonical_lock_domain.display()
        )));
    }
    for (name, path) in [
        ("root_mount_path", storage.root_mount_path.as_path()),
        ("data_directory", storage.data_directory.as_path()),
        ("internal_directory", internal_directory),
    ] {
        if path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(ConfigError::Invalid(format!(
                "{name} must not contain '.' or '..' components when require_mount=true"
            )));
        }
    }
    if storage.data_directory.starts_with(&storage.root_mount_path) {
        return Err(ConfigError::Invalid(
            "data_directory must not be inside root_mount_path when require_mount=true".into(),
        ));
    }

    let filesystem_type = storage.expected_filesystem_type.as_deref().ok_or_else(|| {
        ConfigError::Invalid("require_mount=true requires expected_filesystem_type".into())
    })?;
    if filesystem_type.is_empty()
        || !filesystem_type
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ConfigError::Invalid(
            "expected_filesystem_type must be a non-empty Linux filesystem type".into(),
        ));
    }
    if storage.external_writers && !matches!(filesystem_type, "cifs" | "smb3") {
        return Err(ConfigError::Invalid(
            "external_writers=true is supported only with the audited cifs/smb3 mount policy"
                .into(),
        ));
    }

    let mount_source = storage.expected_mount_source.as_deref().ok_or_else(|| {
        ConfigError::Invalid("require_mount=true requires expected_mount_source".into())
    })?;
    if mount_source.is_empty() || mount_source.chars().any(char::is_control) {
        return Err(ConfigError::Invalid(
            "expected_mount_source must be non-empty and contain no control characters".into(),
        ));
    }

    Ok(())
}

fn curl_connect_host(host: &str) -> String {
    let bare_host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if matches!(bare_host.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
        format!("[{bare_host}]")
    } else {
        bare_host.to_string()
    }
}

fn validate_tls_files(tls: &Tls) -> Result<(), ConfigError> {
    for p in [&tls.cert_file, &tls.key_file] {
        if !p.is_file() {
            return Err(ConfigError::Invalid(format!(
                "TLS file does not exist: {}",
                p.display()
            )));
        }
    }
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(&tls.key_file)?.permissions().mode() & 0o7777;
    if !matches!(mode, 0o400 | 0o440 | 0o600 | 0o640) {
        return Err(ConfigError::Invalid(
            "TLS private key mode must be 0400, 0440, 0600, or 0640".into(),
        ));
    }
    Ok(())
}

pub fn letsencrypt_cache_dir(storage: &Storage, tls: &Tls) -> Result<PathBuf, ConfigError> {
    validate_acme_cache_path(&storage.data_directory, &tls.letsencrypt_cache_dir)?;
    if tls.letsencrypt_cache_dir.is_absolute() {
        Ok(tls.letsencrypt_cache_dir.clone())
    } else {
        Ok(storage.data_directory.join(&tls.letsencrypt_cache_dir))
    }
}

fn validate_letsencrypt(url: &Url, storage: &Storage, tls: &Tls) -> Result<(), ConfigError> {
    let host = url.host_str().ok_or_else(|| {
        ConfigError::Invalid("letsencrypt requires a public_base_url host".into())
    })?;
    if host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok()
        || !host.contains('.')
        || host
            .split('.')
            .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(ConfigError::Invalid(
            "letsencrypt requires a DNS domain in public_base_url".into(),
        ));
    }
    if !tls.letsencrypt_contact_email.contains('@')
        || tls.letsencrypt_contact_email.contains('\n')
        || tls.letsencrypt_contact_email.contains('\r')
        || tls.letsencrypt_contact_email.starts_with("mailto:")
    {
        return Err(ConfigError::Invalid(
            "letsencrypt_contact_email must be a plain email address".into(),
        ));
    }
    letsencrypt_cache_dir(storage, tls).map(|_| ())
}

fn validate_acme_cache_path(data_directory: &Path, cache_dir: &Path) -> Result<(), ConfigError> {
    if cache_dir.as_os_str().is_empty() {
        return Err(ConfigError::Invalid(
            "letsencrypt_cache_dir must not be empty".into(),
        ));
    }
    if cache_dir
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(ConfigError::Invalid(
            "letsencrypt_cache_dir must stay inside data_directory".into(),
        ));
    }
    if cache_dir.is_absolute() {
        if !data_directory.is_absolute() || !cache_dir.starts_with(data_directory) {
            return Err(ConfigError::Invalid(
                "absolute letsencrypt_cache_dir must be inside absolute data_directory".into(),
            ));
        }
    } else if cache_dir
        .components()
        .any(|component| matches!(component, Component::RootDir))
    {
        return Err(ConfigError::Invalid(
            "relative letsencrypt_cache_dir must not contain a root component".into(),
        ));
    }
    Ok(())
}

fn validate_extensions(name: &str, values: &[String]) -> Result<(), ConfigError> {
    if values.iter().any(|extension| {
        extension.is_empty()
            || extension.contains('/')
            || extension.contains('\\')
            || extension.contains('\0')
            || extension.chars().any(char::is_control)
    }) {
        return Err(ConfigError::Invalid(format!(
            "{name} must contain safe extensions"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_toml_examples_deserialize_with_current_parser() {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("config");
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
                continue;
            }
            let serialized = std::fs::read_to_string(&path).unwrap();
            toml::from_str::<Config>(&serialized)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        }
    }
    fn base() -> Config {
        Config {
            server: Server {
                mode: ServerMode::Development,
                listen_address: "127.0.0.1:8080".into(),
                public_base_url: "http://localhost:8080".into(),
                production_mode: false,
            },
            storage: Storage {
                root_mount_path: ".".into(),
                data_directory: ".".into(),
                internal_directory: None,
                require_mount: false,
                external_writers: false,
                expected_filesystem_type: None,
                expected_mount_source: None,
                max_upload_size: 10,
                max_zip_size: 1024,
                max_zip_files: 10,
                max_search_entries: 100,
                max_search_results: 10,
                max_preview_size: 1024,
                preview_extensions: vec!["txt".into()],
                image_preview_extensions: vec!["jpg".into(), "png".into()],
                pdf_preview_enabled: true,
                max_media_preview_size: 1024,
                blocked_extensions: vec![],
            },
            reverse_proxy: ReverseProxy::default(),
            tls: Tls::default(),
            security: Security {
                secure_cookie: false,
                ..Default::default()
            },
            logging: Logging::default(),
        }
    }

    fn configure_local_mount_policy(config: &mut Config) {
        config.storage.root_mount_path = "/srv/vaultlink/shared".into();
        config.storage.data_directory = "/var/lib/vaultlink".into();
        config.storage.internal_directory = Some("/srv/vaultlink/.vaultlink-internal".into());
        config.storage.require_mount = true;
        config.storage.external_writers = false;
        config.storage.expected_filesystem_type = Some("ext4".into());
        config.storage.expected_mount_source = Some("/dev/mapper/vaultlink".into());
    }
    #[test]
    fn development_requires_loopback() {
        let mut c = base();
        c.server.listen_address = "0.0.0.0:8080".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn zero_disables_zip_limits() {
        let mut c = base();
        c.storage.max_zip_size = 0;
        c.storage.max_zip_files = 0;
        c.validate().unwrap();
    }

    #[test]
    fn text_preview_extensions_must_not_be_empty() {
        let mut config = base();
        config.storage.preview_extensions.clear();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("preview_extensions must not be empty"));
    }

    #[test]
    fn legacy_storage_configuration_defaults_to_no_mount_requirement() {
        let serialized = toml::to_string(&base()).unwrap();
        let legacy = serialized
            .lines()
            .filter(|line| {
                !line.starts_with("require_mount =")
                    && !line.starts_with("external_writers =")
                    && !line.starts_with("expected_filesystem_type =")
                    && !line.starts_with("expected_mount_source =")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let parsed: Config = toml::from_str(&legacy).unwrap();
        assert!(!parsed.storage.require_mount);
        assert!(!parsed.storage.external_writers);
        assert_eq!(parsed.storage.expected_filesystem_type, None);
        assert_eq!(parsed.storage.expected_mount_source, None);
        parsed.validate().unwrap();
    }

    #[test]
    fn external_mount_policy_requires_complete_explicit_identity() {
        let mut config = base();
        config.storage.root_mount_path = "/mnt/vaultlink".into();
        config.storage.data_directory = "/var/lib/vaultlink".into();
        config.storage.require_mount = true;
        assert!(config.validate().is_err());

        config.storage.expected_filesystem_type = Some("cifs".into());
        assert!(config.validate().is_err());

        config.storage.expected_mount_source = Some("//nas.example/vaultlink".into());
        config.storage.internal_directory = Some("/mnt/.vaultlink-internal".into());
        config.storage.external_writers = true;
        config.validate().unwrap();
    }

    #[test]
    fn storage_root_has_only_one_configurable_lock_domain() {
        let mut development = base();
        development.storage.root_mount_path = "/srv/vaultlink-dev".into();
        development.storage.data_directory = "/var/lib/vaultlink-dev".into();
        development.storage.internal_directory =
            Some("/srv/vaultlink-dev/.vaultlink-internal".into());
        development.validate().unwrap();
        development.storage.internal_directory = Some("/srv/another-private-dir".into());
        assert!(development
            .validate()
            .unwrap_err()
            .to_string()
            .contains("canonical development lock domain"));

        let mut production = base();
        configure_local_mount_policy(&mut production);
        production.validate().unwrap();
        production.storage.internal_directory =
            Some("/srv/vaultlink/.vaultlink-internal-alternate".into());
        assert!(production
            .validate()
            .unwrap_err()
            .to_string()
            .contains("one storage root cannot use multiple lock domains"));
    }

    #[test]
    fn production_requires_an_explicit_fail_closed_mount_identity() {
        let mut config = base();
        config.server.mode = ServerMode::ReverseProxy;
        config.server.production_mode = true;
        config.server.public_base_url = "https://vaultlink.example".into();
        config.security.secure_cookie = true;
        config.reverse_proxy.enabled = true;
        config.reverse_proxy.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("production_mode=true requires require_mount=true"));
        configure_local_mount_policy(&mut config);
        config.validate().unwrap();
    }

    #[test]
    fn external_mount_policy_rejects_ignored_or_overlapping_settings() {
        let mut config = base();
        config.storage.external_writers = true;
        assert!(config.validate().is_err());
        config.storage.external_writers = false;
        config.storage.expected_filesystem_type = Some("cifs".into());
        assert!(config.validate().is_err());

        config.storage.require_mount = true;
        config.storage.root_mount_path = "/mnt/vaultlink".into();
        config.storage.data_directory = "/mnt/vaultlink/.state".into();
        config.storage.expected_mount_source = Some("//nas.example/vaultlink".into());
        assert!(config.validate().is_err());
    }

    #[test]
    fn required_mount_paths_reject_parent_directory_aliases() {
        let mut config = base();
        configure_local_mount_policy(&mut config);
        config.storage.data_directory = "/var/lib/vaultlink/../state".into();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("must not contain '.' or '..' components"));
    }

    #[test]
    fn public_base_url_rejects_ambiguous_suffixes_and_credentials() {
        let mut c = base();
        for value in [
            "http://localhost:8080/",
            "http://localhost:8080/base/path",
            "http://localhost:8080/.",
            "http://localhost:8080?next=/admin",
            "http://localhost:8080/#section",
            "http://user:secret@localhost:8080",
            "http:/missing-host",
            "mailto:admin@example.test",
        ] {
            c.server.public_base_url = value.into();
            assert!(c.validate().is_err(), "accepted {value}");
        }
    }

    #[test]
    fn security_limits_are_positive_and_bounded() {
        let mut c = base();
        c.validate().unwrap();

        for invalid in [0, MAX_SESSION_HOURS + 1] {
            c.security.session_hours = invalid;
            assert!(c.validate().is_err(), "accepted session_hours={invalid}");
        }
        c.security.session_hours = default_session_hours();

        for invalid in [0, MAX_AUTH_ATTEMPTS + 1] {
            c.security.login_attempts = invalid;
            assert!(c.validate().is_err(), "accepted login_attempts={invalid}");
        }
        c.security.login_attempts = default_attempts();

        for invalid in [0, MAX_LOGIN_WINDOW_SECONDS + 1] {
            c.security.login_window_seconds = invalid;
            assert!(
                c.validate().is_err(),
                "accepted login_window_seconds={invalid}"
            );
        }
        c.security.login_window_seconds = default_window();

        for invalid in [0, MAX_SHARE_UNLOCK_MINUTES + 1] {
            c.security.share_unlock_minutes = invalid;
            assert!(
                c.validate().is_err(),
                "accepted share_unlock_minutes={invalid}"
            );
        }
        c.security.share_unlock_minutes = default_share_unlock_minutes();

        c.security.share_password_max_length = MAX_SHARE_PASSWORD_LENGTH + 1;
        assert!(c.validate().is_err(), "accepted excessive password length");
        c.security.share_password_max_length = default_share_password_max();

        c.storage.max_preview_size = MAX_TEXT_PREVIEW_SIZE + 1;
        assert!(
            c.validate().is_err(),
            "accepted excessive text preview size"
        );
        c.storage.max_preview_size = MAX_TEXT_PREVIEW_SIZE;

        for invalid in [0, MAX_AUTH_ATTEMPTS + 1] {
            c.security.share_password_attempts = invalid;
            assert!(
                c.validate().is_err(),
                "accepted share_password_attempts={invalid}"
            );
        }
    }

    #[test]
    fn password_max_length_uses_only_the_canonical_key() {
        let serialized = toml::to_string(&base()).unwrap();
        assert!(serialized.contains("share_password_max_length = 256"));
        assert!(!serialized.contains("share_password_max_bytes"));

        let legacy = serialized.replace(
            "share_password_max_length = 256",
            "share_password_max_bytes = 256",
        );
        let error = toml::from_str::<Config>(&legacy).unwrap_err().to_string();
        assert!(error.contains("unknown field `share_password_max_bytes`"));
    }

    #[test]
    fn audit_client_ip_logging_is_opt_in_and_round_trips() {
        let serialized = toml::to_string(&base()).unwrap();
        let without_setting = serialized
            .lines()
            .filter(|line| !line.starts_with("audit_client_ip_enabled ="))
            .collect::<Vec<_>>()
            .join("\n");
        let defaulted: Config = toml::from_str(&without_setting).unwrap();
        assert!(!defaulted.security.audit_client_ip_enabled);
        defaulted.validate().unwrap();

        let mut enabled = base();
        enabled.security.audit_client_ip_enabled = true;
        enabled.validate().unwrap();
        let round_trip: Config = toml::from_str(&toml::to_string(&enabled).unwrap()).unwrap();
        assert!(round_trip.security.audit_client_ip_enabled);
        round_trip.validate().unwrap();
    }

    #[test]
    fn production_requires_secure_cookie() {
        let mut c = base();
        c.server.mode = ServerMode::ReverseProxy;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.public_base_url = "https://example.test".into();
        c.reverse_proxy.enabled = true;
        c.reverse_proxy.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];
        assert!(c.validate().is_err());
    }

    #[test]
    fn remote_reverse_proxy_requires_explicit_opt_in() {
        let mut c = base();
        c.server.mode = ServerMode::ReverseProxy;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.listen_address = "0.0.0.0:8080".into();
        c.server.public_base_url = "https://vaultlink.example".into();
        c.security.secure_cookie = true;
        c.reverse_proxy.enabled = true;
        c.reverse_proxy.trusted_proxies = vec!["192.0.2.10".parse().unwrap()];
        assert!(c.validate().is_err());
        c.reverse_proxy.allow_non_loopback = true;
        let error = c.validate().unwrap_err().to_string();
        assert!(error.contains("local readiness peer 127.0.0.1"));
        c.reverse_proxy
            .trusted_proxies
            .push("127.0.0.1".parse().unwrap());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn reverse_proxy_readiness_accepts_mapped_ipv4_allowlist_entry() {
        let mut c = base();
        c.server.mode = ServerMode::ReverseProxy;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.listen_address = "0.0.0.0:8080".into();
        c.server.public_base_url = "https://vaultlink.example".into();
        c.security.secure_cookie = true;
        c.reverse_proxy.enabled = true;
        c.reverse_proxy.allow_non_loopback = true;
        c.reverse_proxy.trusted_proxies = vec![
            "192.0.2.10".parse().unwrap(),
            "::ffff:127.0.0.1".parse().unwrap(),
        ];
        c.validate().unwrap();
    }
    #[test]
    fn hsts_rejected_in_development() {
        let mut c = base();
        c.tls.hsts_enabled = true;
        assert!(c.validate().is_err());
    }

    #[test]
    fn upload_limit_must_fit_inside_the_multipart_ceiling() {
        let mut c = base();
        c.storage.max_upload_size = MAX_UPLOAD_SIZE;
        assert!(c.validate().is_ok());
        c.storage.max_upload_size = MAX_UPLOAD_SIZE + 1;
        assert!(c.validate().is_err());
    }

    #[test]
    fn standalone_tls_rejects_missing_files() {
        let mut c = base();
        c.server.mode = ServerMode::StandaloneTls;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.public_base_url = "https://example.test".into();
        c.security.secure_cookie = true;
        c.tls.enabled = true;
        c.tls.cert_file = "missing-cert.pem".into();
        c.tls.key_file = "missing-key.pem".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn standalone_tls_accepts_only_documented_private_key_modes() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("certificate.pem");
        let private_key = directory.path().join("private-key.pem");
        std::fs::write(&certificate, "certificate").unwrap();
        std::fs::write(&private_key, "private key").unwrap();
        let tls = Tls {
            cert_file: certificate,
            key_file: private_key.clone(),
            ..Tls::default()
        };

        for mode in [0o400, 0o440, 0o600, 0o640] {
            std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(validate_tls_files(&tls).is_ok(), "rejected mode {mode:04o}");
        }
        for mode in [0o660, 0o620, 0o644, 0o700, 0o4640, 0o2640, 0o1640] {
            std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                validate_tls_files(&tls).is_err(),
                "accepted mode {mode:04o}"
            );
        }
    }

    #[test]
    fn standalone_letsencrypt_validates_domain_contact_and_mode() {
        let mut c = base();
        c.server.mode = ServerMode::StandaloneTls;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.listen_address = "0.0.0.0:443".into();
        c.server.public_base_url = "https://files.example.test".into();
        c.security.secure_cookie = true;
        c.tls.enabled = true;
        c.tls.certificate_source = CertificateSource::LetsEncrypt;
        c.tls.letsencrypt_contact_email = "admin@example.test".into();
        c.tls.letsencrypt_cache_dir = "acme".into();
        assert!(c.validate().is_ok());

        c.server.mode = ServerMode::ReverseProxy;
        c.reverse_proxy.enabled = true;
        c.reverse_proxy.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];
        assert!(c.validate().is_err());
    }

    #[test]
    fn letsencrypt_staging_rejects_hsts() {
        let mut c = base();
        c.server.mode = ServerMode::StandaloneTls;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.listen_address = "0.0.0.0:443".into();
        c.server.public_base_url = "https://files.example.test".into();
        c.security.secure_cookie = true;
        c.tls.enabled = true;
        c.tls.certificate_source = CertificateSource::LetsEncrypt;
        c.tls.letsencrypt_contact_email = "admin@example.test".into();
        c.tls.letsencrypt_cache_dir = "acme".into();
        c.tls.letsencrypt_staging = true;
        c.tls.hsts_enabled = true;
        assert!(c.validate().is_err());

        c.tls.hsts_enabled = false;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn certificate_source_accepts_documented_letsencrypt_value() {
        #[derive(Deserialize, Serialize)]
        struct Wrapper {
            certificate_source: CertificateSource,
        }

        let documented: Wrapper = toml::from_str("certificate_source = \"letsencrypt\"").unwrap();
        assert_eq!(
            documented.certificate_source,
            CertificateSource::LetsEncrypt
        );

        let serialized = toml::to_string(&documented).unwrap();
        assert!(serialized.contains("certificate_source = \"letsencrypt\""));
    }

    #[test]
    fn letsencrypt_rejects_localhost_and_unsafe_cache() {
        let mut c = base();
        c.server.mode = ServerMode::StandaloneTls;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.listen_address = "0.0.0.0:443".into();
        c.server.public_base_url = "https://localhost".into();
        c.security.secure_cookie = true;
        c.tls.enabled = true;
        c.tls.certificate_source = CertificateSource::LetsEncrypt;
        c.tls.letsencrypt_contact_email = "admin@example.test".into();
        c.tls.letsencrypt_cache_dir = "acme".into();
        assert!(c.validate().is_err());
        c.server.public_base_url = "https://files.example.test".into();
        c.tls.letsencrypt_cache_dir = "../acme".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn readiness_target_uses_loopback_for_wildcard_reverse_proxy_bind() {
        let mut c = base();
        c.server.mode = ServerMode::ReverseProxy;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.listen_address = "0.0.0.0:8080".into();
        c.server.public_base_url = "https://vaultlink.example".into();
        c.security.secure_cookie = true;
        c.reverse_proxy.enabled = true;
        c.reverse_proxy.allow_non_loopback = true;
        c.reverse_proxy.trusted_proxies =
            vec!["192.0.2.10".parse().unwrap(), "127.0.0.1".parse().unwrap()];
        assert!(c.validate().is_ok());

        assert_eq!(
            c.local_readiness_target().unwrap(),
            LocalReadinessTarget {
                url: "http://127.0.0.1:8080/api/v1/health".into(),
                connect_to: None,
                insecure: false,
            }
        );
    }

    #[test]
    fn standalone_readiness_target_preserves_hostname() {
        let mut c = base();
        c.server.mode = ServerMode::StandaloneTls;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.listen_address = "0.0.0.0:443".into();
        c.server.public_base_url = "https://files.example.test".into();
        c.security.secure_cookie = true;
        c.tls.enabled = true;
        c.tls.certificate_source = CertificateSource::LetsEncrypt;
        c.tls.letsencrypt_contact_email = "admin@example.test".into();
        c.tls.letsencrypt_cache_dir = "acme".into();
        assert!(c.validate().is_ok());

        assert_eq!(
            c.local_readiness_target().unwrap(),
            LocalReadinessTarget {
                url: "https://files.example.test/api/v1/health".into(),
                connect_to: Some("files.example.test:443:127.0.0.1:443".into()),
                insecure: true,
            }
        );
    }

    #[test]
    fn standalone_readiness_target_formats_ipv6_loopback_for_curl() {
        let mut c = base();
        c.server.mode = ServerMode::StandaloneTls;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.listen_address = "[::]:8443".into();
        c.server.public_base_url = "https://files.example.test:8443".into();
        c.security.secure_cookie = true;
        c.tls.enabled = true;
        c.tls.certificate_source = CertificateSource::LetsEncrypt;
        c.tls.letsencrypt_contact_email = "admin@example.test".into();
        c.tls.letsencrypt_cache_dir = "acme".into();
        assert!(c.validate().is_ok());

        assert_eq!(
            c.local_readiness_target().unwrap(),
            LocalReadinessTarget {
                url: "https://files.example.test:8443/api/v1/health".into(),
                connect_to: Some("files.example.test:8443:[::1]:8443".into()),
                insecure: true,
            }
        );
        assert_eq!(curl_connect_host("::1"), "[::1]");
        assert_eq!(curl_connect_host("[::1]"), "[::1]");
    }
}
