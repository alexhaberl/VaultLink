use std::{
    fs,
    net::IpAddr,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

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
    100 * 1024 * 1024
}
fn default_zip_size() -> u64 {
    1024 * 1024 * 1024
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
    1024 * 1024
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
    100 * 1024 * 1024
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
    pub share_password_max_bytes: usize,
    #[serde(default = "default_share_unlock_minutes")]
    pub share_unlock_minutes: i64,
    #[serde(default = "default_attempts")]
    pub share_password_attempts: usize,
}
impl Default for Security {
    fn default() -> Self {
        Self {
            session_hours: default_session_hours(),
            login_attempts: default_attempts(),
            login_window_seconds: default_window(),
            secure_cookie: true,
            share_password_min_length: default_share_password_min(),
            share_password_max_bytes: default_share_password_max(),
            share_unlock_minutes: default_share_unlock_minutes(),
            share_password_attempts: default_attempts(),
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

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let value = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&value)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let url = Url::parse(&self.server.public_base_url)
            .map_err(|e| ConfigError::Invalid(format!("public_base_url: {e}")))?;
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
                        .any(|proxy| !proxy.is_loopback())
                {
                    return Err(ConfigError::Invalid(
                        "non-loopback binding requires a non-loopback trusted proxy".into(),
                    ));
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
        if self.storage.max_zip_size == 0
            || self.storage.max_zip_files == 0
            || self.storage.max_search_entries == 0
            || self.storage.max_search_results == 0
            || self.storage.max_preview_size == 0
            || self.storage.max_media_preview_size == 0
        {
            return Err(ConfigError::Invalid(
                "storage limits must be positive".into(),
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
        if self.security.share_password_min_length < 8
            || self.security.share_password_max_bytes < self.security.share_password_min_length
            || self.security.share_unlock_minutes <= 0
            || self.security.share_password_attempts == 0
        {
            return Err(ConfigError::Invalid("invalid share password policy".into()));
        }
        Ok(())
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&tls.key_file)?.permissions().mode();
        if mode & 0o007 != 0 {
            return Err(ConfigError::Invalid(
                "TLS private key must not be accessible to other users".into(),
            ));
        }
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
    #[test]
    fn development_requires_loopback() {
        let mut c = base();
        c.server.listen_address = "0.0.0.0:8080".into();
        assert!(c.validate().is_err());
    }
    #[test]
    fn production_requires_secure_cookie() {
        let mut c = base();
        c.server.mode = ServerMode::ReverseProxy;
        c.server.production_mode = true;
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
        c.server.listen_address = "0.0.0.0:8080".into();
        c.server.public_base_url = "https://vaultlink.example".into();
        c.security.secure_cookie = true;
        c.reverse_proxy.enabled = true;
        c.reverse_proxy.trusted_proxies = vec!["192.0.2.10".parse().unwrap()];
        assert!(c.validate().is_err());
        c.reverse_proxy.allow_non_loopback = true;
        assert!(c.validate().is_ok());
    }
    #[test]
    fn hsts_rejected_in_development() {
        let mut c = base();
        c.tls.hsts_enabled = true;
        assert!(c.validate().is_err());
    }

    #[test]
    fn standalone_tls_rejects_missing_files() {
        let mut c = base();
        c.server.mode = ServerMode::StandaloneTls;
        c.server.production_mode = true;
        c.server.public_base_url = "https://example.test".into();
        c.security.secure_cookie = true;
        c.tls.enabled = true;
        c.tls.cert_file = "missing-cert.pem".into();
        c.tls.key_file = "missing-key.pem".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn standalone_letsencrypt_validates_domain_contact_and_mode() {
        let mut c = base();
        c.server.mode = ServerMode::StandaloneTls;
        c.server.production_mode = true;
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
    fn letsencrypt_rejects_localhost_and_unsafe_cache() {
        let mut c = base();
        c.server.mode = ServerMode::StandaloneTls;
        c.server.production_mode = true;
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
}
