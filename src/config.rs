use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use thiserror::Error;
use url::Url;

#[derive(Clone, Debug, Deserialize)]
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

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ServerMode {
    Development,
    ReverseProxy,
    StandaloneTls,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Server {
    pub mode: ServerMode,
    pub listen_address: String,
    pub public_base_url: String,
    #[serde(default)]
    pub production_mode: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Storage {
    pub root_mount_path: PathBuf,
    pub data_directory: PathBuf,
    #[serde(default = "default_upload_size")]
    pub max_upload_size: u64,
    #[serde(default)]
    pub blocked_extensions: Vec<String>,
}

fn default_upload_size() -> u64 {
    100 * 1024 * 1024
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ReverseProxy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub trusted_proxies: Vec<IpAddr>,
    #[serde(default)]
    pub trust_x_forwarded_headers: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Tls {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert_file: PathBuf,
    #[serde(default)]
    pub key_file: PathBuf,
    #[serde(default)]
    pub hsts_enabled: bool,
    #[serde(default)]
    pub redirect_http_to_https: bool,
    #[serde(default)]
    pub reload_on_cert_change: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Security {
    #[serde(default = "default_session_hours")]
    pub session_hours: i64,
    #[serde(default = "default_attempts")]
    pub login_attempts: usize,
    #[serde(default = "default_window")]
    pub login_window_seconds: u64,
    #[serde(default = "yes")]
    pub secure_cookie: bool,
}
impl Default for Security {
    fn default() -> Self {
        Self {
            session_hours: default_session_hours(),
            login_attempts: default_attempts(),
            login_window_seconds: default_window(),
            secure_cookie: true,
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

#[derive(Clone, Debug, Deserialize)]
pub struct Logging {
    #[serde(default = "default_level")]
    pub level: String,
    pub audit_log_path: Option<PathBuf>,
}
impl Default for Logging {
    fn default() -> Self {
        Self {
            level: default_level(),
            audit_log_path: None,
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
                if !listen.ip().is_loopback() {
                    return Err(ConfigError::Invalid(
                        "reverse_proxy mode must bind to a loopback address".into(),
                    ));
                }
                if self.tls.enabled {
                    return Err(ConfigError::Invalid(
                        "reverse_proxy mode must not enable application TLS".into(),
                    ));
                }
            }
            ServerMode::StandaloneTls => {
                if !self.server.production_mode || url.scheme() != "https" || !self.tls.enabled {
                    return Err(ConfigError::Invalid(
                        "standalone_tls requires production_mode, HTTPS URL and TLS enabled".into(),
                    ));
                }
                for p in [&self.tls.cert_file, &self.tls.key_file] {
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
                    let mode = fs::metadata(&self.tls.key_file)?.permissions().mode();
                    if mode & 0o007 != 0 {
                        return Err(ConfigError::Invalid(
                            "TLS private key must not be accessible to other users".into(),
                        ));
                    }
                }
                if self.reverse_proxy.enabled {
                    return Err(ConfigError::Invalid(
                        "standalone_tls cannot enable reverse proxy trust".into(),
                    ));
                }
            }
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
        if self.storage.max_upload_size == 0 {
            return Err(ConfigError::Invalid(
                "max_upload_size must be positive".into(),
            ));
        }
        Ok(())
    }
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
}
