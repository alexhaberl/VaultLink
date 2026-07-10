pub mod api;
pub mod auth;
pub mod config;
pub mod db;
pub mod file_ops;
pub mod http_auth;
pub mod multipart_guard;
pub mod path_security;
pub mod proxy;
pub mod range;
pub mod runtime;
pub mod secure_fs;
pub mod setup;
pub mod ui;
pub mod web;

use std::sync::{Arc, RwLock};

use config::Config;
use db::Database;
use runtime::RuntimeSettings;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Database,
    pub secure_root: secure_fs::SecureRoot,
    pub limiter: auth::LoginLimiter,
    pub share_limiter: auth::LoginLimiter,
    pub runtime: Arc<RwLock<RuntimeSettings>>,
    pub storage_mutation: Arc<tokio::sync::Mutex<()>>,
    pub storage_cleanup: Arc<tokio::sync::Mutex<()>>,
    #[cfg(test)]
    pub upload_directory_sync_failure: Arc<std::sync::Mutex<Option<std::io::ErrorKind>>>,
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        config.validate()?;
        let secure_root = secure_fs::SecureRoot::open(&config.storage.root_mount_path)
            .map_err(|error| format!("cannot initialize secure storage access (openat2 is required on Linux): {error}"))?;
        std::fs::create_dir_all(&config.storage.data_directory)?;
        let db = Database::open(config.storage.data_directory.join("data.sqlite"))?;
        let mut runtime = RuntimeSettings::from_config(&config);
        let persisted_runtime = db.runtime_settings()?;
        runtime
            .apply_many(
                persisted_runtime
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_str())),
            )
            .map_err(|error| format!("invalid persisted runtime settings: {error}"))?;
        runtime
            .validate_for_config(&config)
            .map_err(|error| format!("invalid persisted runtime settings: {error}"))?;
        Ok(Self {
            limiter: auth::LoginLimiter::new(
                config.security.login_attempts,
                std::time::Duration::from_secs(config.security.login_window_seconds),
            ),
            share_limiter: auth::LoginLimiter::new(
                config.security.share_password_attempts,
                std::time::Duration::from_secs(300),
            ),
            config: Arc::new(config),
            db,
            secure_root,
            runtime: Arc::new(RwLock::new(runtime)),
            storage_mutation: Arc::new(tokio::sync::Mutex::new(())),
            storage_cleanup: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(test)]
            upload_directory_sync_failure: Arc::new(std::sync::Mutex::new(None)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Logging, ReverseProxy, Security, Server, ServerMode, Storage, Tls};

    fn config(root: &std::path::Path, data: &std::path::Path) -> Config {
        Config {
            server: Server {
                mode: ServerMode::Development,
                listen_address: "127.0.0.1:8080".into(),
                public_base_url: "http://localhost:8080".into(),
                production_mode: false,
            },
            storage: Storage {
                root_mount_path: root.into(),
                data_directory: data.into(),
                max_upload_size: 1_000_000,
                max_zip_size: 1_000_000,
                max_zip_files: 100,
                max_search_entries: 1_000,
                max_search_results: 100,
                max_preview_size: 100_000,
                preview_extensions: vec!["txt".into()],
                image_preview_extensions: vec!["png".into()],
                pdf_preview_enabled: true,
                max_media_preview_size: 1_000_000,
                blocked_extensions: vec!["exe".into()],
            },
            reverse_proxy: ReverseProxy::default(),
            tls: Tls::default(),
            security: Security::default(),
            logging: Logging::default(),
        }
    }

    #[test]
    fn startup_applies_valid_runtime_snapshot_without_key_order_failures() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let config = config(root.path(), data.path());
        let database = Database::open(data.path().join("data.sqlite")).unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let mut runtime = RuntimeSettings::from_config(&config);
        runtime.share_password_min_length = 8;
        runtime.share_password_max_length = 8;
        runtime.validate().unwrap();
        database
            .replace_runtime_settings(&runtime.pairs(), 1)
            .unwrap();
        drop(database);

        let state = AppState::new(config).unwrap();
        let runtime = state.runtime.read().unwrap();
        assert_eq!(runtime.share_password_min_length, 8);
        assert_eq!(runtime.share_password_max_length, 8);
    }
}
