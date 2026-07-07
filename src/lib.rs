pub mod auth;
pub mod config;
pub mod db;
pub mod path_security;
pub mod proxy;
pub mod range;
pub mod runtime;
pub mod secure_fs;
pub mod setup;
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
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        config.validate()?;
        let secure_root = secure_fs::SecureRoot::open(&config.storage.root_mount_path)
            .map_err(|error| format!("cannot initialize secure storage access (openat2 is required on Linux): {error}"))?;
        std::fs::create_dir_all(&config.storage.data_directory)?;
        let db = Database::open(config.storage.data_directory.join("data.sqlite"))?;
        let mut runtime = RuntimeSettings::from_config(&config);
        for (key, value) in db.runtime_settings()? {
            runtime
                .apply(&key, &value)
                .map_err(|error| format!("invalid runtime setting {key}: {error}"))?;
        }
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
        })
    }
}
