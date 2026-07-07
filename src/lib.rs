pub mod auth;
pub mod config;
pub mod db;
pub mod path_security;
pub mod proxy;
pub mod range;
pub mod secure_fs;
pub mod web;

use std::sync::Arc;

use config::Config;
use db::Database;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Database,
    pub secure_root: secure_fs::SecureRoot,
    pub limiter: auth::LoginLimiter,
    pub share_limiter: auth::LoginLimiter,
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        config.validate()?;
        let secure_root = secure_fs::SecureRoot::open(&config.storage.root_mount_path)
            .map_err(|error| format!("cannot initialize secure storage access (openat2 is required on Linux): {error}"))?;
        std::fs::create_dir_all(&config.storage.data_directory)?;
        let db = Database::open(config.storage.data_directory.join("data.sqlite"))?;
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
        })
    }
}
