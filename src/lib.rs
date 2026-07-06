pub mod auth;
pub mod config;
pub mod db;
pub mod path_security;
pub mod proxy;
pub mod web;

use std::sync::Arc;

use config::Config;
use db::Database;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Database,
    pub root: Arc<std::path::PathBuf>,
    pub limiter: auth::LoginLimiter,
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        config.validate()?;
        let root = std::fs::canonicalize(&config.storage.root_mount_path)?;
        if !root.is_dir() {
            return Err("root_mount_path is not a directory".into());
        }
        std::fs::create_dir_all(&config.storage.data_directory)?;
        let db = Database::open(config.storage.data_directory.join("data.sqlite"))?;
        Ok(Self {
            limiter: auth::LoginLimiter::new(
                config.security.login_attempts,
                std::time::Duration::from_secs(config.security.login_window_seconds),
            ),
            config: Arc::new(config),
            db,
            root: Arc::new(root),
        })
    }
}
