use std::{sync::Arc, time::Duration};

use crate::{
    auth::{AdminLoginLimiter, LoginLimiter},
    config::Config,
    db::Database,
};

pub(super) struct AppServices {
    config: Arc<Config>,
    database: Database,
    admin_login_limiter: AdminLoginLimiter,
    login_limiter: LoginLimiter,
    share_limiter: LoginLimiter,
    alias_limiter: LoginLimiter,
    public_transfer_limiter: LoginLimiter,
    preview_token_limiter: LoginLimiter,
    monitoring_limiter: LoginLimiter,
}

impl AppServices {
    pub(super) fn new(
        config: Config,
        database: Database,
        active_admin_usernames: Vec<String>,
    ) -> Self {
        Self {
            admin_login_limiter: AdminLoginLimiter::new(
                active_admin_usernames,
                config.security.login_attempts,
                config.security.account_login_attempts,
                Duration::from_secs(config.security.login_window_seconds),
            ),
            login_limiter: LoginLimiter::new(
                config.security.login_attempts,
                Duration::from_secs(config.security.login_window_seconds),
            ),
            share_limiter: LoginLimiter::new(
                config.security.share_password_attempts,
                Duration::from_secs(300),
            ),
            alias_limiter: LoginLimiter::new(120, Duration::from_secs(60)),
            public_transfer_limiter: LoginLimiter::new(120, Duration::from_secs(60)),
            preview_token_limiter: LoginLimiter::new(60, Duration::from_secs(60)),
            monitoring_limiter: LoginLimiter::new(120, Duration::from_secs(60)),
            config: Arc::new(config),
            database,
        }
    }

    pub(super) fn config(&self) -> &Config {
        &self.config
    }

    pub(super) fn database(&self) -> &Database {
        &self.database
    }

    pub(super) fn admin_login_limiter(&self) -> &AdminLoginLimiter {
        &self.admin_login_limiter
    }

    pub(super) fn login_limiter(&self) -> &LoginLimiter {
        &self.login_limiter
    }

    pub(super) fn share_limiter(&self) -> &LoginLimiter {
        &self.share_limiter
    }

    pub(super) fn alias_limiter(&self) -> &LoginLimiter {
        &self.alias_limiter
    }

    pub(super) fn public_transfer_limiter(&self) -> &LoginLimiter {
        &self.public_transfer_limiter
    }

    pub(super) fn preview_token_limiter(&self) -> &LoginLimiter {
        &self.preview_token_limiter
    }

    pub(super) fn monitoring_limiter(&self) -> &LoginLimiter {
        &self.monitoring_limiter
    }

    #[cfg(test)]
    pub(super) fn replace_config(&mut self, config: Config) {
        self.config = Arc::new(config);
    }

    #[cfg(test)]
    pub(super) fn replace_login_limiter(&mut self, limiter: LoginLimiter) {
        self.login_limiter = limiter;
    }

    #[cfg(test)]
    pub(super) fn replace_monitoring_limiter(&mut self, limiter: LoginLimiter) {
        self.monitoring_limiter = limiter;
    }
}
