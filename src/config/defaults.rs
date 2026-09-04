impl Default for Security {
    fn default() -> Self {
        Self {
            session_hours: default_session_hours(),
            session_idle_minutes: default_session_idle_minutes(),
            login_attempts: default_attempts(),
            account_login_attempts: default_account_login_attempts(),
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
fn default_session_idle_minutes() -> i64 {
    30
}
fn default_attempts() -> usize {
    5
}
fn default_account_login_attempts() -> usize {
    25
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

pub const MAX_PUBLIC_UPLOADS_CEILING: usize = 28;
pub const MAX_UPLOADS_PER_SHARE_CEILING: usize = 2;
pub const UPLOAD_MIN_BYTES_PER_SECOND_FLOOR: u64 = 65_536;
pub const UPLOAD_MAX_DURATION_SECONDS_CEILING: u64 = 21_600;
pub const MAX_PUBLIC_STREAMS_CEILING: usize = 96;
pub const MAX_STREAMS_PER_SHARE_CEILING: usize = 16;
pub const STREAM_MIN_BYTES_PER_SECOND_FLOOR: u64 = 16_384;
pub const STREAM_MAX_DURATION_SECONDS_CEILING: u64 = 21_600;

/// Static slow-client and public-capacity policy. These limits are deliberately
/// restart-only: admitting more work than the compiled safety envelope is not a
/// runtime setting.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    #[serde(default = "default_max_public_uploads")]
    pub max_public_uploads: usize,
    #[serde(default = "default_max_uploads_per_share")]
    pub max_uploads_per_share: usize,
    #[serde(default = "default_upload_min_bytes_per_second")]
    pub upload_min_bytes_per_second: u64,
    #[serde(default = "default_upload_max_duration_seconds")]
    pub upload_max_duration_seconds: u64,
    #[serde(default = "default_max_public_streams")]
    pub max_public_streams: usize,
    #[serde(default = "default_max_streams_per_share")]
    pub max_streams_per_share: usize,
    #[serde(default = "default_stream_min_bytes_per_second")]
    pub stream_min_bytes_per_second: u64,
    #[serde(default = "default_stream_max_duration_seconds")]
    pub stream_max_duration_seconds: u64,
}

impl Default for Admission {
    fn default() -> Self {
        Self {
            max_public_uploads: default_max_public_uploads(),
            max_uploads_per_share: default_max_uploads_per_share(),
            upload_min_bytes_per_second: default_upload_min_bytes_per_second(),
            upload_max_duration_seconds: default_upload_max_duration_seconds(),
            max_public_streams: default_max_public_streams(),
            max_streams_per_share: default_max_streams_per_share(),
            stream_min_bytes_per_second: default_stream_min_bytes_per_second(),
            stream_max_duration_seconds: default_stream_max_duration_seconds(),
        }
    }
}

fn default_max_public_uploads() -> usize {
    MAX_PUBLIC_UPLOADS_CEILING
}

fn default_max_uploads_per_share() -> usize {
    MAX_UPLOADS_PER_SHARE_CEILING
}

fn default_upload_min_bytes_per_second() -> u64 {
    UPLOAD_MIN_BYTES_PER_SECOND_FLOOR
}

fn default_upload_max_duration_seconds() -> u64 {
    UPLOAD_MAX_DURATION_SECONDS_CEILING
}

fn default_max_public_streams() -> usize {
    MAX_PUBLIC_STREAMS_CEILING
}

fn default_max_streams_per_share() -> usize {
    MAX_STREAMS_PER_SHARE_CEILING
}

fn default_stream_min_bytes_per_second() -> u64 {
    STREAM_MIN_BYTES_PER_SECOND_FLOOR
}

fn default_stream_max_duration_seconds() -> u64 {
    STREAM_MAX_DURATION_SECONDS_CEILING
}

const MAX_SESSION_HOURS: i64 = 24 * 365;
const MIN_SESSION_IDLE_MINUTES: i64 = 5;
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
