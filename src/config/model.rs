/// Hard ceiling for an entire multipart request body. This protects the server from
/// configurations that cannot be represented by the HTTP upload routes.
pub const MAX_MULTIPART_BODY_SIZE: u64 = 128 * 1024 * 1024 * 1024;
/// Maximum file payload. One MiB is reserved for multipart boundaries, filenames,
/// and the bounded auxiliary form fields.
pub const MAX_UPLOAD_SIZE: u64 = MAX_MULTIPART_BODY_SIZE - 1024 * 1024;
pub use crate::storage_contract::INTERNAL_STORAGE_DIRECTORY_NAME as DEFAULT_INTERNAL_DIRECTORY_NAME;

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
    pub admission: Admission,
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
    #[serde(
        deserialize_with = "deserialize_required_internal_directory",
        skip_serializing_if = "Option::is_none"
    )]
    pub internal_directory: Option<PathBuf>,
    pub require_mount: bool,
    pub external_writers: bool,
    pub allow_external_writer_replace: bool,
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

fn deserialize_required_internal_directory<'de, D>(
    deserializer: D,
) -> Result<Option<PathBuf>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    PathBuf::deserialize(deserializer).map(Some)
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
    #[serde(default = "default_session_idle_minutes")]
    pub session_idle_minutes: i64,
    #[serde(default = "default_attempts")]
    pub login_attempts: usize,
    #[serde(default = "default_account_login_attempts")]
    pub account_login_attempts: usize,
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
