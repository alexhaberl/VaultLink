#[derive(Clone)]
struct SetupState {
    config_path: Arc<PathBuf>,
    token: Arc<String>,
    commit: Arc<tokio::sync::Mutex<bool>>,
    start_sender: Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    start_requested: Arc<AtomicBool>,
}

const INITIAL_SETUP_PENDING_FILE: &str = ".vaultlink-initial-setup.pending";

struct SetupRenderedHtml(String);

impl Display for SetupRenderedHtml {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl HtmlSafe for SetupRenderedHtml {}

#[derive(Template)]
#[template(path = "setup/base.html")]
struct SetupPageTemplate<'a> {
    locale_code: &'static str,
    title: &'static str,
    skip_to_content: &'static str,
    brand_html: TrustedMarkup,
    show_locale_switcher: bool,
    language_label: &'static str,
    return_to: String,
    german: bool,
    english: bool,
    body: &'a SetupRenderedHtml,
}

#[derive(Template)]
#[template(path = "setup/form.html")]
struct SetupFormTemplate<'a> {
    error: Option<&'a str>,
    max_text_preview_size_mb: u64,
}

#[derive(Template)]
#[template(
    source = r#"<section class="vl-panel"><h1><vl-i18n key="common.error"/></h1><p><vl-i18n key="{{ message_key }}"/></p></section>"#,
    ext = "html"
)]
struct SetupMessageTemplate {
    message_key: &'static str,
}

#[derive(Template)]
#[template(
    source = r#"<section class="vl-panel"><h1><vl-i18n key="setup.completed"/></h1><p><vl-i18n key="setup.config_admin_created"/></p><p><vl-i18n key="setup.totp_recovery_help"/></p><div class="vl-qr-card" aria-label="<vl-i18n key="setup.totp_qr_code"/>">{{ qr }}</div><div class="vl-secret-block"><code>{{ secret }}</code><code>{{ otpauth }}</code></div><form method="post" action="/complete"><button class="vl-button"><vl-i18n key="setup.secret_saved"/></button></form></section>"#,
    ext = "html"
)]
struct SetupCompletedTemplate<'a> {
    qr: &'a TrustedMarkup,
    secret: &'a str,
    otpauth: &'a str,
}

#[derive(Template)]
#[template(
    source = r#"<section class="vl-panel"><h1><vl-i18n key="setup.confirmed"/></h1><p>{{ message }}</p><p><vl-i18n key="setup.configured_for_mode"/> <strong>{{ mode }}</strong>.</p><form method="post" action="/start"><button class="vl-button"><vl-i18n key="setup.start_now"/></button></form><p class="vl-muted"><vl-i18n key="setup.service_start_help"/></p></section>"#,
    ext = "html"
)]
struct SetupConfirmedTemplate<'a> {
    message: &'a str,
    mode: &'static str,
}

#[derive(Template)]
#[template(
    source = r#"<section class="vl-panel"><h1><vl-i18n key="setup.starting"/></h1><p><vl-i18n key="setup.listener_transition"/></p><p><a class="vl-button" href="{{ url }}"><vl-i18n key="setup.open_vaultlink"/></a></p><p class="vl-muted"><vl-i18n key="setup.start_delay"/></p></section>"#,
    ext = "html"
)]
struct SetupStartingTemplate<'a> {
    url: &'a str,
}

#[derive(Deserialize)]
struct SetupLocaleForm {
    locale: String,
    return_to: String,
}

#[derive(Deserialize)]
struct SetupForm {
    server_mode: String,
    listen_address: String,
    public_base_url: String,
    root_mount_path: String,
    data_directory: String,
    internal_directory: String,
    require_mount: Option<String>,
    external_writers: Option<String>,
    allow_external_writer_replace: Option<String>,
    expected_filesystem_type: String,
    expected_mount_source: String,
    max_upload_size_mb: String,
    max_zip_size_gb: String,
    max_zip_files: String,
    max_search_entries: String,
    max_search_results: String,
    max_preview_size_mb: String,
    preview_extensions: String,
    image_preview_extensions: String,
    pdf_preview_enabled: Option<String>,
    max_media_preview_size_mb: String,
    blocked_extensions: String,
    audit_client_ip_enabled: Option<String>,
    trusted_proxies: String,
    certificate_source: String,
    tls_cert_file: String,
    tls_key_file: String,
    letsencrypt_contact_email: String,
    letsencrypt_cache_dir: String,
    letsencrypt_staging: Option<String>,
    hsts_enabled: Option<String>,
    log_level: String,
    admin_username: String,
    admin_password: SecretString,
    admin_password_confirm: SecretString,
}
