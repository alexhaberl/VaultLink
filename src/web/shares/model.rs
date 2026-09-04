struct ShareUploadRulesView {
    show_overwrite: bool,
    overwrite_checked: bool,
    max_total_size_gb: String,
    max_files: u64,
}

struct ShareRowView {
    id: i64,
    display_name: String,
    relative_path: String,
    url: String,
    permission_label: &'static str,
    status_label: &'static str,
    status_tone: &'static str,
    password_protected: bool,
    download_count: u64,
    maximum: String,
    progress: Option<u64>,
    upload_limit: String,
    toggle_label: &'static str,
    upload_rules: Option<ShareUploadRulesView>,
}

#[derive(Template)]
#[template(path = "web/shares/index.html")]
struct ShareIndexTemplate {
    active_count: usize,
    protected_count: usize,
    monthly_download: u64,
    monthly_zip_download: u64,
    monthly_preview: u64,
    month: String,
    statistics_started_label: String,
    query: String,
    status: &'static str,
    sort: &'static str,
    rows: Vec<ShareRowView>,
    previous_url: Option<String>,
    next_url: Option<String>,
    csrf_token: String,
    password_min_length: usize,
    password_max_length: usize,
}

#[derive(Template)]
#[template(path = "web/shares/no_target.html")]
struct ShareNoTargetTemplate;

#[derive(Template)]
#[template(path = "web/shares/create.html")]
struct ShareCreateTemplate {
    csrf_token: String,
    relative_path: String,
    target_type: &'static str,
    is_directory: bool,
    alias_pattern: String,
    calendar_icon: TrustedMarkup,
    password_min_length: usize,
    password_max_length: usize,
    max_upload_size_ceiling_gb: String,
    global_upload_size_gb: String,
    default_total_size_gb: String,
    default_max_files: u64,
    replacements_allowed: bool,
    url_preview: String,
}
