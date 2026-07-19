use askama::Template;
use axum::{
    extract::{Form, Path as AxPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::{
    common::{
        display_limit_unit_ceil, display_limit_unit_floor, encoded, format_unit_decimal,
        format_utc_minute, human, internal, parse_expiry, parse_unit_to_bytes, upload_limit_label,
        CsrfForm,
    },
    rendering::{PageId, GB},
    storage_recovery_app_error,
    templates::{self, TrustedMarkup},
    AppError, Result,
};
use crate::{
    auth,
    db::{
        AuditContext, Permission, RequiredAuditEvent, Share, ShareControlsUpdateOutcome,
        ShareListOptions, ShareListSort, ShareListStatus, UploadConflictStrategy,
        DEFAULT_SHARE_UPLOAD_FILE_COUNT, DEFAULT_SHARE_UPLOAD_TOTAL_SIZE, MAX_SQLITE_UNSIGNED,
    },
    file_ops,
    http_auth::{
        csrf, current_audit_client_ip, database, hash_password_admitted, runtime_settings, session,
        MissingSession,
    },
    i18n::{self},
    path_security,
    policy::{self, ShareAvailability},
    runtime::RuntimeSettings,
    sensitive::SecretString,
    services::share::{
        CreateShareCommand, ShareAuthorityMutation, SharePasswordInput, ShareService,
        ShareServiceError, ShareTarget,
    },
    AppState,
};

#[derive(Default, Deserialize)]
pub(super) struct ShareQuery {
    pub(super) path: Option<String>,
    pub(super) q: Option<String>,
    pub(super) status: Option<String>,
    pub(super) sort: Option<String>,
    pub(super) cursor: Option<i64>,
}

#[derive(Default, Deserialize)]
pub(crate) struct PreviewRawQuery {
    pub(super) path: Option<String>,
    pub(super) preview_token: Option<String>,
}

pub(super) fn share_permission_label(permission: &Permission) -> &'static str {
    let locale = i18n::current_locale();
    match permission {
        Permission::DownloadOnly => i18n::text(locale, i18n::DOWNLOAD_ONLY),
        Permission::UploadOnly => i18n::text(locale, i18n::UPLOAD_ONLY),
        Permission::DownloadUpload => i18n::text(locale, i18n::DOWNLOAD_UPLOAD),
    }
}

pub(super) fn share_primary_status(share: &Share) -> (&'static str, &'static str) {
    let locale = i18n::current_locale();
    match policy::share_availability(share, Utc::now()) {
        ShareAvailability::Inactive => (i18n::text(locale, i18n::INACTIVE), "neutral"),
        ShareAvailability::Expired => (i18n::text(locale, i18n::EXPIRED), "warning"),
        ShareAvailability::LimitReached => (i18n::text(locale, i18n::LIMIT_REACHED), "warning"),
        ShareAvailability::Available => (i18n::text(locale, i18n::ACTIVE), "success"),
    }
}

pub(super) fn share_public_url(settings: &RuntimeSettings, share: &Share) -> String {
    let base = settings.public_base_url.trim_end_matches('/');
    match share.alias.as_deref() {
        Some(alias) => format!("{base}/s/{alias}"),
        None => format!("{base}/v/{}", share.token),
    }
}

pub(super) fn share_list_url(query: &str, status: &str, sort: &str, cursor: Option<i64>) -> String {
    let mut url = format!(
        "/admin/shares?q={}&status={}&sort={}",
        encoded(query),
        encoded(status),
        encoded(sort)
    );
    if let Some(cursor) = cursor {
        url.push_str(&format!("&cursor={cursor}"));
    }
    url
}

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

pub(super) async fn share_index_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ShareQuery>,
) -> Result<Response> {
    let (_, session_data) =
        session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    if let Some(path) = q.path.as_deref().filter(|path| !path.is_empty()) {
        return Ok(
            Redirect::to(&format!("/admin/shares/new?path={}", encoded(path))).into_response(),
        );
    }
    let settings = runtime_settings(&state);
    let now = Utc::now();
    let monthly = database(state.db.clone(), |database| {
        database.current_transfer_monthly_counts()
    })
    .await?;
    let statistics_started_at = database(state.db.clone(), |database| {
        database.transfer_statistics_started_at()
    })
    .await?;
    let statistics_started_label = DateTime::parse_from_rfc3339(&statistics_started_at)
        .map(|value| format_utc_minute(value.with_timezone(&Utc)))
        .unwrap_or(statistics_started_at);
    let query = q.q.as_deref().unwrap_or("").trim().to_string();
    let status = match q.status.as_deref().unwrap_or("all") {
        "active" => "active",
        "protected" => "protected",
        "expired" => "expired",
        "limit" => "limit",
        "inactive" => "inactive",
        _ => "all",
    };
    let sort = if q.sort.as_deref() == Some("oldest") {
        "oldest"
    } else {
        "newest"
    };
    let options = ShareListOptions {
        query: (!query.is_empty()).then(|| query.clone()),
        status: ShareListStatus::parse(status).unwrap_or_default(),
        sort: ShareListSort::parse(sort).unwrap_or_default(),
        cursor: q.cursor.filter(|cursor| *cursor > 0),
        limit: 50,
        now,
    };
    let page_data = database(state.db.clone(), move |database| {
        database.list_share_page(&options)
    })
    .await?;
    let summary = database(state.db.clone(), move |database| {
        database.share_summary(now)
    })
    .await?;
    let active_count = summary.available;
    let protected_count = summary.protected;
    let locale = i18n::current_locale();
    let rows = page_data
        .shares
        .iter()
        .map(|share| {
            let url = share_public_url(&settings, share);
            let display_name = share
                .alias
                .as_deref()
                .or_else(|| share.relative_path.rsplit('/').next())
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| i18n::text(i18n::current_locale(), i18n::DEFAULT_SHARE_NAME));
            let (status_label, status_tone) = share_primary_status(share);
            let maximum = share
                .max_downloads
                .map(|value| value.to_string())
                .unwrap_or_else(|| "∞".into());
            let progress = share.max_downloads.map(|maximum| {
                share
                    .download_count
                    .saturating_mul(100)
                    .saturating_div(maximum.max(1))
                    .min(100)
            });
            let upload_settings = if share.is_directory && share.permission.can_upload() {
                Some(ShareUploadRulesView {
                    show_overwrite: state.config.storage.replacements_allowed(),
                    overwrite_checked: share.upload_conflict_strategy.can_overwrite(),
                    max_total_size_gb: format_unit_decimal(
                        share
                            .max_upload_total_size
                            .unwrap_or(DEFAULT_SHARE_UPLOAD_TOTAL_SIZE),
                        GB,
                    ),
                    max_files: share
                        .max_upload_files
                        .unwrap_or(DEFAULT_SHARE_UPLOAD_FILE_COUNT),
                })
            } else {
                None
            };
            let single_upload_limit = share
                .max_upload_size
                .map(upload_limit_label)
                .unwrap_or_else(|| format!("global {}", human(settings.max_upload_size)));
            let upload_limit = if share.permission.can_upload() {
                let (cumulative, files) = if locale == i18n::Locale::De {
                    ("kumulativ", "Dateien")
                } else {
                    ("cumulative", "Files")
                };
                format!(
                    "{single_upload_limit}; {cumulative} {} / {}; {files} {} / {}",
                    human(share.uploaded_bytes),
                    share
                        .max_upload_total_size
                        .map(human)
                        .unwrap_or_else(|| "—".into()),
                    share.uploaded_files,
                    share
                        .max_upload_files
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "—".into()),
                )
            } else {
                single_upload_limit
            };
            ShareRowView {
                id: share.id,
                display_name: display_name.to_string(),
                relative_path: share.relative_path.clone(),
                url,
                permission_label: share_permission_label(&share.permission),
                status_label,
                status_tone,
                password_protected: share.password_hash.is_some(),
                download_count: share.download_count,
                maximum,
                progress,
                upload_limit,
                toggle_label: if share.active {
                    i18n::text(i18n::current_locale(), i18n::DEACTIVATE_COMMON)
                } else {
                    i18n::text(i18n::current_locale(), i18n::ACTIVATE)
                },
                upload_rules: upload_settings,
            }
        })
        .collect();
    let previous = q
        .cursor
        .filter(|cursor| *cursor > 0)
        .map(|_| share_list_url(&query, status, sort, None));
    let next = page_data
        .next_cursor
        .map(|cursor| share_list_url(&query, status, sort, Some(cursor)));
    let body = ShareIndexTemplate {
        active_count,
        protected_count,
        monthly_download: monthly.download,
        monthly_zip_download: monthly.zip_download,
        monthly_preview: monthly.preview,
        month: monthly.month,
        statistics_started_label,
        query,
        status,
        sort,
        rows,
        previous_url: previous,
        next_url: next,
        csrf_token: session_data.csrf_token.clone(),
        password_min_length: settings.share_password_min_length,
        password_max_length: settings.share_password_max_length,
    };
    Ok(Html(templates::admin_page(
        &state,
        PageId::Links,
        &body,
        false,
        &session_data.csrf_token,
        true,
    )?)
    .into_response())
}

pub(super) async fn share_create_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ShareQuery>,
) -> Result<Html<String>> {
    let (_, session_data) =
        session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let settings = runtime_settings(&state);
    let Some(raw_path) = query.path.as_deref().filter(|path| !path.is_empty()) else {
        return Ok(Html(templates::admin_page(
            &state,
            PageId::CreateLink,
            &ShareNoTargetTemplate,
            false,
            &session_data.csrf_token,
            true,
        )?));
    };
    let relative_path = path_security::validate_relative(raw_path)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid target path"))?
        .to_string_lossy()
        .replace('\\', "/");
    let secure_root = state.secure_root.clone();
    let metadata_path = relative_path.clone();
    let metadata = tokio::task::spawn_blocking(move || secure_root.metadata(&metadata_path))
        .await
        .map_err(internal)?
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid target path"))?;
    let is_directory = metadata.is_dir();
    let url_preview = format!(
        "{}/v/••••••••",
        settings.public_base_url.trim_end_matches('/')
    );
    let alias_pattern = format!(
        "[A-Za-z0-9_-]{{{},{}}}",
        path_security::SHARE_ALIAS_MIN_LENGTH,
        path_security::SHARE_ALIAS_MAX_LENGTH
    );
    let body = ShareCreateTemplate {
        csrf_token: session_data.csrf_token.clone(),
        relative_path,
        target_type: i18n::text(
            i18n::current_locale(),
            if is_directory {
                i18n::FOLDER
            } else {
                i18n::FILE
            },
        ),
        is_directory,
        alias_pattern,
        calendar_icon: TrustedMarkup::static_icon(crate::ui::Icon::Calendar),
        password_min_length: settings.share_password_min_length,
        password_max_length: settings.share_password_max_length,
        max_upload_size_ceiling_gb: display_limit_unit_floor(crate::config::MAX_UPLOAD_SIZE, GB),
        global_upload_size_gb: display_limit_unit_floor(settings.max_upload_size, GB),
        default_total_size_gb: display_limit_unit_ceil(
            DEFAULT_SHARE_UPLOAD_TOTAL_SIZE.max(settings.max_upload_size),
            GB,
        ),
        default_max_files: DEFAULT_SHARE_UPLOAD_FILE_COUNT,
        replacements_allowed: state.config.storage.replacements_allowed(),
        url_preview,
    };
    Ok(Html(templates::admin_page(
        &state,
        PageId::CreateLink,
        &body,
        false,
        &session_data.csrf_token,
        true,
    )?))
}

#[derive(Deserialize)]
pub(super) struct CreateShare {
    csrf: String,
    path: String,
    permission: String,
    alias: Option<String>,
    expires_local: Option<String>,
    expires_tz_offset_minutes: Option<String>,
    max_downloads: Option<String>,
    max_upload_size_gb: Option<String>,
    max_upload_total_size_gb: Option<String>,
    max_upload_files: Option<String>,
    password: Option<SecretString>,
    password_confirm: Option<SecretString>,
    password_enabled: Option<String>,
    overwrite_allowed: Option<String>,
}
pub(super) async fn create_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<CreateShare>,
) -> Result<Redirect> {
    let (_, s) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&s, &f.csrf)?;
    let settings = runtime_settings(&state);
    let service = ShareService::new(
        state.db.clone(),
        settings.clone(),
        !state.config.storage.replacements_allowed(),
    );
    let rel = service
        .normalize_target_path(&f.path)
        .map_err(share_service_app_error)?;
    let permission = Permission::parse(&f.permission)
        .ok_or(AppError(StatusCode::BAD_REQUEST, "Invalid permission"))?;
    let alias = f.alias.filter(|value| !value.is_empty());
    let exp = parse_expiry(
        f.expires_local.as_deref(),
        f.expires_tz_offset_minutes.as_deref(),
    )?;
    let token = auth::random_token(24);
    let password = f.password.filter(|value| !value.expose_secret().is_empty());
    let password_confirm = f
        .password_confirm
        .filter(|value| !value.expose_secret().is_empty());
    let password_requested = f.password_enabled.as_deref() == Some("1")
        || password.is_some()
        || password_confirm.is_some();
    if password_requested && password.is_none() && password_confirm.is_none() {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Password and confirmation are required for password protection",
        ));
    }
    let password = if password_requested {
        SharePasswordInput::WithConfirmation {
            password,
            confirmation: password_confirm,
        }
    } else {
        SharePasswordInput::None
    };
    let secure_root = state.secure_root.clone();
    let metadata_path = rel.clone();
    let target_metadata = tokio::task::spawn_blocking(move || secure_root.metadata(&metadata_path))
        .await
        .map_err(internal)?
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid target path"))?;
    if !target_metadata.is_file() && !target_metadata.is_dir() {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Shares are allowed only for regular files or directories",
        ));
    }
    let target = if target_metadata.is_dir() {
        ShareTarget::Directory
    } else {
        ShareTarget::File
    };
    let max_downloads = f
        .max_downloads
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid transfer limit"))?;
    // The browser keeps the directory upload controls in the form and hides
    // them when `download_only` is selected. Hidden successful controls are
    // still submitted, so ignore every upload-only field unless the selected
    // permission actually allows uploads.
    let (max_upload_size, max_upload_total_size, max_upload_files) =
        if target_metadata.is_dir() && permission.can_upload() {
            let max_upload_size = f
                .max_upload_size_gb
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| parse_unit_to_bytes(value, GB, "Invalid upload limit"))
                .transpose()?;
            let max_upload_total_size = f
                .max_upload_total_size_gb
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| parse_unit_to_bytes(value, GB, "Invalid cumulative upload limit"))
                .transpose()?;
            let max_upload_files = f
                .max_upload_files
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::parse::<u64>)
                .transpose()
                .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid upload file limit"))?;
            (max_upload_size, max_upload_total_size, max_upload_files)
        } else {
            (None, None, None)
        };
    let overwrite_allowed = permission.can_upload() && f.overwrite_allowed.as_deref() == Some("1");
    let revalidation_path = rel.clone();
    let validated = service
        .prepare_create(CreateShareCommand {
            token,
            path: rel,
            target,
            permission,
            alias,
            expires_at: exp,
            max_downloads,
            max_upload_size,
            max_upload_total_size,
            max_upload_files,
            password,
            overwrite_allowed,
            created_by: s.admin_id,
        })
        .map_err(share_service_app_error)?;
    let (prepared, password) = validated.into_password_hash_input();
    let password_hash = match password {
        Some(password) => Some(hash_password_admitted(&state, password).await?),
        None => None,
    };
    let storage_guard = state.storage_mutation.clone().lock_owned().await;
    let storage_guard = file_ops::recover_pending_file_operations_with_guard(&state, storage_guard)
        .await
        .map_err(storage_recovery_app_error)?;
    let secure_root = state.secure_root.clone();
    let metadata_path = revalidation_path;
    let current_metadata =
        tokio::task::spawn_blocking(move || secure_root.metadata(&metadata_path))
            .await
            .map_err(internal)?
            .map_err(|_| AppError(StatusCode::CONFLICT, "Target changed during processing"))?;
    let current_target = if current_metadata.is_dir() {
        ShareTarget::Directory
    } else if current_metadata.is_file() {
        ShareTarget::File
    } else {
        return Err(AppError(
            StatusCode::CONFLICT,
            "Target changed during processing",
        ));
    };
    if current_target != target {
        return Err(AppError(
            StatusCode::CONFLICT,
            "Target changed during processing",
        ));
    }
    let authority_mutation = ShareAuthorityMutation::from_guard(&state, storage_guard);
    let username = s.username;
    let audit_client_ip = settings
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(username, audit_client_ip);
    authority_mutation
        .commit(move |_| {
            // Keep target revalidation and the non-cancellable SQLite create
            // serialized even when the client disconnects mid-request.
            service
                .create(prepared, password_hash.as_deref(), &audit_context)
                .map(drop)
                .map_err(share_service_database_error)
        })
        .await
        .map_err(|error| {
            if error.status == StatusCode::SERVICE_UNAVAILABLE {
                AppError::from(error)
            } else {
                AppError(StatusCode::CONFLICT, "Token or alias already exists")
            }
        })?;
    Ok(Redirect::to("/admin/shares"))
}

fn share_service_app_error(error: ShareServiceError) -> AppError {
    match error {
        ShareServiceError::InvalidPath => AppError(StatusCode::BAD_REQUEST, "Invalid target path"),
        ShareServiceError::InvalidAlias => AppError(StatusCode::BAD_REQUEST, "Invalid alias"),
        ShareServiceError::ExpirationNotFuture => {
            AppError(StatusCode::BAD_REQUEST, "Expiration date is in the past")
        }
        ShareServiceError::UploadPermissionRequiresDirectory => AppError(
            StatusCode::BAD_REQUEST,
            "Uploads are available for folder links only",
        ),
        ShareServiceError::InvalidDownloadLimit => {
            AppError(StatusCode::BAD_REQUEST, "Invalid transfer limit")
        }
        ShareServiceError::InvalidUploadLimit => {
            AppError(StatusCode::BAD_REQUEST, "Invalid upload limit")
        }
        ShareServiceError::UploadLimitsRequireDirectoryUpload => AppError(
            StatusCode::BAD_REQUEST,
            "Upload limits are allowed only for upload shares",
        ),
        ShareServiceError::InvalidUploadTotalLimit
        | ShareServiceError::UploadTotalBelowSingleLimit => AppError(
            StatusCode::BAD_REQUEST,
            "The cumulative upload limit is invalid",
        ),
        ShareServiceError::InvalidUploadFileLimit => {
            AppError(StatusCode::BAD_REQUEST, "The upload file limit is invalid")
        }
        ShareServiceError::OverwriteRequiresDirectoryUpload => AppError(
            StatusCode::BAD_REQUEST,
            "Overwriting is not allowed for this share",
        ),
        ShareServiceError::OverwriteDisabledForExternalWriters => AppError(
            StatusCode::BAD_REQUEST,
            "Overwriting is disabled with external storage writers",
        ),
        ShareServiceError::PasswordConfirmationRequired => AppError(
            StatusCode::BAD_REQUEST,
            "Password and confirmation are required for password protection",
        ),
        ShareServiceError::PasswordConfirmationMismatch => {
            AppError(StatusCode::BAD_REQUEST, "Passwords do not match")
        }
        ShareServiceError::InvalidPasswordCharacterLength
        | ShareServiceError::PasswordTooManyBytes => AppError(
            StatusCode::BAD_REQUEST,
            "Share password does not meet the policy",
        ),
        ShareServiceError::PasswordHashStateMismatch => internal(()),
        ShareServiceError::Database(error) => internal(error),
    }
}

fn share_service_database_error(error: ShareServiceError) -> rusqlite::Error {
    error
        .into_database_error()
        .unwrap_or(rusqlite::Error::InvalidQuery)
}

pub(super) async fn toggle_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Redirect> {
    let (_, s) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&s, &f.csrf)?;
    let authority_mutation = ShareAuthorityMutation::acquire(&state).await;
    let sh = database(state.db.clone(), move |db| db.share_by_id(id))
        .await?
        .ok_or(AppError(StatusCode::NOT_FOUND, "Link not found"))?;
    let active = !sh.active;
    let username = s.username;
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(username, audit_client_ip);
    let changed = authority_mutation
        .commit(move |db| {
            db.set_share_active_and_audit(id, active, &audit_context, "share_toggled")
        })
        .await?;
    if !changed {
        return Err(AppError(StatusCode::NOT_FOUND, "Link not found"));
    }
    Ok(Redirect::to("/admin/shares"))
}

#[derive(Deserialize)]
pub(super) struct UploadConflictForm {
    csrf: String,
    strategy: Option<String>,
    overwrite_allowed: Option<String>,
    max_upload_total_size_gb: Option<String>,
    max_upload_files: Option<String>,
}

pub(super) async fn set_share_upload_conflict(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(form): Form<UploadConflictForm>,
) -> Result<Redirect> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    let strategy = if let Some(strategy) = form.strategy.as_deref() {
        UploadConflictStrategy::parse(strategy).ok_or(AppError(
            StatusCode::BAD_REQUEST,
            "Invalid upload conflict strategy",
        ))?
    } else if form.overwrite_allowed.as_deref() == Some("1") {
        UploadConflictStrategy::OverwriteAllowed
    } else {
        UploadConflictStrategy::Reject
    };
    if strategy.can_overwrite() && !state.config.storage.replacements_allowed() {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Overwriting is disabled with external storage writers",
        ));
    }
    let authority_mutation = ShareAuthorityMutation::acquire(&state).await;
    let share = database(state.db.clone(), move |db| db.share_by_id(id))
        .await?
        .ok_or(AppError(StatusCode::NOT_FOUND, "Link not found"))?;
    if !share.is_directory || !share.permission.can_upload() {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Overwrite is available only for folder shares with upload permission",
        ));
    }
    let total_limit = form
        .max_upload_total_size_gb
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| parse_unit_to_bytes(value, GB, "Invalid cumulative upload limit"))
        .transpose()
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid cumulative upload limit"))?
        .unwrap_or_else(|| {
            share
                .max_upload_total_size
                .unwrap_or(DEFAULT_SHARE_UPLOAD_TOTAL_SIZE)
        });
    let file_limit = form
        .max_upload_files
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::parse::<u64>)
        .transpose()
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid upload file limit"))?
        .unwrap_or_else(|| {
            share
                .max_upload_files
                .unwrap_or(DEFAULT_SHARE_UPLOAD_FILE_COUNT)
        });
    let effective_single = share
        .max_upload_size
        .unwrap_or_else(|| runtime_settings(&state).max_upload_size)
        .min(crate::config::MAX_UPLOAD_SIZE);
    if total_limit < effective_single
        || total_limit < share.uploaded_bytes
        || total_limit > MAX_SQLITE_UNSIGNED
        || file_limit == 0
        || file_limit < share.uploaded_files
        || file_limit > MAX_SQLITE_UNSIGNED
    {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Invalid cumulative upload limits",
        ));
    }
    let stored_strategy = strategy.clone();
    let username = session.username;
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(username, audit_client_ip);
    let audit_events = [RequiredAuditEvent::security(
        "share_upload_conflict_updated",
        Some(id.to_string()),
        Some(format!(
            "strategy={};bytes={total_limit};files={file_limit}",
            strategy.as_str()
        )),
    )];
    let outcome = authority_mutation
        .commit(move |db| {
            db.update_share_controls_and_audit(
                id,
                None,
                Some(&stored_strategy),
                Some((total_limit, file_limit)),
                &audit_context,
                &audit_events,
            )
        })
        .await?;
    match outcome {
        ShareControlsUpdateOutcome::Updated => {}
        ShareControlsUpdateOutcome::NotFound => {
            return Err(AppError(StatusCode::NOT_FOUND, "Link not found"));
        }
        ShareControlsUpdateOutcome::QuotaConflict => {
            return Err(AppError(
                StatusCode::CONFLICT,
                "Upload capacity is in use by active uploads",
            ));
        }
    }
    Ok(Redirect::to("/admin/shares"))
}

#[derive(Deserialize)]
pub(super) struct SharePasswordForm {
    csrf: String,
    password: Option<SecretString>,
    password_confirm: Option<SecretString>,
    remove: Option<String>,
}

pub(super) async fn set_share_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(form): Form<SharePasswordForm>,
) -> Result<Redirect> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    if database(state.db.clone(), move |db| db.share_by_id(id))
        .await?
        .is_none()
    {
        return Err(AppError(StatusCode::NOT_FOUND, "Link not found"));
    }
    let remove = form.remove.as_deref() == Some("1");
    let settings = runtime_settings(&state);
    let service = ShareService::new(
        state.db.clone(),
        settings.clone(),
        !state.config.storage.replacements_allowed(),
    );
    let password_hash = if remove {
        None
    } else {
        let password = service
            .prepare_password(SharePasswordInput::WithConfirmation {
                password: form.password,
                confirmation: form.password_confirm,
            })
            .map_err(share_service_app_error)?
            .ok_or(AppError(
                StatusCode::BAD_REQUEST,
                "Share password does not meet the policy",
            ))?;
        Some(hash_password_admitted(&state, password).await?)
    };
    let action = if remove {
        "share_password_removed"
    } else {
        "share_password_set"
    };
    let username = session.username;
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(username, audit_client_ip);
    let authority_mutation = ShareAuthorityMutation::acquire(&state).await;
    let changed = authority_mutation
        .commit(move |db| {
            db.set_share_password_and_audit(id, password_hash.as_deref(), &audit_context, action)
        })
        .await?;
    if !changed {
        return Err(AppError(StatusCode::NOT_FOUND, "Link not found"));
    }
    Ok(Redirect::to("/admin/shares"))
}

pub(super) async fn delete_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Redirect> {
    let (_, s) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&s, &f.csrf)?;
    let username = s.username;
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(username, audit_client_ip);
    let authority_mutation = ShareAuthorityMutation::acquire(&state).await;
    let deleted = authority_mutation
        .commit(move |db| db.delete_share_and_audit(id, &audit_context))
        .await?;
    if !deleted {
        return Err(AppError(StatusCode::NOT_FOUND, "Link not found"));
    }
    Ok(Redirect::to("/admin/shares"))
}
