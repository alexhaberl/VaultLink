use axum::{
    extract::{Form, Path as AxPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::{
    common::{
        display_limit_unit_ceil, display_limit_unit_floor, encoded, expiry_picker_html,
        format_unit_decimal, format_utc_minute, human, internal, parse_expiry, parse_unit_to_bytes,
        upload_limit_label, CsrfForm,
    },
    rendering::{admin_page, esc, PageId, GB},
    storage_recovery_app_error, AppError, Result,
};
use crate::{
    auth,
    db::{
        AuditContext, Permission, RequiredAuditEvent, Share, ShareControlsUpdateOutcome,
        UploadConflictStrategy, DEFAULT_SHARE_UPLOAD_FILE_COUNT, DEFAULT_SHARE_UPLOAD_TOTAL_SIZE,
        MAX_SQLITE_UNSIGNED,
    },
    file_ops,
    http_auth::{
        csrf, current_audit_client_ip, database, hash_password_admitted, runtime_settings, session,
        MissingSession,
    },
    i18n::{self},
    path_security,
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
    pub(super) page: Option<usize>,
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

pub(super) fn share_is_expired(share: &Share) -> bool {
    share
        .expires_at
        .is_some_and(|expires_at| expires_at <= Utc::now())
}

pub(super) fn share_limit_reached(share: &Share) -> bool {
    share
        .max_downloads
        .is_some_and(|maximum| share.download_count >= maximum)
}

pub(super) fn share_is_available(share: &Share) -> bool {
    share.active && !share_is_expired(share) && !share_limit_reached(share)
}

pub(super) fn share_primary_status(share: &Share) -> (&'static str, &'static str) {
    let locale = i18n::current_locale();
    if !share.active {
        (i18n::text(locale, i18n::INACTIVE), "neutral")
    } else if share_is_expired(share) {
        (i18n::text(locale, i18n::EXPIRED), "warning")
    } else if share_limit_reached(share) {
        (i18n::text(locale, i18n::LIMIT_REACHED), "warning")
    } else {
        (i18n::text(locale, i18n::ACTIVE), "success")
    }
}

pub(super) fn share_public_url(settings: &RuntimeSettings, share: &Share) -> String {
    let base = settings.public_base_url.trim_end_matches('/');
    match share.alias.as_deref() {
        Some(alias) => format!("{base}/s/{alias}"),
        None => format!("{base}/v/{}", share.token),
    }
}

pub(super) fn selected(current: &str, value: &str) -> &'static str {
    if current == value {
        "selected"
    } else {
        ""
    }
}

pub(super) fn share_list_url(query: &str, status: &str, sort: &str, page: usize) -> String {
    format!(
        "/admin/shares?q={}&status={}&sort={}&page={page}",
        encoded(query),
        encoded(status),
        encoded(sort)
    )
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
    let all_shares = database(state.db.clone(), |database| database.list_shares()).await?;
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
    let active_count = all_shares
        .iter()
        .filter(|share| share_is_available(share))
        .count();
    let protected_count = all_shares
        .iter()
        .filter(|share| share.password_hash.is_some())
        .count();
    let query = q.q.as_deref().unwrap_or("").trim().to_string();
    let query_lower = query.to_lowercase();
    let status = match q.status.as_deref().unwrap_or("all") {
        value @ ("active" | "protected" | "expired" | "limit" | "inactive") => value,
        _ => "all",
    };
    let sort = if q.sort.as_deref() == Some("oldest") {
        "oldest"
    } else {
        "newest"
    };
    let mut shares = all_shares
        .into_iter()
        .filter(|share| {
            let matches_query = query_lower.is_empty()
                || share.relative_path.to_lowercase().contains(&query_lower)
                || share
                    .alias
                    .as_deref()
                    .is_some_and(|alias| alias.to_lowercase().contains(&query_lower));
            let matches_status = match status {
                "active" => share_is_available(share),
                "protected" => share.password_hash.is_some(),
                "expired" => share_is_expired(share),
                "limit" => share_limit_reached(share),
                "inactive" => !share.active,
                _ => true,
            };
            matches_query && matches_status
        })
        .collect::<Vec<_>>();
    if sort == "oldest" {
        shares.reverse();
    }
    const PAGE_SIZE: usize = 50;
    let total = shares.len();
    let total_pages = total.div_ceil(PAGE_SIZE).max(1);
    let page = q
        .page
        .unwrap_or(0)
        .min(1_000_000)
        .min(total_pages.saturating_sub(1));
    let start = page.saturating_mul(PAGE_SIZE).min(total);
    let end = start.saturating_add(PAGE_SIZE).min(total);
    let mut share_rows = String::new();
    for share in &shares[start..end] {
        let url = share_public_url(&settings, share);
        let display_name = share
            .alias
            .as_deref()
            .or_else(|| share.relative_path.rsplit('/').next())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| i18n::text(i18n::current_locale(), i18n::DEFAULT_SHARE_NAME));
        let (status_label, status_tone) = share_primary_status(share);
        let password_badge = if share.password_hash.is_some() {
            r#"<span class="vl-badge vl-badge--neutral"><vl-i18n key="auth.password"/></span>"#
        } else {
            ""
        };
        let maximum = share
            .max_downloads
            .map(|value| value.to_string())
            .unwrap_or_else(|| "∞".into());
        let progress = share
            .max_downloads
            .map(|maximum| {
                let value = share
                    .download_count
                    .saturating_mul(100)
                    .saturating_div(maximum.max(1))
                    .min(100);
                format!(r#"<progress max="100" value="{value}">{value}%</progress>"#)
            })
            .unwrap_or_default();
        let upload_settings = if share.is_directory && share.permission.can_upload() {
            let overwrite_control = if !state.config.storage.replacements_allowed() {
                String::new()
            } else {
                let checked = if share.upload_conflict_strategy.can_overwrite() {
                    "checked"
                } else {
                    ""
                };
                format!(
                    r#"<label class="vl-switch"><input type="checkbox" name="overwrite_allowed" value="1" {checked}><span><vl-i18n key="share.allow_overwrite"/><small><vl-i18n key="share.uploader_confirm_each"/></small></span></label>"#
                )
            };
            format!(
                r#"<details><summary><vl-i18n key="share.upload_rules"/></summary><form method="post" action="/admin/shares/{}/upload-conflict" class="vl-stack"><input type="hidden" name="csrf" value="{}">{}<label class="vl-field"><vl-i18n key="share.cumulative_upload_limit_gb"/><input name="max_upload_total_size_gb" type="number" min="0.000000001" step="any" value="{}" required></label><label class="vl-field">Maximale Upload-Dateien<input name="max_upload_files" type="number" min="1" value="{}" required></label><button class="vl-button vl-button--secondary"><vl-i18n key="common.apply"/></button></form></details>"#,
                share.id,
                esc(&session_data.csrf_token),
                overwrite_control,
                format_unit_decimal(
                    share
                        .max_upload_total_size
                        .unwrap_or(DEFAULT_SHARE_UPLOAD_TOTAL_SIZE),
                    GB,
                ),
                share
                    .max_upload_files
                    .unwrap_or(DEFAULT_SHARE_UPLOAD_FILE_COUNT),
            )
        } else {
            String::new()
        };
        let single_upload_limit = share
            .max_upload_size
            .map(upload_limit_label)
            .unwrap_or_else(|| format!("global {}", human(settings.max_upload_size)));
        let upload_limit = if share.permission.can_upload() {
            format!(
                "{single_upload_limit}; kumulativ {} / {}; Dateien {} / {}",
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
        share_rows += &format!(
            r#"<article class="vl-share-row"><div class="vl-share-identity"><span class="vl-file-kind" aria-hidden="true"></span><div><strong>{}</strong><span class="vl-muted">/{}</span></div></div><div class="vl-share-url"><code>{}</code><button class="vl-button vl-button--secondary vl-button--small vl-copy-button" type="button" data-copy="{}" aria-label="<vl-i18n key="share.copy_aria"/>"><vl-i18n key="common.copy"/></button></div><div class="vl-share-badges"><span class="vl-badge vl-badge--accent">{}</span><span class="vl-badge vl-badge--{}">{}</span>{}</div><div class="vl-share-quota"><span>{} / {} <vl-i18n key="share.counted_transfers"/></span>{}<small class="vl-muted"><vl-i18n key="share.upload_limit_label"/>: {}</small></div><details class="vl-action-details"><summary class="vl-icon-button"><vl-i18n key="common.actions"/></summary><div class="vl-action-panel"><a class="vl-button vl-button--ghost" href="{}"><vl-i18n key="common.open"/></a><form method="post" action="/admin/shares/{}/toggle"><input type="hidden" name="csrf" value="{}"><button class="vl-button vl-button--ghost">{}</button></form><details><summary><vl-i18n key="account.change_password"/></summary><form method="post" action="/admin/shares/{}/password" class="vl-stack"><input type="hidden" name="csrf" value="{}"><label class="vl-field"><vl-i18n key="account.new_password"/><input type="password" name="password" minlength="{}" maxlength="{}"></label><label class="vl-field"><vl-i18n key="common.confirm"/><input type="password" name="password_confirm"></label><div class="vl-inline-actions"><button class="vl-button"><vl-i18n key="common.set"/></button><button class="vl-button vl-button--secondary" name="remove" value="1"><vl-i18n key="common.remove"/></button></div></form></details>{}<form method="post" action="/admin/shares/{}/delete"><input type="hidden" name="csrf" value="{}"><button class="vl-button vl-button--danger"><vl-i18n key="common.delete"/></button></form></div></details></article>"#,
            esc(display_name),
            esc(&share.relative_path),
            esc(&url),
            esc(&url),
            esc(share_permission_label(&share.permission)),
            status_tone,
            status_label,
            password_badge,
            share.download_count,
            maximum,
            progress,
            esc(&upload_limit),
            esc(&url),
            share.id,
            esc(&session_data.csrf_token),
            if share.active {
                i18n::text(i18n::current_locale(), i18n::DEACTIVATE_COMMON)
            } else {
                i18n::text(i18n::current_locale(), i18n::ACTIVATE)
            },
            share.id,
            esc(&session_data.csrf_token),
            settings.share_password_min_length,
            settings.share_password_max_length,
            upload_settings,
            share.id,
            esc(&session_data.csrf_token),
        );
    }
    if share_rows.is_empty() {
        share_rows = r#"<div class="vl-empty"><strong><vl-i18n key="share.no_links"/></strong><p class="vl-muted"><vl-i18n key="share.adjust_filters"/></p></div>"#.into();
    }
    let previous = (page > 0).then(|| share_list_url(&query, status, sort, page - 1));
    let next = (page + 1 < total_pages).then(|| share_list_url(&query, status, sort, page + 1));
    let body = format!(
        r#"<section class="vl-stat-strip" aria-label="<vl-i18n key="share.overview_aria"/>"><div><strong>{active_count}</strong><span><vl-i18n key="share.active_links"/></span></div><div><strong>{protected_count}</strong><span><vl-i18n key="share.password_protected_lower"/></span></div><div><strong>{}</strong><span><vl-i18n key="files.file"/> · {}</span></div><div><strong>{}</strong><span>ZIP · {}</span></div><div><strong>{}</strong><span><vl-i18n key="files.preview"/> · {}</span></div></section><p class="vl-muted"><vl-i18n key="share.monthly_values"/> {}.</p><section class="vl-panel"><form method="get" class="vl-toolbar"><label class="vl-field vl-search"><span class="vl-sr-only"><vl-i18n key="share.search_links"/></span><input name="q" value="{}" placeholder="<vl-i18n key="share.search_links"/>"></label><label class="vl-field"><span class="vl-sr-only"><vl-i18n key="common.status"/></span><select name="status"><option value="all" {}><vl-i18n key="common.all"/></option><option value="active" {}><vl-i18n key="common.active"/></option><option value="protected" {}><vl-i18n key="common.protected"/></option><option value="expired" {}><vl-i18n key="common.expired"/></option><option value="limit" {}><vl-i18n key="share.limit_reached"/></option><option value="inactive" {}><vl-i18n key="common.inactive"/></option></select></label><label class="vl-field"><span class="vl-sr-only"><vl-i18n key="files.sorting"/></span><select name="sort"><option value="newest" {}><vl-i18n key="files.newest_first"/></option><option value="oldest" {}><vl-i18n key="files.oldest_first"/></option></select></label><button class="vl-button"><vl-i18n key="common.filter"/></button></form><div class="vl-share-list">{share_rows}</div><nav class="vl-pagination" aria-label="<vl-i18n key="common.page_navigation"/>">{}<span><vl-i18n key="common.page_of"/> {} <vl-i18n key="common.of"/> {}</span>{}</nav></section>"#,
        monthly.download,
        esc(&monthly.month),
        monthly.zip_download,
        esc(&monthly.month),
        monthly.preview,
        esc(&monthly.month),
        esc(&statistics_started_label),
        esc(&query),
        selected(status, "all"),
        selected(status, "active"),
        selected(status, "protected"),
        selected(status, "expired"),
        selected(status, "limit"),
        selected(status, "inactive"),
        selected(sort, "newest"),
        selected(sort, "oldest"),
        previous
            .map(|url| format!(
                r#"<a class="vl-button vl-button--ghost" href="{}"><vl-i18n key="common.back"/></a>"#,
                esc(&url)
            ))
            .unwrap_or_default(),
        page + 1,
        total_pages,
        next.map(|url| format!(
            r#"<a class="vl-button vl-button--ghost" href="{}"><vl-i18n key="common.continue"/></a>"#,
            esc(&url)
        ))
        .unwrap_or_default(),
    );
    Ok(Html(admin_page(
        &state,
        PageId::Links,
        &body,
        false,
        &session_data.csrf_token,
    ))
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
        let body = r#"<section class="vl-panel vl-empty"><strong><vl-i18n key="share.select_target"/></strong><p class="vl-muted"><vl-i18n key="share.open_browser"/></p><a class="vl-button" href="/admin"><vl-i18n key="share.to_browser"/></a></section>"#;
        return Ok(Html(admin_page(
            &state,
            PageId::CreateLink,
            body,
            false,
            &session_data.csrf_token,
        )));
    };
    let relative_path = path_security::validate_relative(raw_path)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Zielpfad"))?
        .to_string_lossy()
        .replace('\\', "/");
    let secure_root = state.secure_root.clone();
    let metadata_path = relative_path.clone();
    let metadata = tokio::task::spawn_blocking(move || secure_root.metadata(&metadata_path))
        .await
        .map_err(internal)?
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Zielpfad"))?;
    let is_directory = metadata.is_dir();
    let permission_fields = if is_directory {
        r#"<div class="vl-segmented" role="radiogroup" aria-label="<vl-i18n key="share.permission_aria"/>"><label><input type="radio" name="permission" value="download_only" checked><span><vl-i18n key="share.download_only"/></span></label><label><input type="radio" name="permission" value="upload_only"><span><vl-i18n key="share.upload_only"/></span></label><label><input type="radio" name="permission" value="download_upload"><span><vl-i18n key="share.download_upload"/></span></label></div>"#
    } else {
        r#"<input type="hidden" name="permission" value="download_only"><span class="vl-badge vl-badge--accent"><vl-i18n key="share.download_only"/></span><p class="vl-muted"><vl-i18n key="share.upload_folder_only"/></p>"#
    };
    let overwrite_rule = if !state.config.storage.replacements_allowed() {
        ""
    } else {
        r#"<label class="vl-switch"><input type="checkbox" name="overwrite_allowed" value="1"><span><vl-i18n key="share.existing_replace"/><small><vl-i18n key="share.uploader_confirm"/></small></span></label>"#
    };
    let upload_rules = if is_directory {
        format!(
            r#"<section class="vl-form-section" data-upload-rules><h2><vl-i18n key="share.step_upload"/></h2><div class="vl-form-grid"><label class="vl-field"><vl-i18n key="share.max_file"/><input name="max_upload_size_gb" type="number" min="1" max="{}" step="1" placeholder="Global: {} GB"><small><vl-i18n key="share.empty_global"/></small></label><label class="vl-field"><vl-i18n key="share.cumulative_upload_limit_gb"/><input name="max_upload_total_size_gb" type="number" min="1" step="any" value="{}" required></label><label class="vl-field">Maximale Upload-Dateien<input name="max_upload_files" type="number" min="1" value="{}" required></label>{}</div></section>"#,
            display_limit_unit_floor(crate::config::MAX_UPLOAD_SIZE, GB),
            display_limit_unit_floor(settings.max_upload_size, GB),
            display_limit_unit_ceil(
                DEFAULT_SHARE_UPLOAD_TOTAL_SIZE.max(settings.max_upload_size),
                GB,
            ),
            DEFAULT_SHARE_UPLOAD_FILE_COUNT,
            overwrite_rule,
        )
    } else {
        String::new()
    };
    let url_preview = format!(
        "{}/v/••••••••",
        settings.public_base_url.trim_end_matches('/')
    );
    let alias_pattern = format!(
        "[A-Za-z0-9_-]{{{},{}}}",
        path_security::SHARE_ALIAS_MIN_LENGTH,
        path_security::SHARE_ALIAS_MAX_LENGTH
    );
    let body = format!(
        r#"<div class="vl-create-layout"><form method="post" action="/admin/shares" class="vl-panel vl-stack" data-share-create><input type="hidden" name="csrf" value="{}"><input type="hidden" name="path" value="{}"><input type="hidden" name="expires_tz_offset_minutes" data-tz-offset value="0"><section class="vl-target-card"><div><span class="vl-eyebrow"><vl-i18n key="share.selected_target"/></span><strong>/{}</strong><small class="vl-muted">{}</small></div><a class="vl-button vl-button--ghost" href="/admin"><vl-i18n key="share.change_target"/></a></section><section class="vl-form-section"><h2><vl-i18n key="share.step_permission"/></h2>{permission_fields}</section><section class="vl-form-section"><h2><vl-i18n key="share.step_link"/></h2><div class="vl-form-grid"><label class="vl-field"><vl-i18n key="share.short_alias"/><input name="alias" pattern="{alias_pattern}" data-share-alias><small><vl-i18n key="share.alias_help"/></small></label>{}<label class="vl-field"><vl-i18n key="share.max_transfers"/><input name="max_downloads" type="number" min="1"><small><vl-i18n key="share.empty_unlimited"/></small></label></div></section><section class="vl-form-section"><h2><vl-i18n key="share.step_protection"/></h2><label class="vl-switch"><input type="checkbox" name="password_enabled" value="1" data-password-toggle><span><vl-i18n key="share.password_protection"/><small><vl-i18n key="share.password_enable"/></small></span></label><div class="vl-form-grid" data-password-fields><label class="vl-field"><vl-i18n key="auth.password"/><input name="password" type="password" minlength="{}" maxlength="{}" autocomplete="new-password"></label><label class="vl-field"><vl-i18n key="account.confirm_password"/><input name="password_confirm" type="password" autocomplete="new-password"></label></div></section>{upload_rules}<button class="vl-button vl-button--primary" type="submit"><vl-i18n key="share.create_secure"/></button></form><aside class="vl-panel vl-review-card" data-share-review><h2><vl-i18n key="share.review"/></h2><dl class="vl-review-list"><div><dt><vl-i18n key="common.target"/></dt><dd>/{}</dd></div><div><dt><vl-i18n key="share.permission"/></dt><dd data-review-permission><vl-i18n key="share.download_only"/></dd></div><div><dt><vl-i18n key="auth.password"/></dt><dd data-review-password><vl-i18n key="share.no_password"/></dd></div><div><dt><vl-i18n key="share.limit"/></dt><dd data-review-limit><vl-i18n key="common.unlimited"/></dd></div></dl><div class="vl-field"><span><vl-i18n key="share.url_preview"/></span><code data-review-url>{}</code></div><p class="vl-muted"><vl-i18n key="share.audit_help"/></p></aside></div>"#,
        esc(&session_data.csrf_token),
        esc(&relative_path),
        esc(&relative_path),
        i18n::text(
            i18n::current_locale(),
            if is_directory {
                i18n::FOLDER
            } else {
                i18n::FILE
            }
        ),
        expiry_picker_html(),
        settings.share_password_min_length,
        settings.share_password_max_length,
        esc(&relative_path),
        esc(&url_preview),
    );
    Ok(Html(admin_page(
        &state,
        PageId::CreateLink,
        &body,
        false,
        &session_data.csrf_token,
    )))
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
        .ok_or(AppError(StatusCode::BAD_REQUEST, "Ungültige Berechtigung"))?;
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
            "Passwort und Bestätigung sind für den Passwortschutz verpflichtend",
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
    let storage_guard = state.storage_mutation.clone().lock_owned().await;
    let storage_guard = file_ops::recover_pending_file_operations_with_guard(&state, storage_guard)
        .await
        .map_err(storage_recovery_app_error)?;
    let authority_mutation = ShareAuthorityMutation::from_guard(&state, storage_guard);
    let secure_root = state.secure_root.clone();
    let metadata_path = rel.clone();
    let target_metadata = tokio::task::spawn_blocking(move || secure_root.metadata(&metadata_path))
        .await
        .map_err(internal)?
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Zielpfad"))?;
    if !target_metadata.is_file() && !target_metadata.is_dir() {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Freigaben sind nur für reguläre Dateien oder Ordner erlaubt",
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
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiges Übertragungslimit"))?;
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
                .map(|value| parse_unit_to_bytes(value, GB, "Ungültiges Uploadlimit"))
                .transpose()?;
            let max_upload_total_size = f
                .max_upload_total_size_gb
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| parse_unit_to_bytes(value, GB, "Ungültiges kumulatives Uploadlimit"))
                .transpose()?;
            let max_upload_files = f
                .max_upload_files
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::parse::<u64>)
                .transpose()
                .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiges Upload-Dateilimit"))?;
            (max_upload_size, max_upload_total_size, max_upload_files)
        } else {
            (None, None, None)
        };
    let overwrite_allowed = permission.can_upload() && f.overwrite_allowed.as_deref() == Some("1");
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
                .create(prepared, password_hash, &audit_context)
                .map(drop)
                .map_err(share_service_database_error)
        })
        .await
        .map_err(|error| {
            if error.status == StatusCode::SERVICE_UNAVAILABLE {
                AppError::from(error)
            } else {
                AppError(StatusCode::CONFLICT, "Token oder Alias bereits vorhanden")
            }
        })?;
    Ok(Redirect::to("/admin/shares"))
}

fn share_service_app_error(error: ShareServiceError) -> AppError {
    match error {
        ShareServiceError::InvalidPath => AppError(StatusCode::BAD_REQUEST, "Ungültiger Zielpfad"),
        ShareServiceError::InvalidAlias => AppError(StatusCode::BAD_REQUEST, "Ungültiger Alias"),
        ShareServiceError::ExpirationNotFuture => AppError(
            StatusCode::BAD_REQUEST,
            "Ablaufdatum liegt in der Vergangenheit",
        ),
        ShareServiceError::UploadPermissionRequiresDirectory => AppError(
            StatusCode::BAD_REQUEST,
            "Uploads sind nur für Ordnerlinks erlaubt",
        ),
        ShareServiceError::InvalidDownloadLimit => {
            AppError(StatusCode::BAD_REQUEST, "Ungültiges Übertragungslimit")
        }
        ShareServiceError::InvalidUploadLimit => {
            AppError(StatusCode::BAD_REQUEST, "Ungültiges Uploadlimit")
        }
        ShareServiceError::UploadLimitsRequireDirectoryUpload => AppError(
            StatusCode::BAD_REQUEST,
            "Uploadlimits sind nur für Upload-Freigaben erlaubt",
        ),
        ShareServiceError::InvalidUploadTotalLimit
        | ShareServiceError::UploadTotalBelowSingleLimit => AppError(
            StatusCode::BAD_REQUEST,
            "Das kumulative Uploadlimit ist ungültig",
        ),
        ShareServiceError::InvalidUploadFileLimit => AppError(
            StatusCode::BAD_REQUEST,
            "Das Upload-Dateilimit ist ungültig",
        ),
        ShareServiceError::OverwriteRequiresDirectoryUpload => AppError(
            StatusCode::BAD_REQUEST,
            "Überschreiben ist für diese Freigabe nicht erlaubt",
        ),
        ShareServiceError::OverwriteDisabledForExternalWriters => AppError(
            StatusCode::BAD_REQUEST,
            "Überschreiben ist bei externen Storage-Schreibern deaktiviert",
        ),
        ShareServiceError::PasswordConfirmationRequired => AppError(
            StatusCode::BAD_REQUEST,
            "Passwort und Bestätigung sind für den Passwortschutz verpflichtend",
        ),
        ShareServiceError::PasswordConfirmationMismatch => {
            AppError(StatusCode::BAD_REQUEST, "Passwörter stimmen nicht überein")
        }
        ShareServiceError::InvalidPasswordCharacterLength
        | ShareServiceError::PasswordTooManyBytes => AppError(
            StatusCode::BAD_REQUEST,
            "Freigabepasswort entspricht nicht der Richtlinie",
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
    let sh = database(state.db.clone(), |db| db.list_shares())
        .await?
        .into_iter()
        .find(|v| v.id == id)
        .ok_or(AppError(StatusCode::NOT_FOUND, "Link nicht gefunden"))?;
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
        return Err(AppError(StatusCode::NOT_FOUND, "Link nicht gefunden"));
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
            "Ungültige Upload-Konfliktstrategie",
        ))?
    } else if form.overwrite_allowed.as_deref() == Some("1") {
        UploadConflictStrategy::OverwriteAllowed
    } else {
        UploadConflictStrategy::Reject
    };
    if strategy.can_overwrite() && !state.config.storage.replacements_allowed() {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Ueberschreiben ist bei externen Storage-Schreibern deaktiviert",
        ));
    }
    let authority_mutation = ShareAuthorityMutation::acquire(&state).await;
    let share = database(state.db.clone(), |db| db.list_shares())
        .await?
        .into_iter()
        .find(|share| share.id == id)
        .ok_or(AppError(StatusCode::NOT_FOUND, "Link nicht gefunden"))?;
    if !share.is_directory || !share.permission.can_upload() {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Überschreiben ist nur für Ordnerlinks mit Uploadrecht erlaubt",
        ));
    }
    let total_limit = form
        .max_upload_total_size_gb
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| parse_unit_to_bytes(value, GB, "Ungültiges kumulatives Uploadlimit"))
        .transpose()
        .map_err(|_| {
            AppError(
                StatusCode::BAD_REQUEST,
                "Ungültiges kumulatives Uploadlimit",
            )
        })?
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
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiges Upload-Dateilimit"))?
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
            "Ungültige kumulative Uploadlimits",
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
    let audit_events = [RequiredAuditEvent::new(
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
            return Err(AppError(StatusCode::NOT_FOUND, "Link nicht gefunden"));
        }
        ShareControlsUpdateOutcome::QuotaConflict => {
            return Err(AppError(
                StatusCode::CONFLICT,
                "Uploadlimit wird von laufenden Uploads belegt",
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
    if !database(state.db.clone(), |db| db.list_shares())
        .await?
        .iter()
        .any(|share| share.id == id)
    {
        return Err(AppError(StatusCode::NOT_FOUND, "Link nicht gefunden"));
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
                "Freigabepasswort entspricht nicht der Richtlinie",
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
        return Err(AppError(StatusCode::NOT_FOUND, "Link nicht gefunden"));
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
        return Err(AppError(StatusCode::NOT_FOUND, "Link nicht gefunden"));
    }
    Ok(Redirect::to("/admin/shares"))
}
