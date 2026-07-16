use axum::{
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, Redirect},
};
use serde::Deserialize;

use super::{
    common::{display_limit_unit_floor, format_audit_time, parse_unit_to_bytes},
    rendering::{admin_page, esc, PageId, GB, MB},
    AppError, Result,
};
use crate::{
    config::MAX_TEXT_PREVIEW_SIZE,
    db::{
        AuditClientIpDeletionOutcome, AuditContext, AuditSortColumn, AuditSortDirection, Session,
    },
    http_auth::{
        commit_runtime_settings, csrf, database, enabled_audit_client_ip, required_database,
        runtime_settings, session, MissingSession,
    },
    i18n::{self},
    runtime::RuntimeSettings,
    AppState,
};

#[derive(Deserialize)]
pub(super) struct SettingsForm {
    csrf: String,
    public_base_url: String,
    max_upload_size_gb: String,
    blocked_extensions: String,
    share_password_min_length: String,
    share_password_max_length: Option<String>,
    share_unlock_minutes: String,
    max_zip_size_gb: String,
    max_zip_files: String,
    max_search_entries: String,
    max_search_results: String,
    max_preview_size_mb: String,
    preview_extensions: String,
    image_preview_extensions: String,
    pdf_preview_enabled: Option<String>,
    max_media_preview_size_mb: String,
    audit_client_ip_enabled: Option<String>,
}

pub(super) async fn settings_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let settings = runtime_settings(&state);
    let ip_count = database(state.db.clone(), |db| db.count_audit_client_ips()).await?;
    let public_url_locked = state.config.server.mode == crate::config::ServerMode::StandaloneTls
        && state.config.tls.certificate_source == crate::config::CertificateSource::LetsEncrypt;
    let body = settings_form(&session, &settings, ip_count, "", public_url_locked);
    Ok(Html(admin_page(
        &state,
        PageId::Settings,
        &body,
        false,
        &session.csrf_token,
    )))
}

fn field_info_label(label: &str, help_key: &str, tooltip_id: &str) -> String {
    format!(
        r#"<span class="vl-field-label">{label}<span class="vl-field-info" role="button" tabindex="0" aria-label='<vl-i18n key="setup.field_info"/>' aria-describedby="{tooltip_id}"><span aria-hidden="true">i</span><span class="vl-field-tooltip" id="{tooltip_id}" role="tooltip"><vl-i18n key="{help_key}"/></span></span></span>"#
    )
}

pub(super) fn settings_form(
    session: &Session,
    settings: &RuntimeSettings,
    audit_ip_count: u64,
    message: &str,
    public_url_locked: bool,
) -> String {
    let message = if message.is_empty() {
        String::new()
    } else {
        format!(
            r#"<p class="vl-muted">{}</p>"#,
            esc(&i18n::text_from_german(i18n::current_locale(), message))
        )
    };
    let purge_link = if !settings.audit_client_ip_enabled && audit_ip_count > 0 {
        format!(
            r#"<p><a class="vl-button vl-button--danger" href="/admin/settings/audit-ips/delete">{} <vl-i18n key="settings.delete_ips"/></a></p>"#,
            audit_ip_count
        )
    } else {
        String::new()
    };
    let public_url_attributes = if public_url_locked {
        "readonly aria-readonly=\"true\""
    } else {
        ""
    };
    let public_url_hint = if public_url_locked {
        "Im Let's-Encrypt-Modus wird diese URL durch die statische TLS-Konfiguration festgelegt."
    } else {
        ""
    };
    let public_base_url_label = field_info_label(
        "Public Base URL",
        "settings.public_base_url_help",
        "settings-help-public-base-url",
    );
    let upload_limit_label = field_info_label(
        r#"<vl-i18n key="settings.upload_limit"/>"#,
        "settings.upload_limit_help",
        "settings-help-upload-limit",
    );
    let blocked_extensions_label = field_info_label(
        r#"<vl-i18n key="settings.blocked"/>"#,
        "settings.blocked_help",
        "settings-help-blocked-extensions",
    );
    let password_min_label = field_info_label(
        r#"<vl-i18n key="settings.password_min"/>"#,
        "settings.password_min_help",
        "settings-help-password-min",
    );
    let password_max_label = field_info_label(
        r#"<vl-i18n key="settings.password_max"/>"#,
        "settings.password_max_help",
        "settings-help-password-max",
    );
    let unlock_minutes_label = field_info_label(
        r#"<vl-i18n key="settings.unlock_minutes"/>"#,
        "settings.unlock_minutes_help",
        "settings-help-unlock-minutes",
    );
    let zip_gb_label = field_info_label(
        r#"<vl-i18n key="settings.zip_gb"/>"#,
        "settings.zip_gb_help",
        "settings-help-zip-gb",
    );
    let zip_files_label = field_info_label(
        r#"<vl-i18n key="settings.zip_files"/>"#,
        "settings.zip_files_help",
        "settings-help-zip-files",
    );
    let search_entries_label = field_info_label(
        r#"<vl-i18n key="settings.search_entries"/>"#,
        "settings.search_entries_help",
        "settings-help-search-entries",
    );
    let search_results_label = field_info_label(
        r#"<vl-i18n key="settings.search_results"/>"#,
        "settings.search_results_help",
        "settings-help-search-results",
    );
    let text_preview_label = field_info_label(
        r#"<vl-i18n key="settings.text_preview"/>"#,
        "settings.text_preview_help",
        "settings-help-text-preview",
    );
    let text_extensions_label = field_info_label(
        r#"<vl-i18n key="settings.text_extensions"/>"#,
        "settings.text_extensions_help",
        "settings-help-text-extensions",
    );
    let media_preview_label = field_info_label(
        r#"<vl-i18n key="settings.media_preview"/>"#,
        "settings.media_preview_help",
        "settings-help-media-preview",
    );
    let image_extensions_label = field_info_label(
        r#"<vl-i18n key="settings.image_extensions"/>"#,
        "settings.image_extensions_help",
        "settings-help-image-extensions",
    );
    let pdf_preview_label = field_info_label(
        r#"<vl-i18n key="settings.pdf_active"/>"#,
        "settings.pdf_help",
        "settings-help-pdf-preview",
    );
    let audit_ip_label = field_info_label(
        r#"<vl-i18n key="settings.audit_ip"/>"#,
        "settings.audit_ip_help",
        "settings-help-audit-ip",
    );
    format!(
        r#"<section class="vl-panel"><h2><vl-i18n key="settings.runtime"/></h2>{message}<p class="vl-muted"><vl-i18n key="settings.runtime_help"/></p><form method="post" class="vl-form-grid"><input type="hidden" name="csrf" value="{}"><label>{public_base_url_label}<input name="public_base_url" value="{}" {} required><small>{}</small></label><label>{upload_limit_label}<input name="max_upload_size_gb" type="number" min="1" step="1" value="{}" required></label><label>{blocked_extensions_label}<input name="blocked_extensions" value="{}"></label><label>{password_min_label}<input name="share_password_min_length" type="number" min="8" value="{}" required></label><label>{password_max_label}<input name="share_password_max_length" type="number" min="8" value="{}" required></label><label>{unlock_minutes_label}<input name="share_unlock_minutes" type="number" min="1" value="{}" required></label><label>{zip_gb_label}<input name="max_zip_size_gb" type="number" min="0" step="1" value="{}" required></label><label>{zip_files_label}<input name="max_zip_files" type="number" min="0" value="{}" required></label><label>{search_entries_label}<input name="max_search_entries" type="number" min="1" value="{}" required></label><label>{search_results_label}<input name="max_search_results" type="number" min="1" value="{}" required></label><label>{text_preview_label}<input name="max_preview_size_mb" type="number" min="1" step="1" value="{}" required></label><label>{text_extensions_label}<input name="preview_extensions" value="{}" required></label><label>{media_preview_label}<input name="max_media_preview_size_mb" type="number" min="1" step="1" value="{}" required></label><label>{image_extensions_label}<input name="image_preview_extensions" value="{}"></label><label class="vl-toggle"><input type="checkbox" name="pdf_preview_enabled" {}><span>{pdf_preview_label}</span></label><label class="vl-toggle"><input type="checkbox" name="audit_client_ip_enabled" {}><span>{audit_ip_label}</span></label><button class="vl-button"><vl-i18n key="common.save"/></button></form>{purge_link}</section>"#,
        esc(&session.csrf_token),
        esc(&settings.public_base_url),
        public_url_attributes,
        public_url_hint,
        display_limit_unit_floor(settings.max_upload_size, GB),
        esc(&settings.blocked_extensions.join(",")),
        settings.share_password_min_length,
        settings.share_password_max_length,
        settings.share_unlock_minutes,
        display_limit_unit_floor(settings.max_zip_size, GB),
        settings.max_zip_files,
        settings.max_search_entries,
        settings.max_search_results,
        display_limit_unit_floor(settings.max_preview_size, MB),
        esc(&settings.preview_extensions.join(",")),
        display_limit_unit_floor(settings.max_media_preview_size, MB),
        esc(&settings.image_preview_extensions.join(",")),
        if settings.pdf_preview_enabled {
            "checked"
        } else {
            ""
        },
        if settings.audit_client_ip_enabled {
            "checked"
        } else {
            ""
        },
    )
    .replace(
        r#"name="max_preview_size_mb" type="number" min="1""#,
        &format!(
            r#"name="max_preview_size_mb" type="number" min="1" max="{}""#,
            MAX_TEXT_PREVIEW_SIZE / MB
        ),
    )
    .replace(
        r#"name="max_upload_size_gb" type="number" min="1""#,
        &format!(
            r#"name="max_upload_size_gb" type="number" min="1" max="{}""#,
            display_limit_unit_floor(crate::config::MAX_UPLOAD_SIZE, GB)
        ),
    )
}

pub(super) async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SettingsForm>,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    let mut next = runtime_settings(&state);
    let max_upload_size =
        parse_unit_to_bytes(&form.max_upload_size_gb, GB, "Ungültiges Uploadlimit")?.to_string();
    let max_zip_size = if form.max_zip_size_gb.trim() == "0" {
        "0".to_string()
    } else {
        parse_unit_to_bytes(&form.max_zip_size_gb, GB, "Ungültiges ZIP-Limit")?.to_string()
    };
    let max_preview_size =
        parse_unit_to_bytes(&form.max_preview_size_mb, MB, "Ungültiges Preview-Limit")?.to_string();
    let max_media_preview_size = parse_unit_to_bytes(
        &form.max_media_preview_size_mb,
        MB,
        "Ungültiges Media-Preview-Limit",
    )?
    .to_string();
    let share_password_max_length = form.share_password_max_length.unwrap_or_default();
    let entries = [
        ("public_base_url", form.public_base_url.as_str()),
        ("max_upload_size", max_upload_size.as_str()),
        ("blocked_extensions", form.blocked_extensions.as_str()),
        (
            "share_password_min_length",
            form.share_password_min_length.as_str(),
        ),
        (
            "share_password_max_length",
            share_password_max_length.as_str(),
        ),
        ("share_unlock_minutes", form.share_unlock_minutes.as_str()),
        ("max_zip_size", max_zip_size.as_str()),
        ("max_zip_files", form.max_zip_files.as_str()),
        ("max_search_entries", form.max_search_entries.as_str()),
        ("max_search_results", form.max_search_results.as_str()),
        ("max_preview_size", max_preview_size.as_str()),
        ("preview_extensions", form.preview_extensions.as_str()),
        (
            "image_preview_extensions",
            form.image_preview_extensions.as_str(),
        ),
        (
            "pdf_preview_enabled",
            if form.pdf_preview_enabled.is_some() {
                "true"
            } else {
                "false"
            },
        ),
        ("max_media_preview_size", max_media_preview_size.as_str()),
        (
            "audit_client_ip_enabled",
            if form.audit_client_ip_enabled.is_some() {
                "true"
            } else {
                "false"
            },
        ),
    ];
    next.apply_many(entries)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültige Einstellung"))?;
    if state.config.server.production_mode
        && url::Url::parse(&next.public_base_url)
            .ok()
            .is_none_or(|url| url.scheme() != "https")
    {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Production public_base_url muss HTTPS verwenden",
        ));
    }
    let admin_id = session.admin_id;
    let previous = runtime_settings(&state);
    let actor = session.username.clone();
    let changed = previous.changed_keys(&next);
    commit_runtime_settings(
        &state,
        next.clone(),
        admin_id,
        actor,
        format!("changed_keys={}", changed.join(",")),
    )
    .await?;
    let ip_count = database(state.db.clone(), |db| db.count_audit_client_ips()).await?;
    Ok(Html(admin_page(
        &state,
        PageId::Settings,
        &settings_form(
            &session,
            &next,
            ip_count,
            "Einstellungen gespeichert.",
            state.config.server.mode == crate::config::ServerMode::StandaloneTls
                && state.config.tls.certificate_source
                    == crate::config::CertificateSource::LetsEncrypt,
        ),
        false,
        &session.csrf_token,
    )))
}

#[derive(Deserialize)]
pub(super) struct DeleteAuditIpsForm {
    csrf: String,
    confirmation: String,
}

pub(super) async fn audit_ips_delete_confirmation(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    if runtime_settings(&state).audit_client_ip_enabled {
        return Err(AppError(
            StatusCode::CONFLICT,
            "IP-Erfassung muss vor dem Löschen deaktiviert werden",
        ));
    }
    let count = database(state.db.clone(), |db| db.count_audit_client_ips()).await?;
    let body = format!(
        r#"<section class="vl-panel vl-confirm-card"><h2><vl-i18n key="settings.delete_ip_data"/></h2><p><vl-i18n key="settings.values_prefix"/> <strong>{count}</strong> <vl-i18n key="settings.delete_ip_values"/></p><form method="post" action="/admin/settings/audit-ips/delete" class="vl-stack"><input type="hidden" name="csrf" value="{}"><label class="vl-field"><vl-i18n key="settings.enter_confirm"/> <code>IP-DATEN LÖSCHEN</code><input name="confirmation" autocomplete="off" required></label><div class="vl-inline-actions"><button class="vl-button vl-button--danger"><vl-i18n key="settings.delete_ip_action"/></button><a class="vl-button vl-button--secondary" href="/admin/settings"><vl-i18n key="common.cancel"/></a></div></form></section>"#,
        esc(&session.csrf_token),
    );
    Ok(Html(admin_page(
        &state,
        PageId::Settings,
        &body,
        false,
        &session.csrf_token,
    )))
}

pub(super) async fn delete_audit_ips_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeleteAuditIpsForm>,
) -> Result<Redirect> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    if form.confirmation != "IP-DATEN LÖSCHEN" {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Exakte Bestätigung IP-DATEN LÖSCHEN erforderlich",
        ));
    }
    let fallback_logging_enabled = runtime_settings(&state).audit_client_ip_enabled;
    let audit_actor = session.username;
    let audit_client_ip = enabled_audit_client_ip(&state);
    let audit_context = AuditContext::new(audit_actor, audit_client_ip);
    let outcome = required_database(state.db.clone(), move |db| {
        db.delete_audit_client_ips_if_disabled_and_audit(fallback_logging_enabled, &audit_context)
    })
    .await?;
    let AuditClientIpDeletionOutcome::Deleted(_) = outcome else {
        return Err(AppError(
            StatusCode::CONFLICT,
            "IP-Erfassung muss vor dem Löschen deaktiviert werden",
        ));
    };
    Ok(Redirect::to("/admin/settings"))
}

fn audit_sort_column(value: Option<&str>) -> AuditSortColumn {
    match value {
        Some("user") => AuditSortColumn::Actor,
        Some("action") => AuditSortColumn::Action,
        Some("object") => AuditSortColumn::Object,
        Some("detail") => AuditSortColumn::Detail,
        Some("client_ip") => AuditSortColumn::ClientIp,
        _ => AuditSortColumn::Time,
    }
}

fn audit_sort_column_value(column: AuditSortColumn) -> &'static str {
    match column {
        AuditSortColumn::Time => "time",
        AuditSortColumn::Actor => "user",
        AuditSortColumn::Action => "action",
        AuditSortColumn::Object => "object",
        AuditSortColumn::Detail => "detail",
        AuditSortColumn::ClientIp => "client_ip",
    }
}

fn default_audit_sort_direction(column: AuditSortColumn) -> AuditSortDirection {
    if column == AuditSortColumn::Time {
        AuditSortDirection::Descending
    } else {
        AuditSortDirection::Ascending
    }
}

fn audit_sort_direction(value: Option<&str>, column: AuditSortColumn) -> AuditSortDirection {
    match value {
        Some("asc") => AuditSortDirection::Ascending,
        Some("desc") => AuditSortDirection::Descending,
        _ => default_audit_sort_direction(column),
    }
}

fn audit_sort_direction_value(direction: AuditSortDirection) -> &'static str {
    match direction {
        AuditSortDirection::Ascending => "asc",
        AuditSortDirection::Descending => "desc",
    }
}

fn toggled_audit_sort_direction(direction: AuditSortDirection) -> AuditSortDirection {
    match direction {
        AuditSortDirection::Ascending => AuditSortDirection::Descending,
        AuditSortDirection::Descending => AuditSortDirection::Ascending,
    }
}

fn audit_page_href(
    action: &str,
    column: AuditSortColumn,
    direction: AuditSortDirection,
    page: usize,
) -> String {
    let action = percent_encoding::utf8_percent_encode(action, percent_encoding::NON_ALPHANUMERIC);
    format!(
        "/admin/audit?action={action}&sort={}&direction={}&page={page}",
        audit_sort_column_value(column),
        audit_sort_direction_value(direction),
    )
}

fn audit_sort_header(
    class_name: &str,
    label: &str,
    column: AuditSortColumn,
    current_column: AuditSortColumn,
    current_direction: AuditSortDirection,
    action: &str,
) -> String {
    let active = column == current_column;
    let direction = if active {
        current_direction
    } else {
        default_audit_sort_direction(column)
    };
    let next_direction = if active {
        toggled_audit_sort_direction(direction)
    } else {
        direction
    };
    let aria_sort = if active {
        match direction {
            AuditSortDirection::Ascending => "ascending",
            AuditSortDirection::Descending => "descending",
        }
    } else {
        "none"
    };
    let indicator = if active {
        match direction {
            AuditSortDirection::Ascending => "↑",
            AuditSortDirection::Descending => "↓",
        }
    } else {
        ""
    };
    let href = esc(&audit_page_href(action, column, next_direction, 0));
    format!(
        r#"<th class="{class_name}" aria-sort="{aria_sort}"><a class="vl-audit-sort" href="{href}">{label}<span class="vl-audit-sort__indicator" aria-hidden="true">{indicator}</span></a></th>"#
    )
}

#[derive(Default, Deserialize)]
pub(super) struct AuditQuery {
    page: Option<usize>,
    action: Option<String>,
    sort: Option<String>,
    direction: Option<String>,
}

pub(super) async fn audit_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let settings = runtime_settings(&state);
    let client_ip_enabled = settings.audit_client_ip_enabled;
    let requested_page = query.page.unwrap_or(0).min(1_000_000);
    let sort_column = audit_sort_column(query.sort.as_deref());
    let sort_direction = audit_sort_direction(query.direction.as_deref(), sort_column);
    let action = query
        .action
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_string());
    let action_for_db = action.clone();
    let (events, total, page_number) = database(state.db.clone(), move |db| {
        let total = db.count_audit(action_for_db.as_deref())?;
        let total_pages = total.div_ceil(100).max(1);
        let page_number = requested_page.min(total_pages - 1);
        let events = db.list_audit_sorted(
            action_for_db.as_deref(),
            100,
            page_number * 100,
            sort_column,
            sort_direction,
        )?;
        Ok((events, total, page_number))
    })
    .await?;
    let total_pages = total.div_ceil(100).max(1);
    let has_next = page_number + 1 < total_pages;
    let mut rows = String::new();
    for event in events {
        let client_ip = if client_ip_enabled {
            format!(
                r#"<td class="vl-audit-ip" data-label="Client IP">{}</td>"#,
                event.client_ip.as_deref().map(esc).unwrap_or_default()
            )
        } else {
            String::new()
        };
        rows += &format!(
            r#"<tr><td class="vl-audit-time" data-label="<vl-i18n key="common.time"/>">{}</td><td class="vl-audit-user" data-label="User">{}</td><td class="vl-audit-action" data-label="<vl-i18n key="common.action"/>"><code>{}</code></td><td class="vl-audit-object" data-label="<vl-i18n key="common.object"/>">{}</td><td class="vl-audit-detail" data-label="<vl-i18n key="common.detail"/>">{}</td>{client_ip}</tr>"#,
            esc(&format_audit_time(&event.occurred_at)),
            esc(&event.actor),
            esc(&event.action),
            event.object_id.as_deref().map(esc).unwrap_or_default(),
            event.detail.as_deref().map(esc).unwrap_or_default()
        );
    }
    let filter_value = action.as_deref().unwrap_or("");
    let previous = if page_number > 0 {
        let href = esc(&audit_page_href(
            filter_value,
            sort_column,
            sort_direction,
            page_number - 1,
        ));
        format!(
            r#"<a class="vl-button vl-button--ghost" href="{href}"><vl-i18n key="common.back"/></a>"#
        )
    } else {
        String::new()
    };
    let next = if has_next {
        let href = esc(&audit_page_href(
            filter_value,
            sort_column,
            sort_direction,
            page_number + 1,
        ));
        format!(
            r#"<a class="vl-button vl-button--ghost" href="{href}"><vl-i18n key="common.continue"/></a>"#
        )
    } else {
        String::new()
    };
    let ip_header = if client_ip_enabled {
        audit_sort_header(
            "vl-audit-ip",
            "Client-IP",
            AuditSortColumn::ClientIp,
            sort_column,
            sort_direction,
            filter_value,
        )
    } else {
        String::new()
    };
    let table_header = format!(
        "{}{}{}{}{}{ip_header}",
        audit_sort_header(
            "vl-audit-time",
            r#"<vl-i18n key="common.time"/>"#,
            AuditSortColumn::Time,
            sort_column,
            sort_direction,
            filter_value,
        ),
        audit_sort_header(
            "vl-audit-user",
            "User",
            AuditSortColumn::Actor,
            sort_column,
            sort_direction,
            filter_value,
        ),
        audit_sort_header(
            "vl-audit-action",
            r#"<vl-i18n key="common.action"/>"#,
            AuditSortColumn::Action,
            sort_column,
            sort_direction,
            filter_value,
        ),
        audit_sort_header(
            "vl-audit-object",
            r#"<vl-i18n key="common.object"/>"#,
            AuditSortColumn::Object,
            sort_column,
            sort_direction,
            filter_value,
        ),
        audit_sort_header(
            "vl-audit-detail",
            r#"<vl-i18n key="common.detail"/>"#,
            AuditSortColumn::Detail,
            sort_column,
            sort_direction,
            filter_value,
        ),
    );
    let sort_value = audit_sort_column_value(sort_column);
    let direction_value = audit_sort_direction_value(sort_direction);
    let url_scheme = url::Url::parse(&settings.public_base_url)
        .ok()
        .map(|url| url.scheme().to_uppercase())
        .unwrap_or_else(|| i18n::text(i18n::current_locale(), i18n::UNKNOWN).into());
    let trusted_proxy_count = state.config.reverse_proxy.trusted_proxies.len();
    let body = format!(
        r#"<div class="vl-audit-layout"><section class="vl-panel"><div class="vl-panel-head"><div><p class="vl-eyebrow"><vl-i18n key="audit.traceability"/></p><h2><vl-i18n key="audit.events"/></h2></div><form method="get" class="vl-inline-actions"><input type="hidden" name="sort" value="{sort_value}"><input type="hidden" name="direction" value="{direction_value}"><label class="vl-field"><span class="vl-sr-only"><vl-i18n key="audit.action_filter"/></span><input name="action" value="{}" placeholder="<vl-i18n key="audit.filter_action"/>"></label><button class="vl-button"><vl-i18n key="common.filter"/></button></form></div><div class="vl-table-wrap"><table class="vl-data-table vl-audit-table"><thead><tr>{table_header}</tr></thead><tbody>{rows}</tbody></table></div><nav class="vl-pagination" aria-label="<vl-i18n key="audit.pages"/>">{previous}<span><vl-i18n key="common.page_of"/> {} <vl-i18n key="common.of"/> {}</span>{next}</nav></section><aside class="vl-panel vl-security-facts"><p class="vl-eyebrow"><vl-i18n key="audit.security_status"/></p><h2><vl-i18n key="audit.proven_config"/></h2><dl><div><dt>MFA</dt><dd><vl-i18n key="audit.mfa_required"/></dd></div><div><dt><vl-i18n key="audit.server_mode"/></dt><dd>{:?}</dd></div><div><dt><vl-i18n key="audit.url_scheme"/></dt><dd>{}</dd></div><div><dt>Trusted Proxies</dt><dd>{}</dd></div><div><dt><vl-i18n key="audit.ip_capture"/></dt><dd>{}</dd></div><div><dt><vl-i18n key="audit.logging"/></dt><dd><vl-i18n key="audit.structured"/></dd></div></dl></aside></div>"#,
        esc(filter_value),
        page_number + 1,
        total_pages,
        state.config.server.mode,
        esc(&url_scheme),
        trusted_proxy_count,
        if client_ip_enabled {
            i18n::text(i18n::current_locale(), i18n::ENABLED)
        } else {
            i18n::text(i18n::current_locale(), i18n::DISABLED)
        },
    );
    Ok(Html(admin_page(
        &state,
        PageId::AuditSecurity,
        &body,
        false,
        &session.csrf_token,
    )))
}
