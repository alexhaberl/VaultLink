use askama::Template;
use axum::{
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, Redirect},
};
use serde::{Deserialize, Serialize};

use super::{
    common::{display_limit_unit_floor, format_audit_time, parse_unit_to_bytes},
    rendering::{PageId, GB, MB},
    templates, AppError, Result,
};

#[derive(Template)]
#[template(path = "web/settings/form.html")]
pub(super) struct SettingsFormTemplate {
    csrf_token: String,
    message: Option<String>,
    public_base_url: String,
    public_url_locked: bool,
    public_url_hint: &'static str,
    max_upload_size_gb: String,
    max_upload_size_gb_ceiling: String,
    blocked_extensions: String,
    share_password_min_length: usize,
    share_password_max_length: usize,
    share_unlock_minutes: i64,
    max_zip_size_gb: String,
    max_zip_files: usize,
    max_search_entries: usize,
    max_search_results: usize,
    max_preview_size_mb: String,
    max_text_preview_size_mb: u64,
    preview_extensions: String,
    max_media_preview_size_mb: String,
    image_preview_extensions: String,
    pdf_preview_enabled: bool,
    audit_client_ip_enabled: bool,
    show_purge_link: bool,
    audit_ip_count: u64,
}

#[derive(Template)]
#[template(path = "web/settings/delete_audit_ips.html")]
struct DeleteAuditIpsTemplate<'a> {
    count: u64,
    csrf_token: &'a str,
}

struct AuditHeaderView {
    class_name: &'static str,
    aria_sort: &'static str,
    action: String,
    sort: &'static str,
    direction: &'static str,
    label_key: Option<&'static str>,
    label: &'static str,
    indicator: &'static str,
}

struct AuditRowView {
    time: String,
    actor: String,
    action: String,
    object_id: String,
    detail: String,
    client_ip: String,
}

#[derive(Template)]
#[template(path = "web/settings/audit.html")]
struct AuditPageTemplate {
    pagination_reset: bool,
    sort_value: &'static str,
    direction_value: &'static str,
    filter_value: String,
    filter_encoded: String,
    headers: Vec<AuditHeaderView>,
    rows: Vec<AuditRowView>,
    client_ip_enabled: bool,
    previous_page: Option<usize>,
    next_page: Option<usize>,
    previous_cursor: Option<String>,
    next_cursor: Option<String>,
    page_number: usize,
    total_pages: usize,
    server_mode: String,
    url_scheme: String,
    trusted_proxy_count: usize,
    ip_capture_label: &'static str,
}
use crate::{
    config::MAX_TEXT_PREVIEW_SIZE,
    db::{
        AuditClientIpDeletionOutcome, AuditContext, AuditCursor, AuditEvent, AuditKeysetPosition,
        AuditSortColumn, AuditSortDirection, Session,
    },
    http_auth::{
        commit_runtime_settings, csrf, database, enabled_audit_client_ip, mfa_session,
        required_mfa_audit_database, runtime_settings, session, MissingSession,
    },
    i18n::{self},
    runtime::RuntimeSettings,
    SettingsRouteState,
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
    State(state): State<SettingsRouteState>,
    headers: HeaderMap,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let settings = runtime_settings(&state);
    let ip_count = database(state.db().clone(), |db| db.count_audit_client_ips()).await?;
    let public_url_locked = state.config().server.mode == crate::config::ServerMode::StandaloneTls
        && state.config().tls.certificate_source == crate::config::CertificateSource::LetsEncrypt;
    let body = settings_form_template(&session, &settings, ip_count, "", public_url_locked);
    Ok(Html(templates::admin_page(
        &state,
        PageId::Settings,
        &body,
        false,
        &session.csrf_token,
        true,
    )?))
}

pub(super) fn settings_form_template(
    session: &Session,
    settings: &RuntimeSettings,
    audit_ip_count: u64,
    message: &str,
    public_url_locked: bool,
) -> SettingsFormTemplate {
    SettingsFormTemplate {
        csrf_token: session.csrf_token.clone(),
        message: (!message.is_empty())
            .then(|| i18n::localized_text(i18n::current_locale(), message).into_owned()),
        public_base_url: settings.public_base_url.clone(),
        public_url_locked,
        public_url_hint: if public_url_locked {
            i18n::text(
                i18n::current_locale(),
                i18n::SETTINGS_PUBLIC_URL_LOCKED_HINT,
            )
        } else {
            ""
        },
        max_upload_size_gb: display_limit_unit_floor(settings.max_upload_size, GB),
        max_upload_size_gb_ceiling: display_limit_unit_floor(crate::config::MAX_UPLOAD_SIZE, GB),
        blocked_extensions: settings.blocked_extensions.join(","),
        share_password_min_length: settings.share_password_min_length,
        share_password_max_length: settings.share_password_max_length,
        share_unlock_minutes: settings.share_unlock_minutes,
        max_zip_size_gb: display_limit_unit_floor(settings.max_zip_size, GB),
        max_zip_files: settings.max_zip_files,
        max_search_entries: settings.max_search_entries,
        max_search_results: settings.max_search_results,
        max_preview_size_mb: display_limit_unit_floor(settings.max_preview_size, MB),
        max_text_preview_size_mb: MAX_TEXT_PREVIEW_SIZE / MB,
        preview_extensions: settings.preview_extensions.join(","),
        max_media_preview_size_mb: display_limit_unit_floor(settings.max_media_preview_size, MB),
        image_preview_extensions: settings.image_preview_extensions.join(","),
        pdf_preview_enabled: settings.pdf_preview_enabled,
        audit_client_ip_enabled: settings.audit_client_ip_enabled,
        show_purge_link: !settings.audit_client_ip_enabled && audit_ip_count > 0,
        audit_ip_count,
    }
}

pub(super) async fn update_settings(
    State(state): State<SettingsRouteState>,
    headers: HeaderMap,
    Form(form): Form<SettingsForm>,
) -> Result<Html<String>> {
    let session = mfa_session(&state, &headers, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    let mut next = runtime_settings(&state);
    let max_upload_size =
        parse_unit_to_bytes(&form.max_upload_size_gb, GB, "Invalid upload limit")?.to_string();
    let max_zip_size = if form.max_zip_size_gb.trim() == "0" {
        "0".to_string()
    } else {
        parse_unit_to_bytes(&form.max_zip_size_gb, GB, "Invalid ZIP limit")?.to_string()
    };
    let max_preview_size =
        parse_unit_to_bytes(&form.max_preview_size_mb, MB, "Invalid preview limit")?.to_string();
    let max_media_preview_size = parse_unit_to_bytes(
        &form.max_media_preview_size_mb,
        MB,
        "Invalid media preview limit",
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
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid setting"))?;
    if state.config().server.production_mode
        && url::Url::parse(&next.public_base_url)
            .ok()
            .is_none_or(|url| url.scheme() != "https")
    {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Production public_base_url must use HTTPS",
        ));
    }
    let previous = runtime_settings(&state);
    let actor = session.username.clone();
    let response_session = (*session).clone();
    let changed = previous.changed_keys(&next);
    super::session_bound(crate::db::release_session_audited(
        commit_runtime_settings(
            &state,
            session,
            next.clone(),
            actor,
            format!("changed_keys={}", changed.join(",")),
        )
        .await?,
    ))?;
    let ip_count = database(state.db().clone(), |db| db.count_audit_client_ips()).await?;
    let body = settings_form_template(
        &response_session,
        &next,
        ip_count,
        "Settings saved.",
        state.config().server.mode == crate::config::ServerMode::StandaloneTls
            && state.config().tls.certificate_source
                == crate::config::CertificateSource::LetsEncrypt,
    );
    Ok(Html(templates::admin_page(
        &state,
        PageId::Settings,
        &body,
        false,
        &response_session.csrf_token,
        true,
    )?))
}

#[derive(Deserialize)]
pub(super) struct DeleteAuditIpsForm {
    csrf: String,
    confirmation: String,
}

pub(super) async fn audit_ips_delete_confirmation(
    State(state): State<SettingsRouteState>,
    headers: HeaderMap,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    if runtime_settings(&state).audit_client_ip_enabled {
        return Err(AppError(
            StatusCode::CONFLICT,
            "IP capture must be disabled before deletion",
        ));
    }
    let count = database(state.db().clone(), |db| db.count_audit_client_ips()).await?;
    let body = DeleteAuditIpsTemplate {
        count,
        csrf_token: &session.csrf_token,
    };
    Ok(Html(templates::admin_page(
        &state,
        PageId::Settings,
        &body,
        false,
        &session.csrf_token,
        true,
    )?))
}

pub(super) async fn delete_audit_ips_ui(
    State(state): State<SettingsRouteState>,
    headers: HeaderMap,
    Form(form): Form<DeleteAuditIpsForm>,
) -> Result<Redirect> {
    let session = mfa_session(&state, &headers, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    if form.confirmation != "IP-DATEN LÖSCHEN" {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Exact confirmation IP-DATEN LÖSCHEN required",
        ));
    }
    let fallback_logging_enabled = runtime_settings(&state).audit_client_ip_enabled;
    let audit_client_ip = enabled_audit_client_ip(&state);
    let outcome =
        required_mfa_audit_database(state.db().clone(), session, move |db, session, proof| {
            let audit_context = AuditContext::new(session.username, audit_client_ip);
            db.delete_audit_client_ips_for_mfa_session(
                &proof,
                fallback_logging_enabled,
                &audit_context,
            )
        })
        .await?;
    let outcome = super::session_bound(outcome)?;
    let AuditClientIpDeletionOutcome::Deleted(_) = outcome else {
        return Err(AppError(
            StatusCode::CONFLICT,
            "IP capture must be disabled before deletion",
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

fn audit_sort_header(
    class_name: &'static str,
    label_key: Option<&'static str>,
    label: &'static str,
    column: AuditSortColumn,
    current_column: AuditSortColumn,
    current_direction: AuditSortDirection,
    action: &str,
) -> AuditHeaderView {
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
    AuditHeaderView {
        class_name,
        aria_sort,
        action: percent_encoding::utf8_percent_encode(action, percent_encoding::NON_ALPHANUMERIC)
            .to_string(),
        sort: audit_sort_column_value(column),
        direction: audit_sort_direction_value(next_direction),
        label_key,
        label,
        indicator,
    }
}

fn audit_headers(
    current_column: AuditSortColumn,
    current_direction: AuditSortDirection,
    action: &str,
    include_client_ip: bool,
) -> Vec<AuditHeaderView> {
    let definitions = [
        (
            "vl-audit-time",
            Some("common.time"),
            "",
            AuditSortColumn::Time,
        ),
        ("vl-audit-user", None, "User", AuditSortColumn::Actor),
        (
            "vl-audit-action",
            Some("common.action"),
            "",
            AuditSortColumn::Action,
        ),
        (
            "vl-audit-object",
            Some("common.object"),
            "",
            AuditSortColumn::Object,
        ),
        (
            "vl-audit-detail",
            Some("common.detail"),
            "",
            AuditSortColumn::Detail,
        ),
    ];
    let mut headers = definitions
        .into_iter()
        .map(|(class_name, label_key, label, column)| {
            audit_sort_header(
                class_name,
                label_key,
                label,
                column,
                current_column,
                current_direction,
                action,
            )
        })
        .collect::<Vec<_>>();
    if include_client_ip {
        headers.push(audit_sort_header(
            "vl-audit-ip",
            None,
            "Client-IP",
            AuditSortColumn::ClientIp,
            current_column,
            current_direction,
            action,
        ));
    }
    headers
}

#[derive(Default, Deserialize)]
pub(super) struct AuditQuery {
    page: Option<usize>,
    action: Option<String>,
    sort: Option<String>,
    direction: Option<String>,
    cursor: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct AuditCursorToken {
    #[serde(default = "legacy_audit_cursor_version")]
    version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    id: i64,
    position: String,
    action: String,
    sort: String,
    direction: String,
}

fn legacy_audit_cursor_version() -> u8 {
    1
}

fn encode_audit_cursor(
    cursor: &AuditCursor,
    position: AuditKeysetPosition,
    action: &str,
    sort: AuditSortColumn,
    direction: AuditSortDirection,
) -> Option<String> {
    let token = AuditCursorToken {
        version: 2,
        value: None,
        id: cursor.id,
        position: match position {
            AuditKeysetPosition::After => "after",
            AuditKeysetPosition::Before => "before",
        }
        .to_owned(),
        action: action.to_owned(),
        sort: audit_sort_column_value(sort).to_owned(),
        direction: audit_sort_direction_value(direction).to_owned(),
    };
    serde_json::to_vec(&token)
        .ok()
        .map(|json| data_encoding::BASE64URL_NOPAD.encode(&json))
}

fn decode_audit_cursor(
    encoded: &str,
    action: &str,
    sort: AuditSortColumn,
    direction: AuditSortDirection,
) -> Option<(AuditCursor, AuditKeysetPosition)> {
    if encoded.len() > 8_192 {
        return None;
    }
    let json = data_encoding::BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .ok()?;
    let token = serde_json::from_slice::<AuditCursorToken>(&json).ok()?;
    if !matches!(token.version, 1 | 2)
        || token.id <= 0
        || (token.version == 1 && token.value.is_none())
        || (token.version == 2 && token.value.is_some())
        || token.action != action
        || token.sort != audit_sort_column_value(sort)
        || token.direction != audit_sort_direction_value(direction)
    {
        return None;
    }
    let position = match token.position.as_str() {
        "after" => AuditKeysetPosition::After,
        "before" => AuditKeysetPosition::Before,
        _ => return None,
    };
    Some((
        AuditCursor {
            value: token.value,
            id: token.id,
        },
        position,
    ))
}

struct AuditPagination {
    previous_page: Option<usize>,
    next_page: Option<usize>,
    previous_cursor: Option<String>,
    next_cursor: Option<String>,
}

#[cfg(test)]
#[path = "settings_audit_cursor_tests.rs"]
mod audit_cursor_tests;

fn audit_pagination(
    events: &[AuditEvent],
    page_number: usize,
    total_pages: usize,
    action: &str,
    sort: AuditSortColumn,
    direction: AuditSortDirection,
) -> AuditPagination {
    let previous_page = page_number.checked_sub(1);
    let next_page = (page_number + 1 < total_pages).then_some(page_number + 1);
    let previous_cursor = previous_page.and_then(|_| {
        events
            .first()
            .map(|event| event.cursor(sort))
            .and_then(|cursor| {
                encode_audit_cursor(
                    &cursor,
                    AuditKeysetPosition::Before,
                    action,
                    sort,
                    direction,
                )
            })
    });
    let next_cursor = next_page.and_then(|_| {
        events
            .last()
            .map(|event| event.cursor(sort))
            .and_then(|cursor| {
                encode_audit_cursor(&cursor, AuditKeysetPosition::After, action, sort, direction)
            })
    });
    AuditPagination {
        previous_page,
        next_page,
        previous_cursor,
        next_cursor,
    }
}

pub(super) async fn audit_page(
    State(state): State<SettingsRouteState>,
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
    let cursor = query.cursor.as_deref().and_then(|encoded| {
        decode_audit_cursor(
            encoded,
            action.as_deref().unwrap_or(""),
            sort_column,
            sort_direction,
        )
    });
    let action_for_db = action.clone();
    let (events, total, page_number, pagination_reset) = database(state.db().clone(), move |db| {
        let total = db.count_audit(action_for_db.as_deref())?;
        let total_pages = total.div_ceil(100).max(1);
        let mut page_number = requested_page.min(total_pages - 1);
        let pagination_reset = match cursor.as_ref() {
            Some((cursor, _)) if cursor.value.is_none() => !db.audit_cursor_exists(cursor.id)?,
            _ => false,
        };
        let cursor = if pagination_reset {
            page_number = 0;
            None
        } else {
            cursor
        };
        let (cursor, position) = if let Some((cursor, position)) = cursor {
            (Some(cursor), position)
        } else if page_number > 0 {
            (
                db.audit_cursor_at_offset(
                    action_for_db.as_deref(),
                    page_number.saturating_mul(100).saturating_sub(1),
                    sort_column,
                    sort_direction,
                )?,
                AuditKeysetPosition::After,
            )
        } else {
            (None, AuditKeysetPosition::After)
        };
        let events = db.list_audit_keyset(
            action_for_db.as_deref(),
            100,
            sort_column,
            sort_direction,
            cursor.as_ref(),
            position,
        )?;
        Ok((events, total, page_number, pagination_reset))
    })
    .await?;
    let total_pages = total.div_ceil(100).max(1);
    let filter_value = action.unwrap_or_default();
    let pagination = audit_pagination(
        &events,
        page_number,
        total_pages,
        &filter_value,
        sort_column,
        sort_direction,
    );
    let rows = events
        .into_iter()
        .map(|event| AuditRowView {
            time: format_audit_time(&event.occurred_at),
            actor: event.actor,
            action: event.action,
            object_id: event.object_id.unwrap_or_default(),
            detail: event.detail.unwrap_or_default(),
            client_ip: event.client_ip.unwrap_or_default(),
        })
        .collect();
    let headers = audit_headers(
        sort_column,
        sort_direction,
        &filter_value,
        client_ip_enabled,
    );
    let sort_value = audit_sort_column_value(sort_column);
    let direction_value = audit_sort_direction_value(sort_direction);
    let url_scheme = url::Url::parse(&settings.public_base_url)
        .ok()
        .map(|url| url.scheme().to_uppercase())
        .unwrap_or_else(|| i18n::text(i18n::current_locale(), i18n::UNKNOWN).into());
    let trusted_proxy_count = state.config().reverse_proxy.trusted_proxies.len();
    let filter_encoded =
        percent_encoding::utf8_percent_encode(&filter_value, percent_encoding::NON_ALPHANUMERIC)
            .to_string();
    let body = AuditPageTemplate {
        pagination_reset,
        sort_value,
        direction_value,
        filter_value,
        filter_encoded,
        headers,
        rows,
        client_ip_enabled,
        previous_page: pagination.previous_page,
        next_page: pagination.next_page,
        previous_cursor: pagination.previous_cursor,
        next_cursor: pagination.next_cursor,
        page_number: page_number + 1,
        total_pages,
        server_mode: format!("{:?}", state.config().server.mode),
        url_scheme,
        trusted_proxy_count,
        ip_capture_label: if client_ip_enabled {
            i18n::text(i18n::current_locale(), i18n::ENABLED)
        } else {
            i18n::text(i18n::current_locale(), i18n::DISABLED)
        },
    };
    Ok(Html(templates::admin_page(
        &state,
        PageId::AuditSecurity,
        &body,
        false,
        &session.csrf_token,
        true,
    )?))
}
