use std::net::SocketAddr;

use askama::Template;
use axum::{
    extract::{ConnectInfo, Form, Path as AxPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::Deserialize;

use crate::{
    auth,
    db::{AuditAction, AuditContext, Permission, Share},
    directory_cache::{DirectoryCacheLookup, DirectorySnapshotKey},
    file_ops,
    http_auth::{
        audit_observation, current_client_limit_key, database, enabled_audit_client_ip,
        make_unlock_cookie, redirect_with_cookie, required_audited_database, runtime_settings,
        share_is_unlocked, share_unlock_csrf, verify_password_admitted, UnlockCookieScope,
    },
    i18n,
    internal_reporting::{report_internal, InternalOperation},
    path_security,
    policy::{self, ShareAvailability},
    sensitive::SecretString,
    PublicRouteState,
};

use super::{
    common::{
        build_directory_snapshot, encoded, file_sort_column, file_sort_column_value,
        file_sort_direction, file_sort_direction_value, format_public_date, human,
        list_directory_cursor_page, list_directory_snapshot_cursor_page, parent_path,
        preview_allowed, search_tree, sort_search_hits, BrowseQuery, FileSortColumn,
    },
    shares::share_permission_label,
    storage_recovery_app_error,
    templates::{self, TrustedMarkup},
    AppError, Result, MAX_SEARCH_QUERY_BYTES,
};

#[path = "public/page.rs"]
mod page;
pub(in crate::web) use page::public_page;

#[derive(Template)]
#[template(
    source = r#"<section class="vl-panel vl-auth-card"><p class="vl-eyebrow"><vl-i18n key="share.secure"/></p><h1><vl-i18n key="public.protected_title"/></h1><p class="vl-muted"><vl-i18n key="public.enter_share_password"/></p><form method="post" action="/v/{{ token }}/unlock" class="vl-stack"><label class="vl-field"><vl-i18n key="auth.password"/><input type="password" name="password" autocomplete="current-password" required></label><button class="vl-button">{{ lock_icon }} <vl-i18n key="public.unlock"/></button></form></section>"#,
    ext = "html"
)]
struct ProtectedShareTemplate<'a> {
    token: &'a str,
    lock_icon: TrustedMarkup,
}

struct PublicQuotaView {
    used: u64,
    maximum: u64,
    percent: u64,
}

struct PublicBreadcrumbView {
    label: String,
    url: String,
}

struct PublicSortHeaderView {
    label_key: &'static str,
    aria_sort: &'static str,
    indicator: &'static str,
    token: String,
    path: String,
    sort: &'static str,
    direction: &'static str,
    search: Option<String>,
}

struct PublicFileRowView {
    name: String,
    icon: TrustedMarkup,
    type_label: &'static str,
    size: String,
    modified_datetime: Option<String>,
    modified_label: String,
    is_directory: bool,
    open_url: Option<String>,
    preview_url: Option<String>,
    download_url: Option<String>,
}

struct PublicDirectoryView {
    root_url: String,
    breadcrumbs: Vec<PublicBreadcrumbView>,
    parent_url: Option<String>,
    path: String,
    path_encoded: String,
    sort: &'static str,
    direction: &'static str,
    search: String,
    zip_url: String,
    headers: Vec<PublicSortHeaderView>,
    rows: Vec<PublicFileRowView>,
    truncated: bool,
    previous_cursor: Option<String>,
    next_cursor: Option<String>,
    search_encoded: Option<String>,
}

struct PublicFileView {
    size: String,
    modified_datetime: Option<String>,
    modified_label: String,
    preview_url: Option<String>,
    download_url: String,
}

struct PublicUploadView {
    heading: &'static str,
    hide_existing: bool,
    path: String,
    action_url: String,
    queue_url: String,
    csrf: String,
    allow_overwrite: bool,
    upload_icon: TrustedMarkup,
    folder_icon: TrustedMarkup,
}

#[derive(Template)]
#[template(path = "web/public/share.html")]
struct PublicShareTemplate {
    token: String,
    display_name: String,
    public_base_url: String,
    permission_label: &'static str,
    password_protected: bool,
    expiry: Option<String>,
    quota: Option<PublicQuotaView>,
    transport_label: &'static str,
    upload_notice: Option<&'static str>,
    split_layout: bool,
    directory: Option<PublicDirectoryView>,
    file: Option<PublicFileView>,
    upload: Option<PublicUploadView>,
}

fn public_file_time(value: std::time::SystemTime) -> (String, String) {
    let utc = DateTime::<Utc>::from(value);
    (
        utc.to_rfc3339_opts(SecondsFormat::Secs, true),
        super::common::format_utc_minute(utc),
    )
}

fn public_breadcrumb_views(token: &str, path: &str) -> Vec<PublicBreadcrumbView> {
    let mut current = String::new();
    path.trim_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .map(|part| {
            current = if current.is_empty() {
                part.to_string()
            } else {
                format!("{current}/{part}")
            };
            PublicBreadcrumbView {
                label: part.to_string(),
                url: format!("/v/{token}?path={}", encoded(&current)),
            }
        })
        .collect()
}

fn public_sort_header_view(
    label_key: &'static str,
    column: FileSortColumn,
    current_column: FileSortColumn,
    current_direction: super::common::FileSortDirection,
    token: &str,
    path: &str,
    search: Option<&str>,
) -> PublicSortHeaderView {
    use super::common::FileSortDirection;
    let active = column == current_column;
    let next_direction = if active && current_direction == FileSortDirection::Ascending {
        FileSortDirection::Descending
    } else {
        FileSortDirection::Ascending
    };
    let aria_sort = if active {
        match current_direction {
            FileSortDirection::Ascending => "ascending",
            FileSortDirection::Descending => "descending",
        }
    } else {
        "none"
    };
    let indicator = if active {
        match current_direction {
            FileSortDirection::Ascending => "↑",
            FileSortDirection::Descending => "↓",
        }
    } else {
        ""
    };
    PublicSortHeaderView {
        label_key,
        aria_sort,
        indicator,
        token: token.to_string(),
        path: encoded(path),
        sort: file_sort_column_value(column),
        direction: file_sort_direction_value(next_direction),
        search: search.map(encoded),
    }
}

pub(super) fn usable(sh: &Share) -> Result<()> {
    match policy::share_availability(sh, Utc::now()) {
        ShareAvailability::Available => Ok(()),
        ShareAvailability::Inactive
        | ShareAvailability::Expired
        | ShareAvailability::LimitReached => {
            Err(AppError(StatusCode::GONE, "This link is no longer active"))
        }
    }
}

pub(super) async fn get_share(state: &PublicRouteState, token: &str) -> Result<Share> {
    let token = token.to_string();
    let sh = database(state.db().clone(), move |db| db.share_by_token(&token))
        .await?
        .ok_or(AppError(StatusCode::NOT_FOUND, "Link not found"))?;
    usable(&sh)?;
    Ok(sh)
}

pub(super) async fn get_storage_share(
    state: &PublicRouteState,
    token: &str,
    expected_id: i64,
) -> Result<(Share, crate::storage_authority::StorageReadGuard)> {
    let guard = file_ops::acquire_storage_read(state)
        .await
        .map_err(storage_recovery_app_error)?;
    let share = get_share(state, token).await?;
    if share.id != expected_id {
        return Err(AppError(StatusCode::GONE, "Share changed in the meantime"));
    }
    Ok((share, guard))
}

#[derive(Deserialize)]
pub(super) struct UnlockForm {
    password: SecretString,
}

pub(super) async fn unlock_share(
    State(state): State<PublicRouteState>,
    ConnectInfo(_peer): ConnectInfo<SocketAddr>,
    _headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Form(form): Form<UnlockForm>,
) -> Result<Response> {
    let share = get_share(&state, &token).await?;
    let Some(password_hash) = share.password_hash.clone() else {
        return Ok(Redirect::to(&format!("/v/{token}")).into_response());
    };
    let expected_password_hash = password_hash.clone();
    let expected_upload_policy_epoch = share.upload_policy_epoch;
    let ip = current_client_limit_key();
    let global_key = format!("share-unlock-ip:{ip}");
    let share_key = format!("share-unlock:{}:{ip}", share.id);
    if !state
        .share_limiter()
        .check_and_record_attempts(&[&global_key, &share_key])
    {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many password attempts",
        ));
    }
    let password = form.password;
    if password.expose_secret().len() > auth::MAX_PASSWORD_BYTES {
        audit_observation(
            &state,
            "public".into(),
            AuditAction::ShareUnlockFailed,
            Some(share.id.to_string()),
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid password"));
    }
    let valid = verify_password_admitted(&state, Some(password_hash), password).await?;
    if !valid {
        audit_observation(
            &state,
            "public".into(),
            AuditAction::ShareUnlockFailed,
            Some(share.id.to_string()),
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid password"));
    }
    // Do not clear successful unlock attempts: a known share password must not
    // provide an unlimited Argon2/session/audit oracle.
    let unlock_token = auth::random_token(32);
    let unlock_csrf = auth::random_token(24);
    let stored_unlock_token = unlock_token.clone();
    let stored_unlock_csrf = unlock_csrf.clone();
    let share_id = share.id;
    let expires = Utc::now() + Duration::minutes(runtime_settings(&state).share_unlock_minutes);
    let audit_context = AuditContext::new("public", enabled_audit_client_ip(&state));
    let created = required_audited_database(state.db().clone(), move |db| {
        db.create_unlock_session_for_verified_password_and_audit_audited(
            &stored_unlock_token,
            share_id,
            &expected_password_hash,
            expected_upload_policy_epoch,
            &stored_unlock_csrf,
            expires,
            &audit_context,
        )
    })
    .await?;
    if !created {
        audit_observation(
            &state,
            "public".into(),
            AuditAction::ShareUnlockFailed,
            Some(share.id.to_string()),
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid password"));
    }
    Ok(redirect_with_cookie(
        &format!("/v/{token}"),
        &make_unlock_cookie(&state, &share, &unlock_token, UnlockCookieScope::Web),
    )?)
}

fn protected_share_page(token: &str) -> Html<String> {
    let body = ProtectedShareTemplate {
        token,
        lock_icon: TrustedMarkup::static_icon(crate::ui::Icon::Lock),
    };
    Html(
        templates::public_page(i18n::PROTECTED_SHARE_TITLE, &body)
            .expect("the protected-share template writes only to an in-memory string"),
    )
}

fn joined_relative(base: &str, child: &str) -> Result<String> {
    let mut path = path_security::validate_relative(base)
        .map_err(|_| AppError(StatusCode::FORBIDDEN, "Invalid path"))?;
    path.push(
        path_security::validate_relative(child)
            .map_err(|_| AppError(StatusCode::FORBIDDEN, "Invalid path"))?,
    );
    Ok(path.to_string_lossy().replace('\\', "/"))
}

pub(super) async fn short_redirect(
    State(state): State<PublicRouteState>,
    ConnectInfo(_peer): ConnectInfo<SocketAddr>,
    _headers: HeaderMap,
    AxPath(alias): AxPath<String>,
) -> Result<Redirect> {
    let ip = current_client_limit_key();
    if !state
        .alias_limiter()
        .check_and_record_attempt(&format!("alias:{ip}"))
    {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many alias requests",
        ));
    }
    if path_security::validate_share_alias(&alias).is_err() {
        return Err(AppError(StatusCode::NOT_FOUND, "Alias not found"));
    }
    let sh = database(state.db().clone(), move |db| db.share_by_alias(&alias))
        .await?
        .ok_or(AppError(StatusCode::NOT_FOUND, "Alias not found"))?;
    usable(&sh)?;
    Ok(Redirect::to(&format!("/v/{}", sh.token)))
}
