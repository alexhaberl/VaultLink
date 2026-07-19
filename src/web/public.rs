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
    file_ops,
    http_auth::{
        audit_observation, current_client_limit_key, database, enabled_audit_client_ip,
        make_unlock_cookie, redirect_with_cookie, required_database, runtime_settings,
        share_is_unlocked, share_unlock_csrf, try_acquire_client_activity,
        verify_password_admitted, UnlockCookieScope,
    },
    i18n, path_security,
    policy::{self, ShareAvailability},
    sensitive::SecretString,
    AppState,
};

use super::{
    common::{
        encoded, file_sort_column, file_sort_column_value, file_sort_direction,
        file_sort_direction_value, format_public_date, human, internal, list_directory_cursor_page,
        parent_path, preview_allowed, search_tree, sort_search_hits, BrowseQuery, FileSortColumn,
    },
    shares::share_permission_label,
    storage_recovery_app_error,
    templates::{self, TrustedMarkup},
    AppError, Result, MAX_SEARCH_QUERY_BYTES,
};

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

fn usable_for_transfer(sh: &Share) -> Result<()> {
    match policy::share_availability(sh, Utc::now()) {
        ShareAvailability::Available | ShareAvailability::LimitReached => Ok(()),
        ShareAvailability::Inactive | ShareAvailability::Expired => {
            Err(AppError(StatusCode::GONE, "This link is no longer active"))
        }
    }
}

pub(super) async fn get_share(state: &AppState, token: &str) -> Result<Share> {
    let token = token.to_string();
    let sh = database(state.db.clone(), move |db| db.share_by_token(&token))
        .await?
        .ok_or(AppError(StatusCode::NOT_FOUND, "Link not found"))?;
    usable(&sh)?;
    Ok(sh)
}

pub(super) async fn get_share_for_transfer(state: &AppState, token: &str) -> Result<Share> {
    let token = token.to_string();
    let sh = database(state.db.clone(), move |db| db.share_by_token(&token))
        .await?
        .ok_or(AppError(StatusCode::NOT_FOUND, "Link not found"))?;
    usable_for_transfer(&sh)?;
    Ok(sh)
}

pub(super) async fn get_storage_share(
    state: &AppState,
    token: &str,
    expected_id: i64,
) -> Result<(Share, tokio::sync::OwnedMutexGuard<()>)> {
    let guard = state.storage_mutation.clone().lock_owned().await;
    let guard = file_ops::recover_pending_file_operations_with_guard(state, guard)
        .await
        .map_err(storage_recovery_app_error)?;
    let share = get_share(state, token).await?;
    if share.id != expected_id {
        return Err(AppError(StatusCode::GONE, "Share changed in the meantime"));
    }
    Ok((share, guard))
}

pub(super) async fn get_storage_share_for_transfer(
    state: &AppState,
    token: &str,
    expected_id: i64,
) -> Result<(Share, tokio::sync::OwnedMutexGuard<()>)> {
    let guard = state.storage_mutation.clone().lock_owned().await;
    let guard = file_ops::recover_pending_file_operations_with_guard(state, guard)
        .await
        .map_err(storage_recovery_app_error)?;
    let share = get_share_for_transfer(state, token).await?;
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
    State(state): State<AppState>,
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
        .share_limiter
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
    let created = required_database(state.db.clone(), move |db| {
        db.create_unlock_session_for_verified_password_and_audit(
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

pub(super) async fn public_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(q): Query<BrowseQuery>,
) -> Result<Html<String>> {
    let sh = get_share(&state, &token).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Ok(protected_share_page(&token));
    }
    let expected_id = sh.id;
    let (sh, storage_guard) = get_storage_share(&state, &token, expected_id).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Ok(protected_share_page(&token));
    }
    let settings = runtime_settings(&state);
    let upload_csrf = share_unlock_csrf(&state, &headers, &sh).await?;
    let share_scope = if sh.is_directory && sh.permission.can_download() {
        Some(
            state
                .secure_root
                .bind_directory(&sh.relative_path)
                .map_err(|_| AppError(StatusCode::NOT_FOUND, "Share target unavailable"))?,
        )
    } else {
        None
    };
    drop(storage_guard);
    let display_name = if sh.permission == Permission::UploadOnly {
        i18n::text(i18n::current_locale(), i18n::UPLOAD_FILE).to_string()
    } else {
        sh.relative_path
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| i18n::text(i18n::current_locale(), i18n::DEFAULT_SHARE_NAME))
            .to_string()
    };
    let secure_transport = url::Url::parse(&settings.public_base_url)
        .ok()
        .is_some_and(|url| url.scheme() == "https");
    let expiry = sh.expires_at.map(format_public_date);
    let quota = sh.max_downloads.map(|maximum| {
        let value = sh
            .download_count
            .saturating_mul(100)
            .saturating_div(maximum.max(1))
            .min(100);
        PublicQuotaView {
            used: sh.download_count,
            maximum,
            percent: value,
        }
    });
    let upload_notice = q.upload.as_deref().and_then(|upload_status| {
        let message = match upload_status {
            "replaced" => i18n::text(i18n::current_locale(), i18n::FILE_REPLACED_SUCCESS),
            "ok" => i18n::text(i18n::current_locale(), i18n::UPLOAD_COMPLETED),
            "uncertain" => i18n::text(i18n::current_locale(), i18n::UPLOAD_STORAGE_UNCONFIRMED),
            "replaced_uncertain" => {
                i18n::text(i18n::current_locale(), i18n::REPLACE_STORAGE_UNCONFIRMED)
            }
            "audit_uncertain" => {
                i18n::text(i18n::current_locale(), i18n::AUDIT_DURABILITY_UNCERTAIN)
            }
            _ => "",
        };
        (!message.is_empty()).then_some(message)
    });
    let split_layout =
        sh.is_directory && sh.permission.can_download() && sh.permission.can_upload();
    let mut directory_view = None;
    let mut file_view = None;
    let mut upload_view = None;
    if sh.is_directory && sh.permission.can_download() {
        let sub = q.path.clone().unwrap_or_default();
        let after_cursor = q.after.clone();
        let before_cursor = q.before.clone();
        let sort_column = file_sort_column(q.sort.as_deref());
        let sort_direction = file_sort_direction(q.direction.as_deref());
        let search =
            q.q.map(|value| value.trim().to_string())
                .filter(|v| !v.is_empty());
        if after_cursor.is_some() && before_cursor.is_some() {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "Invalid directory cursor",
            ));
        }
        if search.is_some() && (after_cursor.is_some() || before_cursor.is_some()) {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "Directory cursors cannot be combined with search",
            ));
        }
        if search
            .as_ref()
            .is_some_and(|value| value.len() > MAX_SEARCH_QUERY_BYTES)
        {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "Search query is too long",
            ));
        }
        let clean_sub = path_security::validate_relative(&sub)
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid path"))?
            .to_string_lossy()
            .replace('\\', "/");
        let relative_dir = clean_sub.clone();
        let share_scope = share_scope.expect("downloadable directory share is bound");
        let _scan_peer_permit = try_acquire_client_activity(
            state.expensive_peer_admission.clone(),
            current_client_limit_key(),
            crate::MAX_EXPENSIVE_OPERATIONS_PER_CLIENT,
        )
        .ok_or(AppError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many concurrent expensive operations from this client",
        ))?;
        let _scan_permit = state
            .search_admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                AppError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Too many concurrent file searches",
                )
            })?;
        let secure_root = share_scope;
        let mut rows = Vec::new();
        let mut truncated = false;
        let mut previous_cursor = None;
        let mut next_cursor = None;
        if let Some(search) = search.clone() {
            let search_settings = settings.clone();
            let mut hits = tokio::task::spawn_blocking(move || {
                search_tree(&secure_root, &relative_dir, &search, &search_settings)
            })
            .await
            .map_err(internal)?
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::InvalidInput {
                    AppError(StatusCode::BAD_REQUEST, "Invalid directory cursor")
                } else {
                    AppError(StatusCode::NOT_FOUND, "Share target unavailable")
                }
            })?;
            sort_search_hits(&mut hits, sort_column, sort_direction);
            for hit in hits {
                let share_rel = hit.relative_path.clone();
                let target = encoded(&share_rel);
                let open_url = if hit.entry.is_dir {
                    Some(format!("/v/{token}?path={target}"))
                } else {
                    None
                };
                let preview_url =
                    if !hit.entry.is_dir && preview_allowed(&hit.relative_path, &settings) {
                        Some(format!("/v/{token}/preview?path={target}"))
                    } else {
                        None
                    };
                let download_url =
                    (!hit.entry.is_dir).then(|| format!("/v/{token}/download?path={target}"));
                let modified = hit.entry.modified.map(public_file_time);
                let (modified_datetime, modified_label) = if let Some((datetime, label)) = modified
                {
                    (Some(datetime), label)
                } else {
                    (None, "—".into())
                };
                rows.push(PublicFileRowView {
                    name: share_rel,
                    icon: TrustedMarkup::static_icon(if hit.entry.is_dir {
                        crate::ui::Icon::Folder
                    } else {
                        crate::ui::Icon::File
                    }),
                    type_label: i18n::text(
                        i18n::current_locale(),
                        if hit.entry.is_dir {
                            i18n::FOLDER
                        } else {
                            i18n::FILE
                        },
                    ),
                    size: if hit.entry.is_dir {
                        "—".into()
                    } else {
                        human(hit.entry.len)
                    },
                    modified_datetime,
                    modified_label,
                    is_directory: hit.entry.is_dir,
                    open_url,
                    preview_url,
                    download_url,
                });
            }
        } else {
            let scan_limit = settings.max_search_entries;
            let cursor_after = after_cursor.clone();
            let cursor_before = before_cursor.clone();
            let listing_page = tokio::task::spawn_blocking(move || {
                list_directory_cursor_page(
                    &secure_root,
                    &relative_dir,
                    cursor_after.as_deref(),
                    cursor_before.as_deref(),
                    scan_limit,
                    sort_column,
                    sort_direction,
                )
            })
            .await
            .map_err(internal)?
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::InvalidInput {
                    AppError(StatusCode::BAD_REQUEST, "Invalid directory cursor")
                } else {
                    AppError(StatusCode::NOT_FOUND, "Share target unavailable")
                }
            })?;
            previous_cursor = listing_page.previous_cursor;
            next_cursor = listing_page.next_cursor;
            for entry in listing_page.entries {
                let rel = joined_relative(&clean_sub, &entry.name)?;
                let target = encoded(&rel);
                let modified = entry.modified.map(public_file_time);
                let (modified_datetime, modified_label) = if let Some((datetime, label)) = modified
                {
                    (Some(datetime), label)
                } else {
                    (None, "—".into())
                };
                rows.push(PublicFileRowView {
                    name: entry.name,
                    icon: TrustedMarkup::static_icon(if entry.is_dir {
                        crate::ui::Icon::Folder
                    } else {
                        crate::ui::Icon::File
                    }),
                    type_label: i18n::text(
                        i18n::current_locale(),
                        if entry.is_dir {
                            i18n::FOLDER
                        } else {
                            i18n::FILE
                        },
                    ),
                    size: if entry.is_dir {
                        "—".into()
                    } else {
                        human(entry.len)
                    },
                    modified_datetime,
                    modified_label,
                    is_directory: entry.is_dir,
                    open_url: entry.is_dir.then(|| format!("/v/{token}?path={target}")),
                    preview_url: (!entry.is_dir && preview_allowed(&rel, &settings))
                        .then(|| format!("/v/{token}/preview?path={target}")),
                    download_url: (!entry.is_dir)
                        .then(|| format!("/v/{token}/download?path={target}")),
                });
            }
            truncated = listing_page.truncated;
        }
        let encoded_sub = encoded(&clean_sub);
        let search_encoded = search.as_deref().map(encoded);
        let headers = [
            ("common.name", FileSortColumn::Name),
            ("common.type", FileSortColumn::Type),
            ("common.size", FileSortColumn::Size),
            ("common.changed", FileSortColumn::Modified),
        ]
        .into_iter()
        .map(|(label, column)| {
            public_sort_header_view(
                label,
                column,
                sort_column,
                sort_direction,
                &token,
                &clean_sub,
                search.as_deref(),
            )
        })
        .collect();
        directory_view = Some(PublicDirectoryView {
            root_url: format!("/v/{token}"),
            breadcrumbs: public_breadcrumb_views(&token, &clean_sub),
            parent_url: parent_path(&clean_sub)
                .map(|parent| format!("/v/{token}?path={}", encoded(&parent))),
            path: clean_sub.clone(),
            path_encoded: encoded_sub.clone(),
            sort: file_sort_column_value(sort_column),
            direction: file_sort_direction_value(sort_direction),
            search: search.clone().unwrap_or_default(),
            zip_url: format!("/v/{token}/download.zip?path={encoded_sub}"),
            headers,
            rows,
            truncated,
            previous_cursor: previous_cursor.map(|cursor| encoded(&cursor)),
            next_cursor: next_cursor.map(|cursor| encoded(&cursor)),
            search_encoded,
        });
    } else if !sh.is_directory && sh.permission.can_download() {
        let secure_root = state.secure_root.clone();
        let metadata_path = sh.relative_path.clone();
        let metadata = tokio::task::spawn_blocking(move || secure_root.metadata(&metadata_path))
            .await
            .map_err(internal)?
            .map_err(|_| AppError(StatusCode::NOT_FOUND, "Shared file unavailable"))?;
        let modified = metadata.modified().ok().map(public_file_time);
        let (modified_datetime, modified_label) = if let Some((datetime, label)) = modified {
            (Some(datetime), label)
        } else {
            (None, "—".into())
        };
        file_view = Some(PublicFileView {
            size: human(metadata.len()),
            modified_datetime,
            modified_label,
            preview_url: preview_allowed(&sh.relative_path, &settings)
                .then(|| format!("/v/{token}/preview")),
            download_url: format!("/v/{token}/download"),
        });
    }
    if sh.is_directory && sh.permission.can_upload() {
        let upload_path = if sh.permission.can_download() {
            path_security::validate_relative(q.path.as_deref().unwrap_or_default())
                .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid path"))?
                .to_string_lossy()
                .replace('\\', "/")
        } else {
            String::new()
        };
        upload_view = Some(PublicUploadView {
            heading: if sh.permission == Permission::UploadOnly {
                i18n::text(i18n::current_locale(), i18n::UPLOAD_FILE)
            } else {
                i18n::text(i18n::current_locale(), i18n::UPLOAD_FILES_PUBLIC)
            },
            hide_existing: sh.permission == Permission::UploadOnly,
            path: upload_path,
            action_url: format!("/v/{token}/upload"),
            queue_url: format!("/v/{token}/upload/queue"),
            csrf: upload_csrf.unwrap_or_default(),
            allow_overwrite: sh.upload_conflict_strategy.can_overwrite()
                && state.config.storage.replacements_allowed(),
            upload_icon: TrustedMarkup::static_icon(crate::ui::Icon::Upload),
            folder_icon: TrustedMarkup::static_icon(crate::ui::Icon::Folder),
        });
    }
    let body = PublicShareTemplate {
        token,
        display_name,
        public_base_url: settings.public_base_url.clone(),
        permission_label: share_permission_label(&sh.permission),
        password_protected: sh.password_hash.is_some(),
        expiry,
        quota,
        transport_label: if secure_transport {
            i18n::text(i18n::current_locale(), i18n::HTTPS_SECURE)
        } else {
            i18n::text(i18n::current_locale(), i18n::LOCAL_HTTP)
        },
        upload_notice,
        split_layout,
        directory: directory_view,
        file: file_view,
        upload: upload_view,
    };
    Ok(Html(templates::public_page(i18n::SHARE, &body)?))
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
    State(state): State<AppState>,
    ConnectInfo(_peer): ConnectInfo<SocketAddr>,
    _headers: HeaderMap,
    AxPath(alias): AxPath<String>,
) -> Result<Redirect> {
    let ip = current_client_limit_key();
    if !state
        .alias_limiter
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
    let sh = database(state.db.clone(), move |db| db.share_by_alias(&alias))
        .await?
        .ok_or(AppError(StatusCode::NOT_FOUND, "Alias not found"))?;
    usable(&sh)?;
    Ok(Redirect::to(&format!("/v/{}", sh.token)))
}
