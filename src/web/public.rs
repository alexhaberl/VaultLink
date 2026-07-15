use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Form, Path as AxPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::{Duration, Utc};
use serde::Deserialize;

use crate::{
    auth,
    db::{AuditContext, Permission, Share},
    file_ops,
    http_auth::{
        audit_observation, current_client_limit_key, database, enabled_audit_client_ip,
        make_unlock_cookie, redirect_with_cookie, required_database, runtime_settings,
        share_is_unlocked, share_unlock_csrf, try_acquire_client_activity,
        verify_password_admitted, UnlockCookieScope,
    },
    i18n, path_security,
    policy::{self, ShareAvailability},
    proxy,
    sensitive::SecretString,
    AppState,
};

use super::{
    encoded, esc, format_file_time, format_public_date, human, internal, list_directory_page,
    parent_path, plain_page, preview_allowed, public_breadcrumbs, search_tree,
    share_permission_label, storage_recovery_app_error, AppError, BrowseQuery, Result,
    MAX_SEARCH_QUERY_BYTES,
};

pub(super) fn usable(sh: &Share) -> Result<()> {
    match policy::share_availability(sh, Utc::now()) {
        ShareAvailability::Available => Ok(()),
        ShareAvailability::Inactive | ShareAvailability::Expired => Err(AppError(
            StatusCode::GONE,
            "Dieser Link ist nicht mehr aktiv",
        )),
    }
}
pub(super) async fn get_share(state: &AppState, token: &str) -> Result<Share> {
    let token = token.to_string();
    let sh = database(state.db.clone(), move |db| db.share_by_token(&token))
        .await?
        .ok_or(AppError(StatusCode::NOT_FOUND, "Link nicht gefunden"))?;
    usable(&sh)?;
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
        return Err(AppError(
            StatusCode::GONE,
            "Freigabe wurde zwischenzeitlich geändert",
        ));
    }
    Ok((share, guard))
}

#[derive(Deserialize)]
pub(super) struct UnlockForm {
    password: SecretString,
}

pub(super) async fn unlock_share(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Form(form): Form<UnlockForm>,
) -> Result<Response> {
    let share = get_share(&state, &token).await?;
    let Some(password_hash) = share.password_hash.clone() else {
        return Ok(Redirect::to(&format!("/v/{token}")).into_response());
    };
    let expected_password_hash = password_hash.clone();
    let expected_upload_policy_epoch = share.upload_policy_epoch;
    let ip = proxy::client_limit_key(proxy::effective_client_ip(
        peer.ip(),
        &headers,
        &state.config,
    ));
    let key = format!("share:{}:{ip}", share.id);
    if !state.share_limiter.check_and_record_attempt(&key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele Passwortversuche",
        ));
    }
    let password = form.password;
    if password.expose_secret().len() > auth::MAX_PASSWORD_BYTES {
        audit_observation(
            &state,
            "public".into(),
            "share_unlock_failed",
            Some(share.id.to_string()),
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültiges Passwort"));
    }
    let valid = verify_password_admitted(&state, Some(password_hash), password).await?;
    if !valid {
        audit_observation(
            &state,
            "public".into(),
            "share_unlock_failed",
            Some(share.id.to_string()),
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültiges Passwort"));
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
            "share_unlock_failed",
            Some(share.id.to_string()),
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültiges Passwort"));
    }
    Ok(redirect_with_cookie(
        &format!("/v/{token}"),
        make_unlock_cookie(&state, &share, &unlock_token, UnlockCookieScope::Web),
    )?)
}

fn protected_share_page(token: &str) -> Html<String> {
    let body = format!(
        r#"<section class="vl-panel vl-auth-card"><p class="vl-eyebrow"><vl-i18n key="share.secure"/></p><h1><vl-i18n key="public.protected_title"/></h1><p class="vl-muted"><vl-i18n key="public.enter_share_password"/></p><form method="post" action="/v/{0}/unlock" class="vl-stack"><label class="vl-field"><vl-i18n key="auth.password"/><input type="password" name="password" autocomplete="current-password" required></label><button class="vl-button">{1} <vl-i18n key="public.unlock"/></button></form></section>"#,
        esc(token),
        crate::ui::icon(crate::ui::Icon::Lock),
    );
    Html(plain_page("Geschützte Freigabe", &body))
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
                .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabeziel nicht verfügbar"))?,
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
    let expiry_badge = sh
        .expires_at
        .map(|expires_at| {
            format!(
                r#"<span class="vl-badge"><vl-i18n key="public.valid_until"/> {}</span>"#,
                format_public_date(expires_at)
            )
        })
        .unwrap_or_else(|| {
            r#"<span class="vl-badge"><vl-i18n key="share.no_expiry"/></span>"#.into()
        });
    let password_badge = if sh.password_hash.is_some() {
        r#"<span class="vl-badge vl-badge--neutral"><vl-i18n key="share.password_protected"/></span>"#
    } else {
        ""
    };
    let quota = sh.max_downloads.map(|maximum| {
        let value = sh
            .download_count
            .saturating_mul(100)
            .saturating_div(maximum.max(1))
            .min(100);
        format!(r#"<div class="vl-public-quota"><span>{} <vl-i18n key="public.transfers_used_prefix"/> {} <vl-i18n key="public.transfers_used_suffix"/></span><progress class="vl-public-progress" max="100" value="{value}">{value}%</progress></div>"#, sh.download_count, maximum)
    }).unwrap_or_default();
    let mut body = format!(
        r#"<section class="vl-panel vl-public-hero"><div><p class="vl-eyebrow"><vl-i18n key="share.secure"/></p><h1>{}</h1><p class="vl-muted"><vl-i18n key="public.provided_by"/> {}</p><div class="vl-share-badges"><span class="vl-badge vl-badge--accent">{}</span>{password_badge}{expiry_badge}</div></div><div>{}<p class="vl-muted">{}</p></div></section>"#,
        esc(&display_name),
        esc(&settings.public_base_url),
        esc(share_permission_label(&sh.permission)),
        quota,
        if secure_transport {
            i18n::text(i18n::current_locale(), i18n::HTTPS_SECURE)
        } else {
            i18n::text(i18n::current_locale(), i18n::LOCAL_HTTP)
        },
    );
    if let Some(upload_status) = q.upload.as_deref() {
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
        if !message.is_empty() {
            body += &format!(r#"<p class="vl-notice vl-notice--success">{message}</p>"#);
        }
    }
    let split_layout =
        sh.is_directory && sh.permission.can_download() && sh.permission.can_upload();
    if split_layout {
        body += r#"<div class="vl-public-share-layout"><section class="vl-panel">"#;
    } else if sh.is_directory && sh.permission.can_download() {
        body += r#"<section class="vl-panel">"#;
    }
    if sh.is_directory && sh.permission.can_download() {
        let sub = q.path.clone().unwrap_or_default();
        let page_number = q.page.unwrap_or(0).min(1_000_000);
        let search =
            q.q.map(|value| value.trim().to_string())
                .filter(|v| !v.is_empty());
        if search
            .as_ref()
            .is_some_and(|value| value.len() > MAX_SEARCH_QUERY_BYTES)
        {
            return Err(AppError(StatusCode::BAD_REQUEST, "Suchbegriff ist zu lang"));
        }
        let clean_sub = path_security::validate_relative(&sub)
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Pfad"))?
            .to_string_lossy()
            .replace('\\', "/");
        let relative_dir = clean_sub.clone();
        let share_scope = share_scope.expect("downloadable directory share is bound");
        let _scan_peer_permit = try_acquire_client_activity(
            state.expensive_peer_admission.clone(),
            current_client_limit_key(),
            crate::MAX_EXPENSIVE_OPERATIONS_PER_CLIENT,
        )
        .map_err(internal)?
        .ok_or(AppError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Zu viele gleichzeitige aufwendige Vorgänge dieses Clients",
        ))?;
        let _scan_permit = state
            .search_admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                AppError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Zu viele gleichzeitige Dateisuchen",
                )
            })?;
        body += &public_breadcrumbs(&token, &clean_sub);
        if let Some(parent) = parent_path(&clean_sub) {
            body += &format!(
                r#"<p><a href="/v/{token}?path={}"><vl-i18n key="files.up"/></a></p>"#,
                encoded(&parent)
            );
        }
        body += &format!(
            r#"<form method="get" class="vl-toolbar"><input type="hidden" name="path" value="{}"><label class="vl-field vl-search"><span class="vl-sr-only"><vl-i18n key="files.browse"/></span><input name="q" value="{}" placeholder="<vl-i18n key="files.search_placeholder"/>"></label><button class="vl-button"><vl-i18n key="common.search"/></button><a class="vl-button vl-button--secondary" href="/v/{token}/download.zip?path={}"><vl-i18n key="files.folder_zip"/></a></form>"#,
            esc(&clean_sub),
            esc(search.as_deref().unwrap_or("")),
            encoded(&clean_sub)
        );
        let secure_root = share_scope;
        let mut rows = String::new();
        let mut has_next = false;
        if let Some(search) = search.clone() {
            let search_settings = settings.clone();
            let hits = tokio::task::spawn_blocking(move || {
                search_tree(secure_root, &relative_dir, &search, &search_settings)
            })
            .await
            .map_err(internal)?
            .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabeziel nicht verfügbar"))?;
            for hit in hits {
                let share_rel = hit.relative_path.clone();
                let target = encoded(&share_rel);
                let preview = if !hit.entry.is_dir && preview_allowed(&hit.relative_path, &settings)
                {
                    format!(
                        r#"<a class="vl-button vl-button--ghost vl-button--small" href="/v/{token}/preview?path={target}"><vl-i18n key="common.view"/></a> "#
                    )
                } else {
                    String::new()
                };
                let modified = hit
                    .entry
                    .modified
                    .map(format_file_time)
                    .unwrap_or_else(|| "—".into());
                let name = if hit.entry.is_dir {
                    format!(
                        r#"{} <a href="/v/{token}?path={target}">{}</a>"#,
                        crate::ui::icon(crate::ui::Icon::Folder),
                        esc(&share_rel)
                    )
                } else {
                    format!(
                        "{} {}",
                        crate::ui::icon(crate::ui::Icon::File),
                        esc(&share_rel)
                    )
                };
                rows += &format!(
                    r#"<tr><td data-label="<vl-i18n key="common.name"/>">{name}</td><td data-label="<vl-i18n key="common.size"/>">{}</td><td data-label="<vl-i18n key="common.changed"/>">{modified}</td><td data-label="<vl-i18n key="common.action"/>" class="vl-inline-actions">{}{preview}</td></tr>"#,
                    if hit.entry.is_dir {
                        "—".into()
                    } else {
                        human(hit.entry.len)
                    },
                    if hit.entry.is_dir {
                        format!(
                            r#"<a class="vl-button vl-button--ghost vl-button--small" href="/v/{token}?path={target}"><vl-i18n key="common.open"/></a>"#
                        )
                    } else {
                        format!(
                            r#"<a class="vl-button vl-button--secondary vl-button--small" href="/v/{token}/download?path={target}"><vl-i18n key="common.download"/></a>"#
                        )
                    },
                );
            }
        } else {
            let scan_limit = settings.max_search_entries;
            let (entries, truncated) = tokio::task::spawn_blocking(move || {
                list_directory_page(&secure_root, &relative_dir, page_number, scan_limit)
            })
            .await
            .map_err(internal)?
            .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabeziel nicht verfügbar"))?;
            has_next = entries.len() > 100;
            for entry in entries.into_iter().take(100) {
                let rel = joined_relative(&clean_sub, &entry.name)?;
                let name = esc(&entry.name);
                let target = encoded(&rel);
                if entry.is_dir {
                    rows += &format!(
                        r#"<tr><td data-label="<vl-i18n key="common.name"/>">{} <a href="/v/{token}?path={target}">{name}</a></td><td data-label="<vl-i18n key="common.size"/>">—</td><td data-label="<vl-i18n key="common.changed"/>">{}</td><td data-label="<vl-i18n key="common.action"/>"><a class="vl-button vl-button--ghost vl-button--small" href="/v/{token}?path={target}"><vl-i18n key="common.open"/></a></td></tr>"#,
                        crate::ui::icon(crate::ui::Icon::Folder),
                        entry
                            .modified
                            .map(format_file_time)
                            .unwrap_or_else(|| "—".into())
                    );
                } else {
                    let preview = if preview_allowed(&rel, &settings) {
                        format!(
                            r#"<a class="vl-button vl-button--ghost vl-button--small" href="/v/{token}/preview?path={target}"><vl-i18n key="common.view"/></a> "#
                        )
                    } else {
                        String::new()
                    };
                    rows += &format!(
                        r#"<tr><td data-label="<vl-i18n key="common.name"/>">{} {name}</td><td data-label="<vl-i18n key="common.size"/>">{}</td><td data-label="<vl-i18n key="common.changed"/>">{}</td><td data-label="<vl-i18n key="common.action"/>" class="vl-inline-actions">{}<a class="vl-button vl-button--secondary vl-button--small" href="/v/{token}/download?path={target}"><vl-i18n key="common.download"/></a></td></tr>"#,
                        crate::ui::icon(crate::ui::Icon::File),
                        human(entry.len),
                        entry
                            .modified
                            .map(format_file_time)
                            .unwrap_or_else(|| "—".into()),
                        preview,
                    );
                }
            }
            if truncated {
                rows += r#"<tr><td colspan="4" class="vl-muted"><vl-i18n key="files.scan_limit"/></td></tr>"#;
            }
        }
        body += "<div class=\"vl-table-wrap\"><table class=\"vl-data-table\"><thead><tr><th><vl-i18n key=\"common.name\"/></th><th><vl-i18n key=\"common.size\"/></th><th><vl-i18n key=\"common.changed\"/></th><th><vl-i18n key=\"common.action\"/></th></tr></thead><tbody>";
        body += &rows;
        body += "</tbody></table></div>";
        let encoded_sub = encoded(&clean_sub);
        let search_param = search
            .as_deref()
            .map(|value| format!("&q={}", encoded(value)))
            .unwrap_or_default();
        if page_number > 0 {
            body += &format!(
                " <a href=\"/v/{token}?path={encoded_sub}&page={}{}\"><vl-i18n key=\"common.back\"/></a>",
                page_number - 1,
                search_param
            );
        }
        if has_next {
            body += &format!(
                " <a href=\"/v/{token}?path={encoded_sub}&page={}{}\"><vl-i18n key=\"common.continue\"/></a>",
                page_number + 1,
                search_param
            );
        }
        body += "</section>";
    } else if !sh.is_directory && sh.permission.can_download() {
        let secure_root = state.secure_root.clone();
        let metadata_path = sh.relative_path.clone();
        let metadata = tokio::task::spawn_blocking(move || secure_root.metadata(&metadata_path))
            .await
            .map_err(internal)?
            .map_err(|_| AppError(StatusCode::NOT_FOUND, "Freigabedatei nicht verfügbar"))?;
        let preview = if preview_allowed(&sh.relative_path, &settings) {
            format!(
                r#"<a class="vl-button vl-button--secondary" href="/v/{token}/preview"><vl-i18n key="files.view_browser"/></a> "#
            )
        } else {
            String::new()
        };
        body += &format!(
            r#"<section class="vl-panel"><p class="vl-muted">{} · <vl-i18n key="files.modified_label"/> {}</p><div class="vl-inline-actions">{}<a class="vl-button" href="/v/{token}/download"><vl-i18n key="files.download_file"/></a></div></section>"#,
            human(metadata.len()),
            metadata
                .modified()
                .map(format_file_time)
                .unwrap_or_else(|_| "—".into()),
            preview,
        );
    }
    if sh.is_directory && sh.permission.can_upload() {
        let upload_path = if sh.permission.can_download() {
            path_security::validate_relative(q.path.as_deref().unwrap_or_default())
                .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiger Pfad"))?
                .to_string_lossy()
                .replace('\\', "/")
        } else {
            String::new()
        };
        let overwrite_checkbox = if sh.upload_conflict_strategy.can_overwrite()
            && !state.config.storage.external_writers
        {
            r#"<label class="vl-switch"><input type="checkbox" name="overwrite_existing" value="1"><span><vl-i18n key="share.replace_existing_file"/><small><vl-i18n key="share.replace_concrete"/></small></span></label>"#
        } else {
            ""
        };
        let target_hint = if sh.permission == Permission::UploadOnly {
            r#"<p class="vl-notice"><strong><vl-i18n key="share.existing_hidden"/></strong></p>"#
                .to_string()
        } else {
            format!(
                r#"<p class="vl-muted"><vl-i18n key="public.target_folder"/>: /{}</p>"#,
                esc(&upload_path)
            )
        };
        let panel_tag = if split_layout { "aside" } else { "section" };
        body += &format!(
            r#"<{panel_tag} class="vl-panel vl-upload-panel"><h2>{}</h2>{target_hint}<form method="post" enctype="multipart/form-data" action="/v/{token}/upload" class="vl-stack" data-upload-queue data-queue-endpoint="/v/{token}/upload/queue"><input type="hidden" name="path" value="{}"><input type="hidden" name="csrf" value="{}"><label class="vl-upload-dropzone" data-upload-dropzone>{}<strong><vl-i18n key="upload.drop_here"/></strong><span class="vl-muted"><vl-i18n key="upload.or_choose"/></span><input class="vl-upload-input" type="file" name="file" required data-upload-input></label>{}<div class="vl-upload-queue" data-upload-list aria-live="polite"></div><button class="vl-button" data-upload-submit>{} <vl-i18n key="upload.securely"/></button><p class="vl-muted"><vl-i18n key="share.no_replace_help"/></p></form></{panel_tag}>"#,
            if sh.permission == Permission::UploadOnly {
                i18n::text(i18n::current_locale(), i18n::UPLOAD_FILE)
            } else {
                i18n::text(i18n::current_locale(), i18n::UPLOAD_FILES_PUBLIC)
            },
            esc(&upload_path),
            esc(upload_csrf.as_deref().unwrap_or("")),
            crate::ui::icon(crate::ui::Icon::Upload),
            overwrite_checkbox,
            crate::ui::icon(crate::ui::Icon::Upload),
        );
    }
    if split_layout {
        body += "</div>";
    }
    Ok(Html(plain_page("Freigabe", &body)))
}
fn joined_relative(base: &str, child: &str) -> Result<String> {
    let mut path = path_security::validate_relative(base)
        .map_err(|_| AppError(StatusCode::FORBIDDEN, "Ungültiger Pfad"))?;
    path.push(
        path_security::validate_relative(child)
            .map_err(|_| AppError(StatusCode::FORBIDDEN, "Ungültiger Pfad"))?,
    );
    Ok(path.to_string_lossy().replace('\\', "/"))
}

pub(super) async fn short_redirect(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AxPath(alias): AxPath<String>,
) -> Result<Redirect> {
    let ip = proxy::client_limit_key(proxy::effective_client_ip(
        peer.ip(),
        &headers,
        &state.config,
    ));
    if !state
        .alias_limiter
        .check_and_record_attempt(&format!("alias:{ip}"))
    {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele Alias-Anfragen",
        ));
    }
    if path_security::validate_share_alias(&alias).is_err() {
        return Err(AppError(StatusCode::NOT_FOUND, "Alias nicht gefunden"));
    }
    let sh = database(state.db.clone(), move |db| db.share_by_alias(&alias))
        .await?
        .ok_or(AppError(StatusCode::NOT_FOUND, "Alias nicht gefunden"))?;
    usable(&sh)?;
    Ok(Redirect::to(&format!("/v/{}", sh.token)))
}
