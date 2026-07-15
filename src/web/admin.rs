use axum::{
    extract::{Form, Path as AxPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, Redirect},
};
use serde::Deserialize;

use crate::{
    auth,
    db::AdminDeactivationOutcome,
    http_auth::{
        audit_sync, csrf, database, enabled_audit_client_ip, hash_password_admitted, session,
        MissingSession,
    },
    AppState,
};

use super::{
    admin_page, admin_page_without_locale_switcher, esc, format_audit_time, otpauth_url, qr_svg,
    AppError, CsrfForm, PageId, Result,
};

pub(super) async fn admins_page(
    State(state): State<AppState>,
    Query(query): Query<AdminNoticeQuery>,
    headers: HeaderMap,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let admins = database(state.db.clone(), |db| db.list_admins()).await?;
    let mut active_rows = String::new();
    let mut inactive_rows = String::new();
    for admin in admins {
        let action = if admin.id == session.admin_id {
            r#"<div class="vl-stack"><span class="vl-badge vl-badge--accent"><vl-i18n key="admins.current"/></span></div>"#
                .to_string()
        } else {
            let status_action = if admin.active {
                format!(
                    r#"<form method="post" action="/admin/admins/{}/deactivate"><input type="hidden" name="csrf" value="{}"><button class="vl-button vl-button--secondary"><vl-i18n key="admins.deactivate"/></button></form>"#,
                    admin.id,
                    esc(&session.csrf_token)
                )
            } else {
                format!(
                    r#"<form method="post" action="/admin/admins/{}/activate"><input type="hidden" name="csrf" value="{}"><button class="vl-button"><vl-i18n key="admins.activate"/></button></form>"#,
                    admin.id,
                    esc(&session.csrf_token)
                )
            };
            format!(
                r#"<div class="vl-stack"><div class="vl-button-group">{}<form method="post" action="/admin/admins/{}/totp"><input type="hidden" name="csrf" value="{}"><button class="vl-button vl-button--secondary"><vl-i18n key="admins.reset_mfa"/></button></form></div><form method="post" action="/admin/admins/{}/password" class="vl-form-grid"><input type="hidden" name="csrf" value="{}"><label class="vl-field"><vl-i18n key="account.new_password"/><input name="password" type="password" minlength="14" maxlength="1024" required></label><label class="vl-field"><vl-i18n key="common.confirm"/><input name="password_confirm" type="password" minlength="14" maxlength="1024" required></label><button class="vl-button"><vl-i18n key="admins.set_password"/></button></form></div>"#,
                status_action,
                admin.id,
                esc(&session.csrf_token),
                admin.id,
                esc(&session.csrf_token)
            )
        };
        let row = format!(
            r#"<tr><td data-label="ID">{}</td><td data-label="<vl-i18n key="auth.username"/>">{}</td><td data-label="<vl-i18n key="common.created"/>">{}</td><td data-label="<vl-i18n key="common.action"/>">{}</td></tr>"#,
            admin.id,
            esc(&admin.username),
            esc(&format_audit_time(&admin.created_at)),
            action
        );
        if admin.active {
            active_rows.push_str(&row);
        } else {
            inactive_rows.push_str(&row);
        }
    }
    if active_rows.is_empty() {
        active_rows.push_str(
            r#"<tr><td colspan="4" class="vl-muted"><vl-i18n key="admins.no_active"/></td></tr>"#,
        );
    }
    if inactive_rows.is_empty() {
        inactive_rows.push_str(
            r#"<tr><td colspan="4" class="vl-muted"><vl-i18n key="admins.no_inactive"/></td></tr>"#,
        );
    }
    let notice = match query.notice.as_deref() {
        Some("password_reset") => {
            r#"<p class="vl-notice vl-notice--success"><vl-i18n key="admins.password_set"/></p>"#
        }
        _ => "",
    };
    let body = format!(
        r#"<section class="vl-panel"><h2><vl-i18n key="nav.admins"/></h2>{notice}<div class="vl-stack"><details class="vl-form-card" open><summary><vl-i18n key="admins.active"/></summary><div class="vl-table-wrap"><table class="vl-data-table"><thead><tr><th>ID</th><th><vl-i18n key="auth.username"/></th><th><vl-i18n key="common.created"/></th><th><vl-i18n key="common.action"/></th></tr></thead><tbody>{active_rows}</tbody></table></div></details><details class="vl-form-card" open><summary><vl-i18n key="admins.inactive"/></summary><div class="vl-table-wrap"><table class="vl-data-table"><thead><tr><th>ID</th><th><vl-i18n key="auth.username"/></th><th><vl-i18n key="common.created"/></th><th><vl-i18n key="common.action"/></th></tr></thead><tbody>{inactive_rows}</tbody></table></div></details></div></section><section class="vl-panel"><h2><vl-i18n key="admins.create"/></h2><form method="post" class="vl-admin-create-form"><input type="hidden" name="csrf" value="{}"><label class="vl-field"><vl-i18n key="auth.username"/><input name="username" pattern="[A-Za-z0-9_-]{{3,64}}" required></label><label class="vl-field"><vl-i18n key="auth.password"/><input name="password" type="password" minlength="14" maxlength="1024" required></label><label class="vl-field"><vl-i18n key="account.confirm_password"/><input name="password_confirm" type="password" minlength="14" maxlength="1024" required></label><button class="vl-button"><vl-i18n key="common.create"/></button></form></section>"#,
        esc(&session.csrf_token)
    );
    Ok(Html(admin_page(
        &state,
        PageId::Admins,
        &body,
        false,
        &session.csrf_token,
    )))
}

#[derive(Deserialize)]
pub(super) struct CreateAdminUiForm {
    csrf: String,
    username: String,
    password: String,
    password_confirm: String,
}

#[derive(Deserialize)]
pub(super) struct ResetAdminPasswordForm {
    csrf: String,
    password: String,
    password_confirm: String,
}

#[derive(Deserialize, Default)]
pub(super) struct AdminNoticeQuery {
    notice: Option<String>,
}

pub(super) async fn create_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateAdminUiForm>,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    if !auth::valid_admin_username(&form.username) {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Benutzername muss 3-64 sichere ASCII-Zeichen enthalten",
        ));
    }
    if form.password != form.password_confirm {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Passwörter stimmen nicht überein",
        ));
    }
    if !auth::valid_admin_password(&form.password) {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Passwort muss mindestens 14 Zeichen und darf höchstens 1024 Byte enthalten",
        ));
    }
    let username = form.username.clone();
    let secret = auth::new_totp_secret();
    let hash = hash_password_admitted(&state, form.password).await?;
    let created_username = username.clone();
    let created_secret = secret.clone();
    let audit_actor = session.username;
    let audit_client_ip = enabled_audit_client_ip(&state);
    database(state.db.clone(), move |db| {
        db.create_admin(&created_username, &hash, &created_secret)?;
        audit_sync(
            &db,
            &audit_actor,
            "admin_created",
            Some(&created_username),
            None,
            audit_client_ip.as_deref(),
        );
        Ok(())
    })
    .await
    .map_err(|_| AppError(StatusCode::CONFLICT, "Benutzername existiert bereits"))?;
    let otpauth = otpauth_url(&username, &secret);
    let qr = qr_svg(&otpauth)?;
    let body = format!(
        r#"<section class="vl-panel"><h2><vl-i18n key="title.admin_created"/></h2><p><vl-i18n key="admins.secret_once"/></p><p><strong>{}</strong></p><div class="vl-qr-card" aria-label="TOTP QR-Code">{}</div><div class="vl-secret-block"><code>{}</code><code>{}</code></div><p><a class="vl-button vl-button--secondary" href="/admin/admins"><vl-i18n key="admins.to_list"/></a></p></section>"#,
        esc(&username),
        qr,
        esc(&secret),
        esc(&otpauth)
    );
    Ok(Html(admin_page_without_locale_switcher(
        &state,
        PageId::AdminCreated,
        &body,
        false,
        &session.csrf_token,
    )))
}

pub(super) async fn reset_admin_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(form): Form<ResetAdminPasswordForm>,
) -> Result<Redirect> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    if id == session.admin_id {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Eigenes Passwort kann hier nicht zurückgesetzt werden",
        ));
    }
    if form.password != form.password_confirm {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Passwörter stimmen nicht überein",
        ));
    }
    if !auth::valid_admin_password(&form.password) {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Passwort muss mindestens 14 Zeichen und darf höchstens 1024 Byte enthalten",
        ));
    }
    let hash = hash_password_admitted(&state, form.password).await?;
    let audit_actor = session.username;
    let audit_object = id.to_string();
    let audit_client_ip = enabled_audit_client_ip(&state);
    let changed = database(state.db.clone(), move |db| {
        let changed = db.reset_admin_password(id, &hash)?;
        if changed {
            audit_sync(
                &db,
                &audit_actor,
                "admin_password_reset",
                Some(&audit_object),
                None,
                audit_client_ip.as_deref(),
            );
        }
        Ok(changed)
    })
    .await?;
    if !changed {
        return Err(AppError(StatusCode::NOT_FOUND, "Admin nicht gefunden"));
    }
    Ok(Redirect::to("/admin/admins?notice=password_reset"))
}

pub(super) async fn reset_admin_totp(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    if id == session.admin_id {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Eigene MFA kann hier nicht zurückgesetzt werden",
        ));
    }
    let secret = auth::new_totp_secret();
    let reset_secret = secret.clone();
    let audit_actor = session.username;
    let audit_object = id.to_string();
    let audit_client_ip = enabled_audit_client_ip(&state);
    let username = database(state.db.clone(), move |db| {
        let username = db.reset_admin_totp(id, &reset_secret)?;
        if username.is_some() {
            audit_sync(
                &db,
                &audit_actor,
                "admin_totp_reset",
                Some(&audit_object),
                None,
                audit_client_ip.as_deref(),
            );
        }
        Ok(username)
    })
    .await?
    .ok_or(AppError(StatusCode::NOT_FOUND, "Admin nicht gefunden"))?;
    let otpauth = otpauth_url(&username, &secret);
    let qr = qr_svg(&otpauth)?;
    let body = format!(
        r#"<section class="vl-panel"><h2><vl-i18n key="title.mfa_reset"/></h2><p><vl-i18n key="admins.new_secret_once"/></p><p><strong>{}</strong></p><div class="vl-qr-card" aria-label="TOTP QR-Code">{}</div><div class="vl-secret-block"><code>{}</code><code>{}</code></div><p><a class="vl-button vl-button--secondary" href="/admin/admins"><vl-i18n key="admins.to_list"/></a></p></section>"#,
        esc(&username),
        qr,
        esc(&secret),
        esc(&otpauth)
    );
    Ok(Html(admin_page_without_locale_switcher(
        &state,
        PageId::MfaReset,
        &body,
        false,
        &session.csrf_token,
    )))
}

pub(super) async fn deactivate_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Redirect> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    if id == session.admin_id {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Eigener Admin kann nicht stillgelegt werden",
        ));
    }
    let audit_actor = session.username;
    let audit_object = id.to_string();
    let audit_client_ip = enabled_audit_client_ip(&state);
    let outcome = database(state.db.clone(), move |db| {
        let outcome = db.deactivate_admin(id)?;
        if matches!(
            outcome,
            AdminDeactivationOutcome::Deactivated | AdminDeactivationOutcome::AlreadyInactive
        ) {
            audit_sync(
                &db,
                &audit_actor,
                "admin_deactivated",
                Some(&audit_object),
                None,
                audit_client_ip.as_deref(),
            );
        }
        Ok(outcome)
    })
    .await?;
    match outcome {
        AdminDeactivationOutcome::Deactivated | AdminDeactivationOutcome::AlreadyInactive => {}
        AdminDeactivationOutcome::LastActive => {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "Letzter aktiver Admin kann nicht stillgelegt werden",
            ));
        }
        AdminDeactivationOutcome::NotFound => {
            return Err(AppError(StatusCode::NOT_FOUND, "Admin nicht gefunden"));
        }
    }
    Ok(Redirect::to("/admin/admins"))
}

pub(super) async fn activate_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Redirect> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    let audit_actor = session.username;
    let audit_object = id.to_string();
    let audit_client_ip = enabled_audit_client_ip(&state);
    let changed = database(state.db.clone(), move |db| {
        let changed = db.activate_admin(id)?;
        if changed {
            audit_sync(
                &db,
                &audit_actor,
                "admin_activated",
                Some(&audit_object),
                None,
                audit_client_ip.as_deref(),
            );
        }
        Ok(changed)
    })
    .await?;
    if !changed {
        return Err(AppError(StatusCode::NOT_FOUND, "Admin nicht gefunden"));
    }
    Ok(Redirect::to("/admin/admins"))
}
