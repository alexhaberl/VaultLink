use axum::{
    extract::{Form, Path as AxPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, Redirect},
};
use serde::Deserialize;

use crate::{
    db::{AdminDeactivationOutcome, AuditContext},
    http_auth::{
        csrf, database, enabled_audit_client_ip, hash_password_admitted, required_database,
        session, MissingSession,
    },
    sensitive::SecretString,
    services::admin::{AdminActivationResult, AdminService, AdminServiceError, CreateAdminCommand},
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
    password: SecretString,
    password_confirm: SecretString,
}

#[derive(Deserialize)]
pub(super) struct ResetAdminPasswordForm {
    csrf: String,
    password: SecretString,
    password_confirm: SecretString,
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
    let service = AdminService::new(state.db.clone());
    let validated = service
        .prepare_create(CreateAdminCommand {
            username: form.username,
            password: form.password,
            confirmation: Some(form.password_confirm),
        })
        .map_err(admin_validation_error)?;
    let (prepared, password) = validated.into_hash_input();
    let hash = hash_password_admitted(&state, password).await?;
    let audit_context = AuditContext::new(session.username, enabled_audit_client_ip(&state));
    let create_result = required_database(state.db.clone(), move |_| {
        service
            .create(prepared, hash, &audit_context)
            .map_err(admin_database_error)
    })
    .await;
    let created = match create_result {
        Ok(created) => created,
        Err(error) if error.status == StatusCode::SERVICE_UNAVAILABLE => {
            return Err(error.into());
        }
        Err(_) => {
            return Err(AppError(
                StatusCode::CONFLICT,
                "Benutzername existiert bereits",
            ));
        }
    };
    let username = created.summary.username;
    let response_secret = created.totp_secret;
    let otpauth = otpauth_url(&username, response_secret.expose_secret());
    let qr = qr_svg(otpauth.expose_secret())?;
    let body = format!(
        r#"<section class="vl-panel"><h2><vl-i18n key="title.admin_created"/></h2><p><vl-i18n key="admins.secret_once"/></p><p><strong>{}</strong></p><div class="vl-qr-card" aria-label="TOTP QR-Code">{}</div><div class="vl-secret-block"><code>{}</code><code>{}</code></div><p><a class="vl-button vl-button--secondary" href="/admin/admins"><vl-i18n key="admins.to_list"/></a></p></section>"#,
        esc(&username),
        qr,
        esc(response_secret.expose_secret()),
        esc(otpauth.expose_secret())
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
    let service = AdminService::new(state.db.clone());
    let password = service
        .prepare_password(form.password, Some(form.password_confirm))
        .map_err(admin_validation_error)?;
    let hash = hash_password_admitted(&state, password).await?;
    let audit_context = AuditContext::new(session.username, enabled_audit_client_ip(&state));
    let changed = required_database(state.db.clone(), move |_| {
        service
            .reset_password(id, &hash, &audit_context)
            .map_err(admin_database_error)
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
    let audit_context = AuditContext::new(session.username, enabled_audit_client_ip(&state));
    let service = AdminService::new(state.db.clone());
    let reset = required_database(state.db.clone(), move |_| {
        service
            .reset_totp(id, &audit_context)
            .map_err(admin_database_error)
    })
    .await?
    .ok_or(AppError(StatusCode::NOT_FOUND, "Admin nicht gefunden"))?;
    let username = reset.username;
    let response_secret = reset.totp_secret;
    let otpauth = otpauth_url(&username, response_secret.expose_secret());
    let qr = qr_svg(otpauth.expose_secret())?;
    let body = format!(
        r#"<section class="vl-panel"><h2><vl-i18n key="title.mfa_reset"/></h2><p><vl-i18n key="admins.new_secret_once"/></p><p><strong>{}</strong></p><div class="vl-qr-card" aria-label="TOTP QR-Code">{}</div><div class="vl-secret-block"><code>{}</code><code>{}</code></div><p><a class="vl-button vl-button--secondary" href="/admin/admins"><vl-i18n key="admins.to_list"/></a></p></section>"#,
        esc(&username),
        qr,
        esc(response_secret.expose_secret()),
        esc(otpauth.expose_secret())
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
    let audit_context = AuditContext::new(session.username, enabled_audit_client_ip(&state));
    let service = AdminService::new(state.db.clone());
    let outcome = required_database(state.db.clone(), move |_| {
        service
            .set_active(id, false, &audit_context)
            .map_err(admin_database_error)
    })
    .await?;
    match outcome {
        AdminActivationResult::Deactivation(outcome) => match outcome {
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
        },
        AdminActivationResult::NotFound => {
            return Err(AppError(StatusCode::NOT_FOUND, "Admin nicht gefunden"));
        }
        AdminActivationResult::Changed => {}
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
    let audit_context = AuditContext::new(session.username, enabled_audit_client_ip(&state));
    let service = AdminService::new(state.db.clone());
    let outcome = required_database(state.db.clone(), move |_| {
        service
            .set_active(id, true, &audit_context)
            .map_err(admin_database_error)
    })
    .await?;
    if outcome == AdminActivationResult::NotFound {
        return Err(AppError(StatusCode::NOT_FOUND, "Admin nicht gefunden"));
    }
    Ok(Redirect::to("/admin/admins"))
}

fn admin_validation_error(error: AdminServiceError) -> AppError {
    match error {
        AdminServiceError::InvalidUsername => AppError(
            StatusCode::BAD_REQUEST,
            "Benutzername muss 3-64 sichere ASCII-Zeichen enthalten",
        ),
        AdminServiceError::InvalidPassword => AppError(
            StatusCode::BAD_REQUEST,
            "Passwort muss mindestens 14 Zeichen und darf höchstens 1024 Byte enthalten",
        ),
        AdminServiceError::PasswordConfirmationMismatch => {
            AppError(StatusCode::BAD_REQUEST, "Passwörter stimmen nicht überein")
        }
        AdminServiceError::Database(_) => {
            AppError(StatusCode::INTERNAL_SERVER_ERROR, "Datenbankfehler")
        }
    }
}

fn admin_database_error(error: AdminServiceError) -> rusqlite::Error {
    error
        .into_database_error()
        .unwrap_or(rusqlite::Error::InvalidQuery)
}
