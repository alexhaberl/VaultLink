use askama::Template;
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
    i18n,
    sensitive::SecretString,
    services::admin::{AdminActivationResult, AdminService, AdminServiceError, CreateAdminCommand},
    AppState,
};

use super::{
    common::{format_audit_time, otpauth_url, qr_svg, CsrfForm},
    rendering::PageId,
    templates::{admin_page as render_admin_page, TrustedMarkup},
    AppError, Result,
};

struct AdminRow {
    id: i64,
    username: String,
    created_at: String,
    active: bool,
    current: bool,
}

struct AdminGroup {
    label_key: &'static str,
    empty_key: &'static str,
    rows: Vec<AdminRow>,
}

#[derive(Template)]
#[template(path = "web/admin/admins.html")]
struct AdminsTemplate<'a> {
    groups: Vec<AdminGroup>,
    csrf: &'a str,
    password_reset: bool,
    username_label: &'static str,
    created_label: &'static str,
    action_label: &'static str,
}

#[derive(Template)]
#[template(path = "web/admin/totp_secret.html")]
struct TotpSecretTemplate<'a> {
    title_key: &'static str,
    help_key: &'static str,
    username: &'a str,
    qr: &'a TrustedMarkup,
    secret: &'a str,
    otpauth: &'a str,
}

pub(super) async fn admins_page(
    State(state): State<AppState>,
    Query(query): Query<AdminNoticeQuery>,
    headers: HeaderMap,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let admins = database(state.db.clone(), |db| db.list_admins()).await?;
    let mut active_rows = Vec::new();
    let mut inactive_rows = Vec::new();
    for admin in admins {
        let active = admin.active;
        let row = AdminRow {
            id: admin.id,
            username: admin.username,
            created_at: format_audit_time(&admin.created_at),
            active,
            current: admin.id == session.admin_id,
        };
        if active {
            active_rows.push(row);
        } else {
            inactive_rows.push(row);
        }
    }
    let body = AdminsTemplate {
        groups: vec![
            AdminGroup {
                label_key: "admins.active",
                empty_key: "admins.no_active",
                rows: active_rows,
            },
            AdminGroup {
                label_key: "admins.inactive",
                empty_key: "admins.no_inactive",
                rows: inactive_rows,
            },
        ],
        csrf: &session.csrf_token,
        password_reset: query.notice.as_deref() == Some("password_reset"),
        username_label: i18n::text(i18n::current_locale(), i18n::USERNAME),
        created_label: i18n::text(i18n::current_locale(), i18n::CREATED),
        action_label: i18n::text(i18n::current_locale(), i18n::ACTION),
    };
    Ok(Html(render_admin_page(
        &state,
        PageId::Admins,
        &body,
        false,
        &session.csrf_token,
        true,
    )?))
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
        .map_err(|error| admin_validation_error(&error))?;
    let (prepared, password) = validated.into_hash_input();
    let hash = hash_password_admitted(&state, password).await?;
    let audit_context = AuditContext::new(session.username, enabled_audit_client_ip(&state));
    let create_result = required_database(state.db.clone(), move |database| {
        let created = service
            .create(&prepared, &hash, &audit_context)
            .map_err(admin_database_error)?;
        Ok((created, database.active_admin_usernames()?))
    })
    .await;
    let (created, active_admins) = match create_result {
        Ok(result) => result,
        Err(error) if error.status == StatusCode::SERVICE_UNAVAILABLE => {
            return Err(error.into());
        }
        Err(_) => {
            return Err(AppError(StatusCode::CONFLICT, "Username already exists"));
        }
    };
    state
        .admin_login_limiter
        .replace_active_admins(active_admins);
    let username = created.summary.username;
    let response_secret = created.totp_secret;
    let otpauth = otpauth_url(&username, response_secret.expose_secret());
    let qr = qr_svg(otpauth.expose_secret())?;
    let body = TotpSecretTemplate {
        title_key: "title.admin_created",
        help_key: "admins.secret_once",
        username: &username,
        qr: &qr,
        secret: response_secret.expose_secret(),
        otpauth: otpauth.expose_secret(),
    };
    Ok(Html(render_admin_page(
        &state,
        PageId::AdminCreated,
        &body,
        false,
        &session.csrf_token,
        false,
    )?))
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
            "Your own password cannot be reset here",
        ));
    }
    let service = AdminService::new(state.db.clone());
    let password = service
        .prepare_password(form.password, Some(form.password_confirm))
        .map_err(|error| admin_validation_error(&error))?;
    let hash = hash_password_admitted(&state, password).await?;
    let audit_context = AuditContext::new(session.username, enabled_audit_client_ip(&state));
    let changed = required_database(state.db.clone(), move |_| {
        service
            .reset_password(id, &hash, &audit_context)
            .map_err(admin_database_error)
    })
    .await?;
    if !changed {
        return Err(AppError(StatusCode::NOT_FOUND, "Admin not found"));
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
            "Your own MFA cannot be reset here",
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
    .ok_or(AppError(StatusCode::NOT_FOUND, "Admin not found"))?;
    let username = reset.username;
    let response_secret = reset.totp_secret;
    let otpauth = otpauth_url(&username, response_secret.expose_secret());
    let qr = qr_svg(otpauth.expose_secret())?;
    let body = TotpSecretTemplate {
        title_key: "title.mfa_reset",
        help_key: "admins.new_secret_once",
        username: &username,
        qr: &qr,
        secret: response_secret.expose_secret(),
        otpauth: otpauth.expose_secret(),
    };
    Ok(Html(render_admin_page(
        &state,
        PageId::MfaReset,
        &body,
        false,
        &session.csrf_token,
        false,
    )?))
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
            "Your own administrator account cannot be deactivated",
        ));
    }
    let audit_context = AuditContext::new(session.username, enabled_audit_client_ip(&state));
    let service = AdminService::new(state.db.clone());
    let (outcome, active_admins) = required_database(state.db.clone(), move |database| {
        let outcome = service
            .set_active(id, false, &audit_context)
            .map_err(admin_database_error)?;
        Ok((outcome, database.active_admin_usernames()?))
    })
    .await?;
    state
        .admin_login_limiter
        .replace_active_admins(active_admins);
    match outcome {
        AdminActivationResult::Deactivation(outcome) => match outcome {
            AdminDeactivationOutcome::Deactivated | AdminDeactivationOutcome::AlreadyInactive => {}
            AdminDeactivationOutcome::LastActive => {
                return Err(AppError(
                    StatusCode::BAD_REQUEST,
                    "The final active admin cannot be deactivated",
                ));
            }
            AdminDeactivationOutcome::NotFound => {
                return Err(AppError(StatusCode::NOT_FOUND, "Admin not found"));
            }
        },
        AdminActivationResult::NotFound => {
            return Err(AppError(StatusCode::NOT_FOUND, "Admin not found"));
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
    let (outcome, active_admins) = required_database(state.db.clone(), move |database| {
        let outcome = service
            .set_active(id, true, &audit_context)
            .map_err(admin_database_error)?;
        Ok((outcome, database.active_admin_usernames()?))
    })
    .await?;
    state
        .admin_login_limiter
        .replace_active_admins(active_admins);
    if outcome == AdminActivationResult::NotFound {
        return Err(AppError(StatusCode::NOT_FOUND, "Admin not found"));
    }
    Ok(Redirect::to("/admin/admins"))
}

fn admin_validation_error(error: &AdminServiceError) -> AppError {
    match error {
        AdminServiceError::InvalidUsername => AppError(
            StatusCode::BAD_REQUEST,
            "Username must contain 3-64 safe ASCII characters",
        ),
        AdminServiceError::InvalidPassword => AppError(
            StatusCode::BAD_REQUEST,
            "Password must contain at least 14 and at most 256 characters",
        ),
        AdminServiceError::PasswordConfirmationMismatch => {
            AppError(StatusCode::BAD_REQUEST, "Passwords do not match")
        }
        AdminServiceError::Database(_) => {
            AppError(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
        }
    }
}

fn admin_database_error(error: AdminServiceError) -> rusqlite::Error {
    error
        .into_database_error()
        .unwrap_or(rusqlite::Error::InvalidQuery)
}
