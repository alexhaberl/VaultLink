use askama::Template;
use axum::{
    extract::{Form, Json, Path as AxPath, State},
    http::{HeaderMap, StatusCode},
    response::{Html, Redirect, Response},
};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::common::webauthn_start_response;
use super::{
    common::{decode_security_keys, format_utc_minute, internal, otpauth_url, qr_svg},
    rendering::PageId,
    templates::admin_page as render_admin_page,
    AppError, Result,
};
use crate::{
    auth,
    db::{
        AdminMfaEnrollmentActivationOutcome, AdminPasswordChangeOutcome, AdminTotpSettingOutcome,
        AdminWebauthnCredentialDeletionOutcome, AdminWebauthnCredentialRegistrationOutcome,
        AuditContext, AuditedAdminMfaEnrollmentStartOutcome,
    },
    http_auth::{
        audit_observation, clear_session_cookie, csrf, current_audit_client_ip, database,
        enabled_audit_client_ip, hash_password_admitted, redirect_with_cookie, required_database,
        runtime_settings, session, verify_password_admitted, MissingSession,
    },
    sensitive::SecretString,
    AppState,
};

struct SecurityKeyView {
    id: i64,
    label: String,
    created_at: String,
}

#[derive(Template)]
#[template(path = "web/account/account.html")]
struct AccountTemplate<'a> {
    username: &'a str,
    csrf: &'a str,
    security_keys: Vec<SecurityKeyView>,
    totp_enabled: bool,
    totp_can_disable: bool,
}

#[derive(Template)]
#[template(path = "web/account/mfa_enrollment.html")]
struct MfaEnrollmentTemplate<'a> {
    qr: &'a str,
    secret: &'a str,
    otpauth: &'a str,
    expires_at: &'a str,
    csrf: &'a str,
    enrollment_token: &'a str,
}

#[derive(Deserialize)]
pub(super) struct SecurityKeyRegistrationStart {
    csrf: String,
    current_password: SecretString,
    label: String,
}

pub(super) async fn start_security_key_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SecurityKeyRegistrationStart>,
) -> Result<Response> {
    let (token, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &body.csrf)?;
    let limiter_key = format!("security-key-register:{}", session.admin_id);
    if !state.limiter.check_and_record_attempt(&limiter_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele Passwortversuche",
        ));
    }
    let label = body.label.trim();
    if label.is_empty() || label.chars().count() > 80 {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Ungültiger Schlüsselname",
        ));
    }
    let username = session.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username))
        .await?
        .ok_or(AppError(StatusCode::UNAUTHORIZED, "Anmeldung erforderlich"))?;
    let password_hash = admin.password_hash;
    let current_password = body.current_password;
    if current_password.expose_secret().len() > auth::MAX_PASSWORD_BYTES {
        audit_observation(
            &state,
            session.username,
            "security_key_reauth_failed",
            None,
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    let password_valid =
        verify_password_admitted(&state, Some(password_hash), current_password).await?;
    if !password_valid {
        audit_observation(
            &state,
            session.username,
            "security_key_reauth_failed",
            None,
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    // Successful password reauthentication remains rate-limited.
    let admin_id = session.admin_id;
    let rows = database(state.db.clone(), move |db| {
        db.admin_webauthn_credentials(admin_id)
    })
    .await?;
    let existing = decode_security_keys(&rows)?;
    let webauthn = crate::http_auth::webauthn_service(&state)?;
    webauthn_start_response(webauthn.start_registration(
        &token,
        admin_id,
        &session.username,
        &existing,
    ))
}

#[derive(Deserialize)]
pub(super) struct SecurityKeyRegistrationFinish {
    csrf: String,
    label: String,
    credential: webauthn_rs::prelude::RegisterPublicKeyCredential,
}

pub(super) async fn finish_security_key_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SecurityKeyRegistrationFinish>,
) -> Result<Json<serde_json::Value>> {
    let (token, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &body.csrf)?;
    let label = body.label.trim().to_string();
    if label.is_empty() || label.chars().count() > 80 {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Ungültiger Schlüsselname",
        ));
    }
    let security_settings_guard = state.security_settings_mutation.clone().lock_owned().await;
    let webauthn = crate::http_auth::webauthn_service(&state)?;
    let key = webauthn
        .finish_registration(&token, session.admin_id, &body.credential)
        .map_err(|_| {
            AppError(
                StatusCode::BAD_REQUEST,
                "Ungültige Sicherheitsschlüssel-Antwort",
            )
        })?;
    let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.cred_id());
    let credential_json = serde_json::to_string(&key).map_err(internal)?;
    let admin_id = session.admin_id;
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let registration = required_database(state.db.clone(), move |db| {
        // Keep origin changes serialized even if the HTTP request is cancelled
        // after this non-cancellable database task has started.
        let _security_settings_guard = security_settings_guard;
        db.add_admin_webauthn_credential_for_session(
            &token,
            admin_id,
            &label,
            &credential_id,
            &credential_json,
            audit_client_ip.as_deref(),
        )
    })
    .await
    .map_err(|error| {
        if error.status == StatusCode::SERVICE_UNAVAILABLE {
            return AppError::from(error);
        }
        AppError(
            StatusCode::CONFLICT,
            "Sicherheitsschlüssel ist bereits registriert",
        )
    })?;
    if registration == AdminWebauthnCredentialRegistrationOutcome::SessionUnavailable {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Anmeldung erforderlich"));
    }
    Ok(Json(serde_json::json!({"redirect":"/admin/account"})))
}

#[derive(Deserialize)]
pub(super) struct DeleteSecurityKeyForm {
    csrf: String,
    current_password: SecretString,
    current_code: Option<SecretString>,
}

pub(super) async fn delete_security_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(form): Form<DeleteSecurityKeyForm>,
) -> Result<Redirect> {
    let (token, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    let limiter_key = format!("security-key-delete:{}", session.admin_id);
    if !state.limiter.check_and_record_attempt(&limiter_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele Passwortversuche",
        ));
    }
    let username = session.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username))
        .await?
        .ok_or(AppError(StatusCode::UNAUTHORIZED, "Anmeldung erforderlich"))?;
    let expected_password_hash = admin.password_hash;
    let expected_totp_secret = admin.totp_secret;
    let totp_enabled = admin.totp_enabled;
    let password = form.current_password;
    if password.expose_secret().len() > auth::MAX_PASSWORD_BYTES {
        audit_observation(
            &state,
            session.username,
            "security_key_reauth_failed",
            Some(id.to_string()),
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    let password_valid =
        verify_password_admitted(&state, Some(expected_password_hash.clone()), password).await?;
    if !password_valid {
        audit_observation(
            &state,
            session.username,
            "security_key_reauth_failed",
            Some(id.to_string()),
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    let totp_step = if totp_enabled {
        form.current_code.as_ref().and_then(|code| {
            auth::matching_totp_step_now(expected_totp_secret.expose_secret(), code.expose_secret())
        })
    } else {
        None
    };
    if totp_enabled && totp_step.is_none() {
        audit_observation(
            &state,
            session.username,
            "security_key_reauth_failed",
            Some(id.to_string()),
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    // Successful password reauthentication remains rate-limited.
    let admin_id = session.admin_id;
    let audit_client_ip = enabled_audit_client_ip(&state);
    let outcome = required_database(state.db.clone(), move |db| {
        if totp_enabled {
            db.delete_admin_webauthn_credential_with_totp(
                &token,
                id,
                admin_id,
                &expected_password_hash,
                expected_totp_secret.expose_secret(),
                totp_step.expect("enabled TOTP was validated before the database task"),
                audit_client_ip.as_deref(),
            )
        } else {
            db.delete_admin_webauthn_credential_without_totp(
                &token,
                id,
                admin_id,
                &expected_password_hash,
                audit_client_ip.as_deref(),
            )
        }
    })
    .await?;
    match outcome {
        AdminWebauthnCredentialDeletionOutcome::Deleted => Ok(Redirect::to("/admin/account")),
        AdminWebauthnCredentialDeletionOutcome::ReauthenticationRejected
        | AdminWebauthnCredentialDeletionOutcome::TotpRejected => {
            audit_observation(
                &state,
                session.username,
                "security_key_reauth_failed",
                Some(id.to_string()),
                None,
            )
            .await;
            Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"))
        }
        AdminWebauthnCredentialDeletionOutcome::NotDeleted => Err(AppError(
            StatusCode::CONFLICT,
            "Sicherheitsschlüssel nicht gefunden",
        )),
    }
}

pub(super) async fn account_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let admin_id = session.admin_id;
    let username = session.username.clone();
    let (security_keys, totp_enabled) = database(state.db.clone(), move |db| {
        let keys = db.admin_webauthn_credentials(admin_id)?;
        let admin = db
            .admin(&username)?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        Ok((keys, admin.totp_enabled))
    })
    .await?;
    let totp_can_disable = security_keys.len() >= 2;
    let body = AccountTemplate {
        username: &session.username,
        csrf: &session.csrf_token,
        security_keys: security_keys
            .into_iter()
            .map(|key| {
                let created_at = DateTime::parse_from_rfc3339(&key.created_at)
                    .map(|value| format_utc_minute(value.with_timezone(&Utc)))
                    .unwrap_or(key.created_at);
                SecurityKeyView {
                    id: key.id,
                    label: key.label,
                    created_at,
                }
            })
            .collect(),
        totp_enabled,
        totp_can_disable,
    };
    Ok(Html(render_admin_page(
        &state,
        PageId::Account,
        &body,
        false,
        &session.csrf_token,
        true,
    )?))
}

#[derive(Deserialize)]
pub(super) struct AccountTotpSettingForm {
    csrf: String,
    current_password: SecretString,
    current_code: Option<SecretString>,
    enabled: bool,
}

pub(super) async fn set_account_totp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AccountTotpSettingForm>,
) -> Result<Redirect> {
    let (token, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    let limiter_key = format!("account-totp-setting:{}", session.admin_id);
    if !state.limiter.check_and_record_attempt(&limiter_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele Passwortversuche",
        ));
    }
    let username = session.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username))
        .await?
        .ok_or(AppError(StatusCode::UNAUTHORIZED, "Anmeldung erforderlich"))?;
    let expected_password_hash = admin.password_hash;
    let expected_totp_secret = admin.totp_secret;
    let password = form.current_password;
    if password.expose_secret().len() > auth::MAX_PASSWORD_BYTES {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    let password_valid =
        verify_password_admitted(&state, Some(expected_password_hash.clone()), password).await?;
    if !password_valid {
        audit_observation(
            &state,
            session.username,
            "account_totp_setting_reauth_failed",
            None,
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    let totp_step = if form.enabled {
        None
    } else {
        form.current_code.as_ref().and_then(|code| {
            auth::matching_totp_step_now(expected_totp_secret.expose_secret(), code.expose_secret())
        })
    };
    if !form.enabled && totp_step.is_none() {
        audit_observation(
            &state,
            session.username,
            "account_totp_setting_reauth_failed",
            None,
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    let admin_id = session.admin_id;
    let enabled = form.enabled;
    let audit_client_ip = enabled_audit_client_ip(&state);
    let security_settings_guard = state.security_settings_mutation.clone().lock_owned().await;
    let outcome = required_database(state.db.clone(), move |db| {
        let _security_settings_guard = security_settings_guard;
        db.set_admin_totp_enabled_with_reauthentication(
            &token,
            admin_id,
            &expected_password_hash,
            expected_totp_secret.expose_secret(),
            enabled,
            totp_step,
            audit_client_ip.as_deref(),
        )
    })
    .await?;
    match outcome {
        AdminTotpSettingOutcome::Updated | AdminTotpSettingOutcome::Unchanged => {
            Ok(Redirect::to("/admin/account"))
        }
        AdminTotpSettingOutcome::InsufficientSecurityKeys => Err(AppError(
            StatusCode::CONFLICT,
            "Mindestens zwei Sicherheitsschlüssel erforderlich",
        )),
        AdminTotpSettingOutcome::ReauthenticationRejected
        | AdminTotpSettingOutcome::TotpRejected => {
            audit_observation(
                &state,
                session.username,
                "account_totp_setting_reauth_failed",
                None,
                None,
            )
            .await;
            Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"))
        }
    }
}

#[derive(Deserialize)]
pub(super) struct AccountPasswordForm {
    csrf: String,
    current_password: SecretString,
    new_password: SecretString,
    password_confirm: SecretString,
}

pub(super) async fn change_account_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AccountPasswordForm>,
) -> Result<Response> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    let limiter_key = format!("account-password:{}", session.admin_id);
    if !state.limiter.check_and_record_attempt(&limiter_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele Passwortversuche",
        ));
    }

    let username = session.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username))
        .await?
        .ok_or(AppError(StatusCode::UNAUTHORIZED, "Anmeldung erforderlich"))?;
    let expected_hash = admin.password_hash.clone();
    let verification_hash = expected_hash.clone();
    let current_password = form.current_password;
    if current_password.expose_secret().len() > auth::MAX_PASSWORD_BYTES {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    let current_password_valid =
        verify_password_admitted(&state, Some(verification_hash), current_password).await?;
    if !current_password_valid {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    // Successful password reauthentication remains rate-limited.

    if !form
        .new_password
        .matches_confirmation(&form.password_confirm)
    {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Passwörter stimmen nicht überein",
        ));
    }
    if !auth::valid_admin_password(form.new_password.expose_secret()) {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Passwort muss mindestens 14 und darf höchstens 256 Zeichen enthalten",
        ));
    }
    drop(form.password_confirm);
    let new_hash = hash_password_admitted(&state, form.new_password).await?;
    let admin_id = session.admin_id;
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let outcome = required_database(state.db.clone(), move |db| {
        db.change_admin_password_cas(
            admin_id,
            &expected_hash,
            &new_hash,
            audit_client_ip.as_deref(),
        )
    })
    .await?;
    match outcome {
        AdminPasswordChangeOutcome::Changed => Ok(redirect_with_cookie(
            "/login",
            clear_session_cookie(&state),
        )?),
        AdminPasswordChangeOutcome::StalePassword => Err(AppError(
            StatusCode::CONFLICT,
            "Kontoänderung fehlgeschlagen.",
        )),
        AdminPasswordChangeOutcome::Inactive | AdminPasswordChangeOutcome::NotFound => {
            Err(AppError(StatusCode::UNAUTHORIZED, "Anmeldung erforderlich"))
        }
    }
}

#[derive(Deserialize)]
pub(super) struct AccountMfaStartForm {
    csrf: String,
    current_password: SecretString,
    current_code: SecretString,
}

pub(super) async fn start_account_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AccountMfaStartForm>,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    let limiter_key = format!("account-mfa-start:{}", session.admin_id);
    if !state.limiter.check_and_record_attempt(&limiter_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele MFA-Versuche",
        ));
    }

    let username = session.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username))
        .await?
        .ok_or(AppError(StatusCode::UNAUTHORIZED, "Anmeldung erforderlich"))?;
    let verification_hash = admin.password_hash;
    let current_password = form.current_password;
    if current_password.expose_secret().len() > auth::MAX_PASSWORD_BYTES {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    let current_password_valid =
        verify_password_admitted(&state, Some(verification_hash), current_password).await?;
    let totp_step = current_password_valid
        .then(|| {
            auth::matching_totp_step_now(
                admin.totp_secret.expose_secret(),
                form.current_code.expose_secret(),
            )
        })
        .flatten();
    let Some(totp_step) = totp_step else {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    };
    // Successful password reauthentication remains rate-limited.

    let enrollment_token = auth::random_token(32);
    let new_secret = auth::new_totp_secret_value();
    let response_secret = new_secret.duplicate_for_one_time_response();
    let admin_id = session.admin_id;
    let token_for_db = enrollment_token.clone();
    let audit_context =
        AuditContext::new(session.username.clone(), enabled_audit_client_ip(&state));
    let outcome = required_database(state.db.clone(), move |db| {
        db.start_admin_mfa_enrollment_and_audit(
            admin_id,
            &token_for_db,
            new_secret.expose_secret(),
            totp_step,
            &audit_context,
        )
    })
    .await?;
    let expires_at = match outcome {
        AuditedAdminMfaEnrollmentStartOutcome::Started { expires_at } => expires_at,
        AuditedAdminMfaEnrollmentStartOutcome::AdminInactive
        | AuditedAdminMfaEnrollmentStartOutcome::AdminNotFound => {
            return Err(AppError(StatusCode::UNAUTHORIZED, "Anmeldung erforderlich"));
        }
        AuditedAdminMfaEnrollmentStartOutcome::TotpRejected => {
            return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
        }
    };
    let expires_at = DateTime::parse_from_rfc3339(&expires_at)
        .map(|value| format_utc_minute(value.with_timezone(&Utc)))
        .unwrap_or(expires_at);
    let otpauth = otpauth_url(&session.username, response_secret.expose_secret());
    let qr = qr_svg(otpauth.expose_secret())?;
    let body = MfaEnrollmentTemplate {
        qr: &qr,
        secret: response_secret.expose_secret(),
        otpauth: otpauth.expose_secret(),
        expires_at: &expires_at,
        csrf: &session.csrf_token,
        enrollment_token: &enrollment_token,
    };
    Ok(Html(render_admin_page(
        &state,
        PageId::Account,
        &body,
        false,
        &session.csrf_token,
        false,
    )?))
}

#[derive(Deserialize)]
pub(super) struct AccountMfaConfirmForm {
    csrf: String,
    enrollment_token: String,
    code: SecretString,
}

pub(super) async fn confirm_account_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AccountMfaConfirmForm>,
) -> Result<Response> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    csrf(&session, &form.csrf)?;
    if form.enrollment_token.is_empty() || form.enrollment_token.len() > 256 {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Kontoänderung fehlgeschlagen.",
        ));
    }
    let limiter_key = format!("account-mfa-confirm:{}", session.admin_id);
    if !state.limiter.check_and_record_attempt(&limiter_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele MFA-Versuche",
        ));
    }
    let admin_id = session.admin_id;
    let lookup_token = form.enrollment_token.clone();
    let enrollment = database(state.db.clone(), move |db| {
        db.admin_mfa_enrollment(admin_id, &lookup_token)
    })
    .await?
    .ok_or(AppError(
        StatusCode::CONFLICT,
        "Kontoänderung fehlgeschlagen.",
    ))?;
    let Some(totp_step) = auth::matching_totp_step_now(
        enrollment.totp_secret.expose_secret(),
        form.code.expose_secret(),
    ) else {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültiger MFA-Code"));
    };
    let activation_token = form.enrollment_token;
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let outcome = required_database(state.db.clone(), move |db| {
        db.activate_admin_mfa_enrollment(
            admin_id,
            &activation_token,
            totp_step,
            audit_client_ip.as_deref(),
        )
    })
    .await?;
    match outcome {
        AdminMfaEnrollmentActivationOutcome::Activated => {
            state.limiter.success(&limiter_key);
            Ok(redirect_with_cookie(
                "/login",
                clear_session_cookie(&state),
            )?)
        }
        AdminMfaEnrollmentActivationOutcome::NotFoundOrExpired => Err(AppError(
            StatusCode::CONFLICT,
            "Kontoänderung fehlgeschlagen.",
        )),
    }
}
