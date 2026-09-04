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
    templates::{admin_page as render_admin_page, TrustedMarkup},
    AppError, Result,
};
use crate::{
    auth,
    db::{
        AdminMfaEnrollmentActivationOutcome, AdminPasswordChangeOutcome, AdminTotpSettingOutcome,
        AdminWebauthnCredentialDeletionOutcome, AuditAction, AuditContext,
        AuditedAdminMfaEnrollmentStartOutcome, Database, RequiredAuditEvent,
    },
    http_auth::{
        audit_observation, clear_session_cookie, csrf, current_audit_client_ip, database,
        enabled_audit_client_ip, hash_password_admitted, mfa_session, redirect_with_cookie,
        required_database, runtime_settings, session, verify_password_admitted, MissingSession,
    },
    sensitive::SecretString,
    webauthn::WebAuthnServiceError,
    AppState,
};

enum SecurityKeyRegistrationFinishError {
    Database(rusqlite::Error),
    Webauthn(WebAuthnServiceError),
}

impl From<rusqlite::Error> for SecurityKeyRegistrationFinishError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

impl From<WebAuthnServiceError> for SecurityKeyRegistrationFinishError {
    fn from(error: WebAuthnServiceError) -> Self {
        Self::Webauthn(error)
    }
}

fn security_key_registration_finish_error(error: SecurityKeyRegistrationFinishError) -> AppError {
    match error {
        SecurityKeyRegistrationFinishError::Webauthn(_error) => {
            AppError(StatusCode::BAD_REQUEST, "Invalid security-key response")
        }
        SecurityKeyRegistrationFinishError::Database(error)
            if matches!(
                &error,
                rusqlite::Error::SqliteFailure(failure, _)
                    if failure.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
            ) =>
        {
            AppError(StatusCode::CONFLICT, "Security key is already registered")
        }
        SecurityKeyRegistrationFinishError::Database(error) => {
            AppError::from(crate::http_auth::database_error(error))
        }
    }
}

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
    qr: &'a TrustedMarkup,
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
    let authenticated = mfa_session(&state, &headers, MissingSession::RedirectToLogin).await?;
    csrf(&authenticated, &body.csrf)?;
    let limiter_key = format!("security-key-register:{}", authenticated.admin_id);
    if !state.limiter.check_and_record_attempt(&limiter_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many password attempts",
        ));
    }
    let label = body.label.trim();
    if label.is_empty() || label.chars().count() > 80 {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Invalid security-key label",
        ));
    }
    let username = authenticated.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username))
        .await?
        .ok_or(AppError(StatusCode::UNAUTHORIZED, "Sign-in required"))?;
    let password_hash = admin.password_hash;
    let current_password = body.current_password;
    if current_password.expose_secret().len() > auth::MAX_PASSWORD_BYTES {
        audit_observation(
            &state,
            authenticated.username.clone(),
            AuditAction::SecurityKeyReauthFailed,
            None,
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }
    let password_valid =
        verify_password_admitted(&state, Some(password_hash), current_password).await?;
    if !password_valid {
        audit_observation(
            &state,
            authenticated.username.clone(),
            AuditAction::SecurityKeyReauthFailed,
            None,
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }
    // Successful password reauthentication remains rate-limited.
    let admin_id = authenticated.admin_id;
    let rows = database(state.db.clone(), move |db| {
        db.admin_webauthn_credentials(admin_id)
    })
    .await?;
    let existing = decode_security_keys(&rows)?;
    let security_settings_guard = state.security_settings_mutation.clone().lock_owned().await;
    let webauthn = crate::http_auth::webauthn_service(&state)?;
    let username = authenticated.username.clone();
    let proof = authenticated.proof().clone();
    let ceremony_key = proof.webauthn_registration_key();
    let registration = required_database(state.db.clone(), move |db| {
        // Keep the RP/origin snapshot and pending-ceremony mutation ordered
        // with settings replacement even if the HTTP future is cancelled.
        let _security_settings_guard = security_settings_guard;
        let prepared =
            match webauthn.prepare_registration(ceremony_key, admin_id, &username, &existing) {
                Ok(prepared) => prepared,
                Err(error) => {
                    return Ok(crate::db::SessionBound::Authorized(Err(error)));
                }
            };
        webauthn.with_registration_mutations(|registrations| {
            db.with_live_mfa_fence(&proof, || {
                Ok::<_, rusqlite::Error>(registrations.commit_start(prepared))
            })
        })
    })
    .await?;
    webauthn_start_response(super::session_bound(registration)?)
}

#[derive(Deserialize)]
pub(super) struct SecurityKeyRegistrationFinish {
    csrf: String,
    label: String,
    credential: serde_json::Value,
}

pub(super) async fn finish_security_key_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SecurityKeyRegistrationFinish>,
) -> Result<Json<serde_json::Value>> {
    let authenticated = mfa_session(&state, &headers, MissingSession::RedirectToLogin).await?;
    csrf(&authenticated, &body.csrf)?;
    let label = body.label.trim().to_string();
    if label.is_empty() || label.chars().count() > 80 {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Invalid security-key label",
        ));
    }
    let security_settings_guard = state.security_settings_mutation.clone().lock_owned().await;
    let webauthn = crate::http_auth::webauthn_service(&state)?;
    let admin_id = authenticated.admin_id;
    let proof = authenticated.proof().clone();
    let ceremony_key = proof.webauthn_registration_key();
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(authenticated.username.clone(), audit_client_ip);
    let database = state.db.clone();
    let credential = body.credential;
    let registration = tokio::task::spawn_blocking(move || {
        // The complete settings -> pending registration -> SQLite writer
        // boundary remains alive even if the HTTP future is cancelled.
        let _security_settings_guard = security_settings_guard;
        webauthn.with_registration_mutations(|registrations| {
            database.required_transaction_for_mfa_session(&proof, &audit_context, |transaction| {
                // The live-session predicate has succeeded while BEGIN
                // IMMEDIATE is held. Only now may this single-use challenge
                // be consumed and its credential made durable.
                let key = registrations.finish(&ceremony_key, admin_id, &credential)?;
                let credential_id =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.credential_id());
                let credential_blob = key.to_blob()?;
                Database::insert_admin_webauthn_credential_in_transaction(
                    transaction,
                    &proof,
                    &label,
                    &credential_id,
                    &credential_blob,
                )?;
                Ok((
                    (),
                    vec![RequiredAuditEvent::new(
                        AuditAction::WebauthnCredentialAdded,
                        None,
                        None,
                    )],
                ))
            })
        })
    })
    .await
    .map_err(internal)?
    .map_err(security_key_registration_finish_error)?;
    super::session_bound(registration)?;
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
) -> Result<Response> {
    let authenticated = mfa_session(&state, &headers, MissingSession::RedirectToLogin).await?;
    csrf(&authenticated, &form.csrf)?;
    let limiter_key = format!("security-key-delete:{}", authenticated.admin_id);
    if !state.limiter.check_and_record_attempt(&limiter_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many password attempts",
        ));
    }
    let username = authenticated.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username))
        .await?
        .ok_or(AppError(StatusCode::UNAUTHORIZED, "Sign-in required"))?;
    let expected_password_hash = admin.password_hash;
    let expected_totp_secret = admin.totp_secret;
    let expected_totp_generation = admin.totp_generation;
    let totp_enabled = admin.totp_enabled;
    let password = form.current_password;
    if password.expose_secret().len() > auth::MAX_PASSWORD_BYTES {
        audit_observation(
            &state,
            authenticated.username.clone(),
            AuditAction::SecurityKeyReauthFailed,
            Some(id.to_string()),
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }
    let password_valid =
        verify_password_admitted(&state, Some(expected_password_hash.clone()), password).await?;
    if !password_valid {
        audit_observation(
            &state,
            authenticated.username.clone(),
            AuditAction::SecurityKeyReauthFailed,
            Some(id.to_string()),
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid credentials"));
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
            authenticated.username.clone(),
            AuditAction::SecurityKeyReauthFailed,
            Some(id.to_string()),
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }
    // Successful password reauthentication remains rate-limited.
    let security_settings_guard = state.security_settings_mutation.clone().lock_owned().await;
    let proof = authenticated.proof().clone();
    let audit_client_ip = enabled_audit_client_ip(&state);
    let outcome = required_database(state.db.clone(), move |db| {
        // Credential deletion changes the WebAuthn credential count and must
        // serialize with public-base-URL/runtime replacement.
        let _security_settings_guard = security_settings_guard;
        if totp_enabled {
            db.delete_admin_webauthn_credential_with_totp_for_mfa_session(
                &proof,
                id,
                &expected_password_hash,
                expected_totp_generation,
                totp_step.expect("enabled TOTP was validated before the database task"),
                audit_client_ip.as_deref(),
            )
        } else {
            db.delete_admin_webauthn_credential_without_totp_for_mfa_session(
                &proof,
                id,
                &expected_password_hash,
                audit_client_ip.as_deref(),
            )
        }
    })
    .await?;
    let outcome = super::session_bound(outcome)?;
    match outcome {
        AdminWebauthnCredentialDeletionOutcome::Deleted => Ok(redirect_with_cookie(
            "/login",
            &clear_session_cookie(&state),
        )?),
        AdminWebauthnCredentialDeletionOutcome::ReauthenticationRejected
        | AdminWebauthnCredentialDeletionOutcome::TotpRejected => {
            audit_observation(
                &state,
                authenticated.username.clone(),
                AuditAction::SecurityKeyReauthFailed,
                Some(id.to_string()),
                None,
            )
            .await;
            Err(AppError(StatusCode::UNAUTHORIZED, "Invalid credentials"))
        }
        AdminWebauthnCredentialDeletionOutcome::NotDeleted => {
            Err(AppError(StatusCode::CONFLICT, "Security key not found"))
        }
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
    let authenticated = mfa_session(&state, &headers, MissingSession::RedirectToLogin).await?;
    csrf(&authenticated, &form.csrf)?;
    let limiter_key = format!("account-totp-setting:{}", authenticated.admin_id);
    if !state.limiter.check_and_record_attempt(&limiter_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many password attempts",
        ));
    }
    let username = authenticated.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username))
        .await?
        .ok_or(AppError(StatusCode::UNAUTHORIZED, "Sign-in required"))?;
    let expected_password_hash = admin.password_hash;
    let expected_totp_secret = admin.totp_secret;
    let expected_totp_generation = admin.totp_generation;
    let password = form.current_password;
    if password.expose_secret().len() > auth::MAX_PASSWORD_BYTES {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }
    let password_valid =
        verify_password_admitted(&state, Some(expected_password_hash.clone()), password).await?;
    if !password_valid {
        audit_observation(
            &state,
            authenticated.username.clone(),
            AuditAction::AccountTotpSettingReauthFailed,
            None,
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid credentials"));
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
            authenticated.username.clone(),
            AuditAction::AccountTotpSettingReauthFailed,
            None,
            None,
        )
        .await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }
    let enabled = form.enabled;
    let audit_client_ip = enabled_audit_client_ip(&state);
    let security_settings_guard = state.security_settings_mutation.clone().lock_owned().await;
    let proof = authenticated.proof().clone();
    let outcome = required_database(state.db.clone(), move |db| {
        let _security_settings_guard = security_settings_guard;
        db.set_admin_totp_enabled_with_reauthentication_for_mfa_session(
            &proof,
            &expected_password_hash,
            expected_totp_generation,
            enabled,
            totp_step,
            audit_client_ip.as_deref(),
        )
    })
    .await?;
    let outcome = super::session_bound(outcome)?;
    match outcome {
        AdminTotpSettingOutcome::Updated | AdminTotpSettingOutcome::Unchanged => {
            Ok(Redirect::to("/admin/account"))
        }
        AdminTotpSettingOutcome::InsufficientSecurityKeys => Err(AppError(
            StatusCode::CONFLICT,
            "At least two security keys are required",
        )),
        AdminTotpSettingOutcome::ReauthenticationRejected
        | AdminTotpSettingOutcome::TotpRejected => {
            audit_observation(
                &state,
                authenticated.username.clone(),
                AuditAction::AccountTotpSettingReauthFailed,
                None,
                None,
            )
            .await;
            Err(AppError(StatusCode::UNAUTHORIZED, "Invalid credentials"))
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
    let authenticated = mfa_session(&state, &headers, MissingSession::RedirectToLogin).await?;
    csrf(&authenticated, &form.csrf)?;
    let limiter_key = format!("account-password:{}", authenticated.admin_id);
    if !state.limiter.check_and_record_attempt(&limiter_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many password attempts",
        ));
    }

    let username = authenticated.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username))
        .await?
        .ok_or(AppError(StatusCode::UNAUTHORIZED, "Sign-in required"))?;
    let expected_hash = admin.password_hash.clone();
    let verification_hash = expected_hash.clone();
    let current_password = form.current_password;
    if current_password.expose_secret().len() > auth::MAX_PASSWORD_BYTES {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }
    let current_password_valid =
        verify_password_admitted(&state, Some(verification_hash), current_password).await?;
    if !current_password_valid {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }
    // Successful password reauthentication remains rate-limited.

    if !form
        .new_password
        .matches_confirmation(&form.password_confirm)
    {
        return Err(AppError(StatusCode::BAD_REQUEST, "Passwords do not match"));
    }
    if !auth::valid_admin_password(form.new_password.expose_secret()) {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Password must contain at least 14 and at most 256 characters",
        ));
    }
    drop(form.password_confirm);
    let new_hash = hash_password_admitted(&state, form.new_password).await?;
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(authenticated.username.clone(), audit_client_ip);
    let proof = authenticated.proof().clone();
    let outcome = required_database(state.db.clone(), move |db| {
        db.change_admin_password_cas_for_session(&proof, &expected_hash, &new_hash, &audit_context)
    })
    .await?;
    let outcome = super::session_bound(outcome)?;
    match outcome {
        AdminPasswordChangeOutcome::Changed => Ok(redirect_with_cookie(
            "/login",
            &clear_session_cookie(&state),
        )?),
        AdminPasswordChangeOutcome::StalePassword => {
            Err(AppError(StatusCode::CONFLICT, "Account change failed."))
        }
        AdminPasswordChangeOutcome::Inactive | AdminPasswordChangeOutcome::NotFound => {
            Err(AppError(StatusCode::UNAUTHORIZED, "Sign-in required"))
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
    let authenticated = mfa_session(&state, &headers, MissingSession::RedirectToLogin).await?;
    csrf(&authenticated, &form.csrf)?;
    let limiter_key = format!("account-mfa-start:{}", authenticated.admin_id);
    if !state.limiter.check_and_record_attempt(&limiter_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many MFA attempts",
        ));
    }

    let username = authenticated.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username))
        .await?
        .ok_or(AppError(StatusCode::UNAUTHORIZED, "Sign-in required"))?;
    let verification_hash = admin.password_hash;
    let current_password = form.current_password;
    if current_password.expose_secret().len() > auth::MAX_PASSWORD_BYTES {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid credentials"));
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
        return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    };
    // Successful password reauthentication remains rate-limited.

    let enrollment_token = auth::random_token(32);
    let new_secret = auth::new_totp_secret_value();
    let response_secret = new_secret.duplicate_for_one_time_response();
    let token_for_db = enrollment_token.clone();
    let audit_context = AuditContext::new(
        authenticated.username.clone(),
        enabled_audit_client_ip(&state),
    );
    let proof = authenticated.proof().clone();
    let outcome = required_database(state.db.clone(), move |db| {
        db.start_admin_mfa_enrollment_and_audit_for_session(
            &proof,
            &token_for_db,
            new_secret.expose_secret(),
            totp_step,
            &audit_context,
        )
    })
    .await?;
    let outcome = super::session_bound(outcome)?;
    let expires_at = match outcome {
        AuditedAdminMfaEnrollmentStartOutcome::Started { expires_at } => expires_at,
        AuditedAdminMfaEnrollmentStartOutcome::AdminInactive
        | AuditedAdminMfaEnrollmentStartOutcome::AdminNotFound => {
            return Err(AppError(StatusCode::UNAUTHORIZED, "Sign-in required"));
        }
        AuditedAdminMfaEnrollmentStartOutcome::TotpRejected => {
            return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid credentials"));
        }
    };
    let expires_at = DateTime::parse_from_rfc3339(&expires_at)
        .map(|value| format_utc_minute(value.with_timezone(&Utc)))
        .unwrap_or(expires_at);
    let otpauth = otpauth_url(&authenticated.username, response_secret.expose_secret());
    let qr = qr_svg(otpauth.expose_secret())?;
    let body = MfaEnrollmentTemplate {
        qr: &qr,
        secret: response_secret.expose_secret(),
        otpauth: otpauth.expose_secret(),
        expires_at: &expires_at,
        csrf: &authenticated.csrf_token,
        enrollment_token: &enrollment_token,
    };
    Ok(Html(render_admin_page(
        &state,
        PageId::Account,
        &body,
        false,
        &authenticated.csrf_token,
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
    let authenticated = mfa_session(&state, &headers, MissingSession::RedirectToLogin).await?;
    csrf(&authenticated, &form.csrf)?;
    if form.enrollment_token.is_empty() || form.enrollment_token.len() > 256 {
        return Err(AppError(StatusCode::BAD_REQUEST, "Account change failed."));
    }
    let limiter_key = format!("account-mfa-confirm:{}", authenticated.admin_id);
    if !state.limiter.check_and_record_attempt(&limiter_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many MFA attempts",
        ));
    }
    let admin_id = authenticated.admin_id;
    let lookup_token = form.enrollment_token.clone();
    let enrollment = database(state.db.clone(), move |db| {
        db.admin_mfa_enrollment(admin_id, &lookup_token)
    })
    .await?
    .ok_or(AppError(StatusCode::CONFLICT, "Account change failed."))?;
    let Some(totp_step) = auth::matching_totp_step_now(
        enrollment.totp_secret.expose_secret(),
        form.code.expose_secret(),
    ) else {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid MFA code"));
    };
    let activation_token = form.enrollment_token;
    let audit_client_ip = runtime_settings(&state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(authenticated.username.clone(), audit_client_ip);
    let proof = authenticated.proof().clone();
    let outcome = required_database(state.db.clone(), move |db| {
        db.activate_admin_mfa_enrollment_for_session(
            &proof,
            &activation_token,
            totp_step,
            &audit_context,
        )
    })
    .await?;
    let outcome = super::session_bound(outcome)?;
    match outcome {
        AdminMfaEnrollmentActivationOutcome::Activated => {
            // Keep the attempt history until its normal expiry. Clearing it
            // after the database commit would let an old request mutate
            // process state after a concurrent revocation has returned; the
            // fail-closed retention is both bounded and cancellation-safe.
            Ok(redirect_with_cookie(
                "/login",
                &clear_session_cookie(&state),
            )?)
        }
        AdminMfaEnrollmentActivationOutcome::NotFoundOrExpired => {
            Err(AppError(StatusCode::CONFLICT, "Account change failed."))
        }
    }
}
