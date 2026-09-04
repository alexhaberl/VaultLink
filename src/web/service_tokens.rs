use askama::Template;
use axum::{
    extract::{Form, Path as AxPath, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::{Months, Utc};
use serde::Deserialize;

use crate::{
    auth,
    db::{
        valid_service_token_name, AuditContext, ServiceTokenCreationOutcome,
        SERVICE_TOKEN_NAME_MAX_CHARACTERS, SERVICE_TOKEN_NAME_MIN_CHARACTERS,
        SERVICE_TOKEN_SCOPE_MONITORING_READ,
    },
    http_auth::{
        csrf, database, enabled_audit_client_ip, mfa_session, required_mfa_audit_database, session,
        verify_password_admitted, MissingSession, SERVICE_TOKEN_PREFIX, SERVICE_TOKEN_RANDOM_BYTES,
    },
    i18n,
    sensitive::SecretString,
    ServiceTokenRouteState,
};

use super::{
    common::{format_audit_time, parse_expiry, CsrfForm},
    rendering::PageId,
    session_bound,
    templates::admin_page as render_admin_page,
    AppError, Result,
};

struct ServiceTokenRow {
    id: i64,
    name: String,
    scope: &'static str,
    created_by: String,
    created_at: String,
    expires_at: String,
    last_used_at: String,
    status_key: &'static str,
    status_tone: &'static str,
}

#[derive(Template)]
#[template(path = "web/admin/service_tokens.html")]
struct ServiceTokensTemplate<'a> {
    rows: Vec<ServiceTokenRow>,
    csrf: &'a str,
    revoked: bool,
    default_expires_at: String,
    name_min_length: usize,
    name_max_length: usize,
    password_max_length: usize,
    name_label: &'static str,
    scope_label: &'static str,
    created_by_label: &'static str,
    created_label: &'static str,
    expires_label: &'static str,
    last_used_label: &'static str,
    status_label: &'static str,
    action_label: &'static str,
}

#[derive(Template)]
#[template(path = "web/admin/service_token_created.html")]
struct ServiceTokenCreatedTemplate<'a> {
    name: &'a str,
    token: &'a str,
}

#[derive(Default, Deserialize)]
pub(super) struct ServiceTokenNoticeQuery {
    notice: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct CreateServiceTokenForm {
    csrf: String,
    current_password: SecretString,
    name: String,
    expires_at: Option<String>,
    expires_tz_offset_minutes: Option<String>,
    no_expiry: Option<String>,
}

pub(super) async fn service_tokens_page(
    State(state): State<ServiceTokenRouteState>,
    Query(query): Query<ServiceTokenNoticeQuery>,
    headers: HeaderMap,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let tokens = database(state.db().clone(), |database| {
        database.list_service_tokens()
    })
    .await?;
    let locale = i18n::current_locale();
    let now = Utc::now();
    let rows = tokens
        .into_iter()
        .map(|token| {
            let expired = token
                .expires_at
                .as_deref()
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .is_some_and(|expires_at| expires_at <= now);
            ServiceTokenRow {
                id: token.id,
                name: token.name,
                scope: if token.scope_mask == SERVICE_TOKEN_SCOPE_MONITORING_READ {
                    "monitoring:read"
                } else {
                    "unknown"
                },
                created_by: token.created_by_username,
                created_at: format_audit_time(&token.created_at),
                expires_at: token
                    .expires_at
                    .as_deref()
                    .map(format_audit_time)
                    .unwrap_or_else(|| i18n::text(locale, i18n::SERVICE_TOKEN_NEVER).to_string()),
                last_used_at: token
                    .last_used_at
                    .as_deref()
                    .map(format_audit_time)
                    .unwrap_or_else(|| {
                        i18n::text(locale, i18n::SERVICE_TOKEN_NOT_USED).to_string()
                    }),
                status_key: if expired {
                    "service_tokens.expired"
                } else {
                    "service_tokens.active"
                },
                status_tone: if expired { "warning" } else { "success" },
            }
        })
        .collect();
    let body = ServiceTokensTemplate {
        rows,
        csrf: &session.csrf_token,
        revoked: query.notice.as_deref() == Some("revoked"),
        default_expires_at: default_expiry_value(now),
        name_min_length: SERVICE_TOKEN_NAME_MIN_CHARACTERS,
        name_max_length: SERVICE_TOKEN_NAME_MAX_CHARACTERS,
        password_max_length: auth::MAX_PASSWORD_BYTES,
        name_label: i18n::text(locale, i18n::SERVICE_TOKEN_NAME),
        scope_label: i18n::text(locale, i18n::SERVICE_TOKEN_SCOPE),
        created_by_label: i18n::text(locale, i18n::SERVICE_TOKEN_CREATED_BY),
        created_label: i18n::text(locale, i18n::CREATED),
        expires_label: i18n::text(locale, i18n::SERVICE_TOKEN_EXPIRES),
        last_used_label: i18n::text(locale, i18n::SERVICE_TOKEN_LAST_USED),
        status_label: i18n::text(locale, i18n::STATUS),
        action_label: i18n::text(locale, i18n::ACTION),
    };
    Ok(Html(render_admin_page(
        &state,
        PageId::ServiceTokens,
        &body,
        false,
        &session.csrf_token,
        true,
    )?))
}

pub(super) async fn create_service_token(
    State(state): State<ServiceTokenRouteState>,
    headers: HeaderMap,
    Form(form): Form<CreateServiceTokenForm>,
) -> Result<Response> {
    let authenticated = mfa_session(&state, &headers, MissingSession::RedirectToLogin).await?;
    csrf(&authenticated, &form.csrf)?;

    let name = form.name;
    if !valid_service_token_name(&name) {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Invalid service token name",
        ));
    }
    let no_expiry = match form.no_expiry.as_deref() {
        None => false,
        Some("1") => true,
        Some(_) => {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "Invalid service token expiration setting",
            ));
        }
    };
    let expires_at = if no_expiry {
        None
    } else {
        Some(
            parse_expiry(
                form.expires_at.as_deref(),
                form.expires_tz_offset_minutes.as_deref(),
            )?
            .ok_or(AppError(
                StatusCode::BAD_REQUEST,
                "Choose an expiration date or explicitly select no expiration",
            ))?,
        )
    };
    if expires_at.is_some_and(|value| value <= Utc::now()) {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Expiration date is in the past",
        ));
    }

    let limiter_key = format!("service-token-create:{}", authenticated.admin_id);
    if !state.login_limiter().check_and_record_attempt(&limiter_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many password attempts",
        ));
    }
    let username = authenticated.username.clone();
    let admin = database(state.db().clone(), move |database| {
        database.admin(&username)
    })
    .await?
    .ok_or(AppError(StatusCode::UNAUTHORIZED, "Sign-in required"))?;
    let expected_password_hash = admin.password_hash;
    let current_password = form.current_password;
    if current_password.expose_secret().len() > auth::MAX_PASSWORD_BYTES {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }
    let password_valid = verify_password_admitted(
        &state,
        Some(expected_password_hash.clone()),
        current_password,
    )
    .await?;
    if !password_valid {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }
    // Successful password reauthentication remains rate-limited.

    let plaintext_token = SecretString::from(format!(
        "{SERVICE_TOKEN_PREFIX}{}",
        auth::random_token(SERVICE_TOKEN_RANDOM_BYTES)
    ));
    let response_token = plaintext_token.duplicate_for_one_time_response();
    let response_name = name.clone();
    let response_session = (*authenticated).clone();
    let audit_client_ip = enabled_audit_client_ip(&state);
    let outcome = required_mfa_audit_database(
        state.db().clone(),
        authenticated,
        move |database, session, proof| {
            let audit_context = AuditContext::new(session.username, audit_client_ip);
            database.create_service_token_for_mfa_session(
                &proof,
                &expected_password_hash,
                &name,
                plaintext_token.expose_secret(),
                expires_at,
                &audit_context,
            )
        },
    )
    .await?;
    let outcome = session_bound(outcome)?;

    match outcome {
        ServiceTokenCreationOutcome::Created(_) => {
            let response_token = response_token.into_one_time_response();
            let body = ServiceTokenCreatedTemplate {
                name: &response_name,
                token: &response_token,
            };
            let html = render_admin_page(
                &state,
                PageId::ServiceTokenCreated,
                &body,
                false,
                &response_session.csrf_token,
                false,
            )?;
            Ok(no_store_html(html))
        }
        ServiceTokenCreationOutcome::ReauthenticationRejected => {
            Err(AppError(StatusCode::UNAUTHORIZED, "Invalid credentials"))
        }
        ServiceTokenCreationOutcome::CapacityReached => Err(AppError(
            StatusCode::CONFLICT,
            "Service token capacity reached",
        )),
        ServiceTokenCreationOutcome::NameConflict => Err(AppError(
            StatusCode::CONFLICT,
            "Service token name already exists",
        )),
    }
}

pub(super) async fn revoke_service_token(
    State(state): State<ServiceTokenRouteState>,
    headers: HeaderMap,
    AxPath(id): AxPath<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Redirect> {
    let authenticated = mfa_session(&state, &headers, MissingSession::RedirectToLogin).await?;
    csrf(&authenticated, &form.csrf)?;
    let audit_client_ip = enabled_audit_client_ip(&state);
    let revoked = required_mfa_audit_database(
        state.db().clone(),
        authenticated,
        move |database, session, proof| {
            let audit_context = AuditContext::new(session.username, audit_client_ip);
            database.revoke_service_token_for_mfa_session(&proof, id, &audit_context)
        },
    )
    .await?;
    let revoked = session_bound(revoked)?;
    if !revoked {
        return Err(AppError(StatusCode::NOT_FOUND, "Service token not found"));
    }
    Ok(Redirect::to("/admin/service-tokens?notice=revoked"))
}

fn default_expiry_value(now: chrono::DateTime<Utc>) -> String {
    now.checked_add_months(Months::new(12))
        .expect("adding twelve months to a supported UI timestamp must succeed")
        .format("%Y-%m-%dT%H:%M")
        .to_string()
}

fn no_store_html(html: String) -> Response {
    let mut response = Html(html).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    #[test]
    fn default_expiry_is_one_year_ahead() {
        let now = Utc.with_ymd_and_hms(2026, 8, 30, 13, 45, 0).unwrap();
        assert_eq!(default_expiry_value(now), "2027-08-30T13:45");
    }

    #[test]
    fn default_expiry_clamps_a_leap_day_to_the_next_calendar_year() {
        let now = Utc.with_ymd_and_hms(2024, 2, 29, 13, 45, 0).unwrap();
        assert_eq!(default_expiry_value(now), "2025-02-28T13:45");
    }

    #[test]
    fn one_time_response_is_explicitly_not_cacheable() {
        let response = no_store_html("secret".to_string());
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
    }
}
