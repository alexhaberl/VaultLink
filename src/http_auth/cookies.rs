pub fn named_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut found = None;
    for header_value in headers.get_all(header::COOKIE) {
        let value = header_value.to_str().ok()?;
        for pair in value.split(';') {
            let Some((key, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if key != name {
                continue;
            }
            // Ambiguous cookies are rejected instead of relying on ordering that
            // differs between browsers and can be influenced by sibling domains.
            if found.is_some() {
                return None;
            }
            found = Some(value);
        }
    }
    found
}

fn session_cookie_name(state: &AppState) -> &'static str {
    if state.config().security.secure_cookie {
        SECURE_SESSION_COOKIE
    } else {
        SESSION_COOKIE
    }
}

enum ExactHeader<'a> {
    Missing,
    One(&'a str),
    Malformed,
    Ambiguous,
}

fn exact_session_cookie<'a>(headers: &'a HeaderMap, name: &str) -> ExactHeader<'a> {
    let mut found = None;
    for header_value in headers.get_all(header::COOKIE) {
        let Ok(value) = header_value.to_str() else {
            return ExactHeader::Malformed;
        };
        for pair in value.split(';') {
            let Some((key, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if key != name {
                continue;
            }
            if found.is_some() {
                return ExactHeader::Ambiguous;
            }
            found = Some(value);
        }
    }
    found.map_or(ExactHeader::Missing, ExactHeader::One)
}

fn exact_authorization(headers: &HeaderMap) -> ExactHeader<'_> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return ExactHeader::Missing;
    };
    if values.next().is_some() {
        return ExactHeader::Ambiguous;
    }
    let Ok(value) = value.to_str() else {
        return ExactHeader::Malformed;
    };
    if value.contains(',') {
        return ExactHeader::Ambiguous;
    }
    ExactHeader::One(value)
}

fn strict_service_token(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    if bytes.len() < 7 || !bytes[..6].eq_ignore_ascii_case(b"Bearer") || bytes[6] != b' ' {
        return None;
    }
    let token = &value[7..];
    let encoded = token.strip_prefix(SERVICE_TOKEN_PREFIX)?;
    if encoded.len() != 43
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return None;
    }
    let decoded = zeroize::Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded.as_bytes()).ok()?);
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded.as_slice()) != encoded {
        return None;
    }
    Some(token)
}

enum MonitoringCredentials<'a> {
    Session,
    ServiceToken(&'a str),
}

// Keep syntax/ambiguity selection independent of database work. Both the HTTP
// adapter and the fuzz harness exercise this exact decision.
fn monitoring_credentials<'a>(
    headers: &'a HeaderMap,
    cookie_name: &str,
) -> Result<MonitoringCredentials<'a>> {
    let cookie = exact_session_cookie(headers, cookie_name);
    let authorization = exact_authorization(headers);
    match (cookie, authorization) {
        (ExactHeader::One(_), ExactHeader::One(_) | ExactHeader::Malformed)
        | (ExactHeader::One(_), ExactHeader::Ambiguous)
        | (ExactHeader::Ambiguous, _)
        | (_, ExactHeader::Ambiguous) => Err(HttpAuthError::with_kind(
            StatusCode::BAD_REQUEST,
            "Ambiguous authentication",
            HttpAuthErrorKind::AmbiguousAuthentication,
        )),
        (ExactHeader::Malformed, _) | (_, ExactHeader::Malformed) => Err(HttpAuthError::status(
            StatusCode::UNAUTHORIZED,
            "Invalid authentication",
        )),
        (ExactHeader::One(_), ExactHeader::Missing) => Ok(MonitoringCredentials::Session),
        (ExactHeader::Missing, ExactHeader::One(value)) => strict_service_token(value)
            .map(MonitoringCredentials::ServiceToken)
            .ok_or_else(|| HttpAuthError::status(StatusCode::UNAUTHORIZED, "Invalid authentication")),
        (ExactHeader::Missing, ExactHeader::Missing) => Err(HttpAuthError::status(
            StatusCode::UNAUTHORIZED,
            "Authentication required",
        )),
    }
}

/// Authorizes the deliberately narrow monitoring API with exactly one
/// authentication mechanism. All other administrator routes remain cookie-only.
pub(crate) async fn authorize_monitoring(
    state: &(impl Borrow<AppState> + ?Sized),
    headers: &HeaderMap,
) -> Result<()> {
    let state = borrowed_app_state(state);
    match monitoring_credentials(headers, session_cookie_name(state))? {
        MonitoringCredentials::Session => {
            session(state, headers, true, MissingSession::Unauthorized)
                .await
                .map(drop)
        }
        MonitoringCredentials::ServiceToken(value) => {
            let token = zeroize::Zeroizing::new(value.to_owned());
            let outcome = database(state.db().clone(), move |database| {
                database.authorize_service_token(
                    token.as_str(),
                    crate::db::SERVICE_TOKEN_SCOPE_MONITORING_READ,
                )
            })
            .await?;
            match outcome {
                crate::db::ServiceTokenAuthorizationOutcome::Authorized { .. } => Ok(()),
                crate::db::ServiceTokenAuthorizationOutcome::Unauthorized => Err(
                    HttpAuthError::status(StatusCode::UNAUTHORIZED, "Invalid authentication"),
                ),
                crate::db::ServiceTokenAuthorizationOutcome::InsufficientScope => {
                    Err(HttpAuthError::with_kind(
                        StatusCode::FORBIDDEN,
                        "Insufficient token scope",
                        HttpAuthErrorKind::InsufficientScope,
                    ))
                }
            }
        }
    }
}

pub fn session_cookie<'a>(
    state: &(impl Borrow<AppState> + ?Sized),
    headers: &'a HeaderMap,
) -> Option<&'a str> {
    named_cookie(headers, session_cookie_name(borrowed_app_state(state)))
}

pub async fn session(
    state: &(impl Borrow<AppState> + ?Sized),
    headers: &HeaderMap,
    require_mfa: bool,
    missing: MissingSession,
) -> Result<(String, Session)> {
    let state = borrowed_app_state(state);
    let token = session_cookie(state, headers).ok_or_else(|| match missing {
        MissingSession::RedirectToLogin => HttpAuthError::redirect("/login"),
        MissingSession::Unauthorized => {
            HttpAuthError::status(StatusCode::UNAUTHORIZED, "Sign-in required")
        }
    })?;
    let session_token = token.to_string();
    let session = database(state.db().clone(), move |db| db.session(&session_token))
        .await?
        .ok_or_else(|| {
            HttpAuthError::with_kind(
                StatusCode::UNAUTHORIZED,
                "Session is no longer authorized",
                HttpAuthErrorKind::SessionRevoked,
            )
        })?;
    if require_mfa && !session.mfa_verified {
        return Err(HttpAuthError::status(
            StatusCode::FORBIDDEN,
            "MFA verification required",
        ));
    }
    Ok((token.to_string(), session))
}

/// Performs the request-bound MFA check and retains only an opaque hash proof
/// of the exact session for the later commit-time revalidation.
pub(crate) async fn mfa_session(
    state: &(impl Borrow<AppState> + ?Sized),
    headers: &HeaderMap,
    missing: MissingSession,
) -> Result<MfaMutationContext> {
    let state = borrowed_app_state(state);
    let token = session_cookie(state, headers).ok_or_else(|| match missing {
        MissingSession::RedirectToLogin => HttpAuthError::redirect("/login"),
        MissingSession::Unauthorized => {
            HttpAuthError::status(StatusCode::UNAUTHORIZED, "Sign-in required")
        }
    })?;
    let session_token = token.to_string();
    let authenticated = database(state.db().clone(), move |database| {
        database.authenticated_mfa_session(&session_token)
    })
    .await?
    .ok_or_else(|| {
        HttpAuthError::with_kind(
            StatusCode::UNAUTHORIZED,
            "Session is no longer authorized",
            HttpAuthErrorKind::SessionRevoked,
        )
    })?;
    match authenticated {
        crate::db::MfaSessionAuthentication::Authenticated(authenticated) => Ok(authenticated),
        crate::db::MfaSessionAuthentication::MfaRequired => Err(HttpAuthError::status(
            StatusCode::FORBIDDEN,
            "MFA verification required",
        )),
    }
}

pub fn csrf(session: &Session, value: &str) -> Result<()> {
    if !auth::constant_time_eq(&session.csrf_token, value) {
        return Err(HttpAuthError::status(
            StatusCode::FORBIDDEN,
            "Invalid CSRF token",
        ));
    }
    Ok(())
}

pub fn csrf_header(session: &Session, headers: &HeaderMap) -> Result<()> {
    let value = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| HttpAuthError::status(StatusCode::FORBIDDEN, "CSRF token missing"))?;
    csrf(session, value)
}

pub fn make_session_cookie(state: &(impl Borrow<AppState> + ?Sized), token: &str) -> String {
    let state = borrowed_app_state(state);
    let name = session_cookie_name(state);
    format!(
        "{name}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={};{}",
        state.config().security.session_hours * 3600,
        if state.config().security.secure_cookie {
            " Secure"
        } else {
            ""
        }
    )
}
pub fn clear_session_cookie(state: &(impl Borrow<AppState> + ?Sized)) -> String {
    let state = borrowed_app_state(state);
    let name = session_cookie_name(state);
    format!(
        "{name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0;{}",
        if state.config().security.secure_cookie {
            " Secure"
        } else {
            ""
        }
    )
}

pub fn redirect_with_cookie(to: &str, value: &str) -> Result<Response> {
    let mut response = Redirect::to(to).into_response();
    let value = HeaderValue::from_str(value).map_err(|error| {
        HttpAuthError::from(report_internal(
            InternalOperation::HttpAuthResponseCookieHeader,
            error,
        ))
    })?;
    response.headers_mut().insert(header::SET_COOKIE, value);
    Ok(response)
}

pub fn unlock_cookie_name(share_id: i64) -> String {
    format!("vaultlink_unlock_{share_id}")
}

pub async fn share_is_unlocked(
    state: &(impl Borrow<AppState> + ?Sized),
    headers: &HeaderMap,
    share: &Share,
) -> Result<bool> {
    let state = borrowed_app_state(state);
    if share.password_hash.is_none() {
        return Ok(true);
    }
    let name = unlock_cookie_name(share.id);
    let Some(token) = named_cookie(headers, &name) else {
        return Ok(false);
    };
    let token = token.to_string();
    let share_id = share.id;
    database(state.db().clone(), move |db| {
        db.unlock_session(&token, share_id)
    })
    .await
}

/// Returns the CSRF token bound to the current password-unlock cookie. Passwordless
/// capability URLs do not use ambient cookie authority and therefore return `None`.
pub async fn share_unlock_csrf(
    state: &(impl Borrow<AppState> + ?Sized),
    headers: &HeaderMap,
    share: &Share,
) -> Result<Option<String>> {
    let state = borrowed_app_state(state);
    if share.password_hash.is_none() {
        return Ok(None);
    }
    let name = unlock_cookie_name(share.id);
    let Some(token) = named_cookie(headers, &name) else {
        return Ok(None);
    };
    let token = token.to_string();
    let share_id = share.id;
    database(state.db().clone(), move |db| {
        db.unlock_session_csrf(&token, share_id)
    })
    .await
}

#[derive(Clone, Copy)]
pub enum UnlockCookieScope {
    Web,
    Api,
}

#[derive(Clone, Copy)]
pub enum TransferCookieScope {
    Web,
    Api,
}

pub fn transfer_cookie_name(share_id: i64) -> String {
    format!("vaultlink_transfer_{share_id}")
}

pub fn transfer_cookie(headers: &HeaderMap, share_id: i64) -> Option<&str> {
    named_cookie(headers, &transfer_cookie_name(share_id))
}

pub fn make_transfer_cookie(
    state: &(impl Borrow<AppState> + ?Sized),
    share: &Share,
    token: &str,
    scope: TransferCookieScope,
) -> String {
    let state = borrowed_app_state(state);
    let path = match scope {
        TransferCookieScope::Web => format!("/v/{}", share.token),
        TransferCookieScope::Api => format!("/api/v2/public/shares/{}", share.token),
    };
    format!(
        "{}={}; Path={}; HttpOnly; SameSite=Strict; Max-Age={};{}",
        transfer_cookie_name(share.id),
        token,
        path,
        TRANSFER_COOKIE_MAX_AGE_SECONDS,
        if state.config().security.secure_cookie {
            " Secure"
        } else {
            ""
        }
    )
}

pub fn make_unlock_cookie(
    state: &(impl Borrow<AppState> + ?Sized),
    share: &Share,
    token: &str,
    scope: UnlockCookieScope,
) -> String {
    let state = borrowed_app_state(state);
    let settings = runtime_settings(state);
    let path = match scope {
        UnlockCookieScope::Web => format!("/v/{}", share.token),
        UnlockCookieScope::Api => format!("/api/v2/public/shares/{}", share.token),
    };
    format!(
        "{}={}; Path={}; HttpOnly; SameSite=Strict; Max-Age={};{}",
        unlock_cookie_name(share.id),
        token,
        path,
        settings.share_unlock_minutes * 60,
        if state.config().security.secure_cookie {
            " Secure"
        } else {
            ""
        }
    )
}
