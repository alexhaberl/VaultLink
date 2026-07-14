use super::*;

pub(super) async fn login_page() -> Html<String> {
    Html(plain_page(
        "Login",
        r#"<section class="vl-panel vl-auth-card"><h1><vl-i18n key="auth.admin_login"/></h1><form method="post" class="vl-stack"><label class="vl-field"><vl-i18n key="auth.username"/><input name="username" autocomplete="username" required></label><label class="vl-field"><vl-i18n key="auth.password"/><input name="password" type="password" maxlength="1024" autocomplete="current-password" required></label><button class="vl-button"><vl-i18n key="auth.sign_in"/></button></form></section>"#,
    ))
}

#[derive(Deserialize)]
pub(super) struct LoginForm {
    username: String,
    password: String,
}

pub(super) async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Result<Response> {
    let ip = proxy::client_limit_key(proxy::effective_client_ip(
        peer.ip(),
        &headers,
        &state.config,
    ));
    let ip_key = format!("ip:{ip}");
    if !auth::valid_admin_username(&form.username) {
        if !state.limiter.check_and_record_attempt(&ip_key) {
            return Err(AppError(
                StatusCode::TOO_MANY_REQUESTS,
                "Zu viele Anmeldeversuche",
            ));
        }
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    let key = format!("{}:{}", ip, form.username.to_lowercase());
    if !state.limiter.check_and_record_attempts(&[&key, &ip_key]) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele Anmeldeversuche",
        ));
    }
    if form.password.len() > auth::MAX_PASSWORD_BYTES {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    let username = form.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username)).await?;
    let expected_password_hash = admin.as_ref().map(|admin| admin.password_hash.clone());
    let verification_hash = expected_password_hash.clone();
    let password = form.password;
    let valid = verify_password_admitted(&state, verification_hash, password).await?;
    if !valid {
        audit(&state, form.username, "login_failed", None, None).await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    let a = admin.unwrap();
    let token = auth::random_token(32);
    let csrf = auth::random_token(24);
    let session_token = token.clone();
    let session_csrf = csrf.clone();
    let expires = Utc::now() + Duration::hours(state.config.security.session_hours);
    let admin_id = a.id;
    let audit_actor = a.username;
    let audit_client_ip = enabled_audit_client_ip(&state);
    let expected_password_hash = expected_password_hash.expect("valid password requires a hash");
    let outcome = database(state.db.clone(), move |db| {
        let outcome = db.create_session_for_verified_password(
            &session_token,
            admin_id,
            &expected_password_hash,
            &session_csrf,
            expires,
        )?;
        if outcome == PasswordSessionCreationOutcome::Created {
            audit_sync(
                &db,
                &audit_actor,
                "password_verified",
                None,
                None,
                audit_client_ip.as_deref(),
            );
        }
        Ok(outcome)
    })
    .await?;
    if outcome != PasswordSessionCreationOutcome::Created {
        audit(&state, form.username, "login_failed", None, None).await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten"));
    }
    // Successful password verifications remain in the fixed window as well. This
    // bounds Argon2 work, pre-MFA session creation and audit growth for valid but
    // compromised credentials.
    Ok(redirect_with_cookie(
        "/mfa",
        make_session_cookie(&state, &token),
    )?)
}

pub(super) async fn mfa_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Html<String>> {
    let (_, current_session) =
        session(&state, &headers, false, MissingSession::RedirectToLogin).await?;
    let admin_id = current_session.admin_id;
    let security_key_count = database(state.db.clone(), move |db| {
        db.admin_webauthn_credentials(admin_id)
            .map(|credentials| credentials.len())
    })
    .await?;
    let security_key_button = if security_key_count >= 2 {
        format!(
            r#"<hr><button type="button" data-security-key-login data-csrf="{}"><vl-i18n key="auth.security_key_use"/></button><p class="vl-muted" data-security-key-status></p>"#,
            esc(&current_session.csrf_token)
        )
    } else {
        String::new()
    };
    Ok(Html(plain_page(
        "MFA",
        &format!(
            r#"<section class="vl-panel vl-auth-card"><h1><vl-i18n key="auth.second_factor"/></h1><form method="post" class="vl-stack"><input type="hidden" name="csrf" value="{}"><label class="vl-field"><vl-i18n key="auth.six_digit_totp"/><input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{{6}}" required></label><button class="vl-button"><vl-i18n key="auth.verify"/></button></form>{security_key_button}</section>"#,
            esc(&current_session.csrf_token)
        ),
    )))
}

#[derive(Deserialize)]
pub(super) struct MfaForm {
    csrf: String,
    code: String,
}

pub(super) async fn mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<MfaForm>,
) -> Result<Response> {
    let (token, s) = session(&state, &headers, false, MissingSession::RedirectToLogin).await?;
    csrf(&s, &form.csrf)?;
    let key = format!("mfa:{}", s.username.to_lowercase());
    if !state.limiter.check_and_record_attempt(&key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele MFA-Versuche",
        ));
    }
    let username = s.username.clone();
    let admin = database(state.db.clone(), move |db| db.admin(&username))
        .await?
        .ok_or_else(|| internal(()))?;
    let Some(totp_step) = auth::matching_totp_step_now(&admin.totp_secret, &form.code) else {
        audit(&state, s.username, "mfa_failed", None, None).await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültiger MFA-Code"));
    };
    let admin_id = s.admin_id;
    let new_token = auth::random_token(32);
    let new_csrf = auth::random_token(24);
    let rotated_token = new_token.clone();
    let rotated_csrf = new_csrf.clone();
    let audit_actor = s.username.clone();
    let audit_client_ip = enabled_audit_client_ip(&state);
    let accepted = database(state.db.clone(), move |db| {
        let accepted = db.verify_mfa_with_totp_step(
            &token,
            &rotated_token,
            &rotated_csrf,
            admin_id,
            totp_step,
        )?;
        if accepted {
            audit_sync(
                &db,
                &audit_actor,
                "login_success",
                None,
                None,
                audit_client_ip.as_deref(),
            );
        }
        Ok(accepted)
    })
    .await?;
    if !accepted {
        audit(&state, s.username, "mfa_replayed", None, None).await;
        return Err(AppError(StatusCode::UNAUTHORIZED, "Ungültiger MFA-Code"));
    }
    state.limiter.success(&key);
    Ok(redirect_with_cookie(
        "/admin",
        make_session_cookie(&state, &new_token),
    )?)
}

pub(super) async fn start_security_key_authentication(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CsrfForm>,
) -> Result<Json<webauthn_rs::prelude::RequestChallengeResponse>> {
    let (token, session) =
        session(&state, &headers, false, MissingSession::RedirectToLogin).await?;
    if session.mfa_verified {
        return Err(AppError(
            StatusCode::CONFLICT,
            "MFA wurde bereits bestätigt",
        ));
    }
    csrf(&session, &body.csrf)?;
    let start_key = format!("mfa-webauthn-start:{}", session.username.to_lowercase());
    if !state.limiter.check_and_record_attempt(&start_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele Sicherheitsschluessel-Anfragen",
        ));
    }
    let admin_id = session.admin_id;
    let rows = database(state.db.clone(), move |db| {
        db.admin_webauthn_credentials(admin_id)
    })
    .await?;
    if rows.len() < 2 {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Kein Sicherheitsschlüssel registriert",
        ));
    }
    let keys = decode_security_keys(&rows)?;
    let webauthn = state
        .webauthn
        .read()
        .expect("WebAuthn service lock poisoned")
        .clone();
    let challenge = webauthn
        .start_authentication(&token, admin_id, &keys)
        .map_err(|_| {
            AppError(
                StatusCode::BAD_REQUEST,
                "Sicherheitsschlüssel konnte nicht gestartet werden",
            )
        })?;
    Ok(Json(challenge))
}

#[derive(Deserialize)]
pub(super) struct SecurityKeyAuthenticationFinish {
    csrf: String,
    credential: webauthn_rs::prelude::PublicKeyCredential,
}

pub(super) async fn finish_security_key_authentication(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SecurityKeyAuthenticationFinish>,
) -> Result<Response> {
    let (token, session) =
        session(&state, &headers, false, MissingSession::RedirectToLogin).await?;
    if session.mfa_verified {
        return Err(AppError(
            StatusCode::CONFLICT,
            "MFA wurde bereits bestätigt",
        ));
    }
    csrf(&session, &body.csrf)?;
    let attempt_key = format!("mfa:{}", session.username.to_lowercase());
    if !state.limiter.check_and_record_attempt(&attempt_key) {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Zu viele MFA-Versuche",
        ));
    }
    let admin_id = session.admin_id;
    let rows = database(state.db.clone(), move |db| {
        db.admin_webauthn_credentials(admin_id)
    })
    .await?;
    let mut keys = decode_security_keys(&rows)?;
    let webauthn = state
        .webauthn
        .read()
        .expect("WebAuthn service lock poisoned")
        .clone();
    let index = webauthn
        .finish_authentication(&token, admin_id, &body.credential, &mut keys)
        .map_err(|_| AppError(StatusCode::UNAUTHORIZED, "Ungültiger Sicherheitsschlüssel"))?;
    let row = rows.get(index).ok_or_else(|| internal(()))?;
    let credential_id = row.id;
    let expected_credential_json = row.credential_json.clone();
    let credential_json = serde_json::to_string(&keys[index]).map_err(internal)?;
    let new_token = auth::random_token(32);
    let new_csrf = auth::random_token(24);
    let rotated_token = new_token.clone();
    let rotated_csrf = new_csrf.clone();
    let audit_actor = session.username.clone();
    let audit_client_ip = enabled_audit_client_ip(&state);
    let completed = database(state.db.clone(), move |db| {
        let completed = db.complete_webauthn_mfa(
            &token,
            &rotated_token,
            &rotated_csrf,
            credential_id,
            admin_id,
            &expected_credential_json,
            &credential_json,
        )?;
        if completed {
            audit_sync(
                &db,
                &audit_actor,
                "login_success_webauthn",
                None,
                None,
                audit_client_ip.as_deref(),
            );
        }
        Ok(completed)
    })
    .await?;
    if !completed {
        return Err(AppError(
            StatusCode::CONFLICT,
            "Sicherheitsschlüssel wurde gleichzeitig geändert",
        ));
    }
    state.limiter.success(&attempt_key);
    let mut response = Json(serde_json::json!({"redirect":"/admin"})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&make_session_cookie(&state, &new_token)).map_err(internal)?,
    );
    Ok(response)
}

pub(super) async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    let (token, s) = session(&state, &headers, false, MissingSession::RedirectToLogin).await?;
    csrf(&s, &form.csrf)?;
    let audit_actor = s.username;
    let audit_client_ip = enabled_audit_client_ip(&state);
    database(state.db.clone(), move |db| {
        db.delete_session(&token)?;
        audit_sync(
            &db,
            &audit_actor,
            "logout",
            None,
            None,
            audit_client_ip.as_deref(),
        );
        Ok(())
    })
    .await?;
    Ok(redirect_with_cookie(
        "/login",
        clear_session_cookie(&state),
    )?)
}
