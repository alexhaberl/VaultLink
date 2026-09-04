const SETUP_COOKIE: &str = "vaultlink_setup";

fn setup_cookie_authorized(headers: &HeaderMap, state: &SetupState) -> bool {
    named_cookie(headers, SETUP_COOKIE)
        .is_some_and(|token| auth::constant_time_eq(state.token.as_str(), token))
}

#[derive(Deserialize)]
struct SetupBootstrapRequest {
    token: String,
}

async fn setup_bootstrap(
    State(state): State<SetupState>,
    Json(request): Json<SetupBootstrapRequest>,
) -> Response {
    if !auth::constant_time_eq(state.token.as_str(), &request.token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let cookie = format!(
        "{SETUP_COOKIE}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600",
        state.token
    );
    let mut response = StatusCode::NO_CONTENT.into_response();
    match HeaderValue::from_str(&cookie) {
        Ok(cookie) => {
            response.headers_mut().insert(header::SET_COOKIE, cookie);
            response
        }
        Err(error) => setup_internal(InternalOperation::SetupBootstrapCookieHeader, error),
    }
}

async fn setup_page(State(state): State<SetupState>, headers: HeaderMap) -> Response {
    if !setup_cookie_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Html(page(
                &SetupMessageTemplate {
                    message_key: "setup.token_invalid",
                },
                None,
            )),
        )
            .into_response();
    }
    Html(page(&setup_form(None), None)).into_response()
}

async fn submit_setup(
    State(state): State<SetupState>,
    headers: HeaderMap,
    Form(form): Form<SetupForm>,
) -> Response {
    if !setup_cookie_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Html(page(
                &SetupMessageTemplate {
                    message_key: "setup.token_invalid",
                },
                None,
            )),
        )
            .into_response();
    }
    let completed = state.commit.lock().await;
    if *completed {
        return (
            StatusCode::CONFLICT,
            Html(page(
                &SetupMessageTemplate {
                    message_key: "setup.already_completed",
                },
                None,
            )),
        )
            .into_response();
    }
    match build_and_store(&state.config_path, form).await {
        Ok(result) => match TrustedMarkup::generated_qr(result.otpauth.expose_secret()) {
            Ok(qr) => Html(page_without_locale_switcher(&SetupCompletedTemplate {
                qr: &qr,
                secret: result.totp_secret.expose_secret(),
                otpauth: result.otpauth.expose_secret(),
            }))
            .into_response(),
            Err(error) => setup_internal(InternalOperation::SetupQrRender, error),
        },
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Html(page(&setup_form(Some(&error)), None)),
        )
            .into_response(),
    }
}

async fn complete_setup(State(state): State<SetupState>, headers: HeaderMap) -> Response {
    if !setup_cookie_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Html(page(
                &SetupMessageTemplate {
                    message_key: "setup.token_invalid",
                },
                None,
            )),
        )
            .into_response();
    }
    let mut completed = state.commit.lock().await;
    if *completed {
        return match Config::load(state.config_path.as_ref()) {
            Ok(config) => Html(page_without_locale_switcher(&setup_confirmed_body(
                &config,
                i18n::text(i18n::current_locale(), i18n::SETUP_TOTP_ALREADY_CLOSED),
            )))
            .into_response(),
            Err(error) => setup_internal(InternalOperation::SetupConfigLoad, error),
        };
    }
    let config = match Config::load(state.config_path.as_ref()) {
        Ok(config) => config,
        Err(error) => return setup_internal(InternalOperation::SetupConfigLoad, error),
    };
    match clear_initial_setup_pending_for_storage(&config.storage) {
        Ok(()) => {
            *completed = true;
            Html(page_without_locale_switcher(&setup_confirmed_body(
                &config,
                i18n::text(i18n::current_locale(), i18n::SETUP_TOTP_CLOSED),
            )))
            .into_response()
        }
        Err(error) => setup_internal(InternalOperation::SetupStorageFinalize, error),
    }
}

fn setup_confirmed_body<'a>(config: &Config, message: &'a str) -> SetupConfirmedTemplate<'a> {
    let mode = match &config.server.mode {
        ServerMode::Development => "Development",
        ServerMode::ReverseProxy => "Reverse Proxy",
        ServerMode::StandaloneTls => "Standalone TLS",
    };
    SetupConfirmedTemplate { message, mode }
}

async fn start_server(State(state): State<SetupState>, headers: HeaderMap) -> Response {
    if !setup_cookie_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Html(page(
                &SetupMessageTemplate {
                    message_key: "setup.token_invalid",
                },
                None,
            )),
        )
            .into_response();
    }
    if !*state.commit.lock().await {
        return (
            StatusCode::CONFLICT,
            Html(page(
                &SetupMessageTemplate {
                    message_key: "setup.totp_confirm_first",
                },
                None,
            )),
        )
            .into_response();
    }
    let config = match Config::load(state.config_path.as_ref()) {
        Ok(config) => config,
        Err(error) => return setup_internal(InternalOperation::SetupConfigLoad, error),
    };
    let Some(sender) = state.start_sender.lock().await.take() else {
        return (
            StatusCode::CONFLICT,
            Html(page(
                &SetupMessageTemplate {
                    message_key: "setup.start_already_requested",
                },
                None,
            )),
        )
            .into_response();
    };
    let start_requested = state.start_requested.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        start_requested.store(true, Ordering::Release);
        if sender.send(()).is_err() {
            start_requested.store(false, Ordering::Release);
        }
    });
    Html(page_without_locale_switcher(&SetupStartingTemplate {
        url: &config.server.public_base_url,
    }))
    .into_response()
}
