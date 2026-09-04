pub async fn run(
    config_path: PathBuf,
    listen: SocketAddr,
) -> Result<bool, Box<dyn std::error::Error>> {
    validate_setup_listen(listen)?;
    let token = auth::random_token(32);
    println!("{}", setup_access_instructions(listen, &token));
    let (start_sender, start_receiver) = tokio::sync::oneshot::channel();
    let start_requested = Arc::new(AtomicBool::new(false));
    let state = SetupState {
        config_path: Arc::new(config_path),
        token: Arc::new(token),
        commit: Arc::new(tokio::sync::Mutex::new(false)),
        start_sender: Arc::new(tokio::sync::Mutex::new(Some(start_sender))),
        start_requested: start_requested.clone(),
    };
    let app = setup_router(state);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = start_receiver => {},
                _ = tokio::signal::ctrl_c() => {},
            }
        })
        .await?;
    Ok(start_requested.load(Ordering::Acquire))
}

const SETUP_REQUEST_ID_HEADER: header::HeaderName = header::HeaderName::from_static("x-request-id");

#[derive(Clone, Debug)]
struct SetupRequestId(String);

impl SetupRequestId {
    fn as_str(&self) -> &str {
        &self.0
    }
}

async fn discard_setup_client_request_id(mut request: Request, next: Next) -> Response {
    request.headers_mut().remove(SETUP_REQUEST_ID_HEADER);
    next.run(request).await
}

async fn attach_setup_request_id(mut request: Request, next: Next) -> Response {
    let request_id = request
        .headers()
        .get(SETUP_REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("<missing>")
        .to_owned();
    request.extensions_mut().insert(SetupRequestId(request_id));
    next.run(request).await
}

fn setup_internal<E>(operation: InternalOperation, error: E) -> Response {
    let _reported = report_internal(operation, error);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(page(
            &SetupMessageTemplate {
                message_key: "error.internal",
            },
            None,
        )),
    )
        .into_response()
}

crate::declare_routes! {
    pub static SETUP_ROUTE_SPECS = Setup;
    fn add_setup_routes(router: Router<SetupState>) -> Router<SetupState>;
    "/" {
        GET => setup_page, [SetupToken, None, None, None, None, ReadOnly];
        POST => submit_setup, [SetupToken, None, None, Required, Form, Setup];
    }
    "/bootstrap" {
        POST => setup_bootstrap, [Public, None, None, None, Json, Authentication];
    }
    "/locale" {
        POST => set_setup_locale, [Public, None, None, None, Form, Preference];
    }
    "/complete" {
        POST => complete_setup, [SetupToken, None, None, None, None, Setup];
    }
    "/start" {
        POST => start_server, [SetupToken, None, None, None, None, Setup];
    }
    "/browse" {
        GET => setup_browse, [SetupToken, None, None, None, None, ReadOnly];
    }
    "/mounts" {
        GET => setup_mounts, [SetupToken, None, None, None, None, ReadOnly];
    }
    "/assets/vaultlink.css" {
        GET => stylesheet_asset, [Public, None, None, None, None, ReadOnly];
    }
    "/assets/setup.js" {
        GET => setup_javascript_asset, [Public, None, None, None, None, ReadOnly];
    }
    "/assets/favicon.svg" {
        GET => setup_favicon_svg, [Public, None, None, None, None, ReadOnly];
    }
    "/assets/favicon-32.png" {
        GET => setup_favicon_png, [Public, None, None, None, None, ReadOnly];
    }
    "/favicon.ico" {
        GET => setup_favicon_png, [Public, None, None, None, None, ReadOnly];
    }
}

fn setup_router(state: SetupState) -> Router {
    crate::install_safe_panic_reporting();
    let router = add_setup_routes(Router::new());
    #[cfg(panic = "unwind")]
    let router = router.layer(CatchPanicLayer::custom(setup_panic_response));
    router
        .layer(middleware::from_fn(setup_security_headers))
        .layer(middleware::from_fn(setup_locale_context))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request| {
                let matched_path = request
                    .extensions()
                    .get::<MatchedPath>()
                    .map(MatchedPath::as_str)
                    .unwrap_or("<unmatched>");
                tracing::debug_span!(
                    "setup_http_request",
                    method = %request.method(),
                    route = matched_path,
                    version = ?request.version(),
                    request_id = %request
                        .extensions()
                        .get::<SetupRequestId>()
                        .map(SetupRequestId::as_str)
                        .unwrap_or("<missing>")
                )
            }),
        )
        .layer(middleware::from_fn(attach_setup_request_id))
        .layer(SetRequestIdLayer::new(
            SETUP_REQUEST_ID_HEADER,
            MakeRequestUuid,
        ))
        .layer(middleware::from_fn(discard_setup_client_request_id))
        .with_state(state)
}

#[cfg(panic = "unwind")]
fn setup_panic_response(_panic: Box<dyn std::any::Any + Send + 'static>) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html("<!doctype html><title>Internal error</title><p>Internal error</p>"),
    )
        .into_response()
}

async fn stylesheet_asset() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        ui::STYLESHEET,
    )
}

async fn setup_favicon_svg() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "image/svg+xml; charset=utf-8")],
        ui::LOGO_SVG,
    )
}

async fn setup_favicon_png() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/png")], ui::FAVICON_PNG)
}

async fn setup_javascript_asset() -> impl IntoResponse {
    let script = i18n::render_markers(i18n::current_locale(), SETUP_JAVASCRIPT);
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        script,
    )
}

async fn setup_locale_context(request: Request, next: Next) -> Response {
    let locale = Locale::resolve(request.headers());
    let return_to = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    i18n::scope(locale, return_to, async move {
        let mut response = next.run(request).await;
        let is_localized_content = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.starts_with("text/html") || value.starts_with("application/javascript")
            });
        if is_localized_content {
            response.headers_mut().insert(
                header::CONTENT_LANGUAGE,
                HeaderValue::from_static(locale.code()),
            );
        }
        response
    })
    .await
}

async fn setup_security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; connect-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    response
}

fn safe_setup_return_to(value: &str) -> String {
    if !value.starts_with('/') || value.starts_with("//") || value.contains('\\') {
        return "/".to_string();
    }
    let Ok(uri) = value.parse::<Uri>() else {
        return "/".to_string();
    };
    if uri.scheme().is_some() || uri.authority().is_some() || uri.path() != "/" {
        return "/".to_string();
    }
    uri.path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string())
}

async fn set_setup_locale(Form(form): Form<SetupLocaleForm>) -> Response {
    let Some(locale) = Locale::parse(&form.locale) else {
        return (
            StatusCode::BAD_REQUEST,
            Html(page(
                &SetupMessageTemplate {
                    message_key: "error.invalid_language",
                },
                None,
            )),
        )
            .into_response();
    };
    let return_to = safe_setup_return_to(&form.return_to);
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000",
        i18n::LOCALE_COOKIE,
        locale.code()
    );
    let mut response = Redirect::to(&return_to).into_response();
    match HeaderValue::from_str(&cookie) {
        Ok(cookie) => {
            response.headers_mut().insert(header::SET_COOKIE, cookie);
            response
        }
        Err(error) => setup_internal(InternalOperation::SetupLocaleCookieHeader, error),
    }
}

fn setup_return_to(token: Option<&str>) -> String {
    if let Some(token) = token {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("token", token)
            .finish();
        return format!("/?{query}");
    }
    safe_setup_return_to(&i18n::current_return_to())
}

fn validate_setup_listen(listen: SocketAddr) -> Result<(), &'static str> {
    if listen.port() == 0 {
        Err("setup port must not be 0")
    } else if listen.ip().is_loopback() {
        Ok(())
    } else {
        Err("setup bind address must be loopback-only")
    }
}

fn setup_access_instructions(listen: SocketAddr, token: &str) -> String {
    let port = listen.port();
    let tunnel_target = match listen.ip() {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    };
    format!(
        "VaultLink-Setup lauscht ausschlie\u{00df}lich auf Loopback ({listen}). / VaultLink setup listens only on loopback.\n\
         Headless-Server / headless server: Auf dem eigenen Rechner in einem zweiten Terminal ausf\u{00fc}hren; replace BENUTZER and SERVER:\n\
         ssh -4 -N -L 127.0.0.1:{port}:{tunnel_target}:{port} BENUTZER@SERVER\n\
         Danach diese lokale URL im Browser \u{00f6}ffnen / then open this local browser URL:\n\
         http://127.0.0.1:{port}/#token={token}\n\
         Das Setup-Token wird nur einmal ausgegeben und ist f\u{00fc}r das Browserformular erforderlich. / The setup token is printed once and is required by the browser form."
    )
}
