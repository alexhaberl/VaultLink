use std::{
    collections::{BTreeSet, HashSet},
    net::SocketAddr,
    path::Path,
};

use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, HeaderValue, Method, Request, StatusCode},
    response::Response,
};
use chrono::{Duration, Utc};
use tower::ServiceExt;

use crate::{
    config::{
        Admission, Config, Logging, ReverseProxy, Security, Server, ServerMode, Storage, Tls,
    },
    routing::{
        AuditContract, AuthContract, BodyContract, CsrfContract, MfaContract, MutationContract,
        RouteMethod, RouteSpec, RouteSurface,
    },
    AppState,
};

const UNMATCHED_ROUTE_STATUS: StatusCode = StatusCode::IM_A_TEAPOT;
const MULTIPART_BOUNDARY: &str = "vaultlink-route-contract";

fn all_specs() -> impl Iterator<Item = &'static RouteSpec> {
    crate::web::WEB_ROUTE_SPECS
        .iter()
        .chain(crate::api::API_ROUTE_SPECS)
        .chain(crate::setup::SETUP_ROUTE_SPECS)
}

fn manifest_snapshot() -> String {
    all_specs()
        .map(|spec| {
            format!(
                "{}|{}|{}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
                spec.surface,
                spec.method,
                spec.externally_visible_path(),
                spec.auth,
                spec.mfa,
                spec.csrf,
                spec.audit,
                spec.body,
                spec.mutation,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn route_manifest_matches_the_reviewed_snapshot() {
    assert_eq!(
        manifest_snapshot(),
        include_str!("route-manifest.snapshot").trim_end()
    );
}

#[test]
fn every_registered_method_has_one_complete_contract() {
    let specs = all_specs().collect::<Vec<_>>();
    let unique = specs
        .iter()
        .map(|spec| (spec.surface, spec.method, spec.path))
        .collect::<HashSet<_>>();
    assert_eq!(unique.len(), specs.len(), "duplicate route method contract");
    assert_eq!(crate::web::WEB_ROUTE_SPECS.len(), 67);
    assert_eq!(crate::api::API_ROUTE_SPECS.len(), 45);
    assert_eq!(crate::setup::SETUP_ROUTE_SPECS.len(), 13);

    for spec in specs {
        if spec.mfa == MfaContract::MutationContext {
            assert_eq!(spec.auth, AuthContract::AdminSession, "{spec:?}");
            assert_ne!(spec.csrf, CsrfContract::None, "{spec:?}");
            assert_ne!(spec.mutation, MutationContract::ReadOnly, "{spec:?}");
        }
        if matches!(
            spec.mutation,
            MutationContract::Privileged | MutationContract::Storage | MutationContract::Upload
        ) {
            assert_eq!(spec.audit, AuditContract::Required, "{spec:?}");
        }
        if spec.surface == RouteSurface::ApiV2 && spec.mfa == MfaContract::MutationContext {
            assert_eq!(spec.csrf, CsrfContract::Header, "{spec:?}");
        }
        if spec.method == RouteMethod::Head {
            assert_eq!(spec.mutation, MutationContract::ReadOnly, "{spec:?}");
        }
    }
}

fn test_state(root: &Path, data: &Path) -> AppState {
    AppState::new(Config {
        server: Server {
            mode: ServerMode::Development,
            listen_address: "127.0.0.1:8080".into(),
            public_base_url: "http://localhost:8080".into(),
            production_mode: false,
        },
        storage: Storage {
            root_mount_path: root.into(),
            data_directory: data.into(),
            internal_directory: Some(root.join(crate::config::DEFAULT_INTERNAL_DIRECTORY_NAME)),
            require_mount: false,
            external_writers: false,
            allow_external_writer_replace: false,
            expected_filesystem_type: None,
            expected_mount_source: None,
            max_upload_size: 1_000_000,
            max_zip_size: 1_000_000_000,
            max_zip_files: 100,
            max_search_entries: 1_000,
            max_search_results: 100,
            max_preview_size: 1_000_000,
            preview_extensions: vec!["txt".into(), "md".into()],
            image_preview_extensions: vec!["jpg".into(), "png".into()],
            pdf_preview_enabled: true,
            max_media_preview_size: 100_000_000,
            blocked_extensions: vec!["exe".into()],
        },
        reverse_proxy: ReverseProxy::default(),
        tls: Tls::default(),
        security: Security {
            secure_cookie: false,
            ..Default::default()
        },
        admission: Admission::default(),
        logging: Logging::default(),
    })
    .unwrap()
}

fn request(method: Method, uri: &str, content_type: Option<&str>, body: &str) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    let mut request = builder.body(Body::from(body.to_owned())).unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    request
}

fn http_method(method: RouteMethod) -> Method {
    match method {
        RouteMethod::Get => Method::GET,
        RouteMethod::Head => Method::HEAD,
        RouteMethod::Post => Method::POST,
        RouteMethod::Put => Method::PUT,
        RouteMethod::Patch => Method::PATCH,
        RouteMethod::Delete => Method::DELETE,
    }
}

struct RouteRequestFixture {
    uri: String,
    content_type: Option<&'static str>,
    body: String,
}

fn route_request_fixture(spec: &RouteSpec, csrf: &str) -> RouteRequestFixture {
    let mut uri = spec
        .externally_visible_path()
        .replace("{token}", "missing-token")
        .replace("{alias}", "missing-alias")
        .replace("{id}", "999");
    if matches!(
        uri.as_str(),
        "/admin/files/download" | "/admin/files/delete" | "/admin/preview" | "/admin/preview/raw"
    ) {
        uri.push_str("?path=missing.txt");
    }

    let (content_type, body) = match spec.body {
        BodyContract::None => (None, String::new()),
        BodyContract::Multipart => {
            let body = if spec.csrf == CsrfContract::FormField {
                format!(
                    "--{MULTIPART_BOUNDARY}\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n.\r\n--{MULTIPART_BOUNDARY}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n{csrf}\r\n--{MULTIPART_BOUNDARY}--\r\n"
                )
            } else {
                format!("--{MULTIPART_BOUNDARY}--\r\n")
            };
            (
                Some("multipart/form-data; boundary=vaultlink-route-contract"),
                body,
            )
        }
        BodyContract::Form => {
            let body = match spec.path {
                "/login" => "username=missing&password=invalid".to_owned(),
                "/mfa" => format!("csrf={csrf}&code=000000"),
                "/locale" => "locale=en&return_to=%2F".to_owned(),
                "/admin/account/password" => format!(
                    "csrf={csrf}&current_password=invalid&new_password=not-a-real-password&password_confirm=not-a-real-password"
                ),
                "/admin/account/totp" => {
                    format!("csrf={csrf}&current_password=invalid&enabled=false")
                }
                "/admin/account/mfa/start" => {
                    format!("csrf={csrf}&current_password=invalid&current_code=000000")
                }
                "/admin/account/mfa/confirm" => {
                    format!("csrf={csrf}&enrollment_token=missing&code=000000")
                }
                "/admin/account/security-keys/{id}/delete" => {
                    format!("csrf={csrf}&current_password=invalid")
                }
                "/admin/files/directories" => {
                    format!("csrf={csrf}&parent=&name=route-contract")
                }
                "/admin/files/rename" => {
                    format!("csrf={csrf}&path=missing.txt&name=renamed.txt")
                }
                "/admin/files/delete" => format!("csrf={csrf}&path=missing.txt"),
                "/admin/shares" => {
                    format!("csrf={csrf}&path=missing.txt&permission=download_only")
                }
                "/admin/shares/{id}/upload-conflict" => {
                    format!("csrf={csrf}&strategy=reject")
                }
                "/admin/shares/{id}/password" => format!("csrf={csrf}&remove=1"),
                "/admin/admins" => format!(
                    "csrf={csrf}&username=operator&password=not-a-real-password&password_confirm=not-a-real-password"
                ),
                "/admin/admins/{id}/password" => format!(
                    "csrf={csrf}&password=not-a-real-password&password_confirm=not-a-real-password"
                ),
                "/admin/service-tokens" => {
                    format!("csrf={csrf}&current_password=invalid&name=route-contract&no_expiry=1")
                }
                "/admin/settings" => format!(
                    "csrf={csrf}&public_base_url=http%3A%2F%2Flocalhost%3A8080&max_upload_size_gb=1&blocked_extensions=exe&share_password_min_length=12&share_password_max_length=128&share_unlock_minutes=30&max_zip_size_gb=1&max_zip_files=100&max_search_entries=1000&max_search_results=100&max_preview_size_mb=1&preview_extensions=txt&image_preview_extensions=png&max_media_preview_size_mb=100"
                ),
                "/admin/settings/audit-ips/delete" => {
                    format!("csrf={csrf}&confirmation=IP-DATEN+L%C3%96SCHEN")
                }
                "/v/{token}/unlock" => "password=invalid".to_owned(),
                _ => format!("csrf={csrf}"),
            };
            (Some("application/x-www-form-urlencoded"), body)
        }
        BodyContract::Json => {
            let body = match (spec.surface, spec.path, spec.method) {
                (RouteSurface::ApiV2, "/session/login", _) => {
                    r#"{"username":"missing","password":"invalid"}"#.to_owned()
                }
                (RouteSurface::ApiV2, "/session/mfa", _) => {
                    r#"{"code":"000000"}"#.to_owned()
                }
                (RouteSurface::ApiV2, "/files", RouteMethod::Patch) => {
                    r#"{"path":"missing.txt","name":"renamed.txt"}"#.to_owned()
                }
                (RouteSurface::ApiV2, "/files", RouteMethod::Delete) => {
                    r#"{"path":"missing.txt","confirm_name":null}"#.to_owned()
                }
                (RouteSurface::ApiV2, "/files/directories", _) => {
                    r#"{"parent":"","name":"route-contract"}"#.to_owned()
                }
                (RouteSurface::ApiV2, "/shares", RouteMethod::Post) => {
                    r#"{"path":"missing.txt","permission":"download_only"}"#.to_owned()
                }
                (RouteSurface::ApiV2, "/shares/{id}", RouteMethod::Patch) => {
                    r#"{"active":true}"#.to_owned()
                }
                (RouteSurface::ApiV2, "/shares/{id}/password", RouteMethod::Put)
                | (RouteSurface::ApiV2, "/admins/{id}/password", RouteMethod::Put) => {
                    r#"{"password":"not-a-real-password"}"#.to_owned()
                }
                (RouteSurface::ApiV2, "/admins", RouteMethod::Post) => {
                    r#"{"username":"operator","password":"not-a-real-password"}"#.to_owned()
                }
                (RouteSurface::ApiV2, "/settings", RouteMethod::Put) => r#"{"public_base_url":"http://localhost:8080","max_upload_size":1000000,"blocked_extensions":["exe"],"share_password_min_length":12,"share_password_max_length":128,"share_unlock_minutes":30,"max_zip_size":1000000000,"max_zip_files":100,"max_search_entries":1000,"max_search_results":100,"max_preview_size":1000000,"preview_extensions":["txt"],"image_preview_extensions":["png"],"pdf_preview_enabled":true,"max_media_preview_size":100000000,"audit_client_ip_enabled":false}"#.to_owned(),
                (RouteSurface::ApiV2, "/audit/client-ips", RouteMethod::Delete) => {
                    r#"{"confirmation":"IP-DATEN LÖSCHEN"}"#.to_owned()
                }
                (RouteSurface::ApiV2, "/service-tokens", RouteMethod::Post) => {
                    r#"{"name":"route-contract","expires_at":null,"current_password":"invalid"}"#.to_owned()
                }
                (RouteSurface::ApiV2, "/public/shares/{token}/unlock", _) => {
                    r#"{"password":"invalid"}"#.to_owned()
                }
                (RouteSurface::Web, "/mfa/security-key/start", _) => {
                    format!(r#"{{"csrf":"{csrf}"}}"#)
                }
                (RouteSurface::Web, "/mfa/security-key/finish", _) => {
                    format!(r#"{{"csrf":"{csrf}","credential":{{}}}}"#)
                }
                (RouteSurface::Web, "/admin/account/security-keys/register/start", _) => format!(
                    r#"{{"csrf":"{csrf}","current_password":"invalid","label":"route-contract"}}"#
                ),
                (RouteSurface::Web, "/admin/account/security-keys/register/finish", _) => {
                    format!(r#"{{"csrf":"{csrf}","label":"route-contract","credential":{{}}}}"#)
                }
                _ => format!(r#"{{"csrf":"{csrf}"}}"#),
            };
            (Some("application/json"), body)
        }
    };
    RouteRequestFixture {
        uri,
        content_type,
        body,
    }
}

fn route_request(spec: &RouteSpec, csrf: &str) -> Request<Body> {
    let fixture = route_request_fixture(spec, csrf);
    request(
        http_method(spec.method),
        &fixture.uri,
        fixture.content_type,
        &fixture.body,
    )
}

fn add_session_headers(
    request: &mut Request<Body>,
    token: &'static str,
    csrf: &str,
    spec: &RouteSpec,
) {
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static(match token {
            "verified" => "vaultlink_session=verified",
            "pending" => "vaultlink_session=pending",
            "revoked" => "vaultlink_session=revoked",
            _ => unreachable!("test session token must have a static cookie fixture"),
        }),
    );
    if spec.csrf == CsrfContract::Header {
        request
            .headers_mut()
            .insert("x-csrf-token", HeaderValue::from_str(csrf).unwrap());
    }
}

fn authenticated_api_request(
    method: Method,
    uri: &str,
    content_type: Option<&str>,
    body: &str,
    token: &'static str,
    csrf: &'static str,
) -> Request<Body> {
    let mut request = request(method, uri, content_type, body);
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static(match token {
            "session" => "vaultlink_session=session",
            _ => unreachable!("authenticated API fixture requires a static cookie"),
        }),
    );
    request
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_static(csrf));
    request
}

fn public_upload_request(uri: &str, name: &str, content: &[u8]) -> Request<Body> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{MULTIPART_BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{MULTIPART_BOUNDARY}--\r\n").as_bytes());
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={MULTIPART_BOUNDARY}"),
        )
        .body(Body::from(body))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    request
}

fn install_audit_failure(data: &Path, trigger: &str, action: &str) {
    rusqlite::Connection::open(data.join("data.sqlite"))
        .unwrap()
        .execute_batch(&format!(
            "CREATE TRIGGER {trigger}
             BEFORE INSERT ON audit
             WHEN NEW.action='{action}'
             BEGIN SELECT RAISE(FAIL, 'injected route-manifest audit failure'); END;"
        ))
        .unwrap();
}

async fn response_text(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

fn install_verified_session(state: &AppState, token: &str, csrf: &str) {
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(token, 1, csrf, Utc::now() + Duration::hours(1))
        .unwrap();
    assert!(state.db().verify_mfa(token).unwrap());
}

fn install_auth_contract_sessions(state: &AppState) {
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session("pending", 1, "correct", Utc::now() + Duration::hours(1))
        .unwrap();
    state
        .db()
        .create_session("verified", 1, "correct", Utc::now() + Duration::hours(1))
        .unwrap();
    assert!(state.db().verify_mfa("verified").unwrap());
}

fn expected_anonymous_auth_status(spec: &RouteSpec) -> Option<StatusCode> {
    match (spec.surface, spec.auth) {
        (RouteSurface::Web, AuthContract::Session | AuthContract::AdminSession) => {
            Some(StatusCode::SEE_OTHER)
        }
        (
            RouteSurface::ApiV2,
            AuthContract::Session | AuthContract::AdminSession | AuthContract::MonitoringCredential,
        ) => Some(StatusCode::UNAUTHORIZED),
        _ => None,
    }
}

#[tokio::test]
async fn every_product_route_is_routable_and_enforces_declared_anonymous_auth() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let app = crate::web::router(test_state(root.path(), data.path()))
        .fallback(|| async { UNMATCHED_ROUTE_STATUS });

    for spec in all_specs().filter(|spec| spec.surface != RouteSurface::Setup) {
        let response = app
            .clone()
            .oneshot(route_request(spec, "wrong"))
            .await
            .unwrap();
        assert_ne!(
            response.status(),
            UNMATCHED_ROUTE_STATUS,
            "declared route did not match: {spec:?}"
        );
        if let Some(expected) = expected_anonymous_auth_status(spec) {
            if response.status() != expected {
                eprintln!(
                    "anonymous auth mismatch: expected={expected}, actual={}, spec={spec:?}",
                    response.status()
                );
            }
            assert_eq!(
                response.status(),
                expected,
                "declared auth contract was hidden by routing or extraction: {spec:?}"
            );
        }
    }
}

#[tokio::test]
async fn every_declared_csrf_contract_rejects_the_wrong_proof_before_mutation() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    install_auth_contract_sessions(&state);
    let app = crate::web::router(state);

    let cases = all_specs()
        .filter(|spec| {
            spec.surface != RouteSurface::Setup
                && spec.csrf != CsrfContract::None
                && matches!(
                    spec.auth,
                    AuthContract::Session | AuthContract::AdminSession
                )
        })
        .collect::<Vec<_>>();
    assert!(cases
        .iter()
        .any(|spec| spec.csrf == CsrfContract::FormField));
    assert!(cases
        .iter()
        .any(|spec| spec.csrf == CsrfContract::JsonField));
    assert!(cases.iter().any(|spec| spec.csrf == CsrfContract::Header));

    for spec in cases {
        let token = if spec.auth == AuthContract::AdminSession {
            "verified"
        } else {
            "pending"
        };
        let mut request = route_request(spec, "wrong");
        add_session_headers(&mut request, token, "wrong", spec);
        let response = app.clone().oneshot(request).await.unwrap();
        if response.status() != StatusCode::FORBIDDEN {
            eprintln!(
                "CSRF mismatch: expected=403, actual={}, spec={spec:?}",
                response.status()
            );
        }
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "CSRF contract did not reject a wrong proof: {spec:?}"
        );
    }
}

#[tokio::test]
async fn every_declared_mfa_contract_rejects_a_pre_mfa_session() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    install_auth_contract_sessions(&state);
    let app = crate::web::router(state);
    let cases = all_specs()
        .filter(|spec| {
            spec.surface != RouteSurface::Setup
                && matches!(
                    spec.mfa,
                    MfaContract::VerifiedSession | MfaContract::MutationContext
                )
        })
        .collect::<Vec<_>>();
    assert!(cases
        .iter()
        .any(|spec| spec.mfa == MfaContract::VerifiedSession));
    assert!(cases
        .iter()
        .any(|spec| spec.mfa == MfaContract::MutationContext));

    for spec in cases {
        let mut request = route_request(spec, "correct");
        add_session_headers(&mut request, "pending", "correct", spec);
        let response = app.clone().oneshot(request).await.unwrap();
        if response.status() != StatusCode::FORBIDDEN {
            eprintln!(
                "MFA mismatch: expected=403, actual={}, spec={spec:?}",
                response.status()
            );
        }
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "pre-MFA session reached a route declaring an MFA contract: {spec:?}"
        );
    }
}

#[tokio::test]
async fn every_session_protected_route_rejects_an_exactly_revoked_session() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    install_verified_session(&state, "revoked", "correct");
    state.db().delete_session("revoked").unwrap();
    let app = crate::web::router(state);

    for spec in all_specs().filter(|spec| {
        spec.surface != RouteSurface::Setup
            && matches!(
                spec.auth,
                AuthContract::Session | AuthContract::AdminSession
            )
    }) {
        let mut request = route_request(spec, "correct");
        add_session_headers(&mut request, "revoked", "correct", spec);
        let response = app.clone().oneshot(request).await.unwrap();
        let expected = match (spec.surface, spec.path) {
            // The queue endpoint is a fetch/JSON transport under the web URL
            // space and intentionally preserves its stable 401 response.
            (RouteSurface::Web, "/admin/files/upload/queue") => StatusCode::UNAUTHORIZED,
            (RouteSurface::Web, _) => StatusCode::SEE_OTHER,
            (RouteSurface::ApiV2, _) => StatusCode::UNAUTHORIZED,
            (RouteSurface::Setup, _) => unreachable!(),
        };
        if response.status() != expected {
            eprintln!(
                "revocation mismatch: expected={expected}, actual={}, spec={spec:?}",
                response.status()
            );
        }
        assert_eq!(
            response.status(),
            expected,
            "revoked session reached a protected handler: {spec:?}"
        );
        if spec.surface == RouteSurface::ApiV2 {
            assert!(
                response_text(response).await.contains("session_revoked"),
                "API revocation response lost its stable error code: {spec:?}"
            );
        }
    }
}

#[test]
fn required_audit_behavior_matrix_covers_every_web_and_api_mutation_class() {
    let probes = [
        (
            RouteMethod::Post,
            "/session/logout",
            MutationContract::Authentication,
        ),
        (RouteMethod::Post, "/admins", MutationContract::Privileged),
        (
            RouteMethod::Post,
            "/files/directories",
            MutationContract::Storage,
        ),
        (
            RouteMethod::Post,
            "/public/shares/{token}/upload",
            MutationContract::Upload,
        ),
        (
            RouteMethod::Get,
            "/public/shares/{token}/download",
            MutationContract::ReadOnly,
        ),
    ];
    let declared_classes = all_specs()
        .filter(|spec| spec.surface != RouteSurface::Setup && spec.audit == AuditContract::Required)
        .map(|spec| spec.mutation)
        .collect::<BTreeSet<_>>();
    let probed_classes = probes
        .iter()
        .map(|(_, _, mutation)| *mutation)
        .collect::<BTreeSet<_>>();
    assert_eq!(probed_classes, declared_classes);

    for (method, path, mutation) in probes {
        let spec = crate::api::API_ROUTE_SPECS
            .iter()
            .find(|spec| spec.method == method && spec.path == path)
            .unwrap_or_else(|| panic!("required-audit probe is not a declared API route: {path}"));
        assert_eq!(spec.audit, AuditContract::Required, "{spec:?}");
        assert_eq!(spec.mutation, mutation, "{spec:?}");
    }
}

#[tokio::test]
async fn required_audit_failure_rolls_back_authentication_mutation() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    install_verified_session(&state, "session", "csrf");
    install_audit_failure(data.path(), "route_manifest_fail_logout_audit", "logout");
    let response = crate::web::router(state.clone())
        .oneshot(authenticated_api_request(
            Method::POST,
            "/api/v2/session/logout",
            None,
            "",
            "session",
            "csrf",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response_text(response).await.contains("audit_unavailable"));
    assert!(state.db().session("session").unwrap().is_some());
    assert_eq!(state.db().count_audit(Some("logout")).unwrap(), 0);
}

#[tokio::test]
async fn required_audit_failure_rolls_back_a_declared_privileged_mutation() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    install_verified_session(&state, "session", "csrf");
    install_audit_failure(
        data.path(),
        "route_manifest_fail_admin_audit",
        "admin_created",
    );
    let app = crate::web::router(state.clone());
    let mut request = request(
        Method::POST,
        "/api/v2/admins",
        Some("application/json"),
        r#"{"username":"operator","password":"correct horse battery staple"}"#,
    );
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=session"),
    );
    request
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_static("csrf"));

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response_text(response).await.contains("audit_unavailable"));
    assert_eq!(state.db().list_admins().unwrap().len(), 1);
    assert_eq!(state.db().count_audit(Some("admin_created")).unwrap(), 0);
}

#[tokio::test]
async fn required_audit_failure_preserves_storage_uncertainty_contract() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    install_verified_session(&state, "session", "csrf");
    install_audit_failure(
        data.path(),
        "route_manifest_fail_directory_audit",
        "directory_created",
    );
    let response = crate::web::router(state.clone())
        .oneshot(authenticated_api_request(
            Method::POST,
            "/api/v2/files/directories",
            Some("application/json"),
            r#"{"parent":"","name":"audit-uncertain"}"#,
            "session",
            "csrf",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(response_text(response)
        .await
        .contains("audit_durability_uncertain"));
    assert!(root.path().join("audit-uncertain").is_dir());
    assert_eq!(
        state.db().count_audit(Some("directory_created")).unwrap(),
        0
    );
}

#[tokio::test]
async fn required_audit_failure_before_upload_publication_is_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share_with_upload_limits(
            "audit-failure-upload",
            None,
            "uploads",
            true,
            &crate::db::Permission::UploadOnly,
            None,
            None,
            Some(100),
            Some(100),
            Some(10),
            1,
            None,
            &crate::db::UploadConflictStrategy::Reject,
        )
        .unwrap();
    install_audit_failure(
        data.path(),
        "route_manifest_fail_upload_audit",
        "upload_quota_committed",
    );
    let response = crate::web::router(state.clone())
        .oneshot(public_upload_request(
            "/api/v2/public/shares/audit-failure-upload/upload",
            "must-not-appear.txt",
            b"payload",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response_text(response).await.contains("audit_unavailable"));
    assert!(!root.path().join("uploads/must-not-appear.txt").exists());
    let share = state
        .db()
        .share_by_token("audit-failure-upload")
        .unwrap()
        .unwrap();
    assert_eq!((share.uploaded_bytes, share.uploaded_files), (0, 0));
}

#[tokio::test]
async fn required_audit_failure_withholds_read_only_transfer_data() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("download.txt"), b"must not be delivered").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
        .create_share(
            "audit-failure-download",
            None,
            "download.txt",
            false,
            &crate::db::Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &crate::db::UploadConflictStrategy::Reject,
        )
        .unwrap();
    install_audit_failure(
        data.path(),
        "route_manifest_fail_download_audit",
        "download",
    );
    let response = crate::web::router(state.clone())
        .oneshot(request(
            Method::GET,
            "/api/v2/public/shares/audit-failure-download/download",
            None,
            "",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(to_bytes(response.into_body(), usize::MAX).await.is_err());
    let share = state
        .db()
        .share_by_token("audit-failure-download")
        .unwrap()
        .unwrap();
    assert_eq!(share.download_count, 0);
    assert_eq!(state.db().count_audit(Some("download")).unwrap(), 0);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if state.db().active_transfer_reservations(share_id).unwrap() == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("failed required-audit finalizer must release its transfer reservation");
}

#[test]
fn mfa_enrollment_ttl_starts_after_the_session_fenced_writer_is_admitted() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    install_verified_session(&state, "session", "csrf");

    let blocker = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let database = state.db().clone();
    let worker = std::thread::spawn(move || {
        database.start_admin_mfa_enrollment_and_audit_for_session(
            &crate::db::MfaSessionProof::for_test("session", 1),
            "pending-enrollment",
            "pending-secret",
            42,
            &crate::db::AuditContext::new("admin", None),
        )
    });

    // This exceeds timestamp rounding noise and would consume part of the TTL
    // if it were captured before BEGIN IMMEDIATE admitted the worker.
    std::thread::sleep(std::time::Duration::from_millis(2_500));
    let writer_released_at = Utc::now();
    blocker.execute_batch("COMMIT").unwrap();
    let outcome = worker.join().unwrap().unwrap();
    let crate::db::SessionBound::Authorized(outcome) = outcome else {
        panic!("verified session must start an MFA enrollment");
    };
    let crate::db::AuditedAdminMfaEnrollmentStartOutcome::Started { expires_at } =
        outcome.into_test_value()
    else {
        panic!("verified session must start an MFA enrollment");
    };
    let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_at)
        .unwrap()
        .with_timezone(&Utc);
    assert!(
        expires_at
            >= writer_released_at
                + Duration::seconds(crate::db::ADMIN_MFA_ENROLLMENT_TTL_SECONDS - 1),
        "MFA enrollment TTL was consumed while waiting for the writer"
    );
}

#[tokio::test]
async fn removed_api_v1_namespace_stays_unroutable() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let response = crate::web::router(test_state(root.path(), data.path()))
        .oneshot(request(Method::GET, "/api/v1/health", None, ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
