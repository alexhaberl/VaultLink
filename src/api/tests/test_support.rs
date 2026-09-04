use super::*;
use crate::config::{
    Admission, Config, Logging, ReverseProxy, Security, Server, ServerMode, Storage, Tls,
};
use axum::{
    body::{to_bytes, Body},
    http::{Method, Request},
};
use chrono::{DateTime, Duration, Utc};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;

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
            max_search_entries: 1000,
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

fn json_request(method: Method, uri: &str, body: &str) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    request
}

fn multipart_request(uri: &str, name: &str, content: &[u8]) -> Request<Body> {
    let boundary = "vaultlink-api-test-boundary";
    let mut body = Vec::new();
    body.extend_from_slice(format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        ).as_bytes());
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    request
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

fn json_string_value(body: &str, key: &str) -> String {
    let marker = format!("\"{key}\":\"");
    let start = body.find(&marker).expect("json key") + marker.len();
    let end = body[start..].find('"').expect("json value end") + start;
    body[start..end].to_string()
}

fn json_i64_value(body: &str, key: &str) -> i64 {
    let marker = format!("\"{key}\":");
    let start = body.find(&marker).expect("json key") + marker.len();
    let end = body[start..]
        .find(|c: char| !c.is_ascii_digit())
        .map(|offset| start + offset)
        .unwrap_or(body.len());
    body[start..end].parse().unwrap()
}

fn cookie(response: &Response) -> String {
    response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

fn current_totp(secret: &str) -> String {
    let step = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;
    auth::totp_code(secret, step).unwrap()
}
