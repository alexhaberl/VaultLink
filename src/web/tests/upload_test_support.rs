fn multipart_request(uri: &str, name: &str, content: &[u8]) -> Request {
    multipart_request_with_path(uri, name, content, None)
}

fn multipart_request_with_path(
    uri: &str,
    name: &str,
    content: &[u8],
    path: Option<&str>,
) -> Request {
    multipart_request_with_options(uri, name, content, path, false)
}

fn multipart_request_with_options(
    uri: &str,
    name: &str,
    content: &[u8],
    path: Option<&str>,
    overwrite_existing: bool,
) -> Request {
    let boundary = "vaultlink-test-boundary";
    let mut body = Vec::new();
    if let Some(path) = path {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n{path}\r\n"
            )
            .as_bytes(),
        );
    }
    if overwrite_existing {
        body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"overwrite_existing\"\r\n\r\n1\r\n"
                )
                .as_bytes(),
            );
    }
    body.extend_from_slice(format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        ).as_bytes());
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::COOKIE, "vaultlink_locale=de")
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

fn multipart_request_with_late_overwrite(uri: &str, name: &str, content: &[u8]) -> Request {
    let boundary = "vaultlink-late-intent-boundary";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(content);
    body.extend_from_slice(
        format!(
            "\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"overwrite_existing\"\r\n\r\n1\r\n--{boundary}--\r\n"
        )
        .as_bytes(),
    );
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::COOKIE, "vaultlink_locale=de")
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

fn public_folder_upload_request(
    uri: &str,
    path: &str,
    folder_path: &str,
    name: &str,
    content: &[u8],
) -> Request {
    folder_upload_request(uri, path, None, folder_path, name, content)
}

fn raw_multipart_request(uri: &str, boundary: &str, body: Vec<u8>) -> Request {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::COOKIE, "vaultlink_locale=de")
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

const CONTROLLED_UPLOAD_BOUNDARY: &str = "vaultlink-controlled-upload-boundary";

fn controlled_multipart_request(
    uri: &str,
    name: &str,
    content: &[u8],
    overwrite_requested: bool,
) -> (
    Request,
    tokio::sync::mpsc::Sender<std::result::Result<Bytes, io::Error>>,
) {
    let (sender, receiver) = tokio::sync::mpsc::channel(4);
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|chunk| (chunk, receiver))
    });
    let mut prefix = Vec::new();
    if overwrite_requested {
        prefix.extend_from_slice(
            format!(
                "--{CONTROLLED_UPLOAD_BOUNDARY}\r\nContent-Disposition: form-data; name=\"overwrite_existing\"\r\n\r\n1\r\n"
            )
            .as_bytes(),
        );
    }
    prefix.extend_from_slice(
        format!(
            "--{CONTROLLED_UPLOAD_BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    prefix.extend_from_slice(content);
    sender.try_send(Ok(Bytes::from(prefix))).unwrap();
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::COOKIE, "vaultlink_locale=de")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={CONTROLLED_UPLOAD_BOUNDARY}"),
        )
        .body(Body::from_stream(stream))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    (request, sender)
}

fn controlled_admin_multipart_request(
    uri: &str,
    path: &str,
    csrf: &str,
    session_token: &str,
    name: &str,
    content: &[u8],
) -> (
    Request,
    tokio::sync::mpsc::Sender<std::result::Result<Bytes, io::Error>>,
) {
    controlled_admin_multipart_request_with_overwrite(
        uri,
        path,
        csrf,
        session_token,
        name,
        content,
        false,
    )
}

fn controlled_admin_multipart_request_with_overwrite(
    uri: &str,
    path: &str,
    csrf: &str,
    session_token: &str,
    name: &str,
    content: &[u8],
    overwrite_existing: bool,
) -> (
    Request,
    tokio::sync::mpsc::Sender<std::result::Result<Bytes, io::Error>>,
) {
    let (sender, receiver) = tokio::sync::mpsc::channel(4);
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|chunk| (chunk, receiver))
    });
    let mut prefix = Vec::new();
    for (field, value) in [("path", path), ("csrf", csrf)] {
        prefix.extend_from_slice(
            format!(
                "--{CONTROLLED_UPLOAD_BOUNDARY}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    if overwrite_existing {
        prefix.extend_from_slice(
            format!(
                "--{CONTROLLED_UPLOAD_BOUNDARY}\r\nContent-Disposition: form-data; name=\"overwrite_existing\"\r\n\r\n1\r\n"
            )
            .as_bytes(),
        );
    }
    prefix.extend_from_slice(
        format!(
            "--{CONTROLLED_UPLOAD_BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    prefix.extend_from_slice(content);
    sender.try_send(Ok(Bytes::from(prefix))).unwrap();
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::COOKIE, format!("vaultlink_session={session_token}"))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={CONTROLLED_UPLOAD_BOUNDARY}"),
        )
        .body(Body::from_stream(stream))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    (request, sender)
}

async fn finish_controlled_multipart(
    sender: tokio::sync::mpsc::Sender<std::result::Result<Bytes, io::Error>>,
) {
    sender
        .send(Ok(Bytes::from(format!(
            "\r\n--{CONTROLLED_UPLOAD_BOUNDARY}--\r\n"
        ))))
        .await
        .unwrap();
}

async fn wait_for_upload_fragment(root: &Path) {
    let staging = root.join(".vaultlink-internal").join("uploads");
    for _ in 0..200 {
        if std::fs::read_dir(&staging).is_ok_and(|mut entries| entries.next().is_some()) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("upload did not reach staging");
}

fn upload_fragment_count(root: &Path) -> usize {
    std::fs::read_dir(root.join(".vaultlink-internal").join("uploads"))
        .map(|entries| entries.filter_map(std::result::Result::ok).count())
        .unwrap_or_default()
}

async fn wait_for_public_upload_cleanup(state: &AppState, root: &Path, share_id: i64) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if state.db().active_upload_reservations(share_id).unwrap() == 0
                && upload_fragment_count(root) == 0
                && state.upload_admission_available_for_test() == 1
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("public upload resources should be released");
}

fn api_share_strategy_request(
    share_id: i64,
    strategy: &str,
    session_token: &str,
    csrf_token: &str,
) -> Request {
    let mut request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/api/v2/shares/{share_id}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("vaultlink_session={session_token}"))
        .header("x-csrf-token", csrf_token)
        .body(Body::from(format!(
            r#"{{"upload_conflict_strategy":"{strategy}"}}"#
        )))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    request
}

fn html_share_strategy_request(
    share_id: i64,
    strategy: &str,
    session_token: &str,
    csrf_token: &str,
) -> Request {
    let mut request = request(
        Method::POST,
        &format!("/admin/shares/{share_id}/upload-conflict"),
        &format!("csrf={csrf_token}&strategy={strategy}"),
    );
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("vaultlink_session={session_token}")).unwrap(),
    );
    request
}

fn public_multipart_request_with_csrf(
    uri: &str,
    name: &str,
    content: &[u8],
    csrf: &str,
) -> Request {
    let boundary = "vaultlink-public-csrf-boundary";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n{csrf}\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::COOKIE, "vaultlink_locale=de")
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

fn admin_multipart_request(
    uri: &str,
    path: &str,
    csrf: &str,
    name: &str,
    content: &[u8],
    overwrite_existing: bool,
) -> Request {
    let boundary = "vaultlink-admin-upload-boundary";
    let mut body = Vec::new();
    for (field, value) in [("path", path), ("csrf", csrf)] {
        body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{value}\r\n"
                )
                .as_bytes(),
            );
    }
    if overwrite_existing {
        body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"overwrite_existing\"\r\n\r\n1\r\n"
                )
                .as_bytes(),
            );
    }
    body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::COOKIE, "vaultlink_locale=de")
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

fn admin_folder_upload_request(
    uri: &str,
    path: &str,
    csrf: &str,
    folder_path: &str,
    name: &str,
    content: &[u8],
) -> Request {
    folder_upload_request(uri, path, Some(csrf), folder_path, name, content)
}

fn folder_upload_request(
    uri: &str,
    path: &str,
    csrf: Option<&str>,
    folder_path: &str,
    name: &str,
    content: &[u8],
) -> Request {
    let boundary = "vaultlink-folder-upload-boundary";
    let mut body = Vec::new();
    for (field, value) in [
        ("path", Some(path)),
        ("csrf", csrf),
        ("folder_path", Some(folder_path)),
    ] {
        if let Some(value) = value {
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{value}\r\n"
                )
                .as_bytes(),
            );
        }
    }
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::COOKIE, "vaultlink_locale=de")
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
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn windows_1252_byte(ch: char) -> Option<u8> {
    match ch {
        '\u{0000}'..='\u{009f}' | '\u{00a0}'..='\u{00ff}' => Some(ch as u32 as u8),
        '\u{20ac}' => Some(0x80),
        '\u{201a}' => Some(0x82),
        '\u{0192}' => Some(0x83),
        '\u{201e}' => Some(0x84),
        '\u{2026}' => Some(0x85),
        '\u{2020}' => Some(0x86),
        '\u{2021}' => Some(0x87),
        '\u{02c6}' => Some(0x88),
        '\u{2030}' => Some(0x89),
        '\u{0160}' => Some(0x8a),
        '\u{2039}' => Some(0x8b),
        '\u{0152}' => Some(0x8c),
        '\u{017d}' => Some(0x8e),
        '\u{2018}' => Some(0x91),
        '\u{2019}' => Some(0x92),
        '\u{201c}' => Some(0x93),
        '\u{201d}' => Some(0x94),
        '\u{2022}' => Some(0x95),
        '\u{2013}' => Some(0x96),
        '\u{2014}' => Some(0x97),
        '\u{02dc}' => Some(0x98),
        '\u{2122}' => Some(0x99),
        '\u{0161}' => Some(0x9a),
        '\u{203a}' => Some(0x9b),
        '\u{0153}' => Some(0x9c),
        '\u{017e}' => Some(0x9e),
        '\u{0178}' => Some(0x9f),
        _ => None,
    }
}

fn assert_no_mojibake(label: &str, text: &str) {
    if let Some((offset, _)) = text.char_indices().find(|(_, ch)| *ch == '\u{fffd}') {
        panic!("{label} contains the Unicode replacement character at byte {offset}");
    }

    let chars = text.char_indices().collect::<Vec<_>>();
    for start in 0..chars.len() {
        for len in 2..=4 {
            let end = start + len;
            if end > chars.len() {
                continue;
            }
            let Some(bytes) = chars[start..end]
                .iter()
                .map(|(_, ch)| windows_1252_byte(*ch))
                .collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            let expected_len = match bytes[0] {
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => continue,
            };
            if len != expected_len || !bytes[1..].iter().all(|byte| (0x80..=0xbf).contains(byte)) {
                continue;
            }
            let Ok(decoded) = std::str::from_utf8(&bytes) else {
                continue;
            };
            let start_offset = chars[start].0;
            let end_offset = chars.get(end).map_or(text.len(), |(offset, _)| *offset);
            let suspect = &text[start_offset..end_offset];
            panic!(
                    "{label} contains likely Windows-1252/UTF-8 mojibake at byte {start_offset}: {suspect:?} should be {decoded:?}"
                );
        }
    }
}

fn web_production_sources() -> [(&'static str, &'static str); 20] {
    [
        ("src/web.rs", include_str!("../../web.rs")),
        ("src/web/account.rs", include_str!("../account.rs")),
        ("src/web/admin.rs", include_str!("../admin.rs")),
        ("src/web/admission.rs", include_str!("../admission.rs")),
        ("src/web/auth_ui.rs", include_str!("../auth_ui.rs")),
        ("src/web/common.rs", include_str!("../common.rs")),
        ("src/web/files.rs", include_str!("../files.rs")),
        ("src/web/preview_zip.rs", include_str!("../preview_zip.rs")),
        ("src/web/public.rs", include_str!("../public.rs")),
        (
            "src/web/public_preview.rs",
            include_str!("../public_preview.rs"),
        ),
        ("src/web/rendering.rs", include_str!("../rendering.rs")),
        (
            "src/web/service_tokens.rs",
            include_str!("../service_tokens.rs"),
        ),
        (
            "src/web/settings_audit.rs",
            include_str!("../settings_audit.rs"),
        ),
        ("src/web/shares.rs", include_str!("../shares.rs")),
        ("src/web/transfer.rs", include_str!("../transfer.rs")),
        (
            "src/web/transfer_runtime.rs",
            include_str!("../transfer_runtime.rs"),
        ),
        (
            "src/web/public_upload/mod.rs",
            include_str!("../public_upload/mod.rs"),
        ),
        (
            "src/web/public_upload/finalizer.rs",
            include_str!("../../public_upload_transport/finalizer.rs"),
        ),
        (
            "src/web/public_upload/multipart.rs",
            include_str!("../../public_upload_transport/multipart.rs"),
        ),
        (
            "src/web/public_upload/presenter.rs",
            include_str!("../public_upload/presenter.rs"),
        ),
    ]
}

fn preview_token_from(html: &str) -> String {
    let marker = "preview_token=";
    let start = html.find(marker).expect("preview token in html") + marker.len();
    let encoded = html[start..]
        .chars()
        .take_while(|c| *c != '"' && *c != '&')
        .collect::<String>();
    percent_encoding::percent_decode_str(&encoded)
        .decode_utf8()
        .unwrap()
        .into_owned()
}

fn range_request(method: Method, uri: &str, range: Option<&str>) -> Request {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(range) = range {
        builder = builder.header(header::RANGE, range);
    }
    let mut request = builder.body(Body::empty()).unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    request
}
