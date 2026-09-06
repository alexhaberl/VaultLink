#[tokio::test]
async fn admin_raw_preview_get_head_ranges_limits_and_authorization() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session("raw-session", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    state.db().verify_mfa("raw-session").unwrap();
    std::fs::write(root.path().join("image.png"), b"raw-preview!").unwrap();
    std::fs::write(root.path().join("empty.png"), b"").unwrap();
    let app = router(state.clone());
    let uri = "/admin/preview/raw?path=image.png";
    assert_eq!(
        app.clone()
            .oneshot(request(Method::GET, uri, ""))
            .await
            .unwrap()
            .status(),
        StatusCode::SEE_OTHER
    );
    for method in [Method::GET, Method::HEAD] {
        for (range, status, length, content) in [
            (None, StatusCode::OK, "12", &b"raw-preview!"[..]),
            (
                Some("bytes=2-5"),
                StatusCode::PARTIAL_CONTENT,
                "4",
                &b"w-pr"[..],
            ),
            (
                Some("bytes=100-"),
                StatusCode::RANGE_NOT_SATISFIABLE,
                "0",
                &b""[..],
            ),
        ] {
            let mut req = range_request(method.clone(), uri, range);
            req.headers_mut().insert(
                header::COOKIE,
                HeaderValue::from_static("vaultlink_session=raw-session"),
            );
            let response = app.clone().oneshot(req).await.unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::ACCEPT_RANGES], "bytes");
            if status == StatusCode::RANGE_NOT_SATISFIABLE {
                assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes */12");
            } else {
                assert_eq!(response.headers()[header::CONTENT_LENGTH], length);
                assert_eq!(response.headers()[header::CONTENT_TYPE], "image/png");
                assert_eq!(response.headers()["x-content-type-options"], "nosniff");
                assert!(response.headers()[header::CONTENT_DISPOSITION]
                    .to_str()
                    .unwrap()
                    .starts_with("inline;"));
            }
            if status == StatusCode::PARTIAL_CONTENT {
                assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes 2-5/12");
            }
            let bytes = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(
                &bytes[..],
                if method == Method::HEAD {
                    &b""[..]
                } else {
                    content
                }
            );
        }
    }
    for (path, status) in [
        ("empty.png", StatusCode::OK),
        ("missing.png", StatusCode::NOT_FOUND),
        ("image.txt", StatusCode::UNSUPPORTED_MEDIA_TYPE),
    ] {
        let mut req = request(Method::GET, &format!("/admin/preview/raw?path={path}"), "");
        req.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_static("vaultlink_session=raw-session"),
        );
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), status);
    }
    state.mutate_runtime_for_test(|runtime| runtime.max_media_preview_size = 1);
    let mut req = request(Method::GET, uri, "");
    req.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("vaultlink_session=raw-session"),
    );
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}
