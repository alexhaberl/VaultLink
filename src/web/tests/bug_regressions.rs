mod bug_regressions {
    use super::*;
    use crate::{db::UploadOperationScope, test_checkpoint::Checkpoint};

    fn session(state: &AppState) {
        state.db().create_admin("admin", "hash", "secret").unwrap();
        state
            .db()
            .create_session(
                "bugs-session",
                1,
                "bugs-csrf",
                Utc::now() + Duration::hours(1),
            )
            .unwrap();
        state.db().verify_mfa("bugs-session").unwrap();
    }
    fn with_cookie(mut request: Request, cookie: &str) -> Request {
        request
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        request
    }
    fn unlock(state: &AppState, id: i64, token: &str) -> String {
        let share = state.db().share_by_id(id).unwrap().unwrap();
        assert!(state
            .db()
            .create_unlock_session_for_verified_password(
                token,
                id,
                share.password_hash.as_deref().unwrap(),
                share.upload_policy_epoch,
                "bugs-csrf",
                Utc::now() + Duration::hours(1)
            )
            .unwrap());
        format!("{}={token}", crate::http_auth::unlock_cookie_name(id))
    }
    fn share(
        state: &AppState,
        token: &str,
        path: &str,
        permission: Permission,
        protected: bool,
    ) -> i64 {
        state
            .db()
            .create_share(
                token,
                None,
                path,
                true,
                &permission,
                None,
                None,
                None,
                1,
                protected.then_some("old-password-hash"),
                &UploadConflictStrategy::Reject,
            )
            .unwrap()
    }
    fn multipart(uri: &str, id: &str, cookie: &str, name: &str) -> Request {
        let mut body = String::new();
        for (key, value) in [("upload_id", id), ("path", ""), ("csrf", "bugs-csrf")] {
            body.push_str(&format!(
                "--bugs\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n"
            ));
        }
        body.push_str(&format!("--bugs\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: text/plain\r\n\r\npayload\r\n--bugs--\r\n"));
        let mut request = with_cookie(request(Method::POST, uri, &body), cookie);
        request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("multipart/form-data; boundary=bugs"),
        );
        request
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn password_rotation_between_authorization_and_transfer_is_rejected_on_every_surface() {
        for prefix in ["/v", "/api/v2/public/shares"] {
            for (method, suffix, path) in [
                (Method::GET, "download", "file.txt"),
                (Method::HEAD, "download", "file.txt"),
                (Method::GET, "download.zip", ""),
                (Method::GET, "preview", "file.txt"),
                (Method::GET, "preview/raw", "file.png"),
                (Method::HEAD, "preview/raw", "file.png"),
            ] {
                let root = tempfile::tempdir().unwrap();
                let data = tempfile::tempdir().unwrap();
                std::fs::create_dir(root.path().join("docs")).unwrap();
                std::fs::write(root.path().join("docs/file.txt"), b"private payload").unwrap();
                std::fs::write(root.path().join("docs/file.png"), b"private payload").unwrap();
                let state = test_state(root.path(), data.path());
                session(&state);
                let token = auth::random_token(16);
                let id = share(&state, &token, "docs", Permission::DownloadOnly, true);
                let old_cookie = unlock(&state, id, "old-unlock");
                let phase = if method == Method::HEAD {
                    "transfer-check"
                } else {
                    "transfer-begin"
                };
                let checkpoint = Checkpoint::new(format!("{phase}:{token}"));
                let mut uri = format!("{prefix}/{token}/{suffix}?path={path}");
                if suffix == "preview/raw" {
                    state
                        .db()
                        .create_preview_session(
                            "bugs-preview",
                            "bugs-owner",
                            id,
                            path,
                            Utc::now() + Duration::hours(1),
                        )
                        .unwrap();
                    uri.push_str("&preview_token=bugs-preview");
                }
                let app = router(state.clone());
                eprintln!("race regression: {method} {uri}");
                let req = with_cookie(request(method.clone(), &uri, ""), &old_cookie);
                let task_app = app.clone();
                let mut task = tokio::spawn(async move { task_app.oneshot(req).await.unwrap() });
                tokio::select! {
                    () = checkpoint.entered() => {},
                    response = &mut task => {
                        let response = response.unwrap();
                        eprintln!("premature response {}: {}", response.status(), response_text(response).await);
                        panic!("transfer did not reach lease boundary");
                    }
                }
                state
                    .db()
                    .set_share_password(id, Some("new-password-hash"))
                    .unwrap();
                checkpoint.release();
                let response = task.await.unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::UNAUTHORIZED,
                    "{method} {uri}"
                );
                assert!(!response_text(response).await.contains("private payload"));
                assert_eq!(state.db().active_transfer_reservations(id).unwrap(), 0);
                assert_eq!(
                    state.db().share_by_id(id).unwrap().unwrap().download_count,
                    0
                );
                drop(checkpoint);
                let new_cookie = unlock(&state, id, "new-unlock");
                let response = app
                    .oneshot(with_cookie(request(method, &uri, ""), &new_cookie))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK, "new unlock: {uri}");
                axum::body::to_bytes(response.into_body(), 1024 * 1024)
                    .await
                    .unwrap();
            }
        }
    }

    #[tokio::test]
    async fn navigation_never_issues_upload_ids_and_html_preparation_uploads_without_javascript() {
        for mode in ["admin", "public", "protected"] {
            let root = tempfile::tempdir().unwrap();
            let data = tempfile::tempdir().unwrap();
            let state = test_state(root.path(), data.path());
            session(&state);
            let (page, base, cookie, scope) = if mode == "admin" {
                (
                    "/admin".to_owned(),
                    "/admin/files/upload".to_owned(),
                    "vaultlink_session=bugs-session".to_owned(),
                    UploadOperationScope::Admin(1),
                )
            } else {
                let id = share(
                    &state,
                    "navigation",
                    "",
                    Permission::UploadOnly,
                    mode == "protected",
                );
                let cookie = if mode == "protected" {
                    unlock(&state, id, "navigation-unlock")
                } else {
                    String::new()
                };
                (
                    "/v/navigation".to_owned(),
                    "/v/navigation/upload".to_owned(),
                    cookie,
                    UploadOperationScope::Share(id),
                )
            };
            let app = router(state.clone());
            for _ in 0..65 {
                let response = app
                    .clone()
                    .oneshot(with_cookie(request(Method::GET, &page, ""), &cookie))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK, "{mode}");
                let html = response_text(response).await;
                assert!(html.contains("data-upload-prepare"));
                assert!(!html.contains("name=\"upload_id\""));
            }
            let probe = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
            assert_eq!(
                probe
                    .query_row::<i64, _, _>("SELECT COUNT(*) FROM upload_operations", [], |row| row
                        .get(0))
                    .unwrap(),
                0
            );
            if mode != "public" {
                let response = app
                    .clone()
                    .oneshot(with_cookie(
                        request(Method::POST, &format!("{base}/prepare"), "csrf=wrong"),
                        &cookie,
                    ))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
            }
            let response = app
                .clone()
                .oneshot(with_cookie(
                    request(Method::POST, &format!("{base}/prepare"), "csrf=bugs-csrf"),
                    &cookie,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "prepare {mode}");
            assert!(!response.headers().contains_key(header::LOCATION));
            let html = response_text(response).await;
            assert!(!html.contains("data-upload-queue"));
            let id = html
                .split("name=\"upload_id\" value=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            assert!(html.find("name=\"upload_id\"").unwrap() < html.find("name=\"file\"").unwrap());
            let response = app
                .clone()
                .oneshot(multipart(&base, id, &cookie, "html.txt"))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::SEE_OTHER,
                "upload {mode}: {}",
                response_text(response).await
            );
            assert_eq!(
                std::fs::read(root.path().join("html.txt")).unwrap(),
                b"payload"
            );
            assert_eq!(
                state
                    .db()
                    .upload_operation(scope, id)
                    .unwrap()
                    .unwrap()
                    .state,
                "completed"
            );
            // The JSON path still obtains a separate ticket on explicit action.
            let mut req = with_cookie(
                request(Method::POST, &format!("{base}/operations"), ""),
                &cookie,
            );
            req.headers_mut()
                .insert("x-csrf-token", HeaderValue::from_static("bugs-csrf"));
            req.headers_mut().insert(
                "x-vaultlink-upload-csrf",
                HeaderValue::from_static("bugs-csrf"),
            );
            let response = app.oneshot(req).await.unwrap();
            assert_eq!(response.status(), StatusCode::CREATED, "ticket {mode}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancelled_upload_claim_is_retryable_and_handed_off_commit_finishes_once() {
        for admin in [false, true] {
            for finalizing in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let data = tempfile::tempdir().unwrap();
                let state = test_state(root.path(), data.path());
                session(&state);
                let share_id = share(&state, "cancel-upload", "", Permission::UploadOnly, false);
                let (scope, uri, cookie) = if admin {
                    (
                        UploadOperationScope::Admin(1),
                        "/admin/files/upload/queue",
                        "vaultlink_session=bugs-session",
                    )
                } else {
                    (
                        UploadOperationScope::Share(share_id),
                        "/v/cancel-upload/upload/queue",
                        "",
                    )
                };
                let (id, _) = state.db().create_upload_operation(scope).unwrap().unwrap();
                let key = if finalizing {
                    format!("upload-finalizing:{}", crate::db::token_hash(&id))
                } else {
                    format!("upload-claimed:{id}")
                };
                let checkpoint = Checkpoint::new(key);
                let app = router(state.clone());
                let req = multipart(uri, &id, cookie, "once.txt");
                let task_app = app.clone();
                let task = tokio::spawn(async move { task_app.oneshot(req).await.unwrap() });
                checkpoint.entered().await;
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
                checkpoint.release();
                let expected = if finalizing { "completed" } else { "retryable" };
                tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    loop {
                        if state
                            .db()
                            .upload_operation(scope, &id)
                            .unwrap()
                            .unwrap()
                            .state
                            == expected
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                assert_eq!(root.path().join("once.txt").exists(), finalizing);
                drop(checkpoint);
                let response = app
                    .oneshot(multipart(uri, &id, cookie, "once.txt"))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(
                    std::fs::read(root.path().join("once.txt")).unwrap(),
                    b"payload"
                );
                assert_eq!(state.db().active_upload_reservations(share_id).unwrap(), 0);
                if !admin {
                    let share = state.db().share_by_id(share_id).unwrap().unwrap();
                    assert_eq!((share.uploaded_files, share.uploaded_bytes), (1, 7));
                }
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_download_open_retains_stream_capacity_until_worker_returns() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let path = format!("blocked-{}", auth::random_token(12));
        std::fs::create_dir(root.path().join(&path)).unwrap();
        std::fs::write(root.path().join(&path).join("file.txt"), b"content").unwrap();
        let mut state = test_state(root.path(), data.path());
        let streams = Arc::new(tokio::sync::Semaphore::new(1));
        state.replace_stream_admission_for_test(streams.clone());
        session(&state);
        share(
            &state,
            "cancel-open",
            &path,
            Permission::DownloadOnly,
            false,
        );
        let checkpoint = Checkpoint::new(format!("download-open:{path}"));
        let app = router(state);
        let task_app = app.clone();
        let task = tokio::spawn(async move {
            task_app
                .oneshot(request(
                    Method::GET,
                    "/v/cancel-open/download?path=file.txt",
                    "",
                ))
                .await
        });
        checkpoint.entered().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(streams.available_permits(), 0);
        let response = app
            .oneshot(request(
                Method::GET,
                "/v/cancel-open/download?path=file.txt",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        checkpoint.release();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while streams.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn verified_mfa_redirects_after_csrf_and_security_key_form_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        session(&state);
        let app = router(state);
        let cookie = "vaultlink_session=bugs-session";
        for method in [Method::GET, Method::POST] {
            for _ in 0..12 {
                let response = app
                    .clone()
                    .oneshot(with_cookie(
                        request(method.clone(), "/mfa", "csrf=bugs-csrf&code=invalid"),
                        cookie,
                    ))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::SEE_OTHER);
                assert_eq!(response.headers()[header::LOCATION], "/admin");
            }
        }
        let response = app
            .clone()
            .oneshot(with_cookie(
                request(Method::POST, "/mfa", "csrf=wrong&code=invalid"),
                cookie,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = app
            .oneshot(with_cookie(
                request(Method::GET, "/admin/account", ""),
                cookie,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = response_text(response).await;
        assert!(
            html.contains("method=\"post\" action=\"/admin/account/security-keys/register/start\"")
        );
        assert!(html.contains("disabled data-security-key-fields"));
        assert!(html.contains("data-security-key-script-required"));
    }
}
