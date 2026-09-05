#[tokio::test]
async fn login_username_churn_cannot_reveal_an_existing_account() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state
        .db()
        .create_admin("admin", "irrelevant-hash", &auth::new_totp_secret())
        .unwrap();
    let app = crate::web::router(state.clone());
    for index in 0..5 {
        let response = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/api/v2/session/login",
                &format!(r#"{{"username":"absent-{index}","password":"wrong"}}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    for name in ["admin", "new-unknown"] {
        let response = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/api/v2/session/login",
                &format!(r#"{{"username":"{name}","password":"wrong"}}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}

#[tokio::test]
async fn enormous_login_names_are_bounded_in_both_transports() {
    for web in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let name = "x".repeat(900_000);
        let mut request = if web {
            json_request(
                Method::POST,
                "/login",
                &format!("username={name}&password=wrong"),
            )
        } else {
            json_request(
                Method::POST,
                "/api/v2/session/login",
                &format!(r#"{{"username":"{name}","password":"wrong"}}"#),
            )
        };
        if web {
            request.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            );
        }
        let response = crate::web::router(state.clone())
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response_text(response).await.len() < 20_000);
        let rows = state.db().list_audit(Some("login_failed"), 10, 0).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].actor, "<invalid-username>");
        let detail = rows[0].detail.as_deref().unwrap();
        assert!(detail.contains("username_bytes=900000;username_sha256="));
        assert!(detail.len() < 180);
    }
}

#[tokio::test]
async fn storage_busy_has_a_retryable_public_contract() {
    let response =
        ApiError::from(crate::services::public_transfer::PublicTransferError::StorageBusy)
            .into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::RETRY_AFTER], "1");
    assert!(response_text(response).await.contains("storage_busy"));
    let response = crate::web::AppError::from(
        crate::services::public_transfer::PublicTransferError::StorageBusy,
    )
    .into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::RETRY_AFTER], "1");
}
