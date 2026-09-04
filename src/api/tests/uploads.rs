#[tokio::test]
async fn api_delegated_public_upload_errors_are_json() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state
        .db()
        .create_admin("admin", &hash, &auth::new_totp_secret())
        .unwrap();
    state
        .db()
        .create_share(
            "upload-token",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let app = crate::web::router(state);
    let response = app
        .oneshot(multipart_request(
            "/api/v2/public/shares/upload-token/upload",
            "blocked.exe",
            b"blocked",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(response
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("application/json"));
    let body = response_text(response).await;
    assert!(body.contains(r#""code":"unsupported_media_type""#));
    assert!(!body.contains("<html"));
    assert!(!body.contains("Zurück zur Freigabe"));
}

#[tokio::test]
async fn api_upload_reports_required_audit_failure_and_never_publishes_the_file() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
        .create_share_with_upload_limits(
            "audit-failure-upload",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            Some(100),
            Some(100),
            Some(10),
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let fault = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    fault
        .execute_batch(
            "CREATE TRIGGER fail_upload_quota_audit
             BEFORE INSERT ON audit
             WHEN NEW.action='upload_quota_committed'
             BEGIN SELECT RAISE(ABORT, 'injected upload audit failure'); END;",
        )
        .unwrap();
    let app = crate::web::router(state.clone());

    let response = app
        .oneshot(multipart_request(
            "/api/v2/public/shares/audit-failure-upload/upload",
            "must-not-appear.txt",
            b"payload",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("application/json"));
    let body = response_text(response).await;
    assert!(body.contains(r#""code":"audit_unavailable""#));
    assert!(!root.path().join("uploads/must-not-appear.txt").exists());
    let share = state
        .db()
        .share_by_token("audit-failure-upload")
        .unwrap()
        .unwrap();
    assert_eq!((share.uploaded_bytes, share.uploaded_files), (0, 0));
    for _ in 0..100 {
        if state.db().active_upload_reservations(share_id).unwrap() == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    assert_eq!(state.db().active_upload_reservations(share_id).unwrap(), 0);
}

#[tokio::test]
async fn api_upload_reports_post_publication_audit_uncertainty_without_retry_signal() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share_with_upload_limits(
            "post-publish-audit-failure",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            Some(100),
            Some(100),
            Some(10),
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let fault = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    fault
        .execute_batch(
            "CREATE TRIGGER fail_published_upload_audit
             BEFORE INSERT ON audit
             WHEN NEW.action='upload'
             BEGIN SELECT RAISE(ABORT, 'injected post-publication audit failure'); END;",
        )
        .unwrap();
    let app = crate::web::router(state.clone());

    let response = app
        .oneshot(multipart_request(
            "/api/v2/public/shares/post-publish-audit-failure/upload",
            "already-visible.txt",
            b"payload",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(response
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("application/json"));
    let body = response_text(response).await;
    assert!(body.contains(r#""warning":"audit_durability_uncertain""#));
    assert!(body.contains(r#""file":"already-visible.txt""#));
    assert!(root.path().join("uploads/already-visible.txt").exists());
    let share = state
        .db()
        .share_by_token("post-publish-audit-failure")
        .unwrap()
        .unwrap();
    assert_eq!((share.uploaded_bytes, share.uploaded_files), (7, 1));
}

#[test]
fn only_required_audit_introduces_a_new_service_unavailable_code() {
    use crate::http_auth::{HttpAuthError, HttpAuthErrorKind};

    let capacity = ApiError::from(HttpAuthError::with_kind(
        StatusCode::SERVICE_UNAVAILABLE,
        "capacity",
        HttpAuthErrorKind::CapacityUnavailable,
    ));
    assert_eq!(capacity.code, "request_failed");

    let audit = ApiError::from(HttpAuthError::with_kind(
        StatusCode::SERVICE_UNAVAILABLE,
        "audit",
        HttpAuthErrorKind::AuditUnavailable,
    ));
    assert_eq!(audit.code, "audit_unavailable");
}

#[test]
fn file_recovery_required_audit_failure_maps_to_stable_503_code() {
    let data = tempfile::tempdir().unwrap();
    let database_path = data.path().join("data.sqlite");
    let database = crate::db::Database::open(&database_path).unwrap();
    database
        .create_admin("admin", "old-hash", "secret")
        .unwrap();
    rusqlite::Connection::open(database_path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_file_recovery_audit
             BEFORE INSERT ON audit
             BEGIN SELECT RAISE(FAIL, 'injected file recovery audit failure'); END;",
        )
        .unwrap();
    let database_error = database
        .reset_admin_password_and_audit(
            1,
            "new-hash",
            &crate::db::AuditContext::new("system", None),
        )
        .unwrap_err();
    assert!(crate::db::is_audit_unavailable(&database_error));

    let mapped = files::file_operation_error(crate::file_ops::FileOperationError::Database(
        database_error,
    ));
    assert_eq!(mapped.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(mapped.code, "audit_unavailable");
    assert_eq!(mapped.message, "Security audit temporarily unavailable");
}

#[test]
fn file_database_busy_and_locked_errors_map_to_retryable_api_capacity() {
    for code in [rusqlite::ffi::SQLITE_BUSY, rusqlite::ffi::SQLITE_LOCKED] {
        for recovery in [false, true] {
            let file_error = crate::file_ops::FileOperationError::Database(
                rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None),
            );
            let mapped = if recovery {
                storage_recovery_api_error(file_error)
            } else {
                files::file_operation_error(file_error)
            };
            assert_eq!(mapped.status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(mapped.code, "request_failed");
            assert_eq!(
                mapped.message,
                "Request processing capacity is temporarily unavailable"
            );
            assert_eq!(mapped.retry_after_seconds, Some(1));

            let response = mapped.into_response();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "1");
        }
    }
}

#[test]
fn file_database_executor_capacity_keeps_the_api_capacity_contract() {
    for recovery in [false, true] {
        let error = crate::file_ops::FileOperationError::DatabaseCapacity;
        let mapped = if recovery {
            storage_recovery_api_error(error)
        } else {
            files::file_operation_error(error)
        };
        assert_eq!(mapped.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(mapped.code, "request_failed");
        assert_eq!(
            mapped.message,
            "Request processing capacity is temporarily unavailable"
        );
        assert_eq!(mapped.retry_after_seconds, Some(1));
        let response = mapped.into_response();
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "1");
    }
}

#[tokio::test]
async fn api_share_creation_preserves_audit_unavailable_from_real_pending_recovery() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("old.txt"), b"content").unwrap();
    let state = test_state(root.path(), data.path());
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password("correct horse battery staple").unwrap();
    state.db().create_admin("admin", &hash, &secret).unwrap();
    state
        .db()
        .create_share(
            "pending-recovery-token",
            None,
            "old.txt",
            false,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let (session_cookie, csrf) = api_login(&state, &secret).await;
    let fault = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    fault
        .execute_batch(
            "CREATE TRIGGER fail_pending_recovery_audit
             BEFORE INSERT ON audit
             BEGIN SELECT RAISE(FAIL, 'injected recovery audit failure'); END;",
        )
        .unwrap();

    let session_token = session_cookie
        .strip_prefix("vaultlink_session=")
        .expect("test session cookie");
    let proof = crate::db::MfaSessionProof::for_test(session_token, 1);
    let rename = crate::file_ops::rename(
        &state,
        proof,
        "old.txt",
        "new.txt",
        crate::db::AuditContext::new("admin", None),
    )
    .await
    .unwrap();
    let rename = match rename {
        crate::file_ops::RequiredAuditFileOutcome::Audited(audited) => {
            crate::db::release_session_audited(audited)
        }
        crate::file_ops::RequiredAuditFileOutcome::Uncertain(outcome) => outcome,
    };
    let rename = session_bound(rename).unwrap();
    assert!(rename.audit_durability.is_uncertain());
    assert_eq!(
        state.secure_root().pending_file_operations().unwrap().len(),
        1
    );

    let app = crate::web::router(state.clone());
    let mut request = json_request(
        Method::POST,
        "/api/v2/shares",
        r#"{"path":"new.txt","permission":"download_only"}"#,
    );
    authorize_mutation(&mut request, &session_cookie, &csrf);
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response_text(response)
        .await
        .contains(r#""code":"audit_unavailable""#));
    assert_eq!(
        state.secure_root().pending_file_operations().unwrap().len(),
        1
    );
    assert_eq!(
        state
            .db()
            .share_by_token("pending-recovery-token")
            .unwrap()
            .unwrap()
            .relative_path,
        "old.txt"
    );
}
