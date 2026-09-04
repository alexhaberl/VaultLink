#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_response_cookie_is_reported_without_panicking() {
        let error = redirect_with_cookie("/", "cookie=value\r\nbad=value")
            .expect_err("invalid cookie header must be rejected");
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.message, "Internal error");
        assert_eq!(error.kind, HttpAuthErrorKind::Request);
        assert_eq!(error.redirect, None);
    }

    #[test]
    fn duplicate_named_cookies_are_rejected_across_cookie_headers() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("other=x; session=one"),
        );
        headers.append(header::COOKIE, HeaderValue::from_static("session=two"));
        assert_eq!(named_cookie(&headers, "session"), None);

        let mut single = HeaderMap::new();
        single.insert(
            header::COOKIE,
            HeaderValue::from_static("session=one; other=x"),
        );
        assert_eq!(named_cookie(&single, "session"), Some("one"));
    }

    #[test]
    fn service_token_authorization_parser_is_exact_and_canonical() {
        let encoded = URL_SAFE_NO_PAD.encode([7u8; 32]);
        let token = format!("{SERVICE_TOKEN_PREFIX}{encoded}");
        let authorization = format!("Bearer {token}");
        assert_eq!(strict_service_token(&authorization), Some(token.as_str()));
        assert_eq!(
            strict_service_token(&format!("bEaReR {token}")),
            Some(token.as_str())
        );

        for invalid in [
            format!("Bearer  {token}"),
            format!("Bearer {token}="),
            format!("Bearer {SERVICE_TOKEN_PREFIX}{}", &encoded[..42]),
            format!("Bearer {SERVICE_TOKEN_PREFIX}{}!", &encoded[..42]),
        ] {
            assert_eq!(strict_service_token(&invalid), None, "{invalid}");
        }
    }

    #[test]
    fn duplicate_authorization_headers_are_invalid() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer one"),
        );
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer two"),
        );
        assert!(matches!(
            exact_authorization(&headers),
            ExactHeader::Ambiguous
        ));

        let mut joined = HeaderMap::new();
        joined.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer one, Bearer two"),
        );
        assert!(matches!(
            exact_authorization(&joined),
            ExactHeader::Ambiguous
        ));
    }

    #[tokio::test]
    async fn ordinary_database_busy_and_locked_errors_are_retryable_capacity_failures() {
        fn sqlite_capacity_error(code: i32) -> rusqlite::Error {
            rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None)
        }

        for code in [
            rusqlite::ffi::SQLITE_BUSY,
            rusqlite::ffi::SQLITE_BUSY_TIMEOUT,
            rusqlite::ffi::SQLITE_LOCKED,
            rusqlite::ffi::SQLITE_LOCKED_SHAREDCACHE,
        ] {
            assert!(crate::db::is_sqlite_busy_or_locked(&sqlite_capacity_error(
                code
            )));
            let mapped = database(Database::open(":memory:").unwrap(), move |_| {
                Err::<(), _>(sqlite_capacity_error(code))
            })
            .await
            .unwrap_err();
            assert_eq!(mapped.status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(mapped.kind, HttpAuthErrorKind::CapacityUnavailable);
            assert_eq!(mapped.message, DATABASE_BUSY_MESSAGE);

            let response = crate::web::AppError::from(mapped).into_response();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "1");

            let required_mapped =
                required_audited_database(Database::open(":memory:").unwrap(), move |database| {
                    database.required_audit_failure_for_test::<()>(sqlite_capacity_error(code))
                })
                .await
                .unwrap_err();
            assert_eq!(required_mapped.status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(required_mapped.kind, HttpAuthErrorKind::CapacityUnavailable);
        }
    }

    #[tokio::test]
    async fn saturated_database_executor_rejects_reads_after_one_second() {
        let database_handle = Database::open(":memory:").unwrap();
        let permit = database_handle.acquire_runtime_permit().await.unwrap();
        assert_eq!(database_handle.runtime_available_permits(), 0);

        let started = std::time::Instant::now();
        let error = database(database_handle.clone(), |_| Ok(()))
            .await
            .unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.kind, HttpAuthErrorKind::CapacityUnavailable);
        assert_eq!(error.message, DATABASE_BUSY_MESSAGE);
        assert!(elapsed >= std::time::Duration::from_millis(950));
        assert!(elapsed < std::time::Duration::from_millis(1_250));

        drop(permit);
        database(database_handle, |_| Ok(())).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn security_mutation_inline_audit_survives_cancelled_database_await() {
        let db = Database::open(":memory:").unwrap();
        db.create_admin("admin", "old-hash", "secret").unwrap();
        let operation_database = db.clone();
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let (finished_sender, finished_receiver) = tokio::sync::oneshot::channel();

        let request = tokio::spawn(async move {
            required_audited_database(operation_database, move |database| {
                let _ = started_sender.send(());
                release_receiver.recv().unwrap();
                let changed = database.reset_admin_password_and_audit_audited(
                    1,
                    "new-hash",
                    &AuditContext::new("admin", None),
                )?;
                let _ = finished_sender.send(());
                Ok(changed.map(|changed| assert!(changed)))
            })
            .await
        });

        started_receiver.await.unwrap();
        assert_eq!(db.runtime_available_permits(), 0);
        request.abort();
        assert_eq!(db.runtime_available_permits(), 0);
        release_sender.send(()).unwrap();
        finished_receiver.await.unwrap();
        let _ = request.await;

        assert_eq!(
            db.admin("admin").unwrap().unwrap().password_hash,
            "new-hash"
        );
        assert_eq!(db.count_audit(Some("admin_password_reset")).unwrap(), 1);
    }
}
