use super::*;

fn test_service_token(seed: u8) -> String {
    format!(
        "{SERVICE_TOKEN_PREFIX}{}",
        URL_SAFE_NO_PAD.encode([seed; SERVICE_TOKEN_RANDOM_BYTES])
    )
}

fn authenticated_database() -> Database {
    let database = Database::open(":memory:").unwrap();
    database
        .create_admin("admin", "password-hash", "secret")
        .unwrap();
    database
        .create_session("admin-session", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    assert!(database.verify_mfa("admin-session").unwrap());
    database
}

fn admin_proof() -> MfaSessionProof {
    MfaSessionProof::for_test("admin-session", 1)
}

fn authorized<T>(outcome: SessionBound<Audited<T>>) -> T {
    match outcome {
        SessionBound::Authorized(value) => value.into_legacy_inner(),
        SessionBound::SessionUnavailable => panic!("test MFA session was unavailable"),
    }
}

fn create_token(database: &Database, name: &str, seed: u8) -> (String, ServiceToken) {
    let plaintext = test_service_token(seed);
    let context = AuditContext::new("admin", None);
    let outcome = authorized(
        database
            .create_service_token_for_mfa_session(
                &admin_proof(),
                "password-hash",
                name,
                &plaintext,
                Some(Utc::now() + Duration::days(1)),
                &context,
            )
            .unwrap(),
    );
    let ServiceTokenCreationOutcome::Created(token) = outcome else {
        panic!("service token was not created")
    };
    (plaintext, token)
}

#[test]
fn service_tokens_store_only_hash_and_touch_at_most_every_five_minutes() {
    let database = authenticated_database();
    let (plaintext, token) = create_token(&database, "Home Assistant", 7);
    let stored: (String, Option<String>) = database
        .conn()
        .query_row(
            "SELECT token_hash,last_used_at FROM service_tokens WHERE id=?1",
            [token.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(stored.0, token_hash(&plaintext));
    assert!(!stored.0.contains(&plaintext));
    assert!(stored.1.is_none());

    let first = Utc::now();
    assert_eq!(
        database
            .authorize_service_token_at(
                &plaintext,
                super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
                first,
            )
            .unwrap(),
        ServiceTokenAuthorizationOutcome::Authorized { token_id: token.id }
    );
    let first_touch: String = database
        .conn()
        .query_row(
            "SELECT last_used_at FROM service_tokens WHERE id=?1",
            [token.id],
            |row| row.get(0),
        )
        .unwrap();
    database
        .authorize_service_token_at(
            &plaintext,
            super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
            first + Duration::minutes(4),
        )
        .unwrap();
    let throttled_touch: String = database
        .conn()
        .query_row(
            "SELECT last_used_at FROM service_tokens WHERE id=?1",
            [token.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(throttled_touch, first_touch);
    database
        .authorize_service_token_at(
            &plaintext,
            super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
            first + Duration::minutes(5),
        )
        .unwrap();
    let refreshed_touch: String = database
        .conn()
        .query_row(
            "SELECT last_used_at FROM service_tokens WHERE id=?1",
            [token.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_ne!(refreshed_touch, first_touch);
}

#[test]
fn service_token_create_rechecks_live_mfa_session_password_and_capacity() {
    let database = authenticated_database();
    let context = AuditContext::new("admin", None);
    let rejected = authorized(
        database
            .create_service_token_for_mfa_session(
                &admin_proof(),
                "stale-hash",
                "Rejected",
                &test_service_token(1),
                None,
                &context,
            )
            .unwrap(),
    );
    assert_eq!(
        rejected,
        ServiceTokenCreationOutcome::ReauthenticationRejected
    );

    for index in 0..MAX_SERVICE_TOKENS {
        create_token(&database, &format!("token-{index}"), index as u8);
    }
    let capacity = authorized(
        database
            .create_service_token_for_mfa_session(
                &admin_proof(),
                "password-hash",
                "one-too-many",
                &test_service_token(255),
                None,
                &context,
            )
            .unwrap(),
    );
    assert_eq!(capacity, ServiceTokenCreationOutcome::CapacityReached);
    let direct_insert = database.conn().execute(
        "INSERT INTO service_tokens(
             name,token_hash,scope_mask,created_by,created_at
         ) VALUES('direct-overflow',?1,1,1,?2)",
        params![
            token_hash(&test_service_token(255)),
            Utc::now().to_rfc3339()
        ],
    );
    assert!(direct_insert.is_err());
}

#[test]
fn service_token_mutations_distinguish_session_revocation_from_domain_outcomes() {
    let database = authenticated_database();
    let (_, existing) = create_token(&database, "Existing", 2);
    let created_audits = database.count_audit(Some("service_token_created")).unwrap();
    let proof = admin_proof();
    database.delete_session("admin-session").unwrap();

    let create = database
        .create_service_token_for_mfa_session(
            &proof,
            "password-hash",
            "Blocked",
            &test_service_token(3),
            None,
            &AuditContext::new("admin", None),
        )
        .unwrap();
    assert_eq!(create, SessionBound::SessionUnavailable);
    assert_eq!(database.list_service_tokens().unwrap().len(), 1);
    assert_eq!(
        database.count_audit(Some("service_token_created")).unwrap(),
        created_audits
    );

    let revoke = database
        .revoke_service_token_for_mfa_session(
            &proof,
            existing.id,
            &AuditContext::new("admin", None),
        )
        .unwrap();
    assert_eq!(revoke, SessionBound::SessionUnavailable);
    assert_eq!(database.list_service_tokens().unwrap().len(), 1);
    assert_eq!(
        database.count_audit(Some("service_token_revoked")).unwrap(),
        0
    );
}

#[test]
fn service_token_expiration_must_be_strictly_in_the_future() {
    let database = authenticated_database();
    let context = AuditContext::new("admin", None);
    for (index, expires_at) in [Utc::now() - Duration::seconds(1), Utc::now()]
        .into_iter()
        .enumerate()
    {
        let result = database.create_service_token_for_mfa_session(
            &admin_proof(),
            "password-hash",
            &format!("invalid-expiry-{index}"),
            &test_service_token(index as u8 + 40),
            Some(expires_at),
            &context,
        );
        assert!(matches!(result, Err(rusqlite::Error::InvalidQuery)));
    }
    assert!(database.list_service_tokens().unwrap().is_empty());
    assert_eq!(
        database.count_audit(Some("service_token_created")).unwrap(),
        0
    );

    let future = Utc::now() + Duration::days(1);
    let future_string = future.to_rfc3339();
    let outcome = authorized(
        database
            .create_service_token_for_mfa_session(
                &admin_proof(),
                "password-hash",
                "future-expiry",
                &test_service_token(42),
                Some(future),
                &context,
            )
            .unwrap(),
    );
    let ServiceTokenCreationOutcome::Created(created) = outcome else {
        panic!("future service-token expiration was rejected")
    };
    assert_eq!(created.expires_at.as_deref(), Some(future_string.as_str()));
}

#[test]
fn service_token_names_are_canonical_and_case_insensitively_unique() {
    assert!(super::super::valid_service_token_name("Home Assistant"));
    for invalid in ["", " padded", "padded ", "line\nbreak"] {
        assert!(!super::super::valid_service_token_name(invalid));
    }
    assert!(!super::super::valid_service_token_name(
        &"x".repeat(super::super::SERVICE_TOKEN_NAME_MAX_CHARACTERS + 1)
    ));

    let database = authenticated_database();
    create_token(&database, "Home Assistant", 20);
    let outcome = authorized(
        database
            .create_service_token_for_mfa_session(
                &admin_proof(),
                "password-hash",
                "home assistant",
                &test_service_token(21),
                None,
                &AuditContext::new("admin", None),
            )
            .unwrap(),
    );
    assert_eq!(outcome, ServiceTokenCreationOutcome::NameConflict);
    assert_eq!(database.list_service_tokens().unwrap().len(), 1);
}

#[test]
fn unknown_expired_and_insufficient_scope_tokens_are_indistinguishable_or_scoped() {
    let database = authenticated_database();
    let (plaintext, token) = create_token(&database, "Authorization", 30);
    assert_eq!(
        database
            .authorize_service_token(
                &test_service_token(31),
                super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
            )
            .unwrap(),
        ServiceTokenAuthorizationOutcome::Unauthorized
    );
    assert_eq!(
        database.authorize_service_token(&plaintext, 2).unwrap(),
        ServiceTokenAuthorizationOutcome::InsufficientScope
    );
    database
        .conn()
        .execute(
            "UPDATE service_tokens SET expires_at=?2 WHERE id=?1",
            params![token.id, (Utc::now() - Duration::minutes(1)).to_rfc3339()],
        )
        .unwrap();
    assert_eq!(
        database
            .authorize_service_token(
                &plaintext,
                super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
            )
            .unwrap(),
        ServiceTokenAuthorizationOutcome::Unauthorized
    );
}

#[test]
fn create_and_revoke_all_roll_back_when_required_audit_is_unavailable() {
    let database = authenticated_database();
    database
        .conn()
        .execute_batch(
            "CREATE TRIGGER fail_service_token_required_audit
             BEFORE INSERT ON audit
             WHEN NEW.action IN ('service_token_created','service_tokens_revoked_all')
             BEGIN
                 SELECT RAISE(FAIL, 'injected audit failure');
             END;",
        )
        .unwrap();
    let context = AuditContext::new("admin", None);
    let create_error = database
        .create_service_token_for_mfa_session(
            &admin_proof(),
            "password-hash",
            "Rolled Back",
            &test_service_token(40),
            None,
            &context,
        )
        .unwrap_err();
    assert!(super::super::is_audit_unavailable(&create_error));
    assert!(database.list_service_tokens().unwrap().is_empty());

    database
        .conn()
        .execute_batch("DROP TRIGGER fail_service_token_required_audit")
        .unwrap();
    create_token(&database, "Preserved", 41);
    database
        .conn()
        .execute_batch(
            "CREATE TRIGGER fail_service_token_required_audit
             BEFORE INSERT ON audit
             WHEN NEW.action='service_tokens_revoked_all'
             BEGIN
                 SELECT RAISE(FAIL, 'injected audit failure');
             END;",
        )
        .unwrap();
    let revoke_error = database
        .revoke_all_service_tokens_and_audit(&AuditContext::new("local_recovery", None))
        .unwrap_err();
    assert!(super::super::is_audit_unavailable(&revoke_error));
    assert_eq!(database.list_service_tokens().unwrap().len(), 1);
}

#[test]
fn revoked_ids_are_not_reused_and_revoke_all_is_audited_even_when_empty() {
    let database = authenticated_database();
    let (_, first) = create_token(&database, "First", 50);
    let context = AuditContext::new("admin", None);
    assert!(authorized(
        database
            .revoke_service_token_for_mfa_session(&admin_proof(), first.id, &context)
            .unwrap()
    ));
    assert!(!authorized(
        database
            .revoke_service_token_for_mfa_session(&admin_proof(), first.id, &context)
            .unwrap()
    ));
    let (_, second) = create_token(&database, "Second", 51);
    assert!(second.id > first.id);
    assert_eq!(
        database
            .revoke_all_service_tokens_and_audit(&AuditContext::new("local_recovery", None))
            .unwrap(),
        1
    );
    assert_eq!(
        database
            .revoke_all_service_tokens_and_audit(&AuditContext::new("local_recovery", None))
            .unwrap(),
        0
    );
    assert_eq!(
        database
            .count_audit(Some("service_tokens_revoked_all"))
            .unwrap(),
        2
    );
}

#[test]
fn revocation_and_required_audit_are_atomic() {
    let database = authenticated_database();
    let (plaintext, token) = create_token(&database, "Revocable", 11);
    database
        .conn()
        .execute_batch(
            "CREATE TRIGGER fail_service_token_audit
             BEFORE INSERT ON audit
             WHEN NEW.action IN ('service_token_revoked','service_tokens_revoked_all')
             BEGIN
                 SELECT RAISE(FAIL, 'injected audit failure');
             END;",
        )
        .unwrap();
    let context = AuditContext::new("admin", None);
    let error = database
        .revoke_service_token_for_mfa_session(&admin_proof(), token.id, &context)
        .unwrap_err();
    assert!(super::super::is_audit_unavailable(&error));
    assert_eq!(database.list_service_tokens().unwrap().len(), 1);
    assert_eq!(
        database
            .authorize_service_token(
                &plaintext,
                super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
            )
            .unwrap(),
        ServiceTokenAuthorizationOutcome::Authorized { token_id: token.id }
    );
}

struct MonitoringFixture {
    database: Database,
    now: chrono::DateTime<Utc>,
    available: i64,
    inactive: i64,
    expired: i64,
    limited: i64,
}

fn monitoring_fixture() -> MonitoringFixture {
    let database = authenticated_database();
    let now = Utc::now();
    let available = database
        .create_share_with_upload_limits(
            "available-share-secret",
            Some("private-alias"),
            "private/path",
            true,
            &Permission::DownloadUpload,
            None,
            Some(10),
            Some(100),
            Some(1_000),
            Some(10),
            1,
            Some("private-password-hash"),
            &super::super::UploadConflictStrategy::Reject,
        )
        .unwrap();
    let inactive = database
        .create_share(
            "inactive-share-secret",
            None,
            "inactive/path",
            false,
            &Permission::DownloadOnly,
            Some(now - Duration::days(1)),
            Some(1),
            None,
            1,
            None,
            &super::super::UploadConflictStrategy::Reject,
        )
        .unwrap();
    let expired = database
        .create_share(
            "expired-share-secret",
            None,
            "expired/path",
            false,
            &Permission::DownloadOnly,
            Some(now - Duration::days(1)),
            None,
            None,
            1,
            None,
            &super::super::UploadConflictStrategy::Reject,
        )
        .unwrap();
    let limited = database
        .create_share(
            "limited-share-secret",
            None,
            "limited/path",
            false,
            &Permission::DownloadOnly,
            None,
            Some(2),
            None,
            1,
            None,
            &super::super::UploadConflictStrategy::Reject,
        )
        .unwrap();
    database
        .conn()
        .execute("UPDATE shares SET active=0 WHERE id=?1", [inactive])
        .unwrap();
    database
        .conn()
        .execute("UPDATE shares SET download_count=2 WHERE id=?1", [limited])
        .unwrap();
    database
        .conn()
        .execute(
            "INSERT INTO public_upload_usage(share_id,uploaded_bytes,uploaded_files)
             VALUES(?1,250,3)",
            [available],
        )
        .unwrap();
    database
        .conn()
        .execute(
            "INSERT INTO transfer_monthly_counts(month,action,count)
             VALUES(?1,'download',42),
                   (?1,'zip_download',3),
                   (?1,'preview',11)",
            [now.format("%Y-%m").to_string()],
        )
        .unwrap();

    MonitoringFixture {
        database,
        now,
        available,
        inactive,
        expired,
        limited,
    }
}

fn assert_monitoring_summary(fixture: &MonitoringFixture) {
    let summary = fixture.database.monitoring_summary(fixture.now).unwrap();
    assert_eq!(summary.total, 4);
    assert_eq!(summary.available, 1);
    assert_eq!(summary.inactive, 1);
    assert_eq!(summary.expired, 1);
    assert_eq!(summary.download_limit_reached, 1);
    assert_eq!(summary.protected, 1);
    assert_eq!(summary.transfers.download, 42);
    assert_eq!(summary.transfers.zip_download, 3);
    assert_eq!(summary.transfers.preview, 11);
}

fn assert_monitoring_pagination(fixture: &MonitoringFixture) {
    let all = fixture
        .database
        .list_monitoring_share_page(&MonitoringShareListOptions {
            status: super::super::MonitoringShareListStatus::All,
            cursor: None,
            limit: 3,
            now: fixture.now,
        })
        .unwrap();
    assert_eq!(all.shares.len(), 3);
    assert_eq!(all.next_cursor, all.shares.last().map(|share| share.id));
    assert_eq!(all.shares[0].id, fixture.limited);
    assert_eq!(
        all.shares[0].status,
        MonitoringShareStatus::DownloadLimitReached
    );
    let second = fixture
        .database
        .list_monitoring_share_page(&MonitoringShareListOptions {
            status: super::super::MonitoringShareListStatus::All,
            cursor: all.next_cursor,
            limit: 3,
            now: fixture.now,
        })
        .unwrap();
    assert_eq!(second.shares.len(), 1);
    assert_eq!(second.shares[0].id, fixture.available);
    assert!(second.shares[0].password_protected);
    assert_eq!(second.shares[0].uploaded_bytes, 250);
    assert_eq!(second.shares[0].uploaded_files, 3);
}

fn assert_monitoring_status_filters(fixture: &MonitoringFixture) {
    let inactive_page = fixture
        .database
        .list_monitoring_share_page(&MonitoringShareListOptions {
            status: super::super::MonitoringShareListStatus::Inactive,
            cursor: None,
            limit: 50,
            now: fixture.now,
        })
        .unwrap();
    assert_eq!(inactive_page.shares.len(), 1);
    assert_eq!(inactive_page.shares[0].id, fixture.inactive);
    assert_eq!(
        inactive_page.shares[0].status,
        MonitoringShareStatus::Inactive
    );
    assert_ne!(inactive_page.shares[0].id, fixture.expired);

    for (status, expected_id, expected_status) in [
        (
            super::super::MonitoringShareListStatus::Available,
            fixture.available,
            MonitoringShareStatus::Available,
        ),
        (
            super::super::MonitoringShareListStatus::Expired,
            fixture.expired,
            MonitoringShareStatus::Expired,
        ),
        (
            super::super::MonitoringShareListStatus::DownloadLimitReached,
            fixture.limited,
            MonitoringShareStatus::DownloadLimitReached,
        ),
    ] {
        let page = fixture
            .database
            .list_monitoring_share_page(&MonitoringShareListOptions {
                status,
                cursor: None,
                limit: 50,
                now: fixture.now,
            })
            .unwrap();
        assert_eq!(page.shares.len(), 1, "{status:?}");
        assert_eq!(page.shares[0].id, expected_id, "{status:?}");
        assert_eq!(page.shares[0].status, expected_status, "{status:?}");
    }
}

#[test]
fn monitoring_queries_apply_status_priority_and_return_only_redacted_fields() {
    let fixture = monitoring_fixture();
    assert_monitoring_summary(&fixture);
    assert_monitoring_pagination(&fixture);
    assert_monitoring_status_filters(&fixture);
}

#[test]
fn service_tokens_are_instance_wide_across_creator_account_changes() {
    let database = authenticated_database();
    database
        .create_admin("second-admin", "second-password-hash", "second-secret")
        .unwrap();
    let (plaintext, token) = create_token(&database, "Instance-wide", 60);

    assert_eq!(
        database.deactivate_admin(1).unwrap(),
        super::super::AdminDeactivationOutcome::Deactivated
    );
    assert_eq!(
        database
            .authorize_service_token(
                &plaintext,
                super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
            )
            .unwrap(),
        ServiceTokenAuthorizationOutcome::Authorized { token_id: token.id }
    );

    assert!(database
        .reset_admin_password(1, "replacement-password-hash")
        .unwrap());
    assert_eq!(
        database
            .authorize_service_token(
                &plaintext,
                super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
            )
            .unwrap(),
        ServiceTokenAuthorizationOutcome::Authorized { token_id: token.id }
    );

    assert_eq!(
        database.reset_admin_totp(1, "replacement-secret").unwrap(),
        Some("admin".to_string())
    );
    assert_eq!(
        database
            .authorize_service_token(
                &plaintext,
                super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
            )
            .unwrap(),
        ServiceTokenAuthorizationOutcome::Authorized { token_id: token.id }
    );
    let listed = database.list_service_tokens().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, token.id);
    assert_eq!(listed[0].name, token.name);
}

#[test]
fn authorized_monitoring_read_may_finish_across_revoke_without_resurrecting_token() {
    let directory = tempfile::tempdir().unwrap();
    let database = Database::open(directory.path().join("data.sqlite")).unwrap();
    database
        .create_admin("admin", "password-hash", "secret")
        .unwrap();
    database
        .create_session("admin-session", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    assert!(database.verify_mfa("admin-session").unwrap());
    let (plaintext, token) = create_token(&database, "Race", 70);

    let (lookup_sender, lookup_receiver) = std::sync::mpsc::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::channel();
    let authorizing_database = database.clone();
    let authorizing_plaintext = plaintext.clone();
    let request = std::thread::spawn(move || -> rusqlite::Result<_> {
        let authorization = authorizing_database.authorize_service_token_at_after_lookup(
            &authorizing_plaintext,
            super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
            Utc::now(),
            || {
                lookup_sender.send(()).unwrap();
                release_receiver.recv().unwrap();
            },
        )?;
        // This models the rest of the already-authorized monitoring
        // handler. Revocation removes future authority, not an in-flight
        // read that has already crossed the authorization boundary.
        let summary = authorizing_database.monitoring_summary(Utc::now())?;
        Ok((authorization, summary))
    });
    lookup_receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();

    assert!(authorized(
        database
            .revoke_service_token_for_mfa_session(
                &admin_proof(),
                token.id,
                &AuditContext::new("admin", Some("192.0.2.1".into())),
            )
            .unwrap()
    ));
    release_sender.send(()).unwrap();
    let (authorization, summary) = request.join().unwrap().unwrap();
    assert_eq!(
        authorization,
        ServiceTokenAuthorizationOutcome::Authorized { token_id: token.id }
    );
    assert_eq!(summary.total, 0);
    assert_eq!(
        database
            .conn()
            .query_row::<i64, _, _>(
                "SELECT COUNT(*) FROM service_tokens WHERE id=?1",
                [token.id],
                |row| row.get(0),
            )
            .unwrap(),
        0
    );
    for _ in 0..3 {
        assert_eq!(
            database
                .authorize_service_token(
                    &plaintext,
                    super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
                )
                .unwrap(),
            ServiceTokenAuthorizationOutcome::Unauthorized
        );
    }
}

#[test]
fn service_token_audit_fields_never_contain_plaintext_or_hash() {
    let database = authenticated_database();
    let (first_plaintext, first) = create_token(&database, "Audit first", 80);
    let first_hash = token_hash(&first_plaintext);
    // A token-shaped value is a valid 1-80 character name. Audit details
    // must therefore never mirror administrator-supplied token names.
    let (second_plaintext, second) = create_token(&database, &first_plaintext, 81);
    let second_hash = token_hash(&second_plaintext);
    assert!(authorized(
        database
            .revoke_service_token_for_mfa_session(
                &admin_proof(),
                second.id,
                &AuditContext::new("admin", None),
            )
            .unwrap()
    ));
    assert_eq!(
        database
            .revoke_all_service_tokens_and_audit(&AuditContext::new("local_recovery", None))
            .unwrap(),
        1
    );

    let events = database.list_audit(None, 100, 0).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.action.starts_with("service_token"))
            .count(),
        4
    );
    for event in events
        .into_iter()
        .filter(|event| event.action.starts_with("service_token"))
    {
        match event.action.as_str() {
            "service_token_created" => {
                assert_eq!(event.detail.as_deref(), Some("scope=monitoring:read"));
            }
            "service_token_revoked" => assert!(event.detail.is_none()),
            "service_tokens_revoked_all" => {
                assert_eq!(event.detail.as_deref(), Some("count=1"));
            }
            action => panic!("unexpected service-token audit action: {action}"),
        }
        let persisted = [
            Some(event.occurred_at.as_str()),
            Some(event.actor.as_str()),
            Some(event.action.as_str()),
            event.object_id.as_deref(),
            event.detail.as_deref(),
            event.client_ip.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n");
        for forbidden in [
            first_plaintext.as_str(),
            first_hash.as_str(),
            second_plaintext.as_str(),
            second_hash.as_str(),
        ] {
            assert!(!persisted.contains(forbidden));
        }
        assert!(!persisted.contains("token_hash"));
    }
    assert_ne!(first.id, second.id);
}
