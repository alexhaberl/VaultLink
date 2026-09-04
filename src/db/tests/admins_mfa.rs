#[test]
fn initial_admin_creation_is_atomic() {
    let database = Database::open(":memory:").unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for username in ["first", "second"] {
        let database = database.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            database
                .create_initial_admin_and_audit(
                    username,
                    "hash",
                    "secret",
                    &AuditContext::new("setup", None),
                )
                .unwrap()
        }));
    }
    barrier.wait();
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == InitialAdminOutcome::Created)
            .count(),
        1
    );
    assert_eq!(database.admin_count().unwrap(), 1);
    assert_eq!(
        database.count_audit(Some("initial_admin_created")).unwrap(),
        1
    );
}
#[test]
fn initial_admin_creation_refuses_an_initialized_database() {
    let database = Database::open(":memory:").unwrap();
    database
        .create_admin("existing", "existing-hash", "existing-secret")
        .unwrap();

    assert_eq!(
        database
            .create_initial_admin("second", "second-hash", "second-secret")
            .unwrap(),
        InitialAdminOutcome::AlreadyInitialized
    );
    assert_eq!(database.admin_count().unwrap(), 1);
    assert!(database.admin("second").unwrap().is_none());
}

#[test]
fn audited_initial_admin_creation_rolls_back_when_audit_fails() {
    let database = Database::open(":memory:").unwrap();
    database
        .conn()
        .execute_batch(
            "CREATE TRIGGER fail_initial_admin_audit
                 BEFORE INSERT ON audit
                 WHEN NEW.action='initial_admin_created'
                 BEGIN SELECT RAISE(FAIL, 'injected audit failure'); END;",
        )
        .unwrap();
    let context = AuditContext::new("setup", None);

    let error = database
        .create_initial_admin_and_audit("admin", "hash", "secret", &context)
        .unwrap_err();
    assert!(is_audit_unavailable(&error));
    assert_eq!(database.admin_count().unwrap(), 0);
    assert_eq!(
        database.count_audit(Some("initial_admin_created")).unwrap(),
        0
    );

    database
        .conn()
        .execute_batch("DROP TRIGGER fail_initial_admin_audit")
        .unwrap();
    assert_eq!(
        database
            .create_initial_admin_and_audit("admin", "hash", "secret", &context)
            .unwrap(),
        InitialAdminOutcome::Created
    );
    let events = database
        .list_audit(Some("initial_admin_created"), 10, 0)
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor, "setup");
    assert!(events[0].client_ip.is_none());
}

#[test]
fn combined_admin_recovery_is_atomic_and_revokes_sessions() {
    let database = Database::open(":memory:").unwrap();
    database
        .create_admin("admin", "old-hash", "old-secret")
        .unwrap();
    database
        .create_session("session-token", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    database
        .start_admin_mfa_enrollment(1, "stale-enrollment", "stale-pending-secret")
        .unwrap();

    let outcome = database
        .recover_admin("ADMIN", Some("new-hash"), Some("new-secret"))
        .unwrap();
    assert_eq!(
        outcome,
        AdminRecoveryOutcome::Recovered {
            admin_id: 1,
            username: "admin".into(),
            active: true,
        }
    );
    let admin = database.admin("admin").unwrap().unwrap();
    assert_eq!(admin.password_hash, "new-hash");
    assert_eq!(admin.totp_secret.expose_secret(), "new-secret");
    assert!(database.session("session-token").unwrap().is_none());
    assert_eq!(
        database
            .activate_admin_mfa_enrollment(1, "stale-enrollment", 42, None)
            .unwrap(),
        AdminMfaEnrollmentActivationOutcome::NotFoundOrExpired
    );
    assert_eq!(
        database
            .admin("admin")
            .unwrap()
            .unwrap()
            .totp_secret
            .expose_secret(),
        "new-secret"
    );
    assert!(database.consume_admin_totp_step(1, 42).unwrap());
    assert!(!database.consume_admin_totp_step(1, 42).unwrap());
    let events = database.list_audit(Some("admin_recovered"), 10, 0).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor, "local_recovery");
    assert_eq!(
        events[0].detail.as_deref(),
        Some("reset_password=true;reset_mfa=true")
    );
    assert!(events[0].client_ip.is_none());
    let serialized_event = format!("{events:?}");
    assert!(!serialized_event.contains("new-hash"));
    assert!(!serialized_event.contains("new-secret"));
}

#[test]
fn combined_admin_recovery_rolls_back_all_changes_when_audit_fails() {
    let database = Database::open(":memory:").unwrap();
    database
        .create_admin("admin", "old-hash", "old-secret")
        .unwrap();
    database
        .create_session("session-token", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    database
        .start_admin_mfa_enrollment(1, "pending-token", "pending-secret")
        .unwrap();
    database
        .conn()
        .execute_batch(
            "CREATE TEMP TRIGGER fail_admin_recovery_audit
                 BEFORE INSERT ON audit
                 WHEN NEW.action='admin_recovered'
                 BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;",
        )
        .unwrap();

    assert!(database
        .recover_admin("admin", Some("new-hash"), Some("new-secret"))
        .is_err());
    let admin = database.admin("admin").unwrap().unwrap();
    assert_eq!(admin.password_hash, "old-hash");
    assert_eq!(admin.totp_secret.expose_secret(), "old-secret");
    assert!(database.session("session-token").unwrap().is_some());
    assert!(database
        .admin_mfa_enrollment(1, "pending-token")
        .unwrap()
        .is_some());
    assert_eq!(database.count_audit(Some("admin_recovered")).unwrap(), 0);
}

#[test]
fn admin_recovery_returns_not_found_without_side_effects() {
    let database = Database::open(":memory:").unwrap();

    assert_eq!(
        database
            .recover_admin("missing", Some("new-hash"), None)
            .unwrap(),
        AdminRecoveryOutcome::NotFound
    );
    assert_eq!(database.admin_count().unwrap(), 0);
    assert_eq!(database.count_audit(Some("admin_recovered")).unwrap(), 0);
}

#[test]
fn password_change_compare_and_swap_allows_only_one_racing_update() {
    let database = Database::open(":memory:").unwrap();
    database
        .create_admin("admin", "old-hash", "secret")
        .unwrap();
    database
        .create_session("session-token", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for new_hash in ["first-hash", "second-hash"] {
        let database = database.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            database
                .change_admin_password_cas(1, "old-hash", new_hash, Some("198.51.100.10"))
                .unwrap()
        }));
    }
    barrier.wait();
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == AdminPasswordChangeOutcome::Changed)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == AdminPasswordChangeOutcome::StalePassword)
            .count(),
        1
    );
    let admin = database.admin("admin").unwrap().unwrap();
    assert!(matches!(
        admin.password_hash.as_str(),
        "first-hash" | "second-hash"
    ));
    assert!(database.session("session-token").unwrap().is_none());
    assert_eq!(
        database
            .count_audit(Some("account_password_changed"))
            .unwrap(),
        1
    );
    assert_eq!(
        database
            .list_audit(Some("account_password_changed"), 10, 0)
            .unwrap()[0]
            .client_ip
            .as_deref(),
        Some("198.51.100.10")
    );
}

#[test]
fn audited_mfa_enrollment_start_consumes_totp_and_records_required_audit() {
    let database = Database::open(":memory:").unwrap();
    database
        .create_admin("admin", "hash", "old-secret")
        .unwrap();
    let context = AuditContext::new("admin", Some("198.51.100.20".into()));

    let outcome = database
        .start_admin_mfa_enrollment_and_audit(1, "enrollment-token", "new-secret", 42, &context)
        .unwrap();
    assert!(matches!(
        outcome,
        AuditedAdminMfaEnrollmentStartOutcome::Started { .. }
    ));
    assert!(!database.consume_admin_totp_step(1, 42).unwrap());
    assert_eq!(
        database
            .admin_mfa_enrollment(1, "enrollment-token")
            .unwrap()
            .unwrap()
            .totp_secret
            .expose_secret(),
        "new-secret"
    );
    let events = database
        .list_audit(Some("account_mfa_enrollment_started"), 10, 0)
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor, "admin");
    assert_eq!(events[0].object_id.as_deref(), Some("1"));
    assert_eq!(events[0].client_ip.as_deref(), Some("198.51.100.20"));
    assert!(!format!("{events:?}").contains("new-secret"));
}

#[test]
fn audited_mfa_enrollment_start_rolls_back_step_and_pending_secret_on_audit_failure() {
    let database = Database::open(":memory:").unwrap();
    database
        .create_admin("admin", "hash", "old-secret")
        .unwrap();
    database
        .start_admin_mfa_enrollment(1, "old-token", "old-pending-secret")
        .unwrap();
    database
        .conn()
        .execute_batch(
            "CREATE TRIGGER fail_mfa_enrollment_start_audit
                 BEFORE INSERT ON audit
                 WHEN NEW.action='account_mfa_enrollment_started'
                 BEGIN SELECT RAISE(FAIL, 'injected audit failure'); END;",
        )
        .unwrap();
    let context = AuditContext::new("admin", None);

    let error = database
        .start_admin_mfa_enrollment_and_audit(1, "new-token", "new-pending-secret", 43, &context)
        .unwrap_err();
    assert!(is_audit_unavailable(&error));
    assert!(database
        .admin_mfa_enrollment(1, "old-token")
        .unwrap()
        .is_some());
    assert!(database
        .admin_mfa_enrollment(1, "new-token")
        .unwrap()
        .is_none());
    assert!(database.consume_admin_totp_step(1, 43).unwrap());
    assert_eq!(
        database
            .count_audit(Some("account_mfa_enrollment_started"))
            .unwrap(),
        0
    );
}

#[test]
fn pending_mfa_enrollment_has_a_ttl_and_replaces_the_previous_token() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();

    let first = database
        .start_admin_mfa_enrollment(1, "first-token", "first-secret")
        .unwrap();
    let AdminMfaEnrollmentStartOutcome::Started { expires_at } = first else {
        panic!("known administrator must start an enrollment");
    };
    let expires_at = DateTime::parse_from_rfc3339(&expires_at).unwrap();
    let remaining = expires_at.signed_duration_since(Utc::now());
    assert!(remaining <= Duration::seconds(ADMIN_MFA_ENROLLMENT_TTL_SECONDS));
    assert!(remaining > Duration::seconds(ADMIN_MFA_ENROLLMENT_TTL_SECONDS - 5));
    assert_eq!(
        database
            .admin_mfa_enrollment(1, "first-token")
            .unwrap()
            .unwrap()
            .totp_secret
            .expose_secret(),
        "first-secret"
    );

    database
        .start_admin_mfa_enrollment(1, "second-token", "second-secret")
        .unwrap();
    assert!(database
        .admin_mfa_enrollment(1, "first-token")
        .unwrap()
        .is_none());
    assert_eq!(
        database
            .admin_mfa_enrollment(1, "second-token")
            .unwrap()
            .unwrap()
            .totp_secret
            .expose_secret(),
        "second-secret"
    );
    let stored_token_hash = database
        .conn()
        .query_row::<String, _, _>(
            "SELECT token_hash FROM admin_mfa_enrollments WHERE admin_id=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_token_hash, token_hash("second-token"));
    assert_ne!(stored_token_hash, "second-token");

    database
        .conn()
        .execute(
            "UPDATE admin_mfa_enrollments SET expires_at=?1 WHERE admin_id=1",
            [Utc::now()
                .checked_sub_signed(Duration::seconds(1))
                .unwrap()
                .to_rfc3339()],
        )
        .unwrap();
    assert_eq!(database.cleanup_expired_admin_mfa_enrollments().unwrap(), 1);
    assert!(database
        .admin_mfa_enrollment(1, "second-token")
        .unwrap()
        .is_none());
}

#[test]
fn pending_mfa_activation_is_single_use_and_revokes_sessions() {
    let database = Database::open(":memory:").unwrap();
    database
        .create_admin("admin", "hash", "old-secret")
        .unwrap();
    database
        .create_session("session-token", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    database
        .start_admin_mfa_enrollment(1, "enrollment-token", "new-secret")
        .unwrap();

    assert_eq!(
        database
            .activate_admin_mfa_enrollment(1, "enrollment-token", 42, Some("203.0.113.24"),)
            .unwrap(),
        AdminMfaEnrollmentActivationOutcome::Activated
    );
    assert_eq!(
        database
            .admin("admin")
            .unwrap()
            .unwrap()
            .totp_secret
            .expose_secret(),
        "new-secret"
    );
    assert!(database.session("session-token").unwrap().is_none());
    assert!(!database.consume_admin_totp_step(1, 42).unwrap());
    assert!(database.consume_admin_totp_step(1, 43).unwrap());
    assert!(database
        .admin_mfa_enrollment(1, "enrollment-token")
        .unwrap()
        .is_none());
    assert_eq!(
        database
            .activate_admin_mfa_enrollment(1, "enrollment-token", 42, None)
            .unwrap(),
        AdminMfaEnrollmentActivationOutcome::NotFoundOrExpired
    );
    let events = database
        .list_audit(Some("account_mfa_changed"), 10, 0)
        .unwrap();
    assert_eq!(events.len(), 1);
    assert!(events[0].detail.is_none());
    assert_eq!(events[0].client_ip.as_deref(), Some("203.0.113.24"));
    assert!(!format!("{events:?}").contains("new-secret"));
}

#[test]
fn deactivation_removes_pending_mfa_and_blocks_inactive_account_operations() {
    let database = Database::open(":memory:").unwrap();
    database
        .create_admin("one", "one-hash", "one-secret")
        .unwrap();
    database
        .create_admin("two", "two-hash", "two-secret")
        .unwrap();
    database
        .start_admin_mfa_enrollment(1, "pending-token", "pending-secret")
        .unwrap();

    assert_eq!(
        database.deactivate_admin(1).unwrap(),
        AdminDeactivationOutcome::Deactivated
    );
    assert_eq!(
        database
            .conn()
            .query_row::<i64, _, _>(
                "SELECT COUNT(*) FROM admin_mfa_enrollments WHERE admin_id=1",
                [],
                |row| row.get(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        database
            .start_admin_mfa_enrollment(1, "new-token", "new-secret")
            .unwrap(),
        AdminMfaEnrollmentStartOutcome::AdminInactive
    );
    assert_eq!(
        database
            .change_admin_password_cas(1, "one-hash", "new-hash", None)
            .unwrap(),
        AdminPasswordChangeOutcome::Inactive
    );

    database
        .conn()
        .execute(
            "INSERT INTO admin_mfa_enrollments(
                    admin_id,token_hash,totp_key_id,totp_ciphertext,created_at,expires_at
                 ) VALUES(1,?1,1,X'00',?2,?3)",
            params![
                token_hash("injected-token"),
                Utc::now().to_rfc3339(),
                (Utc::now() + Duration::minutes(5)).to_rfc3339()
            ],
        )
        .unwrap();
    assert!(database
        .admin_mfa_enrollment(1, "injected-token")
        .unwrap()
        .is_none());
    assert_eq!(
        database
            .activate_admin_mfa_enrollment(1, "injected-token", 42, None)
            .unwrap(),
        AdminMfaEnrollmentActivationOutcome::NotFoundOrExpired
    );
    let inactive = database
        .conn()
        .query_row::<(String, u64), _, _>(
            "SELECT password_hash,totp_generation FROM admins WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(inactive, ("one-hash".into(), 1));
}

#[test]
fn concurrent_admin_deactivation_preserves_one_active_admin() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("one", "hash", "secret").unwrap();
    database.create_admin("two", "hash", "secret").unwrap();
    database
        .create_session("one-session", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    database
        .create_session("two-session", 2, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let first = {
        let database = database.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            database.deactivate_admin(2).unwrap()
        })
    };
    let second = {
        let database = database.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            database.deactivate_admin(1).unwrap()
        })
    };
    barrier.wait();
    let outcomes = [first.join().unwrap(), second.join().unwrap()];
    assert!(outcomes.contains(&AdminDeactivationOutcome::Deactivated));
    assert!(outcomes.contains(&AdminDeactivationOutcome::LastActive));
    assert_eq!(database.active_admin_count().unwrap(), 1);
    assert_eq!(
        database
            .conn()
            .query_row::<i64, _, _>("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
            .unwrap(),
        1
    );
}

#[test]
fn runtime_settings_replacement_rolls_back_as_one_snapshot() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let original = [
        ("max_upload_size", "10".to_string()),
        ("max_zip_size", "20".to_string()),
    ];
    database.replace_runtime_settings(&original, 1).unwrap();
    database
        .conn()
        .execute_batch(
            "CREATE TEMP TRIGGER fail_runtime_replace
                 BEFORE INSERT ON runtime_settings
                 WHEN NEW.key='max_zip_size'
                 BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
    let replacement = [
        ("max_upload_size", "100".to_string()),
        ("max_zip_size", "200".to_string()),
    ];
    assert!(database.replace_runtime_settings(&replacement, 1).is_err());
    assert_eq!(
        database.runtime_settings().unwrap(),
        vec![
            ("max_upload_size".to_string(), "10".to_string()),
            ("max_zip_size".to_string(), "20".to_string()),
        ]
    );
}
