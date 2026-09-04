#[test]
fn session_mfa_and_logout_lifecycle() {
    let d = Database::open(":memory:").unwrap();
    d.create_admin("admin", "hash", "secret").unwrap();
    d.create_session(
        "session-token",
        1,
        "csrf",
        Utc::now() + chrono::Duration::hours(1),
    )
    .unwrap();
    let session = d.session("session-token").unwrap().unwrap();
    assert!(!session.mfa_verified);
    assert_eq!(session.csrf_token, "csrf");
    assert!(d.verify_mfa("session-token").unwrap());
    assert!(d.session("session-token").unwrap().unwrap().mfa_verified);
    d.delete_session("session-token").unwrap();
    assert!(d.session("session-token").unwrap().is_none());
}

#[test]
fn admin_session_idle_boundary_touch_coalescing_and_absolute_cap() {
    let database = Database::open(":memory:").unwrap();
    database.configure_session_idle_timeout(30);
    database
        .create_admin("admin", "password-hash", "JBSWY3DPEHPK3PXP")
        .unwrap();
    let base = DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    database
        .create_session("idle-session", 1, "csrf", base + Duration::hours(12))
        .unwrap();
    database
        .conn()
        .execute(
            "UPDATE sessions SET last_activity_at=?2 WHERE token_hash=?1",
            params![token_hash("idle-session"), base.to_rfc3339()],
        )
        .unwrap();

    assert!(database
        .session_at_for_test("idle-session", base + Duration::seconds(30))
        .unwrap()
        .is_some());
    let unchanged: String = database
        .conn()
        .query_row(
            "SELECT last_activity_at FROM sessions WHERE token_hash=?1",
            [token_hash("idle-session")],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(unchanged, base.to_rfc3339());

    assert!(database
        .session_at_for_test("idle-session", base + Duration::seconds(61))
        .unwrap()
        .is_some());
    let touched: String = database
        .conn()
        .query_row(
            "SELECT last_activity_at FROM sessions WHERE token_hash=?1",
            [token_hash("idle-session")],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(touched, (base + Duration::seconds(61)).to_rfc3339());

    database
        .conn()
        .execute(
            "UPDATE sessions SET last_activity_at=?2,expires_at=?3 WHERE token_hash=?1",
            params![
                token_hash("idle-session"),
                base.to_rfc3339(),
                (base + Duration::hours(1)).to_rfc3339(),
            ],
        )
        .unwrap();
    assert!(database
        .session_at_for_test("idle-session", base + Duration::minutes(30))
        .unwrap()
        .is_none());

    database
        .create_session("absolute-session", 1, "csrf", base + Duration::minutes(10))
        .unwrap();
    database
        .conn()
        .execute(
            "UPDATE sessions SET last_activity_at=?2 WHERE token_hash=?1",
            params![token_hash("absolute-session"), base.to_rfc3339()],
        )
        .unwrap();
    assert!(database
        .session_at_for_test("absolute-session", base + Duration::minutes(9))
        .unwrap()
        .is_some());
    assert!(database
        .session_at_for_test("absolute-session", base + Duration::minutes(10))
        .unwrap()
        .is_none());
}

#[test]
fn fresh_session_read_does_not_require_a_write_capable_connection() {
    let database = Database::open(":memory:").unwrap();
    database.configure_session_idle_timeout(30);
    database
        .create_admin("admin", "password-hash", "JBSWY3DPEHPK3PXP")
        .unwrap();
    let base = DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    database
        .create_session("read-only-session", 1, "csrf", base + Duration::hours(12))
        .unwrap();
    let connection = database.conn();
    connection
        .execute(
            "UPDATE sessions SET last_activity_at=?2 WHERE token_hash=?1",
            params![token_hash("read-only-session"), base.to_rfc3339()],
        )
        .unwrap();
    connection.pragma_update(None, "query_only", "ON").unwrap();
    drop(connection);

    assert!(database
        .session_at_for_test("read-only-session", base + Duration::seconds(30))
        .unwrap()
        .is_some());
    assert!(database
        .session_at_for_test("read-only-session", base + Duration::seconds(61))
        .is_err());
}

#[test]
fn concurrent_admin_session_checks_coalesce_activity_without_errors() {
    let database = Database::open(":memory:").unwrap();
    database.configure_session_idle_timeout(30);
    database
        .create_admin("admin", "password-hash", "JBSWY3DPEHPK3PXP")
        .unwrap();
    let base = DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let touch_at = base + Duration::seconds(61);
    database
        .create_session("parallel-session", 1, "csrf", base + Duration::hours(12))
        .unwrap();
    database
        .conn()
        .execute(
            "UPDATE sessions SET last_activity_at=?2 WHERE token_hash=?1",
            params![token_hash("parallel-session"), base.to_rfc3339()],
        )
        .unwrap();

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(9));
    let workers = (0..8)
        .map(|_| {
            let database = database.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                database.session_at_for_test("parallel-session", touch_at)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    for worker in workers {
        assert!(worker.join().unwrap().unwrap().is_some());
    }

    let activity: String = database
        .conn()
        .query_row(
            "SELECT last_activity_at FROM sessions WHERE token_hash=?1",
            [token_hash("parallel-session")],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(activity, touch_at.to_rfc3339());
}

#[test]
fn mfa_rotation_refreshes_activity_without_extending_absolute_expiry() {
    let database = Database::open(":memory:").unwrap();
    database
        .create_admin("admin", "password-hash", "JBSWY3DPEHPK3PXP")
        .unwrap();
    let expires = Utc::now() + Duration::hours(3);
    let old_activity = Utc::now() - Duration::minutes(10);
    database
        .create_session("pre-mfa", 1, "csrf", expires)
        .unwrap();
    database
        .conn()
        .execute(
            "UPDATE sessions SET last_activity_at=?2 WHERE token_hash=?1",
            params![token_hash("pre-mfa"), old_activity.to_rfc3339()],
        )
        .unwrap();

    assert!(database
        .verify_mfa_with_totp_step("pre-mfa", "verified", "new-csrf", 1, 42)
        .unwrap());
    let (stored_expiry, activity): (String, String) = database
        .conn()
        .query_row(
            "SELECT expires_at,last_activity_at FROM sessions WHERE token_hash=?1",
            [token_hash("verified")],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(stored_expiry, expires.to_rfc3339());
    assert!(
        DateTime::parse_from_rfc3339(&activity).unwrap()
            > DateTime::parse_from_rfc3339(&old_activity.to_rfc3339()).unwrap()
    );
}

#[test]
fn session_creation_cleans_idle_rows() {
    let database = Database::open(":memory:").unwrap();
    database
        .create_admin("admin", "password-hash", "JBSWY3DPEHPK3PXP")
        .unwrap();
    database
        .create_session("idle", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    database
        .conn()
        .execute(
            "UPDATE sessions SET last_activity_at=?2 WHERE token_hash=?1",
            params![
                token_hash("idle"),
                (Utc::now() - Duration::minutes(31)).to_rfc3339()
            ],
        )
        .unwrap();
    database
        .create_session("fresh", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();

    assert!(database.session("idle").unwrap().is_none());
    assert!(database.session("fresh").unwrap().is_some());
}

#[test]
fn totp_step_is_consumed_once_across_racing_sessions() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    for token in ["first-session", "second-session"] {
        database
            .create_session(token, 1, "csrf", Utc::now() + Duration::hours(1))
            .unwrap();
    }

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let workers = ["first-session", "second-session"].map(|token| {
        let database = database.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            let rotated = format!("{token}-rotated");
            let accepted = database
                .verify_mfa_with_totp_step(token, &rotated, "rotated-csrf", 1, 42)
                .unwrap();
            (token, rotated, accepted)
        })
    });
    barrier.wait();
    let outcomes = workers.map(|worker| worker.join().unwrap());
    assert_eq!(
        outcomes.iter().filter(|(_, _, accepted)| *accepted).count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(
                |(_, rotated, _)| database.session(rotated).unwrap().is_some_and(|session| {
                    session.mfa_verified && session.csrf_token == "rotated-csrf"
                })
            )
            .count(),
        1
    );
    assert!(outcomes
        .iter()
        .all(|(old, _, accepted)| { !accepted || database.session(old).unwrap().is_none() }));

    let pending_token = outcomes
        .iter()
        .find(|(_, _, accepted)| !accepted)
        .map(|(old, _, _)| *old)
        .unwrap();
    assert!(!database
        .verify_mfa_with_totp_step(pending_token, "retry-1", "csrf-1", 1, 42)
        .unwrap());
    assert!(database
        .verify_mfa_with_totp_step(pending_token, "retry-2", "csrf-2", 1, 43)
        .unwrap());
    assert!(database.session(pending_token).unwrap().is_none());
    assert_eq!(
        database.session("retry-2").unwrap().unwrap().csrf_token,
        "csrf-2"
    );
}

#[test]
fn verified_password_session_creation_rejects_a_stale_hash_without_a_zombie_session() {
    let database = Database::open(":memory:").unwrap();
    database
        .create_admin("admin", "verified-hash", "secret")
        .unwrap();
    database.reset_admin_password(1, "rotated-hash").unwrap();

    assert_eq!(
        database
            .create_session_for_verified_password(
                "stale-session",
                1,
                "verified-hash",
                "csrf",
                Utc::now() + Duration::hours(1),
            )
            .unwrap(),
        PasswordSessionCreationOutcome::StalePassword
    );
    assert!(database.session("stale-session").unwrap().is_none());
    assert_eq!(
        database
            .conn()
            .query_row::<i64, _, _>(
                "SELECT COUNT(*) FROM sessions WHERE token_hash=?1",
                [token_hash("stale-session")],
                |row| row.get(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn verified_password_session_creation_rejects_an_inactive_admin_without_a_zombie_session() {
    let database = Database::open(":memory:").unwrap();
    database
        .create_admin("disabled", "verified-hash", "secret")
        .unwrap();
    database
        .create_admin("survivor", "other-hash", "other-secret")
        .unwrap();
    assert_eq!(
        database.deactivate_admin(1).unwrap(),
        AdminDeactivationOutcome::Deactivated
    );

    assert_eq!(
        database
            .create_session_for_verified_password(
                "inactive-session",
                1,
                "verified-hash",
                "csrf",
                Utc::now() + Duration::hours(1),
            )
            .unwrap(),
        PasswordSessionCreationOutcome::AdminInactive
    );
    assert!(database.session("inactive-session").unwrap().is_none());
    assert_eq!(
        database
            .conn()
            .query_row::<i64, _, _>(
                "SELECT COUNT(*) FROM sessions WHERE token_hash=?1",
                [token_hash("inactive-session")],
                |row| row.get(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn verified_password_session_creation_accepts_the_current_active_hash() {
    let database = Database::open(":memory:").unwrap();
    database
        .create_admin("admin", "verified-hash", "secret")
        .unwrap();

    assert_eq!(
        database
            .create_session_for_verified_password(
                "current-session",
                1,
                "verified-hash",
                "csrf",
                Utc::now() + Duration::hours(1),
            )
            .unwrap(),
        PasswordSessionCreationOutcome::Created
    );
    assert!(database.session("current-session").unwrap().is_some());
}
