use super::*;

#[test]
fn live_mfa_session_operation_linearizes_with_session_revocation() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    database
        .create_session("live-session", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    assert!(database.verify_mfa("live-session").unwrap());

    let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::channel();
    let publishing_database = database.clone();
    let publisher = std::thread::spawn(move || {
        publishing_database
            .with_live_mfa_session("live-session", 1, || {
                entered_sender.send(()).unwrap();
                release_receiver.recv().unwrap();
                "published"
            })
            .unwrap()
    });
    entered_receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();

    let (revocation_started_sender, revocation_started_receiver) = std::sync::mpsc::channel();
    let (revoked_sender, revoked_receiver) = std::sync::mpsc::channel();
    let revoking_database = database.clone();
    let revoker = std::thread::spawn(move || {
        revocation_started_sender.send(()).unwrap();
        revoking_database.delete_session("live-session").unwrap();
        revoked_sender.send(()).unwrap();
    });
    revocation_started_receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    assert!(revoked_receiver
        .recv_timeout(std::time::Duration::from_millis(25))
        .is_err());

    release_sender.send(()).unwrap();
    assert_eq!(publisher.join().unwrap(), Some("published"));
    revoked_receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    revoker.join().unwrap();

    let ran_after_revocation = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let marker = ran_after_revocation.clone();
    assert_eq!(
        database
            .with_live_mfa_session("live-session", 1, || {
                marker.store(true, std::sync::atomic::Ordering::SeqCst);
            })
            .unwrap(),
        None
    );
    assert!(!ran_after_revocation.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn persistent_database_uses_four_connections_and_memory_uses_one() {
    let memory = Database::open(":memory:").unwrap();
    assert_eq!(memory.0.pool.max_size(), 1);

    let directory = tempfile::tempdir().unwrap();
    let persistent = Database::open(directory.path().join("data.sqlite")).unwrap();
    assert_eq!(persistent.0.pool.max_size(), 4);
}

#[test]
fn required_audit_failure_rolls_back_admin_share_session_and_settings_mutations() {
    let db = Database::open(":memory:").unwrap();
    db.create_admin("admin", "old-hash", "secret").unwrap();
    db.create_admin("inactive", "inactive-hash", "inactive-secret")
        .unwrap();
    db.create_admin("other-active", "other-hash", "other-secret")
        .unwrap();
    assert_eq!(
        db.deactivate_admin(2).unwrap(),
        AdminDeactivationOutcome::Deactivated
    );
    db.replace_runtime_settings(&[("public_base_url", "https://old.invalid".into())], 1)
        .unwrap();
    let share_id = db
        .create_share(
            "existing-share",
            None,
            "file.txt",
            false,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            Some("old-share-hash"),
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    db.conn()
        .execute_batch(
            "CREATE TRIGGER fail_required_audit
                 BEFORE INSERT ON audit
                 BEGIN
                     SELECT RAISE(FAIL, 'injected audit failure');
                 END;",
        )
        .unwrap();
    let context = AuditContext::new("admin", Some("192.0.2.1".into()));

    let create_admin_error = db
        .create_admin_and_audit("rolled-back-admin", "hash", "secret", &context)
        .unwrap_err();
    assert!(is_audit_unavailable(&create_admin_error));
    assert_eq!(db.admin_count().unwrap(), 3);

    let activate_error = db.activate_admin_and_audit(2, &context).unwrap_err();
    assert!(is_audit_unavailable(&activate_error));
    assert_eq!(
        db.conn()
            .query_row::<i64, _, _>("SELECT active FROM admins WHERE id=2", [], |row| row.get(0))
            .unwrap(),
        0
    );

    let deactivate_error = db.deactivate_admin_and_audit(3, &context).unwrap_err();
    assert!(is_audit_unavailable(&deactivate_error));
    assert_eq!(
        db.conn()
            .query_row::<i64, _, _>("SELECT active FROM admins WHERE id=3", [], |row| row.get(0))
            .unwrap(),
        1
    );

    let admin_error = db
        .reset_admin_password_and_audit(1, "new-hash", &context)
        .unwrap_err();
    assert!(is_audit_unavailable(&admin_error));
    assert_eq!(
        db.admin("admin").unwrap().unwrap().password_hash,
        "old-hash"
    );

    let totp_error = db
        .reset_admin_totp_and_audit(1, "new-secret", &context)
        .unwrap_err();
    assert!(is_audit_unavailable(&totp_error));
    assert_eq!(
        db.admin("admin")
            .unwrap()
            .unwrap()
            .totp_secret
            .expose_secret(),
        "secret"
    );

    let share_error = db
        .set_share_active_and_audit(share_id, false, &context, "share_deactivated")
        .unwrap_err();
    assert!(is_audit_unavailable(&share_error));
    assert!(db.share_by_token("existing-share").unwrap().unwrap().active);

    let control_events = [RequiredAuditEvent::routine(
        "share_controls_updated",
        Some(share_id.to_string()),
        None,
    )];
    let controls_error = db
        .update_share_controls_and_audit(
            share_id,
            Some(false),
            Some(&UploadConflictStrategy::OverwriteAllowed),
            None,
            &context,
            &control_events,
        )
        .unwrap_err();
    assert!(is_audit_unavailable(&controls_error));
    let unchanged_share = db.share_by_token("existing-share").unwrap().unwrap();
    assert!(unchanged_share.active);
    assert_eq!(
        unchanged_share.upload_conflict_strategy,
        UploadConflictStrategy::Reject
    );

    let password_error = db
        .set_share_password_and_audit(
            share_id,
            Some("new-share-hash"),
            &context,
            "share_password_changed",
        )
        .unwrap_err();
    assert!(is_audit_unavailable(&password_error));
    assert_eq!(
        db.share_by_token("existing-share")
            .unwrap()
            .unwrap()
            .password_hash
            .as_deref(),
        Some("old-share-hash")
    );

    let share = db.share_by_token("existing-share").unwrap().unwrap();
    let unlock_error = db
        .create_unlock_session_for_verified_password_and_audit(
            "rolled-back-unlock",
            share_id,
            share.password_hash.as_deref().unwrap(),
            share.upload_policy_epoch,
            "csrf",
            Utc::now() + Duration::hours(1),
            &context,
        )
        .unwrap_err();
    assert!(is_audit_unavailable(&unlock_error));
    assert!(!db.unlock_session("rolled-back-unlock", share_id).unwrap());

    let delete_error = db.delete_share_and_audit(share_id, &context).unwrap_err();
    assert!(is_audit_unavailable(&delete_error));
    assert!(db.share_by_token("existing-share").unwrap().is_some());

    let create_error = db
        .create_share_with_upload_limits_and_audit(
            "rolled-back-share",
            None,
            "other.txt",
            false,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
            &context,
            None,
        )
        .unwrap_err();
    assert!(is_audit_unavailable(&create_error));
    assert!(db.share_by_token("rolled-back-share").unwrap().is_none());

    let session_error = db
        .create_session_for_verified_password_and_audit(
            "rolled-back-session",
            1,
            "old-hash",
            "csrf",
            Utc::now() + chrono::Duration::hours(1),
            &context,
        )
        .unwrap_err();
    assert!(is_audit_unavailable(&session_error));
    assert!(db.session("rolled-back-session").unwrap().is_none());

    let settings_error = db
        .replace_runtime_settings_and_audit(
            &[("public_base_url", "https://new.invalid".into())],
            1,
            &context,
            "changed=true".into(),
        )
        .unwrap_err();
    assert!(is_audit_unavailable(&settings_error));
    assert_eq!(
        db.runtime_settings().unwrap(),
        vec![("public_base_url".into(), "https://old.invalid".into())]
    );
    assert_eq!(db.count_audit(None).unwrap(), 0);
}

#[test]
fn token_hash_keeps_lowercase_sha256_encoding() {
    assert_eq!(
        token_hash("test"),
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    );
}

#[test]
fn fallible_unsigned_sqlite_values_reject_out_of_range_data() {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute("CREATE TABLE numbers(value INTEGER NOT NULL)", [])
        .unwrap();
    connection
        .execute(
            "INSERT INTO numbers(value) VALUES(?1)",
            [MAX_SQLITE_UNSIGNED],
        )
        .unwrap();
    let maximum: u64 = connection
        .query_row("SELECT value FROM numbers", [], |row| row.get(0))
        .unwrap();
    assert_eq!(maximum, MAX_SQLITE_UNSIGNED);
    assert!(connection
        .execute(
            "INSERT INTO numbers(value) VALUES(?1)",
            [MAX_SQLITE_UNSIGNED + 1]
        )
        .is_err());

    connection.execute("DELETE FROM numbers", []).unwrap();
    connection
        .execute("INSERT INTO numbers(value) VALUES(-1)", [])
        .unwrap();
    assert!(connection
        .query_row("SELECT value FROM numbers", [], |row| row.get::<_, u64>(0))
        .is_err());
}

#[test]
fn persistent_database_is_regular_private_and_not_linked() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("data.sqlite");
    std::fs::write(&path, []).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

    let database = Database::open(&path).unwrap();
    drop(database);
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.mode() & 0o7777, 0o600);

    let hard_link = directory.path().join("data-hard-link.sqlite");
    std::fs::hard_link(&path, &hard_link).unwrap();
    assert!(Database::open(&path).is_err());

    let symlink = directory.path().join("data-symlink.sqlite");
    std::os::unix::fs::symlink(&path, &symlink).unwrap();
    assert!(Database::open(&symlink).is_err());
    assert!(Database::open(directory.path()).is_err());
}

#[test]
fn database_open_stays_bound_to_the_validated_directory_capability() {
    let parent = tempfile::tempdir().unwrap();
    let configured = parent.path().join("data");
    let displaced = parent.path().join("data-validated");
    std::fs::create_dir(&configured).unwrap();
    std::fs::set_permissions(&configured, std::fs::Permissions::from_mode(0o700)).unwrap();
    let capability = File::open(&configured).unwrap();

    std::fs::rename(&configured, &displaced).unwrap();
    std::fs::create_dir(&configured).unwrap();

    let database = Database::open_in_directory(capability).unwrap();
    assert_eq!(database.admin_count().unwrap(), 0);
    drop(database);

    assert!(displaced.join("data.sqlite").is_file());
    assert!(!configured.join("data.sqlite").exists());
}

#[test]
fn file_mutations_update_only_exact_share_subtrees() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let mut ids = Vec::new();
    for (index, path) in ["foo", "foo/child.txt", "foobar", "other"]
        .into_iter()
        .enumerate()
    {
        ids.push(
            database
                .create_share(
                    &format!("token-{index}"),
                    None,
                    path,
                    path == "foo",
                    &Permission::DownloadOnly,
                    None,
                    None,
                    None,
                    1,
                    None,
                    &UploadConflictStrategy::Reject,
                )
                .unwrap(),
        );
    }
    database.set_share_active(ids[1], false).unwrap();
    assert_eq!(
        database.rename_share_paths("foo", "renamed", true).unwrap(),
        2
    );
    let shares = database.list_shares().unwrap();
    assert!(shares.iter().any(|share| share.relative_path == "renamed"));
    assert!(shares
        .iter()
        .any(|share| share.relative_path == "renamed/child.txt" && !share.active));
    assert!(shares.iter().any(|share| share.relative_path == "foobar"));
    assert_eq!(
        database
            .count_active_shares_for_path("renamed", true)
            .unwrap(),
        1
    );
    assert_eq!(
        database
            .deactivate_shares_for_path("renamed", true)
            .unwrap(),
        1
    );
    assert_eq!(
        database
            .count_active_shares_for_path("renamed", true)
            .unwrap(),
        0
    );
}

#[test]
fn share_cursor_pages_are_gapless_sorted_and_unicode_searchable() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let aliases = ["alpha", "Grüße", "gamma", "delta", "omega"];
    let mut ids = Vec::new();
    for (index, alias) in aliases.iter().enumerate() {
        ids.push(
            database
                .create_share(
                    &format!("cursor-token-{index}"),
                    Some(alias),
                    &format!("folder/{index}.txt"),
                    false,
                    &Permission::DownloadOnly,
                    None,
                    None,
                    None,
                    1,
                    None,
                    &UploadConflictStrategy::Reject,
                )
                .unwrap(),
        );
    }
    database.set_share_active(ids[3], false).unwrap();
    let now = Utc::now();
    let mut cursor = None;
    let mut newest_ids = Vec::new();
    loop {
        let page = database
            .list_share_page(&ShareListOptions {
                query: None,
                status: ShareListStatus::All,
                sort: ShareListSort::Newest,
                cursor,
                limit: 2,
                now,
            })
            .unwrap();
        newest_ids.extend(page.shares.iter().map(|share| share.id));
        let Some(next) = page.next_cursor else { break };
        cursor = Some(next);
    }
    assert_eq!(newest_ids.len(), aliases.len());
    assert!(newest_ids.windows(2).all(|ids| ids[0] > ids[1]));

    let unicode = database
        .list_share_page(&ShareListOptions {
            query: Some("GRÜS".into()),
            status: ShareListStatus::All,
            sort: ShareListSort::Oldest,
            cursor: None,
            limit: 50,
            now,
        })
        .unwrap();
    assert_eq!(unicode.shares.len(), 1);
    assert_eq!(unicode.shares[0].alias.as_deref(), Some("Grüße"));

    let inactive = database
        .list_share_page(&ShareListOptions {
            query: None,
            status: ShareListStatus::Inactive,
            sort: ShareListSort::Newest,
            cursor: None,
            limit: 50,
            now,
        })
        .unwrap();
    assert_eq!(inactive.shares.len(), 1);
    assert_eq!(inactive.shares[0].id, ids[3]);
    let summary = database.share_summary(now).unwrap();
    assert_eq!(summary.available, 4);
}

#[test]
fn download_limit_is_atomic() {
    let d = Database::open(":memory:").unwrap();
    d.create_admin("a", "h", "s").unwrap();
    let id = d
        .create_share(
            "token",
            None,
            "x",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    assert!(d.count_download(id).unwrap());
    assert!(!d.count_download(id).unwrap());
}
#[test]
fn alias_unique() {
    let d = Database::open(":memory:").unwrap();
    d.create_admin("a", "h", "s").unwrap();
    d.create_share(
        "a",
        Some("alias"),
        "x",
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
    assert!(d
        .create_share(
            "b",
            Some("alias"),
            "y",
            false,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .is_err());
}

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

#[test]
fn audit_client_ips_are_optional_listed_and_purgeable_without_deleting_events() {
    let database = Database::open(":memory:").unwrap();
    database
        .audit("admin", "settings_updated", None, None)
        .unwrap();
    database
        .audit_with_client_ip(
            "public",
            "share_unlock_failed",
            Some("7"),
            Some("rate limited"),
            Some("203.0.113.24"),
        )
        .unwrap();

    assert_eq!(database.count_audit_client_ips().unwrap(), 1);
    assert_eq!(database.count_audit(None).unwrap(), 2);
    assert_eq!(database.count_audit(Some("settings_updated")).unwrap(), 1);
    assert_eq!(database.count_audit(Some("missing_action")).unwrap(), 0);
    let events = database.list_audit(None, 10, 0).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].client_ip.as_deref(), Some("203.0.113.24"));
    assert!(events[1].client_ip.is_none());

    assert_eq!(
        database.delete_audit_client_ips_if_disabled(false).unwrap(),
        AuditClientIpDeletionOutcome::Deleted(1)
    );
    assert_eq!(database.count_audit_client_ips().unwrap(), 0);
    assert_eq!(
        database.delete_audit_client_ips_if_disabled(false).unwrap(),
        AuditClientIpDeletionOutcome::Deleted(0)
    );
    let events = database.list_audit(None, 10, 0).unwrap();
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|event| event.client_ip.is_none()));
}

#[test]
fn audit_listing_sorts_only_by_the_selected_whitelisted_column() {
    let database = Database::open(":memory:").unwrap();
    database
        .audit("zulu", "z_action", Some("2"), Some("later alphabetically"))
        .unwrap();
    database
        .audit(
            "Alpha",
            "a_action",
            Some("1"),
            Some("earlier alphabetically"),
        )
        .unwrap();

    let default = database.list_audit(None, 10, 0).unwrap();
    assert_eq!(default[0].actor, "Alpha");

    let ascending = database
        .list_audit_sorted(
            None,
            10,
            0,
            AuditSortColumn::Actor,
            AuditSortDirection::Ascending,
        )
        .unwrap();
    assert_eq!(
        ascending
            .iter()
            .map(|event| event.actor.as_str())
            .collect::<Vec<_>>(),
        ["Alpha", "zulu"]
    );

    let descending = database
        .list_audit_sorted(
            None,
            10,
            0,
            AuditSortColumn::Actor,
            AuditSortDirection::Descending,
        )
        .unwrap();
    assert_eq!(
        descending
            .iter()
            .map(|event| event.actor.as_str())
            .collect::<Vec<_>>(),
        ["zulu", "Alpha"]
    );
}

#[test]
fn audited_client_ip_purge_rolls_back_when_required_audit_fails() {
    let database = Database::open(":memory:").unwrap();
    database
        .audit_with_client_ip("public", "existing_event", None, None, Some("203.0.113.24"))
        .unwrap();
    assert_eq!(database.count_audit_client_ips().unwrap(), 1);
    database
        .conn()
        .execute_batch(
            "CREATE TRIGGER fail_audit_ip_purge_audit
                 BEFORE INSERT ON audit
                 WHEN NEW.action='audit_client_ips_deleted'
                 BEGIN SELECT RAISE(FAIL, 'injected audit failure'); END;",
        )
        .unwrap();
    let context = AuditContext::new("admin", None);

    let error = database
        .delete_audit_client_ips_if_disabled_and_audit(false, &context)
        .unwrap_err();
    assert!(is_audit_unavailable(&error));
    assert_eq!(database.count_audit_client_ips().unwrap(), 1);
    assert_eq!(
        database
            .count_audit(Some("audit_client_ips_deleted"))
            .unwrap(),
        0
    );
}

#[test]
fn audit_ip_writes_and_purge_follow_the_persisted_privacy_setting() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    database
        .replace_runtime_settings(&[("audit_client_ip_enabled", "true".to_string())], 1)
        .unwrap();
    database
        .audit_with_client_ip("public", "before_disable", None, None, Some("203.0.113.40"))
        .unwrap();

    // The committed setting wins over a stale in-memory fallback.
    assert_eq!(
        database.delete_audit_client_ips_if_disabled(false).unwrap(),
        AuditClientIpDeletionOutcome::LoggingEnabled
    );

    database
        .replace_runtime_settings(&[("audit_client_ip_enabled", "false".to_string())], 1)
        .unwrap();
    // Model a delayed request that captured the IP while logging was still
    // enabled but reaches SQLite only after the disabling commit.
    database
        .audit_with_client_ip(
            "public",
            "delayed_after_disable",
            None,
            None,
            Some("203.0.113.41"),
        )
        .unwrap();
    let delayed = database
        .list_audit(Some("delayed_after_disable"), 1, 0)
        .unwrap();
    assert_eq!(delayed.len(), 1);
    assert!(delayed[0].client_ip.is_none());
    assert_eq!(database.count_audit_client_ips().unwrap(), 1);

    assert_eq!(
        database.delete_audit_client_ips_if_disabled(true).unwrap(),
        AuditClientIpDeletionOutcome::Deleted(1)
    );
    assert_eq!(database.count_audit_client_ips().unwrap(), 0);

    database
        .replace_runtime_settings(&[("audit_client_ip_enabled", "true".to_string())], 1)
        .unwrap();
    assert_eq!(
        database.delete_audit_client_ips_if_disabled(false).unwrap(),
        AuditClientIpDeletionOutcome::LoggingEnabled
    );
}

#[test]
fn audit_retention_keeps_only_the_newest_rows() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    {
        let mut connection = database.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        for index in 0..6 {
            transaction
                .execute(
                    "INSERT INTO audit(
                             occurred_at,actor,action,object_id,detail,client_ip
                         ) VALUES(?1,'test',?2,NULL,NULL,NULL)",
                    params![Utc::now().to_rfc3339(), format!("event-{index}")],
                )
                .unwrap();
            enforce_audit_retention(&transaction, 3).unwrap();
        }
        transaction.commit().unwrap();
    }

    let actions: Vec<String> = {
        let connection = database.conn();
        let mut statement = connection
            .prepare("SELECT action FROM audit ORDER BY id")
            .unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    };
    assert_eq!(
        actions,
        vec![
            "event-3".to_string(),
            "event-4".to_string(),
            "event-5".to_string()
        ]
    );
}

#[test]
fn audit_retention_preserves_security_events_during_routine_volume() {
    let database = Database::open(":memory:").unwrap();
    let connection = database.conn();
    connection
        .execute(
            "INSERT INTO audit(occurred_at,actor,action,priority)
             VALUES(?1,'local_recovery','admin_recovered',100)",
            [Utc::now().to_rfc3339()],
        )
        .unwrap();
    for index in 0..4 {
        connection
            .execute(
                "INSERT INTO audit(occurred_at,actor,action,priority)
                 VALUES(?1,'public',?2,0)",
                params![Utc::now().to_rfc3339(), format!("download-{index}")],
            )
            .unwrap();
    }

    assert_eq!(enforce_audit_retention(&connection, 3).unwrap(), 2);
    let actions: Vec<String> = connection
        .prepare("SELECT action FROM audit ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(actions, ["admin_recovered", "download-2", "download-3"]);
}

#[test]
fn audit_retention_falls_back_to_fifo_for_security_only_volume() {
    let database = Database::open(":memory:").unwrap();
    let connection = database.conn();
    for index in 0..5 {
        connection
            .execute(
                "INSERT INTO audit(occurred_at,actor,action,priority)
                 VALUES(?1,'admin',?2,100)",
                params![Utc::now().to_rfc3339(), format!("security-{index}")],
            )
            .unwrap();
    }

    assert_eq!(enforce_audit_retention(&connection, 3).unwrap(), 2);
    let actions: Vec<String> = connection
        .prepare("SELECT action FROM audit ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(actions, ["security-2", "security-3", "security-4"]);
}

#[test]
fn audit_retention_caps_recent_events() {
    let database = Database::open(":memory:").unwrap();
    let mut connection = database.conn();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    for index in 0..=MAX_AUDIT_ROWS {
        transaction
            .execute(
                "INSERT INTO audit(occurred_at,actor,action,object_id,detail,client_ip)
                 VALUES(?1,'test',?2,NULL,NULL,NULL)",
                params![Utc::now().to_rfc3339(), format!("event-{index}")],
            )
            .unwrap();
    }
    transaction.commit().unwrap();
    drop(connection);

    assert_eq!(database.cleanup_audit_retention().unwrap(), 1);
    assert_eq!(database.count_audit(None).unwrap(), MAX_AUDIT_ROWS as usize);
}

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

#[test]
fn disabled_and_deleted_links_change_state() {
    let d = Database::open(":memory:").unwrap();
    d.create_admin("admin", "hash", "secret").unwrap();
    let id = d
        .create_share(
            "token",
            None,
            "file",
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
    assert!(d.set_share_active(id, false).unwrap());
    assert!(!d.set_share_active(id + 1, false).unwrap());
    assert!(!d.share_by_token("token").unwrap().unwrap().active);
    assert!(d.delete_share(id).unwrap());
    assert!(!d.delete_share(id).unwrap());
    assert!(d.share_by_token("token").unwrap().is_none());
}

#[test]
fn malformed_share_expiry_fails_individual_and_list_queries() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    for (token, path) in [("valid", "valid.txt"), ("corrupt", "corrupt.txt")] {
        database
            .create_share(
                token,
                None,
                path,
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
    }
    database
        .conn()
        .execute(
            "UPDATE shares SET expires_at='not-a-timestamp' WHERE token_hash=?1",
            [token_hash("corrupt")],
        )
        .unwrap();

    assert!(database.share_by_token("corrupt").is_err());
    assert!(database.list_shares().is_err());
}

#[test]
fn rejects_unknown_newer_schema() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("future.sqlite");
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
        .unwrap();
    drop(connection);
    assert!(matches!(
        Database::open(path),
        Err(DatabaseError::Schema(_))
    ));
}

#[test]
fn fresh_database_is_exactly_schema_five_without_plaintext_secret_columns() {
    let database = Database::open(":memory:").unwrap();
    let connection = database.conn();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        SCHEMA_VERSION
    );
    let migration_records: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM vaultlink_schema_migrations WHERE target_version IN (2,3,4,5) AND length(applied_at)>0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(migration_records, 4);
    for index in ["idx_shares_active_id", "idx_shares_active_expires"] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name=?1)",
                [index],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "schema 3 index {index} is missing");
    }
    let last_activity_not_null: i64 = connection
        .query_row(
            "SELECT \"notnull\" FROM pragma_table_info('sessions') WHERE name='last_activity_at'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(last_activity_not_null, 1);
    let priority_not_null: i64 = connection
        .query_row(
            "SELECT \"notnull\" FROM pragma_table_info('audit') WHERE name='priority'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(priority_not_null, 1);
    for (table, forbidden) in [
        ("shares", "token"),
        ("admins", "totp_secret"),
        ("admin_mfa_enrollments", "totp_secret"),
        ("admin_webauthn_credentials", "credential_json"),
    ] {
        let sql = format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name=?1");
        let count: i64 = connection
            .query_row(&sql, [forbidden], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0, "legacy column {table}.{forbidden} exists");
    }
    for (table, encrypted_columns) in [
        ("shares", &["token_key_id", "token_ciphertext"][..]),
        ("admins", &["totp_key_id", "totp_ciphertext"][..]),
        (
            "admin_mfa_enrollments",
            &["totp_key_id", "totp_ciphertext"][..],
        ),
        ("admin_webauthn_credentials", &["credential_blob"][..]),
    ] {
        for column in encrypted_columns {
            let sql = format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name=?1");
            let count: i64 = connection
                .query_row(&sql, [column], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 1, "encrypted column {table}.{column} missing");
        }
    }
}

fn downgrade_audit_to_schema_four(connection: &Connection) {
    connection
        .execute_batch(
            "DROP INDEX idx_audit_priority_id;
             ALTER TABLE audit DROP COLUMN priority;
             DELETE FROM vaultlink_schema_migrations WHERE target_version=5;",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE vaultlink_schema SET fingerprint=?1 WHERE singleton=1",
            [schema::SCHEMA_4_FINGERPRINT],
        )
        .unwrap();
    connection.pragma_update(None, "user_version", 4).unwrap();
}

fn populated_schema_one_fixture() -> (tempfile::TempDir, PathBuf, Vec<u8>, Vec<u8>) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-one.sqlite");
    let database = Database::open(&path).unwrap();
    database
        .create_admin("admin", "password-hash", "TOTP-SECRET")
        .unwrap();
    database
        .create_share(
            "share-token",
            Some("fixture"),
            "fixture.txt",
            false,
            &Permission::DownloadOnly,
            None,
            Some(7),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    database
        .replace_runtime_settings(&[("public_base_url", "https://fixture.invalid".into())], 1)
        .unwrap();
    database
        .audit("admin", "fixture_event", Some("1"), Some("preserved"))
        .unwrap();
    let (share_ciphertext, totp_ciphertext) = database
        .conn()
        .query_row(
            "SELECT shares.token_ciphertext,admins.totp_ciphertext
             FROM shares JOIN admins ON admins.id=shares.created_by",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    drop(database);

    let connection = Connection::open(&path).unwrap();
    downgrade_audit_to_schema_four(&connection);
    connection
        .execute_batch(
            "DROP TABLE vaultlink_schema_migrations;
             DROP INDEX idx_shares_active_id;
             DROP INDEX idx_shares_active_expires;",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE vaultlink_schema SET fingerprint=?1 WHERE singleton=1",
            [schema::SCHEMA_1_FINGERPRINT],
        )
        .unwrap();
    connection.pragma_update(None, "user_version", 1).unwrap();
    drop(connection);
    (directory, path, share_ciphertext, totp_ciphertext)
}

fn schema_two_fixture() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-two.sqlite");
    drop(Database::open(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    downgrade_audit_to_schema_four(&connection);
    connection
        .execute_batch(
            "DROP INDEX idx_shares_active_id;
             DROP INDEX idx_shares_active_expires;
             DELETE FROM vaultlink_schema_migrations WHERE target_version IN (3,4);",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE vaultlink_schema SET fingerprint=?1 WHERE singleton=1",
            [schema::SCHEMA_2_FINGERPRINT],
        )
        .unwrap();
    connection.pragma_update(None, "user_version", 2).unwrap();
    drop(connection);
    (directory, path)
}

fn schema_three_fixture() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-three.sqlite");
    let database = Database::open(&path).unwrap();
    database
        .create_admin("admin", "password-hash", "TOTP-SECRET")
        .unwrap();
    database
        .create_session(
            "schema-three-session",
            1,
            "csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    database
        .audit(
            "admin",
            "schema_three_fixture",
            Some("1"),
            Some("preserved"),
        )
        .unwrap();
    drop(database);

    let connection = Connection::open(&path).unwrap();
    downgrade_audit_to_schema_four(&connection);
    connection
        .execute_batch(
            "ALTER TABLE sessions RENAME TO sessions_schema_4;
             DROP INDEX idx_sessions_exp;
             DROP INDEX idx_sessions_admin;
             CREATE TABLE sessions(
                 token_hash TEXT PRIMARY KEY,
                 admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
                 csrf_token TEXT NOT NULL,
                 mfa_verified INTEGER NOT NULL DEFAULT 0 CHECK(mfa_verified IN (0,1)),
                 expires_at TEXT NOT NULL
             );
             INSERT INTO sessions(token_hash,admin_id,csrf_token,mfa_verified,expires_at)
             SELECT token_hash,admin_id,csrf_token,mfa_verified,expires_at FROM sessions_schema_4;
             CREATE INDEX idx_sessions_exp ON sessions(expires_at);
             CREATE INDEX idx_sessions_admin ON sessions(admin_id);
             DROP TABLE sessions_schema_4;
             DELETE FROM vaultlink_schema_migrations WHERE target_version=4;",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE vaultlink_schema SET fingerprint=?1 WHERE singleton=1",
            [schema::SCHEMA_3_FINGERPRINT],
        )
        .unwrap();
    connection.pragma_update(None, "user_version", 3).unwrap();
    drop(connection);
    (directory, path)
}

fn schema_four_fixture() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-four.sqlite");
    let database = Database::open(&path).unwrap();
    database
        .audit("local_recovery", "admin_recovered", Some("1"), None)
        .unwrap();
    database
        .audit("public", "download", Some("2"), None)
        .unwrap();
    drop(database);

    let connection = Connection::open(&path).unwrap();
    downgrade_audit_to_schema_four(&connection);
    drop(connection);
    (directory, path)
}

#[test]
fn schema_one_migrates_once_and_preserves_data_and_encrypted_secrets() {
    let (_directory, path, share_ciphertext, totp_ciphertext) = populated_schema_one_fixture();
    let database = Database::open(&path).unwrap();
    assert_eq!(database.active_admin_usernames().unwrap(), ["admin"]);
    assert_eq!(
        database
            .admin("admin")
            .unwrap()
            .unwrap()
            .totp_secret
            .expose_secret(),
        "TOTP-SECRET"
    );
    assert_eq!(
        database
            .share_by_token("share-token")
            .unwrap()
            .unwrap()
            .alias
            .as_deref(),
        Some("fixture")
    );
    assert_eq!(
        database.runtime_settings().unwrap(),
        [("public_base_url".into(), "https://fixture.invalid".into())]
    );
    assert_eq!(database.count_audit(Some("fixture_event")).unwrap(), 1);
    let connection = database.conn();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        SCHEMA_VERSION
    );
    let (migrated_share_ciphertext, migrated_totp_ciphertext): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT shares.token_ciphertext,admins.totp_ciphertext
             FROM shares JOIN admins ON admins.id=shares.created_by",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(migrated_share_ciphertext, share_ciphertext);
    assert_eq!(migrated_totp_ciphertext, totp_ciphertext);
    let applied_at: Vec<(i64, String)> = connection
        .prepare(
            "SELECT target_version,applied_at FROM vaultlink_schema_migrations
             WHERE target_version IN (2,3,4,5) ORDER BY target_version",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    drop(connection);
    drop(database);

    let reopened = Database::open(&path).unwrap();
    let reopened_connection = reopened.conn();
    let reopened_applied_at: Vec<(i64, String)> = reopened_connection
        .prepare(
            "SELECT target_version,applied_at FROM vaultlink_schema_migrations
             WHERE target_version IN (2,3,4,5) ORDER BY target_version",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(reopened_applied_at, applied_at);
}

#[test]
fn schema_two_migrates_to_five_with_expected_indexes() {
    let (_directory, path) = schema_two_fixture();
    let database = Database::open(path).unwrap();
    let connection = database.conn();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        SCHEMA_VERSION
    );
    for index in ["idx_shares_active_id", "idx_shares_active_expires"] {
        let present: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name=?1)",
                [index],
                |row| row.get(0),
            )
            .unwrap();
        assert!(present);
    }
}

#[test]
fn schema_four_migration_backfills_security_priority() {
    let (_directory, path) = schema_four_fixture();
    let database = Database::open(path).unwrap();
    let connection = database.conn();
    let priorities: Vec<(String, i64)> = connection
        .prepare("SELECT action,priority FROM audit ORDER BY id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        priorities,
        [("admin_recovered".into(), 100), ("download".into(), 0)]
    );
}

#[test]
fn schema_three_migration_revokes_sessions_and_preserves_other_data() {
    let (_directory, path) = schema_three_fixture();
    let database = Database::open(path).unwrap();
    assert!(database.session("schema-three-session").unwrap().is_none());
    assert_eq!(database.active_admin_usernames().unwrap(), ["admin"]);
    assert_eq!(
        database.count_audit(Some("schema_three_fixture")).unwrap(),
        1
    );
    let connection = database.conn();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        SCHEMA_VERSION
    );
    let session_columns: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='last_activity_at' AND \"notnull\"=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(session_columns, 1);
}

#[test]
fn corrupt_schema_fingerprint_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("corrupt-fingerprint.sqlite");
    drop(Database::open(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE vaultlink_schema SET fingerprint='corrupt' WHERE singleton=1",
            [],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        Database::open(path),
        Err(DatabaseError::Schema(_))
    ));
}

#[test]
fn failed_schema_one_migration_rolls_back_every_change() {
    let (_directory, path, _, _) = populated_schema_one_fixture();
    schema::fail_next_schema_1_to_2_migration();
    assert!(matches!(
        Database::open(&path),
        Err(DatabaseError::Schema(_))
    ));

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        1
    );
    let fingerprint: String = connection
        .query_row(
            "SELECT fingerprint FROM vaultlink_schema WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fingerprint, schema::SCHEMA_1_FINGERPRINT);
    let migration_table: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='vaultlink_schema_migrations')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!migration_table);
}

#[test]
fn failed_schema_two_migration_rolls_back_indexes_and_metadata() {
    let (_directory, path) = schema_two_fixture();
    schema::fail_next_schema_2_to_3_migration();
    assert!(matches!(
        Database::open(&path),
        Err(DatabaseError::Schema(_))
    ));

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        2
    );
    let fingerprint: String = connection
        .query_row(
            "SELECT fingerprint FROM vaultlink_schema WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fingerprint, schema::SCHEMA_2_FINGERPRINT);
    let schema_three_artifacts: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type='index' AND name IN ('idx_shares_active_id','idx_shares_active_expires')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(schema_three_artifacts, 0);
}

#[test]
fn failed_schema_three_migration_restores_sessions_and_metadata() {
    let (_directory, path) = schema_three_fixture();
    schema::fail_next_schema_3_to_4_migration();
    assert!(matches!(
        Database::open(&path),
        Err(DatabaseError::Schema(_))
    ));

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        3
    );
    let fingerprint: String = connection
        .query_row(
            "SELECT fingerprint FROM vaultlink_schema WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fingerprint, schema::SCHEMA_3_FINGERPRINT);
    let session_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(session_count, 1);
    let last_activity_column: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='last_activity_at'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(last_activity_column, 0);
}

#[test]
fn failed_schema_four_migration_restores_audit_shape_and_metadata() {
    let (_directory, path) = schema_four_fixture();
    schema::fail_next_schema_4_to_5_migration();
    assert!(matches!(
        Database::open(&path),
        Err(DatabaseError::Schema(_))
    ));

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        4
    );
    let fingerprint: String = connection
        .query_row(
            "SELECT fingerprint FROM vaultlink_schema WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fingerprint, schema::SCHEMA_4_FINGERPRINT);
    let priority_column: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('audit') WHERE name='priority'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(priority_column, 0);
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM audit", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
}

#[test]
fn persistent_secrets_survive_restart_and_key_rotation_without_plaintext_columns() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("data.sqlite");
    let database = Database::open(&path).unwrap();
    database
        .create_admin("admin", "password-hash", "TOTP-SECRET")
        .unwrap();
    database
        .create_share(
            "share-token",
            None,
            "file.txt",
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
    let before: (u64, Vec<u8>, u64, Vec<u8>) = database
        .conn()
        .query_row(
            "SELECT shares.token_key_id,shares.token_ciphertext,
                    admins.totp_key_id,admins.totp_ciphertext
             FROM shares JOIN admins ON admins.id=shares.created_by",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    drop(database);

    Database::rotate_secrets(&path).unwrap();
    let reopened = Database::open(&path).unwrap();
    assert_eq!(
        reopened
            .share_by_token("share-token")
            .unwrap()
            .unwrap()
            .token,
        "share-token"
    );
    assert_eq!(
        reopened
            .admin("admin")
            .unwrap()
            .unwrap()
            .totp_secret
            .expose_secret(),
        "TOTP-SECRET"
    );
    let after: (u64, Vec<u8>, u64, Vec<u8>) = reopened
        .conn()
        .query_row(
            "SELECT shares.token_key_id,shares.token_ciphertext,
                    admins.totp_key_id,admins.totp_ciphertext
             FROM shares JOIN admins ON admins.id=shares.created_by",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert!(after.0 > before.0);
    assert!(after.2 > before.2);
    assert_ne!(after.1, before.1);
    assert_ne!(after.3, before.3);
    assert_eq!(
        std::fs::metadata(directory.path().join("secrets.keyring"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
}

#[test]
fn initialized_database_rejects_missing_or_unrelated_keyring_at_startup() {
    let missing_directory = tempfile::tempdir().unwrap();
    let missing_path = missing_directory.path().join("data.sqlite");
    let database = Database::open(&missing_path).unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    drop(database);
    std::fs::remove_file(missing_directory.path().join("secrets.keyring")).unwrap();
    assert!(matches!(
        Database::open(&missing_path),
        Err(DatabaseError::Cryptography(_))
    ));

    let first_directory = tempfile::tempdir().unwrap();
    let first_path = first_directory.path().join("data.sqlite");
    let first = Database::open(&first_path).unwrap();
    first.create_admin("admin", "hash", "secret").unwrap();
    drop(first);

    let second_directory = tempfile::tempdir().unwrap();
    let second_path = second_directory.path().join("data.sqlite");
    drop(Database::open(&second_path).unwrap());
    std::fs::copy(
        second_directory.path().join("secrets.keyring"),
        first_directory.path().join("secrets.keyring"),
    )
    .unwrap();
    assert!(matches!(
        Database::open(&first_path),
        Err(DatabaseError::Cryptography(_))
    ));
}

#[test]
fn startup_rejects_ciphertext_nonce_and_aad_manipulation() {
    for manipulation in ["ciphertext", "nonce", "aad"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("data.sqlite");
        let database = Database::open(&path).unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        database
            .create_share(
                "share-token",
                None,
                "file.txt",
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
        if manipulation == "aad" {
            database
                .conn()
                .execute("UPDATE shares SET token_hash=?1", ["0".repeat(64)])
                .unwrap();
        } else {
            let mut ciphertext: Vec<u8> = database
                .conn()
                .query_row("SELECT token_ciphertext FROM shares", [], |row| row.get(0))
                .unwrap();
            let index = if manipulation == "nonce" {
                0
            } else {
                ciphertext.len() - 1
            };
            ciphertext[index] ^= 0x80;
            database
                .conn()
                .execute("UPDATE shares SET token_ciphertext=?1", [ciphertext])
                .unwrap();
        }
        drop(database);
        assert!(Database::open(&path).is_err(), "{manipulation}");
    }
}

#[test]
fn rejects_unversioned_legacy_and_wrong_schema_one_shape() {
    for (version, sql) in [
        (
            0,
            "CREATE TABLE shares(id INTEGER PRIMARY KEY, token TEXT NOT NULL);",
        ),
        (
            1,
            "CREATE TABLE shares(id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL);",
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(format!("legacy-{version}.sqlite"));
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(sql).unwrap();
        connection
            .pragma_update(None, "user_version", version)
            .unwrap();
        drop(connection);
        assert!(Database::open(path).is_err());
    }
}

#[test]
fn unlock_sessions_are_hashed_and_cascade_with_share() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share(
            "share",
            None,
            "folder",
            true,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            Some("password-hash"),
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let original_share = database.share_by_token("share").unwrap().unwrap();
    assert!(database
        .create_unlock_session_for_verified_password(
            "unlock-secret",
            share_id,
            original_share.password_hash.as_deref().unwrap(),
            original_share.upload_policy_epoch,
            "unlock-csrf",
            Utc::now() + chrono::Duration::minutes(60),
        )
        .unwrap());
    assert!(database.unlock_session("unlock-secret", share_id).unwrap());
    assert_eq!(
        database
            .unlock_session_csrf("unlock-secret", share_id)
            .unwrap()
            .as_deref(),
        Some("unlock-csrf")
    );
    let stored: String = database
        .conn()
        .query_row("SELECT token_hash FROM public_unlock_sessions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_ne!(stored, "unlock-secret");
    database
        .set_share_password(share_id, Some("new-password-hash"))
        .unwrap();
    assert!(!database.unlock_session("unlock-secret", share_id).unwrap());
    assert!(!database
        .create_unlock_session_for_verified_password(
            "stale-unlock-secret",
            share_id,
            original_share.password_hash.as_deref().unwrap(),
            original_share.upload_policy_epoch,
            "stale-unlock-csrf",
            Utc::now() + chrono::Duration::minutes(60),
        )
        .unwrap());
    assert!(!database
        .unlock_session("stale-unlock-secret", share_id)
        .unwrap());
    let updated_share = database.share_by_token("share").unwrap().unwrap();
    assert!(updated_share.upload_policy_epoch > original_share.upload_policy_epoch);
    assert!(database
        .create_unlock_session_for_verified_password(
            "new-unlock-secret",
            share_id,
            updated_share.password_hash.as_deref().unwrap(),
            updated_share.upload_policy_epoch,
            "new-unlock-csrf",
            Utc::now() + chrono::Duration::minutes(60),
        )
        .unwrap());
    database
        .set_share_password(share_id, updated_share.password_hash.as_deref())
        .unwrap();
    assert!(!database
        .unlock_session("new-unlock-secret", share_id)
        .unwrap());
    assert!(!database
        .create_unlock_session_for_verified_password(
            "same-hash-stale-secret",
            share_id,
            updated_share.password_hash.as_deref().unwrap(),
            updated_share.upload_policy_epoch,
            "same-hash-stale-csrf",
            Utc::now() + chrono::Duration::minutes(60),
        )
        .unwrap());
    database.delete_share(share_id).unwrap();
    assert_eq!(
        database
            .conn()
            .query_row::<i64, _, _>("SELECT COUNT(*) FROM public_unlock_sessions", [], |row| {
                row.get(0)
            })
            .unwrap(),
        0
    );
}

#[test]
fn upload_quota_reservations_are_atomic_cumulative_and_cancellable() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share_with_upload_limits(
            "upload-share",
            None,
            "folder",
            true,
            &Permission::UploadOnly,
            None,
            None,
            Some(6),
            Some(10),
            Some(2),
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    assert_eq!(
        database
            .begin_upload_reservation("one", share_id, 0)
            .unwrap(),
        UploadReservationBeginOutcome::Reserved
    );
    assert_eq!(
        database
            .begin_upload_reservation("two", share_id, 0)
            .unwrap(),
        UploadReservationBeginOutcome::Reserved
    );
    assert_eq!(
        database
            .begin_upload_reservation("three", share_id, 0)
            .unwrap(),
        UploadReservationBeginOutcome::FileQuotaReached
    );
    assert_eq!(
        database.extend_upload_reservation("one", 6).unwrap(),
        UploadReservationExtendOutcome::Extended
    );
    assert_eq!(
        database.extend_upload_reservation("two", 5).unwrap(),
        UploadReservationExtendOutcome::ByteQuotaReached
    );
    assert!(database.cancel_upload_reservation("two").unwrap());
    assert_eq!(
        database.commit_upload_reservation("one", 6).unwrap(),
        UploadReservationCommitOutcome::Committed
    );

    assert_eq!(
        database
            .begin_upload_reservation("three", share_id, 0)
            .unwrap(),
        UploadReservationBeginOutcome::Reserved
    );
    assert_eq!(
        database.extend_upload_reservation("three", 4).unwrap(),
        UploadReservationExtendOutcome::Extended
    );
    assert_eq!(
        database.commit_upload_reservation("three", 4).unwrap(),
        UploadReservationCommitOutcome::Committed
    );
    let share = database.share_by_token("upload-share").unwrap().unwrap();
    assert_eq!((share.uploaded_bytes, share.uploaded_files), (10, 2));
    assert_eq!(
        database
            .begin_upload_reservation("four", share_id, 0)
            .unwrap(),
        UploadReservationBeginOutcome::ByteQuotaReached
    );
    assert_eq!(
        database.commit_upload_reservation("missing", 0).unwrap(),
        UploadReservationCommitOutcome::NotFound
    );
}

#[test]
fn upload_quota_commit_rolls_back_usage_and_reservation_when_audit_fails() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share_with_upload_limits(
            "upload-share",
            None,
            "folder",
            true,
            &Permission::UploadOnly,
            None,
            None,
            Some(10),
            Some(100),
            Some(2),
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    assert_eq!(
        database
            .begin_upload_reservation("reservation", share_id, 0)
            .unwrap(),
        UploadReservationBeginOutcome::Reserved
    );
    assert_eq!(
        database
            .extend_upload_reservation("reservation", 7)
            .unwrap(),
        UploadReservationExtendOutcome::Extended
    );
    database
        .conn()
        .execute_batch(
            "CREATE TRIGGER fail_upload_quota_audit
                 BEFORE INSERT ON audit
                 WHEN NEW.action='upload_quota_committed'
                 BEGIN SELECT RAISE(FAIL, 'injected audit failure'); END;",
        )
        .unwrap();
    let context = AuditContext::new("public", None);

    let error = database
        .commit_upload_reservation_and_audit("reservation", 7, &context)
        .unwrap_err();
    assert!(is_audit_unavailable(&error));
    let usage_rows: u64 = database
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM public_upload_usage WHERE share_id=?1",
            [share_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(usage_rows, 0);
    assert_eq!(database.active_upload_reservations(share_id).unwrap(), 1);

    database
        .conn()
        .execute_batch("DROP TRIGGER fail_upload_quota_audit")
        .unwrap();
    assert_eq!(
        database
            .commit_upload_reservation_and_audit("reservation", 7, &context)
            .unwrap(),
        UploadReservationCommitOutcome::Committed
    );
    let share = database.share_by_token("upload-share").unwrap().unwrap();
    assert_eq!((share.uploaded_bytes, share.uploaded_files), (7, 1));
    assert_eq!(
        database
            .count_audit(Some("upload_quota_committed"))
            .unwrap(),
        1
    );
}

#[test]
fn upload_reservations_are_revoked_when_share_authority_changes() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let revocations = [
        "UPDATE shares SET active=0 WHERE id=?1",
        "UPDATE shares SET expires_at='2000-01-01T00:00:00Z' WHERE id=?1",
        "UPDATE shares SET is_directory=0 WHERE id=?1",
        "UPDATE shares SET permission='download_only' WHERE id=?1",
    ];

    for (index, revocation) in revocations.into_iter().enumerate() {
        let share_token = format!("revoked-share-{index}");
        let extend_token = format!("extend-{index}");
        let commit_token = format!("commit-{index}");
        let share_id = database
            .create_share_with_upload_limits(
                &share_token,
                None,
                &format!("folder-{index}"),
                true,
                &Permission::UploadOnly,
                None,
                None,
                Some(100),
                Some(1_000),
                Some(10),
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        assert_eq!(
            database
                .begin_upload_reservation(&extend_token, share_id, 0)
                .unwrap(),
            UploadReservationBeginOutcome::Reserved
        );
        assert_eq!(
            database
                .begin_upload_reservation(&commit_token, share_id, 0)
                .unwrap(),
            UploadReservationBeginOutcome::Reserved
        );
        database.conn().execute(revocation, [share_id]).unwrap();

        assert_eq!(
            database
                .extend_upload_reservation(&extend_token, 1)
                .unwrap(),
            UploadReservationExtendOutcome::ShareUnavailable
        );
        assert_eq!(
            database
                .commit_upload_reservation(&commit_token, 0)
                .unwrap(),
            UploadReservationCommitOutcome::ShareUnavailable
        );
        assert_eq!(database.active_upload_reservations(share_id).unwrap(), 0);
        assert!(!database.cancel_upload_reservation(&extend_token).unwrap());
        assert!(!database.cancel_upload_reservation(&commit_token).unwrap());
        let usage: u64 = database
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM public_upload_usage WHERE share_id=?1",
                [share_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(usage, 0);
    }

    let read_write_share = database
        .create_share_with_upload_limits(
            "read-write-share",
            None,
            "read-write-folder",
            true,
            &Permission::DownloadUpload,
            None,
            None,
            Some(100),
            Some(1_000),
            Some(2),
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    assert_eq!(
        database
            .begin_upload_reservation("read-write-upload", read_write_share, 0)
            .unwrap(),
        UploadReservationBeginOutcome::Reserved
    );
    assert_eq!(
        database
            .extend_upload_reservation("read-write-upload", 1)
            .unwrap(),
        UploadReservationExtendOutcome::Extended
    );
    assert_eq!(
        database
            .commit_upload_reservation("read-write-upload", 1)
            .unwrap(),
        UploadReservationCommitOutcome::Committed
    );
}

#[test]
fn upload_reservation_policy_epoch_rejects_reactivation_and_policy_rotation() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share_with_upload_limits(
            "epoch-share",
            None,
            "folder",
            true,
            &Permission::UploadOnly,
            None,
            None,
            Some(100),
            Some(1_000),
            Some(10),
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();

    assert_eq!(
        database
            .begin_upload_reservation("before-reactivation", share_id, 0)
            .unwrap(),
        UploadReservationBeginOutcome::Reserved
    );
    assert!(database.set_share_active(share_id, false).unwrap());
    assert!(database.set_share_active(share_id, true).unwrap());
    assert_eq!(database.active_upload_reservations(share_id).unwrap(), 0);
    assert_eq!(
        database
            .extend_upload_reservation("before-reactivation", 1)
            .unwrap(),
        UploadReservationExtendOutcome::ShareUnavailable
    );
    assert_eq!(
        database
            .begin_upload_reservation("stale-reactivation", share_id, 0)
            .unwrap(),
        UploadReservationBeginOutcome::ShareUnavailable
    );

    let before_password_epoch = database
        .share_by_token("epoch-share")
        .unwrap()
        .unwrap()
        .upload_policy_epoch;
    assert_eq!(
        database
            .begin_upload_reservation("before-password", share_id, before_password_epoch)
            .unwrap(),
        UploadReservationBeginOutcome::Reserved
    );
    assert!(database
        .set_share_password(share_id, Some("rotated-password-hash"))
        .unwrap());
    assert_eq!(
        database
            .commit_upload_reservation("before-password", 0)
            .unwrap(),
        UploadReservationCommitOutcome::ShareUnavailable
    );
    assert_eq!(
        database
            .begin_upload_reservation("stale-password", share_id, before_password_epoch)
            .unwrap(),
        UploadReservationBeginOutcome::ShareUnavailable
    );

    let before_strategy_epoch = database
        .share_by_token("epoch-share")
        .unwrap()
        .unwrap()
        .upload_policy_epoch;
    assert_eq!(
        database
            .begin_upload_reservation("before-strategy", share_id, before_strategy_epoch)
            .unwrap(),
        UploadReservationBeginOutcome::Reserved
    );
    assert_eq!(
        database
            .update_share_controls(
                share_id,
                None,
                Some(&UploadConflictStrategy::OverwriteAllowed),
                None,
            )
            .unwrap(),
        ShareControlsUpdateOutcome::Updated
    );
    assert_eq!(
        database
            .extend_upload_reservation("before-strategy", 1)
            .unwrap(),
        UploadReservationExtendOutcome::ShareUnavailable
    );

    let before_quota_epoch = database
        .share_by_token("epoch-share")
        .unwrap()
        .unwrap()
        .upload_policy_epoch;
    assert_eq!(
        database
            .begin_upload_reservation("before-quota", share_id, before_quota_epoch)
            .unwrap(),
        UploadReservationBeginOutcome::Reserved
    );
    assert_eq!(
        database
            .update_share_controls(share_id, None, None, Some((2_000, 20)))
            .unwrap(),
        ShareControlsUpdateOutcome::Updated
    );
    assert_eq!(
        database
            .commit_upload_reservation("before-quota", 0)
            .unwrap(),
        UploadReservationCommitOutcome::ShareUnavailable
    );

    let current_epoch = database
        .share_by_token("epoch-share")
        .unwrap()
        .unwrap()
        .upload_policy_epoch;
    assert_eq!(
        database
            .begin_upload_reservation("current-policy", share_id, current_epoch)
            .unwrap(),
        UploadReservationBeginOutcome::Reserved
    );
    assert_eq!(
        database
            .extend_upload_reservation("current-policy", 1)
            .unwrap(),
        UploadReservationExtendOutcome::Extended
    );
    assert_eq!(
        database
            .commit_upload_reservation("current-policy", 1)
            .unwrap(),
        UploadReservationCommitOutcome::Committed
    );
}

#[test]
fn stale_upload_quota_update_does_not_partially_change_strategy() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share_with_upload_limits(
            "atomic-share",
            None,
            "folder",
            true,
            &Permission::UploadOnly,
            None,
            None,
            Some(5),
            Some(20),
            Some(3),
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    // These reservations represent concurrent uploads started after the UI
    // read its share snapshot but before it submitted strategy plus limits.
    for token in ["upload-one", "upload-two"] {
        database
            .begin_upload_reservation(token, share_id, 0)
            .unwrap();
        database.extend_upload_reservation(token, 5).unwrap();
    }

    assert_eq!(
        database
            .update_share_controls(
                share_id,
                None,
                Some(&UploadConflictStrategy::OverwriteAllowed),
                Some((5, 1)),
            )
            .unwrap(),
        ShareControlsUpdateOutcome::QuotaConflict
    );
    let share = database.share_by_token("atomic-share").unwrap().unwrap();
    assert_eq!(
        share.upload_conflict_strategy,
        UploadConflictStrategy::Reject
    );
    assert_eq!(share.max_upload_total_size, Some(20));
    assert_eq!(share.max_upload_files, Some(3));

    assert!(database.cancel_upload_reservation("upload-two").unwrap());
    assert_eq!(
        database
            .update_share_controls(
                share_id,
                None,
                Some(&UploadConflictStrategy::OverwriteAllowed),
                Some((5, 1)),
            )
            .unwrap(),
        ShareControlsUpdateOutcome::Updated
    );
    let share = database.share_by_token("atomic-share").unwrap().unwrap();
    assert_eq!(
        share.upload_conflict_strategy,
        UploadConflictStrategy::OverwriteAllowed
    );
    assert_eq!(share.max_upload_total_size, Some(5));
    assert_eq!(share.max_upload_files, Some(1));

    database
        .conn()
        .execute(
            "UPDATE public_upload_reservations SET expires_at=?2 WHERE token_hash=?1",
            params![
                token_hash("upload-one"),
                (Utc::now() - Duration::seconds(1)).to_rfc3339()
            ],
        )
        .unwrap();
    assert_eq!(
        database
            .update_share_controls(share_id, None, None, Some((1, 1)))
            .unwrap(),
        ShareControlsUpdateOutcome::Updated
    );
    let share = database.share_by_token("atomic-share").unwrap().unwrap();
    assert_eq!(share.max_upload_total_size, Some(1));
    assert_eq!(share.max_upload_files, Some(1));
}

#[test]
fn invalid_atomic_share_insert_leaves_no_row() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    assert!(database
        .create_share_with_upload_limits(
            "invalid-share",
            None,
            "folder",
            true,
            &Permission::UploadOnly,
            None,
            None,
            Some(10),
            Some(9),
            Some(2),
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .is_err());
    assert!(database.share_by_token("invalid-share").unwrap().is_none());
}

#[test]
fn preview_sessions_are_hashed_share_and_path_bound() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share(
            "share",
            None,
            "folder",
            true,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    database
        .create_preview_session(
            "preview-secret",
            "preview-owner",
            share_id,
            "folder/image.png",
            Utc::now() + chrono::Duration::minutes(5),
        )
        .unwrap();
    assert!(database
        .preview_session("preview-secret", share_id, "folder/image.png")
        .unwrap());
    assert!(!database
        .preview_session("preview-secret", share_id, "folder/other.png")
        .unwrap());
    assert!(!database
        .preview_session("wrong", share_id, "folder/image.png")
        .unwrap());
    let stored: String = database
        .conn()
        .query_row(
            "SELECT token_hash FROM public_preview_sessions",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_ne!(stored, "preview-secret");
}

#[test]
fn preview_sessions_are_expiry_cleaned_and_bounded_per_share_path() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share(
            "bounded-preview-share",
            None,
            "folder",
            true,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let path = "folder/image.png";
    for index in 0..MAX_ACTIVE_PREVIEW_SESSIONS_PER_RESOURCE {
        database
            .create_preview_session(
                &format!("owner-b-preview-{index}"),
                "owner-b",
                share_id,
                path,
                Utc::now() + Duration::minutes(30 + index),
            )
            .unwrap();
    }
    for index in 0..10 {
        database
            .create_preview_session(
                &format!("preview-{index}"),
                "owner-a",
                share_id,
                path,
                Utc::now() + Duration::minutes(10 + index),
            )
            .unwrap();
    }

    let active: u64 = database
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM public_preview_sessions
                 WHERE share_id=?1 AND relative_path=?2
                   AND owner_key_hash=?3 AND expires_at>?4",
            params![
                share_id,
                path,
                token_hash("owner-a"),
                Utc::now().to_rfc3339()
            ],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(active, MAX_ACTIVE_PREVIEW_SESSIONS_PER_RESOURCE as u64);
    assert!(!database
        .preview_session("preview-0", share_id, path)
        .unwrap());
    assert!(!database
        .preview_session("preview-1", share_id, path)
        .unwrap());
    assert!(database
        .preview_session("preview-9", share_id, path)
        .unwrap());
    for index in 0..MAX_ACTIVE_PREVIEW_SESSIONS_PER_RESOURCE {
        assert!(database
            .preview_session(&format!("owner-b-preview-{index}"), share_id, path)
            .unwrap());
    }

    database
        .conn()
        .execute(
            "INSERT INTO public_preview_sessions(
                     token_hash,share_id,relative_path,expires_at,owner_key_hash
                 ) VALUES(?1,?2,?3,?4,?5)",
            params![
                token_hash("expired-preview"),
                share_id,
                "folder/expired.png",
                (Utc::now() - Duration::minutes(1)).to_rfc3339(),
                token_hash("owner-a")
            ],
        )
        .unwrap();
    database
        .create_preview_session(
            "other-path",
            "owner-a",
            share_id,
            "folder/other.png",
            Utc::now() + Duration::minutes(5),
        )
        .unwrap();
    let expired: u64 = database
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM public_preview_sessions WHERE expires_at<=?1",
            [Utc::now().to_rfc3339()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(expired, 0);
    let index_exists: bool = database
        .conn()
        .query_row(
            "SELECT EXISTS(
                     SELECT 1 FROM sqlite_schema
                     WHERE type='index' AND name='idx_preview_share_path_owner'
                 )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(index_exists);
}

#[test]
fn preview_sessions_are_bounded_per_owner_and_share_without_cross_owner_eviction() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share(
            "owner-bounded-preview-share",
            None,
            "folder",
            true,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let expires = Utc::now() + Duration::hours(1);
    assert_eq!(
        database
            .create_preview_session(
                "foreign-preview",
                "owner-b",
                share_id,
                "folder/foreign.png",
                expires,
            )
            .unwrap(),
        PreviewSessionCreateOutcome::Created
    );
    for index in 0..56 {
        assert_eq!(
            database
                .create_preview_session(
                    &format!("owner-a-path-{index}"),
                    "owner-a",
                    share_id,
                    &format!("folder/path-{index}.png"),
                    expires,
                )
                .unwrap(),
            PreviewSessionCreateOutcome::Created
        );
    }
    for index in 0..MAX_ACTIVE_PREVIEW_SESSIONS_PER_RESOURCE {
        assert_eq!(
            database
                .create_preview_session(
                    &format!("owner-a-bucket-{index}"),
                    "owner-a",
                    share_id,
                    "folder/bucket.png",
                    expires + Duration::minutes(index),
                )
                .unwrap(),
            PreviewSessionCreateOutcome::Created
        );
    }

    assert_eq!(
        database
            .create_preview_session(
                "owner-a-over-capacity",
                "owner-a",
                share_id,
                "folder/new-path.png",
                expires,
            )
            .unwrap(),
        PreviewSessionCreateOutcome::OwnerCapacityReached
    );
    assert!(database
        .preview_session("foreign-preview", share_id, "folder/foreign.png")
        .unwrap());
    assert_eq!(
        database
            .create_preview_session(
                "owner-a-bucket-replacement",
                "owner-a",
                share_id,
                "folder/bucket.png",
                expires + Duration::hours(2),
            )
            .unwrap(),
        PreviewSessionCreateOutcome::Created
    );
    assert!(!database
        .preview_session("owner-a-bucket-0", share_id, "folder/bucket.png")
        .unwrap());
    let owner_rows: i64 = database
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM public_preview_sessions
                 WHERE share_id=?1 AND owner_key_hash=?2",
            params![share_id, token_hash("owner-a")],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(owner_rows, MAX_ACTIVE_PREVIEW_SESSIONS_PER_OWNER_SHARE);
}

#[test]
fn preview_sessions_enforce_per_share_capacity_without_cross_share_eviction() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let create_share = |token: &str, path: &str| {
        database
            .create_share(
                token,
                None,
                path,
                true,
                &Permission::DownloadOnly,
                None,
                None,
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap()
    };
    let full_share_id = create_share("full-preview-share", "full-folder");
    let isolated_share_id = create_share("isolated-preview-share", "isolated-folder");
    let expires = (Utc::now() + Duration::hours(1)).to_rfc3339();
    {
        let mut connection = database.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        {
            let mut insert = transaction
                .prepare(
                    "INSERT INTO public_preview_sessions(
                             token_hash,share_id,relative_path,expires_at,owner_key_hash
                         ) VALUES(?1,?2,'full-folder/image.png',?3,?4)",
                )
                .unwrap();
            for index in 0..MAX_ACTIVE_PREVIEW_SESSIONS_PER_SHARE {
                insert
                    .execute(params![
                        format!("share-cap-token-{index}"),
                        full_share_id,
                        expires,
                        format!("share-cap-owner-{index}")
                    ])
                    .unwrap();
            }
        }
        transaction.commit().unwrap();
    }

    assert_eq!(
        database
            .create_preview_session(
                "share-over-capacity",
                "new-owner",
                full_share_id,
                "full-folder/new.png",
                Utc::now() + Duration::hours(1),
            )
            .unwrap(),
        PreviewSessionCreateOutcome::ShareCapacityReached
    );
    let retained_full_share_row: bool = database
        .conn()
        .query_row(
            "SELECT EXISTS(
                     SELECT 1 FROM public_preview_sessions
                     WHERE token_hash='share-cap-token-0'
                 )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(retained_full_share_row);
    assert_eq!(
        database
            .create_preview_session(
                "isolated-share-preview",
                "new-owner",
                isolated_share_id,
                "isolated-folder/image.png",
                Utc::now() + Duration::hours(1),
            )
            .unwrap(),
        PreviewSessionCreateOutcome::Created
    );
    let full_share_rows: i64 = database
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM public_preview_sessions WHERE share_id=?1",
            [full_share_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(full_share_rows, MAX_ACTIVE_PREVIEW_SESSIONS_PER_SHARE);
    assert!(database
        .preview_session(
            "isolated-share-preview",
            isolated_share_id,
            "isolated-folder/image.png"
        )
        .unwrap());
}

#[test]
fn preview_sessions_enforce_global_capacity_after_expiry_purge() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let target_share_id = database
        .create_share(
            "globally-bounded-preview-share",
            None,
            "folder",
            true,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let source_share_ids: Vec<i64> = (0..20)
        .map(|index| {
            database
                .create_share(
                    &format!("global-preview-source-{index}"),
                    None,
                    &format!("source-folder-{index}"),
                    true,
                    &Permission::DownloadOnly,
                    None,
                    None,
                    None,
                    1,
                    None,
                    &UploadConflictStrategy::Reject,
                )
                .unwrap()
        })
        .collect();
    let expires = (Utc::now() + Duration::hours(1)).to_rfc3339();
    {
        let mut connection = database.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        {
            let mut insert = transaction
                .prepare(
                    "INSERT INTO public_preview_sessions(
                             token_hash,share_id,relative_path,expires_at,owner_key_hash
                         ) VALUES(?1,?2,'folder/image.png',?3,?4)",
                )
                .unwrap();
            for index in 0..MAX_ACTIVE_PREVIEW_SESSIONS_GLOBAL {
                let source_share_id = source_share_ids[index as usize % source_share_ids.len()];
                insert
                    .execute(params![
                        format!("global-token-{index}"),
                        source_share_id,
                        expires,
                        format!("global-owner-{index}")
                    ])
                    .unwrap();
            }
        }
        transaction.commit().unwrap();
    }

    assert_eq!(
        database
            .create_preview_session(
                "global-over-capacity",
                "new-owner",
                target_share_id,
                "folder/new.png",
                Utc::now() + Duration::hours(1),
            )
            .unwrap(),
        PreviewSessionCreateOutcome::GlobalCapacityReached
    );
    let retained_foreign_row: bool = database
        .conn()
        .query_row(
            "SELECT EXISTS(
                     SELECT 1 FROM public_preview_sessions
                     WHERE token_hash='global-token-0'
                 )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(retained_foreign_row);

    let expired = (Utc::now() - Duration::minutes(1)).to_rfc3339();
    let updated = database
        .conn()
        .execute(
            "UPDATE public_preview_sessions SET expires_at=?2 WHERE token_hash=?1",
            params!["global-token-0", expired],
        )
        .unwrap();
    assert_eq!(updated, 1);
    let now = Utc::now().to_rfc3339();
    let expired_rows: i64 = database
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM public_preview_sessions WHERE expires_at<=?1",
            [&now],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(expired_rows, 1, "expired={expired};now={now}");
    assert_eq!(
        database
            .create_preview_session(
                "global-after-expiry",
                "new-owner",
                target_share_id,
                "folder/new.png",
                Utc::now() + Duration::hours(1),
            )
            .unwrap(),
        PreviewSessionCreateOutcome::Created
    );
    let global_rows: i64 = database
        .conn()
        .query_row("SELECT COUNT(*) FROM public_preview_sessions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(global_rows, MAX_ACTIVE_PREVIEW_SESSIONS_GLOBAL);
}

#[test]
fn transfer_grant_reserves_and_counts_once_across_request_leases() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share(
            "share",
            None,
            "file.bin",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();

    assert_eq!(
        {
            let counts = database.current_transfer_monthly_counts().unwrap();
            counts.download + counts.zip_download + counts.preview
        },
        0
    );

    assert_eq!(
        database
            .check_transfer_availability("client", share_id, "file.bin", "download")
            .unwrap(),
        TransferAvailabilityOutcome::Available
    );

    assert_eq!(
        database
            .begin_transfer_lease("client", "lease-one", share_id, "file.bin", "download")
            .unwrap(),
        TransferLeaseBeginOutcome::NewLease
    );
    assert_eq!(
        database
            .begin_transfer_lease("client", "lease-two", share_id, "file.bin", "download")
            .unwrap(),
        TransferLeaseBeginOutcome::NewLease
    );
    assert_eq!(database.active_transfer_reservations(share_id).unwrap(), 1);
    assert_eq!(
        database
            .check_transfer_availability("client", share_id, "file.bin", "download")
            .unwrap(),
        TransferAvailabilityOutcome::Available
    );
    assert_eq!(
        database
            .check_transfer_availability("other", share_id, "file.bin", "download")
            .unwrap(),
        TransferAvailabilityOutcome::LimitReached
    );
    assert_eq!(
        database
            .begin_transfer_lease("other", "blocked", share_id, "file.bin", "download")
            .unwrap(),
        TransferLeaseBeginOutcome::LimitReached
    );
    assert_eq!(
        database.complete_transfer_lease("lease-one").unwrap(),
        TransferLeaseCompleteOutcome::Counted
    );
    assert_eq!(
        database
            .share_by_token("share")
            .unwrap()
            .unwrap()
            .download_count,
        1
    );
    assert_eq!(
        database.current_transfer_monthly_counts().unwrap().download,
        1
    );
    assert_eq!(
        database.complete_transfer_lease("lease-two").unwrap(),
        TransferLeaseCompleteOutcome::AlreadyCounted
    );
    assert_eq!(
        database.current_transfer_monthly_counts().unwrap().download,
        1
    );
    assert_eq!(
        database
            .check_transfer_availability("client", share_id, "file.bin", "download")
            .unwrap(),
        TransferAvailabilityOutcome::AlreadyCounted
    );
    assert_eq!(
        database
            .check_transfer_availability("other", share_id, "file.bin", "download")
            .unwrap(),
        TransferAvailabilityOutcome::LimitReached
    );
    assert_eq!(
        database
            .share_by_token("share")
            .unwrap()
            .unwrap()
            .download_count,
        1
    );
    let counted_expiry: String = database
        .conn()
        .query_row(
            "SELECT expires_at FROM public_transfer_grants WHERE share_id=?1",
            [share_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        database
            .begin_transfer_lease("client", "resume", share_id, "file.bin", "download")
            .unwrap(),
        TransferLeaseBeginOutcome::AlreadyCounted
    );
    let resumed_expiry: String = database
        .conn()
        .query_row(
            "SELECT expires_at FROM public_transfer_grants WHERE share_id=?1",
            [share_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(resumed_expiry, counted_expiry);
    assert_eq!(
        database.complete_transfer_lease("resume").unwrap(),
        TransferLeaseCompleteOutcome::AlreadyCounted
    );
    assert_eq!(
        database.current_transfer_monthly_counts().unwrap().download,
        1
    );
    assert_eq!(
        database
            .begin_transfer_lease("client", "new-resource", share_id, "other.bin", "download")
            .unwrap(),
        TransferLeaseBeginOutcome::LimitReached
    );
}

#[test]
fn transfer_required_audit_uses_grant_values_and_rolls_back_on_failure() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share(
            "share",
            None,
            "file.bin",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    assert_eq!(
        database
            .begin_transfer_lease("client", "lease", share_id, "file.bin", "download")
            .unwrap(),
        TransferLeaseBeginOutcome::NewLease
    );
    database
        .conn()
        .execute_batch(
            "CREATE TRIGGER fail_transfer_audit
                 BEFORE INSERT ON audit
                 WHEN NEW.action='download'
                 BEGIN SELECT RAISE(FAIL, 'injected audit failure'); END;",
        )
        .unwrap();
    let context = AuditContext::new("public", Some("192.0.2.44".into()));

    let error = database
        .complete_transfer_lease_and_audit(
            "lease",
            &context,
            "caller_supplied_wrong_action",
            share_id + 999,
        )
        .unwrap_err();
    assert!(is_audit_unavailable(&error));
    assert_eq!(
        database
            .share_by_token("share")
            .unwrap()
            .unwrap()
            .download_count,
        0
    );
    assert_eq!(database.active_transfer_reservations(share_id).unwrap(), 1);

    database
        .conn()
        .execute_batch("DROP TRIGGER fail_transfer_audit")
        .unwrap();
    assert_eq!(
        database
            .complete_transfer_lease_and_audit(
                "lease",
                &context,
                "caller_supplied_wrong_action",
                share_id + 999,
            )
            .unwrap(),
        TransferLeaseCompleteOutcome::Counted
    );
    let events = database.list_audit(Some("download"), 10, 0).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].object_id.as_deref(),
        Some(share_id.to_string().as_str())
    );
    assert_eq!(events[0].actor, "public");
}

#[test]
fn completed_transfers_increment_each_supported_monthly_action() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share(
            "share",
            None,
            "folder",
            true,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();

    for (index, action) in ["download", "zip_download", "preview"]
        .into_iter()
        .enumerate()
    {
        let session = format!("client-{index}");
        let lease = format!("lease-{index}");
        let resource = format!("resource-{index}");
        assert_eq!(
            database
                .begin_transfer_lease(&session, &lease, share_id, &resource, action)
                .unwrap(),
            TransferLeaseBeginOutcome::NewLease
        );
        assert_eq!(
            database.complete_transfer_lease(&lease).unwrap(),
            TransferLeaseCompleteOutcome::Counted
        );
    }

    let counts = database.current_transfer_monthly_counts().unwrap();
    assert_eq!(counts.month, current_utc_month());
    assert_eq!(counts.download, 1);
    assert_eq!(counts.zip_download, 1);
    assert_eq!(counts.preview, 1);
    assert_eq!(counts.download + counts.zip_download + counts.preview, 3);
    assert_eq!(
        {
            let counts = database.transfer_monthly_counts("2000-01").unwrap();
            counts.download + counts.zip_download + counts.preview
        },
        0
    );
    assert!(database.transfer_monthly_counts("2026-00").is_err());
    assert!(database.transfer_monthly_counts("2026-1").is_err());
}

#[test]
fn monthly_count_failure_rolls_back_the_counted_transfer() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share(
            "share",
            None,
            "file.bin",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    assert_eq!(
        database
            .begin_transfer_lease("client", "lease", share_id, "file.bin", "download")
            .unwrap(),
        TransferLeaseBeginOutcome::NewLease
    );
    database
        .conn()
        .execute("DROP TABLE transfer_monthly_counts", [])
        .unwrap();

    assert!(database.complete_transfer_lease("lease").is_err());
    assert_eq!(
        database
            .share_by_token("share")
            .unwrap()
            .unwrap()
            .download_count,
        0
    );
    let counted: i64 = database
        .conn()
        .query_row(
            "SELECT counted FROM public_transfer_grants WHERE share_id=?1",
            [share_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(counted, 0);
}

#[test]
fn transfer_cancel_releases_only_the_final_pending_lease() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share(
            "share",
            None,
            "file.bin",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    database
        .begin_transfer_lease("client", "one", share_id, "file.bin", "download")
        .unwrap();
    database
        .begin_transfer_lease("client", "two", share_id, "file.bin", "download")
        .unwrap();
    assert_eq!(
        database.cancel_transfer_lease("one").unwrap(),
        TransferLeaseCancelOutcome::Cancelled
    );
    assert_eq!(database.active_transfer_reservations(share_id).unwrap(), 1);
    assert_eq!(
        database.cancel_transfer_lease("two").unwrap(),
        TransferLeaseCancelOutcome::Cancelled
    );
    assert_eq!(database.active_transfer_reservations(share_id).unwrap(), 0);
    assert_eq!(
        database
            .begin_transfer_lease("other", "replacement", share_id, "file.bin", "download")
            .unwrap(),
        TransferLeaseBeginOutcome::NewLease
    );
    assert_eq!(
        {
            let counts = database.current_transfer_monthly_counts().unwrap();
            counts.download + counts.zip_download + counts.preview
        },
        0
    );
}

#[test]
fn concurrent_transfer_grants_cannot_overbook_the_limit() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share(
            "share",
            None,
            "folder",
            true,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for (client, lease, resource) in [
        ("client-a", "lease-a", "folder/a"),
        ("client-b", "lease-b", "folder/b"),
    ] {
        let database = database.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            database
                .begin_transfer_lease(client, lease, share_id, resource, "download")
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
            .filter(|outcome| **outcome == TransferLeaseBeginOutcome::NewLease)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == TransferLeaseBeginOutcome::LimitReached)
            .count(),
        1
    );
    assert_eq!(database.active_transfer_reservations(share_id).unwrap(), 1);
}

#[test]
fn transfer_heartbeat_and_expiry_are_enforced() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share(
            "share",
            None,
            "file.bin",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    database
        .begin_transfer_lease("client", "lease", share_id, "file.bin", "download")
        .unwrap();
    assert_eq!(
        database.heartbeat_transfer_lease("lease").unwrap(),
        TransferLeaseHeartbeatOutcome::Extended
    );
    database
        .conn()
        .execute(
            "UPDATE public_transfer_leases SET expires_at='2000-01-01T00:00:00Z'",
            [],
        )
        .unwrap();
    assert_eq!(
        database.heartbeat_transfer_lease("lease").unwrap(),
        TransferLeaseHeartbeatOutcome::NotFound
    );
    assert_eq!(database.active_transfer_reservations(share_id).unwrap(), 0);
}

#[test]
fn transfer_heartbeat_cannot_extend_lease_past_absolute_lifetime() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share(
            "share",
            None,
            "file.bin",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    database
        .begin_transfer_lease("client", "lease", share_id, "file.bin", "download")
        .unwrap();
    let older_than_absolute_limit =
        Utc::now() - Duration::seconds(TRANSFER_LEASE_MAX_LIFETIME_SECONDS + 1);
    {
        let connection = database.conn();
        connection
            .execute(
                "UPDATE public_transfer_leases
                     SET created_at=?1,expires_at='2000-01-01T00:00:00Z'",
                [older_than_absolute_limit.to_rfc3339()],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE public_transfer_grants SET expires_at='2099-01-01T00:00:00Z'",
                [],
            )
            .unwrap();
    }

    assert_eq!(
        database.heartbeat_transfer_lease("lease").unwrap(),
        TransferLeaseHeartbeatOutcome::CappedAndCounted
    );
    assert_eq!(database.active_transfer_reservations(share_id).unwrap(), 0);
    assert_eq!(
        database
            .share_by_token("share")
            .unwrap()
            .unwrap()
            .download_count,
        1
    );
    assert_eq!(
        database.complete_transfer_lease("lease").unwrap(),
        TransferLeaseCompleteOutcome::NotFound
    );
    assert_eq!(
        database
            .begin_transfer_lease("other", "other-lease", share_id, "file.bin", "download")
            .unwrap(),
        TransferLeaseBeginOutcome::LimitReached
    );
}

#[test]
fn capped_transfer_heartbeat_rolls_back_with_required_audit_and_derives_grant_event() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share(
            "heartbeat-audit-share",
            None,
            "archive.zip",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    database
        .begin_transfer_lease(
            "client",
            "heartbeat-audit-lease",
            share_id,
            "archive.zip",
            "zip_download",
        )
        .unwrap();
    let older_than_absolute_limit =
        Utc::now() - Duration::seconds(TRANSFER_LEASE_MAX_LIFETIME_SECONDS + 1);
    database
        .conn()
        .execute_batch(&format!(
            "UPDATE public_transfer_leases
                 SET created_at='{}',expires_at='2099-01-01T00:00:00Z';
             UPDATE public_transfer_grants SET expires_at='2099-01-01T00:00:00Z';
             CREATE TRIGGER fail_capped_transfer_audit
             BEFORE INSERT ON audit
             BEGIN SELECT RAISE(FAIL, 'injected capped transfer audit failure'); END;",
            older_than_absolute_limit.to_rfc3339()
        ))
        .unwrap();
    let context = AuditContext::new("public", Some("198.51.100.25".into()));

    let error = database
        .heartbeat_transfer_lease_and_audit("heartbeat-audit-lease", &context)
        .unwrap_err();
    assert!(is_audit_unavailable(&error));
    assert_eq!(
        database
            .share_by_token("heartbeat-audit-share")
            .unwrap()
            .unwrap()
            .download_count,
        0
    );
    assert_eq!(database.active_transfer_reservations(share_id).unwrap(), 1);
    assert_eq!(
        database
            .current_transfer_monthly_counts()
            .unwrap()
            .zip_download,
        0
    );
    assert_eq!(database.count_audit(None).unwrap(), 0);

    database
        .conn()
        .execute_batch("DROP TRIGGER fail_capped_transfer_audit")
        .unwrap();
    assert_eq!(
        database
            .heartbeat_transfer_lease_and_audit("heartbeat-audit-lease", &context)
            .unwrap(),
        TransferLeaseHeartbeatOutcome::CappedAndCounted
    );
    let event = database
        .list_audit(Some("zip_download"), 1, 0)
        .unwrap()
        .pop()
        .unwrap();
    let share_id = share_id.to_string();
    assert_eq!(event.actor, "public");
    assert_eq!(event.object_id.as_deref(), Some(share_id.as_str()));
    assert_eq!(event.detail.as_deref(), Some("capped transfer session"));
    assert_eq!(event.client_ip.as_deref(), Some("198.51.100.25"));
}

#[test]
fn webauthn_credentials_are_scoped_unique_and_mutable() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    database.create_admin("other", "hash", "secret").unwrap();

    let id = database
        .add_admin_webauthn_credential(1, "Primary YubiKey", "credential-a", "{\"v\":1}")
        .unwrap();
    let rows = database.admin_webauthn_credentials(1).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, id);
    assert_eq!(rows[0].label, "Primary YubiKey");
    assert!(rows[0].last_used_at.is_none());
    assert!(database.admin_webauthn_credentials(2).unwrap().is_empty());
    assert!(database
        .add_admin_webauthn_credential(1, "", "credential-empty-label", "{}")
        .is_err());
    assert!(database
        .add_admin_webauthn_credential(1, &"x".repeat(81), "credential-long-label", "{}")
        .is_err());

    assert!(database
        .add_admin_webauthn_credential(2, "Duplicate", "credential-a", "{}")
        .is_err());
    assert!(!database
        .update_admin_webauthn_credential(id, 2, "{\"v\":2}")
        .unwrap());
    assert!(database
        .update_admin_webauthn_credential(id, 1, "{\"v\":2}")
        .unwrap());
    let rows = database.admin_webauthn_credentials(1).unwrap();
    assert_eq!(rows[0].credential_blob, b"{\"v\":2}");
    assert!(rows[0].last_used_at.is_some());

    assert!(!database.delete_admin_webauthn_credential(id, 2).unwrap());
    assert!(database.delete_admin_webauthn_credential(id, 1).unwrap());
    assert!(database.admin_webauthn_credentials(1).unwrap().is_empty());

    let first = database
        .add_admin_webauthn_credential(1, "Primary", "credential-c", "{}")
        .unwrap();
    database
        .add_admin_webauthn_credential(1, "Backup", "credential-d", "{}")
        .unwrap();
    assert!(!database.delete_admin_webauthn_credential(first, 1).unwrap());
    database
        .add_admin_webauthn_credential(1, "Replacement", "credential-e", "{}")
        .unwrap();
    assert!(database.delete_admin_webauthn_credential(first, 1).unwrap());
    assert_eq!(database.admin_webauthn_credentials(1).unwrap().len(), 2);

    database
        .add_admin_webauthn_credential(2, "Backup", "credential-b", "{}")
        .unwrap();
    database
        .conn()
        .execute("DELETE FROM admins WHERE id=2", [])
        .unwrap();
    assert!(database.admin_webauthn_credentials(2).unwrap().is_empty());
}

#[test]
fn security_mutation_webauthn_deletion_consumes_totp_and_audits_atomically() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    database
        .create_session(
            "authorized-session",
            1,
            "csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    assert!(database.verify_mfa("authorized-session").unwrap());
    database
        .create_session("other-session", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    assert!(database.verify_mfa("other-session").unwrap());
    let first = database
        .add_admin_webauthn_credential(1, "First", "credential-a", "{}")
        .unwrap();
    let second = database
        .add_admin_webauthn_credential(1, "Second", "credential-b", "{}")
        .unwrap();
    let third = database
        .add_admin_webauthn_credential(1, "Third", "credential-c", "{}")
        .unwrap();
    let delete = |session_token, credential_id, step, client_ip| {
        database.delete_admin_webauthn_credential_with_totp(
            session_token,
            credential_id,
            1,
            "hash",
            1,
            step,
            client_ip,
        )
    };

    assert_eq!(
        delete("authorized-session", first, 42, Some("203.0.113.40")).unwrap(),
        AdminWebauthnCredentialDeletionOutcome::Deleted
    );
    assert!(database.session("authorized-session").unwrap().is_none());
    assert!(database.session("other-session").unwrap().is_none());
    let audit = database
        .list_audit(Some("webauthn_credential_deleted"), 10, 0)
        .unwrap();
    assert_eq!(audit.len(), 1);
    let first_object = first.to_string();
    assert_eq!(audit[0].object_id.as_deref(), Some(first_object.as_str()));
    assert_eq!(audit[0].client_ip.as_deref(), Some("203.0.113.40"));

    database
        .create_session("second-session", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    assert!(database.verify_mfa("second-session").unwrap());

    assert_eq!(
        delete("second-session", second, 42, None).unwrap(),
        AdminWebauthnCredentialDeletionOutcome::TotpRejected
    );
    assert_eq!(
        delete("second-session", second, 43, None).unwrap(),
        AdminWebauthnCredentialDeletionOutcome::NotDeleted
    );
    database
        .add_admin_webauthn_credential(1, "Fourth", "credential-d", "{}")
        .unwrap();

    assert_eq!(
        delete("second-session", second, 43, None).unwrap(),
        AdminWebauthnCredentialDeletionOutcome::Deleted
    );
    database
        .add_admin_webauthn_credential(1, "Fifth", "credential-e", "{}")
        .unwrap();

    database
        .create_session("third-session", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    assert!(database.verify_mfa("third-session").unwrap());

    database
        .conn()
        .execute_batch(
            "CREATE TRIGGER fail_webauthn_delete_audit
                 BEFORE INSERT ON audit
                 WHEN NEW.action='webauthn_credential_deleted'
                 BEGIN
                     SELECT RAISE(ABORT, 'forced audit failure');
                 END;",
        )
        .unwrap();
    assert!(delete("third-session", third, 44, None).is_err());
    assert_eq!(database.admin_webauthn_credentials(1).unwrap().len(), 3);
    database
        .conn()
        .execute_batch("DROP TRIGGER fail_webauthn_delete_audit")
        .unwrap();

    assert_eq!(
        delete("third-session", third, 44, None).unwrap(),
        AdminWebauthnCredentialDeletionOutcome::Deleted
    );
    assert_eq!(
        database
            .count_audit(Some("webauthn_credential_deleted"))
            .unwrap(),
        3
    );
}

#[test]
fn security_mutation_webauthn_deletion_rejects_stale_credentials_and_session() {
    let database = Database::open(":memory:").unwrap();
    database
        .create_admin("admin", "original-hash", "original-secret")
        .unwrap();
    database
        .create_session("stale-session", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    assert!(database.verify_mfa("stale-session").unwrap());
    let first = database
        .add_admin_webauthn_credential(1, "First", "credential-a", "{}")
        .unwrap();
    database
        .add_admin_webauthn_credential(1, "Second", "credential-b", "{}")
        .unwrap();
    database
        .add_admin_webauthn_credential(1, "Third", "credential-c", "{}")
        .unwrap();

    assert_eq!(
        database
            .delete_admin_webauthn_credential_with_totp(
                "stale-session",
                first,
                1,
                "wrong-hash",
                1,
                42,
                None,
            )
            .unwrap(),
        AdminWebauthnCredentialDeletionOutcome::ReauthenticationRejected
    );
    assert_eq!(
        database
            .delete_admin_webauthn_credential_with_totp(
                "stale-session",
                first,
                1,
                "original-hash",
                2,
                42,
                None,
            )
            .unwrap(),
        AdminWebauthnCredentialDeletionOutcome::ReauthenticationRejected
    );

    assert!(database
        .reset_admin_password(1, "replacement-hash")
        .unwrap());
    assert_eq!(
        database
            .delete_admin_webauthn_credential_with_totp(
                "stale-session",
                first,
                1,
                "original-hash",
                1,
                42,
                None,
            )
            .unwrap(),
        AdminWebauthnCredentialDeletionOutcome::ReauthenticationRejected
    );
    assert_eq!(database.admin_webauthn_credentials(1).unwrap().len(), 3);
    assert_eq!(
        database
            .count_audit(Some("webauthn_credential_deleted"))
            .unwrap(),
        0
    );

    database
        .create_session(
            "replacement-session",
            1,
            "csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    assert!(database.verify_mfa("replacement-session").unwrap());
    assert_eq!(
        database
            .delete_admin_webauthn_credential_with_totp(
                "replacement-session",
                first,
                1,
                "replacement-hash",
                1,
                42,
                None,
            )
            .unwrap(),
        AdminWebauthnCredentialDeletionOutcome::Deleted
    );
}

#[test]
fn totp_setting_requires_two_keys_and_protects_key_only_accounts() {
    let database = Database::open(":memory:").unwrap();
    database
        .create_admin("admin", "password-hash", "totp-secret")
        .unwrap();
    assert!(database.admin("admin").unwrap().unwrap().totp_enabled);
    database
        .create_session(
            "authorized-session",
            1,
            "csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    assert!(database.verify_mfa("authorized-session").unwrap());

    assert_eq!(
        database
            .set_admin_totp_enabled_with_reauthentication(
                "authorized-session",
                1,
                "password-hash",
                1,
                false,
                Some(41),
                None,
            )
            .unwrap(),
        AdminTotpSettingOutcome::InsufficientSecurityKeys
    );

    let first = database
        .add_admin_webauthn_credential(1, "Primary", "credential-a", "{}")
        .unwrap();
    database
        .add_admin_webauthn_credential(1, "Backup", "credential-b", "{}")
        .unwrap();
    assert_eq!(
        database
            .set_admin_totp_enabled_with_reauthentication(
                "authorized-session",
                1,
                "password-hash",
                1,
                false,
                None,
                None,
            )
            .unwrap(),
        AdminTotpSettingOutcome::TotpRejected
    );
    assert_eq!(
        database
            .set_admin_totp_enabled_with_reauthentication(
                "authorized-session",
                1,
                "password-hash",
                1,
                false,
                Some(42),
                Some("203.0.113.60"),
            )
            .unwrap(),
        AdminTotpSettingOutcome::Updated
    );
    assert!(!database.admin("admin").unwrap().unwrap().totp_enabled);
    let disabled_audit = database
        .list_audit(Some("admin_totp_disabled"), 1, 0)
        .unwrap();
    assert_eq!(disabled_audit.len(), 1);
    assert_eq!(disabled_audit[0].client_ip.as_deref(), Some("203.0.113.60"));

    assert_eq!(
        database
            .delete_admin_webauthn_credential_without_totp(
                "authorized-session",
                first,
                1,
                "password-hash",
                None,
            )
            .unwrap(),
        AdminWebauthnCredentialDeletionOutcome::NotDeleted
    );
    database
        .add_admin_webauthn_credential(1, "Spare", "credential-c", "{}")
        .unwrap();
    assert_eq!(
        database
            .delete_admin_webauthn_credential_without_totp(
                "authorized-session",
                first,
                1,
                "password-hash",
                None,
            )
            .unwrap(),
        AdminWebauthnCredentialDeletionOutcome::Deleted
    );

    database
        .create_session(
            "replacement-session",
            1,
            "csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    assert!(database.verify_mfa("replacement-session").unwrap());

    assert_eq!(
        database
            .set_admin_totp_enabled_with_reauthentication(
                "replacement-session",
                1,
                "password-hash",
                1,
                true,
                None,
                None,
            )
            .unwrap(),
        AdminTotpSettingOutcome::Updated
    );
    assert!(database.admin("admin").unwrap().unwrap().totp_enabled);

    assert_eq!(
        database.reset_admin_totp(1, "new-totp-secret").unwrap(),
        Some("admin".into())
    );
    assert!(database.admin("admin").unwrap().unwrap().totp_enabled);
    assert!(database.admin_webauthn_credentials(1).unwrap().is_empty());
}

#[test]
fn webauthn_registration_cannot_restore_keys_after_mfa_reset() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let expires = Utc::now() + chrono::Duration::hours(1);

    database
        .create_session("authorized-session", 1, "csrf", expires)
        .unwrap();
    assert!(database.verify_mfa("authorized-session").unwrap());
    assert!(matches!(
        database
            .add_admin_webauthn_credential_for_session(
                "authorized-session",
                1,
                "Primary",
                "credential-a",
                "{}",
                Some("203.0.113.24"),
            )
            .unwrap(),
        AdminWebauthnCredentialRegistrationOutcome::Registered(_)
    ));
    assert_eq!(
        database
            .count_audit(Some("webauthn_credential_added"))
            .unwrap(),
        1
    );
    assert_eq!(
        database
            .list_audit(Some("webauthn_credential_added"), 1, 0)
            .unwrap()[0]
            .client_ip
            .as_deref(),
        Some("203.0.113.24")
    );

    database
        .create_session("stale-session", 1, "csrf", expires)
        .unwrap();
    assert!(database.verify_mfa("stale-session").unwrap());
    assert_eq!(
        database.reset_admin_totp(1, "replacement-secret").unwrap(),
        Some("admin".to_string())
    );
    assert!(database.admin_webauthn_credentials(1).unwrap().is_empty());

    assert_eq!(
        database
            .add_admin_webauthn_credential_for_session(
                "stale-session",
                1,
                "Stale",
                "credential-stale",
                "{}",
                None,
            )
            .unwrap(),
        AdminWebauthnCredentialRegistrationOutcome::SessionUnavailable
    );
    assert!(database.admin_webauthn_credentials(1).unwrap().is_empty());
    assert_eq!(
        database
            .count_audit(Some("webauthn_credential_added"))
            .unwrap(),
        1
    );

    database
        .create_session("pre-mfa-session", 1, "csrf", expires)
        .unwrap();
    assert_eq!(
        database
            .add_admin_webauthn_credential_for_session(
                "pre-mfa-session",
                1,
                "Pre MFA",
                "credential-pre-mfa",
                "{}",
                None,
            )
            .unwrap(),
        AdminWebauthnCredentialRegistrationOutcome::SessionUnavailable
    );
}
