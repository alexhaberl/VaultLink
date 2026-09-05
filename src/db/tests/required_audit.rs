#[test]
fn mfa_session_proof_debug_never_exposes_token_material() {
    let raw_token = "highly-sensitive-session-token";
    let digest = token_hash(raw_token);
    let proof = MfaSessionProof::from_token(raw_token, 42);
    let debug = format!("{proof:?}");

    assert!(debug.contains("[REDACTED]"));
    assert!(debug.contains("admin_id: 42"));
    assert!(!debug.contains(raw_token));
    assert!(!debug.contains(&digest));
}

#[test]
fn audited_proof_debug_never_exposes_the_committed_value() {
    let database = Database::open(":memory:").unwrap();
    let audited = database
        .required_transaction_audited(&AuditContext::system(), |_transaction| {
            Ok((
                "sensitive-result",
                vec![RequiredAuditEvent::new(
                    AuditAction::SettingsUpdated,
                    None,
                    None,
                )],
            ))
        })
        .unwrap();

    let debug = format!("{audited:?}");
    assert_eq!(debug, "Audited([REDACTED])");
    assert!(!debug.contains("sensitive-result"));
    assert_eq!(audited.into_test_value(), "sensitive-result");
}

#[test]
fn transport_consumer_releases_only_database_produced_session_proofs() {
    let database = Database::open(":memory:").unwrap();
    let audited = database
        .required_transaction_audited(&AuditContext::system(), |_transaction| {
            Ok((
                41_u8,
                vec![RequiredAuditEvent::new(
                    AuditAction::SettingsUpdated,
                    None,
                    None,
                )],
            ))
        })
        .unwrap();

    assert_eq!(
        release_session_audited(SessionBound::Authorized(audited)),
        SessionBound::Authorized(41)
    );
    assert_eq!(
        release_session_audited::<u8>(SessionBound::SessionUnavailable),
        SessionBound::SessionUnavailable
    );
}

#[derive(Clone, Copy)]
struct PanickingAuditWriter;

impl std::io::Write for PanickingAuditWriter {
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        panic!("injected tracing subscriber failure")
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for PanickingAuditWriter {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        *self
    }
}

struct TestCommitPublication {
    value: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    previous: usize,
    accepted: bool,
}

impl CommitPublication for TestCommitPublication {
    fn accept_commit(&mut self) {
        self.accepted = true;
    }
}

impl Drop for TestCommitPublication {
    fn drop(&mut self) {
        if !self.accepted {
            self.value
                .store(self.previous, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[test]
fn committed_publication_survives_a_panicking_fallback_tracing_subscriber() {
    let _tracing_guard = crate::test_support::tracing_subscriber_guard();
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let proof = verified_mfa_proof(&database, "post-commit-tracing", 1);
    let value = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let published = value.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(PanickingAuditWriter)
        .finish();

    let outcome = tracing::subscriber::with_default(subscriber, || {
        database.required_transaction_for_mfa_session_with_commit(
            &proof,
            &AuditContext::new("admin", None),
            |_transaction| {
                let previous = published.swap(1, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, rusqlite::Error>((
                    TestCommitPublication {
                        value: published.clone(),
                        previous,
                        accepted: false,
                    },
                    vec![RequiredAuditEvent::new(
                        AuditAction::SettingsUpdated,
                        None,
                        None,
                    )],
                ))
            },
            CommitPublication::accept_commit,
        )
    });

    assert!(matches!(&outcome, Ok(SessionBound::Authorized(_))));
    drop(outcome);
    assert_eq!(value.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(database.count_audit(Some("settings_updated")).unwrap(), 1);
}

#[test]
fn mfa_session_transaction_linearizes_both_race_orders_on_persistent_pool() {
    let directory = tempfile::tempdir().unwrap();
    let database = Database::open(directory.path().join("data.sqlite")).unwrap();
    assert_eq!(database.0.pool.max_size(), 4);
    database.create_admin("admin", "hash", "secret").unwrap();
    database
        .create_session("live-session", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    assert!(database.verify_mfa("live-session").unwrap());
    let proof = MfaSessionProof::from_token("live-session", 1);
    let audit_context = AuditContext::new("admin", None);

    let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::channel();
    let publishing_database = database.clone();
    let publisher = std::thread::spawn(move || {
        publishing_database
            .required_transaction_for_mfa_session_audited(&proof, &audit_context, |_transaction| {
                entered_sender.send(()).unwrap();
                release_receiver.recv().unwrap();
                Ok::<_, rusqlite::Error>(("published", Vec::new()))
            })
            .unwrap()
            .map(Audited::into_test_value)
    });
    entered_receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();

    let (revocation_waiting_sender, revocation_waiting_receiver) = std::sync::mpsc::channel();
    *SQLITE_BUSY_WAIT_SIGNAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(revocation_waiting_sender);
    let (revoked_sender, revoked_receiver) = std::sync::mpsc::channel();
    let revoking_database = database.clone();
    let revoker = std::thread::spawn(move || {
        let mut connection = revoking_database.try_conn().unwrap();
        connection
            .busy_handler(Some(signal_sqlite_busy_wait))
            .unwrap();
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute(
                "DELETE FROM sessions WHERE token_hash=?1",
                [token_hash("live-session")],
            )
            .unwrap();
        transaction.commit().unwrap();
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        revoked_sender.send(()).unwrap();
    });
    // This signal comes from SQLite's busy handler on the revoker's exact
    // connection. It proves BEGIN IMMEDIATE has collided with the mutation's
    // writer transaction; no scheduler timing assumption is involved.
    revocation_waiting_receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    assert!(matches!(
        revoked_receiver.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));

    release_sender.send(()).unwrap();
    assert_eq!(
        publisher.join().unwrap(),
        SessionBound::Authorized("published")
    );
    revoked_receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    revoker.join().unwrap();

    database
        .create_session(
            "revocation-first",
            1,
            "csrf-2",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    assert!(database.verify_mfa("revocation-first").unwrap());
    let proof = MfaSessionProof::from_token("revocation-first", 1);
    let (revocation_holds_writer_sender, revocation_holds_writer_receiver) =
        std::sync::mpsc::channel();
    let (commit_revocation_sender, commit_revocation_receiver) = std::sync::mpsc::channel();
    let revoking_database = database.clone();
    let revoker = std::thread::spawn(move || {
        let mut connection = revoking_database.try_conn().unwrap();
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute(
                "DELETE FROM sessions WHERE token_hash=?1",
                [token_hash("revocation-first")],
            )
            .unwrap();
        revocation_holds_writer_sender.send(()).unwrap();
        commit_revocation_receiver.recv().unwrap();
        transaction.commit().unwrap();
    });
    revocation_holds_writer_receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();

    let ran_after_revocation = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let marker = ran_after_revocation.clone();
    let (checked_sender, checked_receiver) = std::sync::mpsc::channel();
    let checker = std::thread::spawn(move || {
        let outcome = database
            .required_transaction_for_mfa_session_audited(
                &proof,
                &AuditContext::new("admin", None),
                |_transaction| {
                    marker.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok::<_, rusqlite::Error>(((), Vec::new()))
                },
            )
            .unwrap()
            .map(Audited::into_test_value);
        checked_sender.send(()).unwrap();
        outcome
    });
    assert!(checked_receiver
        .recv_timeout(std::time::Duration::from_millis(100))
        .is_err());
    commit_revocation_sender.send(()).unwrap();
    revoker.join().unwrap();
    checked_receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    assert_eq!(checker.join().unwrap(), SessionBound::SessionUnavailable);
    assert!(!ran_after_revocation.load(std::sync::atomic::Ordering::SeqCst));
}

fn verified_mfa_proof(database: &Database, token: &str, admin_id: i64) -> MfaSessionProof {
    database
        .create_session(token, admin_id, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    assert!(database.verify_mfa(token).unwrap());
    MfaSessionProof::from_token(token, admin_id)
}

fn assert_mfa_proof_authorized(database: &Database, proof: &MfaSessionProof) {
    let mut entered = false;
    let outcome = database
        .required_transaction_for_mfa_session(
            proof,
            &AuditContext::new("admin", None),
            |_transaction| {
                entered = true;
                Ok::<_, rusqlite::Error>(((), Vec::new()))
            },
        )
        .unwrap();
    assert_eq!(outcome, SessionBound::Authorized(()));
    assert!(entered);
}

fn assert_mfa_proof_unavailable(database: &Database, proof: &MfaSessionProof) {
    let mut entered = false;
    let outcome = database
        .required_transaction_for_mfa_session(
            proof,
            &AuditContext::new("admin", None),
            |_transaction| {
                entered = true;
                Ok::<_, rusqlite::Error>(((), Vec::new()))
            },
        )
        .unwrap();
    assert_eq!(outcome, SessionBound::SessionUnavailable);
    assert!(
        !entered,
        "an unavailable session entered the mutation closure"
    );
}

#[test]
fn mfa_session_fence_rejects_every_auth_state_revocation_path() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    database
        .create_admin("other-admin", "other-hash", "other-secret")
        .unwrap();

    // Exact-session logout must not invalidate another live session belonging
    // to the same administrator, and the revoked proof must not fall back to
    // administrator identity alone.
    let logged_out = verified_mfa_proof(&database, "logged-out", 1);
    let sibling = verified_mfa_proof(&database, "sibling", 1);
    database.delete_session("logged-out").unwrap();
    assert_mfa_proof_unavailable(&database, &logged_out);
    assert_mfa_proof_authorized(&database, &sibling);

    assert_eq!(
        database.deactivate_admin(1).unwrap(),
        AdminDeactivationOutcome::Deactivated
    );
    assert_mfa_proof_unavailable(&database, &sibling);
    assert!(database.activate_admin(1).unwrap());

    let password_reset = verified_mfa_proof(&database, "password-reset", 1);
    assert!(database
        .reset_admin_password(1, "replacement-hash")
        .unwrap());
    assert_mfa_proof_unavailable(&database, &password_reset);

    let totp_reset = verified_mfa_proof(&database, "totp-reset", 1);
    assert_eq!(
        database.reset_admin_totp(1, "replacement-secret").unwrap(),
        Some("admin".to_string())
    );
    assert_mfa_proof_unavailable(&database, &totp_reset);

    // Security-key deletion is itself a credential reset and revokes every
    // session for the administrator, not only the session authorizing it.
    let credential_authority = verified_mfa_proof(&database, "credential-authority", 1);
    let credential_sibling = verified_mfa_proof(&database, "credential-sibling", 1);
    let credential_id = database
        .add_admin_webauthn_credential(1, "First", "credential-a", "{}")
        .unwrap();
    database
        .add_admin_webauthn_credential(1, "Second", "credential-b", "{}")
        .unwrap();
    database
        .add_admin_webauthn_credential(1, "Third", "credential-c", "{}")
        .unwrap();
    let generation = database.admin("admin").unwrap().unwrap().totp_generation;
    let deleted = database
        .delete_admin_webauthn_credential_with_totp_for_mfa_session(
            &credential_authority,
            credential_id,
            "replacement-hash",
            generation,
            42,
            None,
        )
        .unwrap();
    assert_eq!(
        deleted.map(Audited::into_test_value),
        SessionBound::Authorized(AdminWebauthnCredentialDeletionOutcome::Deleted)
    );
    assert_mfa_proof_unavailable(&database, &credential_authority);
    assert_mfa_proof_unavailable(&database, &credential_sibling);

    let absolute_expiry = verified_mfa_proof(&database, "absolute-expiry", 1);
    database.expire_session_for_test("absolute-expiry").unwrap();
    assert_mfa_proof_unavailable(&database, &absolute_expiry);

    let idle_expiry = verified_mfa_proof(&database, "idle-expiry", 1);
    database
        .conn()
        .execute(
            "UPDATE sessions SET last_activity_at=?2 WHERE token_hash=?1",
            params![
                token_hash("idle-expiry"),
                (Utc::now() - Duration::minutes(31)).to_rfc3339()
            ],
        )
        .unwrap();
    assert_mfa_proof_unavailable(&database, &idle_expiry);
}

#[test]
fn persistent_database_uses_four_connections_and_memory_uses_one() {
    let memory = Database::open(":memory:").unwrap();
    assert_eq!(memory.0.pool.max_size(), 1);
    assert_eq!(
        memory.0.pool.connection_timeout(),
        std::time::Duration::from_secs(1)
    );

    let directory = tempfile::tempdir().unwrap();
    let persistent = Database::open(directory.path().join("data.sqlite")).unwrap();
    assert_eq!(persistent.0.pool.max_size(), 4);
    assert_eq!(
        persistent.0.pool.connection_timeout(),
        std::time::Duration::from_secs(1)
    );
}

#[test]
fn persistent_database_startup_waits_for_sqlite_lock_beyond_checkout_budget() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("data.sqlite");
    let blocker = Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(1500));
        blocker.execute_batch("ROLLBACK").unwrap();
    });

    let opened = Database::open(&path);
    release.join().unwrap();
    let database = opened.unwrap();
    assert_eq!(database.admin_count().unwrap(), 0);
    assert_eq!(database.0.pool.state().connections, 4);
    assert_eq!(database.0.pool.state().idle_connections, 4);
    assert_eq!(
        database.0.pool.connection_timeout(),
        std::time::Duration::from_secs(1)
    );

    let connections: Vec<_> = (0..4).map(|_| database.0.pool.get().unwrap()).collect();
    for connection in &connections {
        let journal_mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode, "wal");
        let foreign_keys: i64 = connection
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        assert_eq!(foreign_keys, 1);
    }
    assert!(database.try_conn().is_err());
}

#[test]
fn database_pool_startup_rejects_partial_initialization_at_its_deadline() {
    let opened = std::sync::atomic::AtomicUsize::new(0);
    let manager = SqliteConnectionManager::memory().with_init(move |connection| {
        if opened.fetch_add(1, Ordering::SeqCst) == 0 {
            configure_connection(connection)
        } else {
            Err(rusqlite::Error::InvalidQuery)
        }
    });
    let pool = r2d2::Pool::builder()
        .max_size(2)
        .connection_timeout(std::time::Duration::from_secs(1))
        .build_unchecked(manager);
    // Wait for the one successful member so the startup check exercises a
    // partially ready pool even when CI schedules its workers slowly.
    drop(
        pool.get_timeout(std::time::Duration::from_secs(10))
            .unwrap(),
    );
    assert!(warm_connection_pool(&pool, std::time::Duration::from_millis(100)).is_err());
    assert_eq!(pool.state().connections, 1);
    assert_eq!(pool.state().idle_connections, 1);
}

#[test]
fn queued_transfer_writers_do_not_exhaust_persistent_read_pool() {
    let directory = tempfile::tempdir().unwrap();
    let database = Database::open(directory.path().join("data.sqlite")).unwrap();
    let write_guard = database.transfer_write_guard().unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(17));
    let (started_sender, started_receiver) = std::sync::mpsc::channel();
    let mut writers = Vec::new();

    for index in 0..16 {
        let writer_database = database.clone();
        let writer_barrier = barrier.clone();
        let writer_started = started_sender.clone();
        writers.push(std::thread::spawn(move || {
            writer_barrier.wait();
            writer_started.send(()).unwrap();
            writer_database
                .cancel_upload_reservation(&format!("queued-writer-{index}"))
                .unwrap()
        }));
    }
    drop(started_sender);
    barrier.wait();
    for _ in 0..16 {
        started_receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
    }

    // Give every writer enough time to reach admission. If connection checkout
    // happened first, four blocked writers would consume the complete pool.
    std::thread::sleep(std::time::Duration::from_millis(100));
    for _ in 0..20 {
        database.readiness_check().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let pool_state = database.0.pool.state();
    assert_eq!(pool_state.connections, pool_state.idle_connections);

    drop(write_guard);
    for writer in writers {
        assert!(!writer.join().unwrap());
    }
}

fn required_audit_failure_fixture() -> (Database, i64, AuditContext) {
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
    (db, share_id, context)
}

fn assert_admin_mutations_roll_back(db: &Database, context: &AuditContext) {
    let create_admin_error = db
        .create_admin_and_audit("rolled-back-admin", "hash", "secret", context)
        .unwrap_err();
    assert!(is_audit_unavailable(&create_admin_error));
    assert_eq!(db.admin_count().unwrap(), 3);

    let activate_error = db.activate_admin_and_audit(2, context).unwrap_err();
    assert!(is_audit_unavailable(&activate_error));
    assert_eq!(
        db.conn()
            .query_row::<i64, _, _>("SELECT active FROM admins WHERE id=2", [], |row| row.get(0))
            .unwrap(),
        0
    );

    let deactivate_error = db.deactivate_admin_and_audit(3, context).unwrap_err();
    assert!(is_audit_unavailable(&deactivate_error));
    assert_eq!(
        db.conn()
            .query_row::<i64, _, _>("SELECT active FROM admins WHERE id=3", [], |row| row.get(0))
            .unwrap(),
        1
    );

    let admin_error = db
        .reset_admin_password_and_audit_audited(1, "new-hash", context)
        .unwrap_err();
    assert!(is_audit_unavailable(&admin_error));
    assert_eq!(
        db.admin("admin").unwrap().unwrap().password_hash,
        "old-hash"
    );

    let totp_error = db
        .reset_admin_totp_and_audit(1, "new-secret", context)
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
}

fn assert_share_mutations_roll_back(db: &Database, share_id: i64, context: &AuditContext) {
    let share_error = db
        .set_share_active_and_audit(share_id, false, context, AuditAction::ShareDeactivated)
        .unwrap_err();
    assert!(is_audit_unavailable(&share_error));
    assert!(db.share_by_token("existing-share").unwrap().unwrap().active);

    let control_events = [RequiredAuditEvent::new(
        AuditAction::ShareUploadConflictUpdated,
        Some(share_id.to_string()),
        None,
    )];
    let controls_error = db
        .update_share_controls_and_audit(
            share_id,
            Some(false),
            Some(&UploadConflictStrategy::OverwriteAllowed),
            None,
            context,
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
            context,
            AuditAction::SharePasswordSet,
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
            context,
        )
        .unwrap_err();
    assert!(is_audit_unavailable(&unlock_error));
    assert!(!db.unlock_session("rolled-back-unlock", share_id).unwrap());

    let delete_error = db.delete_share_and_audit(share_id, context).unwrap_err();
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
            context,
            None,
        )
        .unwrap_err();
    assert!(is_audit_unavailable(&create_error));
    assert!(db.share_by_token("rolled-back-share").unwrap().is_none());
}

fn assert_session_and_settings_mutations_roll_back(db: &Database, context: &AuditContext) {
    let session_error = db
        .create_session_for_verified_password_and_audit(
            "rolled-back-session",
            1,
            "old-hash",
            "csrf",
            Utc::now() + chrono::Duration::hours(1),
            context,
        )
        .unwrap_err();
    assert!(is_audit_unavailable(&session_error));
    assert!(db.session("rolled-back-session").unwrap().is_none());

    let settings_error = db
        .replace_runtime_settings_and_audit(
            &[("public_base_url", "https://new.invalid".into())],
            1,
            context,
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
fn required_audit_failure_rolls_back_admin_share_session_and_settings_mutations() {
    let (db, share_id, context) = required_audit_failure_fixture();
    assert_admin_mutations_roll_back(&db, &context);
    assert_share_mutations_roll_back(&db, share_id, &context);
    assert_session_and_settings_mutations_roll_back(&db, &context);
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
