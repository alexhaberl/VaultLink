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
