fn availability_test_share(database: &Database) -> i64 {
    database.create_admin("admin", "hash", "secret").unwrap();
    database
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
        .unwrap()
}

#[test]
fn transfer_availability_reads_while_another_transfer_holds_the_writer() {
    let directory = tempfile::tempdir().unwrap();
    let database = Database::open(directory.path().join("data.sqlite")).unwrap();
    let share_id = availability_test_share(&database);
    let guard = database.transfer_write_guard().unwrap();
    let mut connection = database.conn();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader_database = database.clone();
    let reader = std::thread::spawn(move || {
        let result =
            reader_database.check_transfer_availability("client", share_id, "file.bin", "download");
        let _ = sender.send(result);
    });
    let result = receiver.recv_timeout(std::time::Duration::from_secs(3));
    // Always release the writer before joining, including on the old code.
    drop(transaction);
    drop(guard);
    reader.join().unwrap();
    assert_eq!(
        result
            .expect("preflight must not wait for the writer")
            .unwrap(),
        TransferAvailabilityOutcome::Available
    );
    assert_eq!(database.active_transfer_reservations(share_id).unwrap(), 0);
}

#[test]
fn transfer_availability_ignores_orphans_without_cleanup_or_quota_bypass() {
    let database = Database::open(":memory:").unwrap();
    let share_id = availability_test_share(&database);
    database
        .begin_transfer_lease("holder", "live", share_id, "file.bin", "download")
        .unwrap();
    let now = Utc::now().to_rfc3339();
    let expires = (Utc::now() + Duration::minutes(15)).to_rfc3339();
    database
        .conn()
        .execute(
            "INSERT INTO public_transfer_grants(session_token_hash,share_id,resource_key,
         action,counted,created_at,expires_at) VALUES(?1,?2,'file.bin','download',0,?3,?4)",
            params![token_hash("orphan"), share_id, now, expires],
        )
        .unwrap();
    let orphan_id = database
        .conn()
        .query_row(
            "SELECT id FROM public_transfer_grants WHERE session_token_hash=?1",
            [token_hash("orphan")],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    database
        .conn()
        .execute(
            "INSERT INTO public_transfer_leases VALUES('expired-lease',?1,?2,?2,'2000')",
            params![orphan_id, now],
        )
        .unwrap();
    for session in ["orphan", "new-client"] {
        assert_eq!(
            database
                .check_transfer_availability(session, share_id, "file.bin", "download")
                .unwrap(),
            TransferAvailabilityOutcome::LimitReached
        );
    }
    assert_eq!(
        database
            .check_transfer_availability("holder", share_id, "file.bin", "download")
            .unwrap(),
        TransferAvailabilityOutcome::Available
    );
    assert_eq!(
        database
            .conn()
            .query_row("SELECT COUNT(*) FROM public_transfer_grants", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        database
            .conn()
            .query_row("SELECT COUNT(*) FROM public_transfer_leases", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        2
    );
    database.complete_transfer_lease("live").unwrap();
    assert_eq!(
        database
            .check_transfer_availability("holder", share_id, "file.bin", "download")
            .unwrap(),
        TransferAvailabilityOutcome::AlreadyCounted
    );
    assert_eq!(
        database
            .check_transfer_availability("orphan", share_id, "file.bin", "download")
            .unwrap(),
        TransferAvailabilityOutcome::LimitReached
    );
}
