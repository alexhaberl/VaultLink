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

fn batching_quota_database() -> (Database, i64) {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share_with_upload_limits(
            "batching-share",
            None,
            "folder",
            true,
            &Permission::UploadOnly,
            None,
            None,
            Some(10),
            Some(10),
            Some(2),
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    for token in ["one", "two"] {
        assert_eq!(
            database
                .begin_upload_reservation(token, share_id, 0)
                .unwrap(),
            UploadReservationBeginOutcome::Reserved
        );
    }
    (database, share_id)
}

#[test]
fn upload_reservation_batching_falls_back_atomically_and_keeps_exact_quota() {
    let (database, share_id) = batching_quota_database();
    assert_eq!(
        database
            .extend_upload_reservation_up_to("one", 4, 6)
            .unwrap(),
        (UploadReservationExtendOutcome::Extended, 6)
    );
    assert_eq!(
        database
            .extend_upload_reservation_up_to("two", 4, 8)
            .unwrap(),
        (UploadReservationExtendOutcome::Extended, 4)
    );
    assert_eq!(
        database
            .extend_upload_reservation_up_to("two", 5, 8)
            .unwrap(),
        (UploadReservationExtendOutcome::ByteQuotaReached, 4)
    );
    assert_eq!(
        database.commit_upload_reservation("one", 4).unwrap(),
        UploadReservationCommitOutcome::Committed
    );
    // Commit accounts actual bytes and releases unused speculative quota.
    assert_eq!(
        database
            .extend_upload_reservation_up_to("two", 6, 8)
            .unwrap(),
        (UploadReservationExtendOutcome::Extended, 6)
    );
    assert_eq!(
        database.commit_upload_reservation("two", 6).unwrap(),
        UploadReservationCommitOutcome::Committed
    );
    let share = database.share_by_id(share_id).unwrap().unwrap();
    assert_eq!((share.uploaded_bytes, share.uploaded_files), (10, 2));
}

#[test]
fn upload_reservation_batching_serializes_competing_quota_requests() {
    let (database, share_id) = batching_quota_database();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = ["one", "two"]
        .into_iter()
        .map(|token| {
            let database = database.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                database
                    .extend_upload_reservation_up_to(token, 4, 6)
                    .unwrap()
            })
        })
        .collect();
    let mut accepted: Vec<_> = workers
        .into_iter()
        .map(|worker| {
            let (outcome, bytes) = worker.join().unwrap();
            assert_eq!(outcome, UploadReservationExtendOutcome::Extended);
            bytes
        })
        .collect();
    accepted.sort_unstable();
    assert_eq!(accepted, [4, 6]);
    for token in ["one", "two"] {
        assert!(database.cancel_upload_reservation(token).unwrap());
    }
    assert_eq!(database.active_upload_reservations(share_id).unwrap(), 0);
    database
        .begin_upload_reservation("after", share_id, 0)
        .unwrap();
    assert_eq!(
        database
            .extend_upload_reservation_up_to("after", 10, 10)
            .unwrap(),
        (UploadReservationExtendOutcome::Extended, 10)
    );
}

#[test]
fn upload_reservation_batching_validates_targets_and_expiry() {
    let (database, _) = batching_quota_database();
    assert!(database
        .extend_upload_reservation_up_to("one", 5, 4)
        .is_err());
    assert_eq!(
        database
            .extend_upload_reservation_up_to("one", 1, u64::MAX)
            .unwrap(),
        (UploadReservationExtendOutcome::Extended, 1)
    );
    assert!(database
        .extend_upload_reservation_up_to("one", 0, 2)
        .is_err());
    assert_eq!(
        database
            .extend_upload_reservation_up_to("one", u64::MAX, u64::MAX)
            .unwrap(),
        (UploadReservationExtendOutcome::ByteQuotaReached, 1)
    );
    database
        .conn()
        .execute(
            "UPDATE public_upload_reservations SET expires_at=?1 WHERE token_hash=?2",
            params![
                (Utc::now() - Duration::seconds(1)).to_rfc3339(),
                token_hash("one")
            ],
        )
        .unwrap();
    assert_eq!(
        database
            .extend_upload_reservation_up_to("one", 1, 8)
            .unwrap(),
        (UploadReservationExtendOutcome::NotFound, 0)
    );
    assert_eq!(
        database
            .extend_upload_reservation_up_to("two", 10, 10)
            .unwrap(),
        (UploadReservationExtendOutcome::Extended, 10)
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
        // Revocation must invalidate unused quota already granted in advance,
        // including a final commit that would fit entirely inside that grant.
        for token in [&extend_token, &commit_token] {
            assert_eq!(
                database
                    .extend_upload_reservation_up_to(token, 1, 8)
                    .unwrap(),
                (UploadReservationExtendOutcome::Extended, 8)
            );
        }
        database.conn().execute(revocation, [share_id]).unwrap();

        assert_eq!(
            database
                .extend_upload_reservation(&extend_token, 8)
                .unwrap(),
            UploadReservationExtendOutcome::ShareUnavailable
        );
        assert_eq!(
            database
                .commit_upload_reservation(&commit_token, 1)
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
