#[test]
fn transfer_authorization_checks_current_unlock_before_resume_grants() {
    use crate::db::TransferAuthorization;
    let db = Database::open(":memory:").unwrap();
    db.create_admin("admin", "hash", "secret").unwrap();
    let id = db
        .create_share(
            "auth-transfer",
            None,
            "file.txt",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            Some("old-hash"),
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let issue = |token: &str| {
        let share = db.share_by_id(id).unwrap().unwrap();
        assert!(db
            .create_unlock_session_for_verified_password(
                token,
                id,
                share.password_hash.as_deref().unwrap(),
                share.upload_policy_epoch,
                "csrf",
                Utc::now() + Duration::hours(1)
            )
            .unwrap());
    };
    let authorization = |token| TransferAuthorization {
        share_id: id,
        unlock_token: token,
    };
    issue("before-password");
    assert_eq!(
        db.begin_authorized_transfer_lease(
            "client",
            "opened",
            authorization(Some("before-password")),
            "file.txt",
            "download"
        )
        .unwrap(),
        TransferLeaseBeginOutcome::NewLease
    );
    db.set_share_password(id, Some("new-hash")).unwrap();
    // An already-opened transfer is still allowed to finish.
    assert_eq!(
        db.complete_transfer_lease("opened").unwrap(),
        TransferLeaseCompleteOutcome::Counted
    );
    for token in [None, Some("before-password"), Some("not-an-unlock")] {
        assert_eq!(
            db.begin_authorized_transfer_lease(
                "client",
                "denied",
                authorization(token),
                "file.txt",
                "download"
            )
            .unwrap(),
            TransferLeaseBeginOutcome::Unauthorized
        );
        assert_eq!(
            db.check_authorized_transfer_availability(
                "client",
                authorization(token),
                "file.txt",
                "download"
            )
            .unwrap(),
            TransferAvailabilityOutcome::Unauthorized
        );
    }
    assert_eq!(
        db.try_conn()
            .unwrap()
            .query_row::<i64, _, _>("SELECT COUNT(*) FROM public_transfer_leases", [], |row| row
                .get(0))
            .unwrap(),
        0
    );
    issue("after-password");
    assert_eq!(
        db.begin_authorized_transfer_lease(
            "client",
            "resumed",
            authorization(Some("after-password")),
            "file.txt",
            "download"
        )
        .unwrap(),
        TransferLeaseBeginOutcome::AlreadyCounted
    );
    db.cancel_transfer_lease("resumed").unwrap();
    db.try_conn()
        .unwrap()
        .execute(
            "UPDATE public_unlock_sessions SET expires_at=?1",
            [(Utc::now() - Duration::seconds(1)).to_rfc3339()],
        )
        .unwrap();
    assert_eq!(
        db.begin_authorized_transfer_lease(
            "client",
            "expired",
            authorization(Some("after-password")),
            "file.txt",
            "download"
        )
        .unwrap(),
        TransferLeaseBeginOutcome::Unauthorized
    );
    assert_eq!(
        db.check_authorized_transfer_availability(
            "client",
            authorization(Some("after-password")),
            "file.txt",
            "download"
        )
        .unwrap(),
        TransferAvailabilityOutcome::Unauthorized
    );
    assert_eq!(db.share_by_id(id).unwrap().unwrap().download_count, 1);
}
