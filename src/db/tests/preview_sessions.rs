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
