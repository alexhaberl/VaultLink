#[tokio::test]
async fn deleting_a_regular_file_finishes_without_pending_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("single.txt"), b"content").unwrap();
    let state = test_state(root.path(), data.path());

    let result = authorized(
        delete(
            &state,
            mfa_proof(&state),
            "single.txt",
            None,
            AuditContext::system(),
        )
        .await
        .unwrap(),
    );
    assert!(!result.cleanup_pending);
    assert!(tombstone_paths(root.path()).is_empty());
    assert!(!root.path().join("single.txt").exists());
}

#[tokio::test]
async fn interrupted_rename_is_reconciled_with_share_paths() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("old.txt"), b"content").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share(
            "rename-token",
            None,
            "old.txt",
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
    let fault = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    fault
        .execute_batch(
            "CREATE TRIGGER fail_share_rename
             BEFORE UPDATE OF relative_path ON shares
             BEGIN SELECT RAISE(ABORT, 'injected rename failure'); END;",
        )
        .unwrap();

    let outcome = authorized(
        rename(
            &state,
            mfa_proof(&state),
            "old.txt",
            "new.txt",
            AuditContext::system(),
        )
        .await
        .unwrap(),
    );
    assert_eq!(outcome.audit_durability, AuditDurability::Uncertain);
    assert!(!root.path().join("old.txt").exists());
    assert_eq!(
        std::fs::read(root.path().join("new.txt")).unwrap(),
        b"content"
    );
    assert_eq!(
        state
            .db()
            .share_by_token("rename-token")
            .unwrap()
            .unwrap()
            .relative_path,
        "old.txt"
    );
    assert_eq!(
        state.secure_root().pending_file_operations().unwrap().len(),
        1
    );

    fault
        .execute_batch("DROP TRIGGER fail_share_rename;")
        .unwrap();
    recover_pending_file_operations(&state).await.unwrap();
    assert_eq!(
        state
            .db()
            .share_by_token("rename-token")
            .unwrap()
            .unwrap()
            .relative_path,
        "new.txt"
    );
    assert!(state
        .secure_root()
        .pending_file_operations()
        .unwrap()
        .is_empty());
    recover_pending_file_operations(&state).await.unwrap();
}

#[tokio::test]
async fn interrupted_delete_is_reconciled_with_share_activation() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("remove.txt"), b"content").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share(
            "delete-token",
            None,
            "remove.txt",
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
    let fault = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    fault
        .execute_batch(
            "CREATE TRIGGER fail_share_deactivate
             BEFORE UPDATE OF active ON shares
             BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END;",
        )
        .unwrap();

    let outcome = authorized(
        delete(
            &state,
            mfa_proof(&state),
            "remove.txt",
            None,
            AuditContext::system(),
        )
        .await
        .unwrap(),
    );
    assert_eq!(outcome.audit_durability, AuditDurability::Uncertain);
    assert!(!root.path().join("remove.txt").exists());
    assert!(
        state
            .db()
            .share_by_token("delete-token")
            .unwrap()
            .unwrap()
            .active
    );
    assert_eq!(
        state.secure_root().pending_file_operations().unwrap().len(),
        1
    );

    fault
        .execute_batch("DROP TRIGGER fail_share_deactivate;")
        .unwrap();
    recover_pending_file_operations(&state).await.unwrap();
    assert!(
        !state
            .db()
            .share_by_token("delete-token")
            .unwrap()
            .unwrap()
            .active
    );
    assert!(state
        .secure_root()
        .pending_file_operations()
        .unwrap()
        .is_empty());
    recover_pending_file_operations(&state).await.unwrap();
}
