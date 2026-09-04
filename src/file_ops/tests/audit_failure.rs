#[tokio::test]
async fn rename_audit_failure_is_uncertain_and_recovery_finishes_once_as_system() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("old.txt"), b"content").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share(
            "rename-audit-token",
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
    let fault = install_audit_failure(data.path());

    let result = rename(
        &state,
        mfa_proof(&state),
        "old.txt",
        "new.txt",
        AuditContext::new("admin", None),
    )
    .await
    .unwrap();
    let result = authorized(result);
    assert_eq!(result.audit_durability, AuditDurability::Uncertain);
    assert!(root.path().join("new.txt").is_file());
    assert_eq!(
        state
            .db()
            .share_by_token("rename-audit-token")
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
        .execute_batch("DROP TRIGGER fail_required_audit;")
        .unwrap();
    recover_pending_file_operations(&state).await.unwrap();
    recover_pending_file_operations(&state).await.unwrap();
    assert_eq!(
        state
            .db()
            .share_by_token("rename-audit-token")
            .unwrap()
            .unwrap()
            .relative_path,
        "new.txt"
    );
    let events = state.db().list_audit(Some("path_renamed"), 10, 0).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor, "system");
    assert!(events[0].client_ip.is_none());
}

#[tokio::test]
async fn delete_audit_failure_is_uncertain_and_recovery_finishes_once_as_system() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("remove.txt"), b"content").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share(
            "delete-audit-token",
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
    let fault = install_audit_failure(data.path());

    let result = authorized(
        delete(
            &state,
            mfa_proof(&state),
            "remove.txt",
            None,
            AuditContext::new("admin", None),
        )
        .await
        .unwrap(),
    );
    assert_eq!(result.audit_durability, AuditDurability::Uncertain);
    assert!(!root.path().join("remove.txt").exists());
    assert!(
        state
            .db()
            .share_by_token("delete-audit-token")
            .unwrap()
            .unwrap()
            .active
    );
    assert_eq!(
        state.secure_root().pending_file_operations().unwrap().len(),
        1
    );

    fault
        .execute_batch("DROP TRIGGER fail_required_audit;")
        .unwrap();
    recover_pending_file_operations(&state).await.unwrap();
    recover_pending_file_operations(&state).await.unwrap();
    assert!(
        !state
            .db()
            .share_by_token("delete-audit-token")
            .unwrap()
            .unwrap()
            .active
    );
    let events = state.db().list_audit(Some("path_deleted"), 10, 0).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor, "system");
    assert!(events[0].client_ip.is_none());
}

#[tokio::test]
async fn rename_database_failure_after_publication_is_uncertain_not_retryable_failure() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("old.txt"), b"content").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share(
            "rename-database-token",
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
    let fault = install_share_update_failure(data.path());

    let result = rename(
        &state,
        mfa_proof(&state),
        "old.txt",
        "new.txt",
        AuditContext::new("admin", None),
    )
    .await
    .expect("a visible rename must be reported as uncertain, not failed");
    let result = authorized(result);
    assert_eq!(result.audit_durability, AuditDurability::Uncertain);
    assert!(root.path().join("new.txt").is_file());
    assert_eq!(
        state
            .db()
            .share_by_token("rename-database-token")
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
        .execute_batch("DROP TRIGGER fail_share_update;")
        .unwrap();
    recover_pending_file_operations(&state).await.unwrap();
    assert_eq!(
        state
            .db()
            .share_by_token("rename-database-token")
            .unwrap()
            .unwrap()
            .relative_path,
        "new.txt"
    );
}

#[tokio::test]
async fn delete_database_failure_after_publication_is_uncertain_not_retryable_failure() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("remove.txt"), b"content").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share(
            "delete-database-token",
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
    let fault = install_share_update_failure(data.path());

    let result = authorized(
        delete(
            &state,
            mfa_proof(&state),
            "remove.txt",
            None,
            AuditContext::new("admin", None),
        )
        .await
        .expect("a visible deletion must be reported as uncertain, not failed"),
    );
    assert_eq!(result.audit_durability, AuditDurability::Uncertain);
    assert!(!root.path().join("remove.txt").exists());
    assert!(
        state
            .db()
            .share_by_token("delete-database-token")
            .unwrap()
            .unwrap()
            .active
    );
    assert_eq!(
        state.secure_root().pending_file_operations().unwrap().len(),
        1
    );

    fault
        .execute_batch("DROP TRIGGER fail_share_update;")
        .unwrap();
    recover_pending_file_operations(&state).await.unwrap();
    assert!(
        !state
            .db()
            .share_by_token("delete-database-token")
            .unwrap()
            .unwrap()
            .active
    );
}
