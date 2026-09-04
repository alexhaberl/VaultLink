#[tokio::test]
async fn published_directory_reports_audit_durability_uncertain_without_retrying() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let fault = install_audit_failure(data.path());

    let result = authorized(
        create_directory(
            &state,
            mfa_proof(&state),
            "",
            "created",
            AuditContext::new("admin", None),
        )
        .await
        .unwrap(),
    );
    assert_eq!(result.audit_durability, AuditDurability::Uncertain);
    assert!(root.path().join("created").is_dir());
    assert_eq!(state.db().count_audit(None).unwrap(), 0);

    fault
        .execute_batch("DROP TRIGGER fail_required_audit;")
        .unwrap();
    assert_eq!(state.db().count_audit(None).unwrap(), 0);
}

#[tokio::test]
async fn directory_parent_sync_failure_is_reported_as_uncertain_and_audited_once() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state
        .secure_root()
        .fail_next_create_directory_sync(io::ErrorKind::Other);

    let result = authorized(
        create_directory(
            &state,
            mfa_proof(&state),
            "",
            "created",
            AuditContext::new("admin", None),
        )
        .await
        .expect("a visible mkdir must not be reported as a retryable failure"),
    );

    assert_eq!(result.audit_durability, AuditDurability::Uncertain);
    assert!(root.path().join("created").is_dir());
    let events = state
        .db()
        .list_audit(Some("directory_created"), 10, 0)
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor, "admin");
}

#[tokio::test]
async fn mkdir_response_loss_with_probe_failure_is_uncertain_and_audited_once() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state
        .secure_root()
        .fail_next_create_directory_mkdir_after_success(io::ErrorKind::TimedOut);
    state
        .secure_root()
        .fail_next_create_directory_probe(io::ErrorKind::WouldBlock);

    let result = authorized(
        create_directory(
            &state,
            mfa_proof(&state),
            "",
            "ambiguous",
            AuditContext::new("admin", None),
        )
        .await
        .expect("a potentially visible mkdir must not be a retryable error"),
    );

    assert_eq!(result.path, "ambiguous");
    assert_eq!(result.audit_durability, AuditDurability::Uncertain);
    assert!(root.path().join("ambiguous").is_dir());
    let events = state
        .db()
        .list_audit(Some("directory_created"), 10, 0)
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor, "admin");
}

#[tokio::test]
async fn rename_parent_sync_failure_recovers_before_releasing_storage_lock() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("old.txt"), b"content").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share(
            "rename-sync-token",
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
    state
        .secure_root()
        .fail_next_rename_parent_sync(io::ErrorKind::Other);

    let result = authorized(
        rename(
            &state,
            mfa_proof(&state),
            "old.txt",
            "new.txt",
            AuditContext::new("admin", None),
        )
        .await
        .expect("a moved entry with uncertain sync must return an uncertain outcome"),
    );
    assert_eq!(result.audit_durability, AuditDurability::Uncertain);
    assert!(root.path().join("new.txt").is_file());
    assert_eq!(
        state
            .db()
            .share_by_token("rename-sync-token")
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
    let events = state.db().list_audit(Some("path_renamed"), 10, 0).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor, "system");

    recover_pending_file_operations(&state).await.unwrap();
    assert_eq!(
        state
            .db()
            .list_audit(Some("path_renamed"), 10, 0)
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn delete_commit_sync_failure_recovers_before_releasing_storage_lock() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("remove.txt"), b"content").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share(
            "delete-sync-token",
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
    state
        .secure_root()
        .fail_next_delete_commit_sync(io::ErrorKind::Other);

    let result = authorized(
        delete(
            &state,
            mfa_proof(&state),
            "remove.txt",
            None,
            AuditContext::new("admin", None),
        )
        .await
        .expect("an unlinked entry with uncertain sync must return an uncertain outcome"),
    );
    assert_eq!(result.audit_durability, AuditDurability::Uncertain);
    assert!(!root.path().join("remove.txt").exists());
    assert!(
        !state
            .db()
            .share_by_token("delete-sync-token")
            .unwrap()
            .unwrap()
            .active
    );
    assert!(state
        .secure_root()
        .pending_file_operations()
        .unwrap()
        .is_empty());
    let events = state.db().list_audit(Some("path_deleted"), 10, 0).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor, "system");

    recover_pending_file_operations(&state).await.unwrap();
    assert_eq!(
        state
            .db()
            .list_audit(Some("path_deleted"), 10, 0)
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn delete_staging_response_loss_recovers_before_unlock_and_is_uncertain() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("ambiguous.txt"), b"content").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share(
            "delete-stage-response-loss-token",
            None,
            "ambiguous.txt",
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
    state
        .secure_root()
        .fail_next_delete_staging_rename_after_success(io::ErrorKind::TimedOut);
    state
        .secure_root()
        .fail_next_delete_staging_identity_probes(io::ErrorKind::WouldBlock, 2);

    let result = authorized(
        delete(
            &state,
            mfa_proof(&state),
            "ambiguous.txt",
            None,
            AuditContext::new("admin", None),
        )
        .await
        .expect("an inconclusive staging rename must return an uncertain outcome"),
    );

    assert_eq!(result.path, "ambiguous.txt");
    assert_eq!(result.kind, EntryKind::File);
    assert_eq!(result.audit_durability, AuditDurability::Uncertain);
    assert!(!result.cleanup_pending);
    assert_eq!(
        std::fs::read(root.path().join("ambiguous.txt")).unwrap(),
        b"content"
    );
    assert!(
        state
            .db()
            .share_by_token("delete-stage-response-loss-token")
            .unwrap()
            .unwrap()
            .active
    );
    assert!(state
        .secure_root()
        .pending_file_operations()
        .unwrap()
        .is_empty());
    assert!(tombstone_paths(root.path()).is_empty());
    assert!(state
        .db()
        .list_audit(Some("path_deleted"), 10, 0)
        .unwrap()
        .is_empty());
}
#[tokio::test]
async fn post_stage_failure_with_failed_restore_is_uncertain_and_recovered_before_unlock() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("restore-retry.txt"), b"content").unwrap();
    let state = test_state(root.path(), data.path());
    state
        .secure_root()
        .fail_next_delete_post_stage(io::ErrorKind::Other);
    state
        .secure_root()
        .fail_next_delete_rollback_rename_before_mutation(io::ErrorKind::TimedOut);

    let result = authorized(
        delete(
            &state,
            mfa_proof(&state),
            "restore-retry.txt",
            None,
            AuditContext::new("admin", None),
        )
        .await
        .expect("a failed post-stage restore must not escape as a retryable error"),
    );

    assert_eq!(result.audit_durability, AuditDurability::Uncertain);
    assert_eq!(
        std::fs::read(root.path().join("restore-retry.txt")).unwrap(),
        b"content"
    );
    assert!(tombstone_paths(root.path()).is_empty());
    assert!(state
        .db()
        .list_audit(Some("path_deleted"), 10, 0)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn restored_delete_with_parent_sync_failure_is_uncertain_and_finalized_before_unlock() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("restore-sync.txt"), b"content").unwrap();
    let state = test_state(root.path(), data.path());
    state
        .secure_root()
        .fail_next_delete_post_stage(io::ErrorKind::Other);
    state
        .secure_root()
        .fail_next_delete_rollback_parent_sync(io::ErrorKind::WouldBlock);

    let result = authorized(
        delete(
            &state,
            mfa_proof(&state),
            "restore-sync.txt",
            None,
            AuditContext::new("admin", None),
        )
        .await
        .expect("a restored name with uncertain sync must return an uncertain outcome"),
    );

    assert_eq!(result.audit_durability, AuditDurability::Uncertain);
    assert_eq!(
        std::fs::read(root.path().join("restore-sync.txt")).unwrap(),
        b"content"
    );
    assert!(tombstone_paths(root.path()).is_empty());
    assert!(state
        .db()
        .list_audit(Some("path_deleted"), 10, 0)
        .unwrap()
        .is_empty());
}
