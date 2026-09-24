#[tokio::test]
async fn upload_crash_child() {
    let Ok(root) = std::env::var("VAULTLINK_TEST_UPLOAD_CRASH_ROOT") else {
        return;
    };
    let data = std::env::var("VAULTLINK_TEST_UPLOAD_CRASH_DATA").unwrap();
    let id = std::env::var("VAULTLINK_TEST_UPLOAD_CRASH_ID").unwrap();
    let state = test_state(Path::new(&root), Path::new(&data));
    let mut request = public_folder_upload_request(
        &state,
        "/v/crash-upload/upload/queue",
        "",
        "new",
        "file.txt",
        b"payload",
    );
    request
        .headers_mut()
        .insert("idempotency-key", id.parse().unwrap());
    let response = router(state).oneshot(request).await.unwrap();
    panic!(
        "upload did not exit at crash checkpoint: {}",
        response.status()
    );
}

#[tokio::test]
async fn abrupt_upload_exit_recovers_each_durable_phase() {
    for phase in [
        "after_staging",
        "before_quota",
        "after_quota",
        "after_directory",
        "after_publication",
        "after_audit",
        "after_result",
    ] {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("uploads")).unwrap();
        let state = test_state(root.path(), data.path());
        state.db().create_admin("admin", "hash", "secret").unwrap();
        let share_id = state
            .db()
            .create_share(
                "crash-upload",
                None,
                "uploads",
                true,
                &Permission::UploadOnly,
                None,
                None,
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        let (id, _) = state
            .db()
            .create_upload_operation(crate::db::UploadOperationScope::Share(share_id))
            .unwrap()
            .unwrap();
        drop(state);

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("web::tests::upload_crash_child")
            .arg("--nocapture")
            .env("VAULTLINK_TEST_UPLOAD_CRASH_ROOT", root.path())
            .env("VAULTLINK_TEST_UPLOAD_CRASH_DATA", data.path())
            .env("VAULTLINK_TEST_UPLOAD_CRASH_ID", &id)
            .env("VAULTLINK_TEST_UPLOAD_CRASH_PHASE", phase)
            .env("VAULTLINK_TEST_UPLOAD_CRASH_TOKEN", "crash-upload")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(137),
            "{phase}: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let state = test_state(root.path(), data.path());
        crate::file_ops::recover_pending_file_operations(&state)
            .await
            .unwrap();
        let view = state
            .db()
            .upload_operation(crate::db::UploadOperationScope::Share(share_id), &id)
            .unwrap()
            .unwrap();
        let expected_state = match phase {
            "after_staging" => "retryable",
            "after_result" => "completed",
            _ => "outcome_unknown",
        };
        assert_eq!(view.state, expected_state, "{phase}");
        assert_eq!(view.result.is_some(), phase == "after_result", "{phase}");
        let claim = state
            .db()
            .claim_upload_operation(crate::db::UploadOperationScope::Share(share_id), &id)
            .unwrap();
        if phase == "after_staging" {
            assert!(matches!(claim, crate::db::UploadOperationClaim::Started));
        } else {
            assert!(matches!(
                claim,
                crate::db::UploadOperationClaim::Existing(_)
            ));
        }

        let quota_charged = !matches!(phase, "after_staging" | "before_quota");
        let share = state.db().share_by_token("crash-upload").unwrap().unwrap();
        assert_eq!(
            share.uploaded_bytes,
            if quota_charged { 7 } else { 0 },
            "{phase}"
        );
        assert_eq!(share.uploaded_files, u64::from(quota_charged), "{phase}");
        assert_eq!(
            state
                .db()
                .count_audit(Some("upload_quota_committed"))
                .unwrap(),
            usize::from(quota_charged),
            "{phase}"
        );
        let directory_created = matches!(
            phase,
            "after_directory" | "after_publication" | "after_audit" | "after_result"
        );
        assert_eq!(
            root.path().join("uploads/new").exists(),
            directory_created,
            "{phase}"
        );
        let published = matches!(phase, "after_publication" | "after_audit" | "after_result");
        assert_eq!(
            root.path().join("uploads/new/file.txt").exists(),
            published,
            "{phase}"
        );
        let audited = matches!(phase, "after_audit" | "after_result");
        assert_eq!(
            state.db().count_audit(Some("upload")).unwrap(),
            usize::from(audited),
            "{phase}"
        );
        if phase == "before_quota" || phase == "after_quota" || phase == "after_directory" {
            let fragments = state.db().protected_upload_fragments().unwrap();
            assert_eq!(fragments.len(), 1, "{phase}");
            let fragment = fragments.iter().next().unwrap();
            assert!(
                root.path()
                    .join(".vaultlink-internal/uploads")
                    .join(fragment)
                    .exists(),
                "{phase}"
            );
        }
    }
}
