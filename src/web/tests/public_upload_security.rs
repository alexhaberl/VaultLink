#[tokio::test]
async fn public_upload_rejects_unreadable_or_excessively_deep_targets_before_staging() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    std::fs::write(root.path().join("uploads/short.txt"), b"short").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
        .create_share(
            "bounded-upload",
            None,
            "uploads",
            true,
            &Permission::DownloadUpload,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let app = router(state.clone());
    let long_folder = vec!["a".repeat(250); 16].join("/");
    let long_name = format!("{}.txt", "f".repeat(100));
    let response = app
        .clone()
        .oneshot(public_folder_upload_request(
            "/v/bounded-upload/upload/queue",
            "",
            &long_folder,
            &long_name,
            b"x",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!root.path().join("uploads").join("a".repeat(250)).exists());

    let deep_folder = vec!["d"; 17].join("/");
    let response = app
        .clone()
        .oneshot(public_folder_upload_request(
            "/v/bounded-upload/upload/queue",
            "",
            &deep_folder,
            "deep.txt",
            b"x",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!root.path().join("uploads/d").exists());
    let share = state.db().share_by_token("bounded-upload").unwrap().unwrap();
    assert_eq!((share.uploaded_bytes, share.uploaded_files), (0, 0));
    assert_eq!(state.db().active_upload_reservations(share_id).unwrap(), 0);
    assert_eq!(upload_fragment_count(root.path()), 0);

    let valid = app
        .clone()
        .oneshot(public_folder_upload_request(
            "/v/bounded-upload/upload/queue",
            "",
            "a/b",
            "good.txt",
            b"good",
        ))
        .await
        .unwrap();
    assert_eq!(valid.status(), StatusCode::OK);
    let download = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/v/bounded-upload/download?path=a%2Fb%2Fgood.txt",
            "",
        ))
        .await
        .unwrap();
    assert_eq!(download.status(), StatusCode::OK);
    let zip = app
        .oneshot(request(Method::GET, "/v/bounded-upload/download.zip", ""))
        .await
        .unwrap();
    assert_eq!(zip.status(), StatusCode::OK);
}

#[tokio::test]
async fn public_upload_audit_identifies_the_full_share_relative_target() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("uploads/a")).unwrap();
    std::fs::create_dir_all(root.path().join("uploads/b")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share(
            "path-audit-upload",
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
    let app = router(state.clone());
    for folder in ["a", "b"] {
        let response = app
            .clone()
            .oneshot(public_folder_upload_request(
                "/v/path-audit-upload/upload/queue",
                "",
                folder,
                "same.txt",
                b"x",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let events = state.db().list_audit(Some("upload"), 10, 0).unwrap();
    assert_eq!(events.len(), 2);
    let details: Vec<_> = events
        .iter()
        .map(|event| event.detail.as_deref().unwrap())
        .collect();
    assert!(details.iter().any(|detail| detail.contains("path=a/same.txt")));
    assert!(details.iter().any(|detail| detail.contains("path=b/same.txt")));
    assert_ne!(details[0], details[1]);
}

#[tokio::test]
async fn public_upload_reports_audit_uncertainty_when_created_directory_audit_fails() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("uploads")).unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share(
            "directory-audit-upload",
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
    let fault = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
    fault
        .execute_batch(
            "CREATE TRIGGER fail_created_directory_audit
             BEFORE INSERT ON audit
             WHEN NEW.action='upload_directories_created'
             BEGIN SELECT RAISE(ABORT, 'injected directory audit failure'); END;",
        )
        .unwrap();
    let response = router(state.clone())
        .oneshot(public_folder_upload_request(
            "/v/directory-audit-upload/upload/queue",
            "",
            "new",
            "file.txt",
            b"x",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(response_text(response)
        .await
        .contains(r#""warning":"audit_durability_uncertain""#));
    assert!(root.path().join("uploads/new/file.txt").exists());
    assert_eq!(state.db().count_audit(Some("upload_directories_created")).unwrap(), 0);
    assert_eq!(state.db().count_audit(Some("upload")).unwrap(), 1);
}
