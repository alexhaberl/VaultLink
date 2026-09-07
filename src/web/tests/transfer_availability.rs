#[tokio::test]
async fn head_downloads_do_not_queue_behind_transfer_writes() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file.bin"), b"content").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let share_id = state
        .db()
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
    let writer = state.db().acquire_transfer_runtime_permit().await.unwrap();
    let app = router(state.clone());
    for path in ["/v/share/download", "/api/v2/public/shares/share/download"] {
        let response = app
            .clone()
            .oneshot(request(Method::HEAD, path, ""))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "7");
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }
    drop(writer);
    assert_eq!(
        state.db().active_transfer_reservations(share_id).unwrap(),
        0
    );
    assert_eq!(
        state
            .db()
            .share_by_token("share")
            .unwrap()
            .unwrap()
            .download_count,
        0
    );
}
