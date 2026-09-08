async fn public_metadata_fixture() -> (tempfile::TempDir, tempfile::TempDir, AppState, i64) {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("metadata.txt"), b"content").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    let id = state
        .db()
        .create_share(
            "metadata-test",
            None,
            "metadata.txt",
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
    crate::file_ops::recover_pending_file_operations(&state)
        .await
        .unwrap();
    (root, data, state, id)
}

async fn metadata_request_after_first_lookup(
    state: &AppState,
) -> (
    tokio::task::JoinHandle<Result<axum::response::Response, std::convert::Infallible>>,
    Vec<crate::db::RuntimeDatabasePermit>,
) {
    let mut holders = Vec::new();
    for _ in 0..state.db().runtime_available_permits() {
        holders.push(state.db().acquire_runtime_permit().await.unwrap());
    }
    let mut response = Box::pin(
        router(state.clone()).oneshot(
            Request::builder()
                .uri("/v/metadata-test")
                .body(Body::empty())
                .unwrap(),
        ),
    );
    assert!(futures_util::poll!(&mut response).is_pending());
    let database = state.db().clone();
    let mut catcher = Box::pin(async move { database.acquire_runtime_permit().await.unwrap() });
    assert!(futures_util::poll!(&mut catcher).is_pending());
    // The request receives one slot; this already queued catcher owns it as
    // soon as the first blocking lookup has returned its actual share data.
    drop(holders.remove(0));
    let response = tokio::spawn(response);
    holders.push(
        tokio::time::timeout(std::time::Duration::from_secs(3), catcher)
            .await
            .unwrap(),
    );
    (response, holders)
}

#[tokio::test]
async fn clean_public_metadata_completes_with_one_database_lookup() {
    let (_root, _data, state, _id) = public_metadata_fixture().await;
    let (response, holders) = metadata_request_after_first_lookup(&state).await;
    let response = tokio::time::timeout(std::time::Duration::from_secs(3), response)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(holders);
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn public_metadata_rechecks_revocation_after_waiting_for_storage_authority() {
    let (_root, _data, state, id) = public_metadata_fixture().await;
    let mutation = state.acquire_storage_mutation().await;
    let (response, holders) = metadata_request_after_first_lookup(&state).await;
    assert!(state.db().set_share_active(id, false).unwrap());
    mutation.finish_clean();
    drop(holders);
    let response = tokio::time::timeout(std::time::Duration::from_secs(3), response)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::GONE);
}
