#[tokio::test]
async fn share_summary_pages_share_display_snapshot_across_mutations() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state.db().create_session("summary-session", 1, "csrf", Utc::now()+Duration::hours(1)).unwrap();
    state.db().verify_mfa("summary-session").unwrap();
    let app = router(state.clone());
    let mut requests = tokio::task::JoinSet::new();
    for index in 0..2 {
        let app = app.clone();
        requests.spawn(async move {
            let mut req = request(Method::GET, if index%2==0 { "/admin/shares" } else { "/admin" }, "");
            req.headers_mut().insert(header::COOKIE, HeaderValue::from_static("vaultlink_session=summary-session"));
            let response = app.oneshot(req).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert!(!response_text(response).await.is_empty());
        });
    }
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while let Some(result) = requests.join_next().await { result.unwrap(); }
    }).await.unwrap();
    assert_eq!(state.share_summary_cache().refreshes(), 1);
    state.db().create_share("summary-share", None, "file.txt", false, &Permission::DownloadOnly,
        None, None, None, 1, Some("password-hash"), &UploadConflictStrategy::Reject).unwrap();
    let cached = state.share_summary_cache().get(state.db().clone()).await.unwrap();
    assert_eq!(cached.available, 0);
    assert_eq!(cached.protected, 0);
    // Live security data sees the mutation immediately, despite the display snapshot.
    assert!(state.db().share_by_token("summary-share").unwrap().unwrap().password_hash.is_some());
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let fresh = state.share_summary_cache().get(state.db().clone()).await.unwrap();
    assert_eq!(fresh.available, 1);
    assert_eq!(fresh.protected, 1);
    assert_eq!(state.share_summary_cache().refreshes(), 2);
}
