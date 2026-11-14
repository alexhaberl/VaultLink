use super::*;

#[tokio::test]
async fn closed_refresh_channel_fails_promptly_and_allows_a_new_refresh() {
    let database = Database::open(":memory:").unwrap();
    let cache = ShareSummaryCache::default();
    let (sender, receiver) = watch::channel(None);
    cache.0.lock().unwrap().flight = Some(receiver);
    drop(sender);
    let error = tokio::time::timeout(Duration::from_secs(1), cache.get(database.clone()))
        .await
        .expect("a lost refresh must not strand a waiter")
        .unwrap_err();
    assert!(matches!(
        &*error,
        DatabaseExecutionError::Operation(rusqlite::Error::InvalidQuery)
    ));
    assert_eq!(cache.refreshes(), 0);
    let summary = cache
        .get_with(database, |_| {
            Ok(ShareSummary {
                available: 2,
                protected: 1,
            })
        })
        .await
        .unwrap();
    assert_eq!(summary.available, 2);
    assert_eq!(summary.protected, 1);
    assert_eq!(cache.refreshes(), 1);
}

#[tokio::test]
async fn poisoned_cache_state_recovers_from_a_lost_refresh() {
    let database = Database::open(":memory:").unwrap();
    let cache = ShareSummaryCache::default();
    let failed_cache = cache.clone();
    let failed_worker = std::thread::spawn(move || {
        let mut state = failed_cache.0.lock().unwrap();
        let (sender, receiver) = watch::channel(None);
        state.flight = Some(receiver);
        drop(sender);
        panic!("simulated cache worker failure while holding state");
    });
    assert!(failed_worker.join().is_err());
    assert!(cache.get(database.clone()).await.is_err());
    let summary = tokio::time::timeout(Duration::from_secs(5), cache.get(database))
        .await
        .expect("poison recovery must allow another refresh")
        .unwrap();
    assert_eq!(summary, ShareSummary::default());
}
