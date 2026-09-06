use std::sync::{Arc, Mutex};
use tokio::{
    sync::watch,
    time::{Duration, Instant},
};

use crate::db::{execute_database_operation, Database, DatabaseExecutionError, ShareSummary};

pub(crate) type SummaryError = Arc<DatabaseExecutionError<rusqlite::Error>>;
type SummaryResult = Result<ShareSummary, SummaryError>;
type Flight = watch::Receiver<Option<SummaryResult>>;
const TTL: Duration = Duration::from_secs(1);

#[derive(Default)]
struct State {
    cached: Option<(Instant, ShareSummary)>,
    flight: Option<Flight>,
    #[cfg(test)]
    refreshes: usize,
}

/// Display counts only. The detached refresh owns database admission even when
/// every HTTP waiter disconnects. No authorization or quota decision uses this cache.
#[derive(Clone, Default)]
pub(crate) struct ShareSummaryCache(Arc<Mutex<State>>);

impl ShareSummaryCache {
    pub(crate) async fn get(&self, database: Database) -> SummaryResult {
        self.get_with(database, |db| db.share_summary(chrono::Utc::now()))
            .await
    }

    async fn get_with<F>(&self, database: Database, operation: F) -> SummaryResult
    where
        F: FnOnce(Database) -> rusqlite::Result<ShareSummary> + Send + 'static,
    {
        let mut flight = {
            let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
            if let Some((started, summary)) = state.cached {
                if started.elapsed() < TTL {
                    return Ok(summary);
                }
            }
            state.cached = None;
            if let Some(flight) = &state.flight {
                flight.clone()
            } else {
                let (sender, receiver) = watch::channel(None);
                state.flight = Some(receiver.clone());
                #[cfg(test)]
                {
                    state.refreshes += 1;
                }
                let cache = self.clone();
                let started = Instant::now();
                tokio::spawn(async move {
                    let result = execute_database_operation(database, "share_summary", operation)
                        .await
                        .map_err(Arc::new);
                    let mut state = cache.0.lock().unwrap_or_else(|error| error.into_inner());
                    if let Ok(summary) = &result {
                        state.cached = Some((started, *summary));
                    }
                    sender.send_replace(Some(result));
                    state.flight = None;
                });
                receiver
            }
        };
        loop {
            if let Some(result) = flight.borrow_and_update().clone() {
                return result;
            }
            if flight.changed().await.is_err() {
                return Err(Arc::new(DatabaseExecutionError::Operation(
                    rusqlite::Error::InvalidQuery,
                )));
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn refreshes(&self) -> usize {
        self.0.lock().unwrap().refreshes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn detached_refresh_survives_cancellation_and_errors_are_not_cached() {
        let database = Database::open(":memory:").unwrap();
        let cache = ShareSummaryCache::default();
        let first_cache = cache.clone();
        let first_database = database.clone();
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let first = tokio::spawn(async move {
            first_cache
                .get_with(first_database, move |_| {
                    entered.send(()).unwrap();
                    blocked.recv_timeout(Duration::from_secs(5)).unwrap();
                    Ok(ShareSummary {
                        available: 7,
                        protected: 3,
                    })
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .unwrap()
            .unwrap();
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        let second_cache = cache.clone();
        let second_database = database.clone();
        let second = tokio::spawn(async move {
            second_cache
                .get_with(second_database, |_| panic!("second scan"))
                .await
        });
        tokio::task::yield_now().await;
        assert_eq!(cache.refreshes(), 1);
        release.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), second)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(result.available, 7);
        assert_eq!(result.protected, 3);
        tokio::time::sleep(TTL).await;
        assert!(cache
            .get_with(database.clone(), |_| Err(rusqlite::Error::InvalidQuery))
            .await
            .is_err());
        assert!(cache
            .get_with(database.clone(), |_| panic!("injected loader panic"))
            .await
            .is_err());
        assert_eq!(cache.get(database).await.unwrap(), ShareSummary::default());
        assert_eq!(cache.refreshes(), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn ttl_starts_before_loading_and_separate_states_do_not_share_counts() {
        let database = Database::open(":memory:").unwrap();
        let cache = ShareSummaryCache::default();
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let loading_cache = cache.clone();
        let loading_database = database.clone();
        let loading = tokio::spawn(async move {
            loading_cache
                .get_with(loading_database, move |_| {
                    entered.send(()).unwrap();
                    blocked.recv_timeout(Duration::from_secs(5)).unwrap();
                    Ok(ShareSummary {
                        available: 9,
                        protected: 1,
                    })
                })
                .await
        });
        waiting.await.unwrap();
        tokio::time::advance(TTL).await;
        release.send(()).unwrap();
        assert_eq!(loading.await.unwrap().unwrap().available, 9);
        assert_eq!(
            cache.get(database.clone()).await.unwrap(),
            ShareSummary::default()
        );
        assert_eq!(cache.refreshes(), 2);
        let independent = ShareSummaryCache::default();
        independent.get(database).await.unwrap();
        assert_eq!(independent.refreshes(), 1);
    }
}
