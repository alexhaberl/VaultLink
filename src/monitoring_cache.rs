use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};

const MONITORING_SUMMARY_TTL: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub(crate) struct MonitoringSummarySnapshot {
    pub(crate) generated_at: DateTime<Utc>,
    pub(crate) summary: crate::db::MonitoringSummary,
    pub(crate) storage: Option<crate::disk_stats::DiskStats>,
}

struct CachedSummary {
    captured_at: Instant,
    snapshot: MonitoringSummarySnapshot,
}

/// One-second, per-process single-flight cache for the monitoring overview.
///
/// The short-lived value cache uses a synchronous mutex only for cloning a
/// completed snapshot. The async mutex serializes refreshes without retaining
/// a guard while callers consume the response. Failed loaders never publish a
/// cache entry.
#[derive(Clone)]
pub(crate) struct MonitoringSummaryCache {
    cached: Arc<Mutex<Option<CachedSummary>>>,
    refresh: Arc<tokio::sync::Mutex<()>>,
}

impl MonitoringSummaryCache {
    pub(crate) fn new() -> Self {
        Self {
            cached: Arc::new(Mutex::new(None)),
            refresh: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    pub(crate) async fn get_or_try_insert<E, F, Fut>(
        &self,
        loader: F,
    ) -> Result<MonitoringSummarySnapshot, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<MonitoringSummarySnapshot, E>>,
    {
        if let Some(snapshot) = self.fresh() {
            return Ok(snapshot);
        }

        let _refresh = self.refresh.lock().await;
        if let Some(snapshot) = self.fresh() {
            return Ok(snapshot);
        }

        let snapshot = loader().await?;
        *self
            .cached
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(CachedSummary {
            captured_at: Instant::now(),
            snapshot: snapshot.clone(),
        });
        Ok(snapshot)
    }

    fn fresh(&self) -> Option<MonitoringSummarySnapshot> {
        self.cached
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .filter(|cached| cached.captured_at.elapsed() < MONITORING_SUMMARY_TTL)
            .map(|cached| cached.snapshot.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{MonitoringSummary, TransferMonthlyCounts};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn snapshot(total: u64) -> MonitoringSummarySnapshot {
        MonitoringSummarySnapshot {
            generated_at: Utc::now(),
            summary: MonitoringSummary {
                total,
                available: total,
                inactive: 0,
                expired: 0,
                download_limit_reached: 0,
                protected: 0,
                transfers: TransferMonthlyCounts {
                    month: "2026-09".into(),
                    download: 0,
                    zip_download: 0,
                    preview: 0,
                },
                statistics_started_at: "2026-09-01T00:00:00Z".into(),
            },
            storage: None,
        }
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_successful_refresh() {
        let cache = MonitoringSummaryCache::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let first_calls = calls.clone();
        let second_calls = calls.clone();
        let (first, second) = tokio::join!(
            cache.get_or_try_insert(|| async move {
                first_calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok::<_, ()>(snapshot(7))
            }),
            cache.get_or_try_insert(|| async move {
                second_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, ()>(snapshot(9))
            })
        );

        assert_eq!(first.unwrap().summary.total, 7);
        assert_eq!(second.unwrap().summary.total, 7);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_refresh_is_not_cached() {
        let cache = MonitoringSummaryCache::new();
        assert!(cache
            .get_or_try_insert(|| async { Err::<MonitoringSummarySnapshot, _>("injected") })
            .await
            .is_err());

        let refreshed = cache
            .get_or_try_insert(|| async { Ok::<_, &str>(snapshot(11)) })
            .await
            .unwrap();
        assert_eq!(refreshed.summary.total, 11);
    }
}
