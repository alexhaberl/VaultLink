use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const SUCCESS_TTL: Duration = Duration::from_millis(250);
const ERROR_TTL: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug)]
pub(crate) struct DiskStats {
    pub(crate) free: u64,
    pub(crate) total: u64,
}

#[derive(Clone, Copy)]
struct CachedDiskStats {
    captured_at: Instant,
    value: Result<DiskStats, io::ErrorKind>,
}

type Probe = dyn Fn(&Path) -> io::Result<DiskStats> + Send + Sync;

#[derive(Clone)]
pub(crate) struct DiskStatsCache {
    entries: Arc<Mutex<HashMap<PathBuf, CachedDiskStats>>>,
    refresh: Arc<tokio::sync::Mutex<()>>,
    probe: Arc<Probe>,
}

impl DiskStatsCache {
    pub(crate) fn new() -> Self {
        Self::with_probe(probe_disk_stats)
    }

    fn with_probe(probe: impl Fn(&Path) -> io::Result<DiskStats> + Send + Sync + 'static) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            refresh: Arc::new(tokio::sync::Mutex::new(())),
            probe: Arc::new(probe),
        }
    }

    pub(crate) async fn get(&self, path: &Path) -> io::Result<DiskStats> {
        if let Some(value) = self.fresh(path) {
            return cached_result(value);
        }
        let _refresh = self.refresh.lock().await;
        if let Some(value) = self.fresh(path) {
            return cached_result(value);
        }
        let owned_path = path.to_path_buf();
        let probe = self.probe.clone();
        let result = tokio::task::spawn_blocking(move || probe(&owned_path))
            .await
            .map_err(io::Error::other)?;
        let cached = CachedDiskStats {
            captured_at: Instant::now(),
            value: result.as_ref().copied().map_err(io::Error::kind),
        };
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(path.to_path_buf(), cached);
        result
    }

    pub(crate) fn peek_and_refresh(&self, path: &Path) -> Option<DiskStats> {
        let current = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(path)
            .copied();
        if current.is_none_or(|cached| !is_fresh(cached)) {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                let cache = self.clone();
                let path = path.to_path_buf();
                runtime.spawn(async move {
                    let _ = cache.get(&path).await;
                });
            }
        }
        current.and_then(|cached| cached.value.ok())
    }

    fn fresh(&self, path: &Path) -> Option<CachedDiskStats> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(path)
            .copied()
            .filter(|cached| is_fresh(*cached))
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        probe: impl Fn(&Path) -> io::Result<DiskStats> + Send + Sync + 'static,
    ) -> Self {
        Self::with_probe(probe)
    }
}

fn is_fresh(cached: CachedDiskStats) -> bool {
    cached.captured_at.elapsed()
        < if cached.value.is_ok() {
            SUCCESS_TTL
        } else {
            ERROR_TTL
        }
}

fn cached_result(value: CachedDiskStats) -> io::Result<DiskStats> {
    value
        .value
        .map_err(|kind| io::Error::new(kind, "cached storage capacity probe failed"))
}

fn probe_disk_stats(path: &Path) -> io::Result<DiskStats> {
    let canonical = path.canonicalize()?;
    let stat = rustix::fs::statvfs(&canonical)?;
    let block_size = stat.f_bsize;
    Ok(DiskStats {
        free: stat.f_bavail.saturating_mul(block_size),
        total: stat.f_blocks.saturating_mul(block_size),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn concurrent_reads_share_one_probe_and_errors_are_negatively_cached() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let cache = DiskStatsCache::for_test(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("injected"))
        });
        let path = Path::new("/injected");
        let (first, second, third) =
            tokio::join!(cache.get(path), cache.get(path), cache.get(path),);
        assert!(first.is_err() && second.is_err() && third.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(cache.get(path).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
