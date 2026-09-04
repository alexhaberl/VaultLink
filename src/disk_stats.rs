use std::{
    collections::HashMap,
    io,
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const SUCCESS_TTL: Duration = Duration::from_millis(250);
const ERROR_TTL: Duration = Duration::from_millis(100);
const CALLER_TIMEOUT: Duration = Duration::from_secs(2);

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
type Canonicalizer = dyn Fn(&Path) -> io::Result<PathBuf> + Send + Sync;

struct CacheEntry {
    state: Mutex<EntryState>,
}

#[derive(Default)]
struct EntryState {
    cached: Option<CachedDiskStats>,
    flight: Option<Arc<ProbeFlight>>,
}

struct ProbeFlight {
    result: Mutex<Option<Result<DiskStats, io::ErrorKind>>>,
    changed: tokio::sync::watch::Sender<u64>,
}

enum EntryLookup {
    Cached(CachedDiskStats),
    Wait(Arc<ProbeFlight>),
    Start(Arc<ProbeFlight>),
}

impl ProbeFlight {
    fn new() -> Self {
        let (changed, _) = tokio::sync::watch::channel(0);
        Self {
            result: Mutex::new(None),
            changed,
        }
    }

    fn current(&self) -> Option<Result<DiskStats, io::ErrorKind>> {
        *self
            .result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn finish(&self, result: Result<DiskStats, io::ErrorKind>) {
        *self
            .result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(result);
        self.changed.send_modify(|generation| {
            *generation = generation.wrapping_add(1);
        });
    }

    async fn wait(&self) -> io::Result<DiskStats> {
        let mut changed = self.changed.subscribe();
        loop {
            if let Some(result) = self.current() {
                return result.map_err(cached_error);
            }
            changed
                .changed()
                .await
                .map_err(|_| io::Error::other("storage capacity probe channel closed"))?;
        }
    }
}

impl CacheEntry {
    fn new() -> Self {
        Self {
            state: Mutex::new(EntryState::default()),
        }
    }

    fn current(&self) -> Option<CachedDiskStats> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .cached
    }

    fn lookup(&self) -> EntryLookup {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(cached) = state.cached.filter(|cached| is_fresh(*cached)) {
            return EntryLookup::Cached(cached);
        }
        if let Some(flight) = &state.flight {
            return EntryLookup::Wait(flight.clone());
        }
        let flight = Arc::new(ProbeFlight::new());
        state.flight = Some(flight.clone());
        EntryLookup::Start(flight)
    }

    fn finish_refresh(&self, flight: &Arc<ProbeFlight>, value: Result<DiskStats, io::ErrorKind>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state
            .flight
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, flight))
        {
            state.cached = Some(CachedDiskStats {
                captured_at: Instant::now(),
                value,
            });
            state.flight = None;
        }
        drop(state);
        flight.finish(value);
    }
}

#[derive(Default)]
struct CacheState {
    entries: HashMap<PathBuf, Arc<CacheEntry>>,
}

#[derive(Clone)]
pub(crate) struct DiskStatsCache {
    state: Arc<Mutex<CacheState>>,
    probe: Arc<Probe>,
    canonicalize: Arc<Canonicalizer>,
    caller_timeout: Duration,
}

impl DiskStatsCache {
    pub(crate) fn new() -> Self {
        Self::with_components(probe_disk_stats, |path| path.canonicalize(), CALLER_TIMEOUT)
    }

    #[cfg(test)]
    fn with_probe(probe: impl Fn(&Path) -> io::Result<DiskStats> + Send + Sync + 'static) -> Self {
        Self::with_components(probe, |path| Ok(path.to_path_buf()), CALLER_TIMEOUT)
    }

    fn with_components(
        probe: impl Fn(&Path) -> io::Result<DiskStats> + Send + Sync + 'static,
        canonicalize: impl Fn(&Path) -> io::Result<PathBuf> + Send + Sync + 'static,
        caller_timeout: Duration,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(CacheState::default())),
            probe: Arc::new(probe),
            canonicalize: Arc::new(canonicalize),
            caller_timeout,
        }
    }

    pub(crate) async fn get(&self, path: &Path) -> io::Result<DiskStats> {
        tokio::time::timeout(self.caller_timeout, self.get_without_timeout(path))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "storage capacity probe exceeded its caller deadline",
                )
            })?
    }

    pub(crate) fn peek_and_refresh(&self, path: &Path) -> Option<DiskStats> {
        let current = self
            .entry_for_cached_path(path)
            .and_then(|entry| entry.current());
        if current.is_none_or(|cached| !is_fresh(cached))
            && tokio::runtime::Handle::try_current().is_ok()
        {
            let entry = self.entry_for_path(path);
            if let EntryLookup::Start(flight) = entry.lookup() {
                self.spawn_refresh(entry, flight, path.to_path_buf());
            }
        }
        current.and_then(|cached| cached.value.ok())
    }

    async fn get_without_timeout(&self, path: &Path) -> io::Result<DiskStats> {
        let entry = self.entry_for_path(path);
        match entry.lookup() {
            EntryLookup::Cached(cached) => cached_result(cached),
            EntryLookup::Wait(flight) => flight.wait().await,
            EntryLookup::Start(flight) => {
                self.spawn_refresh(entry, flight.clone(), path.to_path_buf());
                flight.wait().await
            }
        }
    }

    fn entry_for_path(&self, path: &Path) -> Arc<CacheEntry> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .entries
            .entry(path.to_path_buf())
            .or_insert_with(|| Arc::new(CacheEntry::new()))
            .clone()
    }

    fn entry_for_cached_path(&self, path: &Path) -> Option<Arc<CacheEntry>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .get(path)
            .cloned()
    }

    fn spawn_refresh(
        &self,
        entry: Arc<CacheEntry>,
        flight: Arc<ProbeFlight>,
        requested_path: PathBuf,
    ) {
        let canonicalize = self.canonicalize.clone();
        let probe = self.probe.clone();
        drop(tokio::task::spawn_blocking(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                canonicalize(&requested_path).and_then(|canonical| probe(&canonical))
            }))
            .map_or(Err(io::ErrorKind::Other), |result| {
                result.map_err(|error| error.kind())
            });
            entry.finish_refresh(&flight, result);
        }));
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        probe: impl Fn(&Path) -> io::Result<DiskStats> + Send + Sync + 'static,
    ) -> Self {
        Self::with_probe(probe)
    }

    #[cfg(test)]
    fn for_test_with_components(
        probe: impl Fn(&Path) -> io::Result<DiskStats> + Send + Sync + 'static,
        canonicalize: impl Fn(&Path) -> io::Result<PathBuf> + Send + Sync + 'static,
        caller_timeout: Duration,
    ) -> Self {
        Self::with_components(probe, canonicalize, caller_timeout)
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
    value.value.map_err(cached_error)
}

fn cached_error(kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, "cached storage capacity probe failed")
}

fn probe_disk_stats(path: &Path) -> io::Result<DiskStats> {
    let stat = rustix::fs::statvfs(path)?;
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

    async fn wait_for_cached_value(cache: &DiskStatsCache, path: &Path) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if cache
                    .entry_for_cached_path(path)
                    .and_then(|entry| entry.current())
                    .is_some()
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached disk-stat refresh did not finish");
    }

    fn assert_all_timed_out(results: &[io::Result<DiskStats>]) {
        assert_eq!(results.len(), 64);
        assert!(results.iter().all(|result| {
            result
                .as_ref()
                .is_err_and(|error| error.kind() == io::ErrorKind::TimedOut)
        }));
    }

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

    #[tokio::test]
    async fn an_expired_entry_is_canonicalized_again_before_it_is_probed() {
        let canonicalizations = Arc::new(AtomicUsize::new(0));
        let observed_canonicalizations = canonicalizations.clone();
        let probed_paths = Arc::new(Mutex::new(Vec::new()));
        let observed_paths = probed_paths.clone();
        let cache = DiskStatsCache::for_test_with_components(
            move |path| {
                observed_paths
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(path.to_path_buf());
                let free = u64::from(path == Path::new("/target-two")) + 1;
                Ok(DiskStats { free, total: 2 })
            },
            move |_| {
                let call = observed_canonicalizations.fetch_add(1, Ordering::SeqCst);
                Ok(PathBuf::from(if call == 0 {
                    "/target-one"
                } else {
                    "/target-two"
                }))
            },
            CALLER_TIMEOUT,
        );
        let path = Path::new("/rotating-link");
        assert_eq!(cache.get(path).await.unwrap().free, 1);
        tokio::time::sleep(SUCCESS_TTL + Duration::from_millis(25)).await;
        assert_eq!(cache.get(path).await.unwrap().free, 2);
        assert_eq!(canonicalizations.load(Ordering::SeqCst), 2);
        assert_eq!(
            *probed_paths
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            [PathBuf::from("/target-one"), PathBuf::from("/target-two")]
        );
    }

    #[tokio::test]
    async fn different_canonical_paths_refresh_independently() {
        let started = Arc::new(AtomicUsize::new(0));
        let observed = started.clone();
        let cache = DiskStatsCache::for_test(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            let deadline = Instant::now() + Duration::from_millis(250);
            while observed.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            if observed.load(Ordering::SeqCst) < 2 {
                return Err(io::Error::other("probes were serialized"));
            }
            Ok(DiskStats { free: 1, total: 2 })
        });
        let (first, second) = tokio::join!(
            cache.get(Path::new("/first")),
            cache.get(Path::new("/second")),
        );
        assert!(first.is_ok());
        assert!(second.is_ok());
        assert_eq!(started.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn success_and_error_entries_use_their_respective_ttls() {
        let success_calls = Arc::new(AtomicUsize::new(0));
        let observed_success = success_calls.clone();
        let success_cache = DiskStatsCache::for_test(move |_| {
            observed_success.fetch_add(1, Ordering::SeqCst);
            Ok(DiskStats { free: 1, total: 2 })
        });
        let path = Path::new("/success");
        success_cache.get(path).await.unwrap();
        success_cache.get(path).await.unwrap();
        assert_eq!(success_calls.load(Ordering::SeqCst), 1);
        tokio::time::sleep(SUCCESS_TTL + Duration::from_millis(25)).await;
        success_cache.get(path).await.unwrap();
        assert_eq!(success_calls.load(Ordering::SeqCst), 2);

        let error_calls = Arc::new(AtomicUsize::new(0));
        let observed_error = error_calls.clone();
        let error_cache = DiskStatsCache::for_test(move |_| {
            observed_error.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("injected"))
        });
        let path = Path::new("/error");
        assert!(error_cache.get(path).await.is_err());
        assert!(error_cache.get(path).await.is_err());
        assert_eq!(error_calls.load(Ordering::SeqCst), 1);
        tokio::time::sleep(ERROR_TTL + Duration::from_millis(25)).await;
        assert!(error_cache.get(path).await.is_err());
        assert_eq!(error_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn sixty_four_caller_timeouts_do_not_start_a_duplicate_probe() {
        let canonicalizations = Arc::new(AtomicUsize::new(0));
        let observed_canonicalizations = canonicalizations.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let cache = DiskStatsCache::for_test_with_components(
            move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(90));
                Ok(DiskStats { free: 1, total: 2 })
            },
            move |path| {
                observed_canonicalizations.fetch_add(1, Ordering::SeqCst);
                Ok(path.to_path_buf())
            },
            Duration::from_millis(25),
        );
        let path = Path::new("/slow");
        let results = futures_util::future::join_all((0..64).map(|_| cache.get(path))).await;
        assert_all_timed_out(&results);
        assert_eq!(canonicalizations.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        wait_for_cached_value(&cache, path).await;
        assert_eq!(cache.get(path).await.unwrap().free, 1);
        assert_eq!(canonicalizations.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn sixty_four_caller_timeouts_do_not_start_duplicate_canonicalization() {
        let canonicalizations = Arc::new(AtomicUsize::new(0));
        let observed = canonicalizations.clone();
        let probes = Arc::new(AtomicUsize::new(0));
        let observed_probes = probes.clone();
        let cache = DiskStatsCache::for_test_with_components(
            move |_| {
                observed_probes.fetch_add(1, Ordering::SeqCst);
                Ok(DiskStats { free: 1, total: 2 })
            },
            move |path| {
                observed.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(90));
                Ok(path.to_path_buf())
            },
            Duration::from_millis(25),
        );
        let path = Path::new("/slow-canonicalization");
        let results = futures_util::future::join_all((0..64).map(|_| cache.get(path))).await;
        assert_all_timed_out(&results);
        assert_eq!(canonicalizations.load(Ordering::SeqCst), 1);
        wait_for_cached_value(&cache, path).await;
        assert_eq!(cache.get(path).await.unwrap().total, 2);
        assert_eq!(canonicalizations.load(Ordering::SeqCst), 1);
        assert_eq!(probes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancelled_waiters_leave_the_detached_probe_running() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let cache = DiskStatsCache::for_test_with_components(
            move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(90));
                Ok(DiskStats { free: 1, total: 2 })
            },
            |path| Ok(path.to_path_buf()),
            Duration::from_secs(1),
        );
        let path = PathBuf::from("/cancelled-waiters");
        let waiters = (0..64)
            .map(|_| {
                let cache = cache.clone();
                let path = path.clone();
                tokio::spawn(async move { cache.get(&path).await })
            })
            .collect::<Vec<_>>();
        tokio::time::timeout(Duration::from_secs(1), async {
            while calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        for waiter in waiters {
            waiter.abort();
        }
        wait_for_cached_value(&cache, &path).await;
        assert_eq!(cache.get(&path).await.unwrap().total, 2);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_panicking_probe_finishes_the_flight_and_is_negatively_cached() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let cache = DiskStatsCache::for_test(move |_| -> io::Result<DiskStats> {
            observed.fetch_add(1, Ordering::SeqCst);
            panic!("injected probe panic")
        });
        let path = Path::new("/panicking-probe");
        let (first, second) = tokio::join!(cache.get(path), cache.get(path));
        assert_eq!(first.unwrap_err().kind(), io::ErrorKind::Other);
        assert_eq!(second.unwrap_err().kind(), io::ErrorKind::Other);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            cache.get(path).await.unwrap_err().kind(),
            io::ErrorKind::Other
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn poisoned_cache_mutexes_recover_without_sticking_the_flight() {
        let cache = DiskStatsCache::for_test(|_| Ok(DiskStats { free: 1, total: 2 }));
        let path = Path::new("/poisoned");
        let entry = cache.entry_for_path(path);
        let poisoned_entry = entry.clone();
        let _ = catch_unwind(AssertUnwindSafe(move || {
            let _state = poisoned_entry.state.lock().unwrap();
            panic!("poison entry state");
        }));
        let poisoned_cache = cache.state.clone();
        let _ = catch_unwind(AssertUnwindSafe(move || {
            let _state = poisoned_cache.lock().unwrap();
            panic!("poison cache state");
        }));
        assert_eq!(cache.get(path).await.unwrap().free, 1);
    }
}
