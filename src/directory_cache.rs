use std::{
    cmp::Ordering,
    collections::HashMap,
    future::Future,
    hash::Hash,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant, SystemTime},
};

use crate::secure_fs::Entry;

pub(crate) const DIRECTORY_SNAPSHOT_TTL: Duration = Duration::from_secs(1);
pub(crate) const DIRECTORY_SNAPSHOT_MAX_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const DIRECTORY_CACHE_MAX_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum DirectoryEntrySortPrimary {
    Name,
    Type(bool),
    Size(u64),
    Modified(Option<SystemTime>),
}

/// An owned sort key built exactly once for an entry retained by a directory
/// snapshot. Cursor partitioning compares these keys without allocating.
#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct DirectoryEntrySortKey {
    pub(crate) primary: DirectoryEntrySortPrimary,
    pub(crate) folded_name: String,
    pub(crate) original_name: String,
}

impl DirectoryEntrySortKey {
    fn heap_bytes(&self) -> usize {
        self.folded_name
            .capacity()
            .saturating_add(self.original_name.capacity())
    }
}

#[derive(Debug)]
pub(crate) struct DirectorySnapshotEntry {
    pub(crate) entry: Entry,
    pub(crate) sort_key: DirectoryEntrySortKey,
}

impl DirectorySnapshotEntry {
    pub(crate) fn compare_key(&self, other: &DirectoryEntrySortKey, descending: bool) -> Ordering {
        let order = self.sort_key.cmp(other);
        if descending {
            order.reverse()
        } else {
            order
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct DirectorySnapshotKey {
    pub(crate) scope: String,
    pub(crate) directory: String,
    pub(crate) sort: &'static str,
    pub(crate) direction: &'static str,
    pub(crate) scan_limit: usize,
    pub(crate) storage_generation: u64,
}

#[derive(Debug)]
pub(crate) struct DirectorySnapshot {
    pub(crate) entries: Box<[DirectorySnapshotEntry]>,
    pub(crate) truncated: bool,
    accounted_bytes: usize,
}

impl DirectorySnapshot {
    fn accounted_bytes(&self) -> usize {
        self.accounted_bytes
    }
}

/// Builds a snapshot while enforcing its memory ceiling before retaining the
/// entry that would cross it. Callers can immediately fall back to the bounded
/// 101-entry heap without ever constructing an oversized snapshot.
pub(crate) struct DirectorySnapshotBuilder {
    entries: Vec<DirectorySnapshotEntry>,
    accounted_bytes: usize,
    maximum_bytes: usize,
}

impl DirectorySnapshotBuilder {
    pub(crate) fn new() -> Self {
        Self::with_limit(DIRECTORY_SNAPSHOT_MAX_BYTES)
    }

    fn with_limit(maximum_bytes: usize) -> Self {
        Self {
            entries: Vec::new(),
            accounted_bytes: std::mem::size_of::<DirectorySnapshot>(),
            maximum_bytes,
        }
    }

    pub(crate) fn push(
        &mut self,
        entry: Entry,
        sort_key: DirectoryEntrySortKey,
    ) -> Result<(), Entry> {
        let entry_bytes = std::mem::size_of::<DirectorySnapshotEntry>()
            .saturating_add(entry.name.capacity())
            .saturating_add(sort_key.heap_bytes());
        let next = self.accounted_bytes.saturating_add(entry_bytes);
        if next > self.maximum_bytes {
            return Err(entry);
        }
        self.accounted_bytes = next;
        self.entries
            .push(DirectorySnapshotEntry { entry, sort_key });
        Ok(())
    }

    pub(crate) fn finish(self, truncated: bool) -> DirectorySnapshot {
        DirectorySnapshot {
            entries: self.entries.into_boxed_slice(),
            truncated,
            accounted_bytes: self.accounted_bytes,
        }
    }
}

#[derive(Clone)]
pub(crate) enum DirectoryCacheLookup {
    Snapshot(Arc<DirectorySnapshot>),
    /// This key exceeded the per-snapshot cap during the current TTL. Use the
    /// existing bounded heap algorithm instead of attempting another snapshot.
    Bypass,
}

struct CacheRecord {
    captured_at: Instant,
    last_used: u64,
    value: Option<Arc<DirectorySnapshot>>,
    accounted_bytes: usize,
}

fn record_overhead(key: &DirectorySnapshotKey) -> usize {
    std::mem::size_of::<DirectorySnapshotKey>()
        .saturating_add(std::mem::size_of::<CacheRecord>())
        .saturating_add(key.scope.len())
        .saturating_add(key.directory.len())
}

#[derive(Default)]
struct CacheState {
    records: HashMap<DirectorySnapshotKey, CacheRecord>,
    total_bytes: usize,
    clock: u64,
}

type Flight = tokio::sync::Mutex<()>;

struct FlightRegistration {
    flights: Arc<Mutex<HashMap<DirectorySnapshotKey, Weak<Flight>>>>,
    key: DirectorySnapshotKey,
    flight: Weak<Flight>,
}

impl FlightRegistration {
    fn new(
        flights: Arc<Mutex<HashMap<DirectorySnapshotKey, Weak<Flight>>>>,
        key: DirectorySnapshotKey,
        flight: &Arc<Flight>,
    ) -> Self {
        Self {
            flights,
            key,
            flight: Arc::downgrade(flight),
        }
    }
}

impl Drop for FlightRegistration {
    fn drop(&mut self) {
        // A cancelled waiter must not unregister a flight that another request
        // still owns. The final owner removes a dead registration even when
        // cancellation prevents the normal loader cleanup from running.
        if self.flight.strong_count() > 1 {
            return;
        }
        let mut flights = self
            .flights
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if flights
            .get(&self.key)
            .is_some_and(|registered| registered.ptr_eq(&self.flight))
        {
            flights.remove(&self.key);
        }
    }
}

#[derive(Clone)]
pub(crate) struct DirectorySnapshotCache {
    state: Arc<Mutex<CacheState>>,
    flights: Arc<Mutex<HashMap<DirectorySnapshotKey, Weak<Flight>>>>,
    ttl: Duration,
    maximum_snapshot_bytes: usize,
    maximum_total_bytes: usize,
}

impl DirectorySnapshotCache {
    pub(crate) fn new() -> Self {
        Self::with_limits(
            DIRECTORY_SNAPSHOT_TTL,
            DIRECTORY_SNAPSHOT_MAX_BYTES,
            DIRECTORY_CACHE_MAX_BYTES,
        )
    }

    fn with_limits(
        ttl: Duration,
        maximum_snapshot_bytes: usize,
        maximum_total_bytes: usize,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(CacheState::default())),
            flights: Arc::new(Mutex::new(HashMap::new())),
            ttl,
            maximum_snapshot_bytes,
            maximum_total_bytes,
        }
    }

    pub(crate) async fn get_or_try_load<E, F, Fut>(
        &self,
        key: DirectorySnapshotKey,
        loader: F,
    ) -> Result<DirectoryCacheLookup, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<DirectorySnapshot>, E>>,
    {
        if let Some(cached) = self.cached(&key) {
            return Ok(cached);
        }

        let flight = self.flight(&key);
        let _registration = FlightRegistration::new(self.flights.clone(), key.clone(), &flight);
        let _flight_guard = flight.lock().await;
        if let Some(cached) = self.cached(&key) {
            return Ok(cached);
        }

        let loaded = match loader().await {
            Ok(loaded) => loaded,
            Err(error) => {
                self.remove_flight(&key, &flight);
                return Err(error);
            }
        };
        let lookup = self.insert(key.clone(), loaded);
        self.remove_flight(&key, &flight);
        Ok(lookup)
    }

    fn cached(&self, key: &DirectorySnapshotKey) -> Option<DirectoryCacheLookup> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        prune_expired(&mut state, self.ttl);
        state.clock = state.clock.wrapping_add(1);
        let now = state.clock;
        state.records.get_mut(key).map(|record| {
            record.last_used = now;
            record
                .value
                .as_ref()
                .map_or(DirectoryCacheLookup::Bypass, |snapshot| {
                    DirectoryCacheLookup::Snapshot(snapshot.clone())
                })
        })
    }

    fn flight(&self, key: &DirectorySnapshotKey) -> Arc<Flight> {
        let mut flights = self
            .flights
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(flight) = flights.get(key).and_then(Weak::upgrade) {
            return flight;
        }
        let flight = Arc::new(Flight::new(()));
        flights.insert(key.clone(), Arc::downgrade(&flight));
        flight
    }

    fn remove_flight(&self, key: &DirectorySnapshotKey, flight: &Arc<Flight>) {
        let mut flights = self
            .flights
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if flights
            .get(key)
            .and_then(Weak::upgrade)
            .is_some_and(|current| Arc::ptr_eq(&current, flight))
        {
            flights.remove(key);
        }
    }

    fn insert(
        &self,
        key: DirectorySnapshotKey,
        snapshot: Option<DirectorySnapshot>,
    ) -> DirectoryCacheLookup {
        let snapshot = snapshot
            .filter(|snapshot| snapshot.accounted_bytes() <= self.maximum_snapshot_bytes)
            .map(Arc::new);
        let accounted_bytes = record_overhead(&key).saturating_add(
            snapshot
                .as_ref()
                .map_or(0, |snapshot| snapshot.accounted_bytes()),
        );
        let lookup = snapshot
            .as_ref()
            .map_or(DirectoryCacheLookup::Bypass, |snapshot| {
                DirectoryCacheLookup::Snapshot(snapshot.clone())
            });
        // A pathological key must not make the cache exceed its global bound.
        // The caller can still use the bounded heap fallback for this request.
        if accounted_bytes > self.maximum_total_bytes {
            return lookup;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        prune_expired(&mut state, self.ttl);
        if let Some(replaced) = state.records.remove(&key) {
            state.total_bytes = state.total_bytes.saturating_sub(replaced.accounted_bytes);
        }
        while state.total_bytes.saturating_add(accounted_bytes) > self.maximum_total_bytes {
            let Some(oldest) = state
                .records
                .iter()
                .min_by_key(|(_, record)| record.last_used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(evicted) = state.records.remove(&oldest) {
                state.total_bytes = state.total_bytes.saturating_sub(evicted.accounted_bytes);
            }
        }
        state.clock = state.clock.wrapping_add(1);
        let last_used = state.clock;
        state.total_bytes = state.total_bytes.saturating_add(accounted_bytes);
        state.records.insert(
            key,
            CacheRecord {
                captured_at: Instant::now(),
                last_used,
                value: snapshot,
                accounted_bytes,
            },
        );
        lookup
    }
}

fn prune_expired(state: &mut CacheState, ttl: Duration) {
    let expired = state
        .records
        .iter()
        .filter(|(_, record)| record.captured_at.elapsed() >= ttl)
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    for key in expired {
        if let Some(record) = state.records.remove(&key) {
            state.total_bytes = state.total_bytes.saturating_sub(record.accounted_bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn key(generation: u64) -> DirectorySnapshotKey {
        DirectorySnapshotKey {
            scope: "admin".into(),
            directory: "folder".into(),
            sort: "name",
            direction: "asc",
            scan_limit: 50_000,
            storage_generation: generation,
        }
    }

    fn sort_key(name: &str) -> DirectoryEntrySortKey {
        DirectoryEntrySortKey {
            primary: DirectoryEntrySortPrimary::Name,
            folded_name: name.to_lowercase(),
            original_name: name.to_owned(),
        }
    }

    fn snapshot(name: &str) -> DirectorySnapshot {
        let mut builder = DirectorySnapshotBuilder::new();
        let entry = Entry {
            name: name.into(),
            is_dir: false,
            len: 1,
            modified: None,
        };
        builder.push(entry, sort_key(name)).unwrap();
        builder.finish(false)
    }

    #[tokio::test]
    async fn concurrent_requests_share_one_loader() {
        let cache = DirectorySnapshotCache::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let first_calls = calls.clone();
        let second_calls = calls.clone();
        let (first, second) = tokio::join!(
            cache.get_or_try_load(key(1), || async move {
                first_calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok::<_, ()>(Some(snapshot("one")))
            }),
            cache.get_or_try_load(key(1), || async move {
                second_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, ()>(Some(snapshot("two")))
            })
        );
        let DirectoryCacheLookup::Snapshot(first) = first.unwrap() else {
            panic!("cacheable snapshot expected");
        };
        let DirectoryCacheLookup::Snapshot(second) = second.unwrap() else {
            panic!("cacheable snapshot expected");
        };
        assert_eq!(first.entries[0].entry.name, "one");
        assert_eq!(second.entries[0].entry.name, "one");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ten_pages_reuse_one_completed_snapshot() {
        let cache = DirectorySnapshotCache::new();
        let calls = Arc::new(AtomicUsize::new(0));
        for _ in 0..10 {
            let calls = calls.clone();
            let result = cache
                .get_or_try_load(key(1), || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(Some(snapshot("page-source")))
                })
                .await
                .unwrap();
            assert!(matches!(result, DirectoryCacheLookup::Snapshot(_)));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn loader_errors_are_not_cached() {
        let cache = DirectorySnapshotCache::new();
        assert!(cache
            .get_or_try_load(key(1), || async { Err::<Option<DirectorySnapshot>, _>(()) })
            .await
            .is_err());
        let loaded = cache
            .get_or_try_load(key(1), || async { Ok::<_, ()>(Some(snapshot("retry"))) })
            .await
            .unwrap();
        assert!(matches!(loaded, DirectoryCacheLookup::Snapshot(_)));
    }

    #[tokio::test]
    async fn cancelling_unique_loaders_removes_every_flight_registration() {
        let cache = DirectorySnapshotCache::new();
        let mut loaders = Vec::new();
        for generation in 0..64 {
            let cache = cache.clone();
            loaders.push(tokio::spawn(async move {
                let _ = cache
                    .get_or_try_load::<(), _, _>(key(generation), || async {
                        std::future::pending::<Result<Option<DirectorySnapshot>, ()>>().await
                    })
                    .await;
            }));
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let registered = cache
                    .flights
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .len();
                if registered == loaders.len() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all unique directory loads should register a flight");

        for loader in &loaders {
            loader.abort();
        }
        for loader in loaders {
            assert!(loader.await.unwrap_err().is_cancelled());
        }
        assert!(cache
            .flights
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty());
    }

    #[tokio::test]
    async fn generation_and_ttl_invalidate_completed_snapshots() {
        let cache = DirectorySnapshotCache::with_limits(
            Duration::from_millis(20),
            DIRECTORY_SNAPSHOT_MAX_BYTES,
            DIRECTORY_CACHE_MAX_BYTES,
        );
        cache
            .get_or_try_load(key(1), || async { Ok::<_, ()>(Some(snapshot("old"))) })
            .await
            .unwrap();
        let generation_two = cache
            .get_or_try_load(key(2), || async { Ok::<_, ()>(Some(snapshot("new"))) })
            .await
            .unwrap();
        let DirectoryCacheLookup::Snapshot(generation_two) = generation_two else {
            panic!("snapshot expected");
        };
        assert_eq!(generation_two.entries[0].entry.name, "new");

        tokio::time::sleep(Duration::from_millis(25)).await;
        let refreshed = cache
            .get_or_try_load(key(2), || async { Ok::<_, ()>(Some(snapshot("external"))) })
            .await
            .unwrap();
        let DirectoryCacheLookup::Snapshot(refreshed) = refreshed else {
            panic!("snapshot expected");
        };
        assert_eq!(refreshed.entries[0].entry.name, "external");
    }

    #[tokio::test]
    async fn oversized_marker_uses_bounded_heap_fallback_for_one_ttl() {
        let cache = DirectorySnapshotCache::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let first_calls = calls.clone();
        assert!(matches!(
            cache
                .get_or_try_load(key(1), || async move {
                    first_calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(None)
                })
                .await
                .unwrap(),
            DirectoryCacheLookup::Bypass
        ));
        assert!(matches!(
            cache
                .get_or_try_load::<(), _, _>(key(1), || async {
                    panic!("bypass marker must suppress another oversized build")
                })
                .await
                .unwrap(),
            DirectoryCacheLookup::Bypass
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn global_memory_ceiling_evicts_the_least_recent_snapshot() {
        let first_key = key(1);
        let second_key = key(2);
        let first_size = record_overhead(&first_key) + snapshot("first").accounted_bytes();
        let second_size = record_overhead(&second_key) + snapshot("second").accounted_bytes();
        let cache = DirectorySnapshotCache::with_limits(
            Duration::from_secs(1),
            DIRECTORY_SNAPSHOT_MAX_BYTES,
            first_size.max(second_size),
        );
        cache
            .get_or_try_load(first_key.clone(), || async {
                Ok::<_, ()>(Some(snapshot("first")))
            })
            .await
            .unwrap();
        cache
            .get_or_try_load(second_key.clone(), || async {
                Ok::<_, ()>(Some(snapshot("second")))
            })
            .await
            .unwrap();

        let state = cache
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(!state.records.contains_key(&first_key));
        assert!(state.records.contains_key(&second_key));
        assert!(state.total_bytes <= cache.maximum_total_bytes);
    }

    #[test]
    fn builder_rejects_entry_before_crossing_memory_limit() {
        let mut builder = DirectorySnapshotBuilder::with_limit(
            std::mem::size_of::<DirectorySnapshot>()
                + std::mem::size_of::<DirectorySnapshotEntry>()
                + 9,
        );
        let accepted = Entry {
            name: "one".into(),
            is_dir: false,
            len: 1,
            modified: None,
        };
        builder.push(accepted, sort_key("one")).unwrap();
        let rejected = Entry {
            name: "two".into(),
            is_dir: false,
            len: 1,
            modified: None,
        };
        assert_eq!(
            builder.push(rejected, sort_key("two")).unwrap_err().name,
            "two"
        );
    }
}
