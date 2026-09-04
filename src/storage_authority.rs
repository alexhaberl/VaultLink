use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

/// Coordinates access to the storage namespace within one serving process.
///
/// The kernel-backed instance lock remains the cross-process authority. This
/// coordinator adds fair, parallel read access and records whether a cancelled
/// or failed namespace mutation requires journal recovery before storage may be
/// observed again.
#[derive(Clone, Debug)]
pub(crate) struct StorageAuthorityCoordinator {
    inner: Arc<StorageAuthorityInner>,
}

#[derive(Debug)]
struct StorageAuthorityInner {
    lock: Arc<RwLock<()>>,
    generation: AtomicU64,
    recovery_required: AtomicBool,
    #[cfg(test)]
    mutation_gate: Arc<tokio::sync::Mutex<()>>,
}

/// A clean point-in-time view of the storage namespace.
///
/// Capability descriptors opened while this guard is held remain safe after
/// the guard is released. Callers must therefore release it before streaming.
#[derive(Debug)]
pub(crate) struct StorageReadGuard {
    _guard: OwnedRwLockReadGuard<()>,
    generation: u64,
}

/// Exclusive authority for a namespace mutation and its journal finalizer.
///
/// Dropping this guard deliberately leaves `recovery_required` set. Only
/// `finish_clean` is allowed to publish a clean generation.
#[derive(Debug)]
pub(crate) struct StorageMutationGuard {
    _guard: OwnedRwLockWriteGuard<()>,
    inner: Arc<StorageAuthorityInner>,
    recovery_required_on_entry: bool,
}

impl StorageAuthorityCoordinator {
    /// Startup must perform one recovery pass before the first storage read.
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(StorageAuthorityInner {
                lock: Arc::new(RwLock::new(())),
                generation: AtomicU64::new(0),
                recovery_required: AtomicBool::new(true),
                #[cfg(test)]
                mutation_gate: Arc::new(tokio::sync::Mutex::new(())),
            }),
        }
    }

    pub(crate) async fn acquire_read(&self) -> StorageReadGuard {
        let guard = self.inner.lock.clone().read_owned().await;
        StorageReadGuard {
            _guard: guard,
            generation: self.generation(),
        }
    }

    /// Acquires fair exclusive authority and marks it dirty before returning.
    pub(crate) async fn acquire_mutation(&self) -> StorageMutationGuard {
        #[cfg(test)]
        let _mutation_gate = self.inner.mutation_gate.clone().lock_owned().await;
        let guard = self.inner.lock.clone().write_owned().await;
        let recovery_required_on_entry = self.inner.recovery_required.swap(true, Ordering::AcqRel);
        StorageMutationGuard {
            _guard: guard,
            inner: self.inner.clone(),
            recovery_required_on_entry,
        }
    }

    /// Acquires exclusive authority without introducing new dirty state. This
    /// is used by readers that observed an earlier failed/cancelled writer.
    pub(crate) async fn acquire_recovery(&self) -> StorageMutationGuard {
        let guard = self.inner.lock.clone().write_owned().await;
        let recovery_required_on_entry = self.inner.recovery_required.load(Ordering::Acquire);
        StorageMutationGuard {
            _guard: guard,
            inner: self.inner.clone(),
            recovery_required_on_entry,
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::Acquire)
    }

    pub(crate) fn recovery_required(&self) -> bool {
        self.inner.recovery_required.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) async fn acquire_test_exclusive(&self) -> OwnedRwLockWriteGuard<()> {
        self.inner.lock.clone().write_owned().await
    }

    #[cfg(test)]
    pub(crate) fn try_acquire_test_exclusive(
        &self,
    ) -> Result<OwnedRwLockWriteGuard<()>, tokio::sync::TryLockError> {
        self.inner.lock.clone().try_write_owned()
    }

    /// Blocks only namespace mutations while leaving clean capability reads
    /// available. This lets ordering tests prove work happens before writer
    /// acquisition without accidentally blocking the prerequisite read phase.
    #[cfg(test)]
    pub(crate) async fn block_mutations_for_test(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.inner.mutation_gate.clone().lock_owned().await
    }
}

impl StorageReadGuard {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}

impl StorageMutationGuard {
    pub(crate) fn recovery_required_on_entry(&self) -> bool {
        self.recovery_required_on_entry
    }

    /// Publishes the mutation or recovery as the next clean generation.
    pub(crate) fn finish_clean(self) -> u64 {
        self.inner.recovery_required.store(false, Ordering::Release);
        self.inner.generation.fetch_add(1, Ordering::AcqRel) + 1
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    use super::StorageAuthorityCoordinator;

    #[tokio::test]
    async fn dropped_mutation_is_sticky_until_finish_clean() {
        let coordinator = StorageAuthorityCoordinator::new();
        let startup = coordinator.acquire_mutation().await;
        assert!(startup.recovery_required_on_entry());
        assert_eq!(startup.finish_clean(), 1);
        assert!(!coordinator.recovery_required());

        let mutation = coordinator.acquire_mutation().await;
        assert!(!mutation.recovery_required_on_entry());
        drop(mutation);
        assert!(coordinator.recovery_required());

        let recovery = coordinator.acquire_mutation().await;
        assert!(recovery.recovery_required_on_entry());
        assert_eq!(recovery.finish_clean(), 2);
        assert!(!coordinator.recovery_required());
    }

    #[tokio::test]
    async fn generation_changes_only_at_clean_finish() {
        let coordinator = StorageAuthorityCoordinator::new();
        assert_eq!(coordinator.generation(), 0);
        let mutation = coordinator.acquire_mutation().await;
        assert_eq!(coordinator.generation(), 0);
        drop(mutation);
        assert_eq!(coordinator.generation(), 0);
        let recovery = coordinator.acquire_mutation().await;
        recovery.finish_clean();
        assert_eq!(coordinator.generation(), 1);
    }

    #[tokio::test]
    async fn clean_reads_run_in_parallel_and_share_generation() {
        let coordinator = StorageAuthorityCoordinator::new();
        coordinator.acquire_mutation().await.finish_clean();
        let first = coordinator.acquire_read().await;
        let second = tokio::time::timeout(Duration::from_millis(100), coordinator.acquire_read())
            .await
            .expect("readers must not serialize");
        assert_eq!(first.generation(), second.generation());
    }

    #[tokio::test]
    async fn queued_writer_blocks_later_reader() {
        let coordinator = Arc::new(StorageAuthorityCoordinator::new());
        coordinator.acquire_mutation().await.finish_clean();
        let first_reader = coordinator.acquire_read().await;
        let writer_coordinator = coordinator.clone();
        let writer = tokio::spawn(async move { writer_coordinator.acquire_mutation().await });
        tokio::task::yield_now().await;

        assert!(
            tokio::time::timeout(Duration::from_millis(50), coordinator.acquire_read())
                .await
                .is_err()
        );
        drop(first_reader);
        let writer = writer.await.unwrap();
        writer.finish_clean();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dirty_readers_coalesce_on_one_recovery_generation() {
        let coordinator = Arc::new(StorageAuthorityCoordinator::new());
        coordinator.acquire_mutation().await.finish_clean();
        drop(coordinator.acquire_mutation().await);
        let recoveries = Arc::new(AtomicUsize::new(0));
        let mut readers = Vec::new();
        for _ in 0..16 {
            let coordinator = coordinator.clone();
            let recoveries = recoveries.clone();
            readers.push(tokio::spawn(async move {
                loop {
                    let read = coordinator.acquire_read().await;
                    if !coordinator.recovery_required() {
                        return read.generation();
                    }
                    drop(read);
                    let recovery = coordinator.acquire_recovery().await;
                    if recovery.recovery_required_on_entry() {
                        recoveries.fetch_add(1, Ordering::Relaxed);
                        tokio::task::yield_now().await;
                        recovery.finish_clean();
                    }
                }
            }));
        }
        for reader in readers {
            assert_eq!(reader.await.unwrap(), 2);
        }
        assert_eq!(recoveries.load(Ordering::Relaxed), 1);
        assert_eq!(coordinator.generation(), 2);
    }
}
