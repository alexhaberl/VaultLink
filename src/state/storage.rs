use std::sync::Arc;

use crate::{
    directory_cache::DirectorySnapshotCache,
    disk_stats::DiskStatsCache,
    secure_fs::SecureRoot,
    storage_authority::{StorageAuthorityCoordinator, StorageMutationGuard, StorageReadGuard},
    storage_cleanup::{StorageCleanupCoordinator, StorageCleanupStartError, StorageCleanupWorker},
    AppState, StorageInstanceLock,
};

pub(super) struct StorageContext {
    secure_root: SecureRoot,
    authority: StorageAuthorityCoordinator,
    cleanup: StorageCleanupCoordinator,
    disk_stats_cache: DiskStatsCache,
    directory_snapshot_cache: DirectorySnapshotCache,
    // The descriptor owns the kernel lock. Keeping it in every AppState clone
    // prevents another serving process from entering recovery or cleanup for
    // the same private storage domain.
    _instance_lock: Arc<StorageInstanceLock>,
}

impl StorageContext {
    pub(super) fn new(secure_root: SecureRoot, instance_lock: Arc<StorageInstanceLock>) -> Self {
        Self {
            secure_root,
            authority: StorageAuthorityCoordinator::new(),
            cleanup: StorageCleanupCoordinator::new(),
            disk_stats_cache: DiskStatsCache::new(),
            directory_snapshot_cache: DirectorySnapshotCache::new(),
            _instance_lock: instance_lock,
        }
    }

    pub(super) fn secure_root(&self) -> &SecureRoot {
        &self.secure_root
    }

    pub(super) fn cleanup(&self) -> &StorageCleanupCoordinator {
        &self.cleanup
    }

    pub(super) fn disk_stats_cache(&self) -> &DiskStatsCache {
        &self.disk_stats_cache
    }

    pub(super) fn directory_snapshot_cache(&self) -> &DirectorySnapshotCache {
        &self.directory_snapshot_cache
    }

    pub(super) async fn acquire_read(&self) -> StorageReadGuard {
        self.authority.acquire_read().await
    }

    pub(super) async fn acquire_mutation(&self) -> StorageMutationGuard {
        self.authority.acquire_mutation().await
    }

    pub(super) async fn acquire_recovery(&self) -> StorageMutationGuard {
        self.authority.acquire_recovery().await
    }

    pub(super) fn recovery_required(&self) -> bool {
        self.authority.recovery_required()
    }

    pub(super) fn start_cleanup_worker(
        &self,
        state: AppState,
    ) -> Result<StorageCleanupWorker, StorageCleanupStartError> {
        self.cleanup.start_worker(state)
    }

    #[cfg(test)]
    pub(super) async fn acquire_test_exclusive(&self) -> tokio::sync::OwnedRwLockWriteGuard<()> {
        self.authority.acquire_test_exclusive().await
    }

    #[cfg(test)]
    pub(super) fn try_acquire_test_exclusive(
        &self,
    ) -> Result<tokio::sync::OwnedRwLockWriteGuard<()>, tokio::sync::TryLockError> {
        self.authority.try_acquire_test_exclusive()
    }

    #[cfg(test)]
    pub(super) async fn block_mutations_for_test(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.authority.block_mutations_for_test().await
    }

    #[cfg(test)]
    pub(super) fn replace_disk_stats_cache(&mut self, cache: DiskStatsCache) {
        self.disk_stats_cache = cache;
    }
}
