use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use thiserror::Error;
use tokio::sync::{Mutex, Notify, OwnedMutexGuard};

use crate::{file_ops, log_safety::EscapedLogValue, AppState};

pub(crate) const CLEANUP_BATCH_ENTRIES: usize = 4096;
#[cfg(not(test))]
const CLEANUP_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(test)]
const CLEANUP_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(25);

#[derive(Clone)]
pub struct StorageCleanupCoordinator {
    inner: Arc<CoordinatorInner>,
}

struct CoordinatorInner {
    dirty: AtomicBool,
    shutdown: AtomicBool,
    worker_active: AtomicBool,
    notify: Notify,
    serialization: Arc<Mutex<()>>,
    #[cfg(test)]
    pass_count: std::sync::atomic::AtomicUsize,
}

#[derive(Debug, Error)]
pub enum StorageCleanupStartError {
    #[error("storage cleanup worker is already running")]
    AlreadyRunning,
    #[error("storage cleanup coordinator is shutting down")]
    ShuttingDown,
}

pub struct StorageCleanupWorker {
    coordinator: StorageCleanupCoordinator,
    task: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Default)]
struct CleanupStats {
    scanned: usize,
    removed: usize,
    failed: usize,
}

enum CleanupPassError {
    Cancelled,
    Io(std::io::Error),
    Join(tokio::task::JoinError),
    Recovery(file_ops::FileOperationError),
}

fn report_successful_cleanup(stats: &CleanupStats) {
    if stats.removed > 0 {
        tracing::info!(
            scanned = stats.scanned,
            removed = stats.removed,
            "storage cleanup completed"
        );
    }
}

fn report_cleanup_error(error: &CleanupPassError) {
    match error {
        CleanupPassError::Io(error) => {
            tracing::warn!(
                error = %EscapedLogValue::new(error),
                "storage cleanup failed; retrying"
            );
        }
        CleanupPassError::Join(error) => {
            tracing::warn!(%error, "storage cleanup blocking task failed; retrying");
        }
        CleanupPassError::Recovery(error) => {
            tracing::warn!(
                error = %EscapedLogValue::new(error),
                "storage cleanup could not acquire a clean namespace; retrying"
            );
        }
        CleanupPassError::Cancelled => {}
    }
}

impl StorageCleanupCoordinator {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(CoordinatorInner {
                // Every process start performs one broad pass so stale upload
                // fragments and journal-free tombstones are not dependent on a
                // new deletion occurring.
                dirty: AtomicBool::new(true),
                shutdown: AtomicBool::new(false),
                worker_active: AtomicBool::new(false),
                notify: Notify::new(),
                serialization: Arc::new(Mutex::new(())),
                #[cfg(test)]
                pass_count: std::sync::atomic::AtomicUsize::new(0),
            }),
        }
    }

    /// Coalesces any number of cleanup requests into one bit of in-memory
    /// state. The filesystem tombstones remain the durable work list.
    pub fn request_cleanup(&self) {
        self.inner.dirty.store(true, Ordering::Release);
        self.inner.notify.notify_one();
    }

    pub(crate) fn start_worker(
        &self,
        state: AppState,
    ) -> Result<StorageCleanupWorker, StorageCleanupStartError> {
        if self.inner.shutdown.load(Ordering::Acquire) {
            return Err(StorageCleanupStartError::ShuttingDown);
        }
        self.inner
            .worker_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| StorageCleanupStartError::AlreadyRunning)?;

        let coordinator = self.clone();
        let task_coordinator = coordinator.clone();
        let task = tokio::spawn(async move {
            let _active = ActiveWorkerGuard(task_coordinator.inner.clone());
            task_coordinator.run(state).await;
        });
        Ok(StorageCleanupWorker {
            coordinator,
            task: Some(task),
        })
    }

    pub fn request_shutdown(&self) {
        self.inner.shutdown.store(true, Ordering::Release);
        // There is exactly one waiter. notify_one also preserves a permit if
        // shutdown races the worker immediately before it begins waiting.
        self.inner.notify.notify_one();
    }

    async fn run(&self, state: AppState) {
        while self.wait_for_cleanup_pass().await {
            #[cfg(test)]
            self.inner.pass_count.fetch_add(1, Ordering::Relaxed);

            if !self
                .handle_pass_result(self.run_pass(state.clone()).await)
                .await
            {
                return;
            }
        }
    }

    async fn wait_for_cleanup_pass(&self) -> bool {
        loop {
            if self.inner.shutdown.load(Ordering::Acquire) {
                return false;
            }
            if self.inner.dirty.swap(false, Ordering::AcqRel) {
                return true;
            }
            self.wait_for_work().await;
        }
    }

    async fn handle_pass_result(&self, result: Result<CleanupStats, CleanupPassError>) -> bool {
        match result {
            Ok(stats) if stats.failed == 0 => {
                report_successful_cleanup(&stats);
                true
            }
            Ok(stats) => {
                tracing::warn!(
                    scanned = stats.scanned,
                    removed = stats.removed,
                    failed = stats.failed,
                    "storage cleanup left entries behind; retrying"
                );
                self.schedule_retry().await
            }
            Err(CleanupPassError::Cancelled) => false,
            Err(error) => {
                report_cleanup_error(&error);
                self.schedule_retry().await
            }
        }
    }

    async fn schedule_retry(&self) -> bool {
        self.inner.dirty.store(true, Ordering::Release);
        self.wait_for_retry_or_shutdown().await
    }

    async fn wait_for_work(&self) {
        loop {
            let notified = self.inner.notify.notified();
            if self.inner.shutdown.load(Ordering::Acquire)
                || self.inner.dirty.load(Ordering::Acquire)
            {
                return;
            }
            notified.await;
        }
    }

    async fn wait_for_retry_or_shutdown(&self) -> bool {
        let deadline = tokio::time::Instant::now() + CLEANUP_RETRY_DELAY;
        loop {
            if self.inner.shutdown.load(Ordering::Acquire) {
                return false;
            }
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => return true,
                _ = self.inner.notify.notified() => {
                    // Work notifications are intentionally coalesced while the
                    // retry deadline is active. This bounds both attempts and
                    // warning logs under a persistent storage failure.
                }
            }
        }
    }

    async fn run_pass(&self, state: AppState) -> Result<CleanupStats, CleanupPassError> {
        let cleanup_guard = self.acquire_serialization().await?;
        let acquire_authority = file_ops::acquire_storage_mutation(&state);
        tokio::pin!(acquire_authority);
        let authority_guard = loop {
            tokio::select! {
                result = &mut acquire_authority => {
                    break result.map_err(CleanupPassError::Recovery)?;
                }
                _ = self.inner.notify.notified() => {
                    if self.inner.shutdown.load(Ordering::Acquire) {
                        return Err(CleanupPassError::Cancelled);
                    }
                }
            }
        };
        let secure_root = state.secure_root().clone();
        let start_root = secure_root.clone();
        let (cleanup, mut cleanup_guard, mut authority_guard) =
            tokio::task::spawn_blocking(move || {
                let cleanup = start_root.start_upload_fragment_cleanup();
                (cleanup, cleanup_guard, authority_guard)
            })
            .await
            .map_err(CleanupPassError::Join)?;
        let mut cleanup = cleanup.map_err(CleanupPassError::Io)?;
        let mut stats = CleanupStats::default();

        loop {
            // Shutdown permits a batch that is already inside spawn_blocking to
            // finish, but must never launch a new batch afterwards (including
            // when shutdown raced cursor construction or the inter-batch yield).
            if self.inner.shutdown.load(Ordering::Acquire) {
                return Err(CleanupPassError::Cancelled);
            }
            let result = tokio::task::spawn_blocking(move || {
                let batch = cleanup.run_batch(CLEANUP_BATCH_ENTRIES);
                (cleanup, cleanup_guard, authority_guard, batch)
            })
            .await
            .map_err(CleanupPassError::Join)?;
            cleanup = result.0;
            cleanup_guard = result.1;
            authority_guard = result.2;
            let batch = result.3.map_err(CleanupPassError::Io)?;
            stats.scanned = stats.scanned.saturating_add(batch.scanned);
            stats.removed = stats.removed.saturating_add(batch.removed);
            stats.failed = stats.failed.saturating_add(batch.failed);
            if self.inner.shutdown.load(Ordering::Acquire) {
                return Err(CleanupPassError::Cancelled);
            }
            if batch.complete {
                authority_guard.finish_clean();
                return Ok(stats);
            }
            tokio::task::yield_now().await;
        }
    }

    async fn acquire_serialization(&self) -> Result<OwnedMutexGuard<()>, CleanupPassError> {
        loop {
            if self.inner.shutdown.load(Ordering::Acquire) {
                return Err(CleanupPassError::Cancelled);
            }
            let lock = self.inner.serialization.clone().lock_owned();
            tokio::pin!(lock);
            tokio::select! {
                guard = &mut lock => return Ok(guard),
                _ = self.inner.notify.notified() => {
                    if self.inner.shutdown.load(Ordering::Acquire) {
                        return Err(CleanupPassError::Cancelled);
                    }
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn serialization_for_test(&self) -> Arc<Mutex<()>> {
        self.inner.serialization.clone()
    }

    #[cfg(test)]
    pub(crate) fn pass_count_for_test(&self) -> usize {
        self.inner.pass_count.load(Ordering::Relaxed)
    }
}

impl Default for StorageCleanupCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageCleanupWorker {
    pub fn request_shutdown(&self) {
        self.coordinator.request_shutdown();
    }

    pub async fn join(mut self) -> Result<(), tokio::task::JoinError> {
        match self.task.take() {
            Some(task) => task.await,
            None => Ok(()),
        }
    }

    pub async fn shutdown(self) -> Result<(), tokio::task::JoinError> {
        self.request_shutdown();
        self.join().await
    }
}

impl Drop for StorageCleanupWorker {
    fn drop(&mut self) {
        // Error paths that leave server setup before the explicit join still
        // wake the worker. The Tokio runtime owns final task teardown.
        self.coordinator.request_shutdown();
    }
}

struct ActiveWorkerGuard(Arc<CoordinatorInner>);

impl Drop for ActiveWorkerGuard {
    fn drop(&mut self) {
        self.0.worker_active.store(false, Ordering::Release);
    }
}
