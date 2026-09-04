use axum::body::Body;
use tokio::sync::OwnedSemaphorePermit;

use crate::{
    http_auth::ClientActivityPermit,
    services::public_transfer::{PublicTransferLease, ZipTempReservation},
};

struct ZipGenerationResources {
    _zip_permit: OwnedSemaphorePermit,
    _peer_permit: ClientActivityPermit,
}

struct ZipTransferResources {
    generation: ZipGenerationResources,
    transfer: PublicTransferLease,
}

impl ZipTransferResources {
    fn session_token(&self) -> &str {
        self.transfer.session_token()
    }

    async fn cancel(self) {
        let Self {
            generation,
            transfer,
        } = self;
        drop(generation);
        transfer.cancel().await;
    }
}

struct ZipMaterializationResources {
    transfer: ZipTransferResources,
    reservation: ZipTempReservation,
}

enum PreparedZip {
    Materialized(Body),
    Direct(Body),
}

impl PreparedZip {
    fn materialized<F>(resources: ZipTransferResources, body: F) -> Self
    where
        F: FnOnce(PublicTransferLease) -> Body,
    {
        let ZipTransferResources {
            generation,
            transfer,
        } = resources;
        drop(generation);
        Self::Materialized(body(transfer))
    }

    fn direct<F>(resources: ZipTransferResources, body: F) -> Self
    where
        F: FnOnce(PublicTransferLease, ZipGenerationResources) -> Body,
    {
        let ZipTransferResources {
            generation,
            transfer,
        } = resources;
        Self::Direct(body(transfer, generation))
    }

    fn into_body(self) -> Body {
        match self {
            Self::Materialized(body) | Self::Direct(body) => body,
        }
    }
}

async fn zip_blocking_with_resources<R, T, F>(
    resources: R,
    operation: F,
) -> std::result::Result<(R, T), tokio::task::JoinError>
where
    R: Send + 'static,
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let supervisor = tokio::spawn(async move {
        let output = tokio::task::spawn_blocking(operation).await?;
        Ok::<_, tokio::task::JoinError>((resources, output))
    });
    supervisor.await?
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ZipBlockingTestPhase {
    Plan,
    Materialize,
    Direct,
}

#[cfg(test)]
pub(super) struct ZipBlockingTestHook {
    pub(super) path: String,
    pub(super) phase: ZipBlockingTestPhase,
    pub(super) panic_after_release: bool,
    pub(super) entered: std::sync::atomic::AtomicUsize,
    pub(super) released: std::sync::Mutex<bool>,
    pub(super) wake: std::sync::Condvar,
}

#[cfg(test)]
impl ZipBlockingTestHook {
    pub(super) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}

#[cfg(test)]
pub(super) struct ZipBlockingTestGuard(pub(super) std::sync::Arc<ZipBlockingTestHook>);

#[cfg(test)]
impl Drop for ZipBlockingTestGuard {
    fn drop(&mut self) {
        self.0.release();
        let mut hooks = ZIP_BLOCKING_TEST_HOOK
            .get_or_init(|| std::sync::Mutex::new(Vec::new()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        hooks.retain(|active| !std::sync::Arc::ptr_eq(active, &self.0));
    }
}

#[cfg(test)]
static ZIP_BLOCKING_TEST_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Vec<std::sync::Arc<ZipBlockingTestHook>>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
pub(super) fn install_zip_blocking_test_hook(
    hook: std::sync::Arc<ZipBlockingTestHook>,
) -> ZipBlockingTestGuard {
    ZIP_BLOCKING_TEST_HOOK
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(hook.clone());
    ZipBlockingTestGuard(hook)
}

#[cfg(test)]
fn zip_test_phase_active(path: &str, phase: ZipBlockingTestPhase) -> bool {
    ZIP_BLOCKING_TEST_HOOK
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(|hook| hook.path == path && hook.phase == phase)
}

#[cfg(test)]
fn block_zip_for_test(path: &str, phase: ZipBlockingTestPhase) {
    let hook = ZIP_BLOCKING_TEST_HOOK
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|hook| hook.path == path && hook.phase == phase)
        .cloned();
    let Some(hook) = hook else {
        return;
    };
    hook.entered
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    let mut released = hook.released.lock().unwrap();
    while !*released {
        released = hook.wake.wait(released).unwrap();
    }
    drop(released);
    if hook.panic_after_release {
        panic!("injected ZIP blocking task panic");
    }
}

#[path = "transfer/download.rs"]
mod download_adapter;
#[path = "transfer/zip.rs"]
mod zip_adapter;

pub(crate) use download_adapter::download;
pub(crate) use zip_adapter::download_zip;
