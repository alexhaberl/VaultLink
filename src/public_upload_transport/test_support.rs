#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicUploadTestPhase {
    TargetBinding,
    Staging,
    StagingSync,
    Finalizer,
    StorageLocked,
}

pub(crate) struct PublicUploadTestHook {
    token: String,
    phase: PublicUploadTestPhase,
    entered: std::sync::atomic::AtomicUsize,
    entered_wake: tokio::sync::Notify,
    released: std::sync::atomic::AtomicBool,
    release_wake: tokio::sync::Notify,
    blocking_release_lock: std::sync::Mutex<()>,
    blocking_release_wake: std::sync::Condvar,
    failure: Option<std::io::ErrorKind>,
}

impl PublicUploadTestHook {
    pub(crate) fn blocking(token: &str, phase: PublicUploadTestPhase) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            token: token.to_string(),
            phase,
            entered: std::sync::atomic::AtomicUsize::new(0),
            entered_wake: tokio::sync::Notify::new(),
            released: std::sync::atomic::AtomicBool::new(false),
            release_wake: tokio::sync::Notify::new(),
            blocking_release_lock: std::sync::Mutex::new(()),
            blocking_release_wake: std::sync::Condvar::new(),
            failure: None,
        })
    }

    pub(crate) fn failing(
        token: &str,
        phase: PublicUploadTestPhase,
        failure: std::io::ErrorKind,
    ) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            token: token.to_string(),
            phase,
            entered: std::sync::atomic::AtomicUsize::new(0),
            entered_wake: tokio::sync::Notify::new(),
            released: std::sync::atomic::AtomicBool::new(true),
            release_wake: tokio::sync::Notify::new(),
            blocking_release_lock: std::sync::Mutex::new(()),
            blocking_release_wake: std::sync::Condvar::new(),
            failure: Some(failure),
        })
    }

    pub(crate) async fn wait_until_entered(&self) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while self.entered.load(std::sync::atomic::Ordering::Acquire) == 0 {
                self.entered_wake.notified().await;
            }
        })
        .await
        .expect("public upload test phase should be reached");
    }

    pub(crate) fn release(&self) {
        self.released
            .store(true, std::sync::atomic::Ordering::Release);
        self.release_wake.notify_one();
        self.blocking_release_wake.notify_all();
    }
}

pub(crate) struct PublicUploadTestGuard(std::sync::Arc<PublicUploadTestHook>);

impl Drop for PublicUploadTestGuard {
    fn drop(&mut self) {
        self.0.release();
        let mut hooks = PUBLIC_UPLOAD_TEST_HOOKS
            .get_or_init(|| std::sync::Mutex::new(Vec::new()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        hooks.retain(|active| !std::sync::Arc::ptr_eq(active, &self.0));
    }
}

static PUBLIC_UPLOAD_TEST_HOOKS: std::sync::OnceLock<
    std::sync::Mutex<Vec<std::sync::Arc<PublicUploadTestHook>>>,
> = std::sync::OnceLock::new();

fn active_upload_test_hook(
    token: &str,
    phase: PublicUploadTestPhase,
) -> Option<std::sync::Arc<PublicUploadTestHook>> {
    PUBLIC_UPLOAD_TEST_HOOKS
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|hook| hook.token == token && hook.phase == phase)
        .cloned()
}

pub(crate) fn install_public_upload_test_hook(
    hook: std::sync::Arc<PublicUploadTestHook>,
) -> PublicUploadTestGuard {
    PUBLIC_UPLOAD_TEST_HOOKS
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(hook.clone());
    PublicUploadTestGuard(hook)
}

pub(super) async fn upload_phase_test_checkpoint(
    token: &str,
    phase: PublicUploadTestPhase,
) -> std::io::Result<()> {
    let hook = active_upload_test_hook(token, phase);
    let Some(hook) = hook else {
        return Ok(());
    };
    hook.entered
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    hook.entered_wake.notify_one();
    if let Some(kind) = hook.failure {
        return Err(std::io::Error::new(kind, "injected upload staging failure"));
    }
    while !hook.released.load(std::sync::atomic::Ordering::Acquire) {
        hook.release_wake.notified().await;
    }
    Ok(())
}

pub(super) fn upload_blocking_phase_test_checkpoint(
    token: &str,
    phase: PublicUploadTestPhase,
) -> std::io::Result<()> {
    let Some(hook) = active_upload_test_hook(token, phase) else {
        return Ok(());
    };
    hook.entered
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    hook.entered_wake.notify_one();
    if let Some(kind) = hook.failure {
        return Err(std::io::Error::new(
            kind,
            "injected upload target binding failure",
        ));
    }
    let mut release = hook
        .blocking_release_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    while !hook.released.load(std::sync::atomic::Ordering::Acquire) {
        release = hook
            .blocking_release_wake
            .wait(release)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
    Ok(())
}
