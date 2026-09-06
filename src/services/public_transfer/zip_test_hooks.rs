#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ZipBlockingTestPhase {
    Plan,
    Materialize,
    Direct,
}

#[cfg(test)]
pub(crate) struct ZipBlockingTestHook {
    pub(crate) path: String,
    pub(crate) phase: ZipBlockingTestPhase,
    pub(crate) panic_after_release: bool,
    pub(crate) entered: std::sync::atomic::AtomicUsize,
    pub(crate) released: std::sync::Mutex<bool>,
    pub(crate) wake: std::sync::Condvar,
}

#[cfg(test)]
impl ZipBlockingTestHook {
    pub(crate) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}

#[cfg(test)]
pub(crate) struct ZipBlockingTestGuard(pub(crate) std::sync::Arc<ZipBlockingTestHook>);

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
pub(crate) fn install_zip_blocking_test_hook(
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
pub(crate) fn zip_test_phase_active(path: &str, phase: ZipBlockingTestPhase) -> bool {
    ZIP_BLOCKING_TEST_HOOK
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(|hook| hook.path == path && hook.phase == phase)
}

#[cfg(test)]
pub(crate) fn block_zip_for_test(path: &str, phase: ZipBlockingTestPhase) {
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
    let released = hook.released.lock().unwrap();
    let (released, timeout) = hook
        .wake
        .wait_timeout_while(released, std::time::Duration::from_secs(10), |released| {
            !*released
        })
        .unwrap();
    drop(released);
    assert!(!timeout.timed_out(), "ZIP hook timed out");
    if hook.panic_after_release {
        panic!("injected ZIP blocking task panic");
    }
}
