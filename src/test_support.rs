use std::sync::{Mutex, MutexGuard};

// A thread-local tracing dispatcher still rebuilds process-wide callsite
// interest caches when it is installed or removed. Keep only tests that swap
// dispatchers mutually exclusive so parallel tests cannot hide one another's
// events. This intentionally does not serialize the rest of the test suite.
static TRACING_SUBSCRIBER_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn tracing_subscriber_guard() -> MutexGuard<'static, ()> {
    TRACING_SUBSCRIBER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
