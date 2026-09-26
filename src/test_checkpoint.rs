//! Deterministic barriers for cancellation/race regressions; never built in production.
use std::{
    collections::HashMap,
    sync::{Arc, Condvar, Mutex, OnceLock, Weak},
    time::Duration,
};

#[derive(Default)]
struct State {
    entered: bool,
    released: bool,
}
#[derive(Default)]
struct Barrier {
    state: Mutex<State>,
    wake: Condvar,
}
static BARRIERS: OnceLock<Mutex<HashMap<String, Weak<Barrier>>>> = OnceLock::new();

pub(crate) struct Checkpoint {
    key: String,
    barrier: Arc<Barrier>,
}
impl Checkpoint {
    pub(crate) fn new(key: String) -> Self {
        let barrier = Arc::new(Barrier::default());
        assert!(BARRIERS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .insert(key.clone(), Arc::downgrade(&barrier))
            .is_none());
        Self { key, barrier }
    }
    pub(crate) async fn entered(&self) {
        tokio::time::timeout(Duration::from_secs(20), async {
            while !self.barrier.state.lock().unwrap().entered {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("checkpoint was not reached");
    }
    pub(crate) fn release(&self) {
        self.barrier.state.lock().unwrap().released = true;
        self.barrier.wake.notify_all();
    }
}
impl Drop for Checkpoint {
    fn drop(&mut self) {
        self.release();
        BARRIERS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .remove(&self.key);
    }
}
pub(crate) fn hit(key: &str) {
    let barrier = BARRIERS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .get(key)
        .and_then(Weak::upgrade);
    if let Some(barrier) = barrier {
        let mut state = barrier.state.lock().unwrap();
        state.entered = true;
        let (_state, timeout) = barrier
            .wake
            .wait_timeout_while(state, Duration::from_secs(30), |state| !state.released)
            .unwrap();
        assert!(!timeout.timed_out(), "checkpoint release timed out");
    }
}
pub(crate) async fn hit_async(key: String) {
    tokio::task::spawn_blocking(move || hit(&key))
        .await
        .unwrap();
}
