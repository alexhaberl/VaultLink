use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::sync::Semaphore;

use crate::{db::Database, log_safety::EscapedLogValue, secure_fs::SecureRoot};

const CACHE_TTL: Duration = Duration::from_secs(1);
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub(crate) struct ReadinessProbe {
    inner: Arc<ReadinessProbeInner>,
}

struct ReadinessProbeInner {
    admission: Arc<Semaphore>,
    cache: Arc<Mutex<Option<CachedReadiness>>>,
    runner: ProbeRunner,
}

type ProbeRunner =
    Arc<dyn Fn(&Database, &SecureRoot) -> Result<(), ReadinessFailure> + Send + Sync + 'static>;

#[derive(Clone)]
struct CachedReadiness {
    checked_at: Instant,
    ready: bool,
}

impl ReadinessProbe {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(ReadinessProbeInner {
                admission: Arc::new(Semaphore::new(1)),
                cache: Arc::new(Mutex::new(None)),
                runner: Arc::new(run_probe),
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        delay: Duration,
        component: Option<&'static str>,
    ) -> (Self, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = Arc::new(AtomicUsize::new(0));
        let runner_calls = calls.clone();
        let runner = Arc::new(move |_: &Database, _: &SecureRoot| {
            runner_calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(delay);
            match component {
                Some(component) => Err(ReadinessFailure {
                    component,
                    error: "injected readiness failure".into(),
                }),
                None => Ok(()),
            }
        });
        (
            Self {
                inner: Arc::new(ReadinessProbeInner {
                    admission: Arc::new(Semaphore::new(1)),
                    cache: Arc::new(Mutex::new(None)),
                    runner,
                }),
            },
            calls,
        )
    }

    fn cached(&self) -> Option<bool> {
        self.inner
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .filter(|cached| cached.checked_at.elapsed() < CACHE_TTL)
            .map(|cached| cached.ready)
    }

    pub(crate) async fn check(&self, database: Database, storage: SecureRoot) -> bool {
        if let Some(ready) = self.cached() {
            return ready;
        }

        let probe = async {
            let permit = self
                .inner
                .admission
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| "readiness admission closed")?;
            if let Some(ready) = self.cached() {
                return Ok(ready);
            }
            let database_permit =
                tokio::time::timeout(Duration::from_secs(1), database.acquire_runtime_permit())
                    .await
                    .map_err(|_| "database readiness admission timed out")?
                    .map_err(|_| "database readiness admission closed")?;
            let cache = self.inner.cache.clone();
            let runner = self.inner.runner.clone();
            tokio::task::spawn_blocking(move || {
                // The permit deliberately lives inside the blocking task. A timed-out
                // caller cannot start more probes while this one remains stuck.
                let _permit = permit;
                let _database_permit = database_permit;
                let result = runner(&database, &storage);
                let ready = result.is_ok();
                *cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(CachedReadiness {
                    checked_at: Instant::now(),
                    ready,
                });
                if let Err(failure) = result {
                    tracing::warn!(
                        component = failure.component,
                        error = %EscapedLogValue::new(&failure.error),
                        "readiness probe failed"
                    );
                }
                ready
            })
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "readiness probe task failed");
                "readiness task failed"
            })
        };

        match tokio::time::timeout(PROBE_TIMEOUT, probe).await {
            Ok(Ok(ready)) => ready,
            Ok(Err(error)) => {
                tracing::warn!(component = "probe", error, "readiness probe unavailable");
                false
            }
            Err(_) => {
                tracing::warn!(
                    component = "probe",
                    timeout_seconds = PROBE_TIMEOUT.as_secs(),
                    "readiness probe timed out"
                );
                false
            }
        }
    }
}

struct ReadinessFailure {
    component: &'static str,
    error: String,
}

fn run_probe(database: &Database, storage: &SecureRoot) -> Result<(), ReadinessFailure> {
    database
        .readiness_check()
        .map_err(|error| ReadinessFailure {
            component: "database",
            error,
        })?;
    storage.readiness_check().map_err(|error| ReadinessFailure {
        component: "storage",
        error: error.to_string(),
    })
}
