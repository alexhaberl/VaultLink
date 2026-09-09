use super::transfer_progress::TransferAdmissionBudget;
use super::{
    admission_diagnostics::DatabaseWorkPermit, slow_diagnostics::WorkTiming, Database,
    DatabaseExecutorAdmission, RuntimeDatabasePermit, TransferDatabasePermit,
};
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Wake, Waker},
    thread::Thread,
    time::{Duration, Instant},
};
use tokio::{runtime::Handle, sync::oneshot, task::JoinHandle};

const DATABASE_QUEUE_TIMEOUT: Duration = Duration::from_secs(1);

type AdmissionFuture<P> =
    Pin<Box<dyn Future<Output = Result<P, tokio::sync::AcquireError>> + Send + 'static>>;
type LaunchedWork<T> = Result<JoinHandle<T>, DatabaseExecutorAdmission>;

/// One transient admission dispatcher per database, independent of both the
/// HTTP scheduler and Tokio's bounded blocking pool. Only admitted SQL work
/// enters the blocking pool; waiting requests never occupy a blocking worker.
#[derive(Default)]
pub(super) struct DatabaseDispatcher {
    queue: Mutex<DispatchQueue>,
    wake: Arc<DispatcherWake>,
}

#[derive(Default)]
struct DispatchQueue {
    jobs: VecDeque<Box<dyn PendingDatabaseJob>>,
    active: bool,
}

trait PendingDatabaseJob: Send {
    fn dispatcher_started(&mut self, pending_jobs: usize);
    fn poll(&mut self, context: &mut Context<'_>) -> Poll<()>;
    fn deadline(&self) -> Instant;
}

struct DatabaseJob<P, F, T> {
    database: Database,
    class: &'static str,
    started: Instant,
    deadline: Instant,
    progress_budget: Option<TransferAdmissionBudget>,
    pending_transfer: Option<tokio::sync::OwnedSemaphorePermit>,
    admission: Option<AdmissionFuture<P>>,
    operation: Option<F>,
    sender: Option<oneshot::Sender<LaunchedWork<T>>>,
    handle: Handle,
    subscriber: tracing::Dispatch,
    span: tracing::Span,
    timing: Option<WorkTiming>,
}

impl<P, F, T> DatabaseJob<P, F, T>
where
    P: DatabaseWorkPermit,
    F: FnOnce(Database, P) -> T + Send + 'static,
    T: Send + 'static,
{
    fn reject(&mut self, reason: &'static str) -> Poll<()> {
        // An incomplete composite acquisition may already own a class permit.
        // Release that before taking the failure snapshot or reporting it.
        drop(self.admission.take());
        drop(self.pending_transfer.take());
        let error =
            DatabaseExecutorAdmission::new(&self.database, self.class, self.started.elapsed());
        let rejected_at = Instant::now();
        // Deliver the admission failure before optional telemetry is queued.
        // Its subscriber may start immediately on the detached logging worker.
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(Err(error));
        }
        if let Some(timing) = self.timing.take() {
            tracing::dispatcher::with_default(&self.subscriber, || {
                timing.rejected(reason, rejected_at)
            });
        }
        Poll::Ready(())
    }

    fn launch(&mut self, permit: P) -> Poll<()> {
        // A running operation owns runtime capacity; only unadmitted work
        // consumes the separate bounded transfer queue.
        drop(self.pending_transfer.take());
        let database = self.database.clone();
        let class = self.class;
        let operation = self.operation.take().expect("a database job launches once");
        let subscriber = self.subscriber.clone();
        let span = self.span.clone();
        let mut timing = self.timing.take().expect("a database job launches once");
        // A ready fast-path job needs no dispatcher thread. Pending jobs
        // already retain their actual first drain-poll time here.
        timing.dispatcher_started();
        timing.admitted();
        let worker = self.handle.spawn_blocking(move || {
            tracing::dispatcher::with_default(&subscriber, || {
                let _span = span.enter();
                timing.worker_started();
                permit.begin_work(class);
                let result = operation(database.clone(), permit);
                timing.finish(&database.0.work_diagnostics);
                result
            })
        });
        if let Some(sender) = self.sender.take() {
            // Cancellation after dispatch detaches the worker. Its permit
            // remains owned until the actual database operation completes.
            let _ = sender.send(Ok(worker));
        }
        Poll::Ready(())
    }

    fn poll_with_clock(
        &mut self,
        context: &mut Context<'_>,
        now: impl Fn() -> Instant,
    ) -> Poll<()> {
        let Some(sender) = self.sender.as_mut() else {
            return Poll::Ready(());
        };
        // Register the same thread-backed waker for request cancellation.
        // Dropping an unadmitted request therefore removes its FIFO entry
        // without requiring another request poll or a timer-driver wakeup.
        if sender.poll_closed(context).is_ready() {
            return Poll::Ready(());
        }
        if let Some(budget) = &mut self.progress_budget {
            self.deadline = budget.refresh(&self.database.0.transfer_progress);
        }
        let polled_at = now();
        if polled_at >= self.deadline {
            return self.reject_expired(polled_at);
        }
        match self
            .admission
            .as_mut()
            .expect("a queued database job retains its admission future")
            .as_mut()
            .poll(context)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => self.reject("admission_closed"),
            Poll::Ready(Ok(permit)) => {
                // A predecessor may publish completion during acquisition.
                // Use that timestamp before checking the shared queue budget.
                if let Some(budget) = &mut self.progress_budget {
                    self.deadline = budget.refresh(&self.database.0.transfer_progress);
                }
                let admitted_at = now();
                if admitted_at >= self.deadline {
                    drop(permit);
                    return self.reject_expired(admitted_at);
                }
                if self.sender.as_ref().is_none_or(oneshot::Sender::is_closed) {
                    return Poll::Ready(());
                }
                drop(self.admission.take());
                self.launch(permit)
            }
        }
    }

    fn reject_expired(&mut self, now: Instant) -> Poll<()> {
        let reason = self
            .progress_budget
            .as_ref()
            .map_or("queue_timeout", |budget| budget.reason(now));
        self.reject(reason)
    }
}

impl<P, F, T> PendingDatabaseJob for DatabaseJob<P, F, T>
where
    P: DatabaseWorkPermit,
    F: FnOnce(Database, P) -> T + Send + 'static,
    T: Send + 'static,
{
    fn dispatcher_started(&mut self, pending_jobs: usize) {
        if let Some(timing) = self.timing.as_mut() {
            timing.dispatcher_started();
            timing.dispatcher_polled(pending_jobs);
        }
    }

    fn poll(&mut self, context: &mut Context<'_>) -> Poll<()> {
        self.poll_with_clock(context, Instant::now)
    }

    fn deadline(&self) -> Instant {
        self.deadline
    }
}

/// Enqueues general database work once. Neither admission nor the subsequent
/// SQL-worker launch depends on polling this response future again.
pub(crate) async fn dispatch_database_work<T, F>(
    database: Database,
    class: &'static str,
    operation: F,
) -> Result<JoinHandle<T>, DatabaseExecutorAdmission>
where
    T: Send + 'static,
    F: FnOnce(Database, RuntimeDatabasePermit) -> T + Send + 'static,
{
    let admission_database = database.clone();
    dispatch(
        database,
        class,
        async move { admission_database.acquire_runtime_permit().await },
        operation,
    )
    .await
}

/// Uses transfer-then-global FIFO admission. Completed transfer work can
/// renew the inactivity budget, within a fixed total deadline and queue cap.
pub(crate) async fn dispatch_transfer_database_work<T, F>(
    database: Database,
    class: &'static str,
    operation: F,
) -> Result<JoinHandle<T>, DatabaseExecutorAdmission>
where
    T: Send + 'static,
    F: FnOnce(Database, TransferDatabasePermit) -> T + Send + 'static,
{
    let admission_database = database.clone();
    dispatch(
        database,
        class,
        async move { admission_database.acquire_transfer_runtime_permit().await },
        operation,
    )
    .await
}

async fn dispatch<P, F, T>(
    database: Database,
    class: &'static str,
    admission: impl Future<Output = Result<P, tokio::sync::AcquireError>> + Send + 'static,
    operation: F,
) -> Result<JoinHandle<T>, DatabaseExecutorAdmission>
where
    P: DatabaseWorkPermit,
    F: FnOnce(Database, P) -> T + Send + 'static,
    T: Send + 'static,
{
    let started = Instant::now();
    let pending_transfer = if P::IS_TRANSFER {
        match database
            .0
            .transfer_queue_admission
            .clone()
            .try_acquire_owned()
        {
            Ok(permit) => Some(permit),
            Err(_) => {
                database
                    .0
                    .work_diagnostics
                    .start(class)
                    .rejected("transfer_queue_full", started);
                return Err(DatabaseExecutorAdmission::new(
                    &database,
                    class,
                    started.elapsed(),
                ));
            }
        }
    } else {
        None
    };
    let (sender, receiver) = oneshot::channel();
    let mut job = Box::new(DatabaseJob {
        database: database.clone(),
        class,
        started,
        deadline: started + DATABASE_QUEUE_TIMEOUT,
        progress_budget: P::IS_TRANSFER.then(|| TransferAdmissionBudget::new(started)),
        pending_transfer,
        admission: Some(Box::pin(admission)),
        operation: Some(operation),
        sender: Some(sender),
        handle: Handle::current(),
        subscriber: tracing::dispatcher::get_default(Clone::clone),
        span: tracing::Span::current(),
        timing: Some(database.0.work_diagnostics.start(class)),
    });
    // Preserve the existing FIFO position at the request's first poll, even
    // relative to direct admission users. A ready job can start immediately;
    // only a pending admission needs the transient dispatcher thread.
    let pending = {
        let waker = Waker::from(database.0.dispatch.wake.clone());
        let mut context = Context::from_waker(&waker);
        job.poll(&mut context).is_pending()
    };
    if pending {
        enqueue(&database, job);
    } else {
        drop(job);
    }
    receiver.await.unwrap_or_else(|_| {
        // A failed thread launch or an unwinding dispatcher drops its queued
        // senders and fails closed, without executing the unadmitted work.
        Err(DatabaseExecutorAdmission::new(
            &database,
            class,
            started.elapsed(),
        ))
    })
}

fn enqueue(database: &Database, job: Box<dyn PendingDatabaseJob>) {
    let start = {
        let mut queue = database
            .0
            .dispatch
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        queue.jobs.push_back(job);
        let start = !queue.active;
        queue.active = true;
        start
    };
    if start {
        let guard = DispatcherGuard::new(database.clone());
        if std::thread::Builder::new()
            .name("vaultlink-db-dispatch".into())
            .spawn(move || drain(guard))
            .is_err()
        {
            // On spawn failure Rust drops the closure and its guard. Pending
            // senders are dropped outside the queue lock by that guard.
            tracing::error!(
                operation = "database.dispatcher.start",
                "database admission dispatcher could not start"
            );
        }
    } else {
        database.0.dispatch.wake.wake_by_ref();
    }
}

// The waker retains no database handle: a semaphore queue cannot keep a
// database alive solely through its registered wake target.
#[derive(Default)]
struct DispatcherWake(Mutex<Option<Thread>>);

impl DispatcherWake {
    fn set_thread(&self, thread: Option<Thread>) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = thread;
    }

    fn unpark(&self) {
        let thread = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(thread) = thread {
            thread.unpark();
        }
    }
}

impl Wake for DispatcherWake {
    fn wake(self: Arc<Self>) {
        self.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.unpark();
    }
}

struct DispatcherGuard {
    database: Database,
    armed: bool,
}

impl DispatcherGuard {
    fn new(database: Database) -> Self {
        Self {
            database,
            armed: true,
        }
    }
}

impl Drop for DispatcherGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let jobs = {
            let mut queue = self
                .database
                .0
                .dispatch
                .queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            queue.active = false;
            self.database.0.dispatch.wake.set_thread(None);
            std::mem::take(&mut queue.jobs)
        };
        // Dropping queued closures may release other admission and wake
        // unrelated work. Never do that while holding our queue lock.
        drop(jobs);
    }
}

fn drain(mut guard: DispatcherGuard) {
    let current = std::thread::current();
    let waker = Waker::from(guard.database.0.dispatch.wake.clone());
    let mut context = Context::from_waker(&waker);
    let mut pending = VecDeque::new();
    loop {
        {
            let mut queue = guard
                .database
                .0
                .dispatch
                .queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard
                .database
                .0
                .dispatch
                .wake
                .set_thread(Some(current.clone()));
            pending.append(&mut queue.jobs);
            if pending.is_empty() {
                queue.active = false;
                guard.database.0.dispatch.wake.set_thread(None);
                guard.armed = false;
                return;
            }
        }
        for _ in 0..pending.len() {
            let mut job = pending.pop_front().expect("pending job count is stable");
            job.dispatcher_started(pending.len() + 1);
            if job.poll(&mut context).is_pending() {
                pending.push_back(job);
            }
        }
        // A wake during polling retains an unpark token. New submissions and
        // cancellations cannot get lost between this scan and parking. An
        // expired deadline produces zero wait and is rejected on the next scan.
        if let Some(deadline) = pending.iter().map(|job| job.deadline()).min() {
            std::thread::park_timeout(deadline.saturating_duration_since(Instant::now()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    include!("tests/transfer_progress_integration.rs");

    #[tokio::test(flavor = "current_thread")]
    async fn full_transfer_queue_does_not_consume_general_capacity_or_execute_rejected_work() {
        let directory = tempfile::tempdir().unwrap();
        let database = Database::open(directory.path().join("data.sqlite")).unwrap();
        let queued = database
            .0
            .transfer_queue_admission
            .clone()
            .acquire_many_owned(128)
            .await
            .unwrap();
        let result =
            dispatch_transfer_database_work(database.clone(), "full_transfer_queue", |_, _| {
                panic!("queue-full work must never run")
            })
            .await;
        assert!(result.is_err());
        let reader = dispatch_database_work(
            database.clone(),
            "general_while_transfer_full",
            |db, _permit| db.admin_count(),
        )
        .await
        .unwrap();
        assert_eq!(reader.await.unwrap().unwrap(), 0);
        drop(queued);
        let worker = dispatch_transfer_database_work(
            database.clone(),
            "transfer_after_queue_release",
            |_, _| 42,
        )
        .await
        .unwrap();
        assert_eq!(worker.await.unwrap(), 42);
        assert_eq!(database.0.transfer_queue_admission.available_permits(), 128);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_transfer_submission_returns_its_bounded_queue_capacity() {
        let database = Database::open(":memory:").unwrap();
        let holder = database.acquire_transfer_runtime_permit().await.unwrap();
        let mut submission = Box::pin(dispatch_transfer_database_work(
            database.clone(),
            "cancelled_bounded_submission",
            |_, _| panic!("cancelled unadmitted work must never run"),
        ));
        assert!(futures_util::poll!(submission.as_mut()).is_pending());
        assert_eq!(database.0.transfer_queue_admission.available_permits(), 127);
        drop(submission);
        tokio::time::timeout(Duration::from_secs(10), async {
            while database.0.transfer_queue_admission.available_permits() != 128 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancellation must return queue capacity without a new transfer");
        drop(holder);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transfer_writer_admission_uses_one_timeout_across_both_queues() {
        let database = Database::open(":memory:").unwrap();
        let holder = database.acquire_transfer_runtime_permit().await.unwrap();
        let mut context = Context::from_waker(Waker::noop());

        // This real FIFO waiter gets the global slot before the candidate can
        // pass its first admission stage. No runtime scheduling is assumed.
        let mut catcher = Box::pin(database.acquire_runtime_permit());
        assert!(catcher.as_mut().poll(&mut context).is_pending());
        let started = Instant::now();
        let admission_database = database.clone();
        let (sender, mut receiver) = oneshot::channel::<LaunchedWork<()>>();
        let mut candidate = DatabaseJob {
            database: database.clone(),
            class: "two_queue_transfer_write",
            started,
            deadline: started + DATABASE_QUEUE_TIMEOUT,
            progress_budget: Some(TransferAdmissionBudget::new(started)),
            pending_transfer: None,
            admission: Some(Box::pin(async move {
                admission_database.acquire_transfer_runtime_permit().await
            })),
            operation: Some(|_: Database, _: TransferDatabasePermit| {
                panic!("a writer exceeding its shared queue budget must not run")
            }),
            sender: Some(sender),
            handle: Handle::current(),
            subscriber: tracing::dispatcher::get_default(Clone::clone),
            span: tracing::Span::none(),
            timing: Some(
                database
                    .0
                    .work_diagnostics
                    .start("two_queue_transfer_write"),
            ),
        };
        assert!(candidate
            .poll_with_clock(&mut context, || started)
            .is_pending());

        drop(holder);
        let Poll::Ready(Ok(catcher_permit)) = catcher.as_mut().poll(&mut context) else {
            panic!("the earlier waiter must receive the released global slot");
        };
        // Only the clock is controlled: this poll really acquires the transfer
        // slot, then waits on the actual global semaphore behind the catcher.
        assert!(candidate
            .poll_with_clock(&mut context, || started + Duration::from_millis(750))
            .is_pending());
        let waiting = database.runtime_admission_state();
        assert_eq!(waiting.runtime_available, 0);
        assert_eq!(waiting.general_available, 0);
        assert_eq!(waiting.transfer_available, 0);
        assert_eq!(waiting.transfer_phase, Some("runtime_queue"));
        assert!(candidate
            .poll_with_clock(&mut context, || started + Duration::from_millis(999))
            .is_pending());

        // The second stage gets the remainder, not a new one-second budget.
        assert!(candidate
            .poll_with_clock(&mut context, || started + Duration::from_millis(1050))
            .is_ready());
        let error = receiver.try_recv().unwrap().unwrap_err();
        assert_eq!(error.class(), "two_queue_transfer_write");
        assert_eq!(error.state().runtime_available, 0);
        assert_eq!(error.state().general_available, 0);
        assert_eq!(error.state().transfer_available, 1);
        assert_eq!(error.state().transfer_phase, None);
        assert!(candidate.admission.is_none());
        assert!(
            candidate.operation.is_some(),
            "unadmitted work must never launch"
        );
        drop(catcher_permit);
        assert_eq!(database.runtime_available_permits(), 1);
        assert_eq!(database.general_runtime_available_permits(), 1);
    }
}

#[cfg(test)]
mod rejection_logging_regression {
    use super::*;
    use std::{
        io,
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
    };

    #[derive(Clone)]
    struct BlockFirstWrite {
        first: Arc<AtomicBool>,
        entered: mpsc::Sender<()>,
        release: Arc<Mutex<mpsc::Receiver<()>>>,
    }

    impl io::Write for BlockFirstWrite {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if !self.first.swap(true, Ordering::SeqCst) {
                self.entered.send(()).unwrap();
                // Deadlock failsafe only; the test releases this explicitly.
                let _ = self
                    .release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(20));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BlockFirstWrite {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }

    #[test]
    fn slow_rejection_log_must_not_block_following_admitted_work() {
        // The telemetry queue and tracing callsite interest are process-wide.
        // Other parallel admission tests may legitimately produce/drop logs;
        // isolate this test so its deliberately blocked writer is guaranteed
        // to receive the rejection used as the synchronization barrier.
        const CHILD: &str = "VAULTLINK_REJECTION_LOG_REGRESSION_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "db::dispatch::rejection_logging_regression::slow_rejection_log_must_not_block_following_admitted_work", "--nocapture"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated rejection logging test failed: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let _tracing_guard = crate::test_support::tracing_subscriber_guard();
        let database = Database::open(":memory:").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(2)
            .build()
            .unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let subscriber = tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .with_env_filter("warn")
                .without_time()
                .with_ansi(false)
                .with_writer(BlockFirstWrite {
                    first: Arc::new(AtomicBool::new(false)),
                    entered: entered_tx,
                    release: Arc::new(Mutex::new(release_rx)),
                })
                .finish(),
        );
        let now = Instant::now();
        let (rejected_tx, mut rejected_rx) = oneshot::channel::<LaunchedWork<()>>();
        let admission_db = database.clone();
        let expired = DatabaseJob {
            database: database.clone(),
            class: "expired_probe",
            started: now - Duration::from_secs(2),
            deadline: now - Duration::from_secs(1),
            progress_budget: None,
            pending_transfer: None,
            admission: Some(Box::pin(async move {
                admission_db.acquire_runtime_permit().await
            })),
            operation: Some(|_: Database, _: RuntimeDatabasePermit| panic!("expired job ran")),
            sender: Some(rejected_tx),
            handle: runtime.handle().clone(),
            subscriber: subscriber.clone(),
            span: tracing::Span::none(),
            timing: Some(database.0.work_diagnostics.start("expired_probe")),
        };
        let (worker_tx, worker_rx) = mpsc::channel();
        let (launched_tx, launched_rx) = oneshot::channel::<LaunchedWork<()>>();
        let admission_db = database.clone();
        let ready = DatabaseJob {
            database: database.clone(),
            class: "ready_probe",
            started: now,
            deadline: now + Duration::from_secs(30),
            progress_budget: None,
            pending_transfer: None,
            admission: Some(Box::pin(async move {
                admission_db.acquire_runtime_permit().await
            })),
            operation: Some(move |database: Database, permit: RuntimeDatabasePermit| {
                assert_eq!(database.admin_count().unwrap(), 0);
                drop(permit);
                worker_tx.send(()).unwrap();
            }),
            sender: Some(launched_tx),
            handle: runtime.handle().clone(),
            subscriber,
            span: tracing::Span::none(),
            timing: Some(database.0.work_diagnostics.start("ready_probe")),
        };
        {
            let mut queue = database.0.dispatch.queue.lock().unwrap();
            queue.active = true;
            queue.jobs.push_back(Box::new(expired));
            queue.jobs.push_back(Box::new(ready));
        }
        let guard = DispatcherGuard::new(database);
        let dispatcher = std::thread::spawn(move || drain(guard));
        let entered = entered_rx.recv_timeout(Duration::from_secs(5));
        // The barrier guarantees the first WARN really is blocked. Neither
        // slow SQL, an HTTP poll nor unavailable DB admission explains this.
        let rejection_delivered = rejected_rx.try_recv().is_ok();
        let progressed = worker_rx.recv_timeout(Duration::from_secs(3)).is_ok();

        // Clean up before asserting the regression, avoiding a hung test runtime.
        let _ = release_tx.send(());
        dispatcher.join().unwrap();
        runtime.block_on(async {
            launched_rx.await.unwrap().unwrap().await.unwrap();
        });
        entered.expect("rejection did not enter the test writer");
        assert!(crate::best_effort_telemetry::flush(Duration::from_secs(5)));
        assert!(
            rejection_delivered,
            "the error response waited for WARN logging"
        );
        assert!(progressed, "the sole dispatcher blocked on WARN despite free DB capacity and a ready queued SQL job");
    }
}
