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
    fn dispatcher_started(&mut self);
    fn poll(&mut self, context: &mut Context<'_>) -> Poll<()>;
    fn deadline(&self) -> Instant;
}

struct DatabaseJob<P, F, T> {
    database: Database,
    class: &'static str,
    started: Instant,
    deadline: Instant,
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
        let error =
            DatabaseExecutorAdmission::new(&self.database, self.class, self.started.elapsed());
        if let Some(timing) = self.timing.take() {
            tracing::dispatcher::with_default(&self.subscriber, || timing.rejected(reason));
        }
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(Err(error));
        }
        Poll::Ready(())
    }

    fn launch(&mut self, permit: P) -> Poll<()> {
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
        if now() >= self.deadline {
            return self.reject("queue_timeout");
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
                if now() >= self.deadline {
                    drop(permit);
                    return self.reject("queue_timeout");
                }
                if self.sender.as_ref().is_none_or(oneshot::Sender::is_closed) {
                    return Poll::Ready(());
                }
                drop(self.admission.take());
                self.launch(permit)
            }
        }
    }
}

impl<P, F, T> PendingDatabaseJob for DatabaseJob<P, F, T>
where
    P: DatabaseWorkPermit,
    F: FnOnce(Database, P) -> T + Send + 'static,
    T: Send + 'static,
{
    fn dispatcher_started(&mut self) {
        if let Some(timing) = self.timing.as_mut() {
            timing.dispatcher_started();
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

/// Uses the existing transfer-then-global FIFO admission, with one deadline
/// spanning enqueue, dispatcher startup, and both admission stages.
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
    let (sender, receiver) = oneshot::channel();
    let mut job = Box::new(DatabaseJob {
        database: database.clone(),
        class,
        started,
        deadline: started + DATABASE_QUEUE_TIMEOUT,
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
            job.dispatcher_started();
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
