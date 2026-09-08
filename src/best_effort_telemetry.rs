//! Optional trace output isolated from database admission and worker threads.
//!
//! This queue must never be used for the required SQLite audit trail. It is a
//! lossy, bounded transport for diagnostics only. A stuck subscriber can occupy
//! the single telemetry thread, but cannot hold up producers or process exit.
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
        Arc, OnceLock,
    },
    time::{Duration, Instant},
};

const QUEUE_CAPACITY: usize = 64;
static TELEMETRY: OnceLock<Telemetry> = OnceLock::new();

type Event = Box<dyn FnOnce() + Send + 'static>;

enum Message {
    Event(tracing::Dispatch, Event),
    Flush(SyncSender<()>),
}

#[derive(Default)]
struct Counters {
    dropped: AtomicU64,
    panicked: AtomicU64,
    startup_failures: AtomicU64,
}

struct Telemetry {
    sender: SyncSender<Message>,
    counters: Arc<Counters>,
}

/// Enqueue optional output without waiting for a subscriber or queue space.
///
/// Only the dispatcher is captured, never the current request span. Callers
/// should additionally use `parent: None` and capture only bounded, safe data.
pub(crate) fn emit(event: impl FnOnce() + Send + 'static) {
    TELEMETRY
        .get_or_init(|| Telemetry::new(QUEUE_CAPACITY))
        .emit(event);
}

/// Wait at most `timeout` for previously enqueued optional trace output.
///
/// Returns false when the worker is unavailable or the deadline expires. This
/// does not join the worker: an unresponsive subscriber must not hang shutdown.
/// New events remain accepted; callers should stop normal producers first.
pub fn flush(timeout: Duration) -> bool {
    TELEMETRY.get().is_none_or(|queue| queue.flush(timeout))
}

impl Telemetry {
    fn new(capacity: usize) -> Self {
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let counters = Arc::new(Counters::default());
        let worker_counters = Arc::clone(&counters);
        // Deliberately detach: even shutdown must not join a stuck subscriber.
        if std::thread::Builder::new()
            .name("vaultlink-telemetry".into())
            .spawn(move || run_worker(&receiver, &worker_counters))
            .is_err()
        {
            counters.startup_failures.fetch_add(1, Ordering::Relaxed);
        }
        Self { sender, counters }
    }

    fn emit(&self, event: impl FnOnce() + Send + 'static) {
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        if self
            .sender
            .try_send(Message::Event(dispatch, Box::new(event)))
            .is_err()
        {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn flush(&self, timeout: Duration) -> bool {
        let started = Instant::now();
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut barrier = Message::Flush(sender);
        loop {
            match self.sender.try_send(barrier) {
                Ok(()) => break,
                Err(TrySendError::Disconnected(_)) => return false,
                Err(TrySendError::Full(message)) => barrier = message,
            }
            let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
                return false;
            };
            if remaining.is_zero() {
                return false;
            }
            // Only shutdown/explicit flush waits. Producers always use try_send.
            std::thread::sleep(remaining.min(Duration::from_millis(1)));
        }
        receiver
            .recv_timeout(timeout.saturating_sub(started.elapsed()))
            .is_ok()
    }
}

fn run_worker(receiver: &Receiver<Message>, counters: &Counters) {
    let mut reported_dropped = 0;
    let mut reported_panicked = 0;
    while let Ok(message) = receiver.recv() {
        match message {
            Message::Flush(sender) => {
                let _ = sender.try_send(());
            }
            Message::Event(dispatch, event) => {
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    tracing::dispatcher::with_default(&dispatch, event);
                }));
                if outcome.is_err() {
                    counters.panicked.fetch_add(1, Ordering::Relaxed);
                }
                let dropped = counters.dropped.load(Ordering::Relaxed);
                let panicked = counters.panicked.load(Ordering::Relaxed);
                if dropped != reported_dropped || panicked != reported_panicked {
                    reported_dropped = dropped;
                    reported_panicked = panicked;
                    // Report loss only on this worker, never recursively enqueue
                    // or call a subscriber on a producer's critical path.
                    if catch_unwind(AssertUnwindSafe(|| {
                        tracing::dispatcher::with_default(&dispatch, || {
                            tracing::warn!(target: "vaultlink::telemetry", parent: None,
                                event = "telemetry.optional_output_loss",
                                dropped_total = dropped,
                                panicked_total = panicked,
                                "optional telemetry output was lost"
                            );
                        });
                    }))
                    .is_err()
                    {
                        counters.panicked.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io, sync::Mutex};

    struct Output(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Output {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn dispatch_survives_producer_scope_without_capturing_secret_span() {
        let queue = Telemetry::new(4);
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer_bytes = Arc::clone(&bytes);
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || Output(Arc::clone(&writer_bytes)))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let secret = tracing::info_span!("secret_request", secret = "must-not-be-recorded");
            let _entered = secret.enter();
            queue.emit(|| {
                assert!(tracing::Span::current().is_none());
                tracing::info!(parent: None, event = "test.telemetry_dispatch", "safe output");
            });
        });
        assert!(queue.flush(Duration::from_secs(5)));
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert!(output.contains("test.telemetry_dispatch"));
        assert!(!output.contains("secret_request"));
        assert!(!output.contains("must-not-be-recorded"));
        assert_eq!(queue.counters.panicked.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn blocked_sink_and_full_queue_never_wait_for_producers_or_shutdown() {
        let queue = Arc::new(Telemetry::new(2));
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        queue.emit(move || {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let producer_queue = Arc::clone(&queue);
        let producer = std::thread::spawn(move || {
            for _ in 0..100 {
                producer_queue.emit(|| {});
            }
            done_tx.send(()).unwrap();
        });
        let producer_finished = done_rx.recv_timeout(Duration::from_secs(2)).is_ok();
        let flushing_queue = Arc::clone(&queue);
        let (flushed_tx, flushed_rx) = mpsc::sync_channel(1);
        let flushing = std::thread::spawn(move || {
            flushed_tx
                .send(flushing_queue.flush(Duration::from_millis(20)))
                .unwrap();
        });
        let flush_result = flushed_rx.recv_timeout(Duration::from_secs(2));
        let dropped = queue.counters.dropped.load(Ordering::Relaxed);
        release_tx.send(()).unwrap();
        producer.join().unwrap();
        flushing.join().unwrap();
        assert!(producer_finished, "producer waited for the blocked sink");
        assert!(
            !flush_result.unwrap(),
            "blocked output cannot have been flushed"
        );
        assert_eq!(dropped, 98);
        assert!(queue.flush(Duration::from_secs(5)));
    }

    #[test]
    fn panicking_event_does_not_kill_worker_or_following_output() {
        let queue = Telemetry::new(4);
        let (sent, received) = mpsc::sync_channel(1);
        queue.emit(|| panic!("controlled telemetry test panic"));
        queue.emit(move || sent.send(()).unwrap());
        assert!(queue.flush(Duration::from_secs(5)));
        received.try_recv().unwrap();
        assert_eq!(queue.counters.panicked.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn flush_waits_for_accepted_events_in_order() {
        let queue = Telemetry::new(8);
        let (sent, received) = mpsc::channel();
        for value in 0..8 {
            let sent = sent.clone();
            queue.emit(move || sent.send(value).unwrap());
        }
        assert!(queue.flush(Duration::from_secs(5)));
        assert_eq!(
            received.try_iter().collect::<Vec<_>>(),
            (0..8).collect::<Vec<_>>()
        );
    }

    #[test]
    fn disconnected_worker_counts_loss_and_flush_returns() {
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(receiver);
        let queue = Telemetry {
            sender,
            counters: Arc::new(Counters::default()),
        };
        queue.emit(|| panic!("disconnected queue must never invoke output"));
        assert_eq!(queue.counters.dropped.load(Ordering::Relaxed), 1);
        assert!(!queue.flush(Duration::from_secs(5)));
    }
}
