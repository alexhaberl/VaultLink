//! Bounded, content-free timings for slow database worker handoffs.
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};

const SLOW_STAGE: Duration = Duration::from_millis(100);
const WINDOW: Duration = Duration::from_secs(60);
const EVENTS_PER_WINDOW: u32 = 20;

pub(super) struct DatabaseWorkDiagnostics {
    next_job_id: AtomicU64,
    budget: Mutex<Budget>,
}

impl Default for DatabaseWorkDiagnostics {
    fn default() -> Self {
        Self {
            next_job_id: AtomicU64::new(1),
            budget: Mutex::new(Budget::default()),
        }
    }
}

#[derive(Default)]
struct Budget {
    started: Option<Instant>,
    emitted: u32,
    suppressed: u64,
}

impl Budget {
    fn admit(&mut self, now: Instant) -> Option<u64> {
        if self
            .started
            .is_none_or(|started| now.saturating_duration_since(started) >= WINDOW)
        {
            self.started = Some(now);
            self.emitted = 0;
        }
        if self.emitted == EVENTS_PER_WINDOW {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        self.emitted += 1;
        Some(std::mem::take(&mut self.suppressed))
    }
}

pub(super) struct WorkTiming {
    job_id: u64,
    class: &'static str,
    enqueued: Instant,
    dispatcher: Option<Instant>,
    admitted: Option<Instant>,
    worker: Option<Instant>,
}

impl DatabaseWorkDiagnostics {
    pub(super) fn start(&self, class: &'static str) -> WorkTiming {
        WorkTiming {
            job_id: self.next_job_id.fetch_add(1, Ordering::Relaxed),
            class,
            enqueued: Instant::now(),
            dispatcher: None,
            admitted: None,
            worker: None,
        }
    }

    fn admit_event(&self, now: Instant) -> Option<u64> {
        if !tracing::enabled!(target: "vaultlink::database", tracing::Level::INFO) {
            return None;
        }
        // Return a number, never a guard: a slow subscriber must not hold this
        // mutex while another worker records its observation.
        self.budget
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .admit(now)
    }

    pub(super) fn record_ownership(
        &self,
        class: &'static str,
        duration: Duration,
        abandoned: bool,
    ) {
        self.record_ownership_at(class, duration, abandoned, Instant::now());
    }

    fn record_ownership_at(
        &self,
        class: &'static str,
        duration: Duration,
        abandoned: bool,
        now: Instant,
    ) {
        if duration < SLOW_STAGE {
            return;
        }
        if let Some(suppressed) = self.admit_event(now) {
            // Ownership can outlive DB admission. Its separate event does not
            // claim that the worker held a permit throughout this wait.
            tracing::info!(target: "vaultlink::database", parent: None,
                operation = "database.handoff",
                class,
                ownership_wait_ms = millis(duration),
                abandoned,
                suppressed_since_last_event = suppressed,
                "slow transfer ownership handoff finished");
        }
    }
}

impl WorkTiming {
    pub(super) fn dispatcher_started(&mut self) {
        self.dispatcher.get_or_insert_with(Instant::now);
    }

    pub(super) fn admitted(&mut self) {
        self.admitted.get_or_insert_with(Instant::now);
    }

    pub(super) fn worker_started(&mut self) {
        self.worker.get_or_insert_with(Instant::now);
    }

    /// Preserve admission failures independently of the slow-success budget.
    /// Call after dropping the queued admission future and any partial permit.
    pub(super) fn rejected(self, reason: &'static str) {
        self.rejected_at(reason, Instant::now());
    }

    fn rejected_at(self, reason: &'static str, now: Instant) {
        let dispatcher_delay = self
            .dispatcher
            .map(|started| millis(started.saturating_duration_since(self.enqueued)));
        let admission_wait = self.dispatcher.map(|started| {
            millis(
                self.admitted
                    .unwrap_or(now)
                    .saturating_duration_since(started),
            )
        });
        tracing::warn!(target: "vaultlink::database", parent: None,
            operation = "database.dispatcher.rejected",
            job_id = self.job_id,
            class = self.class,
            queue_duration_ms = millis(now.saturating_duration_since(self.enqueued)),
            dispatcher_delay_ms = ?dispatcher_delay,
            admission_wait_ms = ?admission_wait,
            reason,
            "database work rejected before worker execution");
    }

    /// Call after the worker closure and its admission permits have finished.
    /// Worker duration includes all closure work, including any ownership wait;
    /// it is deliberately not described as SQL execution time.
    pub(super) fn finish(self, diagnostics: &DatabaseWorkDiagnostics) {
        self.finish_at(diagnostics, Instant::now());
    }

    fn finish_at(self, diagnostics: &DatabaseWorkDiagnostics, now: Instant) {
        let (Some(dispatcher), Some(admitted), Some(worker)) =
            (self.dispatcher, self.admitted, self.worker)
        else {
            // A cancelled job that never started work has no worker timings.
            return;
        };
        let dispatcher_delay = dispatcher.saturating_duration_since(self.enqueued);
        let admission_wait = admitted.saturating_duration_since(dispatcher);
        let worker_queue = worker.saturating_duration_since(admitted);
        let worker_duration = now.saturating_duration_since(worker);
        if [
            dispatcher_delay,
            admission_wait,
            worker_queue,
            worker_duration,
        ]
        .into_iter()
        .all(|duration| duration < SLOW_STAGE)
        {
            return;
        }
        if let Some(suppressed) = diagnostics.admit_event(now) {
            tracing::info!(target: "vaultlink::database", parent: None,
                operation = "database.executor",
                job_id = self.job_id,
                class = self.class,
                dispatcher_delay_ms = millis(dispatcher_delay),
                admission_wait_ms = millis(admission_wait),
                worker_queue_ms = millis(worker_queue),
                worker_duration_ms = millis(worker_duration),
                suppressed_since_last_event = suppressed,
                "slow database worker completed");
        }
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io, sync::Arc};

    #[derive(Clone, Default)]
    struct Logs(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Logs {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }

    fn capture(event: impl FnOnce()) -> String {
        let _guard = crate::test_support::tracing_subscriber_guard();
        let logs = Logs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_env_filter("info")
            .with_writer(logs.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, event);
        let bytes = logs.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn worker_summary_separates_stages_at_info_level() {
        let diagnostics = DatabaseWorkDiagnostics::default();
        let now = Instant::now();
        let output = capture(|| {
            let mut timing = diagnostics.start("read");
            timing.enqueued = now;
            timing.dispatcher = Some(now + Duration::from_millis(150));
            timing.admitted = Some(now + Duration::from_millis(400));
            timing.worker = Some(now + Duration::from_millis(700));
            timing.finish_at(&diagnostics, now + Duration::from_millis(705));
        });
        assert_eq!(output.lines().count(), 1, "{output}");
        for field in [
            "INFO",
            "database.executor",
            "job_id=1",
            "class=\"read\"",
            "dispatcher_delay_ms=150",
            "admission_wait_ms=250",
            "worker_queue_ms=300",
            "worker_duration_ms=5",
            "suppressed_since_last_event=0",
        ] {
            assert!(output.contains(field), "missing {field}: {output}");
        }
        assert!(!output.contains("sql_duration"));
        assert!(!output.contains("token="));
        assert!(!output.contains("path="));
        assert!(!output.contains("error="));
    }

    #[test]
    fn admission_rejection_keeps_phase_timings_when_success_budget_is_exhausted() {
        let diagnostics = DatabaseWorkDiagnostics::default();
        let now = Instant::now();
        for _ in 0..EVENTS_PER_WINDOW {
            assert_eq!(diagnostics.budget.lock().unwrap().admit(now), Some(0));
        }
        let output = capture(|| {
            let mut timing = diagnostics.start("transfer_complete");
            timing.enqueued = now;
            timing.dispatcher = Some(now + Duration::from_millis(100));
            timing.rejected_at("queue_timeout", now + Duration::from_millis(450));
        });
        assert_eq!(output.lines().count(), 1, "{output}");
        for field in [
            "WARN",
            "database.dispatcher.rejected",
            "job_id=1",
            "class=\"transfer_complete\"",
            "queue_duration_ms=450",
            "dispatcher_delay_ms=Some(100)",
            "admission_wait_ms=Some(350)",
            "reason=\"queue_timeout\"",
        ] {
            assert!(output.contains(field), "missing {field}: {output}");
        }
        assert!(!output.contains("worker_queue_ms"), "{output}");
        assert!(!output.contains("worker_duration_ms"), "{output}");
        assert!(!output.contains("suppressed_since_last_event"), "{output}");
    }

    #[test]
    fn rejection_before_dispatch_marks_unobserved_phases_as_absent() {
        let diagnostics = DatabaseWorkDiagnostics::default();
        let now = Instant::now();
        let output = capture(|| {
            let mut timing = diagnostics.start("read");
            timing.enqueued = now;
            timing.rejected_at("admission_closed", now + Duration::from_millis(500));
        });
        assert_eq!(output.lines().count(), 1, "{output}");
        for field in [
            "WARN",
            "database.dispatcher.rejected",
            "job_id=1",
            "class=\"read\"",
            "queue_duration_ms=500",
            "dispatcher_delay_ms=None",
            "admission_wait_ms=None",
            "reason=\"admission_closed\"",
        ] {
            assert!(output.contains(field), "missing {field}: {output}");
        }
        assert!(!output.contains("worker_queue_ms"), "{output}");
        assert!(!output.contains("worker_duration_ms"), "{output}");
    }

    #[test]
    fn fast_work_is_silent_and_slow_ownership_has_its_own_duration() {
        let diagnostics = DatabaseWorkDiagnostics::default();
        let now = Instant::now();
        let output = capture(|| {
            let mut timing = diagnostics.start("read");
            timing.enqueued = now;
            timing.dispatcher = Some(now);
            timing.admitted = Some(now);
            timing.worker = Some(now);
            timing.finish_at(&diagnostics, now + Duration::from_millis(99));
            diagnostics.record_ownership_at("transfer_cancel", Duration::ZERO, true, now);
            diagnostics.record_ownership_at(
                "transfer_cancel",
                Duration::from_millis(100),
                true,
                now,
            );
        });
        assert_eq!(output.lines().count(), 1, "{output}");
        assert!(output.contains("database.handoff"), "{output}");
        assert!(output.contains("ownership_wait_ms=100"), "{output}");
        assert!(output.contains("abandoned=true"), "{output}");
        assert!(!output.contains("worker_duration_ms"), "{output}");
    }

    #[test]
    fn event_budget_is_shared_per_database_and_reports_suppressed_events() {
        let diagnostics = DatabaseWorkDiagnostics::default();
        let independent = DatabaseWorkDiagnostics::default();
        let now = Instant::now();
        let output = capture(|| {
            for _ in 0..EVENTS_PER_WINDOW + 3 {
                diagnostics.record_ownership_at("transfer_cancel", SLOW_STAGE, true, now);
            }
            independent.record_ownership_at("transfer_cancel", SLOW_STAGE, false, now);
            diagnostics.record_ownership_at("transfer_cancel", SLOW_STAGE, false, now + WINDOW);
        });
        assert_eq!(output.lines().count(), EVENTS_PER_WINDOW as usize + 2);
        assert_eq!(output.matches("suppressed_since_last_event=3").count(), 1);
    }

    #[test]
    fn repeated_dispatch_polls_preserve_the_original_start_time() {
        let diagnostics = DatabaseWorkDiagnostics::default();
        let mut first = diagnostics.start("read");
        let second = diagnostics.start("read");
        assert_eq!(first.job_id, 1);
        assert_eq!(second.job_id, 2);
        let original = first.enqueued;
        first.dispatcher = Some(original);
        first.admitted = Some(original);
        first.worker = Some(original);
        first.dispatcher_started();
        first.admitted();
        first.worker_started();
        assert_eq!(first.dispatcher, Some(original));
        assert_eq!(first.admitted, Some(original));
        assert_eq!(first.worker, Some(original));
    }
}
