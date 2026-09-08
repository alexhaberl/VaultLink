//! Bounded, content-free timings for database worker handoffs.
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

const SLOW_STAGE: Duration = Duration::from_millis(100);
const WINDOW: Duration = Duration::from_secs(60);
const EVENTS_PER_WINDOW: u32 = 20;
const HISTORY_CAPACITY: usize = 128;
const FAILURE_HISTORY_LIMIT: usize = 32;

pub(super) struct DatabaseWorkDiagnostics {
    next_job_id: AtomicU64,
    budget: Mutex<Budget>,
    history: Arc<Mutex<History>>,
}
impl Default for DatabaseWorkDiagnostics {
    fn default() -> Self {
        Self {
            next_job_id: AtomicU64::new(1),
            budget: Mutex::new(Budget::default()),
            history: Arc::new(Mutex::new(History::default())),
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

#[derive(Default)]
struct History {
    records: VecDeque<TimingRecord>,
    evicted: u64,
}
impl History {
    fn push(&mut self, record: TimingRecord) {
        if self.records.len() == HISTORY_CAPACITY {
            self.records.pop_front();
            self.evicted = self.evicted.saturating_add(1);
        }
        self.records.push_back(record);
    }
    fn snapshot(&self, failure_at: Instant) -> (Vec<TimingRecord>, u64, usize) {
        let eligible = self.records.iter().filter(|record| record.at <= failure_at);
        let omitted = eligible
            .clone()
            .count()
            .saturating_sub(FAILURE_HISTORY_LIMIT);
        (
            eligible.skip(omitted).copied().collect(),
            self.evicted,
            omitted,
        )
    }
}

/// Numeric observations only: no request, SQL, path, token or user content.
#[derive(Clone, Copy)]
struct TimingRecord {
    at: Instant,
    job_id: u64,
    class: &'static str,
    stage: &'static str,
    queue_duration_ms: u64,
    dispatcher_delay_ms: Option<u64>,
    admission_wait_ms: Option<u64>,
    worker_queue_ms: Option<u64>,
    worker_duration_ms: Option<u64>,
    poll_count: u64,
    last_poll_gap_ms: Option<u64>,
    max_poll_gap_ms: u64,
    pending_jobs_at_poll: usize,
}
impl TimingRecord {
    fn emit_context(self, rejected_job_id: u64, failure_at: Instant) {
        tracing::warn!(target: "vaultlink::database", parent: None,
            operation = "database.dispatcher.context", rejected_job_id,
            job_id = self.job_id, class = self.class, stage = self.stage,
            observation_before_rejection_ms = millis(failure_at.saturating_duration_since(self.at)),
            job_elapsed_ms = self.queue_duration_ms,
            dispatcher_delay_ms = ?self.dispatcher_delay_ms,
            admission_wait_ms = ?self.admission_wait_ms,
            worker_queue_ms = ?self.worker_queue_ms,
            worker_duration_ms = ?self.worker_duration_ms,
            poll_count = self.poll_count, last_poll_gap_ms = ?self.last_poll_gap_ms,
            max_poll_gap_ms = self.max_poll_gap_ms, pending_jobs_at_poll = self.pending_jobs_at_poll,
            "recent transfer worker observation");
    }
}

pub(super) struct WorkTiming {
    job_id: u64,
    class: &'static str,
    enqueued: Instant,
    dispatcher: Option<Instant>,
    admitted: Option<Instant>,
    worker: Option<Instant>,
    last_poll: Option<Instant>,
    last_poll_gap: Option<Duration>,
    max_poll_gap: Duration,
    poll_count: u64,
    pending_jobs_at_poll: usize,
    history: Arc<Mutex<History>>,
}
impl DatabaseWorkDiagnostics {
    pub(super) fn start(&self, class: &'static str) -> WorkTiming {
        let timing = WorkTiming {
            job_id: self.next_job_id.fetch_add(1, Ordering::Relaxed),
            class,
            enqueued: Instant::now(),
            dispatcher: None,
            admitted: None,
            worker: None,
            last_poll: None,
            last_poll_gap: None,
            max_poll_gap: Duration::ZERO,
            poll_count: 0,
            pending_jobs_at_poll: 0,
            history: self.history.clone(),
        };
        timing.record("queued", timing.enqueued);
        timing
    }
    fn admit_event(&self, now: Instant) -> Option<u64> {
        // Even subscriber enablement callbacks run only on the telemetry worker.
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
            let ownership_wait_ms = millis(duration);
            crate::best_effort_telemetry::emit(move || {
                tracing::info!(target: "vaultlink::database", parent: None,
                    operation = "database.handoff", class, ownership_wait_ms, abandoned,
                    telemetry_delay_ms = millis(Instant::now().saturating_duration_since(now)),
                    suppressed_since_last_event = suppressed, "slow transfer ownership handoff finished");
            });
        }
    }
}
impl WorkTiming {
    pub(super) fn dispatcher_started(&mut self) {
        self.dispatcher.get_or_insert_with(Instant::now);
    }
    pub(super) fn dispatcher_polled(&mut self, pending_jobs: usize) {
        self.polled_at(pending_jobs, Instant::now());
    }
    fn polled_at(&mut self, pending_jobs: usize, now: Instant) {
        if let Some(previous) = self.last_poll {
            let gap = now.saturating_duration_since(previous);
            self.last_poll_gap = Some(gap);
            self.max_poll_gap = self.max_poll_gap.max(gap);
        }
        self.last_poll = Some(now);
        self.poll_count = self.poll_count.saturating_add(1);
        self.pending_jobs_at_poll = pending_jobs;
    }
    pub(super) fn admitted(&mut self) {
        let now = Instant::now();
        self.admitted.get_or_insert(now);
        self.record("admitted", now);
    }
    pub(super) fn worker_started(&mut self) {
        let now = Instant::now();
        self.worker.get_or_insert(now);
        self.record("worker_started", now);
    }
    fn observation(&self, stage: &'static str, now: Instant) -> TimingRecord {
        TimingRecord {
            at: now,
            job_id: self.job_id,
            class: self.class,
            stage,
            queue_duration_ms: millis(now.saturating_duration_since(self.enqueued)),
            dispatcher_delay_ms: self
                .dispatcher
                .map(|t| millis(t.saturating_duration_since(self.enqueued))),
            admission_wait_ms: self
                .dispatcher
                .map(|t| millis(self.admitted.unwrap_or(now).saturating_duration_since(t))),
            worker_queue_ms: self
                .admitted
                .map(|t| millis(self.worker.unwrap_or(now).saturating_duration_since(t))),
            worker_duration_ms: self
                .worker
                .map(|t| millis(now.saturating_duration_since(t))),
            poll_count: self.poll_count,
            last_poll_gap_ms: self.last_poll_gap.map(millis),
            max_poll_gap_ms: millis(self.max_poll_gap),
            pending_jobs_at_poll: self.pending_jobs_at_poll,
        }
    }
    fn record(&self, stage: &'static str, now: Instant) {
        if self.class.starts_with("transfer_") || self.class.starts_with("upload_") {
            self.history
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(self.observation(stage, now));
        }
    }
    /// All partial permits must be released before recording failure. Logging
    /// is best effort and never runs on the admission dispatcher.
    pub(super) fn rejected(self, reason: &'static str, observed_at: Instant) {
        self.rejected_at(reason, observed_at);
    }
    fn rejected_at(self, reason: &'static str, now: Instant) {
        let failure = self.observation("rejected", now);
        self.record("rejected", now);
        let (history, evicted, omitted) = self
            .history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot(now);
        crate::best_effort_telemetry::emit(move || {
            tracing::warn!(target: "vaultlink::database", parent: None,
                operation = "database.dispatcher.rejected", job_id = failure.job_id, class = failure.class,
                telemetry_delay_ms = millis(Instant::now().saturating_duration_since(now)),
                queue_duration_ms = failure.queue_duration_ms,
                dispatcher_delay_ms = ?failure.dispatcher_delay_ms, admission_wait_ms = ?failure.admission_wait_ms,
                poll_count = failure.poll_count, last_poll_gap_ms = ?failure.last_poll_gap_ms,
                max_poll_gap_ms = failure.max_poll_gap_ms, pending_jobs_at_poll = failure.pending_jobs_at_poll,
                history_records = history.len(), history_evicted = evicted, history_omitted = omitted,
                reason, "database work rejected before worker execution");
            for record in history {
                record.emit_context(failure.job_id, now);
            }
        });
    }
    /// Call only after the worker closure and its permits have finished.
    /// Worker duration includes ownership handoffs, not just SQL execution.
    pub(super) fn finish(self, diagnostics: &DatabaseWorkDiagnostics) {
        self.finish_at(diagnostics, Instant::now());
    }
    fn finish_at(self, diagnostics: &DatabaseWorkDiagnostics, now: Instant) {
        let (Some(dispatcher), Some(admitted), Some(worker)) =
            (self.dispatcher, self.admitted, self.worker)
        else {
            return;
        };
        self.record("completed", now);
        let stages = [
            dispatcher.saturating_duration_since(self.enqueued),
            admitted.saturating_duration_since(dispatcher),
            worker.saturating_duration_since(admitted),
            now.saturating_duration_since(worker),
        ];
        if stages.into_iter().all(|duration| duration < SLOW_STAGE) {
            return;
        }
        if let Some(suppressed) = diagnostics.admit_event(now) {
            let timing = self.observation("completed", now);
            crate::best_effort_telemetry::emit(move || {
                tracing::info!(target: "vaultlink::database", parent: None,
                    operation = "database.executor", job_id = timing.job_id, class = timing.class,
                    telemetry_delay_ms = millis(Instant::now().saturating_duration_since(now)),
                    dispatcher_delay_ms = timing.dispatcher_delay_ms.unwrap_or_default(),
                    admission_wait_ms = timing.admission_wait_ms.unwrap_or_default(),
                    worker_queue_ms = timing.worker_queue_ms.unwrap_or_default(),
                    worker_duration_ms = timing.worker_duration_ms.unwrap_or_default(),
                    poll_count = timing.poll_count, last_poll_gap_ms = ?timing.last_poll_gap_ms,
                    max_poll_gap_ms = timing.max_poll_gap_ms, pending_jobs_at_poll = timing.pending_jobs_at_poll,
                    suppressed_since_last_event = suppressed, "slow database worker completed");
            });
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
        assert!(crate::best_effort_telemetry::flush(Duration::from_secs(5)));
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
        assert_eq!(output.lines().count(), 3, "{output}");
        let output = output.lines().next().unwrap();
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
    #[test]
    fn failure_history_is_bounded_and_survives_exhausted_info_budget() {
        let diagnostics = DatabaseWorkDiagnostics::default();
        let now = Instant::now();
        for _ in 0..EVENTS_PER_WINDOW {
            assert_eq!(diagnostics.budget.lock().unwrap().admit(now), Some(0));
        }
        for _ in 0..HISTORY_CAPACITY + 7 {
            diagnostics.start("transfer_write");
        }
        let output = capture(|| {
            diagnostics
                .start("transfer_complete")
                .rejected("queue_timeout", Instant::now())
        });
        assert_eq!(
            output.lines().count(),
            FAILURE_HISTORY_LIMIT + 1,
            "{output}"
        );
        assert!(output.contains("history_evicted=9"), "{output}");
        assert!(output.contains("history_omitted=96"), "{output}");
        assert!(output.contains("rejected_job_id=136"), "{output}");
        assert!(output.contains("stage=\"queued\""), "{output}");
        assert!(!output.contains("job_id=1 "), "{output}");
    }

    #[test]
    fn poll_observations_preserve_later_dispatcher_stalls() {
        let diagnostics = DatabaseWorkDiagnostics::default();
        let mut timing = diagnostics.start("transfer_write");
        let now = timing.enqueued;
        timing.dispatcher = Some(now);
        timing.polled_at(4, now);
        timing.polled_at(3, now + Duration::from_millis(600));
        timing.polled_at(2, now + Duration::from_millis(900));
        let record = timing.observation("rejected", now + Duration::from_secs(1));
        assert_eq!(record.dispatcher_delay_ms, Some(0));
        assert_eq!(record.poll_count, 3);
        assert_eq!(record.last_poll_gap_ms, Some(300));
        assert_eq!(record.max_poll_gap_ms, 600);
        assert_eq!(record.pending_jobs_at_poll, 2);
    }
}
