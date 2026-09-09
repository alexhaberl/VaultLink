use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

const TRANSFER_STALL_TIMEOUT: Duration = Duration::from_secs(1);
const TRANSFER_MAX_QUEUE_TIME: Duration = Duration::from_secs(10);
// Covers the configured public stream/upload envelope (96 + 28), while
// independently bounding queued DB closures rather than blocking workers.
pub(super) const TRANSFER_QUEUE_CAPACITY: usize = 128;

#[derive(Clone, Copy)]
struct CompletionStreak {
    first: Instant,
    last: Instant,
}

/// Constant-size history of actual transfer-worker releases. Remembering the
/// start of an uninterrupted streak lets a delayed dispatcher distinguish
/// continued service from a new completion after a genuine one-second stall.
#[derive(Default)]
pub(super) struct TransferProgress {
    streak: Mutex<Option<CompletionStreak>>,
}

impl TransferProgress {
    pub(super) fn completed(&self) {
        self.completed_at(Instant::now());
    }

    fn completed_at(&self, now: Instant) {
        let mut streak = self
            .streak
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match streak.as_mut() {
            Some(current) if now < current.last + TRANSFER_STALL_TIMEOUT => {
                current.last = now;
            }
            _ => {
                *streak = Some(CompletionStreak {
                    first: now,
                    last: now,
                });
            }
        }
    }
}

/// One budget spans enqueue and both admission stages. Only actual progress
/// before the idle deadline can extend it, and total queue time stays bounded.
pub(super) struct TransferAdmissionBudget {
    deadline: Instant,
    hard_deadline: Instant,
}

impl TransferAdmissionBudget {
    pub(super) fn new(started: Instant) -> Self {
        Self {
            deadline: started + TRANSFER_STALL_TIMEOUT,
            hard_deadline: started + TRANSFER_MAX_QUEUE_TIME,
        }
    }

    pub(super) fn refresh(&mut self, progress: &TransferProgress) -> Instant {
        let streak = *progress
            .streak
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(streak) = streak {
            if streak.first < self.deadline {
                self.deadline = self
                    .deadline
                    .max(streak.last + TRANSFER_STALL_TIMEOUT)
                    .min(self.hard_deadline);
            }
        }
        self.deadline
    }

    pub(super) fn reason(&self, now: Instant) -> &'static str {
        if now >= self.hard_deadline {
            "transfer_queue_deadline"
        } else {
            "transfer_queue_stalled"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_work_keeps_the_original_one_second_budget() {
        let start = Instant::now();
        let mut budget = TransferAdmissionBudget::new(start);
        assert_eq!(
            budget.refresh(&TransferProgress::default()),
            start + Duration::from_secs(1)
        );
        assert_eq!(
            budget.reason(start + Duration::from_secs(1)),
            "transfer_queue_stalled"
        );
    }

    #[test]
    fn actual_completion_time_extends_without_using_the_poll_time() {
        let start = Instant::now();
        let progress = TransferProgress::default();
        let mut budget = TransferAdmissionBudget::new(start);
        progress.completed_at(start + Duration::from_millis(800));
        assert_eq!(
            budget.refresh(&progress),
            start + Duration::from_millis(1800)
        );
        // Reading the same observation again cannot keep a stalled worker alive.
        assert_eq!(
            budget.refresh(&progress),
            start + Duration::from_millis(1800)
        );
    }

    #[test]
    fn a_late_completion_cannot_resurrect_an_expired_budget() {
        let start = Instant::now();
        let progress = TransferProgress::default();
        let mut budget = TransferAdmissionBudget::new(start);
        progress.completed_at(start + Duration::from_millis(1001));
        assert_eq!(budget.refresh(&progress), start + Duration::from_secs(1));
    }

    #[test]
    fn uninterrupted_completions_survive_missed_dispatcher_polls() {
        let start = Instant::now();
        let progress = TransferProgress::default();
        let mut budget = TransferAdmissionBudget::new(start);
        for ms in [800, 1600, 2400, 3200] {
            progress.completed_at(start + Duration::from_millis(ms));
        }
        assert_eq!(
            budget.refresh(&progress),
            start + Duration::from_millis(4200)
        );
    }

    #[test]
    fn interrupted_completions_do_not_hide_an_idle_gap() {
        let start = Instant::now();
        let progress = TransferProgress::default();
        let mut budget = TransferAdmissionBudget::new(start);
        progress.completed_at(start + Duration::from_millis(800));
        assert_eq!(
            budget.refresh(&progress),
            start + Duration::from_millis(1800)
        );
        progress.completed_at(start + Duration::from_millis(1800));
        progress.completed_at(start + Duration::from_millis(2000));
        assert_eq!(
            budget.refresh(&progress),
            start + Duration::from_millis(1800)
        );
    }

    #[test]
    fn continuous_progress_never_exceeds_the_absolute_cap() {
        let start = Instant::now();
        let progress = TransferProgress::default();
        let mut budget = TransferAdmissionBudget::new(start);
        for ms in (500..=12_000).step_by(500) {
            progress.completed_at(start + Duration::from_millis(ms));
        }
        assert_eq!(budget.refresh(&progress), start + Duration::from_secs(10));
        assert_eq!(
            budget.reason(start + Duration::from_secs(10)),
            "transfer_queue_deadline"
        );
    }

    #[test]
    fn old_completions_do_not_extend_new_requests() {
        let start = Instant::now();
        let progress = TransferProgress::default();
        progress.completed_at(start);
        let mut budget = TransferAdmissionBudget::new(start + Duration::from_secs(5));
        assert_eq!(budget.refresh(&progress), start + Duration::from_secs(6));
    }

    #[tokio::test]
    async fn only_started_transfer_workers_record_slot_progress() {
        let database = crate::db::Database::open(":memory:").unwrap();
        let progress = database.0.transfer_progress.clone();
        let unstarted = database.acquire_transfer_runtime_permit().await.unwrap();
        drop(unstarted);
        assert!(progress.streak.lock().unwrap().is_none());

        let worker = database.acquire_transfer_runtime_permit().await.unwrap();
        worker.begin_work("transfer_write");
        assert!(progress.streak.lock().unwrap().is_none());
        drop(worker);
        assert!(progress.streak.lock().unwrap().is_some());
    }

    #[tokio::test]
    async fn general_work_borrowing_the_transfer_slot_cannot_renew_the_budget() {
        use crate::db::admission_diagnostics::DatabaseWorkPermit;

        let directory = tempfile::tempdir().unwrap();
        let database = crate::db::Database::open(directory.path().join("data.sqlite")).unwrap();
        let mut general = Vec::new();
        for _ in 0..3 {
            general.push(database.acquire_runtime_permit().await.unwrap());
        }
        let borrowed = database.acquire_runtime_permit().await.unwrap();
        assert!(borrowed._borrowed_transfer.is_some());
        borrowed.begin_work("metadata_read");
        drop(borrowed);
        assert!(database
            .0
            .transfer_progress
            .streak
            .lock()
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn cancelled_partial_admission_does_not_report_completed_work() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};

        let database = crate::db::Database::open(":memory:").unwrap();
        let runtime = database
            .0
            .runtime_admission
            .clone()
            .acquire_owned()
            .await
            .unwrap();
        let mut acquisition = Box::pin(database.acquire_transfer_runtime_permit());
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            acquisition.as_mut().poll(&mut context),
            Poll::Pending
        ));
        assert_eq!(database.0.transfer_runtime_admission.available_permits(), 0);
        drop(acquisition);
        assert!(database
            .0
            .transfer_progress
            .streak
            .lock()
            .unwrap()
            .is_none());
        assert_eq!(database.0.transfer_runtime_admission.available_permits(), 1);
        drop(runtime);
    }

    #[test]
    fn cleanup_cancellation_bursts_stay_bounded_and_defer_to_expiry() {
        let database = crate::db::Database::open(":memory:").unwrap();
        // Hold the worker state active without scheduling a real worker. This
        // models a paused cleanup drain and makes queue saturation deterministic.
        database.transfer_cleanup_queue_guard().worker_active = true;
        let runtime = tokio::runtime::Runtime::new().unwrap();
        for index in 0..TRANSFER_QUEUE_CAPACITY + 1 {
            database
                .enqueue_upload_reservation_cleanup(runtime.handle(), format!("queued-{index}"));
        }
        let mut queue = database.transfer_cleanup_queue_guard();
        assert_eq!(queue.jobs.len(), TRANSFER_QUEUE_CAPACITY);
        assert!(queue.worker_active);
        queue.jobs.clear();
        queue.worker_active = false;
    }
}
