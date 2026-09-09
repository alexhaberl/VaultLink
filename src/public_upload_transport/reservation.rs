use crate::{
    db::{Database, UploadReservationBeginOutcome},
    http_auth::{dispatch_transfer_database_work, transfer_database},
    internal_reporting::{report_internal, InternalOperation},
};

use super::{AppError, Result};

const INITIAL_RESERVATION_STEP: u64 = 1024 * 1024;
const MAX_RESERVATION_STEP: u64 = 8 * 1024 * 1024;

pub(super) fn preferred_reservation_target(
    received_bytes: u64,
    required_bytes: u64,
    reserved_bytes: u64,
    maximum: u64,
) -> u64 {
    if required_bytes <= reserved_bytes {
        return reserved_bytes;
    }
    // Grow with bytes actually received, never with heartbeat/retry count.
    // At most 8 MiB of extra quota is held; small uploads start at 1 MiB.
    let step = received_bytes
        .clamp(INITIAL_RESERVATION_STEP, MAX_RESERVATION_STEP)
        .next_power_of_two();
    required_bytes
        .checked_add(step - 1)
        .map(|value| value / step * step)
        .unwrap_or(required_bytes)
        .min(maximum)
}

pub(super) struct PendingReservationOwnership<T> {
    outcome: T,
    ownership_sender: Option<tokio::sync::oneshot::Sender<()>>,
}

impl<T: Copy> PendingReservationOwnership<T> {
    pub(super) fn outcome(&self) -> T {
        self.outcome
    }

    pub(super) fn claim(mut self) {
        if let Some(sender) = self.ownership_sender.take() {
            let _ = sender.send(());
        }
    }
}

pub(super) struct UploadQuotaReservation {
    pub(super) database: Database,
    token: String,
    armed: bool,
    pub(super) reserved_bytes: u64,
    pub(super) last_heartbeat: std::time::Instant,
}

impl UploadQuotaReservation {
    pub(super) fn new(database: Database, token: String) -> Self {
        Self {
            database,
            token,
            armed: true,
            reserved_bytes: 0,
            last_heartbeat: std::time::Instant::now(),
        }
    }

    pub(super) fn token(&self) -> &str {
        &self.token
    }

    pub(super) fn committed(mut self) {
        self.armed = false;
    }

    pub(super) fn database_finalized(mut self) {
        self.armed = false;
    }

    pub(super) async fn cancel(mut self) -> Result<()> {
        let token = self.token.clone();
        let database_handle = self.database.clone();
        transfer_database(
            database_handle,
            "upload_reservation_cancel",
            move |database| database.cancel_upload_reservation(&token),
        )
        .await?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for UploadQuotaReservation {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        let token = std::mem::take(&mut self.token);
        let database = self.database.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            database.enqueue_upload_reservation_cleanup(&handle, token);
        }
    }
}

pub(super) async fn begin_upload_reservation_cancellation_safe(
    database: Database,
    reservation_token: String,
    share_id: i64,
    expected_upload_policy_epoch: i64,
) -> Result<PendingReservationOwnership<UploadReservationBeginOutcome>> {
    let (outcome_sender, outcome_receiver) = tokio::sync::oneshot::channel();
    let (ownership_sender, ownership_receiver) = tokio::sync::oneshot::channel();
    let worker = dispatch_transfer_database_work(
        database,
        "upload_reservation_begin",
        move |database, admission| {
            let outcome = database.begin_upload_reservation(
                &reservation_token,
                share_id,
                expected_upload_policy_epoch,
            );
            let reserved = matches!(outcome, Ok(UploadReservationBeginOutcome::Reserved));
            if outcome_sender.send(outcome).is_err() {
                if reserved {
                    let _ = database.cancel_upload_reservation(&reservation_token);
                }
                return;
            }
            if reserved {
                database.finish_upload_handoff(admission, ownership_receiver, reservation_token);
            }
        },
    )
    .await?;
    // The worker waits for HTTP ownership after publishing its outcome.
    // Await only dispatch here; joining before claim would deadlock the handoff.
    drop(worker);
    let outcome = outcome_receiver
        .await
        .map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebUploadReservationBeginChannel,
                error,
            ))
        })?
        .map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebUploadReservationBeginDatabase,
                error,
            ))
        })?;
    Ok(PendingReservationOwnership {
        outcome,
        ownership_sender: Some(ownership_sender),
    })
}

#[cfg(test)]
mod batching_tests {
    use super::preferred_reservation_target;

    #[test]
    fn streaming_64_mib_needs_eleven_bounded_extensions() {
        let mib = 1024 * 1024;
        let maximum = 64 * mib;
        let chunk = 64 * 1024;
        let mut reserved = 0;
        let mut extensions = 0;
        for received in (0..maximum).step_by(chunk as usize) {
            let required = received + chunk;
            let target = preferred_reservation_target(received, required, reserved, maximum);
            assert!(target >= required && target >= reserved && target <= maximum);
            assert!(target - required < 8 * mib);
            if required > reserved {
                extensions += 1;
                reserved = target;
            }
        }
        assert_eq!(extensions, 11);
        assert_eq!(reserved, maximum);
    }

    #[test]
    fn heartbeat_small_limits_and_overflow_do_not_inflate_reservation() {
        let mib = 1024 * 1024;
        assert_eq!(preferred_reservation_target(0, 1, 0, 64 * mib), mib);
        assert_eq!(preferred_reservation_target(0, 1, 0, 7), 7);
        assert_eq!(preferred_reservation_target(3, 4, 7, 7), 7);
        assert_eq!(preferred_reservation_target(7, 7, 7, 7), 7);
        assert_eq!(
            preferred_reservation_target(u64::MAX - 1, u64::MAX, u64::MAX - 1, u64::MAX),
            u64::MAX
        );
    }
}
