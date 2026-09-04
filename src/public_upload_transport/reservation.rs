use crate::{
    db::{Database, UploadReservationBeginOutcome},
    http_auth::{database, database_runtime_permit},
    internal_reporting::{report_internal, InternalOperation},
};

use super::{AppError, Result};

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
        database(database_handle, move |database| {
            database.cancel_upload_reservation(&token)
        })
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
        spawn_drop_database_cleanup(database, "upload_reservation_cancel", move |database| {
            let _ = database.cancel_upload_reservation(&token);
        });
    }
}

pub(super) async fn begin_upload_reservation_cancellation_safe(
    database: Database,
    reservation_token: String,
    share_id: i64,
    expected_upload_policy_epoch: i64,
) -> Result<PendingReservationOwnership<UploadReservationBeginOutcome>> {
    let queue_started = std::time::Instant::now();
    let permit =
        database_runtime_permit(&database, "upload_reservation_begin", queue_started).await?;
    let (outcome_sender, outcome_receiver) = tokio::sync::oneshot::channel();
    let (ownership_sender, ownership_receiver) = tokio::sync::oneshot::channel();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
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
        if reserved && ownership_receiver.blocking_recv().is_err() {
            let _ = database.cancel_upload_reservation(&reservation_token);
        }
    });
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

fn spawn_drop_database_cleanup<F>(database: Database, class: &'static str, cleanup: F)
where
    F: FnOnce(&Database) + Send + 'static,
{
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    match database.try_acquire_runtime_permit() {
        Ok(permit) => {
            drop(handle.spawn_blocking(move || {
                let _permit = permit;
                cleanup(&database);
            }));
        }
        Err(_) => {
            drop(handle.spawn(async move {
                let queue_started = std::time::Instant::now();
                let Ok(permit) = database_runtime_permit(&database, class, queue_started).await
                else {
                    return;
                };
                let _ = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    cleanup(&database);
                })
                .await;
            }));
        }
    }
}
