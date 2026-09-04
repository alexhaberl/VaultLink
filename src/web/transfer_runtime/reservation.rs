pub(super) struct UploadQuotaReservation {
    pub(super) database: Database,
    token: String,
    armed: bool,
}

impl UploadQuotaReservation {
    pub(super) fn new(database: Database, token: String) -> Self {
        Self {
            database,
            token,
            armed: true,
        }
    }

    pub(super) fn committed(mut self) {
        self.armed = false;
    }

    /// Removes the durable reservation before an expected HTTP rejection is
    /// returned. Keeping `self.token` armed until the blocking DB operation
    /// succeeds preserves the Drop fallback if this future is cancelled or the
    /// database is temporarily unavailable.
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
            // See the transfer counterpart above: ownership either reaches an
            // RAII guard or the reservation is removed before this worker exits.
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
