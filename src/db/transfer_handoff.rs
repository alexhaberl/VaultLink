use super::{
    transfer_progress::TransferAdmissionBudget, Database, TransferCleanupJob, TransferCleanupKind,
    TransferDatabasePermit,
};

impl Database {
    pub(crate) fn finish_lease_handoff(
        &self,
        permit: TransferDatabasePermit,
        receiver: tokio::sync::oneshot::Receiver<()>,
        token: String,
    ) {
        self.finish_transfer_handoff(permit, receiver, TransferCleanupKind::TransferLease(token));
    }

    pub(crate) fn finish_upload_handoff(
        &self,
        permit: TransferDatabasePermit,
        receiver: tokio::sync::oneshot::Receiver<()>,
        token: String,
    ) {
        self.finish_transfer_handoff(
            permit,
            receiver,
            TransferCleanupKind::UploadReservation(token),
        );
    }

    fn finish_transfer_handoff(
        &self,
        permit: TransferDatabasePermit,
        receiver: tokio::sync::oneshot::Receiver<()>,
        kind: TransferCleanupKind,
    ) {
        // The transaction is finished. HTTP scheduling must not retain either
        // the single writer slot or a global DB slot. Keep this blocking worker
        // alive so cancellation still compensates during runtime shutdown.
        drop(permit);
        let started = std::time::Instant::now();
        let abandoned = receiver.blocking_recv().is_err();
        let observed_at = std::time::Instant::now();
        let ownership_wait = observed_at.saturating_duration_since(started);
        let class = kind.class();
        crate::best_effort_telemetry::emit(move || {
            tracing::debug!(parent: None,
                operation = "database.handoff",
                class,
                ownership_wait_ms = ownership_wait.as_millis() as u64,
                telemetry_delay_ms = observed_at.elapsed().as_millis() as u64,
                abandoned,
                "transfer ownership handoff finished"
            )
        });
        self.0
            .work_diagnostics
            .record_ownership(class, ownership_wait, abandoned);
        if abandoned {
            // Compensation is a new DB operation: use the existing FIFO and
            // bounded deadline, never perform an unadmitted write after release.
            self.run_transfer_cleanup_job(TransferCleanupJob {
                budget: TransferAdmissionBudget::new(std::time::Instant::now()),
                kind,
            });
        }
    }
}
