use super::{Database, DatabaseAdmissionState, TransferDatabasePermit, TransferSlotPermit};
use std::time::{Duration, Instant};

pub(super) struct TransferObservation {
    pub(super) phase: &'static str,
    pub(super) started: Instant,
    pub(super) phase_started: Instant,
}

impl TransferSlotPermit {
    pub(super) fn observed(
        database: &Database,
        permit: tokio::sync::OwnedSemaphorePermit,
        phase: &'static str,
    ) -> Self {
        let now = Instant::now();
        *database
            .0
            .transfer_observation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(TransferObservation {
            phase,
            started: now,
            phase_started: now,
        });
        Self {
            permit: Some(permit),
            released: database.0.transfer_slot_released.clone(),
            observation: database.0.transfer_observation.clone(),
        }
    }

    pub(super) fn phase(&self, phase: &'static str) {
        if let Some(observation) = self
            .observation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            observation.phase = phase;
            observation.phase_started = Instant::now();
        }
    }
}

impl TransferDatabasePermit {
    pub(crate) fn begin_work(&self, class: &'static str) {
        // Copy the numeric observation before invoking a tracing subscriber.
        let worker_queue_ms = self
            ._transfer
            .observation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|o| o.phase_started.elapsed().as_millis() as u64);
        self._transfer.phase(class);
        if let Some(worker_queue_ms) = worker_queue_ms {
            crate::best_effort_telemetry::emit(move || {
                tracing::debug!(parent: None,
                    operation = "database.transfer_worker",
                    class,
                    worker_queue_ms,
                    "transfer database worker started"
                )
            });
        }
    }
}

impl DatabaseAdmissionState {
    pub(crate) fn report(self, class: &'static str, queue_duration: Duration) {
        let metrics = tokio::runtime::Handle::try_current()
            .ok()
            .map(|h| h.metrics());
        let scheduler_global_queue_depth = metrics.as_ref().map(|m| m.global_queue_depth());
        let scheduler_alive_tasks = metrics.as_ref().map(|m| m.num_alive_tasks());
        let observed_at = Instant::now();
        crate::best_effort_telemetry::emit(move || {
            tracing::warn!(parent: None, operation = "database.admission", class,
            queue_duration_ms = queue_duration.as_millis() as u64,
            runtime_available_permits = self.runtime_available,
            general_available_permits = self.general_available,
            transfer_available_permits = self.transfer_available,
            transfer_phase = self.transfer_phase,
            transfer_held_ms = self.transfer_phase.map(|_| self.transfer_held_ms),
            transfer_phase_ms = self.transfer_phase.map(|_| self.transfer_phase_ms),
            scheduler_global_queue_depth = ?scheduler_global_queue_depth,
            scheduler_alive_tasks = ?scheduler_alive_tasks,
            telemetry_delay_ms = observed_at.elapsed().as_millis() as u64,
            "database executor admission timed out")
        });
    }
}

pub(super) trait DatabaseWorkPermit: Send + 'static {
    fn begin_work(&self, class: &'static str);
}

impl DatabaseWorkPermit for super::RuntimeDatabasePermit {
    fn begin_work(&self, class: &'static str) {
        if let Some(transfer) = &self._borrowed_transfer {
            transfer.phase(class);
        }
    }
}

impl DatabaseWorkPermit for TransferDatabasePermit {
    fn begin_work(&self, class: &'static str) {
        TransferDatabasePermit::begin_work(self, class);
    }
}
