//! Bounded transport diagnostics. Never retain request bytes or peer addresses.
use std::{io, sync::Mutex, time::Duration};
use tokio::time::Instant;

const WINDOW: Duration = Duration::from_secs(60);
const EVENTS_PER_WINDOW: u32 = 60;

struct Budget {
    started: Option<Instant>,
    emitted: u32,
    suppressed: u64,
}

impl Budget {
    fn admit(&mut self, now: Instant) -> Option<u64> {
        if self
            .started
            .is_none_or(|start| now.duration_since(start) >= WINDOW)
        {
            self.started = Some(now);
            self.emitted = 0;
        }
        if self.emitted >= EVENTS_PER_WINDOW {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        self.emitted += 1;
        Some(std::mem::take(&mut self.suppressed))
    }
}

static BUDGET: Mutex<Budget> = Mutex::new(Budget {
    started: None,
    emitted: 0,
    suppressed: 0,
});

#[derive(Debug)]
pub(crate) struct TransportDiagnostics {
    started: Instant,
    peer_port: u16,
    local_port: u16,
    active_at_accept: usize,
    bytes_read: u64,
    bytes_written: u64,
    first_read_ms: Option<u128>,
    last_write_ms: Option<u128>,
    failure: Option<&'static str>,
    io_error: Option<&'static str>,
    write_operation: Option<&'static str>,
    write_poll_result: Option<&'static str>,
    write_requested_bytes: usize,
    last_write_poll_ms: Option<u128>,
    write_poll_gap_ms: Option<u128>,
    write_pending_polls: u64,
    write_deadline_late_ms: Option<u128>,
    write_deadline_recoveries: u64,
    last_write_recovery_late_ms: Option<u128>,
    last_write_recovery_gap_ms: Option<u128>,
}

impl TransportDiagnostics {
    pub(crate) fn new(peer_port: u16, local_port: u16, active_at_accept: usize) -> Self {
        Self {
            started: Instant::now(),
            peer_port,
            local_port,
            active_at_accept,
            bytes_read: 0,
            bytes_written: 0,
            first_read_ms: None,
            last_write_ms: None,
            failure: None,
            io_error: None,
            write_operation: None,
            write_poll_result: None,
            write_requested_bytes: 0,
            last_write_poll_ms: None,
            write_poll_gap_ms: None,
            write_pending_polls: 0,
            write_deadline_late_ms: None,
            write_deadline_recoveries: 0,
            last_write_recovery_late_ms: None,
            last_write_recovery_gap_ms: None,
        }
    }

    pub(crate) fn failure(&mut self, reason: &'static str) {
        self.failure.get_or_insert(reason);
    }

    pub(crate) fn io_error(&mut self, error: &io::Error) {
        self.io_error.get_or_insert(match error.kind() {
            io::ErrorKind::TimedOut => "timed_out",
            io::ErrorKind::ConnectionReset => "connection_reset",
            io::ErrorKind::ConnectionAborted => "connection_aborted",
            io::ErrorKind::BrokenPipe => "broken_pipe",
            io::ErrorKind::UnexpectedEof => "unexpected_eof",
            _ => "other",
        });
        self.failure("io_error");
    }

    pub(crate) fn read(&mut self, bytes: usize) {
        if bytes > 0 {
            self.bytes_read = self.bytes_read.saturating_add(bytes as u64);
            self.first_read_ms
                .get_or_insert_with(|| self.started.elapsed().as_millis());
        }
    }

    pub(crate) fn wrote(&mut self, bytes: usize) {
        if bytes > 0 {
            self.bytes_written = self.bytes_written.saturating_add(bytes as u64);
            self.last_write_ms = Some(self.started.elapsed().as_millis());
        }
    }

    pub(crate) fn write_poll(
        &mut self,
        operation: &'static str,
        result: &'static str,
        requested: usize,
        deadline: Option<Instant>,
    ) {
        // Preserve the I/O observation associated with the first failure;
        // subsequent cleanup polls must not overwrite its evidence.
        if self.failure.is_some() {
            return;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(self.started).as_millis();
        self.write_poll_gap_ms = self.last_write_poll_ms.map(|last| elapsed - last);
        self.last_write_poll_ms = Some(elapsed);
        self.write_operation = Some(operation);
        self.write_poll_result = Some(result);
        self.write_requested_bytes = requested;
        self.write_deadline_late_ms = deadline
            .filter(|deadline| now >= *deadline)
            .map(|deadline| now.duration_since(deadline).as_millis());
        if result == "pending" {
            self.write_pending_polls = self.write_pending_polls.saturating_add(1);
        }
        if self.write_deadline_late_ms.is_some() && matches!(result, "progress" | "complete") {
            self.write_deadline_recoveries = self.write_deadline_recoveries.saturating_add(1);
            self.last_write_recovery_late_ms = self.write_deadline_late_ms;
            self.last_write_recovery_gap_ms = self.write_poll_gap_ms;
        }
    }

    fn reason(&self) -> Option<&'static str> {
        self.failure.or_else(|| {
            // Hyper may close an incomplete request without exposing its error.
            // Byte counts do not prove that a header timeout occurred.
            if self.bytes_written == 0 {
                Some("closed_without_response")
            } else {
                (self.write_deadline_recoveries > 0).then_some("write_idle_recovered")
            }
        })
    }
}

impl Drop for TransportDiagnostics {
    fn drop(&mut self) {
        let Some(reason) = self.reason() else { return };
        if !tracing::enabled!(target: "vaultlink::transport", tracing::Level::WARN) {
            return;
        }
        let suppressed = BUDGET
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .admit(Instant::now());
        if let Some(suppressed) = suppressed {
            tracing::warn!(
                target: "vaultlink::transport",
                reason,
                peer_port = self.peer_port,
                local_port = self.local_port,
                active_at_accept = self.active_at_accept,
                elapsed_ms = self.started.elapsed().as_millis(),
                bytes_read = self.bytes_read,
                bytes_written = self.bytes_written,
                first_read_ms = ?self.first_read_ms,
                last_write_ms = ?self.last_write_ms,
                io_error = self.io_error,
                write_operation = self.write_operation,
                write_poll_result = self.write_poll_result,
                write_requested_bytes = self.write_requested_bytes,
                last_write_poll_ms = ?self.last_write_poll_ms,
                write_poll_gap_ms = ?self.write_poll_gap_ms,
                write_pending_polls = self.write_pending_polls,
                write_deadline_late_ms = ?self.write_deadline_late_ms,
                write_deadline_recoveries = self.write_deadline_recoveries,
                last_write_recovery_late_ms = ?self.last_write_recovery_late_ms,
                last_write_recovery_gap_ms = ?self.last_write_recovery_gap_ms,
                suppressed_since_last_event = suppressed,
                "HTTP connection transport summary"
            );
        }
    }
}

#[cfg(test)]
#[path = "tests/transport_diagnostics.rs"]
mod tests;
