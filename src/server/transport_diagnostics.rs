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

    fn reason(&self) -> Option<&'static str> {
        self.failure.or_else(|| {
            // Hyper may close an incomplete request without exposing its error.
            // Byte counts do not prove that a header timeout occurred.
            (self.bytes_written == 0).then_some("closed_without_response")
        })
    }
}

impl Drop for TransportDiagnostics {
    fn drop(&mut self) {
        let Some(reason) = self.reason() else { return };
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
                suppressed_since_last_event = suppressed,
                "HTTP connection ended without a response or with a transport error"
            );
        }
    }
}

#[cfg(test)]
#[path = "tests/transport_diagnostics.rs"]
mod tests;
