//! Internal transport deadlines shared by the native listener and container proxy.
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const RESPONSE_WRITE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

pub trait TransportObserver: Unpin {
    fn failure(&mut self, _reason: &'static str) {}
    fn io_error(&mut self, _error: &io::Error) {}
    fn read(&mut self, _bytes: usize) {}
    fn wrote(&mut self, _bytes: usize) {}
    fn write_poll(
        &mut self,
        _operation: &'static str,
        _result: &'static str,
        _requested: usize,
        _deadline: Option<tokio::time::Instant>,
    ) {
    }
}

pub struct NoopObserver;
impl TransportObserver for NoopObserver {}

pub struct ConnectionLimitedIo<I, P = (), D = NoopObserver> {
    pub inner: I,
    pub diagnostics: D,
    pub _permit: P,
    pub write_timeout: Option<Pin<Box<tokio::time::Sleep>>>,
    pub write_idle_timeout: Duration,
    pub connection_deadline: Pin<Box<tokio::time::Sleep>>,
}

impl<I, P, D: TransportObserver> ConnectionLimitedIo<I, P, D> {
    fn poll_connection_deadline(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.connection_deadline.as_mut().poll(cx).is_ready() {
            self.diagnostics.failure("connection_lifetime_timeout");
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "absolute HTTP connection lifetime exceeded",
            ));
        }
        Ok(())
    }

    fn poll_write_deadline(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self
            .write_timeout
            .as_mut()
            .is_some_and(|timeout| timeout.as_mut().poll(cx).is_ready())
        {
            self.diagnostics.failure("write_idle_timeout");
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP response write made no progress before the deadline",
            ));
        }
        Ok(())
    }

    fn track_incomplete_write(&mut self, cx: &mut Context<'_>, incomplete: bool) {
        if incomplete {
            if self.write_timeout.is_none() {
                self.write_timeout = Some(Box::pin(tokio::time::sleep(self.write_idle_timeout)));
            }
            if let Some(timeout) = self.write_timeout.as_mut() {
                let _ = timeout.as_mut().poll(cx);
            }
        } else {
            self.write_timeout = None;
        }
    }
}

impl<I: AsyncRead + Unpin, P: Unpin, D: TransportObserver> AsyncRead
    for ConnectionLimitedIo<I, P, D>
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.connection_deadline.as_mut().poll(cx).is_ready() {
            this.diagnostics.failure("connection_lifetime_timeout");
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "absolute HTTP connection lifetime exceeded",
            )));
        }
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buffer);
        match &result {
            Poll::Ready(Ok(())) => this.diagnostics.read(buffer.filled().len() - before),
            Poll::Ready(Err(error)) => this.diagnostics.io_error(error),
            Poll::Pending => {}
        }
        result
    }
}

impl<I: AsyncWrite + Unpin, P: Unpin, D: TransportObserver> AsyncWrite
    for ConnectionLimitedIo<I, P, D>
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Err(error) = this.poll_connection_deadline(cx) {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.inner).poll_write(cx, buffer);
        this.diagnostics.write_poll(
            "write",
            match &result {
                Poll::Pending => "pending",
                Poll::Ready(Ok(0)) => "zero",
                Poll::Ready(Ok(_)) => "progress",
                Poll::Ready(Err(_)) => "error",
            },
            buffer.len(),
            this.write_timeout.as_ref().map(|timer| timer.deadline()),
        );
        match &result {
            Poll::Ready(Ok(bytes)) => this.diagnostics.wrote(*bytes),
            Poll::Ready(Err(error)) => this.diagnostics.io_error(error),
            Poll::Pending => {}
        }
        // Partial writes are progress too: measure idle time since the last
        // successful write, not since the first buffer that could not fit.
        if matches!(&result, Poll::Ready(Ok(written)) if *written > 0) {
            this.write_timeout = None;
        }
        let incomplete = match &result {
            Poll::Pending => true,
            Poll::Ready(Ok(written)) => *written < buffer.len(),
            Poll::Ready(Err(_)) => false,
        };
        // Give restored writability a chance before treating elapsed time
        // as proof that the transport is still blocked. Lifetime stays strict.
        if result.is_pending() {
            if let Err(error) = this.poll_write_deadline(cx) {
                return Poll::Ready(Err(error));
            }
        }
        this.track_incomplete_write(cx, incomplete);
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.poll_connection_deadline(cx) {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        this.diagnostics.write_poll(
            "flush",
            match &result {
                Poll::Pending => "pending",
                Poll::Ready(Ok(())) => "complete",
                Poll::Ready(Err(_)) => "error",
            },
            0,
            this.write_timeout.as_ref().map(|timer| timer.deadline()),
        );
        if let Poll::Ready(Err(error)) = &result {
            this.diagnostics.io_error(error);
        }
        // Give restored writability a chance before treating elapsed time
        // as proof that the transport is still blocked. Lifetime stays strict.
        if result.is_pending() {
            if let Err(error) = this.poll_write_deadline(cx) {
                return Poll::Ready(Err(error));
            }
        }
        this.track_incomplete_write(cx, result.is_pending());
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.poll_connection_deadline(cx) {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.inner).poll_shutdown(cx);
        this.diagnostics.write_poll(
            "shutdown",
            match &result {
                Poll::Pending => "pending",
                Poll::Ready(Ok(())) => "complete",
                Poll::Ready(Err(_)) => "error",
            },
            0,
            this.write_timeout.as_ref().map(|timer| timer.deadline()),
        );
        if let Poll::Ready(Err(error)) = &result {
            this.diagnostics.io_error(error);
        }
        // Give restored writability a chance before treating elapsed time
        // as proof that the transport is still blocked. Lifetime stays strict.
        if result.is_pending() {
            if let Err(error) = this.poll_write_deadline(cx) {
                return Poll::Ready(Err(error));
            }
        }
        this.track_incomplete_write(cx, result.is_pending());
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Err(error) = this.poll_connection_deadline(cx) {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, buffers);
        let requested = buffers.iter().map(|buffer| buffer.len()).sum::<usize>();
        this.diagnostics.write_poll(
            "write_vectored",
            match &result {
                Poll::Pending => "pending",
                Poll::Ready(Ok(0)) => "zero",
                Poll::Ready(Ok(_)) => "progress",
                Poll::Ready(Err(_)) => "error",
            },
            requested,
            this.write_timeout.as_ref().map(|timer| timer.deadline()),
        );
        match &result {
            Poll::Ready(Ok(bytes)) => this.diagnostics.wrote(*bytes),
            Poll::Ready(Err(error)) => this.diagnostics.io_error(error),
            Poll::Pending => {}
        }
        if matches!(&result, Poll::Ready(Ok(written)) if *written > 0) {
            this.write_timeout = None;
        }
        let incomplete = match &result {
            Poll::Pending => true,
            Poll::Ready(Ok(written)) => *written < requested,
            Poll::Ready(Err(_)) => false,
        };
        // Give restored writability a chance before treating elapsed time
        // as proof that the transport is still blocked. Lifetime stays strict.
        if result.is_pending() {
            if let Err(error) = this.poll_write_deadline(cx) {
                return Poll::Ready(Err(error));
            }
        }
        this.track_incomplete_write(cx, incomplete);
        result
    }
}

impl<I, P> ConnectionLimitedIo<I, P> {
    pub fn new(inner: I, permit: P) -> Self {
        Self {
            inner,
            _permit: permit,
            diagnostics: NoopObserver,
            write_timeout: None,
            write_idle_timeout: RESPONSE_WRITE_IDLE_TIMEOUT,
            connection_deadline: Box::pin(tokio::time::sleep(MAX_CONNECTION_LIFETIME)),
        }
    }
}
