use std::{
    borrow::Borrow,
    future::Future as _,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures_util::{Stream, StreamExt as _};
use tracing::Instrument as _;

use crate::{
    db::Database,
    internal_reporting::{report_internal, InternalOperation, ReportedInternalError},
    state::ShareActivityPermit,
    AppState,
};

use super::{
    lease::{spawn_transfer_cancel, transfer_complete_future},
    PublicTransferError, PublicTransferLease,
};

pub(crate) struct PublicTransferStream {
    inner: Pin<Box<dyn Stream<Item = io::Result<Bytes>> + Send>>,
    database: Database,
    lease_token: Option<String>,
    finalizing_lease_token: Option<String>,
    client_ip: Option<String>,
    action: &'static str,
    share_id: i64,
    heartbeat_stop: Option<tokio::sync::oneshot::Sender<()>>,
    finalize: Option<tokio::task::JoinHandle<Result<(), ReportedInternalError>>>,
    pending_chunk: Option<Bytes>,
    remaining_bytes: Option<u64>,
    deadline: Pin<Box<tokio::time::Sleep>>,
    timed_out: bool,
    complete: bool,
    _share_admission: Option<ShareActivityPermit>,
    request_span: tracing::Span,
}

impl PublicTransferStream {
    fn start_finalize(&mut self) {
        self.heartbeat_stop.take();
        let Some(token) = self.lease_token.take() else {
            return;
        };
        // The finalizer owns its token and keeps running if the response body
        // is dropped. Retain a second owner only so a failed required-audit
        // transaction can release the still-live lease afterwards.
        self.finalizing_lease_token = Some(token.clone());
        let future = transfer_complete_future(
            self.database.clone(),
            token,
            self.action,
            self.share_id,
            self.client_ip.take(),
        );
        self.finalize = Some(tokio::spawn(future.instrument(self.request_span.clone())));
    }

    fn poll_finalize(
        &mut self,
        context: &mut Context<'_>,
    ) -> Option<Poll<Option<io::Result<Bytes>>>> {
        let finalize = self.finalize.as_mut()?;
        Some(match Pin::new(finalize).poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(Ok(()))) => {
                self.finalize.take();
                self.finalizing_lease_token.take();
                if let Some(chunk) = self.pending_chunk.take() {
                    if self.remaining_bytes == Some(0) {
                        self.complete = true;
                    }
                    Poll::Ready(Some(Ok(chunk)))
                } else {
                    self.complete = true;
                    Poll::Ready(None)
                }
            }
            Poll::Ready(Ok(Err(_reported))) => {
                self.finalize.take();
                self.cancel_failed_finalize();
                self.pending_chunk.take();
                self.complete = true;
                Poll::Ready(Some(Err(io::Error::other(
                    "public transfer completion failed",
                ))))
            }
            Poll::Ready(Err(error)) => {
                self.finalize.take();
                self.cancel_failed_finalize();
                self.pending_chunk.take();
                self.complete = true;
                let _reported =
                    report_internal(InternalOperation::WebTransferCompleteTaskJoin, error);
                Poll::Ready(Some(Err(io::Error::other(
                    "public transfer completion task failed",
                ))))
            }
        })
    }

    fn cancel_with_error(&mut self, error: io::Error) -> Poll<Option<io::Result<Bytes>>> {
        self.heartbeat_stop.take();
        if let Some(token) = self.lease_token.take() {
            spawn_transfer_cancel(self.database.clone(), token);
        }
        Poll::Ready(Some(Err(error)))
    }

    fn cancel_failed_finalize(&mut self) {
        if let Some(token) = self.finalizing_lease_token.take() {
            // This detached cleanup retains DB admission inside its blocking
            // worker, so dropping the HTTP body cannot cancel or over-admit it.
            spawn_transfer_cancel(self.database.clone(), token);
        }
    }
}

impl Stream for PublicTransferStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.timed_out || self.complete {
            return Poll::Ready(None);
        }
        if self.deadline.as_mut().poll(context).is_ready() {
            self.timed_out = true;
            self.finalize.take();
            return self.cancel_with_error(io::Error::new(
                io::ErrorKind::TimedOut,
                "public transfer lifetime exceeded",
            ));
        }
        loop {
            if let Some(result) = self.poll_finalize(context) {
                return result;
            }
            if self.remaining_bytes == Some(0) && self.lease_token.is_some() {
                self.start_finalize();
                continue;
            }
            match self.inner.poll_next_unpin(context) {
                Poll::Ready(None) => {
                    if self.remaining_bytes.is_some_and(|remaining| remaining > 0) {
                        return self.cancel_with_error(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "transfer source ended before Content-Length",
                        ));
                    }
                    if self.lease_token.is_some() {
                        self.start_finalize();
                        continue;
                    }
                    self.complete = true;
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Err(error))) => return self.cancel_with_error(error),
                Poll::Ready(Some(Ok(chunk))) => {
                    if let Some(remaining) = self.remaining_bytes {
                        let chunk_length = chunk.len() as u64;
                        if chunk_length > remaining {
                            return self.cancel_with_error(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "transfer source exceeded Content-Length",
                            ));
                        }
                        let remaining = remaining - chunk_length;
                        self.remaining_bytes = Some(remaining);
                        if !chunk.is_empty() && self.lease_token.is_some() {
                            self.pending_chunk = Some(chunk);
                            self.start_finalize();
                            continue;
                        }
                        if remaining == 0 {
                            self.complete = true;
                        }
                    } else if !chunk.is_empty() && self.lease_token.is_some() {
                        self.pending_chunk = Some(chunk);
                        self.start_finalize();
                        continue;
                    }
                    return Poll::Ready(Some(Ok(chunk)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Drop for PublicTransferStream {
    fn drop(&mut self) {
        self.heartbeat_stop.take();
        if let Some(token) = self.lease_token.take() {
            spawn_transfer_cancel(self.database.clone(), token);
        }
    }
}

pub(crate) fn transfer_stream<S>(
    stream: S,
    state: &(impl Borrow<AppState> + ?Sized),
    transfer: PublicTransferLease,
    action: &'static str,
    share_id: i64,
    expected_bytes: Option<u64>,
) -> PublicTransferStream
where
    S: Stream<Item = io::Result<Bytes>> + Send + 'static,
{
    let state = state.borrow();
    let (lease_token, heartbeat_stop, client_ip, share_admission) = transfer.into_stream_parts();
    PublicTransferStream {
        inner: Box::pin(stream),
        database: state.db().clone(),
        lease_token: Some(lease_token),
        finalizing_lease_token: None,
        client_ip,
        action,
        share_id,
        heartbeat_stop,
        finalize: None,
        pending_chunk: None,
        remaining_bytes: expected_bytes,
        deadline: Box::pin(tokio::time::sleep(std::time::Duration::from_secs(
            state.config().admission.stream_max_duration_seconds,
        ))),
        timed_out: false,
        complete: false,
        _share_admission: share_admission,
        request_span: tracing::Span::current(),
    }
}

pub(crate) async fn complete_transfer_without_body(
    state: &(impl Borrow<AppState> + ?Sized),
    transfer: PublicTransferLease,
    action: &'static str,
    share_id: i64,
) -> Result<(), PublicTransferError> {
    let state = state.borrow();
    let (lease_token, heartbeat_stop, client_ip, _share_admission) = transfer.into_stream_parts();
    drop(heartbeat_stop);
    tokio::spawn(
        transfer_complete_future(state.db().clone(), lease_token, action, share_id, client_ip)
            .instrument(tracing::Span::current()),
    )
    .await
    .map_err(|error| {
        PublicTransferError::Internal(report_internal(
            InternalOperation::WebTransferCompleteTaskJoin,
            error,
        ))
    })?
    .map_err(PublicTransferError::Internal)
}
