pub(super) struct TransferBodyStream {
    pub(super) inner: Pin<Box<dyn Stream<Item = io::Result<Bytes>> + Send>>,
    pub(super) database: Database,
    pub(super) lease_token: Option<String>,
    pub(super) client_ip: Option<String>,
    pub(super) action: &'static str,
    pub(super) share_id: i64,
    pub(super) heartbeat_stop: Option<tokio::sync::oneshot::Sender<()>>,
    pub(super) finalize: Option<tokio::task::JoinHandle<io::Result<()>>>,
    pub(super) pending_chunk: Option<Bytes>,
    pub(super) remaining_bytes: Option<u64>,
    pub(super) deadline: Pin<Box<tokio::time::Sleep>>,
    pub(super) timed_out: bool,
    pub(super) complete: bool,
    pub(super) request_span: tracing::Span,
}

impl TransferBodyStream {
    fn start_finalize(&mut self) {
        self.heartbeat_stop.take();
        let Some(token) = self.lease_token.take() else {
            return;
        };
        let future = transfer_complete_future(
            self.database.clone(),
            token,
            self.action,
            self.share_id,
            self.client_ip.take(),
        );
        // Dropping a JoinHandle detaches the task. Once payload bytes are ready
        // to be emitted, completion must therefore survive a client disconnect.
        self.finalize = Some(tokio::spawn(future.instrument(self.request_span.clone())));
    }
}

impl Stream for TransferBodyStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.timed_out || self.complete {
            return Poll::Ready(None);
        }
        if self.deadline.as_mut().poll(context).is_ready() {
            self.timed_out = true;
            self.heartbeat_stop.take();
            self.finalize.take();
            if let Some(token) = self.lease_token.take() {
                spawn_transfer_cancel(&self.database, token);
            }
            return Poll::Ready(Some(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "public transfer lifetime exceeded",
            ))));
        }
        loop {
            if let Some(finalize) = self.finalize.as_mut() {
                return match Pin::new(finalize).poll(context) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Ok(Ok(()))) => {
                        self.finalize.take();
                        if let Some(chunk) = self.pending_chunk.take() {
                            // A known-length body may have more source chunks
                            // after the first payload chunk that triggered the
                            // commit. Only an exactly exhausted body ends here.
                            if self.remaining_bytes == Some(0) {
                                self.complete = true;
                            }
                            Poll::Ready(Some(Ok(chunk)))
                        } else {
                            self.complete = true;
                            Poll::Ready(None)
                        }
                    }
                    Poll::Ready(Ok(Err(error))) => {
                        self.finalize.take();
                        self.pending_chunk.take();
                        self.complete = true;
                        Poll::Ready(Some(Err(error)))
                    }
                    Poll::Ready(Err(error)) => {
                        self.finalize.take();
                        self.pending_chunk.take();
                        self.complete = true;
                        Poll::Ready(Some(Err(io::Error::other(error.to_string()))))
                    }
                };
            }
            if self.remaining_bytes == Some(0) && self.lease_token.is_some() {
                self.start_finalize();
                continue;
            }
            match self.inner.as_mut().poll_next(context) {
                Poll::Ready(None) => {
                    if self.remaining_bytes.is_some_and(|remaining| remaining > 0) {
                        self.heartbeat_stop.take();
                        if let Some(token) = self.lease_token.take() {
                            spawn_transfer_cancel(&self.database, token);
                        }
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "transfer source ended before Content-Length",
                        ))));
                    }
                    if self.lease_token.is_some() {
                        self.start_finalize();
                        continue;
                    }
                    self.complete = true;
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Err(error))) => {
                    self.heartbeat_stop.take();
                    if let Some(token) = self.lease_token.take() {
                        spawn_transfer_cancel(&self.database, token);
                    }
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(Some(Ok(chunk))) => {
                    if let Some(remaining) = self.remaining_bytes {
                        let chunk_length = chunk.len() as u64;
                        if chunk_length > remaining {
                            self.heartbeat_stop.take();
                            if let Some(token) = self.lease_token.take() {
                                spawn_transfer_cancel(&self.database, token);
                            }
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "transfer source exceeded Content-Length",
                            ))));
                        }
                        let remaining = remaining - chunk_length;
                        self.remaining_bytes = Some(remaining);
                        if !chunk.is_empty() && self.lease_token.is_some() {
                            // A positive known-length transfer is consumed as
                            // soon as any usable payload can leave the server.
                            // Waiting for the last byte lets a client repeatedly
                            // abort after N-1 bytes without using its limit.
                            self.pending_chunk = Some(chunk);
                            self.start_finalize();
                            continue;
                        }
                        if remaining == 0 {
                            self.complete = true;
                        }
                    } else if !chunk.is_empty() && self.lease_token.is_some() {
                        // Direct ZIP generation has no known final length. Count
                        // it before yielding its first usable payload bytes so a
                        // close-before-EOF cannot evade the transfer limit.
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

impl Drop for TransferBodyStream {
    fn drop(&mut self) {
        self.heartbeat_stop.take();
        if let Some(token) = self.lease_token.take() {
            spawn_transfer_cancel(&self.database, token);
        }
    }
}

pub(super) fn transfer_body<S>(
    stream: S,
    state: &AppState,
    transfer: PublicTransferLease,
    action: &'static str,
    share_id: i64,
    expected_bytes: Option<u64>,
) -> Body
where
    S: Stream<Item = io::Result<Bytes>> + Send + 'static,
{
    let (lease_token, heartbeat_stop, client_ip) = transfer.into_stream_parts();
    Body::from_stream(TransferBodyStream {
        inner: Box::pin(stream),
        database: state.db().clone(),
        lease_token: Some(lease_token),
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
        request_span: tracing::Span::current(),
    })
}
