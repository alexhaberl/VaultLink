use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use askama::Template;
use axum::{
    body::{Body, Bytes},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
};
use futures_util::Stream;

use super::{
    common::{encoded, internal},
    rendering::{escaped_html_len, push_html_escaped, storage_full_error},
    AppError, Result, BUFFERED_RESPONSE_CHUNK_BYTES, MAX_RENDERED_TEXT_PREVIEW_BYTES,
    TEXT_PREVIEW_STREAM_MARKER,
};

#[derive(Template)]
#[template(path = "web/public/upload_error.html")]
struct PublicUploadErrorTemplate {
    message: String,
    back_link: String,
}
use crate::{
    auth,
    db::{
        AuditContext, Database, Share, TransferAvailabilityOutcome, TransferLeaseBeginOutcome,
        TransferLeaseCompleteOutcome, UploadReservationBeginOutcome,
    },
    http_auth::{
        current_audit_client_ip, current_client_limit_key, database, make_transfer_cookie,
        runtime_settings, transfer_cookie, TransferCookieScope,
    },
    i18n::{self},
    AppState,
};

pub(super) struct PublicTransferLease {
    lease_token: String,
    armed: bool,
    cookie: String,
    heartbeat_stop: Option<tokio::sync::oneshot::Sender<()>>,
    database: Database,
    client_ip: Option<String>,
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

impl PublicTransferLease {
    pub(super) fn new(
        database: Database,
        lease_token: String,
        cookie: String,
        heartbeat_stop: Option<tokio::sync::oneshot::Sender<()>>,
        client_ip: Option<String>,
    ) -> Self {
        Self {
            lease_token,
            armed: true,
            cookie,
            heartbeat_stop,
            database,
            client_ip,
        }
    }

    pub(super) fn cookie(&self) -> &str {
        &self.cookie
    }

    /// Explicitly consumes a lease that cannot be handed to a response body.
    /// Drop remains the cancellation backstop for request cancellation.
    pub(super) async fn cancel(mut self) {
        self.heartbeat_stop.take();
        let lease_token = self.lease_token.clone();
        let cancellation_database = self.database.clone();
        if database(cancellation_database, move |database| {
            database.cancel_transfer_lease(&lease_token).map(|_| ())
        })
        .await
        .is_ok()
        {
            self.armed = false;
        }
    }

    fn into_stream_parts(
        mut self,
    ) -> (
        String,
        Option<tokio::sync::oneshot::Sender<()>>,
        Option<String>,
    ) {
        let lease_token = std::mem::take(&mut self.lease_token);
        self.armed = false;
        let heartbeat_stop = self.heartbeat_stop.take();
        let client_ip = self.client_ip.take();
        (lease_token, heartbeat_stop, client_ip)
    }
}

impl Drop for PublicTransferLease {
    fn drop(&mut self) {
        self.heartbeat_stop.take();
        if self.armed {
            self.armed = false;
            spawn_transfer_cancel(self.database.clone(), std::mem::take(&mut self.lease_token));
        }
    }
}

pub(super) fn start_transfer_heartbeat(
    database: Database,
    lease_token: String,
    action: &'static str,
    share_id: i64,
    client_ip: Option<String>,
) -> Option<tokio::sync::oneshot::Sender<()>> {
    let handle = tokio::runtime::Handle::try_current().ok()?;
    let (stop_sender, mut stop_receiver) = tokio::sync::oneshot::channel();
    handle.spawn(async move {
        let heartbeat_interval = std::time::Duration::from_secs(
            (crate::db::TRANSFER_SESSION_TTL_SECONDS / 3) as u64,
        );
        let mut ticker = tokio::time::interval(heartbeat_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = &mut stop_receiver => break,
                _ = ticker.tick() => {
                    let heartbeat_database = database.clone();
                    let heartbeat_token = lease_token.clone();
                    let audit_context = AuditContext::new("public", client_ip.clone());
                    match tokio::task::spawn_blocking(move || {
                        heartbeat_database.heartbeat_transfer_lease_and_audit(
                            &heartbeat_token,
                            &audit_context,
                        )
                    }).await {
                        Ok(Ok(crate::db::TransferLeaseHeartbeatOutcome::Extended)) => {}
                        Ok(Ok(crate::db::TransferLeaseHeartbeatOutcome::CappedAndCounted)) => {
                            tracing::warn!(share_id, action, "public transfer reached its absolute lifetime and was counted");
                            break;
                        }
                        Ok(Ok(crate::db::TransferLeaseHeartbeatOutcome::CappedAlreadyCounted)) => {
                            tracing::warn!(share_id, action, "public transfer reached its absolute lifetime");
                            break;
                        }
                        Ok(Ok(crate::db::TransferLeaseHeartbeatOutcome::NotFound)) => {
                            tracing::warn!("public transfer lease disappeared while the response was active");
                            break;
                        }
                        Ok(Err(error)) => {
                            tracing::warn!(%error, "could not heartbeat public transfer lease");
                        }
                        Err(error) => {
                            tracing::warn!(%error, "public transfer heartbeat task failed");
                            break;
                        }
                    }
                }
            }
        }
    });
    Some(stop_sender)
}

pub(super) fn transfer_scope(uri: &Uri) -> TransferCookieScope {
    if uri.path().starts_with("/api/v2/") {
        TransferCookieScope::Api
    } else {
        TransferCookieScope::Web
    }
}

pub(super) fn public_share_route(uri: &Uri, token: &str) -> String {
    if uri.path().starts_with("/api/v2/") {
        format!("/api/v2/public/shares/{token}")
    } else {
        format!("/v/{token}")
    }
}

pub(super) async fn begin_public_transfer(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    share: &Share,
    resource_key: String,
    action: &'static str,
) -> Result<PublicTransferLease> {
    let client_key = current_client_limit_key();
    if !state
        .public_transfer_limiter
        .check_and_record_attempt(&format!("public-transfer:{}:{client_key}", share.id))
    {
        return Err(AppError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many public transfers",
        ));
    }
    let session_token = transfer_cookie(headers, share.id)
        .map(str::to_string)
        .unwrap_or_else(|| auth::random_token(32));
    let lease_token = auth::random_token(32);
    let session_for_db = session_token.clone();
    let lease_for_db = lease_token.clone();
    let share_id = share.id;
    let pending_ownership = begin_transfer_lease_cancellation_safe(
        state.db.clone(),
        session_for_db,
        lease_for_db,
        share_id,
        resource_key,
        action,
    )
    .await?;
    match pending_ownership.outcome() {
        TransferLeaseBeginOutcome::NewLease | TransferLeaseBeginOutcome::AlreadyCounted => {
            let audit_client_ip_enabled = runtime_settings(state).audit_client_ip_enabled;
            let client_ip = audit_client_ip_enabled
                .then(current_audit_client_ip)
                .flatten()
                .map(|ip| ip.to_string());
            let heartbeat_stop = start_transfer_heartbeat(
                state.db.clone(),
                lease_token.clone(),
                action,
                share.id,
                client_ip.clone(),
            );
            let lease = PublicTransferLease::new(
                state.db.clone(),
                lease_token,
                make_transfer_cookie(state, share, &session_token, transfer_scope(uri)),
                heartbeat_stop,
                client_ip,
            );
            // Acknowledgement is deliberately last: until the RAII owner exists,
            // dropping this request makes the blocking worker cancel the lease.
            pending_ownership.claim();
            Ok(lease)
        }
        TransferLeaseBeginOutcome::LimitReached => {
            Err(AppError(StatusCode::GONE, "Transfer limit reached"))
        }
        TransferLeaseBeginOutcome::ShareUnavailable => {
            Err(AppError(StatusCode::GONE, "Share unavailable"))
        }
    }
}

pub(super) async fn begin_transfer_lease_cancellation_safe(
    database: Database,
    session_token: String,
    lease_token: String,
    share_id: i64,
    resource_key: String,
    action: &'static str,
) -> Result<PendingReservationOwnership<TransferLeaseBeginOutcome>> {
    let (outcome_sender, outcome_receiver) = tokio::sync::oneshot::channel();
    let (ownership_sender, ownership_receiver) = tokio::sync::oneshot::channel();
    tokio::task::spawn_blocking(move || {
        let outcome = database.begin_transfer_lease(
            &session_token,
            &lease_token,
            share_id,
            &resource_key,
            action,
        );
        let reserved = matches!(
            outcome,
            Ok(TransferLeaseBeginOutcome::NewLease) | Ok(TransferLeaseBeginOutcome::AlreadyCounted)
        );
        if outcome_sender.send(outcome).is_err() {
            if reserved {
                let _ = database.cancel_transfer_lease(&lease_token);
            }
            return;
        }
        if reserved && ownership_receiver.blocking_recv().is_err() {
            // The async receiver disappeared after SQLite committed but before
            // a PublicTransferLease could take ownership. Cancel synchronously
            // in this already-blocking worker so no detached lease survives.
            let _ = database.cancel_transfer_lease(&lease_token);
        }
    });
    let outcome = outcome_receiver
        .await
        .map_err(internal)?
        .map_err(internal)?;
    Ok(PendingReservationOwnership {
        outcome,
        ownership_sender: Some(ownership_sender),
    })
}

pub(super) async fn check_public_transfer_availability(
    state: &AppState,
    headers: &HeaderMap,
    share: &Share,
    resource_key: String,
    action: &'static str,
) -> Result<()> {
    let session_token = transfer_cookie(headers, share.id)
        .map(str::to_string)
        .unwrap_or_else(|| auth::random_token(32));
    let share_id = share.id;
    let outcome = database(state.db.clone(), move |database| {
        database.check_transfer_availability(&session_token, share_id, &resource_key, action)
    })
    .await?;
    match outcome {
        TransferAvailabilityOutcome::Available | TransferAvailabilityOutcome::AlreadyCounted => {
            Ok(())
        }
        TransferAvailabilityOutcome::LimitReached => {
            Err(AppError(StatusCode::GONE, "Transfer limit reached"))
        }
        TransferAvailabilityOutcome::ShareUnavailable => {
            Err(AppError(StatusCode::GONE, "Share unavailable"))
        }
    }
}

pub(super) fn transfer_complete_future(
    database: Database,
    lease_token: String,
    action: &'static str,
    share_id: i64,
    client_ip: Option<String>,
) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send>> {
    Box::pin(async move {
        let result = tokio::task::spawn_blocking(move || {
            database.complete_transfer_lease_and_audit(
                &lease_token,
                &AuditContext::new("public", client_ip),
                action,
                share_id,
            )
        })
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
        match result {
            Ok(TransferLeaseCompleteOutcome::Counted)
            | Ok(TransferLeaseCompleteOutcome::AlreadyCounted) => {}
            Ok(TransferLeaseCompleteOutcome::NotFound) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "public transfer lease expired before completion",
                ));
            }
            Err(error) => {
                tracing::warn!(share_id, action, %error, "could not finalize public transfer lease");
                return Err(io::Error::other(error.to_string()));
            }
        }
        Ok(())
    })
}

pub(super) fn spawn_transfer_cancel(database: Database, lease_token: String) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn_blocking(move || {
        let _ = database.cancel_transfer_lease(&lease_token);
    });
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
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn_blocking(move || {
                let _ = database.cancel_upload_reservation(&token);
            });
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
    tokio::task::spawn_blocking(move || {
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
        .map_err(internal)?
        .map_err(internal)?;
    Ok(PendingReservationOwnership {
        outcome,
        ownership_sender: Some(ownership_sender),
    })
}

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
        self.finalize = Some(tokio::spawn(future));
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
                spawn_transfer_cancel(self.database.clone(), token);
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
                            spawn_transfer_cancel(self.database.clone(), token);
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
                        spawn_transfer_cancel(self.database.clone(), token);
                    }
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(Some(Ok(chunk))) => {
                    if let Some(remaining) = self.remaining_bytes {
                        let chunk_length = chunk.len() as u64;
                        if chunk_length > remaining {
                            self.heartbeat_stop.take();
                            if let Some(token) = self.lease_token.take() {
                                spawn_transfer_cancel(self.database.clone(), token);
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
            spawn_transfer_cancel(self.database.clone(), token);
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
        database: state.db.clone(),
        lease_token: Some(lease_token),
        client_ip,
        action,
        share_id,
        heartbeat_stop,
        finalize: None,
        pending_chunk: None,
        remaining_bytes: expected_bytes,
        deadline: Box::pin(tokio::time::sleep(std::time::Duration::from_secs(
            crate::db::TRANSFER_LEASE_MAX_LIFETIME_SECONDS as u64,
        ))),
        timed_out: false,
        complete: false,
    })
}

pub(super) struct EscapedTextPageStream {
    page: Bytes,
    prefix_end: usize,
    prefix_offset: usize,
    suffix_offset: usize,
    text: String,
    text_offset: usize,
    escaped_remaining: usize,
    phase: u8,
}

impl Stream for EscapedTextPageStream {
    type Item = io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match this.phase {
                0 => {
                    if this.prefix_offset >= this.prefix_end {
                        this.phase = 1;
                        continue;
                    }
                    let end = this
                        .prefix_offset
                        .saturating_add(BUFFERED_RESPONSE_CHUNK_BYTES)
                        .min(this.prefix_end);
                    let chunk = this.page.slice(this.prefix_offset..end);
                    this.prefix_offset = end;
                    return Poll::Ready(Some(Ok(chunk)));
                }
                1 => {
                    if this.text_offset >= this.text.len() {
                        if this.escaped_remaining != 0 {
                            this.phase = 3;
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "escaped preview length mismatch",
                            ))));
                        }
                        this.phase = 2;
                        continue;
                    }
                    let mut chunk = String::with_capacity(BUFFERED_RESPONSE_CHUNK_BYTES);
                    while this.text_offset < this.text.len() {
                        let character = this.text[this.text_offset..]
                            .chars()
                            .next()
                            .expect("text offset is a UTF-8 boundary");
                        let escaped_length = match character {
                            '&' => 5,
                            '<' | '>' => 4,
                            '"' => 6,
                            '\'' => 5,
                            character => character.len_utf8(),
                        };
                        if !chunk.is_empty()
                            && chunk.len().saturating_add(escaped_length)
                                > BUFFERED_RESPONSE_CHUNK_BYTES
                        {
                            break;
                        }
                        if escaped_length > this.escaped_remaining {
                            this.phase = 3;
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "escaped preview exceeds its output cap",
                            ))));
                        }
                        push_html_escaped(&mut chunk, character);
                        this.text_offset += character.len_utf8();
                        this.escaped_remaining -= escaped_length;
                    }
                    return Poll::Ready(Some(Ok(Bytes::from(chunk))));
                }
                2 => {
                    let suffix_end = this.page.len();
                    if this.suffix_offset >= suffix_end {
                        this.phase = 3;
                        continue;
                    }
                    let end = this
                        .suffix_offset
                        .saturating_add(BUFFERED_RESPONSE_CHUNK_BYTES)
                        .min(suffix_end);
                    let chunk = this.page.slice(this.suffix_offset..end);
                    this.suffix_offset = end;
                    return Poll::Ready(Some(Ok(chunk)));
                }
                _ => return Poll::Ready(None),
            }
        }
    }
}

/// Inserts a text preview into the single marker emitted by an Askama shell.
///
/// This is the one deliberate exception to Askama's normal value rendering:
/// preview text can be large, so it is HTML-escaped incrementally under the
/// rendered-output cap instead of first allocating a second escaped string.
pub(super) fn escaped_text_page_stream(
    page_template: String,
    text: String,
) -> io::Result<(EscapedTextPageStream, u64)> {
    let marker_index = page_template
        .find(TEXT_PREVIEW_STREAM_MARKER)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "preview marker is missing"))?;
    let suffix_start = marker_index + TEXT_PREVIEW_STREAM_MARKER.len();
    if page_template[suffix_start..].contains(TEXT_PREVIEW_STREAM_MARKER) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "preview marker is ambiguous",
        ));
    }
    let escaped_length = escaped_html_len(&text)
        .filter(|length| *length <= MAX_RENDERED_TEXT_PREVIEW_BYTES)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "escaped preview exceeds its output cap",
            )
        })?;
    let page_length = marker_index
        .checked_add(escaped_length)
        .and_then(|length| length.checked_add(page_template.len() - suffix_start))
        .and_then(|length| u64::try_from(length).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "preview size overflow"))?;
    let page = Bytes::from(page_template);
    Ok((
        EscapedTextPageStream {
            page,
            prefix_end: marker_index,
            prefix_offset: 0,
            suffix_offset: suffix_start,
            text,
            text_offset: 0,
            escaped_remaining: escaped_length,
            phase: 0,
        },
        page_length,
    ))
}

pub(super) async fn complete_transfer_without_body(
    state: &AppState,
    transfer: PublicTransferLease,
    action: &'static str,
    share_id: i64,
) -> Result<()> {
    let (lease_token, heartbeat_stop, client_ip) = transfer.into_stream_parts();
    drop(heartbeat_stop);
    // Keep the durable completion owned by a detached task. If the HTTP
    // request is cancelled while awaiting it, dropping this JoinHandle does
    // not abort the database completion.
    tokio::spawn(transfer_complete_future(
        state.db.clone(),
        lease_token,
        action,
        share_id,
        client_ip,
    ))
    .await
    .map_err(internal)?
    .map_err(internal)
}

pub(super) fn set_transfer_cookie(response: &mut Response, cookie: &str) -> Result<()> {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(cookie).map_err(internal)?,
    );
    Ok(())
}

pub(super) fn upload_io_error(error: std::io::Error) -> AppError {
    if storage_full_error(&error) {
        AppError(StatusCode::INSUFFICIENT_STORAGE, "Not enough free storage")
    } else {
        internal(error)
    }
}

pub(super) enum PendingUploadFileError {
    Begin,
    Take(std::io::Error),
}

pub(super) async fn limited_multipart_text(
    mut field: axum::extract::multipart::Field<'_>,
    maximum: usize,
) -> std::result::Result<String, ()> {
    let mut value = Vec::new();
    while let Some(chunk) = field.chunk().await.map_err(|_| ())? {
        if value
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > maximum)
        {
            return Err(());
        }
        value.extend_from_slice(&chunk);
    }
    String::from_utf8(value).map_err(|_| ())
}

pub(super) fn public_upload_error(
    token: &str,
    upload_subdir: &str,
    status: StatusCode,
    message: &str,
) -> Response {
    let message = i18n::localized_text(i18n::current_locale(), message).into_owned();
    let back = if upload_subdir.is_empty() {
        format!("/v/{token}")
    } else {
        format!("/v/{token}?path={}", encoded(upload_subdir))
    };
    let body = PublicUploadErrorTemplate {
        message,
        back_link: back,
    };
    let page = super::templates::public_page(i18n::ERROR, &body)
        .expect("the public upload error template writes only to an in-memory string");
    (status, Html(page)).into_response()
}
