use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

#[derive(Clone, Copy)]
struct ValidatedClientIp(Option<IpAddr>);

use axum::{
    body::{Body, Bytes, HttpBody},
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderValue, Method, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http_body::{Frame, SizeHint};
use tokio::sync::OwnedSemaphorePermit;

use super::{
    AppError, BUFFERED_RESPONSE_CHUNK_BYTES, BUFFERED_RESPONSE_MAX_LIFETIME,
    DEFAULT_REQUEST_BODY_DEADLINE,
};
use crate::{
    http_auth::{with_audit_client_ip, ClientActivityPermit},
    i18n::{self, Locale},
    proxy, AdmissionRouteState,
};

pub(super) struct AbsoluteDeadlineBody {
    pub(super) inner: Body,
    pub(super) deadline: Pin<Box<tokio::time::Sleep>>,
    pub(super) minimum_progress: Option<MinimumProgress>,
    pub(super) timed_out: bool,
}

const PROGRESS_GRACE_PERIOD: std::time::Duration = std::time::Duration::from_secs(60);
const PROGRESS_WINDOW: std::time::Duration = std::time::Duration::from_secs(30);

pub(super) struct MinimumProgress {
    grace: Pin<Box<tokio::time::Sleep>>,
    window: Pin<Box<tokio::time::Sleep>>,
    grace_complete: bool,
    bytes_in_window: u64,
    minimum_bytes_per_window: u64,
    window_duration: std::time::Duration,
}

impl MinimumProgress {
    pub(super) fn new(minimum_bytes_per_second: u64) -> Self {
        Self::with_intervals(
            minimum_bytes_per_second,
            PROGRESS_GRACE_PERIOD,
            PROGRESS_WINDOW,
        )
    }

    pub(super) fn with_intervals(
        minimum_bytes_per_second: u64,
        grace_period: std::time::Duration,
        window_duration: std::time::Duration,
    ) -> Self {
        let minimum_bytes_per_window =
            minimum_bytes_per_second.saturating_mul(window_duration.as_secs().max(1));
        Self {
            grace: Box::pin(tokio::time::sleep(grace_period)),
            window: Box::pin(tokio::time::sleep(grace_period + window_duration)),
            grace_complete: false,
            bytes_in_window: 0,
            minimum_bytes_per_window,
            window_duration,
        }
    }

    fn poll_timed_out(&mut self, cx: &mut Context<'_>) -> bool {
        if !self.grace_complete {
            if self.grace.as_mut().poll(cx).is_ready() {
                self.grace_complete = true;
                self.bytes_in_window = 0;
                self.window
                    .as_mut()
                    .reset(tokio::time::Instant::now() + self.window_duration);
                let _ = self.window.as_mut().poll(cx);
            }
            return false;
        }
        if self.window.as_mut().poll(cx).is_pending() {
            return false;
        }
        if self.bytes_in_window < self.minimum_bytes_per_window {
            return true;
        }
        self.bytes_in_window = 0;
        self.window
            .as_mut()
            .reset(tokio::time::Instant::now() + self.window_duration);
        let _ = self.window.as_mut().poll(cx);
        false
    }

    fn observe_frame(&mut self, frame: &Frame<Bytes>) {
        if self.grace_complete {
            if let Some(data) = frame.data_ref() {
                self.bytes_in_window = self.bytes_in_window.saturating_add(data.len() as u64);
            }
        }
    }
}

impl HttpBody for AbsoluteDeadlineBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.timed_out {
            return Poll::Ready(None);
        }
        if this.deadline.as_mut().poll(cx).is_ready() {
            this.timed_out = true;
            return Poll::Ready(Some(Err(axum::Error::new(io::Error::new(
                io::ErrorKind::TimedOut,
                "absolute request body deadline exceeded",
            )))));
        }
        if this
            .minimum_progress
            .as_mut()
            .is_some_and(|progress| progress.poll_timed_out(cx))
        {
            this.timed_out = true;
            return Poll::Ready(Some(Err(axum::Error::new(io::Error::new(
                io::ErrorKind::TimedOut,
                "minimum request body progress not met",
            )))));
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(progress) = this.minimum_progress.as_mut() {
                    progress.observe_frame(&frame);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.timed_out || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

pub(super) struct PermitBody {
    pub(super) inner: Body,
    pub(super) _permit: OwnedSemaphorePermit,
}

pub(super) struct StreamAdmissionBody {
    pub(super) inner: Body,
    pub(super) _permit: OwnedSemaphorePermit,
    pub(super) _peer_permit: ClientActivityPermit,
    pub(super) _public_permit: Option<OwnedSemaphorePermit>,
    pub(super) deadline: Pin<Box<tokio::time::Sleep>>,
    pub(super) minimum_progress: MinimumProgress,
    pub(super) transferred_data_bytes: u64,
    pub(super) operation: &'static str,
    pub(super) public: bool,
    pub(super) complete: bool,
}

pub(super) struct BufferedAdmissionBody {
    pub(super) inner: Body,
    pub(super) _permit: OwnedSemaphorePermit,
    pub(super) _peer_permit: ClientActivityPermit,
    pub(super) pending: Option<Bytes>,
    pub(super) complete: bool,
    pub(super) deadline: Pin<Box<tokio::time::Sleep>>,
}

impl HttpBody for BufferedAdmissionBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.complete {
            return Poll::Ready(None);
        }
        if this.deadline.as_mut().poll(cx).is_ready() {
            this.complete = true;
            this.pending.take();
            return Poll::Ready(Some(Err(axum::Error::new(io::Error::new(
                io::ErrorKind::TimedOut,
                "buffered response lifetime exceeded",
            )))));
        }
        if let Some(pending) = this.pending.take() {
            let length = pending.len().min(BUFFERED_RESPONSE_CHUNK_BYTES);
            let chunk = pending.slice(..length);
            if length < pending.len() {
                this.pending = Some(pending.slice(length..));
            }
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    let length = data.len().min(BUFFERED_RESPONSE_CHUNK_BYTES);
                    let chunk = data.slice(..length);
                    if length < data.len() {
                        this.pending = Some(data.slice(length..));
                    }
                    Poll::Ready(Some(Ok(Frame::data(chunk))))
                }
                Err(frame) => Poll::Ready(Some(Ok(frame))),
            },
            Poll::Ready(Some(Err(error))) => {
                this.complete = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.complete = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.complete
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

impl HttpBody for StreamAdmissionBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.complete {
            return Poll::Ready(None);
        }
        if this.deadline.as_mut().poll(cx).is_ready() {
            terminate_incomplete_stream(this, "maximum_duration");
            return Poll::Ready(Some(Err(axum::Error::new(io::Error::new(
                io::ErrorKind::TimedOut,
                "stream response lifetime exceeded",
            )))));
        }
        if this.minimum_progress.poll_timed_out(cx) {
            terminate_incomplete_stream(this, "minimum_progress");
            return Poll::Ready(Some(Err(axum::Error::new(io::Error::new(
                io::ErrorKind::TimedOut,
                "minimum stream progress not met",
            )))));
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(None) => {
                this.complete = true;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                this.complete = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.transferred_data_bytes = this
                        .transferred_data_bytes
                        .saturating_add(data.len() as u64);
                }
                this.minimum_progress.observe_frame(&frame);
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.complete || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn terminate_incomplete_stream(stream: &mut StreamAdmissionBody, reason: &'static str) {
    stream.complete = true;
    // Drop the producer body immediately. This closes ZIP/file channels and
    // runs their RAII cancellation paths before the admission slots are
    // released, rather than waiting for the outer response object to drop.
    stream.inner = Body::empty();
    if stream.transferred_data_bytes > 0 {
        tracing::warn!(
            operation = "stream.incomplete",
            transfer = stream.operation,
            public = stream.public,
            reason,
            transferred_data_bytes = stream.transferred_data_bytes,
            "started response stream terminated before completion"
        );
    }
}

impl HttpBody for PermitBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.get_mut().inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

type ResponseBodyPermits = (
    OwnedSemaphorePermit,
    ClientActivityPermit,
    Option<OwnedSemaphorePermit>,
);

#[derive(Clone, Copy)]
struct AdmissionRejection {
    message: &'static str,
}

impl AdmissionRejection {
    const fn new(message: &'static str) -> Self {
        Self { message }
    }

    fn into_response(self) -> Response {
        admission_rejected(self.message)
    }
}

fn admission_rejected(message: &'static str) -> Response {
    let mut response = (StatusCode::SERVICE_UNAVAILABLE, message).into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

fn request_peer(request: &Request) -> IpAddr {
    request
        .extensions()
        .get::<ValidatedClientIp>()
        .and_then(|client_ip| client_ip.0)
        .map(proxy::client_limit_key)
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

fn try_stream_permits(
    state: &AdmissionRouteState,
    peer: IpAddr,
    public_streaming: bool,
) -> std::result::Result<ResponseBodyPermits, AdmissionRejection> {
    let public = if public_streaming {
        Some(
            state
                .try_acquire_public_stream()
                .map_err(|_| AdmissionRejection::new("Too many concurrent public downloads"))?,
        )
    } else {
        None
    };
    let global = state
        .try_acquire_stream()
        .map_err(|_| AdmissionRejection::new("Too many concurrent downloads"))?;
    let peer_permit = state
        .try_acquire_stream_peer(peer)
        .ok_or_else(|| AdmissionRejection::new("Too many concurrent downloads from this client"))?;
    Ok((global, peer_permit, public))
}

fn try_buffered_permits(
    state: &AdmissionRouteState,
    peer: IpAddr,
) -> std::result::Result<ResponseBodyPermits, AdmissionRejection> {
    let global = state
        .try_acquire_buffered_response()
        .map_err(|_| AdmissionRejection::new("Too many concurrent responses"))?;
    let peer_permit = state
        .try_acquire_buffered_peer(peer)
        .ok_or_else(|| AdmissionRejection::new("Too many concurrent responses from this client"))?;
    Ok((global, peer_permit, None))
}

fn wrap_streaming_response(
    state: &AdmissionRouteState,
    response: Response,
    permits: ResponseBodyPermits,
    operation: &'static str,
    public: bool,
) -> Response {
    let (body_permit, body_peer_permit, public_body_permit) = permits;
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        Body::new(StreamAdmissionBody {
            inner: body,
            _permit: body_permit,
            _peer_permit: body_peer_permit,
            _public_permit: public_body_permit,
            deadline: Box::pin(tokio::time::sleep(std::time::Duration::from_secs(
                state.config().admission.stream_max_duration_seconds,
            ))),
            minimum_progress: MinimumProgress::new(
                state.config().admission.stream_min_bytes_per_second,
            ),
            transferred_data_bytes: 0,
            operation,
            public,
            complete: false,
        }),
    )
}

fn wrap_buffered_response(
    mut response: Response,
    permits: ResponseBodyPermits,
    head_request: bool,
) -> Response {
    if !head_request {
        response.headers_mut().remove(header::CONTENT_LENGTH);
    }
    let (body_permit, body_peer_permit, _) = permits;
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        Body::new(BufferedAdmissionBody {
            inner: body,
            _permit: body_permit,
            _peer_permit: body_peer_permit,
            pending: None,
            complete: false,
            deadline: Box::pin(tokio::time::sleep(BUFFERED_RESPONSE_MAX_LIFETIME)),
        }),
    )
}

pub(super) async fn response_admission(
    State(state): State<AdmissionRouteState>,
    request: Request,
    next: Next,
) -> Response {
    let permit = match state.try_acquire_response() {
        Ok(permit) => permit,
        Err(_) => return admission_rejected("Too many concurrent requests"),
    };
    let path = request.uri().path();
    let streaming = streaming_response_path(path);
    let public_streaming = public_streaming_response_path(path);
    let stream_operation = streaming_operation(path);
    let head_request = request.method() == Method::HEAD;
    let peer = request_peer(&request);
    let body_permits = if streaming {
        try_stream_permits(&state, peer, public_streaming)
    } else {
        try_buffered_permits(&state, peer)
    };
    let body_permits = match body_permits {
        Ok(permits) => permits,
        Err(rejection) => return rejection.into_response(),
    };

    let response = next.run(request).await;
    drop(permit);
    if streaming {
        wrap_streaming_response(
            &state,
            response,
            body_permits,
            stream_operation,
            public_streaming,
        )
    } else {
        wrap_buffered_response(response, body_permits, head_request)
    }
}

pub(super) fn streaming_response_path(path: &str) -> bool {
    path == "/admin/preview/raw"
        || path.ends_with("/download")
        || path.ends_with("/download.zip")
        || path.ends_with("/preview/raw")
        || (path.ends_with("/preview")
            && (path.starts_with("/v/") || path.starts_with("/api/v2/public/shares/")))
}

pub(super) fn public_streaming_response_path(path: &str) -> bool {
    streaming_response_path(path)
        && (path.starts_with("/v/") || path.starts_with("/api/v2/public/shares/"))
}

fn streaming_operation(path: &str) -> &'static str {
    if path.ends_with("/download.zip") {
        "zip_download"
    } else if path.ends_with("/download") {
        "download"
    } else if path.ends_with("/preview/raw") || path.ends_with("/preview") {
        "preview"
    } else {
        "raw_preview"
    }
}

pub(super) fn upload_request_path(path: &str) -> bool {
    path.ends_with("/upload") || path.ends_with("/upload/queue")
}

pub(super) fn upload_request_body_deadline(
    admission: &crate::config::Admission,
    content_length: Option<u64>,
) -> std::time::Duration {
    let configured = admission.upload_max_duration_seconds;
    let seconds = content_length.map_or(configured, |length| {
        let rate_seconds = length / admission.upload_min_bytes_per_second
            + u64::from(length % admission.upload_min_bytes_per_second != 0);
        configured.min((5 * 60_u64).saturating_add(rate_seconds).max(15 * 60))
    });
    std::time::Duration::from_secs(seconds)
}

pub(super) async fn absolute_request_body_deadline(
    State(state): State<AdmissionRouteState>,
    request: Request,
    next: Next,
) -> Response {
    let upload = upload_request_path(request.uri().path());
    let duration = if upload {
        let content_length = request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        upload_request_body_deadline(&state.config().admission, content_length)
    } else {
        DEFAULT_REQUEST_BODY_DEADLINE
    };
    let (parts, body) = request.into_parts();
    let body = Body::new(AbsoluteDeadlineBody {
        inner: body,
        deadline: Box::pin(tokio::time::sleep(duration)),
        minimum_progress: upload
            .then(|| MinimumProgress::new(state.config().admission.upload_min_bytes_per_second)),
        timed_out: false,
    });
    next.run(Request::from_parts(parts, body)).await
}

pub(super) async fn locale_context(req: Request, next: Next) -> Response {
    let locale = Locale::resolve(req.headers());
    let return_to = locale_return_to(req.method(), req.uri());
    i18n::scope(locale, return_to, async move {
        let mut response = next.run(req).await;
        let is_localized_content = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.starts_with("text/html") || value.starts_with("application/javascript")
            });
        if is_localized_content {
            response.headers_mut().insert(
                header::CONTENT_LANGUAGE,
                HeaderValue::from_static(locale.code()),
            );
        }
        response
    })
    .await
}

pub(super) fn locale_return_to(method: &Method, uri: &Uri) -> String {
    let current = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    if matches!(*method, Method::GET | Method::HEAD) {
        return current.to_string();
    }

    match uri.path() {
        "/login"
        | "/mfa"
        | "/admin/shares"
        | "/admin/admins"
        | "/admin/service-tokens"
        | "/admin/settings"
        | "/admin/settings/audit-ips/delete" => current.to_string(),
        "/admin/files/delete" => "/admin".to_string(),
        "/logout" => "/login".to_string(),
        path if path.starts_with("/admin/account/") => "/admin/account".to_string(),
        path if path.starts_with("/admin/files/") => "/admin".to_string(),
        path if path.starts_with("/admin/shares/") => "/admin/shares".to_string(),
        path if path.starts_with("/admin/admins/") => "/admin/admins".to_string(),
        path if path.starts_with("/admin/service-tokens/") => "/admin/service-tokens".to_string(),
        path if path.starts_with("/v/") => {
            let token = path
                .strip_prefix("/v/")
                .and_then(|value| value.split('/').next())
                .filter(|value| !value.is_empty());
            token
                .map(|token| format!("/v/{token}"))
                .unwrap_or_else(|| "/".to_string())
        }
        _ => "/".to_string(),
    }
}

pub(super) async fn audit_client_ip_context(
    State(state): State<AdmissionRouteState>,
    mut req: Request,
    next: Next,
) -> Response {
    let client_ip = match req.extensions().get::<ConnectInfo<SocketAddr>>() {
        Some(ConnectInfo(peer)) => {
            match proxy::validated_effective_client_ip(peer.ip(), req.headers(), state.config()) {
                Ok(client_ip) => Some(client_ip),
                Err(_) => return StatusCode::BAD_REQUEST.into_response(),
            }
        }
        None => None,
    };
    req.extensions_mut().insert(ValidatedClientIp(client_ip));
    with_audit_client_ip(client_ip, next.run(req)).await
}

pub(super) async fn security_headers(
    State(state): State<AdmissionRouteState>,
    req: Request,
    next: Next,
) -> Response {
    let asset_response = req.uri().path().starts_with("/assets/");
    let mut response = next.run(req).await;
    let h = response.headers_mut();
    h.insert("content-security-policy",HeaderValue::from_static("default-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    if state.config().tls.hsts_enabled {
        h.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    if !asset_response || !h.contains_key("cache-control") {
        h.insert("cache-control", HeaderValue::from_static("no-store"));
    }
    response
}

pub(crate) async fn guard_multipart_upload(request: Request, next: Next) -> Response {
    match crate::multipart_guard::guard_multipart_request(request) {
        Ok(request) => next.run(request).await,
        Err(error) => AppError(error.status_code(), "Invalid multipart upload").into_response(),
    }
}
