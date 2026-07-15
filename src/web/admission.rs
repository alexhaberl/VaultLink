use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

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
    DEFAULT_REQUEST_BODY_DEADLINE, UPLOAD_REQUEST_BODY_DEADLINE,
};
use crate::{
    http_auth::{try_acquire_client_activity, with_audit_client_ip, ClientActivityPermit},
    i18n::{self, Locale},
    proxy, AppState,
};

pub(super) struct AbsoluteDeadlineBody {
    pub(super) inner: Body,
    pub(super) deadline: Pin<Box<tokio::time::Sleep>>,
    pub(super) timed_out: bool,
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
        Pin::new(&mut this.inner).poll_frame(cx)
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

pub(super) struct PeerPermitBody {
    pub(super) inner: Body,
    pub(super) _permit: ClientActivityPermit,
}

pub(super) struct StreamAdmissionBody {
    pub(super) inner: Body,
    pub(super) _permit: OwnedSemaphorePermit,
    pub(super) _peer_permit: ClientActivityPermit,
    pub(super) deadline: Pin<Box<tokio::time::Sleep>>,
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
            let chunk = Bytes::copy_from_slice(&pending[..length]);
            if length < pending.len() {
                this.pending = Some(pending.slice(length..));
            }
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    let length = data.len().min(BUFFERED_RESPONSE_CHUNK_BYTES);
                    let chunk = Bytes::copy_from_slice(&data[..length]);
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
            this.complete = true;
            return Poll::Ready(Some(Err(axum::Error::new(io::Error::new(
                io::ErrorKind::TimedOut,
                "stream response lifetime exceeded",
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
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.complete || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
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

impl HttpBody for PeerPermitBody {
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

pub(super) async fn response_admission(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let permit = match state.response_admission.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            let mut response = (
                StatusCode::SERVICE_UNAVAILABLE,
                "Zu viele gleichzeitige Anfragen",
            )
                .into_response();
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            return response;
        }
    };
    let streaming = streaming_response_path(request.uri().path());
    let head_request = request.method() == Method::HEAD;
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| {
            proxy::client_limit_key(proxy::effective_client_ip(
                peer.ip(),
                request.headers(),
                &state.config,
            ))
        })
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let (body_permit, body_peer_permit) = if streaming {
        let global = match state.stream_admission.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                drop(permit);
                let mut response = (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Zu viele gleichzeitige Downloads",
                )
                    .into_response();
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
                return response;
            }
        };
        let peer_permit = match try_acquire_client_activity(
            state.stream_peer_admission.clone(),
            peer,
            crate::MAX_IN_FLIGHT_STREAMS_PER_CLIENT,
        ) {
            Ok(Some(permit)) => permit,
            Ok(None) => {
                drop(global);
                drop(permit);
                let mut response = (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Zu viele gleichzeitige Downloads dieses Clients",
                )
                    .into_response();
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
                return response;
            }
            Err(_) => {
                drop(global);
                drop(permit);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Interner Fehler").into_response();
            }
        };
        (global, peer_permit)
    } else {
        let global = match state
            .buffered_response_admission
            .clone()
            .try_acquire_owned()
        {
            Ok(permit) => permit,
            Err(_) => {
                drop(permit);
                let mut response = (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Zu viele gleichzeitige Antworten",
                )
                    .into_response();
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
                return response;
            }
        };
        let peer_permit = match try_acquire_client_activity(
            state.buffered_peer_admission.clone(),
            peer,
            crate::MAX_IN_FLIGHT_BUFFERED_RESPONSES_PER_CLIENT,
        ) {
            Ok(Some(permit)) => permit,
            Ok(None) => {
                drop(global);
                drop(permit);
                let mut response = (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Zu viele gleichzeitige Antworten dieses Clients",
                )
                    .into_response();
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
                return response;
            }
            Err(_) => {
                drop(global);
                drop(permit);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Interner Fehler").into_response();
            }
        };
        (global, peer_permit)
    };
    let mut response = next.run(request).await;
    drop(permit);
    if streaming {
        let (parts, body) = response.into_parts();
        Response::from_parts(
            parts,
            Body::new(StreamAdmissionBody {
                inner: body,
                _permit: body_permit,
                _peer_permit: body_peer_permit,
                deadline: Box::pin(tokio::time::sleep(std::time::Duration::from_secs(
                    crate::db::TRANSFER_LEASE_MAX_LIFETIME_SECONDS as u64,
                ))),
                complete: false,
            }),
        )
    } else {
        if !head_request {
            response.headers_mut().remove(header::CONTENT_LENGTH);
        }
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
}

pub(super) fn streaming_response_path(path: &str) -> bool {
    path == "/admin/preview/raw"
        || path.ends_with("/download")
        || path.ends_with("/download.zip")
        || path.ends_with("/preview/raw")
        || (path.ends_with("/preview")
            && (path.starts_with("/v/") || path.starts_with("/api/v1/public/shares/")))
}

pub(super) fn upload_request_path(path: &str) -> bool {
    path.ends_with("/upload") || path.ends_with("/upload/queue")
}

pub(super) async fn absolute_request_body_deadline(request: Request, next: Next) -> Response {
    let duration = if upload_request_path(request.uri().path()) {
        UPLOAD_REQUEST_BODY_DEADLINE
    } else {
        DEFAULT_REQUEST_BODY_DEADLINE
    };
    let (parts, body) = request.into_parts();
    let body = Body::new(AbsoluteDeadlineBody {
        inner: body,
        deadline: Box::pin(tokio::time::sleep(duration)),
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
        | "/admin/settings"
        | "/admin/settings/audit-ips/delete" => current.to_string(),
        "/admin/files/delete" => "/admin".to_string(),
        "/logout" => "/login".to_string(),
        path if path.starts_with("/admin/account/") => "/admin/account".to_string(),
        path if path.starts_with("/admin/files/") => "/admin".to_string(),
        path if path.starts_with("/admin/shares/") => "/admin/shares".to_string(),
        path if path.starts_with("/admin/admins/") => "/admin/admins".to_string(),
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
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let client_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| {
            proxy::effective_client_ip(peer.ip(), req.headers(), &state.config)
        });
    with_audit_client_ip(client_ip, next.run(req)).await
}

pub(super) async fn security_headers(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
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
    if state.config.tls.hsts_enabled {
        h.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    response
}

pub(crate) async fn guard_multipart_upload(request: Request, next: Next) -> Response {
    match crate::multipart_guard::guard_multipart_request(request) {
        Ok(request) => next.run(request).await,
        Err(error) => AppError(error.status_code(), "Ungültiger Multipart-Upload").into_response(),
    }
}
