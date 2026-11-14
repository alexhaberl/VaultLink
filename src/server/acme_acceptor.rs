use std::{future::Future, io, pin::Pin, sync::Arc};

use axum_server::accept::Accept;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

type AcmeTlsStream<I> = Compat<rustls_acme::futures_rustls::server::TlsStream<Compat<I>>>;

// rustls-acme's optional Axum adapter still implements axum-server 0.8's trait.
// Use its low-level TLS API so the HTTP server needs only axum-server 0.9.
#[derive(Clone)]
pub(super) struct AcmeHttpAcceptor {
    tls: Arc<rustls::ServerConfig>,
    validation_tls: Arc<rustls::ServerConfig>,
}

impl AcmeHttpAcceptor {
    pub(super) fn new(tls: Arc<rustls::ServerConfig>) -> Self {
        let mut validation_tls = (*tls).clone();
        validation_tls.alpn_protocols = vec![rustls_acme::acme::ACME_TLS_ALPN_NAME.to_vec()];
        Self {
            tls,
            validation_tls: Arc::new(validation_tls),
        }
    }
}

impl<I, S> Accept<I, S> for AcmeHttpAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = AcmeTlsStream<I>;
    type Service = S;
    type Future =
        Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send + 'static>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let handshake = rustls_acme::futures_rustls::LazyConfigAcceptor::new(
            rustls::server::Acceptor::default(),
            stream.compat(),
        );
        let tls = self.tls.clone();
        let validation_tls = self.validation_tls.clone();
        Box::pin(async move {
            let handshake = handshake.await?;
            if rustls_acme::is_tls_alpn_challenge(&handshake.client_hello()) {
                handshake.into_stream(validation_tls).await?;
                // Validation ends at TLS; it must never invoke the HTTP service.
                return Err(io::Error::other("TLS-ALPN-01 validation request"));
            }
            let stream = handshake.into_stream(tls).await?;
            Ok((stream.compat(), service))
        })
    }
}

#[cfg(test)]
#[path = "tests/acme_acceptor.rs"]
mod tests;
