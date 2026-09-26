const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_ACTIVE_CONNECTIONS: usize = 256;
const MAX_ACTIVE_CONNECTIONS_PER_PEER: usize = 32;
const MAX_PENDING_MTLS_HANDSHAKES: usize = 96;
const CONNECTION_ACCEPT_TIMEOUT: Duration = Duration::from_secs(15);
const RESPONSE_WRITE_IDLE_TIMEOUT: Duration = vaultlink::transport::RESPONSE_WRITE_IDLE_TIMEOUT;
const MAX_CONNECTION_LIFETIME: Duration = vaultlink::transport::MAX_CONNECTION_LIFETIME;
const MAX_BLOCKING_THREADS: usize = 64;
const SERVER_DRAIN_TIMEOUT: Duration = Duration::from_secs(25);
const CLEANUP_JOIN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct ConnectionLimitAcceptor<A> {
    inner: A,
    permits: Arc<Semaphore>,
    peer_connections: Arc<Mutex<HashMap<IpAddr, usize>>>,
    trusted_proxy_peers: Option<Arc<HashSet<IpAddr>>>,
    max_connections_per_peer: usize,
    accept_timeout: Duration,
}

impl<A> ConnectionLimitAcceptor<A> {
    fn new(inner: A, trusted_proxy_peers: Option<Arc<HashSet<IpAddr>>>) -> Self {
        Self {
            inner,
            permits: Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS)),
            peer_connections: Arc::new(Mutex::new(HashMap::new())),
            trusted_proxy_peers,
            max_connections_per_peer: MAX_ACTIVE_CONNECTIONS_PER_PEER,
            accept_timeout: CONNECTION_ACCEPT_TIMEOUT,
        }
    }

    fn new_mtls(inner: A) -> Self {
        let mut acceptor = Self::new(inner, None);
        // A separate pre-handshake semaphore limits unauthenticated work.
        // Connections that have completed mTLS may share a proxy's TCP IP.
        acceptor.max_connections_per_peer = MAX_ACTIVE_CONNECTIONS;
        acceptor
    }
}

#[derive(Clone)]
struct VerifiedProxyService<S> {
    inner: S,
    peer: vaultlink::proxy::VerifiedProxyPeer,
}

impl<S> tower::Service<http::Request<hyper::body::Incoming>> for VerifiedProxyService<S>
where
    S: tower::Service<http::Request<hyper::body::Incoming>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: http::Request<hyper::body::Incoming>) -> Self::Future {
        request.extensions_mut().insert(self.peer);
        self.inner.call(request)
    }
}

#[derive(Clone)]
struct MtlsProxyAcceptor<A> {
    inner: A,
    pending_handshakes: Arc<Semaphore>,
}

impl<A> MtlsProxyAcceptor<A> {
    fn new(inner: A) -> Self {
        // Bound unauthenticated handshakes below the authenticated connection
        // budget while allowing the documented 50/20/5 parallel load profile.
        Self {
            inner,
            pending_handshakes: Arc::new(Semaphore::new(MAX_PENDING_MTLS_HANDSHAKES)),
        }
    }
}

impl<A, S> Accept<tokio::net::TcpStream, S> for MtlsProxyAcceptor<A>
where
    A: Accept<tokio::net::TcpStream, S>,
    A::Future: Send + 'static,
    A::Stream: Send + 'static,
    A::Service: Send + 'static,
{
    type Stream = A::Stream;
    type Service = VerifiedProxyService<A::Service>;
    type Future =
        Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send + 'static>>;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        let permit = match self.pending_handshakes.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return Box::pin(async {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "mTLS handshake budget exhausted",
                    ))
                })
            }
        };
        let future = self.inner.accept(stream, service);
        Box::pin(async move {
            let (stream, service) = future.await?;
            drop(permit);
            Ok((
                stream,
                VerifiedProxyService {
                    inner: service,
                    peer: vaultlink::proxy::VerifiedProxyPeer::Mtls,
                },
            ))
        })
    }
}

#[derive(Clone)]
struct UnixProxyAcceptor {
    proxy_uids: Arc<HashSet<u32>>,
    permits: Arc<Semaphore>,
    peers: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl UnixProxyAcceptor {
    fn new(proxy_uids: Vec<u32>) -> Self {
        Self {
            proxy_uids: Arc::new(proxy_uids.into_iter().collect()),
            permits: Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS)),
            peers: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<S> Accept<tokio::net::UnixStream, S> for UnixProxyAcceptor
where
    S: Send + 'static,
{
    type Stream = ConnectionLimitedIo<tokio::net::UnixStream>;
    type Service = VerifiedProxyService<S>;
    type Future =
        Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send + 'static>>;

    fn accept(&self, stream: tokio::net::UnixStream, service: S) -> Self::Future {
        let credential = match stream.peer_cred() {
            Ok(credential) if self.proxy_uids.contains(&credential.uid()) => credential,
            _ => {
                return Box::pin(async {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Unix proxy UID is not allowed",
                    ))
                })
            }
        };
        let permit = match self.permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return Box::pin(async {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "Unix proxy connection budget exhausted",
                    ))
                })
            }
        };
        // The accounting key is internal; it is never a client IP or request identity.
        let accounting_peer = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
        {
            let mut peers = connection_counts(&self.peers, MAX_ACTIVE_CONNECTIONS);
            *peers.entry(accounting_peer).or_default() += 1;
        }
        let lease = ConnectionPermit {
            _global: permit,
            peer_connections: self.peers.clone(),
            peer: accounting_peer,
            maximum: MAX_ACTIVE_CONNECTIONS,
        };
        let diagnostics = TransportDiagnostics::new(
            0,
            0,
            MAX_ACTIVE_CONNECTIONS - self.permits.available_permits(),
        );
        Box::pin(async move {
            Ok((
                ConnectionLimitedIo {
                    inner: stream,
                    diagnostics,
                    _permit: lease,
                    write_timeout: None,
                    write_idle_timeout: RESPONSE_WRITE_IDLE_TIMEOUT,
                    connection_deadline: Box::pin(tokio::time::sleep(MAX_CONNECTION_LIFETIME)),
                },
                VerifiedProxyService {
                    inner: service,
                    peer: vaultlink::proxy::VerifiedProxyPeer::Unix {
                        uid: credential.uid(),
                    },
                },
            ))
        })
    }
}

struct ConnectionPermit {
    _global: OwnedSemaphorePermit,
    peer_connections: Arc<Mutex<HashMap<IpAddr, usize>>>,
    peer: IpAddr,
    maximum: usize,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut peers = connection_counts(&self.peer_connections, self.maximum);
        if let Some(count) = peers.get_mut(&self.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                peers.remove(&self.peer);
            }
        }
    }
}

fn connection_counts(
    counts: &Mutex<HashMap<IpAddr, usize>>,
    maximum: usize,
) -> std::sync::MutexGuard<'_, HashMap<IpAddr, usize>> {
    match counts.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            tracing::error!("recovering poisoned connection limiter mutex");
            let mut guard = poisoned.into_inner();
            guard.retain(|_, count| {
                *count = (*count).min(maximum);
                *count > 0
            });
            counts.clear_poison();
            guard
        }
    }
}

type ConnectionLimitedIo<I> =
    vaultlink::transport::ConnectionLimitedIo<I, ConnectionPermit, TransportDiagnostics>;

impl<S, A> Accept<tokio::net::TcpStream, S> for ConnectionLimitAcceptor<A>
where
    A: Accept<tokio::net::TcpStream, S>,
    A::Future: Send + 'static,
    A::Stream: Send + 'static,
    A::Service: Send + 'static,
{
    type Stream = ConnectionLimitedIo<A::Stream>;
    type Service = A::Service;
    type Future =
        Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send + 'static>>;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        let peer_address = match stream.peer_addr() {
            Ok(address) => address,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        let raw_peer = peer_address.ip();
        let mut diagnostics = TransportDiagnostics::new(
            peer_address.port(),
            stream.local_addr().map_or(0, |address| address.port()),
            MAX_ACTIVE_CONNECTIONS.saturating_sub(self.permits.available_permits()),
        );
        let canonical_peer = vaultlink::proxy::canonical_peer_ip(raw_peer);
        if self
            .trusted_proxy_peers
            .as_ref()
            .is_some_and(|trusted| !trusted.contains(&canonical_peer))
        {
            diagnostics.failure("untrusted_proxy_peer");
            return Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "TCP peer is not in reverse_proxy.trusted_proxies",
                ))
            });
        }
        let peer = vaultlink::proxy::client_limit_key(raw_peer);
        let max_connections_per_peer = peer_connection_limit(
            raw_peer,
            self.trusted_proxy_peers.as_deref(),
            self.max_connections_per_peer,
        );
        let permit = match self.permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                diagnostics.failure("global_connection_limit");
                return Box::pin(async {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "global HTTP connection limit reached",
                    ))
                });
            }
        };
        {
            let mut peers = connection_counts(&self.peer_connections, max_connections_per_peer);
            let count = peers.entry(peer).or_default();
            if *count >= max_connections_per_peer {
                diagnostics.failure("peer_connection_limit");
                return Box::pin(async {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "per-peer HTTP connection limit reached",
                    ))
                });
            }
            *count += 1;
        }
        let connection_permit = ConnectionPermit {
            _global: permit,
            peer_connections: self.peer_connections.clone(),
            peer,
            maximum: max_connections_per_peer,
        };
        let future = self.inner.accept(stream, service);
        let accept_timeout = self.accept_timeout;
        Box::pin(async move {
            // `inner.accept` includes the TLS/ACME handshake. HTTP header/body
            // deadlines only begin afterwards, so bound this phase separately.
            let (inner, service) = match tokio::time::timeout(accept_timeout, future).await {
                Ok(Ok(accepted)) => accepted,
                Ok(Err(error)) => {
                    diagnostics.failure("accept_error");
                    diagnostics.io_error(&error);
                    return Err(error);
                }
                Err(_) => {
                    diagnostics.failure("accept_timeout");
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "connection accept or TLS handshake timed out",
                    ));
                }
            };
            Ok((
                ConnectionLimitedIo {
                    inner,
                    diagnostics,
                    _permit: connection_permit,
                    write_timeout: None,
                    write_idle_timeout: RESPONSE_WRITE_IDLE_TIMEOUT,
                    connection_deadline: Box::pin(tokio::time::sleep(MAX_CONNECTION_LIFETIME)),
                },
                service,
            ))
        })
    }
}

fn peer_connection_limit(
    raw_peer: IpAddr,
    trusted_proxy_peers: Option<&HashSet<IpAddr>>,
    untrusted_limit: usize,
) -> usize {
    if trusted_proxy_peers
        .is_some_and(|trusted| trusted.contains(&vaultlink::proxy::canonical_peer_ip(raw_peer)))
    {
        // All connections from a trusted reverse proxy commonly arrive from one
        // raw socket peer. Give only that explicitly configured peer the global
        // budget; direct clients keep the smaller per-peer abuse boundary.
        MAX_ACTIVE_CONNECTIONS
    } else {
        untrusted_limit
    }
}

fn harden_http_server<Addr: axum_server::Address, Acceptor>(
    server: &mut axum_server::Server<Addr, Acceptor>,
) {
    server
        .http_builder()
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Some(HTTP_HEADER_READ_TIMEOUT))
        .max_headers(64)
        .max_buf_size(64 * 1024);
}

#[cfg(test)]
mod proxy_acceptor_tests {
    use super::*;

    #[tokio::test]
    async fn unix_acceptor_uses_kernel_peer_uid() {
        let (allowed_stream, _peer) = tokio::net::UnixStream::pair().unwrap();
        let uid = allowed_stream.peer_cred().unwrap().uid();
        let (_, verified) = UnixProxyAcceptor::new(vec![uid])
            .accept(allowed_stream, ())
            .await
            .unwrap();
        assert_eq!(
            verified.peer,
            vaultlink::proxy::VerifiedProxyPeer::Unix { uid }
        );

        let (rejected_stream, _peer) = tokio::net::UnixStream::pair().unwrap();
        let foreign_uid = if uid == 0 { 1 } else { 0 };
        let result = UnixProxyAcceptor::new(vec![foreign_uid])
            .accept(rejected_stream, ())
            .await;
        assert!(
            matches!(result, Err(ref error) if error.kind() == io::ErrorKind::PermissionDenied)
        );
    }
}
