const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_ACTIVE_CONNECTIONS: usize = 256;
const MAX_ACTIVE_CONNECTIONS_PER_PEER: usize = 32;
const CONNECTION_ACCEPT_TIMEOUT: Duration = Duration::from_secs(15);
const RESPONSE_WRITE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
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

struct ConnectionLimitedIo<I> {
    inner: I,
    _permit: ConnectionPermit,
    write_timeout: Option<Pin<Box<tokio::time::Sleep>>>,
    write_idle_timeout: Duration,
    connection_deadline: Pin<Box<tokio::time::Sleep>>,
}

impl<I> ConnectionLimitedIo<I> {
    fn poll_write_deadline(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.connection_deadline.as_mut().poll(cx).is_ready() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "absolute HTTP connection lifetime exceeded",
            ));
        }
        if self
            .write_timeout
            .as_mut()
            .is_some_and(|timeout| timeout.as_mut().poll(cx).is_ready())
        {
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

impl<I: AsyncRead + Unpin> AsyncRead for ConnectionLimitedIo<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.connection_deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "absolute HTTP connection lifetime exceeded",
            )));
        }
        Pin::new(&mut this.inner).poll_read(cx, buffer)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for ConnectionLimitedIo<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Err(error) = this.poll_write_deadline(cx) {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.inner).poll_write(cx, buffer);
        let incomplete = match &result {
            Poll::Pending => true,
            Poll::Ready(Ok(written)) => *written < buffer.len(),
            Poll::Ready(Err(_)) => false,
        };
        this.track_incomplete_write(cx, incomplete);
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.poll_write_deadline(cx) {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        this.track_incomplete_write(cx, result.is_pending());
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.poll_write_deadline(cx) {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.inner).poll_shutdown(cx);
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
        if let Err(error) = this.poll_write_deadline(cx) {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, buffers);
        let requested = buffers.iter().map(|buffer| buffer.len()).sum::<usize>();
        let incomplete = match &result {
            Poll::Pending => true,
            Poll::Ready(Ok(written)) => *written < requested,
            Poll::Ready(Err(_)) => false,
        };
        this.track_incomplete_write(cx, incomplete);
        result
    }
}

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
        let raw_peer = match stream.peer_addr() {
            Ok(address) => address.ip(),
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        let canonical_peer = vaultlink::proxy::canonical_peer_ip(raw_peer);
        if self
            .trusted_proxy_peers
            .as_ref()
            .is_some_and(|trusted| !trusted.contains(&canonical_peer))
        {
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
            let (inner, service) = tokio::time::timeout(accept_timeout, future)
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "connection accept or TLS handshake timed out",
                    )
                })??;
            Ok((
                ConnectionLimitedIo {
                    inner,
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
