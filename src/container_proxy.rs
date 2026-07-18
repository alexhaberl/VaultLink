//! HTTP-aware loopback proxy used by the container setup entrypoint.

use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    fs::File,
    io::{self, Read},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use axum::body::Body;
use http::{header, HeaderMap, HeaderValue, Request, Response, StatusCode, Uri};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustix::fs::{Mode, OFlags};
use serde::Deserialize;
use tokio::net::{TcpListener, TcpStream};

use crate::{config::ServerMode, proxy};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_ACTIVE_CONNECTIONS: usize = 256;
const MAX_ACTIVE_CONNECTIONS_PER_PEER: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerProxyOptions {
    pub listen: SocketAddr,
    pub setup_upstream: SocketAddr,
    pub config_path: PathBuf,
}

impl ContainerProxyOptions {
    pub fn parse(args: &[String]) -> Result<Self, String> {
        if args.get(1).map(String::as_str) != Some("container-proxy") {
            return Err("container-proxy parser requires the container-proxy command".into());
        }
        let mut listen = None;
        let mut setup_upstream = None;
        let mut config_path = None;
        let mut index = 2;
        while index < args.len() {
            let option = args[index].as_str();
            if !matches!(option, "--listen" | "--setup-upstream" | "--config") {
                return Err(if option.starts_with('-') {
                    format!("unknown container-proxy option: {option}")
                } else {
                    format!("unexpected container-proxy positional argument: {option}")
                });
            }
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("{option} requires one non-option value"))?;
            if value.is_empty() || value.starts_with('-') {
                return Err(format!("{option} requires one non-option value"));
            }
            let duplicate = match option {
                "--listen" => listen
                    .replace(value.parse::<SocketAddr>().map_err(|_| {
                        "--listen requires a valid numeric socket address".to_string()
                    })?)
                    .is_some(),
                "--setup-upstream" => setup_upstream
                    .replace(value.parse::<SocketAddr>().map_err(|_| {
                        "--setup-upstream requires a valid numeric socket address".to_string()
                    })?)
                    .is_some(),
                "--config" => config_path.replace(PathBuf::from(value)).is_some(),
                _ => unreachable!(),
            };
            if duplicate {
                return Err(format!("{option} may only be provided once"));
            }
            index += 2;
        }
        let listen = listen.ok_or_else(|| "container-proxy requires --listen".to_string())?;
        let setup_upstream = setup_upstream
            .ok_or_else(|| "container-proxy requires --setup-upstream".to_string())?;
        if !setup_upstream.ip().is_loopback() {
            return Err("--setup-upstream must use a loopback address".into());
        }
        let config_path =
            config_path.ok_or_else(|| "container-proxy requires --config".to_string())?;
        Ok(Self {
            listen,
            setup_upstream,
            config_path,
        })
    }
}

#[derive(Clone, Debug, Default)]
struct ProxyPolicy {
    configured_upstream: Option<SocketAddr>,
    trusted_proxies: HashSet<IpAddr>,
    trust_forwarded_headers: bool,
}

impl ProxyPolicy {
    fn trusts(&self, peer: IpAddr) -> bool {
        self.trust_forwarded_headers
            && self
                .trusted_proxies
                .contains(&proxy::canonical_peer_ip(peer))
    }
}

#[derive(Deserialize)]
struct ProxyFileConfig {
    server: ProxyServerConfig,
    #[serde(default)]
    reverse_proxy: ProxyTrustConfig,
}

#[derive(Deserialize)]
struct ProxyServerConfig {
    mode: ServerMode,
    listen_address: String,
}

#[derive(Default, Deserialize)]
struct ProxyTrustConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    trusted_proxies: Vec<IpAddr>,
    #[serde(default)]
    trust_x_forwarded_headers: bool,
}

fn read_proxy_policy(path: &Path) -> ProxyPolicy {
    try_read_proxy_policy(path).unwrap_or_default()
}

fn try_read_proxy_policy(path: &Path) -> Result<ProxyPolicy, Box<dyn std::error::Error>> {
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(errno_error)?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid proxy config file").into());
    }
    let mut serialized = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut serialized)?;
    if serialized.len() as u64 > MAX_CONFIG_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "proxy config is too large").into());
    }
    let config: ProxyFileConfig = toml::from_str(&serialized)?;
    let upstream = config.server.listen_address.parse::<SocketAddr>()?;
    if !upstream.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "container proxy upstream must use loopback",
        )
        .into());
    }
    let trust_forwarded_headers = config.server.mode == ServerMode::ReverseProxy
        && config.reverse_proxy.enabled
        && config.reverse_proxy.trust_x_forwarded_headers;
    let trusted_proxies = if trust_forwarded_headers {
        config
            .reverse_proxy
            .trusted_proxies
            .into_iter()
            .map(proxy::canonical_peer_ip)
            .collect()
    } else {
        HashSet::new()
    };
    Ok(ProxyPolicy {
        configured_upstream: Some(upstream),
        trusted_proxies,
        trust_forwarded_headers,
    })
}

fn errno_error(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[derive(Default)]
struct AdmissionState {
    active: usize,
    peers: HashMap<IpAddr, usize>,
}

struct ConnectionAdmission {
    maximum: usize,
    maximum_per_peer: usize,
    state: Mutex<AdmissionState>,
}

impl ConnectionAdmission {
    fn new(maximum: usize, maximum_per_peer: usize) -> Arc<Self> {
        Arc::new(Self {
            maximum,
            maximum_per_peer,
            state: Mutex::new(AdmissionState::default()),
        })
    }

    fn state(&self) -> MutexGuard<'_, AdmissionState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                tracing::error!("recovering poisoned container proxy admission mutex");
                let state = poisoned.into_inner();
                self.state.clear_poison();
                state
            }
        }
    }

    fn at_capacity(&self) -> bool {
        self.state().active >= self.maximum
    }

    fn try_acquire(self: &Arc<Self>, peer: IpAddr, trusted: bool) -> Option<ConnectionLease> {
        let peer = proxy::client_limit_key(peer);
        let peer_limit = if trusted {
            self.maximum
        } else {
            self.maximum_per_peer
        };
        let mut state = self.state();
        let peer_count = state.peers.get(&peer).copied().unwrap_or_default();
        if state.active >= self.maximum || peer_count >= peer_limit {
            return None;
        }
        state.active += 1;
        state.peers.insert(peer, peer_count + 1);
        drop(state);
        Some(ConnectionLease {
            admission: self.clone(),
            peer,
        })
    }
}

struct ConnectionLease {
    admission: Arc<ConnectionAdmission>,
    peer: IpAddr,
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        let mut state = self.admission.state();
        state.active = state.active.saturating_sub(1);
        if let Some(count) = state.peers.get_mut(&self.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.peers.remove(&self.peer);
            }
        }
    }
}

pub async fn run(options: ContainerProxyOptions) -> io::Result<()> {
    let listener = TcpListener::bind(options.listen).await?;
    let admission =
        ConnectionAdmission::new(MAX_ACTIVE_CONNECTIONS, MAX_ACTIVE_CONNECTIONS_PER_PEER);
    loop {
        let (stream, address) = listener.accept().await?;
        if admission.at_capacity() {
            drop(stream);
            continue;
        }
        let peer = proxy::canonical_peer_ip(address.ip());
        let policy = read_proxy_policy(&options.config_path);
        let Some(lease) = admission.try_acquire(peer, policy.trusts(peer)) else {
            drop(stream);
            continue;
        };
        tokio::spawn(serve_connection(
            stream,
            peer,
            options.setup_upstream,
            policy,
            lease,
            HTTP_HEADER_READ_TIMEOUT,
        ));
    }
}

async fn serve_connection(
    stream: TcpStream,
    peer: IpAddr,
    setup_upstream: SocketAddr,
    policy: ProxyPolicy,
    _lease: ConnectionLease,
    header_timeout: Duration,
) {
    let service =
        service_fn(move |request| forward_request(request, peer, setup_upstream, policy.clone()));
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(header_timeout)
        .max_headers(64)
        .max_buf_size(64 * 1024);
    if let Err(error) = builder
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        tracing::debug!(%peer, %error, "container proxy connection closed");
    }
}

async fn forward_request(
    mut request: Request<Incoming>,
    peer: IpAddr,
    setup_upstream: SocketAddr,
    policy: ProxyPolicy,
) -> Result<Response<Body>, Infallible> {
    if sanitize_forwarding_headers(request.headers_mut(), peer, policy.trusts(peer)).is_err() {
        return Ok(empty_response(StatusCode::BAD_REQUEST));
    }
    let path = request
        .uri()
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/")
        .parse::<Uri>()
        .expect("an HTTP path-and-query is a valid origin-form URI");
    *request.uri_mut() = path;
    request
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));

    let Some(upstream) = connect_upstream(setup_upstream, &policy).await else {
        return Ok(empty_response(StatusCode::BAD_GATEWAY));
    };
    let io = TokioIo::new(upstream);
    let Ok((mut sender, connection)) = hyper::client::conn::http1::handshake::<_, Body>(io).await
    else {
        return Ok(empty_response(StatusCode::BAD_GATEWAY));
    };
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "container proxy upstream connection closed");
        }
    });
    let request = request.map(Body::new);
    match sender.send_request(request).await {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            let mut response = Response::from_parts(parts, Body::new(body));
            response
                .headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("close"));
            Ok(response)
        }
        Err(_) => Ok(empty_response(StatusCode::BAD_GATEWAY)),
    }
}

async fn connect_upstream(setup_upstream: SocketAddr, policy: &ProxyPolicy) -> Option<TcpStream> {
    let mut candidates = vec![setup_upstream];
    if let Some(configured) = policy.configured_upstream {
        if configured != setup_upstream {
            candidates.push(configured);
        }
    }
    for candidate in candidates {
        if let Ok(Ok(stream)) =
            tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(candidate)).await
        {
            return Some(stream);
        }
    }
    None
}

fn sanitize_forwarding_headers(
    headers: &mut HeaderMap,
    peer: IpAddr,
    trusted: bool,
) -> Result<(), ()> {
    let mut forwarded = Vec::new();
    if trusted {
        for value in headers.get_all("x-forwarded-for") {
            let value = value.to_str().map_err(|_| ())?;
            for candidate in value.split(',') {
                let candidate = candidate.trim();
                if candidate.is_empty() {
                    return Err(());
                }
                let address = candidate.parse::<IpAddr>().map_err(|_| ())?;
                forwarded.push(proxy::canonical_peer_ip(address).to_string());
            }
        }
    }
    forwarded.push(proxy::canonical_peer_ip(peer).to_string());
    headers.remove("forwarded");
    headers.remove("x-forwarded-for");
    headers.remove(header::CONNECTION);
    let value = HeaderValue::from_str(&forwarded.join(", ")).map_err(|_| ())?;
    headers.insert("x-forwarded-for", value);
    Ok(())
}

fn empty_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONNECTION, "close")
        .body(Body::empty())
        .expect("static proxy response is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};
    use std::sync::Mutex;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn container_proxy_parser_requires_exact_numeric_options() {
        let parsed = ContainerProxyOptions::parse(&arguments(&[
            "vaultlink",
            "container-proxy",
            "--listen",
            "0.0.0.0:8081",
            "--setup-upstream",
            "127.0.0.1:8080",
            "--config",
            "/state/config.toml",
        ]))
        .unwrap();
        assert_eq!(parsed.listen, "0.0.0.0:8081".parse().unwrap());
        assert_eq!(parsed.setup_upstream, "127.0.0.1:8080".parse().unwrap());
        assert!(ContainerProxyOptions::parse(&arguments(&[
            "vaultlink",
            "container-proxy",
            "--listen",
            "0.0.0.0:8081",
            "--setup-upstream",
            "192.0.2.1:8080",
            "--config",
            "/state/config.toml",
        ]))
        .is_err());
    }

    #[test]
    fn policy_is_direct_by_default_and_reuses_the_runtime_allowlist() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("config.toml");
        assert!(!read_proxy_policy(&path).trust_forwarded_headers);
        std::fs::write(
            &path,
            r#"
[server]
mode = "reverse_proxy"
listen_address = "127.0.0.1:8080"

[reverse_proxy]
enabled = true
trusted_proxies = ["127.0.0.1", "::ffff:192.0.2.10"]
trust_x_forwarded_headers = true
"#,
        )
        .unwrap();
        let policy = read_proxy_policy(&path);
        assert_eq!(
            policy.configured_upstream,
            Some("127.0.0.1:8080".parse().unwrap())
        );
        assert!(policy.trusts("127.0.0.1".parse().unwrap()));
        assert!(policy.trusts("192.0.2.10".parse().unwrap()));
        assert!(!policy.trusts("192.0.2.11".parse().unwrap()));

        std::fs::write(&path, "[server]\nmode = 'not-a-mode'\n").unwrap();
        let invalid = read_proxy_policy(&path);
        assert!(invalid.configured_upstream.is_none());
        assert!(invalid.trusted_proxies.is_empty());
        assert!(!invalid.trust_forwarded_headers);
    }

    #[test]
    fn direct_and_trusted_forwarding_headers_follow_the_same_ip_rules() {
        let peer = "192.0.2.10".parse().unwrap();
        let mut direct = HeaderMap::new();
        direct.append("x-forwarded-for", "malformed".parse().unwrap());
        direct.append("X-Forwarded-For", "203.0.113.9".parse().unwrap());
        direct.append("forwarded", "for=203.0.113.1".parse().unwrap());
        direct.insert(header::CONNECTION, "keep-alive".parse().unwrap());
        sanitize_forwarding_headers(&mut direct, peer, false).unwrap();
        assert_eq!(direct["x-forwarded-for"], "192.0.2.10");
        assert!(!direct.contains_key("forwarded"));
        assert!(!direct.contains_key(header::CONNECTION));

        let mut trusted = HeaderMap::new();
        trusted.append(
            "x-forwarded-for",
            "203.0.113.7, ::ffff:192.0.2.8".parse().unwrap(),
        );
        trusted.append("x-forwarded-for", "2001:0db8::1".parse().unwrap());
        sanitize_forwarding_headers(&mut trusted, peer, true).unwrap();
        assert_eq!(
            trusted["x-forwarded-for"],
            "203.0.113.7, 192.0.2.8, 2001:db8::1, 192.0.2.10"
        );

        let mut malformed = HeaderMap::new();
        malformed.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
        assert!(sanitize_forwarding_headers(&mut malformed, peer, true).is_err());
    }

    #[test]
    fn admission_matches_global_peer_and_ipv6_budgets() {
        let admission = ConnectionAdmission::new(2, 1);
        let first = admission
            .try_acquire("198.51.100.1".parse().unwrap(), false)
            .unwrap();
        assert!(admission
            .try_acquire("198.51.100.1".parse().unwrap(), false)
            .is_none());
        let second = admission
            .try_acquire("198.51.100.2".parse().unwrap(), false)
            .unwrap();
        assert!(admission
            .try_acquire("198.51.100.3".parse().unwrap(), false)
            .is_none());
        drop(first);
        assert!(admission
            .try_acquire("198.51.100.1".parse().unwrap(), false)
            .is_some());
        drop(second);

        let trusted = ConnectionAdmission::new(2, 1);
        let _one = trusted
            .try_acquire("192.0.2.10".parse().unwrap(), true)
            .unwrap();
        let _two = trusted
            .try_acquire("192.0.2.10".parse().unwrap(), true)
            .unwrap();
        assert!(trusted
            .try_acquire("192.0.2.10".parse().unwrap(), true)
            .is_none());

        let ipv6 = ConnectionAdmission::new(2, 1);
        let _v6 = ipv6
            .try_acquire("2001:db8:1:2::1".parse().unwrap(), false)
            .unwrap();
        assert!(ipv6
            .try_acquire("2001:db8:1:2::ffff".parse().unwrap(), false)
            .is_none());
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn body_is_streamed_and_pipelined_second_request_is_not_dispatched() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_upstream = seen.clone();
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = upstream.accept().await.unwrap();
            let service = service_fn(move |request: Request<Incoming>| {
                let seen = seen_by_upstream.clone();
                async move {
                    let path = request.uri().path().to_string();
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    seen.lock().unwrap().push((path, body.to_vec()));
                    Ok::<_, Infallible>(Response::new(Full::new(axum::body::Bytes::new())))
                }
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });

        let (mut client, proxy_stream) = tcp_pair().await;
        let admission = ConnectionAdmission::new(1, 1);
        let lease = admission
            .try_acquire("198.51.100.42".parse().unwrap(), false)
            .unwrap();
        let proxy_task = tokio::spawn(serve_connection(
            proxy_stream,
            "198.51.100.42".parse().unwrap(),
            upstream_address,
            ProxyPolicy::default(),
            lease,
            Duration::from_secs(1),
        ));
        client
            .write_all(
                b"POST /first HTTP/1.1\r\nHost: vaultlink\r\nContent-Length: 4\r\n\r\nbody\
GET /second HTTP/1.1\r\nHost: vaultlink\r\nX-Forwarded-For: 203.0.113.77\r\n\r\n",
            )
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        proxy_task.await.unwrap();
        upstream_task.await.unwrap();

        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            &[("/first".into(), b"body".to_vec())]
        );
        assert!(admission
            .try_acquire("198.51.100.42".parse().unwrap(), false)
            .is_some());
    }

    #[tokio::test]
    async fn absolute_header_timeout_releases_admission() {
        let (_client, proxy_stream) = tcp_pair().await;
        let admission = ConnectionAdmission::new(1, 1);
        let lease = admission
            .try_acquire("198.51.100.42".parse().unwrap(), false)
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            serve_connection(
                proxy_stream,
                "198.51.100.42".parse().unwrap(),
                "127.0.0.1:1".parse().unwrap(),
                ProxyPolicy::default(),
                lease,
                Duration::from_millis(20),
            ),
        )
        .await
        .unwrap();
        assert!(admission
            .try_acquire("198.51.100.42".parse().unwrap(), false)
            .is_some());
    }

    #[tokio::test]
    async fn oversized_header_is_rejected_and_releases_admission() {
        let (mut client, proxy_stream) = tcp_pair().await;
        let admission = ConnectionAdmission::new(1, 1);
        let lease = admission
            .try_acquire("198.51.100.42".parse().unwrap(), false)
            .unwrap();
        let proxy_task = tokio::spawn(serve_connection(
            proxy_stream,
            "198.51.100.42".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicy::default(),
            lease,
            Duration::from_secs(1),
        ));
        let mut request = b"GET / HTTP/1.1\r\nHost: vaultlink\r\nX-Oversized: ".to_vec();
        request.extend(std::iter::repeat_n(b'a', 65 * 1024));
        request.extend_from_slice(b"\r\n\r\n");
        client.write_all(&request).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        proxy_task.await.unwrap();

        assert!(!response.starts_with(b"HTTP/1.1 200"));
        assert!(admission
            .try_acquire("198.51.100.42".parse().unwrap(), false)
            .is_some());
    }
}
