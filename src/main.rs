#![cfg_attr(all(not(test), not(debug_assertions)), forbid(unsafe_code))]

use futures_util::StreamExt;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    env,
    future::Future,
    io,
    net::IpAddr,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use axum_server::accept::Accept;
use hyper_util::rt::TokioTimer;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore},
};
use vaultlink::{
    auth,
    config::{self, CertificateSource, Config, ServerMode},
    db::{
        AdminRecoveryOutcome, AuditContext, AuditRetentionOutcome, Database, InitialAdminOutcome,
    },
    storage_mount, web, AppState,
};
use zeroize::Zeroizing;

const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_ACTIVE_CONNECTIONS: usize = 256;
const MAX_ACTIVE_CONNECTIONS_PER_PEER: usize = 32;
const CONNECTION_ACCEPT_TIMEOUT: Duration = Duration::from_secs(15);
const RESPONSE_WRITE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.get(1).is_some_and(|value| value == "--version") {
        if args.len() != 2 {
            return Err("--version does not accept additional arguments".into());
        }
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.get(1).is_some_and(|value| value == "container-proxy") {
        let options = vaultlink::container_proxy::ContainerProxyOptions::parse(&args)
            .map_err(std::io::Error::other)?;
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
            .init();
        return vaultlink::container_proxy::run(options)
            .await
            .map_err(Into::into);
    }
    if args.get(1).is_some_and(|value| value == "recover-admin") {
        let options = RecoverAdminOptions::parse(&args).map_err(std::io::Error::other)?;
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
            .init();
        return recover_admin(&options);
    }
    if args
        .get(1)
        .is_some_and(|value| value == "revoke-all-service-tokens")
    {
        let options = RevokeAllServiceTokensOptions::parse(&args).map_err(std::io::Error::other)?;
        let revoked = revoke_all_service_tokens(&options)?;
        println!("{revoked}");
        return Ok(());
    }
    if args.get(1).is_some_and(|value| value == "rotate-secrets") {
        let options = RotateSecretsOptions::parse(&args).map_err(std::io::Error::other)?;
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
            .init();
        return rotate_secrets(&options);
    }
    if args
        .get(1)
        .is_some_and(|value| value == "verify-backup-database")
    {
        let options = VerifyBackupDatabaseOptions::parse(&args).map_err(std::io::Error::other)?;
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
            .init();
        return verify_backup_database(&options);
    }
    if args.get(1).is_some_and(|value| value == "provision-cifs") {
        let options = vaultlink::cifs_provision::CifsProvisionOptions::parse(&args)
            .map_err(std::io::Error::other)?;
        return vaultlink::cifs_provision::run(&options).map_err(Into::into);
    }
    let mode = command_mode(&args).map_err(std::io::Error::other)?;
    let config_path = arg(&args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));
    if mode == CommandMode::Setup {
        let listen = arg(&args, "--listen").unwrap_or("127.0.0.1:8090");
        let listen: std::net::SocketAddr = listen.parse()?;
        if !vaultlink::setup::run(config_path.clone(), listen).await? {
            return Ok(());
        }
    }
    let config = Config::load(&config_path)?;
    if mode == CommandMode::ReadinessTarget {
        let target = config.local_readiness_target()?;
        println!("{}", target.url);
        println!("{}", target.connect_to.as_deref().unwrap_or("-"));
        println!("{}", u8::from(target.insecure));
        return Ok(());
    }
    let filter = tracing_subscriber::EnvFilter::try_new(&config.logging.level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    if mode == CommandMode::InitAdmin {
        return init_admin(&config, &args);
    }
    let state = AppState::new(config.clone())?;
    start_audit_retention_worker(state.db.clone());
    vaultlink::file_ops::recover_pending_file_operations(&state).await?;
    let effective_public_base_url = vaultlink::http_auth::runtime_settings(&state).public_base_url;
    let cleanup_coordinator = state.storage_cleanup.clone();
    let cleanup_worker = cleanup_coordinator.start_worker(state.secure_root.clone())?;
    let addr: std::net::SocketAddr = config.server.listen_address.parse()?;
    let trusted_proxy_peers = if config.server.mode == ServerMode::ReverseProxy {
        Some(Arc::new(
            config
                .reverse_proxy
                .trusted_proxies
                .iter()
                .copied()
                .map(vaultlink::proxy::canonical_peer_ip)
                .collect::<HashSet<_>>(),
        ))
    } else {
        None
    };
    let app = web::router(state);
    tracing::info!(%addr,mode=?config.server.mode,"VaultLink starting");
    let server_result = async {
        match config.server.mode {
            ServerMode::StandaloneTls => match config.tls.certificate_source {
                CertificateSource::Files => {
                    let tls = load_http1_rustls_config(&config.tls.cert_file, &config.tls.key_file)
                        .await?;
                    install_sighup_handler_for_files(&config, tls.clone());
                    let handle = axum_server::Handle::new();
                    install_server_shutdown(handle.clone(), cleanup_coordinator.clone());
                    // HTTP/2 can retain an already-buffered DATA frame without polling
                    // the response Body again when peer flow-control is zero. That
                    // bypasses Body deadlines and can pin ZIP/memory permits forever.
                    // HTTP/1.1 plus the socket write-idle timeout gives every response
                    // an independently enforceable progress boundary.
                    let mut server = axum_server::bind_rustls(addr, tls)
                        .map(|acceptor| {
                            ConnectionLimitAcceptor::new(acceptor, trusted_proxy_peers.clone())
                        })
                        .http1_only();
                    harden_http_server(&mut server);
                    server
                        .handle(handle)
                        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                        .await?;
                }
                CertificateSource::LetsEncrypt => {
                    install_noop_sighup_handler("ACME manages certificate renewal internally");
                    let public_url = url::Url::parse(&effective_public_base_url)?;
                    let domain = public_url
                        .host_str()
                        .ok_or("public_base_url must contain a DNS host")?
                        .to_string();
                    let cache_dir = config::letsencrypt_cache_dir(&config.storage, &config.tls)?;
                    std::fs::create_dir_all(&cache_dir)?;
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o700))?;
                    let contact = format!("mailto:{}", config.tls.letsencrypt_contact_email);
                    let mut acme_state = rustls_acme::AcmeConfig::new([domain.clone()])
                        .contact_push(contact)
                        .cache(rustls_acme::caches::DirCache::new(cache_dir))
                        .directory_lets_encrypt(!config.tls.letsencrypt_staging)
                        .state();
                    let acceptor = acme_state.axum_acceptor(acme_state.default_rustls_config());
                    tokio::spawn(async move {
                        while let Some(event) = acme_state.next().await {
                            match event {
                                Ok(event) => tracing::info!(?event, "ACME event"),
                                Err(error) => tracing::error!(?error, "ACME error"),
                            }
                        }
                    });
                    tracing::info!(
                        %domain,
                        staging = config.tls.letsencrypt_staging,
                        "Standalone TLS uses Let's Encrypt ACME tls-alpn-01"
                    );
                    let handle = axum_server::Handle::new();
                    install_server_shutdown(handle.clone(), cleanup_coordinator.clone());
                    let mut server = axum_server::bind(addr)
                        .acceptor(acceptor)
                        .map(|acceptor| {
                            ConnectionLimitAcceptor::new(acceptor, trusted_proxy_peers.clone())
                        })
                        .http1_only();
                    harden_http_server(&mut server);
                    server
                        .handle(handle)
                        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                        .await?;
                }
            },
            _ => {
                install_noop_sighup_handler("no reloadable TLS configuration in this mode");
                let handle = axum_server::Handle::new();
                install_server_shutdown(handle.clone(), cleanup_coordinator.clone());
                let mut server = axum_server::bind(addr)
                    .map(|acceptor| {
                        ConnectionLimitAcceptor::new(acceptor, trusted_proxy_peers.clone())
                    })
                    .http1_only();
                harden_http_server(&mut server);
                server
                    .handle(handle)
                    .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                    .await?;
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    cleanup_worker.shutdown().await?;
    server_result
}

fn start_audit_retention_worker(database: Database) {
    tokio::spawn(async move {
        loop {
            let worker_database = database.clone();
            match tokio::task::spawn_blocking(move || worker_database.cleanup_audit_retention())
                .await
            {
                Ok(Ok(outcome)) => log_audit_retention_outcome(outcome),
                Ok(Err(error)) => tracing::error!(%error, "audit retention cleanup failed"),
                Err(error) => tracing::error!(%error, "audit retention worker failed"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(60 * 60)).await;
        }
    });
}

fn log_audit_retention_outcome(outcome: AuditRetentionOutcome) {
    if outcome.security_deleted > 0 {
        tracing::warn!(
            routine_deleted = outcome.routine_deleted,
            security_deleted = outcome.security_deleted,
            "audit retention removed security-priority events"
        );
    } else if outcome.routine_deleted > 0 {
        tracing::info!(
            routine_deleted = outcome.routine_deleted,
            "excess routine audit events removed"
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommandMode {
    Serve,
    Setup,
    InitAdmin,
    ReadinessTarget,
}

fn command_mode(args: &[String]) -> Result<CommandMode, String> {
    match args.get(1).map(String::as_str) {
        None => Ok(CommandMode::Serve),
        Some("--config") => {
            validate_value_options(args, 1, &["--config"])?;
            Ok(CommandMode::Serve)
        }
        Some("setup") => {
            validate_value_options(args, 2, &["--config", "--listen"])?;
            Ok(CommandMode::Setup)
        }
        Some("init-admin") => {
            validate_value_options(args, 2, &["--config", "--username"])?;
            Ok(CommandMode::InitAdmin)
        }
        Some("readiness-target") => {
            validate_value_options(args, 2, &["--config"])?;
            Ok(CommandMode::ReadinessTarget)
        }
        Some(option) if option.starts_with('-') => {
            Err(format!("unknown VaultLink option: {option}"))
        }
        Some(command) => Err(format!("unknown VaultLink command: {command}")),
    }
}

fn validate_value_options(args: &[String], start: usize, allowed: &[&str]) -> Result<(), String> {
    let mut seen = Vec::new();
    let mut index = start;
    while index < args.len() {
        let option = args[index].as_str();
        if !option.starts_with('-') {
            return Err(format!("unexpected positional argument: {option}"));
        }
        if !allowed.contains(&option) {
            return Err(format!("unknown option: {option}"));
        }
        if seen.contains(&option) {
            return Err(format!("{option} may only be provided once"));
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("{option} requires one non-option value"))?;
        if value.is_empty() || value.starts_with('-') {
            return Err(format!("{option} requires one non-option value"));
        }
        seen.push(option);
        index += 2;
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RecoveryDatabaseSource {
    Config(PathBuf),
    Database(PathBuf),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecoverAdminOptions {
    source: RecoveryDatabaseSource,
    username: String,
    reset_password: bool,
    reset_mfa: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RotateSecretsOptions {
    source: RecoveryDatabaseSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RevokeAllServiceTokensOptions {
    source: RecoveryDatabaseSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifyBackupDatabaseOptions {
    database_path: PathBuf,
}

impl VerifyBackupDatabaseOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        if args.get(1).map(String::as_str) != Some("verify-backup-database") {
            return Err("verify-backup-database parser requires its command".into());
        }
        if args.len() != 4 || args.get(2).map(String::as_str) != Some("--database") {
            return Err("verify-backup-database requires exactly --database DATABASE_PATH".into());
        }
        let database_path = args[3].as_str();
        if database_path.is_empty() || database_path.starts_with('-') {
            return Err("--database requires one non-option value".into());
        }
        Ok(Self {
            database_path: PathBuf::from(database_path),
        })
    }
}

impl RotateSecretsOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        if args.get(1).map(String::as_str) != Some("rotate-secrets") {
            return Err("rotate-secrets parser requires the rotate-secrets command".into());
        }
        let mut config_path = None;
        let mut database_path = None;
        let mut index = 2;
        while index < args.len() {
            let option = args[index].as_str();
            if option != "--config" && option != "--database" {
                return Err(if option.starts_with('-') {
                    format!("unknown rotate-secrets option: {option}")
                } else {
                    format!("unexpected rotate-secrets positional argument: {option}")
                });
            }
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("{option} requires one non-option value"))?;
            if value.is_empty() || value.starts_with('-') {
                return Err(format!("{option} requires one non-option value"));
            }
            let duplicate = if option == "--config" {
                config_path.replace(PathBuf::from(value)).is_some()
            } else {
                database_path.replace(PathBuf::from(value)).is_some()
            };
            if duplicate {
                return Err(format!("{option} may only be provided once"));
            }
            index += 2;
        }
        let source = match (config_path, database_path) {
            (Some(path), None) => RecoveryDatabaseSource::Config(path),
            (None, Some(path)) => RecoveryDatabaseSource::Database(path),
            (None, None) => {
                return Err("rotate-secrets requires exactly one of --config or --database".into())
            }
            (Some(_), Some(_)) => {
                return Err("rotate-secrets accepts only one of --config or --database".into())
            }
        };
        Ok(Self { source })
    }
}

impl RevokeAllServiceTokensOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        if args.get(1).map(String::as_str) != Some("revoke-all-service-tokens") {
            return Err("revoke-all-service-tokens parser requires its command".into());
        }
        let mut config_path = None;
        let mut database_path = None;
        let mut confirmed = false;
        let mut index = 2;
        while index < args.len() {
            let option = args[index].as_str();
            match option {
                "--config" | "--database" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| format!("{option} requires one non-option value"))?;
                    if value.is_empty() || value.starts_with('-') {
                        return Err(format!("{option} requires one non-option value"));
                    }
                    let duplicate = if option == "--config" {
                        config_path.replace(PathBuf::from(value)).is_some()
                    } else {
                        database_path.replace(PathBuf::from(value)).is_some()
                    };
                    if duplicate {
                        return Err(format!("{option} may only be provided once"));
                    }
                    index += 2;
                }
                "--all" => {
                    if confirmed {
                        return Err("--all may only be provided once".into());
                    }
                    confirmed = true;
                    index += 1;
                }
                option if option.starts_with('-') => {
                    return Err(format!(
                        "unknown revoke-all-service-tokens option: {option}"
                    ));
                }
                positional => {
                    return Err(format!(
                        "unexpected revoke-all-service-tokens positional argument: {positional}"
                    ));
                }
            }
        }
        if !confirmed {
            return Err("revoke-all-service-tokens requires --all".into());
        }
        let source = match (config_path, database_path) {
            (Some(path), None) => RecoveryDatabaseSource::Config(path),
            (None, Some(path)) => RecoveryDatabaseSource::Database(path),
            (None, None) => {
                return Err(
                    "revoke-all-service-tokens requires exactly one of --config or --database"
                        .into(),
                )
            }
            (Some(_), Some(_)) => {
                return Err(
                    "revoke-all-service-tokens accepts only one of --config or --database".into(),
                )
            }
        };
        Ok(Self { source })
    }
}

impl RecoverAdminOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        if args.get(1).map(String::as_str) != Some("recover-admin") {
            return Err("recover-admin parser requires the recover-admin command".into());
        }
        let mut config_path = None;
        let mut database_path = None;
        let mut username = None;
        let mut reset_password = false;
        let mut reset_mfa = false;
        let mut index = 2;
        while index < args.len() {
            let option = args[index].as_str();
            match option {
                "--config" | "--database" | "--username" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| format!("{option} requires one non-option value"))?;
                    if value.is_empty() || value.starts_with('-') {
                        return Err(format!("{option} requires one non-option value"));
                    }
                    let duplicate = match option {
                        "--config" => config_path.replace(PathBuf::from(value)).is_some(),
                        "--database" => database_path.replace(PathBuf::from(value)).is_some(),
                        "--username" => username.replace(value.clone()).is_some(),
                        _ => unreachable!(),
                    };
                    if duplicate {
                        return Err(format!("{option} may only be provided once"));
                    }
                    index += 2;
                }
                option if option.starts_with("--username=") => {
                    let value = option
                        .strip_prefix("--username=")
                        .expect("guard checked the prefix");
                    if value.is_empty() {
                        return Err("--username requires a non-empty value".into());
                    }
                    if username.replace(value.to_string()).is_some() {
                        return Err("--username may only be provided once".into());
                    }
                    index += 1;
                }
                "--reset-password" => {
                    if reset_password {
                        return Err("--reset-password may only be provided once".into());
                    }
                    reset_password = true;
                    index += 1;
                }
                "--reset-mfa" => {
                    if reset_mfa {
                        return Err("--reset-mfa may only be provided once".into());
                    }
                    reset_mfa = true;
                    index += 1;
                }
                unknown if unknown.starts_with('-') => {
                    return Err(format!("unknown recover-admin option: {unknown}"));
                }
                positional => {
                    return Err(format!(
                        "unexpected recover-admin positional argument: {positional}"
                    ));
                }
            }
        }
        let source = match (config_path, database_path) {
            (Some(path), None) => RecoveryDatabaseSource::Config(path),
            (None, Some(path)) => RecoveryDatabaseSource::Database(path),
            (None, None) => {
                return Err("recover-admin requires exactly one of --config or --database".into())
            }
            (Some(_), Some(_)) => {
                return Err("recover-admin accepts only one of --config or --database".into())
            }
        };
        let username = username.ok_or_else(|| "recover-admin requires --username".to_string())?;
        if !reset_password && !reset_mfa {
            return Err("recover-admin requires --reset-password and/or --reset-mfa".into());
        }
        Ok(Self {
            source,
            username,
            reset_password,
            reset_mfa,
        })
    }
}

#[derive(Deserialize)]
struct RecoveryConfigFile {
    storage: RecoveryStorageConfig,
}

#[derive(Deserialize)]
struct RecoveryStorageConfig {
    data_directory: PathBuf,
}

fn recovery_database_path(
    source: &RecoveryDatabaseSource,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    match source {
        RecoveryDatabaseSource::Database(path) => Ok(path.clone()),
        RecoveryDatabaseSource::Config(path) => {
            let serialized = std::fs::read_to_string(path)?;
            let config: RecoveryConfigFile = toml::from_str(&serialized)?;
            Ok(config.storage.data_directory.join("data.sqlite"))
        }
    }
}

fn rotate_secrets(options: &RotateSecretsOptions) -> Result<(), Box<dyn std::error::Error>> {
    let database_path = recovery_database_path(&options.source)?;
    if !database_path.is_file() {
        return Err(format!(
            "database does not exist or is not a regular file: {}",
            database_path.display()
        )
        .into());
    }
    Database::rotate_secrets(&database_path)?;
    tracing::info!(database = %database_path.display(), "secret rotation completed");
    Ok(())
}

fn revoke_all_service_tokens(
    options: &RevokeAllServiceTokensOptions,
) -> Result<usize, Box<dyn std::error::Error>> {
    let database_path = recovery_database_path(&options.source)?;
    if !database_path.is_file() {
        return Err(format!(
            "VaultLink database not found at {}",
            database_path.display()
        )
        .into());
    }
    let database = Database::open(database_path)?;
    let revoked =
        database.revoke_all_service_tokens_and_audit(&AuditContext::new("local_recovery", None))?;
    Ok(revoked)
}

fn verify_backup_database(
    options: &VerifyBackupDatabaseOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    if !options.database_path.is_file() {
        return Err(format!(
            "backup database does not exist or is not a regular file: {}",
            options.database_path.display()
        )
        .into());
    }
    Database::verify_backup(&options.database_path)?;
    println!(
        "backup database and adjacent secrets.keyring verified: {}",
        options.database_path.display()
    );
    Ok(())
}

fn init_admin(config: &Config, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let username = arg(args, "--username").ok_or("--username is required")?;
    validate_admin_username(username)?;
    if !config.storage.require_mount {
        std::fs::create_dir_all(&config.storage.data_directory)?;
    }
    let validated_storage = storage_mount::validate_and_open(&config.storage)?;
    validated_storage.verify_path_bindings(&config.storage)?;
    let database = Database::open_in_directory(validated_storage.data_file()?)?;
    if database.admin_count()? != 0 {
        return Err(
            "administrators already exist; init-admin is only available for initial setup".into(),
        );
    }
    let password = prompt_new_admin_password()?;
    let secret = Zeroizing::new(auth::new_totp_secret());
    let hash = auth::hash_password(password.as_str())
        .map_err(|error| std::io::Error::other(format!("password hashing failed: {error}")))?;
    drop(password);
    match database.create_initial_admin_and_audit(
        username,
        &hash,
        secret.as_str(),
        &AuditContext::new("local_init", None),
    )? {
        InitialAdminOutcome::Created => {
            println!(
                "Administrator created. One-time credential output follows; save it now:\nSecret: {0}\notpauth://totp/VaultLink:{username}?secret={0}&issuer=VaultLink",
                secret.as_str()
            );
            Ok(())
        }
        InitialAdminOutcome::AlreadyInitialized => Err(
            "administrators already exist; init-admin is only available for initial setup".into(),
        ),
    }
}

fn recover_admin(options: &RecoverAdminOptions) -> Result<(), Box<dyn std::error::Error>> {
    validate_admin_username(&options.username)?;
    let database_path = recovery_database_path(&options.source)?;
    if !database_path.is_file() {
        return Err(format!(
            "VaultLink database not found at {}",
            database_path.display()
        )
        .into());
    }
    let database = Database::open(database_path)?;
    let password_hash =
        if options.reset_password {
            let password = prompt_new_admin_password()?;
            Some(auth::hash_password(password.as_str()).map_err(|error| {
                std::io::Error::other(format!("password hashing failed: {error}"))
            })?)
        } else {
            None
        };
    let totp_secret = options
        .reset_mfa
        .then(|| Zeroizing::new(auth::new_totp_secret()));
    match database.recover_admin(
        &options.username,
        password_hash.as_deref(),
        totp_secret.as_ref().map(|secret| secret.as_str()),
    )? {
        AdminRecoveryOutcome::NotFound => {
            Err(format!("administrator not found: {}", options.username).into())
        }
        AdminRecoveryOutcome::Recovered {
            admin_id,
            username,
            active,
        } => {
            println!(
                "Administrator recovered: {username} (id {admin_id}). All sessions were revoked."
            );
            if !active {
                println!("Warning: this administrator remains inactive.");
            }
            if let Some(secret) = totp_secret {
                println!(
                    "One-time credential output follows; save it now:\nSecret: {0}\notpauth://totp/VaultLink:{username}?secret={0}&issuer=VaultLink",
                    secret.as_str()
                );
            }
            Ok(())
        }
    }
}

fn validate_admin_username(username: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !auth::valid_admin_username(username) {
        return Err("username must contain 3-64 safe ASCII characters".into());
    }
    Ok(())
}

fn prompt_new_admin_password() -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let password = Zeroizing::new(rpassword::prompt_password("New admin password: ")?);
    validate_admin_password(password.as_str())?;
    let confirmation = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
    if password.as_str() != confirmation.as_str() {
        return Err("passwords do not match".into());
    }
    Ok(password)
}

fn validate_admin_password(password: &str) -> Result<(), &'static str> {
    if !auth::valid_admin_password(password) {
        return Err("password must contain between 14 and 256 characters");
    }
    Ok(())
}

fn install_server_shutdown(
    handle: axum_server::Handle<std::net::SocketAddr>,
    cleanup: vaultlink::storage_cleanup::StorageCleanupCoordinator,
) {
    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("shutdown signal received; draining active connections");
        cleanup.request_shutdown();
        handle.graceful_shutdown(Some(std::time::Duration::from_secs(25)));
    });
}

async fn shutdown_signal() {
    let mut terminate =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(error) => {
                tracing::error!(%error, "cannot install SIGTERM handler");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = terminate.recv() => {},
    }
}

fn install_sighup_handler_for_files(config: &Config, tls: axum_server::tls_rustls::RustlsConfig) {
    if !config.tls.reload_on_cert_change {
        install_noop_sighup_handler("reload_on_cert_change is disabled");
        return;
    }
    let cert_file = config.tls.cert_file.clone();
    let key_file = config.tls.key_file.clone();
    tokio::spawn(async move {
        let Ok(mut signal) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        else {
            tracing::error!("cannot install SIGHUP handler");
            return;
        };
        while signal.recv().await.is_some() {
            match load_http1_rustls_config(&cert_file, &key_file).await {
                Ok(replacement) => {
                    tls.reload_from_config(replacement.get_inner());
                    tracing::info!("TLS certificate reloaded after SIGHUP");
                }
                Err(error) => {
                    tracing::error!(%error, "TLS certificate reload failed; previous certificate remains active")
                }
            }
        }
    });
}

async fn load_http1_rustls_config(
    cert_file: impl AsRef<std::path::Path>,
    key_file: impl AsRef<std::path::Path>,
) -> io::Result<axum_server::tls_rustls::RustlsConfig> {
    let loaded = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_file, key_file).await?;
    let mut server_config = (*loaded.get_inner()).clone();
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(server_config),
    ))
}

fn install_noop_sighup_handler(reason: &'static str) {
    tokio::spawn(async move {
        let Ok(mut signal) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        else {
            tracing::error!("cannot install SIGHUP handler");
            return;
        };
        while signal.recv().await.is_some() {
            tracing::info!(reason, "SIGHUP received; no reload action configured");
        }
    });
}

fn arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|v| v == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLogs {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedLogs {
        type Writer = Self;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn security_audit_retention_eviction_is_warned_with_counts() {
        let captured = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(captured.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            log_audit_retention_outcome(AuditRetentionOutcome {
                routine_deleted: 7,
                security_deleted: 2,
            });
        });
        let output = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(output.contains("WARN"));
        assert!(output.contains("audit retention removed security-priority events"));
        assert!(output.contains("routine_deleted=7"));
        assert!(output.contains("security_deleted=2"));
    }

    #[test]
    fn connection_limiter_recovers_after_lock_poisoning() {
        let peer = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let zero_peer = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
        let counts = Arc::new(Mutex::new(HashMap::from([
            (peer, usize::MAX),
            (zero_peer, 0usize),
        ])));
        let poisoned = counts.clone();
        assert!(std::panic::catch_unwind(move || {
            let _guard = poisoned.lock().unwrap();
            panic!("inject connection limiter poisoning");
        })
        .is_err());

        let recovered = connection_counts(&counts, 8);
        assert_eq!(recovered.get(&peer), Some(&8));
        assert!(!recovered.contains_key(&zero_peer));
        drop(recovered);
        assert!(!counts.is_poisoned());
    }

    #[derive(Clone)]
    struct PendingAcceptor;

    impl<S> Accept<tokio::net::TcpStream, S> for PendingAcceptor
    where
        S: Send + 'static,
    {
        type Stream = tokio::net::TcpStream;
        type Service = S;
        type Future = Pin<
            Box<
                dyn Future<Output = io::Result<(tokio::net::TcpStream, Self::Service)>>
                    + Send
                    + 'static,
            >,
        >;

        fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
            Box::pin(async move {
                let _held = (stream, service);
                std::future::pending::<io::Result<(tokio::net::TcpStream, S)>>().await
            })
        }
    }

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn seed_service_token_database(path: &std::path::Path, name: &str) {
        let database = Database::open(path).unwrap();
        let audit_context = AuditContext::new("recovery-test-admin", None);
        assert_eq!(
            database
                .create_initial_admin_and_audit(
                    "recovery-test-admin",
                    "password-hash",
                    &auth::new_totp_secret(),
                    &audit_context,
                )
                .unwrap(),
            InitialAdminOutcome::Created
        );
        drop(database);

        // This helper exercises the offline, explicitly non-session-bound
        // recovery command. Seed its fixture directly so production code does
        // not expose a raw-session-token service-token mutator as an escape
        // hatch around `MfaSessionProof`.
        let connection = rusqlite::Connection::open(path).unwrap();
        assert_eq!(
            connection
                .execute(
                    "INSERT INTO service_tokens(
                         name,token_hash,scope_mask,created_by,created_at
                     ) VALUES(?1,?2,1,1,?3)",
                    rusqlite::params![name, "0".repeat(64), chrono::Utc::now().to_rfc3339()],
                )
                .unwrap(),
            1
        );
    }

    fn assert_revoke_all_audit(path: &std::path::Path) {
        let database = Database::open(path).unwrap();
        let events = database
            .list_audit(Some("service_tokens_revoked_all"), 10, 0)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor, "local_recovery");
        assert_eq!(events[0].object_id, None);
        assert_eq!(events[0].detail.as_deref(), Some("count=1"));
    }

    #[test]
    fn revoke_all_service_tokens_parser_requires_confirmation_and_one_source() {
        assert_eq!(
            RevokeAllServiceTokensOptions::parse(&arguments(&[
                "vaultlink",
                "revoke-all-service-tokens",
                "--config",
                "config.toml",
                "--all",
            ]))
            .unwrap(),
            RevokeAllServiceTokensOptions {
                source: RecoveryDatabaseSource::Config("config.toml".into()),
            }
        );
        assert_eq!(
            RevokeAllServiceTokensOptions::parse(&arguments(&[
                "vaultlink",
                "revoke-all-service-tokens",
                "--all",
                "--database",
                "data.sqlite",
            ]))
            .unwrap(),
            RevokeAllServiceTokensOptions {
                source: RecoveryDatabaseSource::Database("data.sqlite".into()),
            }
        );

        for invalid in [
            vec![
                "vaultlink",
                "revoke-all-service-tokens",
                "--database",
                "data.sqlite",
            ],
            vec!["vaultlink", "revoke-all-service-tokens", "--all"],
            vec![
                "vaultlink",
                "revoke-all-service-tokens",
                "--config",
                "config.toml",
                "--database",
                "data.sqlite",
                "--all",
            ],
            vec![
                "vaultlink",
                "revoke-all-service-tokens",
                "--database",
                "data.sqlite",
                "--all",
                "--all",
            ],
            vec![
                "vaultlink",
                "revoke-all-service-tokens",
                "--database",
                "--all",
            ],
            vec![
                "vaultlink",
                "revoke-all-service-tokens",
                "--database",
                "data.sqlite",
                "--unknown",
                "--all",
            ],
        ] {
            assert!(RevokeAllServiceTokensOptions::parse(&arguments(&invalid)).is_err());
        }
    }

    #[test]
    fn revoke_all_service_tokens_targets_only_the_selected_database_and_audits_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let direct_database = directory.path().join("direct.sqlite");
        let untouched_database = directory.path().join("untouched.sqlite");
        let config_data_directory = directory.path().join("configured-data");
        std::fs::create_dir(&config_data_directory).unwrap();
        let configured_database = config_data_directory.join("data.sqlite");
        seed_service_token_database(&direct_database, "Direct target");
        seed_service_token_database(&untouched_database, "Untouched target");
        seed_service_token_database(&configured_database, "Config target");

        let direct_options = RevokeAllServiceTokensOptions {
            source: RecoveryDatabaseSource::Database(direct_database.clone()),
        };
        assert_eq!(revoke_all_service_tokens(&direct_options).unwrap(), 1);
        assert!(Database::open(&direct_database)
            .unwrap()
            .list_service_tokens()
            .unwrap()
            .is_empty());
        assert_eq!(
            Database::open(&untouched_database)
                .unwrap()
                .list_service_tokens()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            Database::open(&configured_database)
                .unwrap()
                .list_service_tokens()
                .unwrap()
                .len(),
            1
        );
        assert_revoke_all_audit(&direct_database);

        let config_path = directory.path().join("recovery.toml");
        let serialized_data_directory =
            toml::Value::String(config_data_directory.to_string_lossy().into_owned()).to_string();
        std::fs::write(
            &config_path,
            format!("[storage]\ndata_directory = {serialized_data_directory}\n"),
        )
        .unwrap();
        let config_options = RevokeAllServiceTokensOptions {
            source: RecoveryDatabaseSource::Config(config_path),
        };
        assert_eq!(revoke_all_service_tokens(&config_options).unwrap(), 1);
        assert!(Database::open(&configured_database)
            .unwrap()
            .list_service_tokens()
            .unwrap()
            .is_empty());
        assert_eq!(
            Database::open(&untouched_database)
                .unwrap()
                .list_service_tokens()
                .unwrap()
                .len(),
            1
        );
        assert_revoke_all_audit(&configured_database);
        assert!(Database::open(&untouched_database)
            .unwrap()
            .list_audit(Some("service_tokens_revoked_all"), 10, 0)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn verify_backup_database_parser_is_exact() {
        assert_eq!(
            VerifyBackupDatabaseOptions::parse(&arguments(&[
                "vaultlink",
                "verify-backup-database",
                "--database",
                "backup/data.sqlite",
            ]))
            .unwrap(),
            VerifyBackupDatabaseOptions {
                database_path: "backup/data.sqlite".into(),
            }
        );
        for invalid in [
            vec!["vaultlink", "verify-backup-database"],
            vec![
                "vaultlink",
                "verify-backup-database",
                "--config",
                "config.toml",
            ],
            vec![
                "vaultlink",
                "verify-backup-database",
                "--database",
                "--other",
            ],
            vec![
                "vaultlink",
                "verify-backup-database",
                "--database",
                "one.sqlite",
                "extra",
            ],
        ] {
            assert!(VerifyBackupDatabaseOptions::parse(&arguments(&invalid)).is_err());
        }
    }

    #[test]
    fn verify_backup_database_authenticates_encrypted_state() {
        let valid = tempfile::tempdir().unwrap();
        let valid_database = valid.path().join("data.sqlite");
        let database = Database::open(&valid_database).unwrap();
        assert_eq!(
            database
                .create_initial_admin_and_audit(
                    "admin",
                    "password-hash",
                    "JBSWY3DPEHPK3PXP",
                    &AuditContext::new("backup-verification-test", None),
                )
                .unwrap(),
            InitialAdminOutcome::Created
        );
        drop(database);
        std::fs::remove_file(valid.path().join("secrets.keyring.lock")).unwrap();

        let database_before = std::fs::read(&valid_database).unwrap();
        let keyring_path = valid.path().join("secrets.keyring");
        let keyring_before = std::fs::read(&keyring_path).unwrap();

        let options = VerifyBackupDatabaseOptions {
            database_path: valid_database.clone(),
        };
        verify_backup_database(&options).unwrap();
        assert_eq!(std::fs::read(&valid_database).unwrap(), database_before);
        assert_eq!(std::fs::read(&keyring_path).unwrap(), keyring_before);
        assert!(!valid.path().join("secrets.keyring.lock").exists());

        let unrelated = tempfile::tempdir().unwrap();
        let unrelated_database = unrelated.path().join("data.sqlite");
        drop(Database::open(&unrelated_database).unwrap());
        std::fs::copy(unrelated.path().join("secrets.keyring"), &keyring_path).unwrap();
        assert!(verify_backup_database(&options).is_err());
    }

    #[test]
    fn recover_admin_parser_accepts_exactly_one_database_source() {
        assert_eq!(
            RecoverAdminOptions::parse(&arguments(&[
                "vaultlink",
                "recover-admin",
                "--config",
                "config.toml",
                "--username",
                "admin",
                "--reset-password",
                "--reset-mfa",
            ]))
            .unwrap(),
            RecoverAdminOptions {
                source: RecoveryDatabaseSource::Config("config.toml".into()),
                username: "admin".into(),
                reset_password: true,
                reset_mfa: true,
            }
        );
        assert_eq!(
            RecoverAdminOptions::parse(&arguments(&[
                "vaultlink",
                "recover-admin",
                "--database",
                "data.sqlite",
                "--username",
                "admin",
                "--reset-mfa",
            ]))
            .unwrap()
            .source,
            RecoveryDatabaseSource::Database("data.sqlite".into())
        );
        assert_eq!(
            RecoverAdminOptions::parse(&arguments(&[
                "vaultlink",
                "recover-admin",
                "--database",
                "data.sqlite",
                "--username=--ops",
                "--reset-mfa",
            ]))
            .unwrap()
            .username,
            "--ops"
        );
    }

    #[test]
    fn recover_admin_parser_rejects_ambiguous_or_unknown_arguments() {
        for invalid in [
            vec![
                "vaultlink",
                "recover-admin",
                "--config",
                "config.toml",
                "--username",
                "admin",
            ],
            vec![
                "vaultlink",
                "recover-admin",
                "--config",
                "--username",
                "admin",
                "--reset-mfa",
            ],
            vec![
                "vaultlink",
                "recover-admin",
                "--config",
                "one.toml",
                "--config",
                "two.toml",
                "--username",
                "admin",
                "--reset-mfa",
            ],
            vec![
                "vaultlink",
                "recover-admin",
                "--config",
                "config.toml",
                "--database",
                "data.sqlite",
                "--username",
                "admin",
                "--reset-mfa",
            ],
            vec![
                "vaultlink",
                "recover-admin",
                "--database",
                "data.sqlite",
                "--username",
                "admin",
                "--reset-mfa",
                "--reset-mfa",
            ],
            vec![
                "vaultlink",
                "recover-admin",
                "--database",
                "data.sqlite",
                "--username",
                "admin",
                "--unknown",
                "--reset-mfa",
            ],
            vec![
                "vaultlink",
                "recover-admin",
                "--database",
                "data.sqlite",
                "--username",
                "admin",
                "positional",
                "--reset-mfa",
            ],
        ] {
            assert!(RecoverAdminOptions::parse(&arguments(&invalid)).is_err());
        }
    }

    #[test]
    fn command_dispatch_rejects_typos_without_breaking_config_only_server_start() {
        assert_eq!(
            command_mode(&arguments(&["vaultlink"])).unwrap(),
            CommandMode::Serve
        );
        assert_eq!(
            command_mode(&arguments(&["vaultlink", "--config", "config.toml"])).unwrap(),
            CommandMode::Serve
        );
        assert_eq!(
            command_mode(&arguments(&[
                "vaultlink",
                "setup",
                "--listen",
                "127.0.0.1:8090"
            ]))
            .unwrap(),
            CommandMode::Setup
        );
        assert!(command_mode(&arguments(&["vaultlink", "recover-adminn"])).is_err());
        assert!(command_mode(&arguments(&["vaultlink", "--unknown"])).is_err());
        assert!(command_mode(&arguments(&[
            "vaultlink",
            "--config",
            "config.toml",
            "unexpected"
        ]))
        .is_err());
    }

    #[test]
    fn recovery_config_resolution_does_not_require_runtime_tls_validity() {
        let directory = tempfile::tempdir().unwrap();
        let data_directory = directory.path().join("data");
        let config_path = directory.path().join("recovery.toml");
        let mut config = Config::load("config/development.toml").unwrap();
        config.server.mode = ServerMode::StandaloneTls;
        config.server.listen_address = "127.0.0.1:8443".into();
        config.server.public_base_url = "https://files.example.test".into();
        config.server.production_mode = true;
        config.storage.root_mount_path = directory.path().join("shared");
        config.storage.data_directory = data_directory.clone();
        config.storage.internal_directory = Some(directory.path().join(".vaultlink-internal"));
        config.storage.require_mount = true;
        config.storage.expected_filesystem_type = Some("ext4".into());
        config.storage.expected_mount_source = Some("/dev/mapper/vaultlink-test".into());
        config.security.secure_cookie = true;
        config.tls.enabled = true;
        config.tls.certificate_source = CertificateSource::Files;
        config.tls.cert_file = directory.path().join("missing-cert.pem");
        config.tls.key_file = directory.path().join("missing-key.pem");
        std::fs::write(&config_path, toml::to_string_pretty(&config).unwrap()).unwrap();

        assert!(Config::load(&config_path).is_err());
        assert_eq!(
            recovery_database_path(&RecoveryDatabaseSource::Config(config_path)).unwrap(),
            data_directory.join("data.sqlite")
        );
    }

    #[test]
    fn recovery_config_accepts_a_minimal_storage_section() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("minimal.toml");
        let serialized = format!(
            "[storage]\ndata_directory = '{}'\n[tls]\ncert_file = 'missing.pem'\n",
            directory.path().display()
        );
        std::fs::write(&config_path, serialized).unwrap();

        assert_eq!(
            recovery_database_path(&RecoveryDatabaseSource::Config(config_path)).unwrap(),
            directory.path().join("data.sqlite")
        );
    }

    #[test]
    fn admin_password_minimum_counts_characters_instead_of_bytes() {
        assert!(validate_admin_password("äääääääääääää").is_err());
        assert!(validate_admin_password("ääääääääääääää").is_ok());
        assert!(validate_admin_password(&"x".repeat(auth::ADMIN_PASSWORD_MAX_CHARACTERS)).is_ok());
        assert!(
            validate_admin_password(&"x".repeat(auth::ADMIN_PASSWORD_MAX_CHARACTERS + 1)).is_err()
        );
    }

    #[tokio::test]
    async fn connection_limiter_rejects_excess_connections_and_releases_on_drop() {
        let limiter = ConnectionLimitAcceptor {
            inner: axum_server::accept::DefaultAcceptor::new(),
            permits: Arc::new(Semaphore::new(1)),
            peer_connections: Arc::new(Mutex::new(HashMap::new())),
            trusted_proxy_peers: None,
            max_connections_per_peer: 2,
            accept_timeout: CONNECTION_ACCEPT_TIMEOUT,
        };
        let (_first_client, first_server) = tcp_pair().await;
        let (held_connection, ()) = limiter.accept(first_server, ()).await.unwrap();

        let (_second_client, second_server) = tcp_pair().await;
        let error = limiter
            .accept(second_server, ())
            .await
            .err()
            .expect("the second connection must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);

        drop(held_connection);
        let (_third_client, third_server) = tcp_pair().await;
        assert!(limiter.accept(third_server, ()).await.is_ok());
    }

    #[tokio::test]
    async fn connection_limiter_enforces_and_releases_the_peer_budget() {
        let limiter = ConnectionLimitAcceptor {
            inner: axum_server::accept::DefaultAcceptor::new(),
            permits: Arc::new(Semaphore::new(2)),
            peer_connections: Arc::new(Mutex::new(HashMap::new())),
            trusted_proxy_peers: None,
            max_connections_per_peer: 1,
            accept_timeout: CONNECTION_ACCEPT_TIMEOUT,
        };
        let (_first_client, first_server) = tcp_pair().await;
        let (held_connection, ()) = limiter.accept(first_server, ()).await.unwrap();

        let (_second_client, second_server) = tcp_pair().await;
        let error = limiter
            .accept(second_server, ())
            .await
            .err()
            .expect("the peer limit must reject the second connection");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);

        drop(held_connection);
        let (_third_client, third_server) = tcp_pair().await;
        assert!(limiter.accept(third_server, ()).await.is_ok());
    }

    #[tokio::test]
    async fn connection_limiter_times_out_stalled_tls_accept_and_releases_budgets() {
        let limiter = ConnectionLimitAcceptor {
            inner: PendingAcceptor,
            permits: Arc::new(Semaphore::new(1)),
            peer_connections: Arc::new(Mutex::new(HashMap::new())),
            trusted_proxy_peers: None,
            max_connections_per_peer: 1,
            accept_timeout: Duration::from_millis(20),
        };
        let (_client, server) = tcp_pair().await;
        let error = tokio::time::timeout(Duration::from_millis(250), limiter.accept(server, ()))
            .await
            .expect("the connection accept deadline must wake the task")
            .err()
            .expect("a stalled connection accept must time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(limiter.permits.available_permits(), 1);
        assert!(limiter.peer_connections.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reverse_proxy_acceptor_accepts_only_an_explicit_tcp_peer() {
        let loopback = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let trusted_limiter = ConnectionLimitAcceptor {
            inner: axum_server::accept::DefaultAcceptor::new(),
            permits: Arc::new(Semaphore::new(2)),
            peer_connections: Arc::new(Mutex::new(HashMap::new())),
            trusted_proxy_peers: Some(Arc::new(HashSet::from([loopback]))),
            max_connections_per_peer: 1,
            accept_timeout: CONNECTION_ACCEPT_TIMEOUT,
        };
        let (_trusted_client, trusted_server) = tcp_pair().await;
        assert!(trusted_limiter.accept(trusted_server, ()).await.is_ok());

        let untrusted_limiter = ConnectionLimitAcceptor {
            inner: axum_server::accept::DefaultAcceptor::new(),
            permits: Arc::new(Semaphore::new(2)),
            peer_connections: Arc::new(Mutex::new(HashMap::new())),
            trusted_proxy_peers: Some(Arc::new(HashSet::from(["192.0.2.10".parse().unwrap()]))),
            max_connections_per_peer: 1,
            accept_timeout: CONNECTION_ACCEPT_TIMEOUT,
        };
        let (_direct_client, direct_server) = tcp_pair().await;
        let error = untrusted_limiter
            .accept(direct_server, ())
            .await
            .err()
            .expect("an unlisted direct peer must be rejected before HTTP");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(untrusted_limiter.permits.available_permits(), 2);
        assert!(untrusted_limiter
            .peer_connections
            .lock()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn connection_peer_keys_group_ipv6_prefixes_and_mapped_ipv4() {
        assert_eq!(
            vaultlink::proxy::client_limit_key("2001:db8:1234:5678::1".parse().unwrap()),
            "2001:db8:1234:5678::".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            vaultlink::proxy::client_limit_key("::ffff:192.0.2.7".parse().unwrap()),
            "192.0.2.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn only_exact_trusted_proxy_peers_receive_the_global_budget() {
        let trusted_peer = "192.0.2.10".parse::<IpAddr>().unwrap();
        let trusted_proxy_peers = HashSet::from([trusted_peer]);
        assert_eq!(
            peer_connection_limit(
                trusted_peer,
                Some(&trusted_proxy_peers),
                MAX_ACTIVE_CONNECTIONS_PER_PEER,
            ),
            MAX_ACTIVE_CONNECTIONS
        );
        assert_eq!(
            peer_connection_limit(
                "192.0.2.11".parse().unwrap(),
                Some(&trusted_proxy_peers),
                MAX_ACTIVE_CONNECTIONS_PER_PEER,
            ),
            MAX_ACTIVE_CONNECTIONS_PER_PEER
        );
        assert_eq!(
            peer_connection_limit(
                "::ffff:192.0.2.10".parse().unwrap(),
                Some(&trusted_proxy_peers),
                MAX_ACTIVE_CONNECTIONS_PER_PEER,
            ),
            MAX_ACTIVE_CONNECTIONS
        );
    }

    #[tokio::test]
    async fn connection_io_times_out_when_response_writes_make_no_progress() {
        use tokio::io::AsyncWriteExt as _;

        let peer = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let peer_connections = Arc::new(Mutex::new(HashMap::from([(peer, 1)])));
        let global = Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap();
        let (_client, server) = tokio::io::duplex(1);
        let mut limited = ConnectionLimitedIo {
            inner: server,
            _permit: ConnectionPermit {
                _global: global,
                peer_connections,
                peer,
                maximum: 1,
            },
            write_timeout: None,
            write_idle_timeout: Duration::from_millis(20),
            connection_deadline: Box::pin(tokio::time::sleep(Duration::from_secs(1))),
        };
        limited.write_all(b"x").await.unwrap();
        let error = tokio::time::timeout(Duration::from_millis(250), limited.write_all(b"y"))
            .await
            .expect("write deadline must wake the task")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }
}
