use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::sync::atomic::{AtomicBool, Ordering};

async fn run_bootstrap_health() -> io::Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let router = axum::Router::new()
        .route(
            "/api/v2/health/live",
            axum::routing::get(move || async move {
                axum::Json(serde_json::json!({"ok": true, "version": version}))
            }),
        )
        .route(
            "/api/v2/health/ready",
            axum::routing::get(move || async move {
                (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    axum::Json(serde_json::json!({"ok": false, "version": version})),
                )
            }),
        );
    let address: std::net::SocketAddr = config::PROXY_HEALTH_ADDRESS
        .parse()
        .expect("constant health address");
    let mut server = axum_server::bind(address)
        .map(|acceptor| ConnectionLimitAcceptor::new(acceptor, None))
        .http1_only();
    harden_http_server(&mut server);
    server.serve(router.into_make_service()).await
}

async fn local_health_check(args: &[String]) -> io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let path = match args.get(2).map(String::as_str) {
        Some("--live") if args.len() == 3 => "/api/v2/health/live",
        Some("--ready") if args.len() == 3 => "/api/v2/health/ready",
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: vaultlink health-check --live|--ready",
            ))
        }
    };
    let mut stream = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(config::PROXY_HEALTH_ADDRESS),
    )
    .await??;
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    tokio::time::timeout(Duration::from_secs(3), stream.write_all(request.as_bytes())).await??;
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(3),
        stream.take(4097).read_to_end(&mut response),
    )
    .await??;
    if response.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "health response exceeds limit",
        ));
    }
    let text = std::str::from_utf8(&response).map_err(io::Error::other)?;
    let body = format!(
        "{{\"ok\":true,\"version\":\"{}\"}}",
        env!("CARGO_PKG_VERSION")
    );
    if !text.starts_with("HTTP/1.1 200 ") || !text.ends_with(&body) {
        return Err(io::Error::other("local health check failed"));
    }
    Ok(())
}

fn bind_protected_proxy_socket(
    path: &std::path::Path,
) -> io::Result<std::os::unix::net::UnixListener> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("Unix proxy socket has no parent"))?;
    for ancestor in parent.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Unix proxy socket ancestors must be directories without group/world write access",
            ));
        }
    }
    let metadata = std::fs::symlink_metadata(parent)?;
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.gid() != rustix::process::getegid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o750
    {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            "Unix proxy socket directory must be owned by the service and proxy group with mode 0750"));
    }
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    let socket = std::fs::symlink_metadata(path)?;
    if !socket.file_type().is_socket()
        || socket.uid() != rustix::process::geteuid().as_raw()
        || socket.gid() != rustix::process::getegid().as_raw()
        || socket.permissions().mode() & 0o777 != 0o660
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Unix proxy socket ownership or permissions changed",
        ));
    }
    listener.set_nonblocking(true)?;
    Ok(listener)
}

async fn serve_proxy_application(
    config: &Config,
    state: AppState,
    cleanup: vaultlink::storage_cleanup::StorageCleanupCoordinator,
    app: axum::Router,
) -> Result<(), Box<dyn std::error::Error>> {
    let listening = Arc::new(AtomicBool::new(false));
    let transport = config
        .reverse_proxy
        .transport
        .as_ref()
        .ok_or("proxy transport missing")?;
    let (mut application, stop_application): (
        tokio::task::JoinHandle<io::Result<()>>,
        Box<dyn Fn() + Send>,
    ) = match transport {
        ProxyTransport::Unix {
            socket_path,
            proxy_uids,
        } => {
            install_noop_sighup_handler("Unix proxy transport does not reload certificates");
            let listener = bind_protected_proxy_socket(socket_path)?;
            let handle = axum_server::Handle::new();
            install_server_shutdown(handle.clone(), cleanup.clone());
            let mut server = axum_server::from_unix(listener)?
                .map(|_| UnixProxyAcceptor::new(proxy_uids.clone()))
                .http1_only();
            harden_http_server(&mut server);
            let start_handle = handle.clone();
            let stop_handle = handle.clone();
            let ready = listening.clone();
            tokio::spawn(async move {
                if start_handle.listening().await.is_some() {
                    ready.store(true, Ordering::Release);
                }
            });
            let ready = listening.clone();
            let task = tokio::spawn(async move {
                let result = server
                    .handle(handle.clone())
                    .serve(app.into_make_service())
                    .await;
                ready.store(false, Ordering::Release);
                result
            });
            let stop = Box::new(move || stop_handle.shutdown());
            (task, stop)
        }
        ProxyTransport::Mtls {
            client_ca_file,
            client_fingerprints,
        } => {
            install_noop_sighup_handler("mTLS trust configuration requires a coordinated restart");
            let addr: std::net::SocketAddr = config.server.listen_address.parse()?;
            let tls = load_proxy_mtls_config(config, client_ca_file, client_fingerprints).await?;
            let handle = axum_server::Handle::new();
            install_server_shutdown(handle.clone(), cleanup.clone());
            let mut server = axum_server::bind_rustls(addr, tls)
                .map(|acceptor| MtlsProxyAcceptor::new(ConnectionLimitAcceptor::new_mtls(acceptor)))
                .http1_only();
            harden_http_server(&mut server);
            let start_handle = handle.clone();
            let stop_handle = handle.clone();
            let ready = listening.clone();
            tokio::spawn(async move {
                if start_handle.listening().await.is_some() {
                    ready.store(true, Ordering::Release);
                }
            });
            let ready = listening.clone();
            let task = tokio::spawn(async move {
                let result = server
                    .handle(handle.clone())
                    .serve(app.into_make_service())
                    .await;
                ready.store(false, Ordering::Release);
                result
            });
            let stop = Box::new(move || stop_handle.shutdown());
            (task, stop)
        }
    };

    let health_addr: std::net::SocketAddr = config::PROXY_HEALTH_ADDRESS.parse()?;
    let health_handle = axum_server::Handle::new();
    install_server_shutdown(health_handle.clone(), cleanup.clone());
    let health_router = vaultlink::api::local_health_router(state, listening);
    let health = axum_server::bind(health_addr)
        .map(|acceptor| ConnectionLimitAcceptor::new(acceptor, None))
        .http1_only();
    let mut health = health;
    harden_http_server(&mut health);
    let health_stop = health_handle.clone();
    let mut health_task = tokio::spawn(async move {
        health
            .handle(health_handle)
            .serve(health_router.into_make_service())
            .await
    });
    let outcome = tokio::select! {
        result = &mut application => {
            health_stop.shutdown();
            let _ = tokio::time::timeout(SERVER_DRAIN_TIMEOUT, &mut health_task).await;
            result
        }
        result = &mut health_task => {
            stop_application();
            let _ = tokio::time::timeout(SERVER_DRAIN_TIMEOUT, &mut application).await;
            result
        }
    };
    cleanup.request_shutdown();
    outcome??;
    Ok(())
}

#[cfg(test)]
mod proxy_socket_tests {
    use super::*;

    #[tokio::test]
    async fn unix_acceptor_uses_kernel_peer_uid() {
        let current_uid = rustix::process::geteuid().as_raw();
        let other_uid = if current_uid == 10002 { 10003 } else { 10002 };
        let (rejected_stream, _peer) = tokio::net::UnixStream::pair().unwrap();
        let rejected = UnixProxyAcceptor::new(vec![other_uid])
            .accept(rejected_stream, ())
            .await;
        assert!(matches!(rejected, Err(error) if error.kind() == io::ErrorKind::PermissionDenied));

        let (accepted_stream, _peer) = tokio::net::UnixStream::pair().unwrap();
        let accepted = UnixProxyAcceptor::new(vec![current_uid])
            .accept(accepted_stream, ())
            .await;
        assert!(accepted.is_ok());
    }

    #[tokio::test]
    async fn unix_acceptor_distinguishes_separate_process_uids() {
        use std::os::unix::process::CommandExt;

        if rustix::process::geteuid().as_raw() != 0
            || std::process::Command::new("python3")
                .arg("--version")
                .output()
                .is_err()
        {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = directory.path().join("uid-test.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();

        for (uid, allowed) in [(11002, true), (11003, false)] {
            let mut child = std::process::Command::new("python3");
            child.arg("-c").arg(
                "import socket,sys,time; peer=socket.socket(socket.AF_UNIX); peer.connect(sys.argv[1]); time.sleep(0.2)",
            );
            child.arg(&path).uid(uid).gid(uid);
            let mut child = child.spawn().unwrap();
            let (stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let accepted = UnixProxyAcceptor::new(vec![11002]).accept(stream, ()).await;
            assert_eq!(
                accepted.is_ok(),
                allowed,
                "unexpected authorization for UID {uid}"
            );
            assert!(child.wait().unwrap().success());
        }
    }

    #[test]
    fn unix_socket_rejects_unsafe_directory_and_existing_entries() {
        let home = std::env::var_os("HOME").expect("test HOME");
        let directory = tempfile::Builder::new()
            .prefix("vaultlink-proxy-test-")
            .tempdir_in(std::path::PathBuf::from(home))
            .unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        let socket = directory.path().join("proxy.sock");
        let listener = bind_protected_proxy_socket(&socket).unwrap();
        let metadata = std::fs::symlink_metadata(&socket).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
        assert!(bind_protected_proxy_socket(&socket).is_err());
        drop(listener);
        std::fs::remove_file(&socket).unwrap();

        std::os::unix::fs::symlink(directory.path().join("missing"), &socket).unwrap();
        assert!(bind_protected_proxy_socket(&socket).is_err());
        std::fs::remove_file(&socket).unwrap();
        std::fs::write(&socket, b"foreign entry").unwrap();
        assert!(bind_protected_proxy_socket(&socket).is_err());
        std::fs::remove_file(&socket).unwrap();

        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(bind_protected_proxy_socket(&socket).is_err());
    }
}
