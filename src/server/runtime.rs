fn main() -> Result<(), Box<dyn std::error::Error>> {
    vaultlink::install_safe_panic_reporting();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .build()?;
    let result = runtime.block_on(run());
    // A timed-out blocking operation cannot be cancelled by Tokio. Do not let
    // runtime teardown extend the externally enforced 25s + 10s shutdown
    // budget; systemd retains a separate ten-second termination margin.
    runtime.shutdown_timeout(Duration::ZERO);
    result
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
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
    start_audit_retention_worker(state.database());
    vaultlink::file_ops::recover_pending_file_operations(&state).await?;
    let effective_public_base_url = vaultlink::http_auth::runtime_settings(&state).public_base_url;
    let cleanup_coordinator = state.storage_cleanup_coordinator();
    let cleanup_worker = state.start_storage_cleanup_worker()?;
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
    let server_result = serve_application(
        &config,
        addr,
        &effective_public_base_url,
        cleanup_coordinator,
        trusted_proxy_peers,
        app,
    )
    .await;
    wait_for_cleanup_shutdown(cleanup_worker.shutdown(), CLEANUP_JOIN_TIMEOUT).await?;
    server_result
}

async fn serve_application(
    config: &Config,
    addr: std::net::SocketAddr,
    effective_public_base_url: &str,
    cleanup_coordinator: vaultlink::storage_cleanup::StorageCleanupCoordinator,
    trusted_proxy_peers: Option<Arc<HashSet<IpAddr>>>,
    app: axum::Router,
) -> Result<(), Box<dyn std::error::Error>> {
    match config.server.mode {
        ServerMode::StandaloneTls => match config.tls.certificate_source {
            CertificateSource::Files => {
                let tls =
                    load_http1_rustls_config(&config.tls.cert_file, &config.tls.key_file).await?;
                install_sighup_handler_for_files(config, tls.clone());
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
                let public_url = url::Url::parse(effective_public_base_url)?;
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
                .map(|acceptor| ConnectionLimitAcceptor::new(acceptor, trusted_proxy_peers.clone()))
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
