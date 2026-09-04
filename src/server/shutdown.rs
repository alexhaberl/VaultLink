fn install_server_shutdown(
    handle: axum_server::Handle<std::net::SocketAddr>,
    cleanup: vaultlink::storage_cleanup::StorageCleanupCoordinator,
) {
    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("shutdown signal received; draining active connections");
        cleanup.request_shutdown();
        handle.graceful_shutdown(Some(SERVER_DRAIN_TIMEOUT));
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
