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
                    tracing::error!(
                        error = %EscapedLogValue::new(&error),
                        "TLS certificate reload failed; previous certificate remains active"
                    )
                }
            }
        }
    });
}

async fn load_http1_rustls_config(
    cert_file: impl AsRef<std::path::Path>,
    key_file: impl AsRef<std::path::Path>,
) -> io::Result<axum_server::tls_rustls::RustlsConfig> {
    let cert_file = cert_file.as_ref().to_path_buf();
    let key_file = key_file.as_ref().to_path_buf();
    let pem = tokio::task::spawn_blocking(move || {
        tls_files::read_validated_tls_pem(&cert_file, &key_file)
    })
    .await
    .map_err(|error| io::Error::other(format!("TLS file validation task failed: {error}")))??;
    // `from_pem` parses the complete chain and the complete key before a
    // replacement config can be published by the SIGHUP handler.
    let loaded =
        axum_server::tls_rustls::RustlsConfig::from_pem(pem.certificate_chain, pem.private_key)
            .await?;
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
