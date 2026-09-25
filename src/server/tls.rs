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

#[derive(Debug)]
struct PinnedProxyClientVerifier {
    inner: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    fingerprints: HashSet<String>,
}

impl rustls::server::danger::ClientCertVerifier for PinnedProxyClientVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        certificate: &rustls_pki_types::CertificateDer<'_>,
        intermediates: &[rustls_pki_types::CertificateDer<'_>],
        now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        use sha2::Digest;
        self.inner
            .verify_client_cert(certificate, intermediates, now)?;
        let fingerprint = sha2::Sha256::digest(certificate.as_ref())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if !self.fingerprints.contains(&fingerprint) {
            return Err(rustls::Error::General(
                "client certificate is not an allowed proxy".into(),
            ));
        }
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &rustls_pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &rustls_pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

async fn load_proxy_mtls_config(
    config: &Config,
    client_ca_file: &std::path::Path,
    fingerprints: &[String],
) -> io::Result<axum_server::tls_rustls::RustlsConfig> {
    use rustls_pki_types::pem::PemObject;
    let cert_file = config.tls.cert_file.clone();
    let key_file = config.tls.key_file.clone();
    let ca_file = client_ca_file.to_path_buf();
    let allowed = fingerprints.iter().cloned().collect::<HashSet<_>>();
    tokio::task::spawn_blocking(move || {
        let pem = tls_files::read_validated_tls_pem(&cert_file, &key_file)?;
        let ca_pem = tls_files::read_validated_ca_pem(&ca_file)?;
        let certificates = rustls_pki_types::CertificateDer::pem_slice_iter(&pem.certificate_chain)
            .collect::<Result<Vec<_>, _>>()
            .map_err(io::Error::other)?;
        if certificates.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty server certificate chain",
            ));
        }
        let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(&pem.private_key)
            .map_err(io::Error::other)?;
        let ca_certificates = rustls_pki_types::CertificateDer::pem_slice_iter(&ca_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(io::Error::other)?;
        if ca_certificates.is_empty() || ca_certificates.len() > 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid proxy client CA chain",
            ));
        }
        let mut roots = rustls::RootCertStore::empty();
        for certificate in ca_certificates {
            roots.add(certificate).map_err(io::Error::other)?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(io::Error::other)?;
        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(PinnedProxyClientVerifier {
                inner: verifier,
                fingerprints: allowed,
            }))
            .with_single_cert(certificates, key)
            .map_err(io::Error::other)?;
        let mut config = config;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(axum_server::tls_rustls::RustlsConfig::from_config(
            Arc::new(config),
        ))
    })
    .await
    .map_err(|error| io::Error::other(format!("mTLS loading task failed: {error}")))?
}

fn arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|v| v == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}
