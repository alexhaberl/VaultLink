use super::*;

#[tokio::test]
async fn acme_startup_rejects_invalid_urls_and_unusable_cache_before_network_work() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = Config::load(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config/development.toml"),
    )
    .unwrap();
    config.server.mode = ServerMode::StandaloneTls;
    config.tls.certificate_source = CertificateSource::LetsEncrypt;
    config.storage.data_directory = directory.path().into();
    config.tls.letsencrypt_cache_dir = "acme".into();
    let blocked_cache = directory.path().join("acme");
    std::fs::write(&blocked_cache, b"existing file").unwrap();
    for url in [
        "invalid URL",
        "mailto:admin@example.test",
        "https://localhost",
    ] {
        let result = serve_application(
            &config,
            "127.0.0.1:0".parse().unwrap(),
            url,
            vaultlink::storage_cleanup::StorageCleanupCoordinator::new(),
            None,
            axum::Router::new(),
        )
        .await;
        assert!(
            result.is_err(),
            "invalid ACME startup unexpectedly succeeded"
        );
        assert_eq!(std::fs::read(&blocked_cache).unwrap(), b"existing file");
    }
    config.tls.letsencrypt_cache_dir = "../outside".into();
    assert!(serve_application(
        &config,
        "127.0.0.1:0".parse().unwrap(),
        "https://localhost",
        vaultlink::storage_cleanup::StorageCleanupCoordinator::new(),
        None,
        axum::Router::new(),
    )
    .await
    .is_err());
}
