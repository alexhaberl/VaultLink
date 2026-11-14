use super::*;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn fixture() -> (AcmeHttpAcceptor, rustls::ClientConfig) {
    let directory = tempfile::tempdir().unwrap();
    let certificate_path = directory.path().join("certificate.pem");
    let key_path = directory.path().join("key.pem");
    let result = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-keyout",
        ])
        .arg(&key_path)
        .arg("-out")
        .arg(&certificate_path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "test certificate generation failed"
    );
    let certificate =
        CertificateDer::from_pem_slice(&std::fs::read(certificate_path).unwrap()).unwrap();
    let key = PrivateKeyDer::from_pem_slice(&std::fs::read(key_path).unwrap()).unwrap();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .unwrap();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).unwrap();
    let mut client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    (AcmeHttpAcceptor::new(Arc::new(tls)), client)
}

#[tokio::test]
async fn ordinary_tls_preserves_service_and_transfers_application_bytes() {
    let (acceptor, client_config) = fixture();
    let (client, server) = tokio::io::duplex(4096);
    let server = async move {
        let service = Arc::new(String::from("http service"));
        let (mut stream, returned_service) =
            acceptor.accept(server, service.clone()).await.unwrap();
        assert!(Arc::ptr_eq(&service, &returned_service));
        let mut request = [0; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.unwrap();
        stream.flush().await.unwrap();
    };
    let client = async move {
        let connector = rustls_acme::futures_rustls::TlsConnector::from(Arc::new(client_config));
        let mut stream = connector
            .connect(ServerName::try_from("localhost").unwrap(), client.compat())
            .await
            .unwrap()
            .compat();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(server, client);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn completed_acme_challenge_never_reaches_the_http_service() {
    let (acceptor, mut client_config) = fixture();
    client_config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let (client, server) = tokio::io::duplex(4096);
    let connector = rustls_acme::futures_rustls::TlsConnector::from(Arc::new(client_config));
    let (accepted, connected) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(
            acceptor.accept(server, ()),
            connector.connect(ServerName::try_from("localhost").unwrap(), client.compat())
        )
    })
    .await
    .unwrap();
    let error = accepted.expect_err("ACME challenge reached the HTTP service");
    assert_eq!(error.to_string(), "TLS-ALPN-01 validation request");
    let stream = connected.expect("ACME validation handshake failed");
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"acme-tls/1"[..]));
}

#[tokio::test]
async fn malformed_handshake_is_rejected() {
    let (acceptor, _) = fixture();
    let (mut client, server) = tokio::io::duplex(4096);
    client.write_all(b"not a TLS handshake").await.unwrap();
    drop(client);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        acceptor.accept(server, ()),
    )
    .await
    .unwrap();
    assert!(result.is_err());
}
