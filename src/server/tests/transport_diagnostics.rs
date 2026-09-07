use super::*;
use std::sync::Arc;

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

#[test]
fn warning_budget_reports_suppression_and_recovers() {
    let mut budget = Budget {
        started: None,
        emitted: 0,
        suppressed: 0,
    };
    let now = Instant::now();
    for _ in 0..EVENTS_PER_WINDOW {
        assert_eq!(budget.admit(now), Some(0));
    }
    assert_eq!(budget.admit(now), None);
    assert_eq!(budget.admit(now + WINDOW - Duration::from_millis(1)), None);
    assert_eq!(budget.admit(now + WINDOW), Some(2));
    assert_eq!(budget.admit(now + WINDOW), Some(0));
}

#[tokio::test(start_paused = true)]
async fn incomplete_connection_is_not_mislabelled_as_a_header_timeout() {
    let mut diagnostics = TransportDiagnostics::new(32100, 18081, 150);
    tokio::time::advance(Duration::from_secs(16)).await;
    assert_eq!(diagnostics.reason(), Some("closed_without_response"));
    diagnostics.read(7);
    assert_eq!(diagnostics.first_read_ms, Some(16000));
    diagnostics.wrote(3);
    assert_eq!(diagnostics.bytes_read, 7);
    assert_eq!(diagnostics.bytes_written, 3);
    assert_eq!(diagnostics.last_write_ms, Some(16000));
    assert_eq!(diagnostics.reason(), None);
    diagnostics.failure("write_idle_timeout");
    diagnostics.io_error(&io::Error::new(
        io::ErrorKind::TimedOut,
        "sensitive details",
    ));
    assert_eq!(diagnostics.reason(), Some("write_idle_timeout"));
}

#[test]
fn failure_logs_correlate_ports_and_exclude_raw_error_messages() {
    let _guard = crate::test_support::tracing_subscriber_guard();
    let logs = Logs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(logs.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let mut healthy = TransportDiagnostics::new(32099, 18081, 1);
        healthy.read(100);
        healthy.wrote(200);
        drop(healthy);
        let mut rejected = TransportDiagnostics::new(32100, 18081, 256);
        rejected.failure("global_connection_limit");
        drop(rejected);
        let mut failed = TransportDiagnostics::new(32101, 18081, 150);
        failed.read(17);
        failed.wrote(23);
        failed.io_error(&io::Error::new(
            io::ErrorKind::BrokenPipe,
            "SECRET_TOKEN /v/private?q=secret\nforged",
        ));
        drop(failed);
    });
    let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(output.contains("global_connection_limit"));
    assert!(output.contains("peer_port=32100"));
    assert!(output.contains("active_at_accept=256"));
    assert!(output.contains("peer_port=32101"));
    assert!(output.contains("bytes_read=17"));
    assert!(output.contains("bytes_written=23"));
    assert!(output.contains("broken_pipe"));
    assert!(!output.contains("32099"));
    assert!(!output.contains("SECRET"));
    assert!(!output.contains("/v/private"));
    assert!(!output.contains("forged"));
    assert_eq!(output.lines().count(), 2);
}

#[test]
fn real_http_header_close_records_ports_and_received_bytes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _guard = crate::test_support::tracing_subscriber_guard();
    let logs = Logs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(logs.clone())
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let handle = axum_server::Handle::<std::net::SocketAddr>::new();
        let mut server = axum_server::bind("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .map(|inner| crate::ConnectionLimitAcceptor::new(inner, None))
            .http1_only();
        crate::harden_http_server(&mut server);
        server
            .http_builder()
            .http1()
            .header_read_timeout(Some(Duration::from_millis(25)));
        let server_handle = handle.clone();
        let task = tokio::spawn(async move {
            server
                .handle(server_handle)
                .serve(axum::Router::new().into_make_service())
                .await
                .unwrap();
        });
        let address = handle.listening().await.unwrap();
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        let port = client.local_addr().unwrap().port();
        let incomplete = b"GET /SECRET_TOKEN HTTP/1.1\r\nHost: localhost\r\n";
        client.write_all(incomplete).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.is_empty());
        handle.shutdown();
        task.await.unwrap();
        let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        assert!(output.contains("closed_without_response"), "{output}");
        assert!(output.contains(&format!("peer_port={port}")));
        assert!(output.contains(&format!("bytes_read={}", incomplete.len())));
        assert!(output.contains("bytes_written=0"));
        assert!(!output.contains("SECRET_TOKEN"));
        assert!(!output.contains("header_timeout"));
    });
}
