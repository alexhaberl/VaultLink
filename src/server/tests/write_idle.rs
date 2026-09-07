use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CHUNK: usize = 64 * 1024;

fn connection(
    lifetime: Duration,
) -> (
    tokio::io::DuplexStream,
    ConnectionLimitedIo<tokio::io::DuplexStream>,
) {
    let peer = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let (client, server) = tokio::io::duplex(CHUNK);
    let limited = ConnectionLimitedIo {
        inner: server,
        _permit: ConnectionPermit {
            _global: Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
            peer_connections: Arc::new(Mutex::new(HashMap::from([(peer, 1)]))),
            peer,
            maximum: 1,
        },
        write_timeout: None,
        write_idle_timeout: RESPONSE_WRITE_IDLE_TIMEOUT,
        connection_deadline: Box::pin(tokio::time::sleep(lifetime)),
    };
    (client, limited)
}

async fn write_payload<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
    vectored: bool,
) -> io::Result<()> {
    if !vectored {
        return writer.write_all(payload).await;
    }
    let mut offset = 0;
    while offset < payload.len() {
        let rest = &payload[offset..];
        let split = rest.len() / 2;
        let count = writer
            .write_vectored(&[
                io::IoSlice::new(&rest[..split]),
                io::IoSlice::new(&rest[split..]),
            ])
            .await?;
        assert!(count > 0, "unexpected zero write");
        offset += count;
    }
    Ok(())
}

async fn progressing_reader(vectored: bool, lifetime: Duration, expect_absolute_timeout: bool) {
    const PAYLOAD: usize = 32 * CHUNK;
    let (mut client, mut limited) = connection(lifetime);
    let start = tokio::time::Instant::now();
    let writer = async move {
        let result = write_payload(&mut limited, &vec![b'x'; PAYLOAD], vectored).await;
        drop(limited);
        result
    };
    let reader = async move {
        let mut total = 0;
        let mut chunk = vec![0; CHUNK];
        loop {
            let count = client.read(&mut chunk).await.unwrap();
            if count == 0 {
                break;
            }
            assert!(chunk[..count].iter().all(|byte| *byte == b'x'));
            total += count;
            // 32 KiB/s: active for longer than one idle window, with frequent
            // short writes caused by the bounded transport buffer.
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        total
    };
    let (result, received) = tokio::join!(writer, reader);
    if expect_absolute_timeout {
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error
            .to_string()
            .contains("absolute HTTP connection lifetime"));
        assert!(received > 0 && received < PAYLOAD);
        assert!(start.elapsed() >= lifetime);
    } else {
        result.expect("ongoing write progress must renew the idle deadline");
        assert_eq!(received, PAYLOAD);
        assert!(start.elapsed() > RESPONSE_WRITE_IDLE_TIMEOUT);
    }
}

#[tokio::test(start_paused = true)]
async fn scalar_partial_writes_renew_idle_deadline() {
    progressing_reader(false, Duration::from_secs(3600), false).await;
}

#[tokio::test(start_paused = true)]
async fn vectored_partial_writes_renew_idle_deadline() {
    progressing_reader(true, Duration::from_secs(3600), false).await;
}

#[tokio::test(start_paused = true)]
async fn progress_does_not_extend_absolute_connection_lifetime() {
    for vectored in [false, true] {
        progressing_reader(vectored, Duration::from_secs(40), true).await;
    }
}

#[tokio::test(start_paused = true)]
async fn stalled_writes_expire_after_last_progress() {
    for vectored in [false, true] {
        let (mut client, mut limited) = connection(Duration::from_secs(3600));
        let start = tokio::time::Instant::now();
        let writer =
            async move { write_payload(&mut limited, &vec![b'x'; 4 * CHUNK], vectored).await };
        let reader = async move {
            tokio::time::sleep(Duration::from_secs(20)).await;
            let mut chunk = vec![0; CHUNK];
            client.read_exact(&mut chunk).await.unwrap();
            // Keep the reader open without reading again; dropping it would
            // produce BrokenPipe instead of exercising the idle deadline.
            (client, chunk)
        };
        let (result, (_client, chunk)) = tokio::join!(writer, reader);
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("write made no progress"));
        assert!(chunk.iter().all(|byte| *byte == b'x'));
        assert_eq!(start.elapsed(), Duration::from_secs(50));
    }
}
