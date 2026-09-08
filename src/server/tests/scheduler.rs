use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn external_completions_are_polled_before_the_local_backlog_drains() {
    let runtime = server_runtime_builder().worker_threads(1).build().unwrap();
    let local_polls = Arc::new(AtomicUsize::new(0));
    let worker_polls = local_polls.clone();
    let (queued_sender, queued_receiver) = std::sync::mpsc::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::channel();
    let backlog = runtime.spawn(async move {
        // Stay below Tokio's local-queue capacity so the local backlog does
        // not itself spill into the global queue used by external wakeups.
        for _ in 0..128 {
            let polls = worker_polls.clone();
            tokio::spawn(async move {
                polls.fetch_add(1, Ordering::Relaxed);
            });
        }
        queued_sender.send(()).unwrap();
        // Test-only handshake: the sole worker must not consume its backlog
        // before the main thread has enqueued the external completion.
        release_receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
    });
    queued_receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    let completion = runtime.spawn(async move { local_polls.load(Ordering::Relaxed) });
    release_sender.send(()).unwrap();
    let observed = runtime.block_on(async {
        let result = tokio::time::timeout(Duration::from_secs(5), completion)
            .await
            .unwrap()
            .unwrap();
        backlog.await.unwrap();
        result
    });
    runtime.shutdown_timeout(Duration::ZERO);
    assert!(observed > 0, "local work must continue to make progress");
    assert!(
        observed <= 8,
        "external completion waited behind {observed} local polls"
    );
}

#[test]
fn local_work_is_polled_before_the_external_backlog_drains() {
    let runtime = server_runtime_builder().worker_threads(1).build().unwrap();
    let external_polls = Arc::new(AtomicUsize::new(0));
    let worker_polls = external_polls.clone();
    let (queued_sender, queued_receiver) = std::sync::mpsc::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::channel();
    let local = runtime.spawn(async move {
        let completion = tokio::spawn(async move { worker_polls.load(Ordering::Relaxed) });
        // Displace the completion from Tokio's immediate LIFO slot into its
        // ordinary local queue, where older request work must also progress.
        tokio::spawn(async {});
        queued_sender.send(()).unwrap();
        release_receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        completion.await.unwrap()
    });
    queued_receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    for _ in 0..128 {
        let polls = external_polls.clone();
        runtime.spawn(async move {
            polls.fetch_add(1, Ordering::Relaxed);
        });
    }
    release_sender.send(()).unwrap();
    let observed = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), local)
            .await
            .unwrap()
            .unwrap()
    });
    runtime.shutdown_timeout(Duration::ZERO);
    assert!(
        observed <= 8,
        "local work waited behind {observed} external polls"
    );
}
