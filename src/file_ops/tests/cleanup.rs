#[tokio::test]
async fn delete_reports_pending_and_retries_cleanup_start_and_batch_failures() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("tree")).unwrap();
    std::fs::write(root.path().join("tree/child.txt"), b"content").unwrap();
    let state = test_state(root.path(), data.path());
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_share(
            "tree-token",
            None,
            "tree",
            true,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();

    // Hold the sole worker until the synchronous result and durable
    // tombstone can be asserted. Its first broad scan fails to start; the
    // following attempt fails in run_batch.
    let cleanup_guard = state
        .storage_cleanup()
        .serialization_for_test()
        .lock_owned()
        .await;
    state
        .secure_root()
        .fail_next_cleanup_starts(io::ErrorKind::Other, 1);
    state
        .secure_root()
        .fail_next_cleanup_batch(io::ErrorKind::Other);
    let cleanup_worker = state.start_storage_cleanup_worker().unwrap();

    let result = authorized(
        delete(
            &state,
            mfa_proof(&state),
            "tree",
            Some("tree"),
            AuditContext::system(),
        )
        .await
        .unwrap(),
    );
    assert!(result.cleanup_pending);
    assert_eq!(result.deactivated_shares, 1);
    assert!(!root.path().join("tree").exists());
    assert_eq!(tombstone_paths(root.path()).len(), 1);
    assert!(
        !state
            .db()
            .share_by_token("tree-token")
            .unwrap()
            .unwrap()
            .active
    );

    drop(cleanup_guard);
    for _ in 0..200 {
        if tombstone_paths(root.path()).is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(
        tombstone_paths(root.path()).is_empty(),
        "cleanup did not recover after injected start and batch failures"
    );
    cleanup_worker.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cleanup_shutdown_waits_for_a_running_blocking_batch() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
    state.secure_root().before_next_cleanup_batch(move || {
        entered_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    });
    let worker = state.start_storage_cleanup_worker().unwrap();

    tokio::task::spawn_blocking(move || {
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("cleanup batch did not reach the test hook");
    })
    .await
    .unwrap();
    let mut shutdown = tokio::spawn(worker.shutdown());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut shutdown)
            .await
            .is_err(),
        "shutdown returned before the running blocking batch finished"
    );

    release_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), &mut shutdown)
        .await
        .expect("cleanup worker did not stop after the blocking batch returned")
        .unwrap()
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        state.storage_cleanup().serialization_for_test().lock_owned(),
    )
    .await
    .expect("cleanup mutex was not released after the worker stopped");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cleanup_shutdown_does_not_launch_the_next_batch() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let upload_staging = root
        .path()
        .join(crate::config::DEFAULT_INTERNAL_DIRECTORY_NAME)
        .join("uploads");
    for index in 0..=crate::storage_cleanup::CLEANUP_BATCH_ENTRIES {
        std::fs::write(
            upload_staging.join(format!(".vaultlink-{index:024}.part")),
            b"",
        )
        .unwrap();
    }
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
    state.secure_root().before_next_cleanup_batch(move || {
        entered_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    });
    let worker = state.start_storage_cleanup_worker().unwrap();
    tokio::task::spawn_blocking(move || {
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("cleanup batch did not reach the test hook");
    })
    .await
    .unwrap();

    worker.request_shutdown();
    let mut join = tokio::spawn(worker.join());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut join)
            .await
            .is_err(),
        "shutdown returned before the active batch finished"
    );
    release_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), &mut join)
        .await
        .expect("cleanup worker did not stop after the active batch")
        .unwrap()
        .unwrap();

    let remaining = std::fs::read_dir(upload_staging)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| crate::secure_fs::is_upload_fragment_name(&entry.file_name()))
        .count();
    assert!(remaining > 0, "shutdown launched another cleanup batch");
    assert!(
        remaining < crate::storage_cleanup::CLEANUP_BATCH_ENTRIES + 1,
        "the active cleanup batch did not finish"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cleanup_shutdown_wakes_an_idle_worker_without_starting_another_pass() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let worker = state.start_storage_cleanup_worker().unwrap();

    for _ in 0..100 {
        if state.storage_cleanup().pass_count_for_test() >= 1 {
            let guard = state
                .storage_cleanup()
                .serialization_for_test()
                .lock_owned()
                .await;
            drop(guard);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let completed_passes = state.storage_cleanup().pass_count_for_test();
    assert_eq!(completed_passes, 1);

    tokio::time::timeout(std::time::Duration::from_secs(1), worker.shutdown())
        .await
        .expect("idle cleanup worker did not wake for shutdown")
        .unwrap();
    assert_eq!(
        state.storage_cleanup().pass_count_for_test(),
        completed_passes
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cleanup_shutdown_cancels_a_wait_for_storage_authority() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    recover_pending_file_operations(&state).await.unwrap();
    let authority = state.acquire_storage_test_exclusive().await;
    let worker = state.start_storage_cleanup_worker().unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while state.storage_cleanup().pass_count_for_test() != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("cleanup worker did not begin its authority wait");
    assert_eq!(state.storage_cleanup().pass_count_for_test(), 1);
    tokio::time::timeout(std::time::Duration::from_secs(1), worker.shutdown())
        .await
        .expect("cleanup worker did not cancel its authority wait")
        .unwrap();
    drop(authority);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ten_thousand_cleanup_signals_keep_one_rate_limited_worker() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    state
        .secure_root()
        .fail_next_cleanup_starts(io::ErrorKind::Other, 10_000);

    for _ in 0..10_000 {
        state.storage_cleanup().request_cleanup();
    }
    let worker = state.start_storage_cleanup_worker().unwrap();
    assert!(matches!(
        state.storage_cleanup().start_worker(state.clone()),
        Err(crate::storage_cleanup::StorageCleanupStartError::AlreadyRunning)
    ));

    tokio::time::sleep(std::time::Duration::from_millis(90)).await;
    let attempts = state.storage_cleanup().pass_count_for_test();
    assert!(attempts >= 2, "the failed cleanup was not retried");
    assert!(
        attempts <= 5,
        "coalesced requests bypassed the retry deadline: {attempts} attempts"
    );
    worker.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cleanup_signal_during_a_scan_schedules_one_follow_up_pass() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let state = test_state(root.path(), data.path());
    let cleanup = state.storage_cleanup().clone();
    state.secure_root().before_next_cleanup_batch(move || {
        cleanup.request_cleanup();
    });
    let worker = state.start_storage_cleanup_worker().unwrap();

    for _ in 0..100 {
        if state.storage_cleanup().pass_count_for_test() >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(state.storage_cleanup().pass_count_for_test(), 2);
    worker.shutdown().await.unwrap();
}
