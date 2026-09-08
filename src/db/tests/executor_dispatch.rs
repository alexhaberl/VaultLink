const EXECUTOR_DISPATCH_TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[tokio::test(flavor = "current_thread")]
async fn queued_general_work_starts_without_repolling_the_runtime() {
    let directory = tempfile::tempdir().unwrap();
    let database = Database::open(directory.path().join("data.sqlite")).unwrap();
    let mut general_holders = Vec::new();
    for _ in 0..3 {
        general_holders.push(database.acquire_runtime_permit().await.unwrap());
    }
    let transfer_holder = database.acquire_transfer_runtime_permit().await.unwrap();
    let (completed_sender, completed_receiver) = std::sync::mpsc::channel();
    let mut reader = Box::pin(execute_database_operation(
        database.clone(),
        "unpolled_read",
        move |database| {
            let result = database.admin_count();
            let _ = completed_sender.send(());
            result
        },
    ));
    assert!(futures_util::poll!(reader.as_mut()).is_pending());

    // Release only general capacity. The held transfer slot prevents borrowing
    // from concealing an unused general slot assigned to the suspended waiter.
    drop(general_holders.pop());
    // This deliberately blocks the only async runtime thread. The operation
    // was already submitted and must run without another poll of its response
    // future or any other async task. The timeout is only a deadlock failsafe.
    let completed = completed_receiver.recv_timeout(EXECUTOR_DISPATCH_TEST_TIMEOUT);
    drop(general_holders);
    drop(transfer_holder);
    completed.expect("released general capacity must start submitted SQL without runtime polling");
    assert_eq!(reader.await.unwrap(), 0);
    assert_eq!(database.runtime_available_permits(), 4);
}

#[tokio::test(flavor = "current_thread")]
async fn queued_transfer_work_preserves_fifo_without_repolling_the_runtime() {
    let directory = tempfile::tempdir().unwrap();
    let database = Database::open(directory.path().join("data.sqlite")).unwrap();
    let holder = database.acquire_transfer_runtime_permit().await.unwrap();
    let (completed_sender, completed_receiver) = std::sync::mpsc::channel();
    let mut writers = Vec::new();
    for index in 0..3 {
        let completed_sender = completed_sender.clone();
        let mut writer = Box::pin(execute_transfer_database_operation(
            database.clone(),
            "unpolled_transfer_write",
            move |database| {
                let result = database.cancel_upload_reservation(&format!("unpolled-{index}"));
                let _ = completed_sender.send(index);
                result
            },
        ));
        // A single poll records submission order while the writer lane is
        // held. Keep every response future alive, but do not poll it again.
        assert!(futures_util::poll!(writer.as_mut()).is_pending());
        writers.push(writer);
    }
    drop(completed_sender);
    drop(holder);

    let completed: Result<Vec<_>, _> = (0..3)
        .map(|_| completed_receiver.recv_timeout(EXECUTOR_DISPATCH_TEST_TIMEOUT))
        .collect();
    assert_eq!(
        completed.expect("queued SQL must keep progressing while the async runtime is unpolled"),
        vec![0, 1, 2],
        "serialized transfer work must retain its submission order"
    );
    for writer in writers {
        assert!(!writer.await.unwrap());
    }
    assert_eq!(database.runtime_available_permits(), 4);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_queued_work_does_not_run_or_block_unpolled_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let database = Database::open(directory.path().join("data.sqlite")).unwrap();
    let holder = database.acquire_transfer_runtime_permit().await.unwrap();
    let cancelled_executions = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let executions = cancelled_executions.clone();
    let mut cancelled = Box::pin(execute_transfer_database_operation(
        database.clone(),
        "cancelled_unpolled_transfer_write",
        move |database| {
            executions.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            database.cancel_upload_reservation("cancelled-unpolled")
        },
    ));
    assert!(futures_util::poll!(cancelled.as_mut()).is_pending());
    // The held writer lane proves cancellation happens before SQL can start.
    drop(cancelled);

    let (completed_sender, completed_receiver) = std::sync::mpsc::channel();
    let mut replacement = Box::pin(execute_transfer_database_operation(
        database.clone(),
        "unpolled_replacement_transfer_write",
        move |database| {
            let result = database.cancel_upload_reservation("unpolled-replacement");
            let _ = completed_sender.send(());
            result
        },
    ));
    assert!(futures_util::poll!(replacement.as_mut()).is_pending());
    drop(holder);

    completed_receiver
        .recv_timeout(EXECUTOR_DISPATCH_TEST_TIMEOUT)
        .expect("a cancelled submission must not block replacement SQL without runtime polling");
    assert!(!replacement.await.unwrap());
    assert_eq!(
        cancelled_executions.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "dropping a queued response future must prevent its SQL operation"
    );
    assert_eq!(database.runtime_available_permits(), 4);
}
