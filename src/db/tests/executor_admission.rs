const EXECUTOR_ADMISSION_TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const EXECUTOR_ADMISSION_FAILSAFE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(10);

async fn await_after_first_pending<F>(
    future: F,
    pending_sender: tokio::sync::oneshot::Sender<()>,
) -> F::Output
where
    F: std::future::Future,
{
    tokio::pin!(future);
    let mut pending_sender = Some(pending_sender);
    std::future::poll_fn(|context| {
        match std::future::Future::poll(future.as_mut(), context) {
            std::task::Poll::Pending => {
                let _ = pending_sender
                    .take()
                    .expect("the future must announce Pending exactly once")
                    .send(());
                std::task::Poll::Ready(())
            }
            std::task::Poll::Ready(_) => {
                panic!("the synchronized test future completed before reaching Pending")
            }
        }
    })
    .await;
    future.await
}

#[tokio::test(flavor = "current_thread")]
async fn queued_transfer_writers_leave_runtime_capacity_for_reads() {
    let directory = tempfile::tempdir().unwrap();
    let database = Database::open(directory.path().join("data.sqlite")).unwrap();
    let (holder_entered_sender, holder_entered_receiver) = tokio::sync::oneshot::channel();
    let (release_holder_sender, release_holder_receiver) = std::sync::mpsc::channel();
    let holder_database = database.clone();
    let holder = tokio::spawn(async move {
        execute_transfer_database_operation(
            holder_database,
            "transfer_write",
            move |database| {
                let _write_guard = database.transfer_write_guard()?;
                let _ = holder_entered_sender.send(());
                let _ = release_holder_receiver.recv_timeout(EXECUTOR_ADMISSION_FAILSAFE_TIMEOUT);
                Ok::<_, rusqlite::Error>(())
            },
        )
        .await
    });
    tokio::time::timeout(EXECUTOR_ADMISSION_TEST_TIMEOUT, holder_entered_receiver)
        .await
        .expect("the transfer writer holder must enter its blocking operation")
        .expect("the transfer writer holder must announce entry");

    let mut queued_writers = Vec::new();
    for index in 0..3 {
        let writer_database = database.clone();
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let writer = tokio::spawn(async move {
            await_after_first_pending(
                execute_transfer_database_operation(
                    writer_database,
                    "transfer_write",
                    move |database| {
                        database.cancel_upload_reservation(&format!("queued-writer-{index}"))
                    },
                ),
                started_sender,
            )
            .await
        });
        tokio::time::timeout(EXECUTOR_ADMISSION_TEST_TIMEOUT, started_receiver)
            .await
            .expect("a queued transfer writer must be polled")
            .expect("a queued transfer writer must announce its start");
        assert!(!writer.is_finished());
        queued_writers.push(writer);
    }

    // The holder owns one composite writer/global permit. On this
    // current-thread runtime each start announcement above is sent only after
    // the executor returns Pending. Queued writers must therefore be waiting
    // on writer admission without consuming the three remaining global permits.
    let runtime_permits_before_read = database.runtime_available_permits();
    database
        .readiness_check()
        .expect("a direct connection remains available while transfer writers queue");
    let runtime_read = tokio::time::timeout(
        EXECUTOR_ADMISSION_TEST_TIMEOUT,
        execute_database_operation(database.clone(), "read", |database| {
            database.readiness_check()
        }),
    )
    .await;

    let _ = release_holder_sender.send(());
    tokio::time::timeout(EXECUTOR_ADMISSION_TEST_TIMEOUT, holder)
        .await
        .expect("the transfer writer holder must finish after release")
        .expect("the transfer writer holder task must not panic")
        .expect("the transfer writer holder operation must succeed");
    for writer in queued_writers {
        let cancelled = tokio::time::timeout(EXECUTOR_ADMISSION_TEST_TIMEOUT, writer)
            .await
            .expect("a queued transfer writer must finish after holder release")
            .expect("a queued transfer writer task must not panic")
            .expect("a queued transfer writer operation must succeed");
        assert!(!cancelled);
    }

    assert_eq!(
        runtime_permits_before_read, 3,
        "queued transfer writers must not consume global runtime permits"
    );
    match runtime_read {
        Ok(Ok(())) => {}
        Ok(Err(error)) => panic!("queued transfer writers starved a runtime read: {error:?}"),
        Err(_) => panic!("runtime read did not finish within the bounded test deadline"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_transfer_writer_waiter_releases_its_queue_position() {
    let directory = tempfile::tempdir().unwrap();
    let database = Database::open(directory.path().join("data.sqlite")).unwrap();
    let (holder_entered_sender, holder_entered_receiver) = tokio::sync::oneshot::channel();
    let (release_holder_sender, release_holder_receiver) = std::sync::mpsc::channel();
    let (holder_finished_sender, holder_finished_receiver) = tokio::sync::oneshot::channel();
    let holder_database = database.clone();
    let holder = tokio::spawn(async move {
        execute_transfer_database_operation(
            holder_database,
            "transfer_write",
            move |database| {
                let _write_guard = database.transfer_write_guard()?;
                let _ = holder_entered_sender.send(());
                let _ = release_holder_receiver.recv_timeout(EXECUTOR_ADMISSION_FAILSAFE_TIMEOUT);
                let _ = holder_finished_sender.send(());
                Ok::<_, rusqlite::Error>(())
            },
        )
        .await
    });
    tokio::time::timeout(EXECUTOR_ADMISSION_TEST_TIMEOUT, holder_entered_receiver)
        .await
        .expect("the transfer writer holder must enter its blocking operation")
        .expect("the transfer writer holder must announce entry");
    let permits_before_holder_cancellation = database.runtime_available_permits();
    holder.abort();
    let holder_cancelled = tokio::time::timeout(EXECUTOR_ADMISSION_TEST_TIMEOUT, holder)
        .await
        .expect("the aborted holder future must resolve")
        .expect_err("the holder future must report cancellation");
    assert!(holder_cancelled.is_cancelled());
    let permits_after_holder_cancellation = database.runtime_available_permits();

    let queued_database = database.clone();
    let (queued_started_sender, queued_started_receiver) = tokio::sync::oneshot::channel();
    let queued = tokio::spawn(async move {
        await_after_first_pending(
            execute_transfer_database_operation(
                queued_database,
                "transfer_write",
                |database| database.cancel_upload_reservation("cancelled-queued-writer"),
            ),
            queued_started_sender,
        )
        .await
    });
    tokio::time::timeout(EXECUTOR_ADMISSION_TEST_TIMEOUT, queued_started_receiver)
        .await
        .expect("the queued writer must be polled")
        .expect("the queued writer must announce its start");
    assert!(!queued.is_finished());
    let permits_while_writer_queued = database.runtime_available_permits();
    queued.abort();
    let queued_cancelled = tokio::time::timeout(EXECUTOR_ADMISSION_TEST_TIMEOUT, queued)
        .await
        .expect("the cancelled queued writer future must resolve")
        .expect_err("the queued writer future must report cancellation");
    assert!(queued_cancelled.is_cancelled());
    let permits_after_queued_cancellation = database.runtime_available_permits();

    let _ = release_holder_sender.send(());
    tokio::time::timeout(
        EXECUTOR_ADMISSION_TEST_TIMEOUT,
        holder_finished_receiver,
    )
    .await
    .expect("the detached blocking holder must finish after release")
    .expect("the detached blocking holder must announce completion");
    let replacement = tokio::time::timeout(
        EXECUTOR_ADMISSION_TEST_TIMEOUT,
        execute_transfer_database_operation(
            database,
            "transfer_write",
            |database| database.cancel_upload_reservation("replacement-writer"),
        ),
    )
    .await
    .expect("a replacement writer must not inherit a cancelled queue position")
    .expect("the replacement writer operation must succeed");

    assert!(!replacement);
    assert_eq!(permits_before_holder_cancellation, 3);
    assert_eq!(
        permits_after_holder_cancellation, 3,
        "cancelling the async owner must not release a permit still held by blocking work"
    );
    assert_eq!(
        permits_while_writer_queued, 3,
        "a queued transfer writer must wait before global admission"
    );
    assert_eq!(
        permits_after_queued_cancellation, 3,
        "cancelling a queued transfer writer must not leak global admission"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn transfer_writer_admission_uses_one_timeout_across_both_queues() {
    let directory = tempfile::tempdir().unwrap();
    let database = Database::open(directory.path().join("data.sqlite")).unwrap();
    let transfer_holder = database
        .acquire_transfer_runtime_permit()
        .await
        .expect("the transfer holder must acquire writer and runtime admission");
    let mut held_runtime_permits = Vec::new();
    for _ in 0..3 {
        held_runtime_permits.push(
            database
                .acquire_runtime_permit()
                .await
                .expect("three runtime permits must be available"),
        );
    }

    // Queue a general runtime waiter before the candidate can reach the
    // global queue. It deterministically takes the transfer holder's global
    // permit after release and forces the candidate through both stages.
    let (catcher_started_sender, catcher_started_receiver) = tokio::sync::oneshot::channel();
    let (catcher_acquired_sender, catcher_acquired_receiver) = tokio::sync::oneshot::channel();
    let (release_catcher_sender, release_catcher_receiver) = tokio::sync::oneshot::channel();
    let catcher_database = database.clone();
    let catcher = tokio::spawn(async move {
        let _permit = await_after_first_pending(
            catcher_database.acquire_runtime_permit(),
            catcher_started_sender,
        )
            .await
            .expect("runtime admission must remain open");
        let _ = catcher_acquired_sender.send(());
        let _ = release_catcher_receiver.await;
    });
    tokio::time::timeout(EXECUTOR_ADMISSION_TEST_TIMEOUT, catcher_started_receiver)
        .await
        .expect("the global waiter must be polled")
        .expect("the global waiter must announce its start");
    assert!(!catcher.is_finished());

    let (candidate_started_sender, candidate_started_receiver) = tokio::sync::oneshot::channel();
    let candidate_database = database.clone();
    let candidate = tokio::spawn(async move {
        await_after_first_pending(
            execute_transfer_database_operation(
                candidate_database,
                "two_queue_transfer_write",
                |_| -> Result<(), rusqlite::Error> {
                    panic!("a writer exceeding the shared queue budget must not run")
                },
            ),
            candidate_started_sender,
        )
        .await
    });
    tokio::time::timeout(EXECUTOR_ADMISSION_TEST_TIMEOUT, candidate_started_receiver)
        .await
        .expect("the candidate writer must be polled")
        .expect("the candidate writer must announce its start");
    assert!(!candidate.is_finished());

    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_millis(750)).await;
    drop(transfer_holder);
    catcher_acquired_receiver
        .await
        .expect("the global waiter must acquire the released runtime permit");

    tokio::time::advance(std::time::Duration::from_millis(300)).await;
    tokio::task::yield_now().await;
    assert!(
        candidate.is_finished(),
        "writer admission must use one one-second budget across both queues"
    );
    let candidate_result = candidate
        .await
        .expect("the candidate writer task must not panic");

    drop(held_runtime_permits);
    let _ = release_catcher_sender.send(());
    catcher.await.expect("the global waiter task must not panic");
    tokio::time::resume();

    match candidate_result {
        Err(DatabaseExecutionError::Admission(admission)) => {
            assert_eq!(admission.class(), "two_queue_transfer_write");
        }
        result => panic!("writer admission must time out after the shared budget: {result:?}"),
    }
}

#[test]
fn typed_transfer_cleanup_queue_survives_immediate_runtime_shutdown() {
    let (_directory, database, transfer_share, upload_share) = cleanup_queue_test_database();
    assert_eq!(
        database
            .begin_transfer_lease(
                "shutdown-session",
                "shutdown-lease",
                transfer_share,
                "file.txt",
                "download",
            )
            .unwrap(),
        TransferLeaseBeginOutcome::NewLease
    );
    assert_eq!(
        database
            .begin_upload_reservation("shutdown-upload-reservation", upload_share, 0)
            .unwrap(),
        UploadReservationBeginOutcome::Reserved
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        // Keep the first cleanup pending while both typed jobs enter the same
        // FIFO. Dropping the runtime immediately after releasing this holder
        // must still wait for the synchronously scheduled blocking drain.
        let transfer_holder = database
            .acquire_transfer_runtime_permit()
            .await
            .expect("the transfer holder must acquire admission");
        let handle = tokio::runtime::Handle::current();
        database.enqueue_transfer_lease_cleanup(&handle, "shutdown-lease".into());
        database.enqueue_upload_reservation_cleanup(
            &handle,
            "shutdown-upload-reservation".into(),
        );
        drop(transfer_holder);
    });
    drop(runtime);

    assert_eq!(database.transfer_cleanup_queue_state_for_test(), (false, 0));
    assert_eq!(
        database
            .active_transfer_reservations(transfer_share)
            .unwrap(),
        0
    );
    assert_eq!(
        database.active_upload_reservations(upload_share).unwrap(),
        0
    );
}

#[test]
fn discarded_cleanup_worker_launch_allows_a_new_runtime_to_restart_cleanup() {
    let (_directory, database, _transfer_share, upload_share) = cleanup_queue_test_database();
    assert_eq!(
        database
            .begin_upload_reservation("discarded-launch", upload_share, 0)
            .unwrap(),
        UploadReservationBeginOutcome::Reserved
    );

    let closed_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let closed_handle = closed_runtime.handle().clone();
    drop(closed_runtime);
    database.enqueue_upload_reservation_cleanup(&closed_handle, "discarded-launch".into());
    wait_for_transfer_cleanup_queue_to_idle_blocking(&database);
    assert_eq!(
        database.active_upload_reservations(upload_share).unwrap(),
        1,
        "a closure discarded by a stopped runtime must not run database cleanup"
    );

    let replacement_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    replacement_runtime.block_on(async {
        database.enqueue_upload_reservation_cleanup(
            &tokio::runtime::Handle::current(),
            "discarded-launch".into(),
        );
        wait_for_transfer_cleanup_queue_to_idle(&database).await;
    });
    drop(replacement_runtime);

    assert_eq!(database.transfer_cleanup_queue_state_for_test(), (false, 0));
    assert_eq!(
        database.active_upload_reservations(upload_share).unwrap(),
        0,
        "a discarded launch must not leave a phantom worker blocking future cleanup"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn expired_transfer_cleanup_releases_admission_and_allows_worker_restart() {
    let (_directory, database, _transfer_share, upload_share) = cleanup_queue_test_database();
    assert_eq!(
        database
            .begin_upload_reservation("expired-cleanup", upload_share, 0)
            .unwrap(),
        UploadReservationBeginOutcome::Reserved
    );

    let runtime_capacity = database.runtime_available_permits();
    assert_eq!(runtime_capacity, 4);
    let mut held_runtime_permits = Vec::new();
    for _ in 0..runtime_capacity {
        held_runtime_permits.push(
            database
                .acquire_runtime_permit()
                .await
                .expect("all runtime permits must be acquirable"),
        );
    }
    let handle = tokio::runtime::Handle::current();
    database.enqueue_upload_reservation_cleanup(&handle, "expired-cleanup".into());
    wait_for_transfer_cleanup_queue_to_idle(&database).await;

    assert_eq!(
        database.active_upload_reservations(upload_share).unwrap(),
        1,
        "cleanup whose admission deadline expires must leave the reservation for TTL cleanup"
    );
    drop(held_runtime_permits);
    assert_eq!(database.runtime_available_permits(), runtime_capacity);

    assert_eq!(
        database
            .begin_upload_reservation("replacement-cleanup", upload_share, 0)
            .unwrap(),
        UploadReservationBeginOutcome::Reserved
    );
    database.enqueue_upload_reservation_cleanup(&handle, "replacement-cleanup".into());
    wait_for_transfer_cleanup_queue_to_idle(&database).await;

    assert_eq!(
        database.active_upload_reservations(upload_share).unwrap(),
        1,
        "an expired job must not leave worker_active set or stall a replacement cleanup"
    );
    assert_eq!(database.runtime_available_permits(), runtime_capacity);
    assert!(database.cancel_upload_reservation("expired-cleanup").unwrap());
}

async fn wait_for_transfer_cleanup_queue_to_idle(database: &Database) {
    tokio::time::timeout(EXECUTOR_ADMISSION_TEST_TIMEOUT, async {
        loop {
            if database.transfer_cleanup_queue_state_for_test() == (false, 0) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the transfer cleanup queue must become idle within its bounded deadline");
}

fn wait_for_transfer_cleanup_queue_to_idle_blocking(database: &Database) {
    let deadline = std::time::Instant::now() + EXECUTOR_ADMISSION_TEST_TIMEOUT;
    while database.transfer_cleanup_queue_state_for_test() != (false, 0) {
        assert!(
            std::time::Instant::now() < deadline,
            "the discarded cleanup launch must restore the idle queue state"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn cleanup_queue_test_database() -> (tempfile::TempDir, Database, i64, i64) {
    let directory = tempfile::tempdir().unwrap();
    let database = Database::open(directory.path().join("data.sqlite")).unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let transfer_share = database
        .create_share(
            "cleanup-transfer-share",
            None,
            "file.txt",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let upload_share = database
        .create_share_with_upload_limits(
            "cleanup-upload-share",
            None,
            "uploads",
            true,
            &Permission::UploadOnly,
            None,
            None,
            Some(10),
            Some(100),
            Some(10),
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    (directory, database, transfer_share, upload_share)
}
