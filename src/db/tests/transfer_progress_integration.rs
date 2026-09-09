// Included inside dispatch::tests to exercise its real admission future with
// the existing controlled monotonic clock, without sleeping through a timeout.
#[tokio::test(flavor = "current_thread")]
async fn completed_transfer_worker_admits_a_fifo_successor_past_one_second() {
    let database = Database::open(":memory:").unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let predecessor = dispatch_transfer_database_work(
        database.clone(),
        "progress_predecessor",
        move |database, permit| {
            let _permit = permit;
            let count = database.admin_count().unwrap();
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            count
        },
    )
    .await
    .unwrap();
    entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();

    let started = Instant::now();
    let initial_deadline = started + DATABASE_QUEUE_TIMEOUT;
    let admission_database = database.clone();
    let (sender, mut receiver) = oneshot::channel::<LaunchedWork<i64>>();
    let pending_transfer = database
        .0
        .transfer_queue_admission
        .clone()
        .try_acquire_owned()
        .unwrap();
    let mut candidate = DatabaseJob {
        database: database.clone(),
        class: "progress_successor",
        started,
        deadline: initial_deadline,
        progress_budget: Some(TransferAdmissionBudget::new(started)),
        pending_transfer: Some(pending_transfer),
        admission: Some(Box::pin(async move {
            admission_database.acquire_transfer_runtime_permit().await
        })),
        operation: Some(|database: Database, permit: TransferDatabasePermit| {
            let _permit = permit;
            database.admin_count().unwrap()
        }),
        sender: Some(sender),
        handle: Handle::current(),
        subscriber: tracing::dispatcher::get_default(Clone::clone),
        span: tracing::Span::none(),
        timing: Some(database.0.work_diagnostics.start("progress_successor")),
    };
    let mut context = Context::from_waker(Waker::noop());
    assert!(candidate
        .poll_with_clock(&mut context, || started)
        .is_pending());

    release_tx.send(()).unwrap();
    assert_eq!(predecessor.await.unwrap(), 0);

    // The predecessor really executed and dropped its permit. Poll just past
    // the original deadline: a fixed one-second budget rejects this, while
    // the actual worker completion extends the same composite acquisition.
    let after_original_timeout = initial_deadline + Duration::from_nanos(1);
    assert!(candidate
        .poll_with_clock(&mut context, || after_original_timeout)
        .is_ready());
    let worker = receiver
        .try_recv()
        .unwrap()
        .expect("actual preceding transfer work must renew the queued admission budget");
    assert!(candidate.deadline > initial_deadline);
    assert_eq!(worker.await.unwrap(), 0);
    assert_eq!(database.runtime_available_permits(), 1);
    assert_eq!(database.0.transfer_runtime_admission.available_permits(), 1);
    assert_eq!(database.0.transfer_queue_admission.available_permits(), 128);
}
