use super::*;
use crate::db::{Permission, UploadConflictStrategy};
use std::{
    io::Write,
    sync::{Arc, Mutex},
    time::Duration,
};

#[tokio::test]
async fn unclaimed_public_lease_does_not_hold_admission_and_still_cancels() {
    let directory = tempfile::tempdir().unwrap();
    let database = Database::open(directory.path().join("database.sqlite")).unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share = database
        .create_share(
            "handoff",
            None,
            "file.txt",
            false,
            &Permission::DownloadOnly,
            None,
            Some(2),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let pending = begin_transfer_lease_cancellation_safe(
        database.clone(),
        "session".into(),
        "lease".into(),
        share,
        "file.txt".into(),
        "download",
    )
    .await
    .unwrap_or_else(|_| panic!("public lease begin failed"));
    assert!(matches!(
        pending.outcome,
        TransferLeaseBeginOutcome::NewLease
    ));
    let progress = crate::db::execute_transfer_database_operation(
        database.clone(),
        "handoff_progress",
        |_db| Ok::<_, rusqlite::Error>(()),
    )
    .await;
    drop(pending);
    tokio::time::timeout(Duration::from_secs(3), async {
        while database.active_transfer_reservations(share).unwrap() != 0 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("unclaimed public lease must be compensated");
    assert!(
        progress.is_ok(),
        "HTTP ownership wait retained DB admission: {progress:?}"
    );
}

#[derive(Clone)]
struct Output(Arc<Mutex<Vec<u8>>>);
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn public_transfer_capacity_reports_waiter_and_owner_phase() {
    let _tracing_guard = crate::test_support::tracing_subscriber_guard();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let directory = tempfile::tempdir().unwrap();
        let database = Database::open(directory.path().join("SECRET_DATABASE.sqlite")).unwrap();
        let holder = database.acquire_transfer_runtime_permit().await.unwrap();
        holder.begin_work("upload_reservation_begin");
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = Output(bytes.clone());
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || writer.clone())
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let result =
            dispatch_transfer_work::<(), _>(database.clone(), "transfer_complete", |_, _| {
                panic!("an operation rejected by admission must not start")
            })
            .await;
        drop(holder);
        assert!(matches!(result, Err(PublicTransferError::Capacity)));
        assert!(crate::flush_best_effort_telemetry(Duration::from_secs(5)));
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        for expected in [
            "database.admission",
            "class=\"transfer_complete\"",
            "transfer_phase=\"upload_reservation_begin\"",
            "transfer_held_ms=",
            "transfer_phase_ms=",
            "runtime_available_permits=3",
            "general_available_permits=3",
            "transfer_available_permits=0",
            "scheduler_global_queue_depth=",
        ] {
            assert!(output.contains(expected), "missing {expected}: {output}");
        }
        assert!(!output.contains("SECRET"));
        let released = database.runtime_admission_state();
        assert_eq!(released.transfer_phase, None);
        assert_eq!(released.transfer_available, 1);
    });
}
