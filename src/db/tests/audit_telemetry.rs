mod audit_telemetry_tests {
    use super::*;
    use std::{
        io,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        time::Duration as StdDuration,
    };

    #[derive(Clone)]
    struct BlockingAuditWriter {
        database: Database,
        entered: std::sync::mpsc::Sender<(usize, usize, bool, i64)>,
        release: Arc<Mutex<std::sync::mpsc::Receiver<()>>>,
        fired: Arc<AtomicBool>,
    }

    impl io::Write for BlockingAuditWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if String::from_utf8_lossy(bytes).contains("audit event")
                && !self.fired.swap(true, Ordering::SeqCst)
            {
                let audit_rows: i64 = self
                    .database
                    .conn()
                    .query_row(
                        "SELECT COUNT(*) FROM audit WHERE action='upload_quota_committed'",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
                let guard_locked = self.database.0.transfer_write_admission.try_lock().is_err();
                self.entered
                    .send((
                        self.database.runtime_available_permits(),
                        self.database
                            .0
                            .transfer_runtime_admission
                            .available_permits(),
                        guard_locked,
                        audit_rows,
                    ))
                    .unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(StdDuration::from_secs(10))
                    .unwrap();
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BlockingAuditWriter {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }

    #[test]
    fn slow_optional_audit_output_does_not_retain_transfer_capacity() {
        let _tracing_guard = crate::test_support::tracing_subscriber_guard();
        let directory = tempfile::tempdir().unwrap();
        let database = Database::open(directory.path().join("audit.sqlite")).unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let share = database
            .create_share_with_upload_limits(
                "upload",
                None,
                "folder",
                true,
                &Permission::UploadOnly,
                None,
                None,
                Some(10),
                Some(100),
                Some(2),
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        assert_eq!(
            database
                .begin_upload_reservation("reservation", share, 0)
                .unwrap(),
            UploadReservationBeginOutcome::Reserved
        );
        assert_eq!(
            database
                .extend_upload_reservation("reservation", 7)
                .unwrap(),
            UploadReservationExtendOutcome::Extended
        );
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::INFO)
            .with_writer(BlockingAuditWriter {
                database: database.clone(),
                entered: entered_tx,
                release: Arc::new(Mutex::new(release_rx)),
                fired: Arc::new(AtomicBool::new(false)),
            })
            .finish();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        tracing::subscriber::with_default(subscriber, || {
            runtime.block_on(async {
                let mut commit = Box::pin(execute_transfer_database_operation(
                    database.clone(),
                    "investigation_upload_commit",
                    move |db| {
                        db.commit_upload_reservation_and_audit(
                            "reservation",
                            7,
                            &AuditContext::new("public", None),
                        )
                    },
                ));
                let committed = match futures_util::poll!(commit.as_mut()) {
                    std::task::Poll::Ready(result) => Some(result),
                    std::task::Poll::Pending => None,
                };
                let observed = entered_rx.recv_timeout(StdDuration::from_secs(10)).unwrap();
                let (completed_tx, completed_rx) = std::sync::mpsc::channel();
                let mut following = Box::pin(execute_transfer_database_operation(
                    database.clone(),
                    "investigation_following_transfer",
                    move |db| {
                        let result = db.cancel_upload_reservation("nonexistent");
                        let _ = completed_tx.send(());
                        result
                    },
                ));
                let followed = match futures_util::poll!(following.as_mut()) {
                    std::task::Poll::Ready(result) => Some(result),
                    std::task::Poll::Pending => None,
                };
                let progressed_before_release =
                    completed_rx.recv_timeout(StdDuration::from_secs(3)).is_ok();
                release_tx.send(()).unwrap();
                let committed = match committed {
                    Some(result) => result,
                    None => commit.await,
                };
                let followed = match followed {
                    Some(result) => result,
                    None => following.await,
                };
                assert_eq!(
                    committed.unwrap(),
                    UploadReservationCommitOutcome::Committed
                );
                assert!(!followed.unwrap());
                assert_eq!(
                    observed.3, 1,
                    "required audit must already be committed before optional logging"
                );
                assert!(
                    progressed_before_release,
                    "a blocked optional audit sink must not retain transfer admission"
                );
                assert_eq!(database.runtime_available_permits(), 4);
            })
        });
        assert!(crate::flush_best_effort_telemetry(StdDuration::from_secs(
            5
        )));
    }
}
