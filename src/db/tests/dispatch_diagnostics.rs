mod dispatch_diagnostics {
    use super::*;
    use std::{
        io,
        sync::{Arc, Mutex},
        time::Duration,
    };

    #[derive(Clone)]
    struct TimingLogs {
        bytes: Arc<Mutex<Vec<u8>>>,
        capacity_at_write: Arc<Mutex<Vec<(usize, usize, usize)>>>,
        database: Database,
    }

    impl io::Write for TimingLogs {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            // Capture at the subscriber call, not after the HTTP future wakes:
            // logging itself must not delay release of any admission slot.
            let state = self.database.runtime_admission_state();
            self.capacity_at_write.lock().unwrap().push((
                state.runtime_available,
                state.general_available,
                state.transfer_available,
            ));
            self.bytes.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TimingLogs {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn info_summary_observes_blocking_queue_after_permit_release_without_request_fields() {
        let _tracing_guard = crate::test_support::tracing_subscriber_guard();
        let directory = tempfile::tempdir().unwrap();
        let database = Database::open(directory.path().join("SECRET_DATABASE.sqlite")).unwrap();
        let logs = TimingLogs {
            bytes: Arc::new(Mutex::new(Vec::new())),
            capacity_at_write: Arc::new(Mutex::new(Vec::new())),
            database: database.clone(),
        };
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter("info")
            .with_ansi(false)
            .without_time()
            .with_writer(logs.clone())
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let request = tracing::info_span!(
            "private_request",
            path = "/v/SECRET_PATH",
            token = "SECRET_TOKEN"
        );
        let _request = request.enter();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();

        runtime.block_on(async {
            let (entered_sender, entered_receiver) = tokio::sync::oneshot::channel();
            let (release_sender, release_receiver) = std::sync::mpsc::channel();
            let holder = tokio::task::spawn_blocking(move || {
                let _ = entered_sender.send(());
                // Dropping the sender on assertion failure also releases this
                // holder; the runtime cannot hang while unwinding the test.
                let _ = release_receiver.recv_timeout(Duration::from_secs(10));
            });
            tokio::time::timeout(Duration::from_secs(3), entered_receiver)
                .await
                .expect("the sole blocking worker must start")
                .expect("the blocking holder must announce entry");

            let mut read = Box::pin(execute_database_operation(
                database.clone(),
                "diagnostic_read",
                |database| database.admin_count(),
            ));
            assert!(futures_util::poll!(&mut read).is_pending());
            assert_eq!(
                database.runtime_available_permits(),
                3,
                "DB work must already be admitted while its worker is queued"
            );
            // Real elapsed time is intentional: the production diagnostic
            // uses std::time::Instant, not Tokio's optionally paused clock.
            tokio::time::sleep(Duration::from_millis(150)).await;
            release_sender.send(()).unwrap();
            let result = tokio::time::timeout(Duration::from_secs(3), read)
                .await
                .expect("one blocking worker must suffice after holder release")
                .expect("the queued read must finish successfully");
            holder.await.expect("the holder must not panic");
            assert_eq!(result, 0);
            assert_eq!(database.runtime_available_permits(), 4);
        });

        let output = String::from_utf8(logs.bytes.lock().unwrap().clone()).unwrap();
        let summaries: Vec<_> = output
            .lines()
            .filter(|line| line.contains("operation=\"database.executor\""))
            .collect();
        assert_eq!(summaries.len(), 1, "{output}");
        let summary = summaries[0];
        assert!(summary.contains("INFO"), "{summary}");
        assert!(summary.contains("class=\"diagnostic_read\""), "{summary}");
        assert!(timing_field(summary, "job_id") > 0, "{summary}");
        assert!(timing_field(summary, "worker_queue_ms") >= 100, "{summary}");
        let _worker_duration = timing_field(summary, "worker_duration_ms");
        assert!(!output.contains("SECRET"), "{output}");
        assert!(!output.contains("private_request"), "{output}");
        let observed = logs.capacity_at_write.lock().unwrap();
        assert!(
            !observed.is_empty(),
            "the real worker must emit an INFO event"
        );
        assert!(
            observed.iter().all(|capacity| *capacity == (4, 3, 1)),
            "the subscriber observed retained DB admission: {observed:?}"
        );
    }

    fn timing_field(line: &str, field: &str) -> u64 {
        let prefix = format!("{field}=");
        line.split_whitespace()
            .find_map(|word| word.strip_prefix(&prefix))
            .unwrap_or_else(|| panic!("missing {field}: {line}"))
            .parse()
            .unwrap_or_else(|error| panic!("invalid {field}: {error}: {line}"))
    }
}
