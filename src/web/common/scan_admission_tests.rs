#[cfg(test)]
mod scan_admission_tests {
    use super::ScanAdmission;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    #[tokio::test]
    async fn cancelled_scan_holds_both_permits_until_worker_exits() {
        for panic_after_release in [false, true] {
            let counts = Arc::new(Mutex::new(HashMap::new()));
            let peer = "192.0.2.1".parse().unwrap();
            let client =
                crate::http_auth::try_acquire_client_activity(counts.clone(), peer, 1).unwrap();
            let capacity = Arc::new(tokio::sync::Semaphore::new(1));
            let admission =
                ScanAdmission::new(client, capacity.clone().try_acquire_owned().unwrap());
            let weak = Arc::downgrade(&admission);
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let worker = admission.spawn_blocking(move || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                assert!(!panic_after_release, "injected worker panic");
            });
            entered_rx.await.unwrap();
            worker.abort();
            assert_eq!(capacity.available_permits(), 0);
            assert!(
                crate::http_auth::try_acquire_client_activity(counts.clone(), peer, 1).is_none()
            );
            assert!(weak.upgrade().is_some());
            release_tx.send(()).unwrap();
            assert_eq!(worker.await.is_err(), panic_after_release);
            assert_eq!(capacity.available_permits(), 1);
            assert!(counts.lock().unwrap().is_empty());
            assert!(weak.upgrade().is_none());
        }
    }
}
