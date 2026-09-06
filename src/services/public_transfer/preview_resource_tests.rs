use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountDrop(Arc<AtomicUsize>);

impl Drop for CountDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn read_result_retains_owner_and_errors_or_panics_release_it_once() {
    for fail in [false, true] {
        let drops = Arc::new(AtomicUsize::new(0));
        let result = read_preview_with_resources(CountDrop(drops.clone()), move || {
            if fail {
                Err(io::Error::other("injected read failure"))
            } else {
                Ok(PreviewContent::Text("preview".into()))
            }
        })
        .await
        .unwrap();
        assert_eq!(result.1.is_err(), fail);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(result);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let result = read_preview_with_resources(CountDrop(drops.clone()), || {
        panic!("injected preview read panic")
    })
    .await;
    assert!(result.err().unwrap().is_panic());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancelled_waiter_keeps_owner_until_detached_read_finishes() {
    let drops = Arc::new(AtomicUsize::new(0));
    let (entered, started) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let owner = CountDrop(drops.clone());
    let waiter = tokio::spawn(read_preview_with_resources(owner, move || {
        entered.send(()).unwrap();
        released
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        Ok(PreviewContent::Text("discarded result".into()))
    }));
    tokio::time::timeout(std::time::Duration::from_secs(5), started)
        .await
        .unwrap()
        .unwrap();
    waiter.abort();
    assert!(waiter.await.err().unwrap().is_cancelled());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    release.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while drops.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}
