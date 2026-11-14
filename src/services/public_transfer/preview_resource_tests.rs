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

#[test]
fn descriptor_preview_checks_file_kind_and_media_limits() {
    let root = tempfile::tempdir().unwrap();
    let config = crate::config::Config::load(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config/development.toml"),
    )
    .unwrap();
    let mut settings = RuntimeSettings::from_config(&config);
    settings.max_media_preview_size = 1;
    std::fs::create_dir(root.path().join("docs")).unwrap();
    std::fs::write(root.path().join("docs/text.txt"), b"preview").unwrap();
    std::fs::write(root.path().join("docs/image.png"), b"png").unwrap();
    let secure = crate::secure_fs::SecureRoot::open(root.path()).unwrap();
    let scope = secure.bind_directory("docs").unwrap();
    assert!(matches!(
        read_preview_secure_file(scope.open_file("text.txt").unwrap(), "text.txt", &settings),
        Ok(PreviewContent::Text(text)) if text == "preview"
    ));
    assert!(matches!(
        read_preview_secure_file(
            scope.open_file("image.png").unwrap(),
            "image.png",
            &settings
        ),
        Ok(PreviewContent::TooLarge { size: 3 })
    ));
    settings.max_media_preview_size = 3;
    assert!(matches!(
        read_preview_secure_file(
            scope.open_file("image.png").unwrap(),
            "image.png",
            &settings
        ),
        Ok(PreviewContent::Media {
            kind: PreviewKind::Image("image/png"),
            size: 3
        })
    ));
    let directory = std::fs::File::open(root.path()).unwrap();
    let metadata = directory.metadata().unwrap();
    let Err(error) = read_preview_opened(directory, &metadata, "directory.txt", &settings) else {
        panic!("a directory must not become a text preview");
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}
