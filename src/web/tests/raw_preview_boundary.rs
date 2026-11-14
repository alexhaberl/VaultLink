use super::*;
use std::{
    io,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

#[derive(Clone)]
enum FailedPreviewDirectory {
    Busy,
    Missing,
    Panic,
    Directory(std::path::PathBuf),
}

impl DirectoryAccess for FailedPreviewDirectory {
    fn scan_entries(&self, _: &str) -> io::Result<crate::secure_fs::DirectoryScan> {
        Err(io::Error::other("raw preview must not scan directories"))
    }

    fn open_regular_file(&self, _: &str) -> io::Result<std::fs::File> {
        match self {
            Self::Busy => Err(io::ErrorKind::WouldBlock.into()),
            Self::Missing => Err(io::ErrorKind::NotFound.into()),
            Self::Panic => panic!("simulated preview worker failure"),
            Self::Directory(path) => std::fs::File::open(path),
        }
    }
}

struct CountPreviewGuardDrops(Arc<AtomicUsize>);

impl Drop for CountPreviewGuardDrops {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn storage_failures_release_authority_and_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    for (failure, status, message) in [
        (
            FailedPreviewDirectory::Busy,
            StatusCode::SERVICE_UNAVAILABLE,
            "Storage temporarily busy",
        ),
        (
            FailedPreviewDirectory::Missing,
            StatusCode::NOT_FOUND,
            "File unavailable",
        ),
        (
            FailedPreviewDirectory::Panic,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error",
        ),
        (
            FailedPreviewDirectory::Directory(directory.path().into()),
            StatusCode::BAD_REQUEST,
            "Not a file",
        ),
    ] {
        let drops = Arc::new(AtomicUsize::new(0));
        let error = raw_preview_response(
            failure,
            Method::GET,
            HeaderMap::new(),
            "preview.png".into(),
            PreviewKind::Image("image/png"),
            1024,
            CountPreviewGuardDrops(drops.clone()),
        )
        .await
        .expect_err("failed storage must not produce a preview body");
        assert_eq!(error.0, status);
        assert_eq!(error.1, message);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn preview_filename_cannot_inject_response_headers() {
    let mut response = Response::new(Body::empty());
    add_raw_preview_headers(
        &mut response,
        &RawPreviewHeaders {
            relative_file: "folder/überblick\r\nx-injected: secret.png",
            kind: PreviewKind::Image("image/png"),
            range: None,
            length: 4,
            start: 0,
            end: 3,
            response_length: 4,
        },
    )
    .unwrap();
    let disposition = response.headers()[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap();
    assert!(disposition.contains("%C3%BCberblick%0D%0Ax%2Dinjected%3A%20secret%2Epng"));
    assert!(response.headers().get("x-injected").is_none());
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
}
