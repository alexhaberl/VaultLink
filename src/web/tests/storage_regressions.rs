mod storage_regressions {
    use super::*;
    use crate::{
        admitted_file::AdmittedFile, response_work::ResponseWorkAdmission,
        test_checkpoint::Checkpoint,
    };
    use std::{
        io::{SeekFrom, Write as _},
        os::{
            fd::AsRawFd as _,
            unix::fs::{MetadataExt as _, PermissionsExt as _},
        },
    };
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_file_reads_and_seeks_keep_global_and_public_capacity() {
        for operation in ["read", "seek", "read-error"] {
            let root = tempfile::tempdir().unwrap();
            let data = tempfile::tempdir().unwrap();
            let state = test_state(root.path(), data.path());
            let global = Arc::new(tokio::sync::Semaphore::new(1));
            let public = Arc::new(tokio::sync::Semaphore::new(1));
            let peer = state
                .try_acquire_stream_peer("127.0.0.1".parse().unwrap())
                .unwrap();
            let owner = ResponseWorkAdmission::new((
                global.clone().try_acquire_owned().unwrap(),
                peer,
                Some(public.clone().try_acquire_owned().unwrap()),
            ));
            let path = root.path().join("read.txt");
            std::fs::write(&path, b"file contents").unwrap();
            let file = if operation == "read-error" {
                std::fs::OpenOptions::new().write(true).open(path).unwrap()
            } else {
                std::fs::File::open(path).unwrap()
            };
            let kind = if operation == "seek" { "seek" } else { "read" };
            let checkpoint = Checkpoint::new(format!("file-{kind}:{}", file.as_raw_fd()));
            let task = tokio::spawn(owner.scope(async move {
                let mut file = AdmittedFile::from_std(file);
                if operation == "seek" {
                    file.seek(SeekFrom::Start(2)).await.map(|_| ())
                } else {
                    file.read_exact(&mut [0; 4]).await.map(|_| ())
                }
            }));
            checkpoint.entered().await;
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert_eq!(
                (global.available_permits(), public.available_permits()),
                (0, 0)
            );
            checkpoint.release();
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while global.available_permits() != 1 || public.available_permits() != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn file_worker_panic_releases_capacity_and_buffered_seek_tracks_logical_position() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let global = Arc::new(tokio::sync::Semaphore::new(1));
        let owner = ResponseWorkAdmission::new((
            global.clone().try_acquire_owned().unwrap(),
            state
                .try_acquire_stream_peer("127.0.0.1".parse().unwrap())
                .unwrap(),
            None,
        ));
        let worker = owner.spawn_blocking(|| panic!("controlled file worker panic"));
        drop(owner);
        assert!(worker.await.unwrap_err().is_panic());
        assert_eq!(global.available_permits(), 1);
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"abcdef").unwrap();
        std::io::Seek::seek(&mut file, SeekFrom::Start(0)).unwrap();
        let mut file = AdmittedFile::from_std(file);
        let mut first = [0; 2];
        file.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"ab");
        assert_eq!(file.seek(SeekFrom::Current(1)).await.unwrap(), 3);
        let mut remainder = Vec::new();
        file.read_to_end(&mut remainder).await.unwrap();
        assert_eq!(remainder, b"def");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zip_temp_and_stream_detect_growth_and_shrink_during_reading() {
        for direct in [false, true] {
            for shrink in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let data = tempfile::tempdir().unwrap();
                let name = format!("mid-read-{}.txt", auth::random_token(12));
                let path = root.path().join(&name);
                let size = BUFFERED_RESPONSE_CHUNK_BYTES * 3;
                std::fs::write(&path, vec![b'x'; size]).unwrap();
                let state = test_state(root.path(), data.path());
                let scope = state.secure_root().bind_directory("").unwrap();
                let plan = plan_zip(&scope, "", &runtime_settings(&state)).unwrap();
                let checkpoint = Checkpoint::new(format!("zip-read:{name}"));
                let task = tokio::spawn(async move {
                    if direct {
                        let mut stream = Box::pin(direct_zip_stream(scope, plan));
                        let mut failed = false;
                        while let Some(chunk) = stream.next().await {
                            if chunk.is_err() {
                                failed = true;
                                break;
                            }
                        }
                        failed
                    } else {
                        tokio::task::spawn_blocking(move || {
                            matches!(build_zip_temp(&scope, &plan), Err(ZipBuildError::Source(_)))
                        })
                        .await
                        .unwrap()
                    }
                });
                checkpoint.entered().await;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .append(!shrink)
                    .open(path)
                    .unwrap();
                if shrink {
                    file.set_len(1).unwrap();
                } else {
                    file.write_all(b"extra").unwrap();
                }
                checkpoint.release();
                assert!(task.await.unwrap(), "direct={direct} shrink={shrink}");
            }
        }
    }

    #[derive(Clone)]
    struct FaultingDirectory(crate::secure_fs::SecureRoot);
    impl super::super::common::DirectoryAccess for FaultingDirectory {
        fn scan_entries(&self, relative: &str) -> io::Result<crate::secure_fs::DirectoryScan> {
            let mut scan = self.0.scan_directory(relative)?;
            scan.inject_error(io::ErrorKind::Other);
            Ok(scan)
        }
        fn open_regular_file(&self, relative: &str) -> io::Result<std::fs::File> {
            self.0.open_file(relative)
        }
    }

    #[test]
    fn scan_io_errors_propagate_through_pagination_search_and_snapshots() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let directory = FaultingDirectory(state.secure_root().clone());
        assert!(list_directory_page(&directory, "", 1, 1000).is_err());
        assert!(search_tree(&directory, "", "needle", &runtime_settings(&state)).is_err());
        assert!(build_directory_snapshot(
            &directory,
            "",
            1000,
            FileSortColumn::Name,
            FileSortDirection::Ascending
        )
        .is_err());
        assert!(list_directory_cursor_page(
            &directory,
            "",
            None,
            None,
            1000,
            FileSortColumn::Name,
            FileSortDirection::Ascending
        )
        .is_err());
    }

    #[test]
    fn directory_permission_failure_never_becomes_a_complete_scan_or_zip_plan() {
        // Real EACCES needs the unprivileged Linux suite; root smoke runs retain
        // the controlled-I/O coverage above.
        if std::fs::metadata("/proc/self").unwrap().uid() == 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let path = root.path().join("denied");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("file.txt"), b"content").unwrap();
        let state = test_state(root.path(), data.path());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let settings = runtime_settings(&state);
        let list = state.secure_root().list("denied", 1, 1);
        let snapshot = build_directory_snapshot(
            state.secure_root(),
            "denied",
            1000,
            FileSortColumn::Name,
            FileSortDirection::Ascending,
        );
        let search = search_tree(state.secure_root(), "denied", "file", &settings);
        let zip = plan_zip(state.secure_root(), "denied", &settings);
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(list, Err(error) if error.kind() == io::ErrorKind::PermissionDenied));
        assert!(snapshot.is_err());
        assert!(search.is_err());
        assert!(
            matches!(zip, Err(ZipBuildError::Source(error)) if error.kind() == io::ErrorKind::PermissionDenied)
        );
    }
}
