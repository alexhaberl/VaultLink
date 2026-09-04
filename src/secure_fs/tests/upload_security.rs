    #[test]
    fn insecure_internal_directory_permissions_fail_closed() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let internal = directory.path().join(INTERNAL_DIRECTORY_NAME);
        std::fs::create_dir(&internal).unwrap();
        std::fs::set_permissions(&internal, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = match SecureRoot::open(directory.path()) {
            Ok(_) => panic!("insecure internal directory was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn special_files_are_hidden_and_never_block_regular_file_open() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};

        extern "C" {
            fn mkfifo(path: *const std::os::raw::c_char, mode: u32) -> i32;
        }

        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("pipe");
        let fifo_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `fifo_path` is a valid, NUL-terminated path for this call.
        assert_eq!(unsafe { mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        let root = SecureRoot::open(directory.path()).unwrap();
        assert!(root.list("", 0, 100).unwrap().is_empty());
        assert_eq!(
            root.open_file("pipe").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn existing_linux_filenames_are_not_reduced_to_windows_upload_policy() {
        let directory = tempfile::tempdir().unwrap();
        for name in ["report:2026.txt", "CON.txt", "frage?.txt", "trailing."] {
            std::fs::write(directory.path().join(name), name).unwrap();
        }
        let root = SecureRoot::open(directory.path()).unwrap();
        let names = root
            .list("", 0, 100)
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect::<std::collections::HashSet<_>>();
        for name in ["report:2026.txt", "CON.txt", "frage?.txt", "trailing."] {
            assert!(names.contains(name), "valid Linux file was hidden: {name}");
        }
    }

    #[test]
    fn upload_publish_is_noclobber_and_cleans_temporary_files() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("existing.txt"), b"original").unwrap();

        let mut upload = root.begin_upload("").unwrap();
        let mut file = upload.take_file().unwrap();
        file.write_all(b"replacement").unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert_eq!(
            upload.publish("existing.txt").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        drop(upload);
        assert_eq!(
            std::fs::read(directory.path().join("existing.txt")).unwrap(),
            b"original"
        );

        let mut upload = root.begin_upload("").unwrap();
        let mut file = upload.take_file().unwrap();
        file.write_all(b"complete").unwrap();
        file.sync_all().unwrap();
        drop(file);
        upload.publish("complete.txt").unwrap();
        assert_eq!(
            std::fs::read(directory.path().join("complete.txt")).unwrap(),
            b"complete"
        );
    }

    #[test]
    fn pending_upload_revalidates_the_current_destination_inode() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("target")).unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let upload = root.begin_upload("target").unwrap();
        let original = root.bind_directory("target").unwrap();
        assert!(upload.destination_matches(&original).unwrap());

        std::fs::rename(
            directory.path().join("target"),
            directory.path().join("moved-target"),
        )
        .unwrap();
        std::fs::create_dir(directory.path().join("target")).unwrap();

        let replacement = root.bind_directory("target").unwrap();
        let moved = root.bind_directory("moved-target").unwrap();
        assert!(!upload.destination_matches(&replacement).unwrap());
        assert!(upload.destination_matches(&moved).unwrap());
    }

    #[test]
    fn staged_upload_can_bind_its_destination_after_admission() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("target")).unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let mut upload = root.begin_staged_upload().unwrap();
        let mut file = upload.take_file().unwrap();
        file.write_all(b"admitted").unwrap();
        file.sync_all().unwrap();
        drop(file);

        assert_eq!(
            upload.publish("deferred.txt").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let destination = root.bind_directory("target").unwrap();
        upload.bind_destination(&destination).unwrap();
        assert!(upload.destination_matches(&destination).unwrap());
        assert_eq!(
            upload.bind_destination(&destination).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        upload.publish("deferred.txt").unwrap();

        assert_eq!(
            std::fs::read(directory.path().join("target/deferred.txt")).unwrap(),
            b"admitted"
        );
    }

    #[test]
    fn upload_publish_replace_is_atomic_and_cleans_temporary_file() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("existing.txt"), b"original").unwrap();

        let mut upload = root.begin_upload("").unwrap();
        let mut file = upload.take_file().unwrap();
        file.write_all(b"replacement").unwrap();
        file.sync_all().unwrap();
        drop(file);
        upload.publish_replace("existing.txt").unwrap();
        drop(upload);

        assert_eq!(
            std::fs::read(directory.path().join("existing.txt")).unwrap(),
            b"replacement"
        );
        let remaining_parts = std::fs::read_dir(
            directory
                .path()
                .join(INTERNAL_DIRECTORY_NAME)
                .join(UPLOAD_STAGING_DIRECTORY_NAME),
        )
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".part"))
        .count();
        assert_eq!(remaining_parts, 0);
    }

    #[test]
    fn external_writer_storage_disables_replace_at_the_filesystem_boundary() {
        use std::os::unix::fs::PermissionsExt;

        let mount = tempfile::tempdir().unwrap();
        let shared = mount.path().join("shared");
        let internal = mount.path().join(INTERNAL_DIRECTORY_NAME);
        let uploads = internal.join(UPLOAD_STAGING_DIRECTORY_NAME);
        let tombstones = internal.join(TOMBSTONE_STAGING_DIRECTORY_NAME);
        for path in [&shared, &internal, &uploads, &tombstones] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let root = SecureRoot::open_configured(&shared, Some(&internal), true, true).unwrap();
        std::fs::write(shared.join("existing.txt"), b"original").unwrap();
        let mut upload = root.begin_upload("").unwrap();
        let mut file = upload.take_file().unwrap();
        file.write_all(b"replacement").unwrap();
        file.sync_all().unwrap();
        drop(file);

        assert_eq!(
            upload.publish_replace("existing.txt").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            std::fs::read(shared.join("existing.txt")).unwrap(),
            b"original"
        );
    }

    #[test]
    fn explicit_external_writer_replace_policy_enables_filesystem_replace() {
        use std::os::unix::fs::PermissionsExt;

        let mount = tempfile::tempdir().unwrap();
        let shared = mount.path().join("shared");
        let internal = mount.path().join(INTERNAL_DIRECTORY_NAME);
        let uploads = internal.join(UPLOAD_STAGING_DIRECTORY_NAME);
        let tombstones = internal.join(TOMBSTONE_STAGING_DIRECTORY_NAME);
        for path in [&shared, &internal, &uploads, &tombstones] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let root =
            SecureRoot::open_configured_inner(&shared, Some(&internal), true, true, true, None)
                .unwrap();
        std::fs::write(shared.join("existing.txt"), b"external").unwrap();
        let mut upload = root.begin_upload("").unwrap();
        let mut file = upload.take_file().unwrap();
        file.write_all(b"vaultlink").unwrap();
        file.sync_all().unwrap();
        drop(file);

        upload.publish_replace("existing.txt").unwrap();
        assert_eq!(
            std::fs::read(shared.join("existing.txt")).unwrap(),
            b"vaultlink"
        );
    }

    #[test]
    fn abandoned_upload_is_removed() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        {
            let mut upload = root.begin_upload("").unwrap();
            let mut file = upload.take_file().unwrap();
            file.write_all(b"partial").unwrap();
            assert!(root.list("", 0, 100).unwrap().is_empty());
        }
        let names: Vec<_> = std::fs::read_dir(
            directory
                .path()
                .join(INTERNAL_DIRECTORY_NAME)
                .join(UPLOAD_STAGING_DIRECTORY_NAME),
        )
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
        assert!(names.is_empty(), "temporary upload remained: {names:?}");
    }

    #[test]
    fn sync_failure_reports_published_but_uncertain_outcome() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let mut upload = root.begin_upload("").unwrap();
        let mut file = upload.take_file().unwrap();
        file.write_all(b"complete").unwrap();
        file.sync_all().unwrap();
        drop(file);
        upload.fail_next_directory_sync(io::ErrorKind::Other);

        let outcome = upload.publish("complete.txt").unwrap();
        let PublishOutcome::PublishedSyncUncertain(error) = outcome else {
            panic!("injected sync failure was not reported");
        };
        assert_eq!(error.kind(), io::ErrorKind::Other);
        drop(upload);
        assert_eq!(
            std::fs::read(directory.path().join("complete.txt")).unwrap(),
            b"complete"
        );
    }

    #[test]
    fn replace_sync_failure_keeps_the_published_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("existing.txt"), b"old").unwrap();
        let mut upload = root.begin_upload("").unwrap();
        let mut file = upload.take_file().unwrap();
        file.write_all(b"new").unwrap();
        file.sync_all().unwrap();
        drop(file);
        upload.fail_next_directory_sync(io::ErrorKind::Other);

        assert!(matches!(
            upload.publish_replace("existing.txt").unwrap(),
            PublishOutcome::PublishedSyncUncertain(_)
        ));
        drop(upload);
        assert_eq!(
            std::fs::read(directory.path().join("existing.txt")).unwrap(),
            b"new"
        );
    }

    #[test]
    fn upload_response_loss_with_probe_failures_is_published_uncertain() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let mut upload = root.begin_upload("").unwrap();
        let mut file = upload.take_file().unwrap();
        file.write_all(b"published").unwrap();
        file.sync_all().unwrap();
        drop(file);
        upload.fail_next_publication_rename_after_success(io::ErrorKind::TimedOut);
        upload.fail_next_publication_identity_probes(io::ErrorKind::WouldBlock, 2);

        let outcome = upload.publish("ambiguous.txt").unwrap();

        let PublishOutcome::PublishedUncertain(error) = outcome else {
            panic!("an inconclusive publication must not be returned as a normal error");
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(upload);
        assert_eq!(
            std::fs::read(directory.path().join("ambiguous.txt")).unwrap(),
            b"published"
        );
    }

    #[test]
    fn upload_replace_response_loss_with_probe_failures_is_published_uncertain() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("existing.txt"), b"old").unwrap();
        let mut upload = root.begin_upload("").unwrap();
        let mut file = upload.take_file().unwrap();
        file.write_all(b"replacement").unwrap();
        file.sync_all().unwrap();
        drop(file);
        upload.fail_next_publication_rename_after_success(io::ErrorKind::ConnectionReset);
        upload.fail_next_publication_identity_probes(io::ErrorKind::WouldBlock, 2);

        let outcome = upload.publish_replace("existing.txt").unwrap();

        let PublishOutcome::PublishedUncertain(error) = outcome else {
            panic!("an inconclusive replacement must not be returned as a normal error");
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        drop(upload);
        assert_eq!(
            std::fs::read(directory.path().join("existing.txt")).unwrap(),
            b"replacement"
        );
    }

    #[test]
    fn concurrent_publish_has_exactly_one_winner() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|value| {
                let root = root.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut upload = root.begin_upload("").unwrap();
                    let mut file = upload.take_file().unwrap();
                    file.write_all(value.to_string().as_bytes()).unwrap();
                    file.sync_all().unwrap();
                    drop(file);
                    barrier.wait();
                    upload.publish("same.txt").is_ok()
                })
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|won| *won)
                .count(),
            1
        );
        assert!(directory.path().join("same.txt").is_file());
    }

    #[test]
    fn symlink_escape_is_rejected_for_all_storage_operations() {
        use std::os::unix::fs::symlink;
        let root_directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"secret").unwrap();
        symlink(outside.path(), root_directory.path().join("escape")).unwrap();
        let root = SecureRoot::open(root_directory.path()).unwrap();
        assert!(root.open_file("escape/secret").is_err());
        assert!(root.metadata("escape/secret").is_err());
        assert!(root.list("escape", 0, 100).is_err());
        assert!(root.begin_upload("escape").is_err());
    }

    #[test]
    fn share_scope_allows_internal_symlinks_and_blocks_sibling_share_symlinks() {
        use std::io::Read;
        use std::os::unix::fs::symlink;

        let root_directory = tempfile::tempdir().unwrap();
        let share_a = root_directory.path().join("share-a");
        let share_b = root_directory.path().join("share-b");
        std::fs::create_dir_all(share_a.join("real")).unwrap();
        std::fs::create_dir_all(share_b.join("nested")).unwrap();
        std::fs::create_dir_all(share_b.join("uploads")).unwrap();
        std::fs::write(share_a.join("real/allowed.txt"), b"allowed").unwrap();
        std::fs::write(share_b.join("secret.txt"), b"secret").unwrap();
        symlink("real", share_a.join("inside")).unwrap();
        symlink("../share-b", share_a.join("outside")).unwrap();

        let root = SecureRoot::open(root_directory.path()).unwrap();
        let scope = root.bind_directory("share-a").unwrap();
        let mut allowed = scope.open_file("inside/allowed.txt").unwrap().into_file();
        let mut contents = String::new();
        allowed.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "allowed");

        assert!(scope.open_file("outside/secret.txt").is_err());
        assert!(scope.metadata("outside/secret.txt").is_err());
        assert!(scope.list("outside/nested", 0, 100).is_err());
        assert!(scope.begin_upload("outside/uploads").is_err());

        // Authenticated admin access intentionally remains bounded only by the
        // global storage root, so this in-root path is still available there.
        let mut admin_file = root.open_file("share-a/outside/secret.txt").unwrap();
        contents.clear();
        admin_file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "secret");
    }

    #[test]
    fn bound_directory_descriptor_survives_share_path_retargeting() {
        use std::io::Read;
        use std::os::unix::fs::symlink;

        let root_directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(root_directory.path().join("share-a")).unwrap();
        std::fs::create_dir(root_directory.path().join("share-b")).unwrap();
        std::fs::write(root_directory.path().join("share-a/file.txt"), b"safe").unwrap();
        std::fs::write(root_directory.path().join("share-b/file.txt"), b"secret").unwrap();
        let root = SecureRoot::open(root_directory.path()).unwrap();
        let scope = root.bind_directory("share-a").unwrap();

        std::fs::rename(
            root_directory.path().join("share-a"),
            root_directory.path().join("moved-share-a"),
        )
        .unwrap();
        symlink("share-b", root_directory.path().join("share-a")).unwrap();

        let mut file = scope.open_file("file.txt").unwrap().into_file();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "safe");
        assert!(root.bind_directory("share-a").is_err());
    }
