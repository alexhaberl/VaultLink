    #[test]
    fn interrupted_rename_intent_is_idempotently_recovered() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("before.txt"), b"content").unwrap();

        let mut staged = root.stage_rename("before.txt", "after.txt").unwrap();
        staged.begin_database_commit();
        drop(staged);
        drop(root);

        let reopened = SecureRoot::open(directory.path()).unwrap();
        let pending = reopened.pending_file_operations().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            reopened.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Rename {
                original_path: "before.txt".into(),
                new_path: "after.txt".into(),
                is_directory: false,
            }
        );
        reopened.complete_file_operation(&pending[0]).unwrap();
        assert_eq!(
            std::fs::read(directory.path().join("after.txt")).unwrap(),
            b"content"
        );
        assert!(reopened.pending_file_operations().unwrap().is_empty());
    }

    #[test]
    fn moved_rename_recovery_preserves_old_path_replacement_even_with_matching_identity() {
        use std::os::unix::fs::MetadataExt;

        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("before.txt"), b"replacement").unwrap();
        let replacement = std::fs::metadata(directory.path().join("before.txt")).unwrap();
        let operation = DurableFileOperation::Rename {
            original_path: "before.txt".into(),
            new_path: "after.txt".into(),
            kind: DurableEntryKind::File,
            // Deliberately model dev/inode reuse after the completed target at
            // the new path was removed.
            device: replacement.dev(),
            inode: replacement.ino(),
            phase: DurableRenamePhase::Moved,
        };
        write_file_operation(root.tombstones.as_ref(), &operation).unwrap();
        let pending = root.pending_file_operations().unwrap();

        assert_eq!(
            root.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Rename {
                original_path: "before.txt".into(),
                new_path: "after.txt".into(),
                is_directory: false,
            }
        );
        assert_eq!(
            std::fs::read(directory.path().join("before.txt")).unwrap(),
            b"replacement"
        );
        assert!(!directory.path().join("after.txt").exists());
        root.complete_file_operation(&pending[0]).unwrap();
    }

    #[test]
    fn intent_rename_recovery_cancels_in_place_instead_of_replaying_old_name() {
        use std::os::unix::fs::MetadataExt;

        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("before.txt"), b"replacement").unwrap();
        let replacement = std::fs::metadata(directory.path().join("before.txt")).unwrap();
        let operation = DurableFileOperation::Rename {
            original_path: "before.txt".into(),
            new_path: "after.txt".into(),
            kind: DurableEntryKind::File,
            // This deliberately also matches the recorded identity, modeling
            // inode reuse in the crash window before the moved marker landed.
            device: replacement.dev(),
            inode: replacement.ino(),
            phase: DurableRenamePhase::Intent,
        };
        write_file_operation(root.tombstones.as_ref(), &operation).unwrap();
        let pending = root.pending_file_operations().unwrap();

        assert_eq!(
            root.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Cancelled
        );
        assert_eq!(
            std::fs::read(directory.path().join("before.txt")).unwrap(),
            b"replacement"
        );
        assert!(!directory.path().join("after.txt").exists());
        assert!(root.pending_file_operations().unwrap().is_empty());
    }

    #[test]
    fn rename_verifies_the_moved_inode_after_source_name_swap() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let source = directory.path().join("source.txt");
        let externally_moved = directory.path().join("externally-moved.txt");
        std::fs::write(&source, b"authorized").unwrap();
        let hook_source = source.clone();
        let hook_external = externally_moved.clone();
        let hook_replacement = source;
        root.before_next_rename(move || {
            std::fs::rename(hook_source, hook_external).unwrap();
            std::fs::write(hook_replacement, b"replacement").unwrap();
        });

        let error = root
            .stage_rename("source.txt", "renamed.txt")
            .err()
            .expect("source-name replacement must fail identity verification");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read(externally_moved).unwrap(), b"authorized");
        assert_eq!(
            std::fs::read(directory.path().join("renamed.txt")).unwrap(),
            b"replacement"
        );
        assert_eq!(root.pending_file_operations().unwrap().len(), 1);
    }

    #[test]
    fn interrupted_committed_delete_retains_recovery_metadata_until_reconciled() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::create_dir(directory.path().join("tree")).unwrap();
        std::fs::write(directory.path().join("tree/child.txt"), b"content").unwrap();

        let committed = root
            .stage_delete_ready("tree")
            .unwrap()
            .commit(true)
            .unwrap();
        let tombstone = committed.outcome().tombstone_path.as_ref().unwrap().clone();
        drop(committed);
        drop(root);

        let reopened = SecureRoot::open(directory.path()).unwrap();
        let pending = reopened.pending_file_operations().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            reopened.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Delete {
                original_path: "tree".into(),
                is_directory: true,
                tombstone_path: Some(tombstone.clone()),
            }
        );
        reopened.complete_file_operation(&pending[0]).unwrap();
        let mut cleanup = reopened.start_deletion_cleanup(&tombstone).unwrap();
        while !cleanup.run_batch(1).unwrap().complete {}
        assert!(!directory.path().join("tree").exists());
        assert!(reopened.pending_file_operations().unwrap().is_empty());
    }

    #[test]
    fn delete_recovery_never_reclaims_visible_original_when_private_names_are_missing() {
        use std::os::unix::fs::MetadataExt;

        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("reused.txt"), b"replacement").unwrap();
        let replacement = std::fs::metadata(directory.path().join("reused.txt")).unwrap();
        let operation = DurableFileOperation::Delete {
            original_path: "reused.txt".into(),
            kind: DurableEntryKind::File,
            // Deliberately record the replacement identity to model dev/inode
            // reuse after the original target was unlinked.
            device: replacement.dev(),
            inode: replacement.ino(),
            pending_name: deletion_pending_name(),
            tombstone_name: deletion_tombstone_name(),
            allow_recursive: false,
            phase: DurableDeletePhase::Moved,
        };
        write_file_operation(root.tombstones.as_ref(), &operation).unwrap();
        let pending = root.pending_file_operations().unwrap();
        assert_eq!(pending.len(), 1);

        assert_eq!(
            root.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Delete {
                original_path: "reused.txt".into(),
                is_directory: false,
                tombstone_path: None,
            }
        );
        assert_eq!(
            std::fs::read(directory.path().join("reused.txt")).unwrap(),
            b"replacement"
        );
        root.complete_file_operation(&pending[0]).unwrap();
    }

    #[test]
    fn rename_rejects_symlink_sources_without_moving_them() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("target.txt"), b"target").unwrap();
        symlink("target.txt", directory.path().join("link.txt")).unwrap();

        let error = match root.stage_rename("link.txt", "moved.txt") {
            Ok(_) => panic!("symlink rename unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(directory.path().join("link.txt").is_symlink());
        assert!(!directory.path().join("moved.txt").exists());
    }

    #[test]
    fn cleanup_removes_only_flat_private_upload_fragments() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let staging = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(UPLOAD_STAGING_DIRECTORY_NAME);
        let nested = staging.join("nested");
        std::fs::create_dir(&nested).unwrap();
        let first = upload_fragment_name();
        let second = upload_fragment_name();
        std::fs::write(staging.join(&first), b"partial").unwrap();
        std::fs::write(nested.join(&second), b"partial").unwrap();
        let public_fragment = upload_fragment_name();
        std::fs::write(directory.path().join(&public_fragment), b"client-owned").unwrap();
        std::fs::write(staging.join("keep.part"), b"keep").unwrap();
        let matching_directory = staging.join(upload_fragment_name());
        std::fs::create_dir(&matching_directory).unwrap();

        let mut cleanup = root.start_upload_fragment_cleanup().unwrap();
        let batch = cleanup.run_batch(100).unwrap();
        assert!(batch.complete);
        assert_eq!(batch.removed, 1);
        assert!(!staging.join(first).exists());
        assert_eq!(std::fs::read(nested.join(second)).unwrap(), b"partial");
        assert_eq!(std::fs::read(staging.join("keep.part")).unwrap(), b"keep");
        assert!(matching_directory.is_dir());
        assert_eq!(
            std::fs::read(directory.path().join(public_fragment)).unwrap(),
            b"client-owned"
        );
    }

    #[test]
    fn cleanup_stops_at_the_configured_scan_bound() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let staging = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(UPLOAD_STAGING_DIRECTORY_NAME);
        std::fs::write(staging.join(upload_fragment_name()), b"one").unwrap();
        std::fs::write(staging.join(upload_fragment_name()), b"two").unwrap();
        let mut cleanup = root.start_upload_fragment_cleanup().unwrap();
        let batch = cleanup.run_batch(1).unwrap();
        assert_eq!(batch.scanned, 1);
        assert!(!batch.complete);
    }

    #[test]
    fn directory_scan_counts_filtered_raw_items() {
        let directory = tempfile::tempdir().unwrap();
        let fragment = upload_fragment_name();
        std::fs::write(directory.path().join(&fragment), b"partial").unwrap();
        std::fs::write(directory.path().join("visible.txt"), b"visible").unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();

        let mut scan = root.scan_directory("").unwrap();
        let mut scanned = 0usize;
        let mut names = Vec::new();
        loop {
            let batch = scan.run_batch(1).unwrap();
            assert!(batch.scanned <= 1);
            scanned += batch.scanned;
            names.extend(batch.entries.into_iter().map(|entry| entry.name));
            if batch.complete {
                break;
            }
        }
        assert_eq!(scanned, 3);
        assert_eq!(names, vec!["visible.txt"]);
    }

    #[test]
    fn cleanup_continues_across_strictly_bounded_batches() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let staging = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(UPLOAD_STAGING_DIRECTORY_NAME);
        let mut fragments = Vec::new();
        for index in 0usize..16 {
            let fragment = upload_fragment_name();
            std::fs::write(staging.join(&fragment), b"partial").unwrap();
            std::fs::write(staging.join(format!("keep-{index}.txt")), b"keep").unwrap();
            fragments.push(staging.join(fragment));
        }
        let mut cleanup = root.start_upload_fragment_cleanup().unwrap();
        let mut removed = 0usize;
        for _ in 0..256 {
            let batch = cleanup.run_batch(1).unwrap();
            assert!(batch.scanned <= 1);
            removed += batch.removed;
            if batch.complete {
                break;
            }
        }

        assert_eq!(removed, fragments.len());
        assert!(fragments.iter().all(|path| !path.exists()));
        assert!(staging.join("keep-0.txt").is_file());
        assert!(staging.join("keep-1.txt").is_file());
    }

    #[test]
    fn recursive_cleanup_depth_limit_is_retryable_and_stays_inside_the_tombstone() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("must-survive.txt");
        std::fs::write(&outside_file, b"outside").unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let tombstone_name = deletion_tombstone_name();
        let tombstone = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
            .join(&tombstone_name);
        std::fs::create_dir(&tombstone).unwrap();
        let mut deepest = tombstone.clone();
        for index in 0..(MAX_CLEANUP_DIRECTORY_STACK * 3) {
            deepest = deepest.join(format!("d{index}"));
            std::fs::create_dir(&deepest).unwrap();
        }
        std::fs::write(deepest.join("payload.txt"), b"private").unwrap();
        symlink(outside.path(), deepest.join("outside-link")).unwrap();

        let mut limit_errors = 0usize;
        let mut complete = false;
        for _ in 0..16 {
            let mut cleanup = root.start_deletion_cleanup(&tombstone_name).unwrap();
            loop {
                match cleanup.run_batch(8) {
                    Ok(batch) if batch.complete => {
                        complete = true;
                        break;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        assert_eq!(
                            error.kind(),
                            io::ErrorKind::WouldBlock,
                            "unexpected cleanup error: {error:?}, raw={:?}",
                            error.raw_os_error()
                        );
                        assert!(cleanup.directories.len() <= MAX_CLEANUP_DIRECTORY_STACK);
                        limit_errors += 1;
                        break;
                    }
                }
            }
            assert_eq!(std::fs::read(&outside_file).unwrap(), b"outside");
            if complete {
                break;
            }
        }

        assert!(complete, "segmented cleanup retries did not finish");
        assert!(limit_errors > 0, "test did not exercise the depth limit");
        assert!(!tombstone.exists());
        assert_eq!(std::fs::read(outside_file).unwrap(), b"outside");
    }

    #[test]
    fn cleanup_segmentation_rejects_a_replaced_source_name() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let tombstone_name = deletion_tombstone_name();
        let tombstone = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
            .join(&tombstone_name);
        let parent = tombstone.join("parent");
        let current = parent.join("current");
        std::fs::create_dir(&tombstone).unwrap();
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&current).unwrap();
        std::fs::write(current.join("original.txt"), b"original").unwrap();

        let mut cleanup = root.start_deletion_cleanup(&tombstone_name).unwrap();
        assert!(!cleanup.run_batch(1).unwrap().complete);
        assert!(!cleanup.run_batch(1).unwrap().complete);
        assert_eq!(cleanup.directories.len(), 3);

        let moved = parent.join("moved-current");
        std::fs::rename(&current, &moved).unwrap();
        std::fs::create_dir(&current).unwrap();
        std::fs::write(current.join("replacement.txt"), b"replacement").unwrap();

        let error = rebase_cleanup_directory(cleanup.directories.last().unwrap()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(
            std::fs::read(moved.join("original.txt")).unwrap(),
            b"original"
        );
        assert_eq!(
            std::fs::read(current.join("replacement.txt")).unwrap(),
            b"replacement"
        );
        assert!(std::fs::read_dir(&tombstone).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(CLEANUP_SEGMENT_PREFIX)
        }));
    }

    #[test]
    fn recursive_cleanup_visited_limit_makes_bounded_progress_across_retries() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let public_file = directory.path().join("must-survive.txt");
        std::fs::write(&public_file, b"public").unwrap();
        let tombstone_name = deletion_tombstone_name();
        let tombstone = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
            .join(&tombstone_name);
        std::fs::create_dir(&tombstone).unwrap();
        for index in 0..6 {
            let child = tombstone.join(format!("child-{index}"));
            std::fs::create_dir(&child).unwrap();
            std::fs::write(child.join("payload.txt"), b"private").unwrap();
        }

        let mut limit_errors = 0usize;
        let mut complete = false;
        for _ in 0..16 {
            let mut cleanup = root.start_deletion_cleanup(&tombstone_name).unwrap();
            cleanup.max_visited_directories = 2;
            loop {
                match cleanup.run_batch(2) {
                    Ok(batch) if batch.complete => {
                        complete = true;
                        break;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                        assert!(cleanup.visited.len() <= cleanup.max_visited_directories);
                        limit_errors += 1;
                        break;
                    }
                }
            }
            if complete {
                break;
            }
        }

        assert!(complete, "bounded cleanup retries did not finish");
        assert!(limit_errors > 0, "test did not exercise the visited limit");
        assert!(!tombstone.exists());
        assert_eq!(std::fs::read(public_file).unwrap(), b"public");
    }

    #[test]
    fn cleanup_respects_a_fragment_reserved_before_creation() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let fragment = upload_fragment_name();
        let fragment_path = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(UPLOAD_STAGING_DIRECTORY_NAME)
            .join(&fragment);

        // PendingUpload reserves the random name before the SMB create, so
        // cleanup cannot observe an unregistered fragment at any point.
        let active_key = fragment;
        assert!(active_upload_fragment_guard().insert(active_key.clone()));
        std::fs::write(&fragment_path, b"active").unwrap();
        let mut cleanup = root.start_upload_fragment_cleanup().unwrap();
        let mut removed = 0usize;
        loop {
            let batch = cleanup.run_batch(1).unwrap();
            removed += batch.removed;
            if batch.complete {
                break;
            }
        }
        assert_eq!(removed, 0);
        assert_eq!(std::fs::read(&fragment_path).unwrap(), b"active");
        unregister_upload_fragment(&active_key);
    }

    #[test]
    fn cleanup_skips_a_live_pending_upload() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let mut pending = root.begin_upload("").unwrap();
        pending.take_file().unwrap().write_all(b"active").unwrap();
        let mut cleanup = root.start_upload_fragment_cleanup().unwrap();
        loop {
            let batch = cleanup.run_batch(1).unwrap();
            assert_eq!(batch.removed, 0);
            if batch.complete {
                break;
            }
        }
        pending.publish("published.txt").unwrap();
        assert_eq!(
            std::fs::read(directory.path().join("published.txt")).unwrap(),
            b"active"
        );
    }
