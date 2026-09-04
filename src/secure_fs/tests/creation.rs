    #[test]
    fn upload_fragment_filter_is_strict() {
        let generated = upload_fragment_name();
        assert!(is_upload_fragment_name(OsStr::new(&generated)));
        for name in [
            ".vaultlink-short.part",
            ".vaultlink-AAAAAAAAAAAAAAAAAAAAAAAA.tmp",
            ".vaultlink-AAAAAAAAAAAAAAAAAAAAAAA!.part",
            "vaultlink-AAAAAAAAAAAAAAAAAAAAAAAA.part",
            ".vaultlink-AAAAAAAAAAAAAAAAAAAAAAAA.part.bak",
        ] {
            assert!(!is_upload_fragment_name(OsStr::new(name)), "{name}");
        }
    }

    #[test]
    fn private_fragment_namespace_cannot_be_published() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let mut pending = root.begin_upload("").unwrap();
        pending.take_file().unwrap().write_all(b"content").unwrap();
        assert_eq!(
            pending.publish(&upload_fragment_name()).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn deletion_tombstone_filter_is_strict() {
        let generated = deletion_tombstone_name();
        assert!(is_deletion_tombstone_name(OsStr::new(&generated)));
        for name in [
            ".vaultlink-delete-short.tombstone",
            ".vaultlink-delete-AAAAAAAAAAAAAAAAAAAAAAAA.part",
            ".vaultlink-delete-AAAAAAAAAAAAAAAAAAAAAAA!.tombstone",
            "vaultlink-delete-AAAAAAAAAAAAAAAAAAAAAAAA.tombstone",
        ] {
            assert!(!is_deletion_tombstone_name(OsStr::new(name)), "{name}");
        }
    }

    #[test]
    fn admin_mutations_create_rename_rollback_and_delete_tree() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let (created, outcome) = root.create_directory("", "docs").unwrap();
        assert_eq!(created, "docs");
        assert!(outcome.is_durable());
        std::fs::write(directory.path().join("docs/file.txt"), b"content").unwrap();

        {
            let staged = root.stage_rename("docs/file.txt", "draft.txt").unwrap();
            assert_eq!(staged.kind(), EntryKind::File);
            assert!(directory.path().join("docs/draft.txt").exists());
        }
        assert!(directory.path().join("docs/file.txt").exists());

        root.stage_rename("docs/file.txt", "final.txt")
            .unwrap()
            .commit()
            .unwrap();
        assert!(directory.path().join("docs/final.txt").exists());
        assert!(root.stage_rename("docs/final.txt", "final.txt").is_err());
        assert!(root
            .create_directory("", &deletion_tombstone_name())
            .is_err());

        let staged = root.stage_delete_ready("docs").unwrap();
        assert_eq!(
            staged.status(),
            &EntryStatus {
                kind: EntryKind::Directory,
                directory_non_empty: true,
            }
        );
        let outcome = staged.commit(true).unwrap().complete().unwrap();
        assert!(outcome.cleanup_pending);
        assert!(!directory.path().join("docs").exists());
        let tombstone = outcome.tombstone_path.unwrap();
        let mut cleanup = root.start_deletion_cleanup(&tombstone).unwrap();
        loop {
            let batch = cleanup.run_batch(1).unwrap();
            if batch.complete {
                break;
            }
        }
        assert!(root.list("", 0, 10).unwrap().is_empty());
    }

    #[test]
    fn directory_tree_creation_is_descriptor_bound_and_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let scope = root.bind_directory("").unwrap();
        assert_eq!(
            scope.ensure_directory_tree("album/2026/summer").unwrap(),
            ["album", "album/2026", "album/2026/summer"]
        );
        assert!(scope
            .ensure_directory_tree("album/2026/summer")
            .unwrap()
            .is_empty());
        std::fs::write(directory.path().join("file"), b"content").unwrap();
        assert!(scope.ensure_directory_tree("file/child").is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside.path(), directory.path().join("escape")).unwrap();
            assert!(scope.ensure_directory_tree("escape/child").is_err());
            assert!(!outside.path().join("child").exists());
        }
    }

    #[test]
    fn directory_tree_outcome_preserves_visible_partial_creation_on_terminal_error() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let external_path = directory.path().to_path_buf();
        root.after_next_directory_tree_create(move || {
            std::fs::write(external_path.join("album/blocker"), b"external file").unwrap();
        });

        let outcome = root
            .bind_directory("")
            .unwrap()
            .ensure_directory_tree_with_outcome("album/blocker/child")
            .unwrap();

        assert_eq!(outcome.created, ["album"]);
        assert!(outcome.sync_error.is_none());
        assert!(matches!(
            outcome.terminal_error.as_ref().map(io::Error::kind),
            Some(io::ErrorKind::NotADirectory)
        ));
        assert!(directory.path().join("album").is_dir());
        assert!(directory.path().join("album/blocker").is_file());
        assert!(!directory.path().join("album/blocker/child").exists());
    }

    #[test]
    fn directory_tree_preserves_first_component_publication_uncertainty() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        root.fail_next_create_directory_mkdir_after_success(io::ErrorKind::TimedOut);
        root.fail_next_create_directory_probe(io::ErrorKind::WouldBlock);

        let outcome = root
            .bind_directory("")
            .unwrap()
            .ensure_directory_tree_with_outcome("first/second")
            .unwrap();

        assert_eq!(outcome.created, ["first", "first/second"]);
        assert_eq!(
            outcome.sync_error.as_ref().map(io::Error::kind),
            Some(io::ErrorKind::TimedOut)
        );
        assert!(outcome.terminal_error.is_none());
        assert!(directory.path().join("first/second").is_dir());
    }

    #[test]
    fn directory_tree_preserves_later_component_publication_uncertainty() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let fault_root = root.clone();
        root.after_next_directory_tree_create(move || {
            fault_root
                .fail_next_create_directory_mkdir_after_success(io::ErrorKind::ConnectionReset);
            fault_root.fail_next_create_directory_probe(io::ErrorKind::WouldBlock);
        });

        let outcome = root
            .bind_directory("")
            .unwrap()
            .ensure_directory_tree_with_outcome("first/second")
            .unwrap();

        assert_eq!(outcome.created, ["first", "first/second"]);
        assert_eq!(
            outcome.sync_error.as_ref().map(io::Error::kind),
            Some(io::ErrorKind::ConnectionReset)
        );
        assert!(outcome.terminal_error.is_none());
        assert!(directory.path().join("first/second").is_dir());
    }

    #[test]
    fn create_directory_reports_parent_sync_uncertainty() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        root.fail_next_create_directory_sync(io::ErrorKind::Other);

        let (created, outcome) = root.create_directory("", "uncertain").unwrap();
        assert_eq!(created, "uncertain");
        let PublishOutcome::PublishedSyncUncertain(error) = outcome else {
            panic!("injected post-mkdir sync failure must preserve publication state");
        };
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(directory.path().join("uncertain").is_dir());
    }

    #[test]
    fn create_directory_response_loss_with_probe_failure_is_published_uncertain() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        root.fail_next_create_directory_mkdir_after_success(io::ErrorKind::TimedOut);
        root.fail_next_create_directory_probe(io::ErrorKind::WouldBlock);

        let (created, outcome) = root.create_directory("", "ambiguous").unwrap();

        assert_eq!(created, "ambiguous");
        let PublishOutcome::PublishedUncertain(error) = outcome else {
            panic!("mkdir response loss with an inconclusive probe must be typed uncertain");
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(directory.path().join("ambiguous").is_dir());
    }

    #[test]
    fn empty_directory_delete_restores_late_external_content_instead_of_cleaning_it() {
        use std::os::fd::AsRawFd;

        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::create_dir(directory.path().join("empty")).unwrap();
        let external_writer = File::open(directory.path().join("empty")).unwrap();

        let mut staged = root.stage_delete_ready("empty").unwrap();
        assert!(!staged.status().directory_non_empty);
        let cleanup_root = root.clone();
        staged.run_after_promotion(move || {
            std::fs::write(
                format!("/proc/self/fd/{}/late.txt", external_writer.as_raw_fd()),
                b"must survive",
            )
            .unwrap();

            // Model a generic cleanup cursor that was started before the
            // operation journal existed. The in-process active guard must keep
            // it from recursively entering the newly promoted tombstone.
            let mut cleanup = start_cleanup_from_directory(
                cleanup_root.tombstones.as_ref(),
                CleanupPolicy::TombstoneRoot,
                None,
            )
            .unwrap();
            let mut removed = 0;
            loop {
                let batch = cleanup.run_batch(100).unwrap();
                removed += batch.removed;
                if batch.complete {
                    break;
                }
            }
            assert_eq!(removed, 0);
        });

        let error = match staged.commit(false) {
            Ok(_) => panic!("empty-only delete unexpectedly accepted late content"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::DirectoryNotEmpty);
        assert_eq!(
            std::fs::read(directory.path().join("empty/late.txt")).unwrap(),
            b"must survive"
        );
        assert!(root.pending_file_operations().unwrap().is_empty());
    }

    #[test]
    fn ambiguous_empty_directory_probe_preserves_intent_and_blocks_cleanup() {
        use std::os::fd::AsRawFd;

        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::create_dir(directory.path().join("empty")).unwrap();
        let external_writer = File::open(directory.path().join("empty")).unwrap();
        let mut staged = root.stage_delete_ready("empty").unwrap();
        staged.run_after_promotion(move || {
            std::fs::write(
                format!("/proc/self/fd/{}/late.txt", external_writer.as_raw_fd()),
                b"must survive ambiguous probe",
            )
            .unwrap();
        });
        root.fail_next_delete_identity_probe(io::ErrorKind::WouldBlock);

        let error = staged
            .commit(false)
            .err()
            .expect("ambiguous identity probe must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        let pending = root.pending_file_operations().unwrap();
        assert_eq!(pending.len(), 1);
        let tombstone_name = match &pending[0].operation {
            DurableFileOperation::Delete {
                tombstone_name,
                allow_recursive,
                ..
            } => {
                assert!(!allow_recursive);
                tombstone_name.clone()
            }
            DurableFileOperation::Rename { .. } => panic!("expected delete intent"),
        };
        let tombstone_path = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
            .join(&tombstone_name);
        assert_eq!(
            std::fs::read(tombstone_path.join("late.txt")).unwrap(),
            b"must survive ambiguous probe"
        );

        // Simulate a fresh process without the in-memory guard. Both targeted
        // and generic cleanup still fail closed because the durable intent is
        // consulted live.
        unregister_upload_fragment(&tombstone_name);
        assert_eq!(
            root.start_deletion_cleanup(&tombstone_name)
                .err()
                .expect("durable intent must block targeted cleanup")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        let mut cleanup = root.start_upload_fragment_cleanup().unwrap();
        let mut removed = 0;
        loop {
            let batch = cleanup.run_batch(100).unwrap();
            removed += batch.removed;
            if batch.complete {
                break;
            }
        }
        assert_eq!(removed, 0);
        assert!(tombstone_path.join("late.txt").is_file());

        root.fail_next_delete_identity_probe(io::ErrorKind::TimedOut);
        let recovery_error = root.recover_file_operation(&pending[0]).unwrap_err();
        assert_eq!(recovery_error.kind(), io::ErrorKind::TimedOut);
        assert!(tombstone_path.join("late.txt").is_file());
        assert_eq!(root.pending_file_operations().unwrap().len(), 1);
    }

    #[test]
    fn phase_less_legacy_journals_deserialize_as_moved() {
        let rename: DurableFileOperation = serde_json::from_value(serde_json::json!({
            "operation": "rename",
            "original_path": "before.txt",
            "new_path": "after.txt",
            "kind": "file",
            "device": 1,
            "inode": 2
        }))
        .unwrap();
        assert!(matches!(
            rename,
            DurableFileOperation::Rename {
                phase: DurableRenamePhase::Moved,
                ..
            }
        ));

        let delete: DurableFileOperation = serde_json::from_value(serde_json::json!({
            "operation": "delete",
            "original_path": "old.txt",
            "kind": "file",
            "device": 1,
            "inode": 2,
            "pending_name": deletion_pending_name(),
            "tombstone_name": deletion_tombstone_name(),
            "allow_recursive": false
        }))
        .unwrap();
        assert!(matches!(
            delete,
            DurableFileOperation::Delete {
                phase: DurableDeletePhase::Moved,
                ..
            }
        ));
    }

    #[test]
    fn rename_rollback_journal_cancels_after_namespace_was_restored() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("before.txt"), b"content").unwrap();

        let mut staged = root.stage_rename("before.txt", "after.txt").unwrap();
        replace_file_operation(
            &staged.operation_staging,
            &staged.operation_name,
            &DurableFileOperation::Rename {
                original_path: staged.original_path.clone(),
                new_path: staged.new_path.clone(),
                kind: staged.kind.into(),
                device: staged.source_identity.0,
                inode: staged.source_identity.1,
                phase: DurableRenamePhase::Rollback,
            },
        )
        .unwrap();
        linux::rename_noreplace(&staged.parent, &staged.new_name, &staged.original_name).unwrap();
        staged.parent.sync_all().unwrap();
        staged.committed = true;
        drop(staged);

        let pending = root.pending_file_operations().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            root.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Cancelled
        );
        assert_eq!(
            std::fs::read(directory.path().join("before.txt")).unwrap(),
            b"content"
        );
        assert!(!directory.path().join("after.txt").exists());
        assert!(root.pending_file_operations().unwrap().is_empty());
    }

    #[test]
    fn delete_intent_recovery_restores_the_pending_source_without_db_commit() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("restore.txt"), b"content").unwrap();

        let mut staged = root.stage_delete_ready("restore.txt").unwrap();
        let operation = DurableFileOperation::Delete {
            original_path: staged.original_path.clone(),
            kind: staged.status.kind.into(),
            device: staged.source_identity.0,
            inode: staged.source_identity.1,
            pending_name: staged.tombstone_name.clone(),
            tombstone_name: deletion_tombstone_name(),
            allow_recursive: false,
            phase: DurableDeletePhase::Intent,
        };
        write_file_operation(root.tombstones.as_ref(), &operation).unwrap();
        staged.committed = true;
        staged.release_active();
        drop(staged);

        let pending = root.pending_file_operations().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            root.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Cancelled
        );
        assert_eq!(
            std::fs::read(directory.path().join("restore.txt")).unwrap(),
            b"content"
        );
        assert!(root.pending_file_operations().unwrap().is_empty());
    }

    #[test]
    fn delete_rollback_journal_cancels_after_visible_restoration() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::create_dir(directory.path().join("restore-dir")).unwrap();

        let mut staged = root.stage_delete_ready("restore-dir").unwrap();
        let (committed_name, operation_name) = staged.promote_for_cleanup(false).unwrap();
        assert_eq!(committed_name, staged.tombstone_name);
        replace_delete_operation_phase(
            &staged.staging,
            &operation_name,
            DurableDeletePhase::Rollback,
        )
        .unwrap();
        linux::rename_noreplace_between(
            &staged.staging,
            &staged.tombstone_name,
            &staged.parent,
            &staged.original_name,
        )
        .unwrap();
        staged.parent.sync_all().unwrap();
        staged.staging.sync_all().unwrap();
        staged.committed = true;
        staged.release_active();
        drop(staged);

        let pending = root.pending_file_operations().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            root.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Cancelled
        );
        assert!(directory.path().join("restore-dir").is_dir());
        assert!(root.pending_file_operations().unwrap().is_empty());
    }
