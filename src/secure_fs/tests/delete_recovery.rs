    #[test]
    fn upload_staging_is_reserved_hidden_and_separate_from_destination() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let staging = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(UPLOAD_STAGING_DIRECTORY_NAME);
        let mut pending = root.begin_upload("").unwrap();

        assert!(root.bind_directory(INTERNAL_DIRECTORY_NAME).is_err());
        assert!(root.list("", 0, 100).unwrap().is_empty());
        assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 1);
        let mut file = pending.take_file().unwrap();
        file.write_all(b"complete").unwrap();
        file.sync_all().unwrap();
        drop(file);
        pending.publish("published.txt").unwrap();

        assert_eq!(std::fs::read_dir(staging).unwrap().count(), 0);
        assert_eq!(
            std::fs::read(directory.path().join("published.txt")).unwrap(),
            b"complete"
        );
    }

    #[test]
    fn cleanup_skips_an_active_deletion_tombstone() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("keep.txt"), b"keep").unwrap();
        let staged = root.stage_delete_ready("keep.txt").unwrap();
        let mut cleanup = root.start_upload_fragment_cleanup().unwrap();
        let mut removed = 0;
        loop {
            let batch = cleanup.run_batch(1).unwrap();
            removed += batch.removed;
            if batch.complete {
                break;
            }
        }
        assert_eq!(removed, 0);
        drop(staged);
        assert_eq!(
            std::fs::read(directory.path().join("keep.txt")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn delete_staging_reconciles_executed_rename_reported_as_exists() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("response-loss.txt"), b"original").unwrap();
        root.fail_next_delete_staging_rename_after_success(io::ErrorKind::AlreadyExists);

        let staged = root.stage_delete_ready("response-loss.txt").unwrap();
        assert!(!directory.path().join("response-loss.txt").exists());
        let recovery_path = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
            .join(&staged.tombstone_name);
        assert_eq!(std::fs::read(&recovery_path).unwrap(), b"original");
        assert!(recovery_path
            .with_file_name(deletion_manifest_name(&staged.tombstone_name))
            .is_file());

        drop(staged);
        assert_eq!(
            std::fs::read(directory.path().join("response-loss.txt")).unwrap(),
            b"original"
        );
        assert_eq!(
            std::fs::read_dir(
                directory
                    .path()
                    .join(INTERNAL_DIRECTORY_NAME)
                    .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
            )
            .unwrap()
            .count(),
            0
        );
    }

    #[test]
    fn delete_staging_response_loss_with_probe_failures_preserves_recovery_intent() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("ambiguous.txt"), b"original").unwrap();
        root.fail_next_delete_staging_rename_after_success(io::ErrorKind::TimedOut);
        root.fail_next_delete_staging_identity_probes(io::ErrorKind::WouldBlock, 2);

        let outcome = root.stage_delete("ambiguous.txt").unwrap();
        let DeleteStageOutcome::PublishedUncertain {
            original_path,
            kind,
            error,
        } = outcome
        else {
            panic!("inconclusive delete staging must not be returned as a normal error");
        };
        assert_eq!(original_path, "ambiguous.txt");
        assert_eq!(kind, EntryKind::File);
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(!directory.path().join("ambiguous.txt").exists());

        let tombstones = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME);
        assert_eq!(std::fs::read_dir(&tombstones).unwrap().count(), 2);
        root.recover_pending_deletions(&[]).unwrap();
        assert_eq!(
            std::fs::read(directory.path().join("ambiguous.txt")).unwrap(),
            b"original"
        );
        assert_eq!(std::fs::read_dir(tombstones).unwrap().count(), 0);
    }

    #[test]
    fn delete_restore_response_loss_returns_original_error_after_verified_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("restored.txt"), b"original").unwrap();
        root.fail_next_delete_post_stage(io::ErrorKind::InvalidData);
        root.fail_next_delete_rollback_rename_after_success(io::ErrorKind::TimedOut);

        let Err(error) = root.stage_delete("restored.txt") else {
            panic!("a verified durable rollback must return the original pre-publication error");
        };

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            std::fs::read(directory.path().join("restored.txt")).unwrap(),
            b"original"
        );
        assert_eq!(
            std::fs::read_dir(
                directory
                    .path()
                    .join(INTERNAL_DIRECTORY_NAME)
                    .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
            )
            .unwrap()
            .count(),
            0
        );
    }

    #[test]
    fn deletion_promotion_reconciles_response_loss_before_exists_handling() {
        for error_kind in [io::ErrorKind::AlreadyExists, io::ErrorKind::Other] {
            let directory = tempfile::tempdir().unwrap();
            let root = SecureRoot::open(directory.path()).unwrap();
            std::fs::write(directory.path().join("commit.txt"), b"content").unwrap();
            let staged = root.stage_delete_ready("commit.txt").unwrap();
            root.fail_next_delete_promotion_rename_after_success(error_kind);

            let outcome = staged.commit(false).unwrap().complete().unwrap();
            assert_eq!(
                outcome,
                DeleteCommitOutcome {
                    cleanup_pending: false,
                    tombstone_path: None,
                }
            );
            assert!(!directory.path().join("commit.txt").exists());
            assert_eq!(
                std::fs::read_dir(
                    directory
                        .path()
                        .join(INTERNAL_DIRECTORY_NAME)
                        .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
                )
                .unwrap()
                .count(),
                0
            );
        }
    }

    #[test]
    fn rollback_conflict_preserves_recovery_entry_and_new_external_file() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("report.txt"), b"original").unwrap();
        let staged = root.stage_delete_ready("report.txt").unwrap();
        let recovery_name = staged.tombstone_name.clone();

        // Simulate a co-writer reusing the visible name before rollback.
        std::fs::write(directory.path().join("report.txt"), b"external").unwrap();
        drop(staged);

        assert_eq!(
            std::fs::read(directory.path().join("report.txt")).unwrap(),
            b"external"
        );
        let recovery_path = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
            .join(&recovery_name);
        let manifest_path = recovery_path.with_file_name(deletion_manifest_name(&recovery_name));
        assert_eq!(std::fs::read(&recovery_path).unwrap(), b"original");
        assert!(manifest_path.is_file());
        let mut cleanup = root.start_upload_fragment_cleanup().unwrap();
        let batch = cleanup.run_batch(100).unwrap();
        assert!(batch.complete);
        assert_eq!(batch.removed, 0);
        assert_eq!(std::fs::read(recovery_path).unwrap(), b"original");
        drop(root);
        let error = SecureRoot::open(directory.path())
            .err()
            .expect("startup must refuse an unresolved unjournaled rollback conflict");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(directory.path().join("report.txt")).unwrap(),
            b"external"
        );
        assert!(manifest_path.is_file());
    }

    #[test]
    fn restart_restores_uncommitted_pending_delete_from_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("restore.txt"), b"original").unwrap();
        let staged = root.stage_delete_ready("restore.txt").unwrap();
        let active_key = staged.active_key.clone().unwrap();

        // Simulate process loss: Drop cannot run and the in-memory registry is
        // empty in the next process, while pending data + durable manifest remain.
        std::mem::forget(staged);
        unregister_upload_fragment(&active_key);
        drop(root);

        let reopened = SecureRoot::open(directory.path()).unwrap();
        assert_eq!(
            std::fs::read(directory.path().join("restore.txt")).unwrap(),
            b"original"
        );
        let tombstones = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME);
        assert_eq!(std::fs::read_dir(tombstones).unwrap().count(), 0);
        drop(reopened);
    }

    #[test]
    fn restart_restores_every_unjournaled_delete_and_preserves_journaled_work() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let mut staged_deletes = Vec::new();
        for index in 0..32 {
            let path = format!("restore-{index}.txt");
            std::fs::write(directory.path().join(&path), path.as_bytes()).unwrap();
            staged_deletes.push((path.clone(), root.stage_delete_ready(&path).unwrap()));
        }
        std::fs::write(directory.path().join("forward.txt"), b"forward").unwrap();
        let forward = root.stage_delete_ready("forward.txt").unwrap();
        let forward_operation = DurableFileOperation::Delete {
            original_path: forward.original_path.clone(),
            kind: forward.status.kind.into(),
            device: forward.source_identity.0,
            inode: forward.source_identity.1,
            pending_name: forward.tombstone_name.clone(),
            tombstone_name: deletion_tombstone_name(),
            allow_recursive: false,
            phase: DurableDeletePhase::Moved,
        };
        write_file_operation(root.tombstones.as_ref(), &forward_operation).unwrap();

        for (_, staged) in staged_deletes.iter() {
            unregister_upload_fragment(staged.active_key.as_ref().unwrap());
        }
        unregister_upload_fragment(forward.active_key.as_ref().unwrap());
        for (_, staged) in staged_deletes {
            std::mem::forget(staged);
        }
        std::mem::forget(forward);
        drop(root);

        let reopened = SecureRoot::open(directory.path()).unwrap();
        for index in 0..32 {
            let path = format!("restore-{index}.txt");
            assert_eq!(
                std::fs::read(directory.path().join(&path)).unwrap(),
                path.as_bytes()
            );
        }
        assert!(!directory.path().join("forward.txt").exists());
        let pending = reopened.pending_file_operations().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            reopened.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Delete {
                original_path: "forward.txt".into(),
                is_directory: false,
                tombstone_path: None,
            }
        );
        reopened.complete_file_operation(&pending[0]).unwrap();
        assert!(reopened.pending_file_operations().unwrap().is_empty());
    }

    #[test]
    fn restart_refuses_unjournaled_pending_delete_when_original_was_reused() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("shared.txt"), b"original").unwrap();
        let staged = root.stage_delete_ready("shared.txt").unwrap();
        let pending_name = staged.tombstone_name.clone();
        let active_key = staged.active_key.clone().unwrap();
        std::fs::write(directory.path().join("shared.txt"), b"replacement").unwrap();

        std::mem::forget(staged);
        unregister_upload_fragment(&active_key);
        drop(root);

        let error = SecureRoot::open(directory.path())
            .err()
            .expect("startup must fail closed while an unjournaled delete cannot roll back");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(directory.path().join("shared.txt")).unwrap(),
            b"replacement"
        );
        let recovery_path = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
            .join(pending_name);
        assert_eq!(std::fs::read(recovery_path).unwrap(), b"original");
    }

    #[test]
    fn restart_leaves_journaled_pending_delete_for_forward_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("forward.txt"), b"content").unwrap();
        let staged = root.stage_delete_ready("forward.txt").unwrap();
        let active_key = staged.active_key.clone().unwrap();
        let committed_name = deletion_tombstone_name();
        let operation = DurableFileOperation::Delete {
            original_path: staged.original_path.clone(),
            kind: staged.status.kind.into(),
            device: staged.source_identity.0,
            inode: staged.source_identity.1,
            pending_name: staged.tombstone_name.clone(),
            tombstone_name: committed_name,
            allow_recursive: false,
            phase: DurableDeletePhase::Moved,
        };
        write_file_operation(root.tombstones.as_ref(), &operation).unwrap();

        std::mem::forget(staged);
        unregister_upload_fragment(&active_key);
        drop(root);

        let reopened = SecureRoot::open(directory.path()).unwrap();
        assert!(!directory.path().join("forward.txt").exists());
        let pending = reopened.pending_file_operations().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            reopened.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Delete {
                original_path: "forward.txt".into(),
                is_directory: false,
                tombstone_path: None,
            }
        );
        reopened.complete_file_operation(&pending[0]).unwrap();
        assert!(reopened.pending_file_operations().unwrap().is_empty());
    }

    #[test]
    fn startup_removes_only_strict_incomplete_operation_journal_names() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let tombstones = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME);
        let temporary_names = (0..32)
            .map(|_| format!("{}.pending", file_operation_name()))
            .collect::<Vec<_>>();
        let unknown_name = format!("{}.pending.backup", file_operation_name());
        let unknown_manifest = format!("not-a-delete{DELETION_MANIFEST_SUFFIX}");
        for temporary_name in &temporary_names {
            std::fs::write(tombstones.join(temporary_name), b"partial").unwrap();
        }
        std::fs::write(tombstones.join(&unknown_name), b"preserve").unwrap();
        std::fs::write(tombstones.join(&unknown_manifest), b"preserve manifest").unwrap();
        drop(root);

        let reopened = SecureRoot::open(directory.path()).unwrap();
        assert!(temporary_names
            .iter()
            .all(|temporary_name| !tombstones.join(temporary_name).exists()));
        assert_eq!(
            std::fs::read(tombstones.join(unknown_name)).unwrap(),
            b"preserve"
        );
        assert_eq!(
            std::fs::read(tombstones.join(unknown_manifest)).unwrap(),
            b"preserve manifest"
        );
        drop(reopened);
    }

    #[test]
    fn startup_fails_closed_and_preserves_an_invalid_orphan_delete_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let tombstones = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME);
        let manifest_name = deletion_manifest_name(&deletion_pending_name());
        std::fs::write(tombstones.join(&manifest_name), b"not valid json").unwrap();
        drop(root);

        let error = SecureRoot::open(directory.path())
            .err()
            .expect("startup must fail closed on an invalid recovery manifest");
        assert!(error.to_string().contains("has no valid recovery manifest"));
        assert_eq!(
            std::fs::read(tombstones.join(manifest_name)).unwrap(),
            b"not valid json"
        );
    }

    #[test]
    fn committed_delete_removes_pending_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("delete.txt"), b"content").unwrap();
        let staged = root.stage_delete_ready("delete.txt").unwrap();
        assert!(staged
            .commit(false)
            .unwrap()
            .complete()
            .unwrap()
            .tombstone_path
            .is_none());
        let tombstones = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME);
        assert_eq!(std::fs::read_dir(tombstones).unwrap().count(), 0);
    }

    #[test]
    fn preprovisioned_sibling_staging_cannot_be_reached_through_share_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let mount = tempfile::tempdir().unwrap();
        let shared = mount.path().join("shared");
        let internal = mount.path().join(INTERNAL_DIRECTORY_NAME);
        std::fs::create_dir(&shared).unwrap();
        std::fs::create_dir(&internal).unwrap();
        std::fs::create_dir(internal.join(UPLOAD_STAGING_DIRECTORY_NAME)).unwrap();
        std::fs::create_dir(internal.join(TOMBSTONE_STAGING_DIRECTORY_NAME)).unwrap();
        for path in [
            internal.as_path(),
            &internal.join(UPLOAD_STAGING_DIRECTORY_NAME),
            &internal.join(TOMBSTONE_STAGING_DIRECTORY_NAME),
        ] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let root = SecureRoot::open_configured(&shared, Some(&internal), true, true).unwrap();
        symlink("../.vaultlink-internal", shared.join("leak")).unwrap();

        assert!(root.bind_directory("leak/uploads").is_err());
    }

    #[test]
    fn nested_reserved_internal_storage_is_filtered_and_unreachable() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let shared = tempfile::tempdir().unwrap();
        let internal = shared.path().join(INTERNAL_DIRECTORY_NAME);
        std::fs::create_dir(&internal).unwrap();
        std::fs::create_dir(internal.join(UPLOAD_STAGING_DIRECTORY_NAME)).unwrap();
        std::fs::create_dir(internal.join(TOMBSTONE_STAGING_DIRECTORY_NAME)).unwrap();
        for path in [
            internal.as_path(),
            &internal.join(UPLOAD_STAGING_DIRECTORY_NAME),
            &internal.join(TOMBSTONE_STAGING_DIRECTORY_NAME),
        ] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(shared.path().join("document.txt"), b"visible").unwrap();
        symlink(
            INTERNAL_DIRECTORY_NAME,
            shared.path().join("internal-alias"),
        )
        .unwrap();

        let root = SecureRoot::open_configured(shared.path(), Some(&internal), true, true).unwrap();
        let entries = root.list("", 0, 100).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "document.txt");
        assert!(root.metadata(INTERNAL_DIRECTORY_NAME).is_err());
        assert!(root.bind_directory("internal-alias/uploads").is_err());
    }
