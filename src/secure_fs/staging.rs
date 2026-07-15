#[cfg(test)]
use std::sync::Mutex;
use std::{ffi::OsStr, io};

use crate::path_security;

use super::identity::{entry_identity_state, entry_matches_identity};
use super::journal::{
    remove_file_operation, remove_pending_manifest, replace_delete_operation_phase,
    replace_file_operation, rollback_pending_delete, write_file_operation, write_pending_manifest,
};
use super::private_entries::{active_upload_fragment_guard, unregister_upload_fragment};
use super::{
    deletion_pending_name, deletion_tombstone_name, directory_scan_from_file, join_relative, linux,
    split_parent_name, DeleteCommitOutcome, DurableDeletePhase, DurableFileOperation,
    DurableRenamePhase, EntryIdentityState, EntryKind, EntryStatus, PendingDeleteCommit,
    SecureRoot, StagedDelete, StagedRename,
};

impl SecureRoot {
    pub fn stage_rename(&self, relative: &str, new_name: &str) -> io::Result<StagedRename> {
        use std::os::unix::fs::MetadataExt;

        let (parent_path, original_name) = split_parent_name(relative)?;
        let original_path = join_relative(&parent_path, &original_name);
        let new_name = path_security::safe_admin_filename(new_name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid destination name"))?;
        if original_name == new_name {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "new name matches current name",
            ));
        }
        let parent = self.root.bind_directory(&parent_path)?;
        let transaction_parent = parent.directory.try_clone()?;
        let operation_staging = self.tombstones.as_ref().try_clone()?;
        let source = linux::openat2(
            parent.directory.as_ref(),
            &original_name,
            linux::O_PATH | linux::O_NOFOLLOW,
        )?;
        let source_metadata = source.metadata()?;
        let kind = if source_metadata.is_file() {
            EntryKind::File
        } else if source_metadata.is_dir() {
            EntryKind::Directory
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "rename source is not a regular file or directory",
            ));
        };
        let source_identity = (source_metadata.dev(), source_metadata.ino());
        let new_path = join_relative(&parent_path, new_name);
        let intent = DurableFileOperation::Rename {
            original_path: original_path.clone(),
            new_path: new_path.clone(),
            kind: kind.into(),
            device: source_identity.0,
            inode: source_identity.1,
            phase: DurableRenamePhase::Intent,
        };
        let operation_name = match write_file_operation(self.tombstones.as_ref(), &intent) {
            Ok(name) => name,
            Err(error) => {
                // If publication succeeded but its directory fsync failed, the
                // intent may survive. The source name is still unchanged, so
                // recovery can safely cancel it without touching SQLite.
                return Err(error.into_io());
            }
        };
        #[cfg(test)]
        self.run_before_rename_hook();
        let rename = parent.rename_noreplace(&original_name, new_name);
        let destination_state =
            entry_identity_state(parent.directory.as_ref(), new_name, source_identity, kind)?;
        match (rename, destination_state) {
            (Ok(()), EntryIdentityState::Expected) => {}
            (Ok(()), EntryIdentityState::Missing) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "rename destination disappeared before identity verification",
                ));
            }
            (Ok(()), EntryIdentityState::Replaced) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "rename moved an object other than the authorized source",
                ));
            }
            (Err(error), EntryIdentityState::Expected) => {
                if entry_identity_state(
                    parent.directory.as_ref(),
                    &original_name,
                    source_identity,
                    kind,
                )? == EntryIdentityState::Expected
                {
                    remove_file_operation(self.tombstones.as_ref(), &operation_name)?;
                    return Err(error);
                }
                tracing::warn!(%error, from = %original_path, to = %new_path, "rename returned an error after the entry moved; continuing with verified identity");
            }
            (Err(error), EntryIdentityState::Missing) => {
                if entry_identity_state(
                    parent.directory.as_ref(),
                    &original_name,
                    source_identity,
                    kind,
                )? == EntryIdentityState::Expected
                {
                    remove_file_operation(self.tombstones.as_ref(), &operation_name)?;
                }
                return Err(error);
            }
            (Err(error), EntryIdentityState::Replaced) => {
                if entry_identity_state(
                    parent.directory.as_ref(),
                    &original_name,
                    source_identity,
                    kind,
                )? == EntryIdentityState::Expected
                {
                    remove_file_operation(self.tombstones.as_ref(), &operation_name)?;
                }
                return Err(error);
            }
        }
        // Do not let SQLite observe the new path until the directory entry is
        // durable. If fsync fails, the journal deliberately remains for startup
        // recovery instead of pretending that the cross-resource commit ended.
        transaction_parent.sync_all()?;
        replace_file_operation(
            self.tombstones.as_ref(),
            &operation_name,
            &DurableFileOperation::Rename {
                original_path: original_path.clone(),
                new_path: new_path.clone(),
                kind: kind.into(),
                device: source_identity.0,
                inode: source_identity.1,
                phase: DurableRenamePhase::Moved,
            },
        )?;
        Ok(StagedRename {
            original_path,
            new_path,
            kind,
            source_identity,
            committed: false,
            parent: transaction_parent,
            operation_staging,
            original_name,
            new_name: new_name.to_string(),
            operation_name,
            commit_started: false,
            _storage_instance_lock: self._storage_instance_lock.clone(),
        })
    }

    pub fn stage_delete(&self, relative: &str) -> io::Result<StagedDelete> {
        use std::os::unix::fs::MetadataExt;

        let (parent_path, original_name) = split_parent_name(relative)?;
        let original_path = join_relative(&parent_path, &original_name);
        let parent = self.root.bind_directory(&parent_path)?;
        // Acquire every capability needed by the returned transaction before the
        // source name is mutated. An fd-allocation failure must never strand an
        // untracked tombstone after the original path has disappeared.
        let rollback_parent = parent.directory.try_clone()?;
        let transaction_staging = self.tombstones.as_ref().try_clone()?;
        let source = linux::openat2(
            parent.directory.as_ref(),
            &original_name,
            linux::O_PATH | linux::O_NOFOLLOW,
        )?;
        let source_metadata = source.metadata()?;
        let source_identity = (source_metadata.dev(), source_metadata.ino());
        let source_kind = if source_metadata.is_file() {
            EntryKind::File
        } else if source_metadata.is_dir() {
            EntryKind::Directory
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "deletion target is not a regular file or directory",
            ));
        };
        let (tombstone_name, manifest_name) = loop {
            let candidate = deletion_pending_name();
            // Register before any staging I/O. Cleanup can never observe the
            // renamed pending entry before its active name is published.
            if !active_upload_fragment_guard().insert(candidate.clone()) {
                continue;
            }
            let manifest_name = match write_pending_manifest(
                self.tombstones.as_ref(),
                &candidate,
                &original_path,
            ) {
                Ok(name) => name,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    unregister_upload_fragment(&candidate);
                    continue;
                }
                Err(error) => {
                    unregister_upload_fragment(&candidate);
                    return Err(error);
                }
            };
            let rename = linux::rename_noreplace_between(
                parent.directory.as_ref(),
                &original_name,
                self.tombstones.as_ref(),
                &candidate,
            );
            #[cfg(test)]
            let rename = inject_error_after_successful_rename(
                rename,
                self.next_delete_staging_rename_error.as_ref(),
            );
            match rename {
                Ok(()) => break (candidate, manifest_name),
                Err(error) => {
                    if entry_matches_identity(
                        self.tombstones.as_ref(),
                        &candidate,
                        source_identity,
                        source_kind,
                    ) {
                        tracing::warn!(%error, pending = %candidate, original = %original_path, "delete staging rename returned an error after the source became pending; continuing with verified identity");
                        break (candidate, manifest_name);
                    }
                    let source_unchanged = entry_matches_identity(
                        parent.directory.as_ref(),
                        &original_name,
                        source_identity,
                        source_kind,
                    );
                    if source_unchanged {
                        if let Err(cleanup_error) =
                            remove_pending_manifest(self.tombstones.as_ref(), &manifest_name)
                        {
                            tracing::warn!(%cleanup_error, manifest = %manifest_name, "could not remove unused deletion manifest");
                        }
                        unregister_upload_fragment(&candidate);
                        if error.kind() == io::ErrorKind::AlreadyExists {
                            continue;
                        }
                    } else {
                        tracing::error!(%error, recovery_entry = %candidate, manifest = %manifest_name, original = %original_path, "delete staging rename outcome is ambiguous; recovery metadata was preserved");
                    }
                    return Err(error);
                }
            }
        };
        let active_key = tombstone_name.clone();
        let tombstone = match linux::openat2(
            self.tombstones.as_ref(),
            &tombstone_name,
            linux::O_PATH | linux::O_NOFOLLOW,
        ) {
            Ok(file) => file,
            Err(error) => {
                let rollback = rollback_pending_delete(
                    self.tombstones.as_ref(),
                    &tombstone_name,
                    &manifest_name,
                    parent.directory.as_ref(),
                    &original_name,
                    &original_path,
                );
                unregister_upload_fragment(&active_key);
                rollback?;
                return Err(error);
            }
        };
        let tombstone_metadata = match tombstone.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                let rollback = rollback_pending_delete(
                    self.tombstones.as_ref(),
                    &tombstone_name,
                    &manifest_name,
                    parent.directory.as_ref(),
                    &original_name,
                    &original_path,
                );
                unregister_upload_fragment(&active_key);
                rollback?;
                return Err(error);
            }
        };
        if (tombstone_metadata.dev(), tombstone_metadata.ino()) != source_identity
            || tombstone_metadata.is_dir() != source_metadata.is_dir()
            || tombstone_metadata.is_file() != source_metadata.is_file()
        {
            let rollback = rollback_pending_delete(
                self.tombstones.as_ref(),
                &tombstone_name,
                &manifest_name,
                parent.directory.as_ref(),
                &original_name,
                &original_path,
            );
            unregister_upload_fragment(&active_key);
            rollback?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "deletion target changed during atomic staging",
            ));
        }
        let status = if tombstone_metadata.is_file() {
            EntryStatus {
                kind: EntryKind::File,
                directory_non_empty: false,
            }
        } else if tombstone_metadata.is_dir() {
            let directory = match linux::openat2(
                self.tombstones.as_ref(),
                &tombstone_name,
                linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
            ) {
                Ok(directory) => directory,
                Err(error) => {
                    let rollback = rollback_pending_delete(
                        self.tombstones.as_ref(),
                        &tombstone_name,
                        &manifest_name,
                        parent.directory.as_ref(),
                        &original_name,
                        &original_path,
                    );
                    unregister_upload_fragment(&active_key);
                    rollback?;
                    return Err(error);
                }
            };
            let mut scan = match directory_scan_from_file(directory, false) {
                Ok(scan) => scan,
                Err(error) => {
                    let rollback = rollback_pending_delete(
                        self.tombstones.as_ref(),
                        &tombstone_name,
                        &manifest_name,
                        parent.directory.as_ref(),
                        &original_name,
                        &original_path,
                    );
                    unregister_upload_fragment(&active_key);
                    rollback?;
                    return Err(error);
                }
            };
            EntryStatus {
                kind: EntryKind::Directory,
                directory_non_empty: scan.entries.next().is_some(),
            }
        } else {
            let rollback = rollback_pending_delete(
                self.tombstones.as_ref(),
                &tombstone_name,
                &manifest_name,
                parent.directory.as_ref(),
                &original_name,
                &original_path,
            );
            unregister_upload_fragment(&active_key);
            rollback?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "deletion target is not a regular file or directory",
            ));
        };
        // The private destination must be durable before the visible source
        // removal. On either failure, restore through the manifest and report
        // the operation as failed instead of returning an uncertain stage.
        if let Err(error) = self.tombstones.sync_all() {
            let rollback = rollback_pending_delete(
                self.tombstones.as_ref(),
                &tombstone_name,
                &manifest_name,
                parent.directory.as_ref(),
                &original_name,
                &original_path,
            );
            unregister_upload_fragment(&active_key);
            rollback?;
            return Err(error);
        }
        if let Err(error) = parent.directory.sync_all() {
            let rollback = rollback_pending_delete(
                self.tombstones.as_ref(),
                &tombstone_name,
                &manifest_name,
                parent.directory.as_ref(),
                &original_name,
                &original_path,
            );
            unregister_upload_fragment(&active_key);
            rollback?;
            return Err(error);
        }
        Ok(StagedDelete {
            original_path,
            tombstone_path: tombstone_name.clone(),
            status,
            committed: false,
            parent: rollback_parent,
            staging: transaction_staging,
            original_name,
            tombstone_name,
            manifest_name,
            operation_name: None,
            source_identity,
            active_key: Some(active_key),
            _storage_instance_lock: self._storage_instance_lock.clone(),
            #[cfg(test)]
            next_promotion_rename_error: self.next_delete_promotion_rename_error.clone(),
            #[cfg(test)]
            next_identity_probe_error: self.next_delete_identity_probe_error.clone(),
            #[cfg(test)]
            after_promotion_hook: None,
        })
    }

    #[cfg(test)]
    pub(super) fn fail_next_delete_staging_rename_after_success(&self, kind: io::ErrorKind) {
        *self
            .next_delete_staging_rename_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(kind);
    }

    #[cfg(test)]
    pub(super) fn fail_next_delete_promotion_rename_after_success(&self, kind: io::ErrorKind) {
        *self
            .next_delete_promotion_rename_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(kind);
    }

    #[cfg(test)]
    pub(super) fn fail_next_delete_identity_probe(&self, kind: io::ErrorKind) {
        *self
            .next_delete_identity_probe_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(kind);
    }

    #[cfg(test)]
    pub(super) fn before_next_rename(&self, hook: impl FnOnce() + Send + 'static) {
        *self
            .before_rename_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Box::new(hook));
    }

    #[cfg(test)]
    fn run_before_rename_hook(&self) {
        let hook = self
            .before_rename_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(hook) = hook {
            hook();
        }
    }
}

impl StagedRename {
    pub fn original_path(&self) -> &str {
        &self.original_path
    }

    pub fn new_path(&self) -> &str {
        &self.new_path
    }

    pub fn kind(&self) -> EntryKind {
        self.kind
    }

    /// From this point onward a database error must leave the durable intent in
    /// place instead of rolling the filesystem back behind a possibly committed
    /// SQLite transaction.
    pub fn begin_database_commit(&mut self) {
        self.commit_started = true;
    }

    pub fn commit(mut self) -> io::Result<()> {
        self.committed = true;
        remove_file_operation(&self.operation_staging, &self.operation_name)
    }

    fn rollback(&self) -> io::Result<()> {
        match entry_identity_state(
            &self.parent,
            &self.new_name,
            self.source_identity,
            self.kind,
        )? {
            EntryIdentityState::Expected => {}
            EntryIdentityState::Missing => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "rename rollback target is missing",
                ));
            }
            EntryIdentityState::Replaced => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "rename rollback target was replaced",
                ));
            }
        }
        replace_file_operation(
            &self.operation_staging,
            &self.operation_name,
            &DurableFileOperation::Rename {
                original_path: self.original_path.clone(),
                new_path: self.new_path.clone(),
                kind: self.kind.into(),
                device: self.source_identity.0,
                inode: self.source_identity.1,
                phase: DurableRenamePhase::Rollback,
            },
        )?;
        linux::rename_noreplace(&self.parent, &self.new_name, &self.original_name)?;
        self.parent.sync_all()?;
        remove_file_operation(&self.operation_staging, &self.operation_name)
    }
}

impl Drop for StagedRename {
    fn drop(&mut self) {
        if !self.committed && !self.commit_started {
            if let Err(error) = self.rollback() {
                tracing::error!(%error, from = %self.new_path, to = %self.original_path, "could not roll back staged rename");
            }
        }
    }
}

impl StagedDelete {
    pub fn original_path(&self) -> &str {
        &self.original_path
    }

    pub fn status(&self) -> &EntryStatus {
        &self.status
    }

    pub fn commit(mut self, allow_recursive: bool) -> io::Result<PendingDeleteCommit> {
        // Confirmation is a capability, not a stale observation. Without it the
        // operation remains rmdir-only all the way through the final syscall.
        if self.status.kind == EntryKind::Directory
            && !allow_recursive
            && self.staged_directory_non_empty()?
        {
            return Err(io::Error::new(
                io::ErrorKind::DirectoryNotEmpty,
                "directory became non-empty after deletion confirmation",
            ));
        }

        let (committed_tombstone, operation_name) = self.promote_for_cleanup(allow_recursive)?;
        self.committed = true;
        remove_pending_manifest(&self.staging, &self.manifest_name)?;
        #[cfg(test)]
        if let Some(hook) = self.after_promotion_hook.take() {
            hook();
        }
        if self.status.kind == EntryKind::Directory && allow_recursive {
            return Ok(PendingDeleteCommit {
                staging: self.staging.try_clone()?,
                operation_name,
                outcome: DeleteCommitOutcome {
                    cleanup_pending: true,
                    tombstone_path: Some(committed_tombstone),
                },
                active_key: self.active_key.take(),
                _storage_instance_lock: self._storage_instance_lock.clone(),
            });
        }
        let removal = match self.status.kind {
            EntryKind::File => linux::unlink(&self.staging, OsStr::new(&self.tombstone_name)),
            EntryKind::Directory => linux::rmdir(&self.staging, OsStr::new(&self.tombstone_name)),
        };
        if let Err(error) = removal {
            if self.status.kind == EntryKind::Directory && !allow_recursive {
                match self.tombstone_identity_state()? {
                    EntryIdentityState::Missing => {
                        // Some remote filesystems can report a lost response
                        // after rmdir executed. Only an explicit missing entry
                        // proves that no object remains eligible for cleanup.
                        self.staging.sync_all()?;
                        return Ok(PendingDeleteCommit {
                            staging: self.staging.try_clone()?,
                            operation_name,
                            outcome: DeleteCommitOutcome {
                                cleanup_pending: false,
                                tombstone_path: None,
                            },
                            active_key: self.active_key.take(),
                            _storage_instance_lock: self._storage_instance_lock.clone(),
                        });
                    }
                    EntryIdentityState::Expected => {}
                    EntryIdentityState::Replaced => {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "empty-only deletion tombstone was replaced",
                        ));
                    }
                }
                let became_non_empty = self.staged_directory_non_empty().unwrap_or(false);
                match self.rollback() {
                    Ok(()) => {
                        self.release_active();
                        return if became_non_empty {
                            Err(io::Error::new(
                                io::ErrorKind::DirectoryNotEmpty,
                                "directory changed while the empty-only delete was committing",
                            ))
                        } else {
                            Err(error)
                        };
                    }
                    Err(rollback_error) => {
                        tracing::error!(%rollback_error, tombstone = %self.tombstone_path, "could not restore an empty-only deletion after a concurrent writer added content; recovery intent was preserved");
                        return Err(rollback_error);
                    }
                }
            }
            tracing::warn!(%error, tombstone = %self.tombstone_path, "deletion tombstone cleanup deferred");
            return Ok(PendingDeleteCommit {
                staging: self.staging.try_clone()?,
                operation_name,
                outcome: DeleteCommitOutcome {
                    cleanup_pending: true,
                    tombstone_path: Some(committed_tombstone),
                },
                active_key: self.active_key.take(),
                _storage_instance_lock: self._storage_instance_lock.clone(),
            });
        }
        self.staging.sync_all()?;
        Ok(PendingDeleteCommit {
            staging: self.staging.try_clone()?,
            operation_name,
            outcome: DeleteCommitOutcome {
                cleanup_pending: false,
                tombstone_path: None,
            },
            active_key: self.active_key.take(),
            _storage_instance_lock: self._storage_instance_lock.clone(),
        })
    }

    #[cfg(test)]
    pub(super) fn run_after_promotion(&mut self, hook: impl FnOnce() + Send + 'static) {
        self.after_promotion_hook = Some(Box::new(hook));
    }

    fn tombstone_identity_state(&self) -> io::Result<EntryIdentityState> {
        #[cfg(test)]
        if let Some(kind) = self
            .next_identity_probe_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            return Err(io::Error::new(
                kind,
                "injected deletion identity probe failure",
            ));
        }
        entry_identity_state(
            &self.staging,
            &self.tombstone_name,
            self.source_identity,
            self.status.kind,
        )
    }

    fn staged_directory_non_empty(&self) -> io::Result<bool> {
        let directory = linux::openat2(
            &self.staging,
            &self.tombstone_name,
            linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
        )?;
        let mut scan = directory_scan_from_file(directory, false)?;
        Ok(scan.entries.next().is_some())
    }

    fn rollback(&self) -> io::Result<()> {
        if let Some(operation_name) = self.operation_name.as_deref() {
            // A forward journal must never outlive a namespace rollback. Make
            // the rollback decision durable first; recovery can then finish it
            // without changing SQLite at every following crash boundary.
            replace_delete_operation_phase(
                &self.staging,
                operation_name,
                DurableDeletePhase::Rollback,
            )?;
        }
        linux::rename_noreplace_between(
            &self.staging,
            &self.tombstone_name,
            &self.parent,
            &self.original_name,
        )?;
        // Cross-directory rename durability is destination-before-source: the
        // visible restoration must land before removal of the private name.
        self.parent.sync_all()?;
        self.staging.sync_all()?;
        if let Err(error) = remove_pending_manifest(&self.staging, &self.manifest_name) {
            tracing::warn!(%error, manifest = %self.manifest_name, "could not remove durable rollback manifest");
        }
        if let Some(operation_name) = self.operation_name.as_deref() {
            remove_file_operation(&self.staging, operation_name)?;
        }
        Ok(())
    }

    pub(super) fn promote_for_cleanup(
        &mut self,
        allow_recursive: bool,
    ) -> io::Result<(String, String)> {
        use std::os::unix::fs::MetadataExt;

        let pending = linux::openat2(
            &self.staging,
            &self.tombstone_name,
            linux::O_PATH | linux::O_NOFOLLOW,
        )?;
        let pending_metadata = pending.metadata()?;
        let pending_identity = (pending_metadata.dev(), pending_metadata.ino());
        for _ in 0..16 {
            let committed_name = deletion_tombstone_name();
            if !active_upload_fragment_guard().insert(committed_name.clone()) {
                continue;
            }
            let operation = DurableFileOperation::Delete {
                original_path: self.original_path.clone(),
                kind: self.status.kind.into(),
                device: self.source_identity.0,
                inode: self.source_identity.1,
                pending_name: self.tombstone_name.clone(),
                tombstone_name: committed_name.clone(),
                allow_recursive,
                phase: DurableDeletePhase::Intent,
            };
            let operation_name = match write_file_operation(&self.staging, &operation) {
                Ok(name) => {
                    self.operation_name = Some(name.clone());
                    name
                }
                Err(mut error) => {
                    self.operation_name = error.published_name.take();
                    unregister_upload_fragment(&committed_name);
                    return Err(error.into_io());
                }
            };
            let rename =
                linux::rename_noreplace(&self.staging, &self.tombstone_name, &committed_name);
            #[cfg(test)]
            let rename = inject_error_after_successful_rename(
                rename,
                self.next_promotion_rename_error.as_ref(),
            );
            match rename {
                Ok(()) => {
                    let committed_name = self.finish_promotion(committed_name);
                    self.staging.sync_all()?;
                    replace_delete_operation_phase(
                        &self.staging,
                        &operation_name,
                        DurableDeletePhase::Moved,
                    )?;
                    return Ok((committed_name, operation_name));
                }
                Err(error) => {
                    if entry_matches_identity(
                        &self.staging,
                        &committed_name,
                        pending_identity,
                        self.status.kind,
                    ) {
                        tracing::warn!(%error, tombstone = %committed_name, "committed deletion rename returned an error after the pending entry moved; continuing with verified identity");
                        let committed_name = self.finish_promotion(committed_name);
                        self.staging.sync_all()?;
                        replace_delete_operation_phase(
                            &self.staging,
                            &operation_name,
                            DurableDeletePhase::Moved,
                        )?;
                        return Ok((committed_name, operation_name));
                    }
                    unregister_upload_fragment(&committed_name);
                    if entry_matches_identity(
                        &self.staging,
                        &self.tombstone_name,
                        pending_identity,
                        self.status.kind,
                    ) {
                        remove_file_operation(&self.staging, &operation_name)?;
                        self.operation_name = None;
                    }
                    if error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(error);
                    }
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate committed deletion tombstone",
        ))
    }

    fn finish_promotion(&mut self, committed_name: String) -> String {
        let mut active = active_upload_fragment_guard();
        if let Some(previous) = self.active_key.replace(committed_name.clone()) {
            active.remove(&previous);
        }
        self.tombstone_name = committed_name.clone();
        self.tombstone_path = committed_name.clone();
        drop(active);
        committed_name
    }

    pub(super) fn release_active(&mut self) {
        if let Some(active_key) = self.active_key.take() {
            unregister_upload_fragment(&active_key);
        }
    }
}

impl PendingDeleteCommit {
    pub fn outcome(&self) -> &DeleteCommitOutcome {
        &self.outcome
    }

    pub fn complete(mut self) -> io::Result<DeleteCommitOutcome> {
        remove_file_operation(&self.staging, &self.operation_name)?;
        if let Some(active_key) = self.active_key.take() {
            unregister_upload_fragment(&active_key);
        }
        Ok(self.outcome.clone())
    }
}

impl Drop for PendingDeleteCommit {
    fn drop(&mut self) {
        if let Some(active_key) = self.active_key.take() {
            unregister_upload_fragment(&active_key);
        }
    }
}

#[cfg(test)]
fn inject_error_after_successful_rename(
    rename: io::Result<()>,
    next_error: &Mutex<Option<io::ErrorKind>>,
) -> io::Result<()> {
    rename?;
    let kind = next_error
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    match kind {
        Some(kind) => Err(io::Error::new(kind, "injected rename response loss")),
        None => Ok(()),
    }
}

impl Drop for StagedDelete {
    fn drop(&mut self) {
        if !self.committed {
            if let Err(error) = self.rollback() {
                // Pending names are deliberately excluded from every automatic
                // cleanup pass. If a co-writer occupied the original name, both
                // objects survive and an operator can recover the pending entry.
                tracing::error!(%error, recovery_entry = %self.tombstone_path, original = %self.original_path, "could not roll back staged deletion; private recovery entry was preserved");
            }
            self.release_active();
        }
    }
}
