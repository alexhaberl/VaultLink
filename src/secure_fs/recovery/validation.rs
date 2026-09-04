fn validate_file_operation(operation: &DurableFileOperation) -> io::Result<()> {
    let (device, inode) = match operation {
        DurableFileOperation::Rename {
            original_path,
            new_path,
            device,
            inode,
            ..
        } => {
            let (original_parent, _) = split_parent_name(original_path)?;
            let (new_parent, _) = split_parent_name(new_path)?;
            if original_parent != new_parent || original_path == new_path {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid rename recovery journal",
                ));
            }
            (*device, *inode)
        }
        DurableFileOperation::Delete {
            original_path,
            device,
            inode,
            pending_name,
            tombstone_name,
            ..
        } => {
            split_parent_name(original_path)?;
            if !is_deletion_pending_name(OsStr::new(pending_name))
                || !is_deletion_tombstone_name(OsStr::new(tombstone_name))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid delete recovery journal",
                ));
            }
            (*device, *inode)
        }
    };
    if device == 0 || inode == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file-operation journal has an invalid filesystem identity",
        ));
    }
    Ok(())
}

fn snapshot_directory_names(directory: &File) -> io::Result<Vec<OsString>> {
    use std::os::fd::AsRawFd;

    let proc_path = format!("/proc/self/fd/{}", directory.as_raw_fd());
    std::fs::read_dir(proc_path)?
        .map(|item| item.map(|entry| entry.file_name()))
        .collect()
}

impl SecureRoot {
    pub(super) fn remove_incomplete_file_operation_writes(&self) -> io::Result<()> {
        let names = snapshot_directory_names(self.tombstones.as_ref())?;
        let mut removed = false;
        for name in names {
            // Orphaned delete manifests are recovery intents, not incomplete
            // writes. recover_pending_deletions syncs the restored visible
            // parent before removing them.
            let should_remove = is_file_operation_temporary_name(&name);
            if !should_remove {
                continue;
            }
            match linux::unlink(self.tombstones.as_ref(), &name) {
                Ok(()) => removed = true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        if removed {
            self.tombstones.sync_all()?;
        }
        Ok(())
    }

    pub(crate) fn recover_pending_deletions(
        &self,
        pending_operations: &[PendingFileOperation],
    ) -> io::Result<()> {
        let journaled_pending: HashSet<&str> = pending_operations
            .iter()
            .filter_map(|pending| match &pending.operation {
                DurableFileOperation::Delete { pending_name, .. } => Some(pending_name.as_str()),
                DurableFileOperation::Rename { .. } => None,
            })
            .collect();
        let names = snapshot_directory_names(self.tombstones.as_ref())?;
        for manifest_name in &names {
            let Some(pending_name) = deletion_pending_from_manifest_name(manifest_name) else {
                continue;
            };
            if journaled_pending.contains(pending_name)
                || entry_exists(self.tombstones.as_ref(), pending_name)?
            {
                continue;
            }
            let Some(manifest_name) = manifest_name.to_str() else {
                continue;
            };
            let original_path = read_pending_manifest(self.tombstones.as_ref(), manifest_name)
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!(
                            "restored deletion {pending_name} has no valid recovery manifest: {error}"
                        ),
                    )
                })?;
            let (parent_path, original_name) = split_parent_name(&original_path)?;
            let parent = self.root.bind_directory(&parent_path)?;
            if !entry_exists(parent.directory.as_ref(), &original_name)? {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "delete recovery lost both pending entry {pending_name} and original path {original_path}"
                    ),
                ));
            }
            parent.directory.sync_all()?;
            self.tombstones.sync_all()?;
            remove_pending_manifest(self.tombstones.as_ref(), manifest_name)?;
            unregister_upload_fragment(pending_name);
            tracing::warn!(
                recovery_entry = %EscapedLogPath::new(pending_name),
                original = %EscapedLogPath::new(&original_path),
                "finalized an uncertain restored deletion during recovery"
            );
        }
        for pending_name in names {
            if !is_deletion_pending_name(&pending_name) {
                continue;
            }
            let Some(pending_name) = pending_name.to_str() else {
                continue;
            };
            if journaled_pending.contains(pending_name) {
                continue;
            }
            let manifest_name = deletion_manifest_name(pending_name);
            let original_path = read_pending_manifest(self.tombstones.as_ref(), &manifest_name)
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!(
                            "pending deletion {pending_name} has no valid recovery manifest: {error}"
                        ),
                    )
                })?;
            let (parent_path, original_name) = split_parent_name(&original_path)?;
            let parent = self.root.bind_directory(&parent_path)?;
            linux::rename_noreplace_between(
                self.tombstones.as_ref(),
                pending_name,
                parent.directory.as_ref(),
                &original_name,
            )?;
            parent.directory.sync_all()?;
            self.tombstones.sync_all()?;
            let manifest_result = remove_pending_manifest(self.tombstones.as_ref(), &manifest_name);
            unregister_upload_fragment(pending_name);
            manifest_result?;
            tracing::warn!(
                recovery_entry = %EscapedLogPath::new(pending_name),
                original = %EscapedLogPath::new(&original_path),
                "restored uncommitted deletion during recovery"
            );
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fail_next_cleanup_starts(&self, kind: io::ErrorKind, count: usize) {
        assert!(count > 0, "cleanup failure count must be positive");
        *self
            .next_cleanup_start_errors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((kind, count));
    }

    #[cfg(test)]
    pub(crate) fn fail_next_cleanup_batch(&self, kind: io::ErrorKind) {
        *self
            .next_cleanup_batch_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(kind);
    }

    #[cfg(test)]
    pub(crate) fn before_next_cleanup_batch(&self, hook: impl FnOnce() + Send + 'static) {
        *self
            .before_cleanup_batch_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Box::new(hook));
    }

    #[cfg(test)]
    fn injected_cleanup_start_error(&self) -> Option<io::Error> {
        let mut failure = self
            .next_cleanup_start_errors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (kind, remaining) = failure.as_mut()?;
        let error = io::Error::new(*kind, "injected cleanup start failure");
        *remaining -= 1;
        if *remaining == 0 {
            *failure = None;
        }
        Some(error)
    }

    /// Starts a recursive cleanup cursor suitable for bounded background batches.
    /// Active transactions and tombstones referenced by durable operation
    /// journals cannot be removed by the generic cleanup pass.
    pub fn start_upload_fragment_cleanup(&self) -> io::Result<UploadFragmentCleanup> {
        use std::os::unix::fs::MetadataExt;

        #[cfg(test)]
        if let Some(error) = self.injected_cleanup_start_error() {
            return Err(error);
        }

        let uploads = self.root.staging.as_ref().try_clone()?;
        let tombstones = self.tombstones.as_ref().try_clone()?;
        let upload_identity = uploads.metadata()?;
        let tombstone_identity = tombstones.metadata()?;
        Ok(UploadFragmentCleanup {
            directories: vec![
                cleanup_directory_from_file(&tombstones, CleanupPolicy::TombstoneRoot)?,
                cleanup_directory_from_file(&uploads, CleanupPolicy::UploadFragments)?,
            ],
            visited: HashSet::from([
                (upload_identity.dev(), upload_identity.ino()),
                (tombstone_identity.dev(), tombstone_identity.ino()),
            ]),
            max_directory_stack: MAX_CLEANUP_DIRECTORY_STACK,
            max_visited_directories: MAX_CLEANUP_VISITED_DIRECTORIES,
            operation_staging: Some(self.tombstones.as_ref().try_clone()?),
            _storage_instance_lock: self._storage_instance_lock.clone(),
            #[cfg(test)]
            next_batch_error: Some(self.next_cleanup_batch_error.clone()),
            #[cfg(test)]
            before_batch_hook: Some(self.before_cleanup_batch_hook.clone()),
        })
    }

    pub fn start_deletion_cleanup(
        &self,
        tombstone_relative: &str,
    ) -> io::Result<UploadFragmentCleanup> {
        #[cfg(test)]
        if let Some(error) = self.injected_cleanup_start_error() {
            return Err(error);
        }
        let (parent_path, tombstone_name) = split_parent_name_private(tombstone_relative)?;
        if !parent_path.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "deletion tombstone must be inside the private tombstone staging directory",
            ));
        }
        if !is_deletion_tombstone_name(OsStr::new(&tombstone_name)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid deletion tombstone",
            ));
        }
        let is_active = active_upload_fragment_guard().contains(&tombstone_name);
        let has_durable_intent = deletion_tombstone_has_durable_intent(
            self.tombstones.as_ref(),
            OsStr::new(&tombstone_name),
        )?;
        if is_active || has_durable_intent {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "deletion tombstone still belongs to an incomplete operation",
            ));
        }
        use std::os::unix::fs::MetadataExt;
        let directory = linux::openat2(
            self.tombstones.as_ref(),
            &tombstone_name,
            linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
        )?;
        let metadata = directory.metadata()?;
        let deletion_root = Arc::new(directory.try_clone()?);
        let mut cleanup = cleanup_directory_from_file(&directory, CleanupPolicy::DeleteAll)?;
        cleanup.remove_from = Some((
            self.tombstones.as_ref().try_clone()?,
            OsString::from(tombstone_name),
        ));
        cleanup.deletion_root = Some(deletion_root);
        Ok(UploadFragmentCleanup {
            directories: vec![cleanup],
            visited: HashSet::from([(metadata.dev(), metadata.ino())]),
            max_directory_stack: MAX_CLEANUP_DIRECTORY_STACK,
            max_visited_directories: MAX_CLEANUP_VISITED_DIRECTORIES,
            operation_staging: None,
            _storage_instance_lock: self._storage_instance_lock.clone(),
            #[cfg(test)]
            next_batch_error: Some(self.next_cleanup_batch_error.clone()),
            #[cfg(test)]
            before_batch_hook: Some(self.before_cleanup_batch_hook.clone()),
        })
    }

    pub(crate) fn pending_file_operations(&self) -> io::Result<Vec<PendingFileOperation>> {
        use std::os::fd::AsRawFd;

        let proc_path = format!("/proc/self/fd/{}", self.tombstones.as_ref().as_raw_fd());
        let mut operations = Vec::new();
        for item in std::fs::read_dir(proc_path)? {
            let item = item?;
            let name = item.file_name();
            if !is_file_operation_name(&name) {
                continue;
            }
            let name = name.to_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "file-operation journal has a non-UTF-8 name",
                )
            })?;
            let operation = read_file_operation(self.tombstones.as_ref(), name)?;
            validate_file_operation(&operation)?;
            operations.push(PendingFileOperation {
                journal_name: name.to_string(),
                operation,
            });
        }
        operations.sort_by(|left, right| left.journal_name.cmp(&right.journal_name));
        Ok(operations)
    }

    pub(crate) fn recover_file_operation(
        &self,
        pending: &PendingFileOperation,
    ) -> io::Result<FileOperationRecovery> {
        match &pending.operation {
            DurableFileOperation::Rename {
                original_path,
                new_path,
                kind,
                device,
                inode,
                phase,
            } => self.recover_rename_operation(
                &pending.journal_name,
                original_path,
                new_path,
                (*kind).into(),
                (*device, *inode),
                *phase,
            ),
            DurableFileOperation::Delete {
                original_path,
                kind,
                device,
                inode,
                pending_name,
                tombstone_name,
                allow_recursive,
                phase,
            } => self.recover_delete_operation(
                &pending.journal_name,
                original_path,
                (*kind).into(),
                (*device, *inode),
                pending_name,
                tombstone_name,
                *allow_recursive,
                *phase,
            ),
        }
    }

    pub(crate) fn complete_file_operation(&self, pending: &PendingFileOperation) -> io::Result<()> {
        remove_file_operation(self.tombstones.as_ref(), &pending.journal_name)?;
        if let DurableFileOperation::Delete { tombstone_name, .. } = &pending.operation {
            unregister_upload_fragment(tombstone_name);
        }
        Ok(())
    }

    fn deletion_tombstone_identity_state(
        &self,
        tombstone_name: &str,
        identity: (u64, u64),
        kind: EntryKind,
    ) -> io::Result<EntryIdentityState> {
        #[cfg(test)]
        if let Some(kind) = self
            .next_delete_identity_probe_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            return Err(io::Error::new(
                kind,
                "injected deletion identity probe failure",
            ));
        }
        entry_identity_state(self.tombstones.as_ref(), tombstone_name, identity, kind)
    }
}
